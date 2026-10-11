// Package mcp is a minimal Model Context Protocol transport: a JSON-RPC 2.0
// server that advertises tools (tools/list) and runs them (tools/call), plus an
// HTTP client that satisfies gustoms.Client so an MCP server can sit behind the
// gustoms gateway (allowlist + manifest pin + authorization). It also provides
// the demo web_fetch tool, whose every target is screened by netpolicy (M16
// egress containment).
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/t0ul/emaildrop/pkg/argcheck"
	"github.com/t0ul/emaildrop/pkg/netpolicy"
	"github.com/t0ul/gustoms"
)

// Tool is one MCP tool: a name, a description (part of the pinned manifest), and
// a handler.
type Tool struct {
	Name        string
	Description string
	// Schema, when set, validates arguments (argcheck) before the handler runs —
	// unknown args, type mismatches, and shell metacharacters are rejected.
	Schema  argcheck.Schema
	Handler func(ctx context.Context, args map[string]any) (any, error)
}

// Server serves a set of tools over JSON-RPC/HTTP.
type Server struct{ tools []Tool }

// NewServer builds an MCP server over the given tools.
func NewServer(tools ...Tool) *Server { return &Server{tools: tools} }

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResp struct {
	JSONRPC string  `json:"jsonrpc"`
	ID      any     `json:"id"`
	Result  any     `json:"result,omitempty"`
	Error   *rpcErr `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ServeHTTP implements the JSON-RPC endpoint (tools/list, tools/call).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req rpcReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeRPC(w, rpcResp{JSONRPC: "2.0", Error: &rpcErr{-32700, "parse error"}})
		return
	}
	switch req.Method {
	case "tools/list":
		specs := make([]gustoms.ToolSpec, len(s.tools))
		for i, t := range s.tools {
			specs[i] = gustoms.ToolSpec{Name: t.Name, Description: t.Description}
		}
		writeRPC(w, rpcResp{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": specs}})
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		json.Unmarshal(req.Params, &p)
		tool := s.find(p.Name)
		if tool == nil {
			writeRPC(w, rpcResp{JSONRPC: "2.0", ID: req.ID, Error: &rpcErr{-32601, "no such tool: " + p.Name}})
			return
		}
		if tool.Schema != nil {
			if _, err := argcheck.Validate(tool.Schema, p.Arguments); err != nil {
				writeRPC(w, rpcResp{JSONRPC: "2.0", ID: req.ID, Error: &rpcErr{-32602, "invalid arguments: " + err.Error()}})
				return
			}
		}
		out, err := tool.Handler(r.Context(), p.Arguments)
		if err != nil {
			writeRPC(w, rpcResp{JSONRPC: "2.0", ID: req.ID, Error: &rpcErr{-32000, err.Error()}})
			return
		}
		writeRPC(w, rpcResp{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"result": out}})
	default:
		writeRPC(w, rpcResp{JSONRPC: "2.0", ID: req.ID, Error: &rpcErr{-32601, "method not found"}})
	}
}

func (s *Server) find(name string) *Tool {
	for i := range s.tools {
		if s.tools[i].Name == name {
			return &s.tools[i]
		}
	}
	return nil
}

func writeRPC(w http.ResponseWriter, resp rpcResp) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// HTTPClient talks to an MCP server over HTTP and satisfies gustoms.Client.
type HTTPClient struct {
	URL  string
	HTTP *http.Client
}

func (c *HTTPClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *HTTPClient) rpc(ctx context.Context, method string, params any) (json.RawMessage, error) {
	body, _ := json.Marshal(rpcReq{JSONRPC: "2.0", ID: 1, Method: method, Params: mustRaw(params)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcErr         `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("mcp: %s", out.Error.Message)
	}
	return out.Result, nil
}

// ListTools implements gustoms.Client.
func (c *HTTPClient) ListTools(ctx context.Context) ([]gustoms.ToolSpec, error) {
	raw, err := c.rpc(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var r struct {
		Tools []gustoms.ToolSpec `json:"tools"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return r.Tools, nil
}

// CallTool implements gustoms.Client.
func (c *HTTPClient) CallTool(ctx context.Context, name string, args map[string]any) (any, error) {
	raw, err := c.rpc(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	var r struct {
		Result any `json:"result"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return r.Result, nil
}

func mustRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// WebFetchTool is the demo browse/search primitive: it fetches a URL only after
// netpolicy clears it (allowlist + no internal/IMDS address), so a compromised
// caller cannot turn it into an SSRF or credential-theft channel.
func WebFetchTool(policy netpolicy.Policy, maxBytes int64) Tool {
	// The client dials only IPs the policy vetted at connect time, so even a
	// rebinding DNS cannot steer the fetch to an internal address.
	httpc := policy.HTTPClient(15 * time.Second)
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	return Tool{
		Name:        "web_fetch",
		Description: "Fetch an allow-listed HTTP(S) URL and return its status and body.",
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			url, _ := args["url"].(string)
			if url == "" {
				return nil, errors.New("web_fetch: 'url' argument is required")
			}
			if err := policy.Check(url); err != nil {
				return nil, err // M16: refused before any connection
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return nil, err
			}
			resp, err := httpc.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
			return map[string]any{"status": resp.StatusCode, "bytes": len(body), "body": string(body)}, nil
		},
	}
}
