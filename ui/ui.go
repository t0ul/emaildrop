// Package ui is the View in the webapp's MVC split: the dashboard template and
// its static assets, embedded into the binary at build time so the server ships
// as a single artifact. The page is a Go html/template (dashboard.gohtml) so the
// per-session operator capability token is injected with correct contextual
// (JS-string) escaping, not a raw string replace. CSS/JS live as static files
// under static/ and are served separately, so they are cacheable and editable on
// their own. pkg/server renders this; it never writes HTML inline.
package ui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io"
)

//go:embed templates/dashboard.gohtml
var dashboardSrc string

// Static holds the dashboard's CSS/JS, served by the server under /static/.
//
//go:embed static/*
var Static embed.FS

var dashboardTmpl = template.Must(template.New("dashboard").Parse(dashboardSrc))

// AssetVersion is a content hash of the embedded CSS/JS, appended to their URLs as a
// query string so a rebuilt binary never serves a page that runs a browser-cached
// script from the previous build (the fix for a bug is only a fix if the browser runs it).
var AssetVersion = assetVersion()

func assetVersion() string {
	h := sha256.New()
	for _, name := range []string{"static/app.css", "static/app.js"} {
		b, _ := Static.ReadFile(name)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// DashboardData is the template data for the dashboard page.
type DashboardData struct {
	CapToken     string // operator capability Grant, html/template-escaped into the page
	Surface      string // "app" (consumer: zero knobs) or "studio" (operator: the tuning/governance plane)
	AssetVersion string // content hash of the embedded assets, cache-busts /static/ URLs
}

// RenderDashboard writes the dashboard page for the given surface ("app" or
// "studio"), with the capability token escaped in. One template, two surfaces: the
// JS shows only the tabs that belong to the surface (1 view, 1 job).
func RenderDashboard(w io.Writer, token, surface string) error {
	if surface == "" {
		surface = "app"
	}
	return dashboardTmpl.Execute(w, DashboardData{CapToken: token, Surface: surface, AssetVersion: AssetVersion})
}
