package ui

import (
	"regexp"
	"strings"
	"testing"
)

// The dashboard builds its HTML as strings and wires buttons with inline onclick
// handlers. A value placed inside such a handler's JavaScript string literal must be
// JS-quoted (jsarg), never only HTML-escaped (esc): the HTML parser decodes entities
// before the JS parser runs, so a title like "Chancellor's Day" ended the literal and
// every click on that row was a silent SyntaxError. This reads the real shipped
// app.js and refuses the pattern that caused it.
func TestInlineHandlerArgsAreJSQuoted(t *testing.T) {
	src, err := Static.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	// Any `\''+expr+'\'` splice is a value dropped into a JS string literal by hand.
	if n := strings.Count(js, `\''+`); n != 0 {
		t.Fatalf("app.js splices %d value(s) into inline-handler string literals by hand; use jsarg() so a quote in the value cannot break the handler", n)
	}
	if !strings.Contains(js, "const jsarg=") {
		t.Fatal("app.js must define jsarg (JSON-quote, then entity-escape) for inline handler arguments")
	}
	// esc must neutralize both quote characters too, so a value in a quoted attribute
	// cannot end the attribute.
	escDef := regexp.MustCompile(`const esc=[^\n]*`).FindString(js)
	for _, want := range []string{`&quot;`, `&#39;`} {
		if !strings.Contains(escDef, want) {
			t.Fatalf("esc() must escape quotes (%s); got: %s", want, escDef)
		}
	}
}

// The page must load its assets under a content-hash query so a rebuilt binary is
// never paired with a browser-cached script from the previous build.
func TestAssetsAreCacheBusted(t *testing.T) {
	var b strings.Builder
	if err := RenderDashboard(&b, "tok", "app"); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	if len(AssetVersion) != 12 {
		t.Fatalf("AssetVersion must be a 12-hex content hash, got %q", AssetVersion)
	}
	for _, want := range []string{"/static/app.js?v=" + AssetVersion, "/static/app.css?v=" + AssetVersion} {
		if !strings.Contains(html, want) {
			t.Fatalf("dashboard must reference %s", want)
		}
	}
}
