package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

func TestAssetsRouteServesOnlyEmbeddedFiles(t *testing.T) {
	p := New()
	get := func(path string) *pluginv1.HandleHTTPResponse {
		resp, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	logo := get("/assets/plex.svg")
	if logo.GetStatusCode() != http.StatusOK || logo.GetHeaders()["Content-Type"] != "image/svg+xml" || !strings.Contains(string(logo.GetBody()), "<svg") {
		t.Fatalf("logo not served: %v", logo)
	}
	if logo.GetHeaders()["X-Content-Type-Options"] != "nosniff" || logo.GetHeaders()["Cache-Control"] != assetCache {
		t.Errorf("asset headers = %v", logo.GetHeaders())
	}
	// The login button icon is a PNG: Apple apps do not draw SVG icons.
	button := get("/assets/plex.png")
	if button.GetStatusCode() != http.StatusOK || button.GetHeaders()["Content-Type"] != "image/png" || !strings.HasPrefix(string(button.GetBody()), "\x89PNG\r\n\x1a\n") {
		t.Fatalf("button icon not served: %d %v", button.GetStatusCode(), button.GetHeaders())
	}
	for _, path := range []string{"/assets/", "/assets/other.svg", "/assets/../manifest.json", "/assets/plex.svg/extra", "/assets/%2e%2e/x", "/assets/..%2fprovider.go", "/assets/.svg", "/assets/web/static/plex.svg"} {
		if resp := get(path); resp.GetStatusCode() != http.StatusNotFound {
			t.Errorf("%s must be 404, got %d", path, resp.GetStatusCode())
		}
	}
}

func TestSafeAvatar(t *testing.T) {
	tests := map[string]string{
		"":                                     "",
		"https://plex.tv/users/abc/avatar?c=1": "https://plex.tv/users/abc/avatar",
		"https://assets.plex.tv/a.png":         "https://assets.plex.tv/a.png",
		"/users/abc/avatar":                    "https://plex.tv/users/abc/avatar",
		"http://plex.tv/a.png":                 "",
		"https://evil.example/a.png":           "",
		"https://plex.tv.evil.example/a.png":   "",
		"https://user@plex.tv/a.png":           "",
		"javascript:alert(1)":                  "",
		"https://plex.tv:8443/a.png":           "",
	}
	for in, want := range tests {
		if got := safeAvatar(in); got != want {
			t.Errorf("safeAvatar(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestViewHelpers(t *testing.T) {
	if got := initials("Claire Lemoine"); got != "CL" {
		t.Errorf("initials = %q", got)
	}
	if got := initials("  "); got != "?" {
		t.Errorf("initials empty = %q", got)
	}
	if got := initials("@élodie"); got != "É" {
		t.Errorf("initials accent = %q", got)
	}
	if got := shortID("a1b2c3d4e5f6a7b8c9f9"); got != "a1b2c3…f9" {
		t.Errorf("shortID = %q", got)
	}
	if got := shortID("abc"); got != "abc" {
		t.Errorf("shortID short = %q", got)
	}
	if got := formatRef("7KQ4M2"); got != "7KQ-4M2" {
		t.Errorf("formatRef = %q", got)
	}
}

func TestRenderPageSetsSecurityHeaders(t *testing.T) {
	resp := renderPage(http.StatusOK, "avatar", struct {
		Name, Thumb string
		Anonymous   bool
	}{"Claire", "https://evil.example/x", false})
	h := resp.GetHeaders()
	if h["Content-Security-Policy"] != contentSecurityPolicy || h["Cache-Control"] != "no-store" || h["Referrer-Policy"] != "no-referrer" {
		t.Fatalf("headers = %v", h)
	}
	if body := string(resp.GetBody()); strings.Contains(body, "evil") || !strings.Contains(body, ">C<") {
		t.Errorf("body = %s", body)
	}
}
