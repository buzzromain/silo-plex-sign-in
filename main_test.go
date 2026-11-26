package main

import (
	"encoding/json"
	"testing"

	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"github.com/buzzromain/silo-plugin-auth-plex/provider"
)

// TestVersionMatchesManifest keeps provider.Version, which the binary reports
// to Silo and Plex, equal to the version in manifest.json.
func TestVersionMatchesManifest(t *testing.T) {
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != provider.Version {
		t.Fatalf("manifest.json version %s != provider.Version %s", m.Version, provider.Version)
	}
}

func TestManifestCatalogPresentation(t *testing.T) {
	m, err := manifestWithHTTPRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.ValidateCatalogPresentation(m, "https://github.com/buzzromain/silo-plugin-auth-plex"); err != nil {
		t.Fatalf("catalog presentation: %v", err)
	}
}

func TestManifestRoutes(t *testing.T) {
	m, err := manifestWithHTTPRoutes()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{ access, id string }{
		"GET /plex/start": {"public", "plex-start"}, "POST /plex/status": {"public", "plex-status"}, "GET /assets/*": {"public", "plex-assets"},
		"GET /admin/access":      {"admin", "access-page"},
		"POST /admin/people/add": {"admin", "people-add"}, "POST /admin/people/remove": {"admin", "people-remove"},
		"POST /admin/activity/allow": {"admin", "activity-allow"}, "GET /admin/activity/export": {"admin", "activity-export"},
		"POST /admin/plex/disconnect": {"admin", "plex-disconnect"},
		"GET /admin/find-server":      {"admin", "find-server-page"}, "POST /admin/find-server/start": {"admin", "find-server-start"},
		"POST /admin/find-server/poll": {"admin", "find-server-poll"}, "POST /admin/find-server/select": {"admin", "find-server-select"},
	}
	for _, route := range m.GetHttpRoutes() {
		key := route.GetMethod() + " " + route.GetPath()
		expect, ok := want[key]
		if !ok {
			t.Errorf("unexpected route: %s (%s, id=%s)", key, route.GetAccess(), route.GetId())
			continue
		}
		if expect.access != route.GetAccess() || expect.id != route.GetId() {
			t.Errorf("unexpected route: %s (access=%s id=%s), want access=%s id=%s", key, route.GetAccess(), route.GetId(), expect.access, expect.id)
		}
		delete(want, key)
		if route.GetNavigable() != (key == "GET /admin/access") {
			t.Errorf("unexpected navigation for %s", key)
		}
		if route.GetNavigable() && (route.GetNavigationLabel() != "Plex Sign-In" || route.GetNavigationKind() != "admin") {
			t.Errorf("invalid navigation for %s", key)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing routes: %v", want)
	}
	if got, expected := len(m.GetHttpRoutes()), 13; got != expected {
		t.Errorf("route count = %d, want %d", got, expected)
	}
}

func TestManifestBrandingHasDefaultsAndNoEditableFields(t *testing.T) {
	m, err := manifestWithHTTPRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if m.GetVersion() != "0.1.0" || m.GetCapabilities()[0].GetDisplayName() != "Plex" {
		t.Fatal("unexpected manifest version or login label")
	}
	want := map[string]string{"icon_url_path": "plex.png"}
	for _, setting := range m.GetGlobalConfigSchema() {
		key := setting.GetKey()
		value, ok := want[key]
		if !ok || setting.GetAdminForm() != nil || setting.GetRequired() {
			t.Fatalf("unexpected native configuration: %s", key)
		}
		var schema struct {
			Properties map[string]map[string]string `json:"properties"`
		}
		if err := json.Unmarshal([]byte(setting.GetJsonSchema()), &schema); err != nil {
			t.Fatal(err)
		}
		if field := schema.Properties["value"]; field["const"] != value || field["default"] != value {
			t.Errorf("%s not fixed to %q", key, value)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("missing branding defaults: %v", want)
	}
}
