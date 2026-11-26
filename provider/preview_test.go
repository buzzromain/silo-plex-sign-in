package provider

import (
	"context"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWritePreviews renders every screen to PLEX_SSO_PREVIEW_DIR for
// screenshots. It does nothing unless the variable is set.
func TestWritePreviews(t *testing.T) {
	dir := os.Getenv("PLEX_SSO_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set PLEX_SSO_PREVIEW_DIR to write previews")
	}
	write := func(name string, body []byte) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	static, _ := fs.Sub(webFS, "web/static")
	_ = fs.WalkDir(static, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := fs.ReadFile(static, path)
			write(filepath.Join("assets", path), data)
		}
		return nil
	})
	account := &statusAccount{Title: "Claire L.", Username: "claire.l"}
	for _, lang := range []Lang{English} {
		screens := map[string]signinPage{}
		for _, screen := range []string{"waiting", "success"} {
			page := newSigninPage(lang)
			page.Screen, page.Host = screen, "media.example.com"
			page.ExpiresAt = time.Now().Add(9*time.Minute + 42*time.Second).UTC().Format(time.RFC3339)
			if screen == "success" {
				page.Account = account
			}
			screens[screen] = page
		}
		for _, e := range signinErrors {
			page := newSigninPage(lang)
			page.Screen, page.Code, page.Ref, page.Host = "error", e.Code, "7KQ4M2", "media.example.com"
			if e.Code != ReasonExpired && e.Code != ReasonClaimed && e.Code != ReasonNotConfigured {
				page.Account = account
			}
			screens["error-"+string(e.Code)] = page
		}
		for name, page := range screens {
			write(filepath.Join("signin", string(lang)+"-"+name+".html"), renderPage(http.StatusOK, "signin.html", page).GetBody())
		}
		p := New()
		store := withAccess(t, p, Settings{Manual: []ManualEntry{
			{Input: "claire.l", UUID: "fixture-claire", Title: "Claire L.", Username: "claire.l", Email: "claire.l@example.test"},
			{Input: "sam"},
		}}, "")
		now := time.Now().UTC()
		store.put(t, connectionKey, plexConnection{Version: connectionVersion, ServerMachineID: "a1b2c3d4e5f6f9", ServerName: "Home Cinema", UpdatedAt: now.Add(-30 * time.Minute).Format(time.RFC3339)})
		store.put(t, activityKey, []ActivityEntry{
			{Ref: "7KQ4M2", At: now.Add(-10 * time.Minute), Outcome: outcomeRefuse, Reason: ReasonNotAllowed, Username: "camille", Title: "Camille P.", UUID: "fixture-camille"},
			{Ref: "Z2W4N6", At: now.Add(-20 * time.Minute), Outcome: outcomeRefuse, Reason: ReasonNotAllowed, Username: "claire.l", Title: "Claire L.", UUID: "fixture-claire"},
			{Ref: "A6Y4W3", At: now.Add(-time.Hour), Outcome: outcomeAllow, Rule: RuleManual, Username: "claire.l", Title: "Claire L.", UUID: "fixture-claire"},
			{Ref: "Q8M3T5", At: now.Add(-26 * time.Hour), Outcome: outcomeRefuse, Reason: ReasonExpired},
		})
		for _, tab := range []string{"access", "people", "activity"} {
			write(filepath.Join("admin", string(lang)+"-"+tab+".html"), p.renderAdmin(context.Background(), lang, adminInput{tab: tab, ref: "7KQ4M2"}, http.StatusOK).GetBody())
		}
		pending := New()
		withAccess(t, pending, Settings{}, "")
		write(filepath.Join("admin", string(lang)+"-access-empty.html"), pending.renderAdmin(context.Background(), lang, adminInput{}, http.StatusOK).GetBody())
		withAccess(t, pending, Settings{}, "a1b2c3d4e5f6f9")
		write(filepath.Join("admin", string(lang)+"-access-connected.html"), pending.renderAdmin(context.Background(), lang, adminInput{}, http.StatusOK).GetBody())
		offline := newSigninPage(lang)
		offline.Screen, offline.Code, offline.Host = "error", ReasonExpired, "media.example.com"
		write(filepath.Join("signin", string(lang)+"-error-offline.html"), renderPage(http.StatusGone, "signin.html", offline).GetBody())

		finder := finderPage{Lang: lang, T: lang.T, CSP: metaContentSecurityPolicy, Assets: assetsBase}
		write(filepath.Join("admin", string(lang)+"-finder.html"), renderPage(http.StatusOK, "finder.html", finder).GetBody())
		waiting := finder
		waiting.Flow, waiting.Resume, waiting.Plex = "fixture-flow", "find-server?flow=fixture-flow", "https://app.plex.tv/auth#?code=fixture"
		write(filepath.Join("admin", string(lang)+"-finder-waiting.html"), renderPage(http.StatusOK, "finder.html", waiting).GetBody())
		finder.Ready, finder.Servers = true, []foundServer{{Name: "Home Cinema", ID: "a1b2c3d4e5f6f9"}}
		write(filepath.Join("admin", string(lang)+"-finder-select.html"), renderPage(http.StatusOK, "finder.html", finder).GetBody())
		finder.Problem = "finder.unavailable"
		write(filepath.Join("admin", string(lang)+"-finder-error.html"), renderPage(http.StatusOK, "finder.html", finder).GetBody())

	}
}
