package provider

import (
	"io/fs"
	"regexp"
	"testing"
	"time"
)

func TestCatalogueHasNoEmptyMessages(t *testing.T) {
	for key, message := range messagesEN {
		if message == "" {
			t.Errorf("%s: empty message", key)
		}
	}
}

func TestTFallsBackToKey(t *testing.T) {
	if got := English.T("signin.header", "media.example"); got != "Signing in to media.example" {
		t.Errorf("header = %q", got)
	}
	if got := English.T("no.such.key"); got != "no.such.key" {
		t.Errorf("unknown key = %q", got)
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		ago  time.Duration
		want string
	}{
		{10 * time.Second, "just now"},
		{5 * time.Minute, "5 min ago"},
		{3 * time.Hour, "3 h ago"},
		{50 * time.Hour, "2 d ago"},
	}
	for _, tt := range tests {
		if got := English.RelativeTime(now.Add(-tt.ago), now); got != tt.want {
			t.Errorf("RelativeTime(%v) = %q, want %q", tt.ago, got, tt.want)
		}
	}
}

// TestTemplateKeysExist catches a template that calls a key nobody defined,
// which would render the key itself on the page.
func TestTemplateKeysExist(t *testing.T) {
	files, err := fs.Glob(webFS, "web/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	key := regexp.MustCompile(`call \$?\.T "([^"]+)"`)
	for _, name := range files {
		data, err := fs.ReadFile(webFS, name)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range key.FindAllSubmatch(data, -1) {
			k := string(match[1])
			if messagesEN[k] == "" {
				t.Errorf("%s uses missing key %q", name, k)
			}
		}
	}
}
