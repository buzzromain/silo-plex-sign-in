// Package provider implements Plex Sign-In, a Silo auth_provider.v1 and
// http_routes.v1 plugin that lets people sign in to Silo with Plex.
package provider

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// webFS holds every template, stylesheet, script and image. Catalog installs
// ship only the binary, so nothing is read from disk.
//
//go:embed web/templates/*.html web/static/*
var webFS embed.FS

// logger writes JSON to stderr, which go-plugin forwards to Silo's log.
// Never log tokens, PIN codes, claims or emails.
var logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))

// metaContentSecurityPolicy allows only same-origin styles, scripts and
// requests, and Plex avatars. Silo's plugin proxy relays only a few response
// headers and drops Content-Security-Policy, so every page also carries the
// policy in a <meta> element, which cannot hold frame-ancestors.
const metaContentSecurityPolicy = "default-src 'none'; img-src 'self' https://plex.tv https://*.plex.tv; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'"

// contentSecurityPolicy is the full policy, sent as a header for hosts that
// relay it.
const contentSecurityPolicy = metaContentSecurityPolicy + "; frame-ancestors 'self'"

const (
	contentTypeHTML = "text/html; charset=utf-8"
	contentTypeJSON = "application/json; charset=utf-8"
	contentTypeText = "text/plain; charset=utf-8"
	assetCache      = "public, max-age=86400"
)

var templateFuncs = template.FuncMap{
	"initials":   initials,
	"safeAvatar": safeAvatar,
	"shortID":    shortID,
	"formatRef":  formatRef,
	// assetVersion busts the browser cache of admin.css/js after an update.
	"assetVersion": func() string { return assetVersion },
	"personActions": func(p personRow, t func(string, ...any) string, token, action string) map[string]any {
		return map[string]any{"Person": p, "T": t, "Token": token, "Action": action, "AddAction": "../people/add", "AllowAction": "../activity/allow"}
	},
}

// assetVersion is a short hash of the embedded static files.
var assetVersion = func() string {
	h := sha256.New()
	_ = fs.WalkDir(webFS, "web/static", func(name string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := fs.ReadFile(webFS, name)
			h.Write([]byte(name))
			h.Write(data)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

var templates = template.Must(template.New("").Funcs(templateFuncs).ParseFS(webFS, "web/templates/*.html"))

var staticTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
}

// httpResponse builds a response with the headers every plugin page needs.
func httpResponse(status int, contentType, body string) *pluginv1.HandleHTTPResponse {
	return &pluginv1.HandleHTTPResponse{
		StatusCode: int32(status),
		Headers: map[string]string{
			"Content-Type":           contentType,
			"Cache-Control":          "no-store",
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "no-referrer",
			"X-Frame-Options":        "DENY",
		},
		Body: []byte(body),
	}
}

// jsonResponse returns a JSON body with the standard plugin headers.
func jsonResponse(status int, body string) *pluginv1.HandleHTTPResponse {
	return httpResponse(status, contentTypeJSON, body)
}

// renderPage executes the named template and returns it as an HTML response
// with the content security policy.
func renderPage(status int, name string, data any) *pluginv1.HandleHTTPResponse {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		logger.Warn("render page", "template", name, "error", err)
		return httpResponse(http.StatusInternalServerError, contentTypeText, http.StatusText(http.StatusInternalServerError))
	}
	response := httpResponse(status, contentTypeHTML, buf.String())
	response.Headers["Content-Security-Policy"] = contentSecurityPolicy
	return response
}

// serveAsset answers GET /assets/<name> with an embedded static file. Only
// exact file names exist: no directories, no other paths.
func serveAsset(requestPath string) *pluginv1.HandleHTTPResponse {
	name := strings.TrimPrefix(requestPath, "/assets/")
	contentType, known := staticTypes[path.Ext(name)]
	if !known || name == "" || strings.ContainsAny(name, "/\\%") || strings.HasPrefix(name, ".") {
		return httpResponse(http.StatusNotFound, contentTypeText, "not found")
	}
	data, err := fs.ReadFile(webFS, "web/static/"+name)
	if err != nil {
		return httpResponse(http.StatusNotFound, contentTypeText, "not found")
	}
	response := httpResponse(http.StatusOK, contentType, string(data))
	response.Headers["Cache-Control"] = assetCache
	return response
}

// initials returns up to two capital letters for an avatar fallback.
func initials(value string) string {
	fields := strings.Fields(strings.TrimPrefix(value, "@"))
	if len(fields) == 0 {
		return "?"
	}
	result := string([]rune(strings.ToUpper(fields[0]))[0])
	if len(fields) > 1 {
		result += string([]rune(strings.ToUpper(fields[1]))[0])
	}
	return result
}

// safeAvatar returns value as an absolute https URL on plex.tv or one of its
// subdomains, resolving paths relative to plex.tv. Anything else is dropped.
func safeAvatar(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if u.Scheme == "" && u.Host == "" {
		u, err = url.Parse("https://plex.tv/" + strings.TrimLeft(value, "/"))
		if err != nil {
			return ""
		}
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme != "https" || u.User != nil || u.Port() != "" || (host != "plex.tv" && !strings.HasSuffix(host, ".plex.tv")) {
		return ""
	}
	// Plex avatars do not need credentials or identifying query parameters.
	u.RawQuery, u.Fragment, u.ForceQuery = "", "", false
	if strings.Contains(u.Path, "@") {
		return ""
	}
	return u.String()
}

// shortID shortens a long identifier to its first six and last two
// characters, for display; the full value belongs in a title attribute.
func shortID(id string) string {
	if len(id) <= 10 {
		return id
	}
	return id[:6] + "…" + id[len(id)-2:]
}

// formatRef shows a six-character reference as "7KQ-4M2".
func formatRef(ref string) string {
	if len(ref) != 6 {
		return ref
	}
	return fmt.Sprintf("%s-%s", ref[:3], ref[3:])
}

// publicName keeps account identifiers and email addresses out of UI copy.
func publicName(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "@") || looksLikeUUID(value) || strings.HasPrefix(strings.ToLower(value), "plex:") {
		return ""
	}
	return value
}
