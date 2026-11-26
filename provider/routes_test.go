package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

func TestEveryDeclaredRouteIsServed(t *testing.T) {
	p := New()
	for _, r := range routeTable {
		path := r.path
		if strings.HasSuffix(path, "/*") {
			path = strings.TrimSuffix(path, "*") + "plex.png"
		}
		resp, err := p.Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: r.method, Path: path})
		if err != nil {
			t.Fatalf("%s %s: %v", r.method, path, err)
		}
		// A handler may answer 404 itself (an unknown sign-in flow does), so
		// only the router's own "not found" body proves the route is missing.
		if status := resp.GetStatusCode(); status == http.StatusMethodNotAllowed ||
			(status == http.StatusNotFound && string(resp.GetBody()) == "not found") {
			t.Errorf("%s %s is declared but not served (%d)", r.method, path, status)
		}
	}
}
