package provider

// HTTP route table: the single place where a route's manifest descriptor and
// its handler are declared, so the two cannot drift apart.

import (
	"context"
	"net/http"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// routeHandler serves one route after its path and method have matched.
type routeHandler func(*Provider, context.Context, *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse

// route is one HTTP route declared to Silo and served by this plugin.
type route struct {
	id, method, path, access string
	navigable                bool
	label, kind              string
	handle                   routeHandler
}

var routeTable = []route{
	{id: "plex-start", method: http.MethodGet, path: "/plex/start", access: "public", handle: (*Provider).startRoute},
	{id: "plex-status", method: http.MethodPost, path: "/plex/status", access: "public", handle: (*Provider).statusRoute},
	{id: "plex-assets", method: http.MethodGet, path: "/assets/*", access: "public", handle: (*Provider).assetRoute},
	{id: "access-page", method: http.MethodGet, path: accessPath, access: "admin", navigable: true, label: "Plex Sign-In", kind: "admin", handle: (*Provider).handleAdmin},
	{id: "people-add", method: http.MethodPost, path: peopleAddPath, access: "admin", handle: (*Provider).handleAdmin},
	{id: "people-remove", method: http.MethodPost, path: peopleRemovePath, access: "admin", handle: (*Provider).handleAdmin},
	{id: "activity-allow", method: http.MethodPost, path: activityAllowPath, access: "admin", handle: (*Provider).handleAdmin},
	{id: "activity-export", method: http.MethodGet, path: activityExportPath, access: "admin", handle: (*Provider).exportActivity},
	{id: "plex-disconnect", method: http.MethodPost, path: disconnectPath, access: "admin", handle: (*Provider).handleAdmin},
	{id: "find-server-page", method: http.MethodGet, path: finderPath, access: "admin", handle: (*Provider).handleFinder},
	{id: "find-server-start", method: http.MethodPost, path: finderStartPath, access: "admin", handle: (*Provider).handleFinder},
	{id: "find-server-poll", method: http.MethodPost, path: finderStatusPath, access: "admin", handle: (*Provider).handleFinder},
	{id: "find-server-select", method: http.MethodPost, path: finderSelectPath, access: "admin", handle: (*Provider).handleFinder},
}

// HTTPRoutes returns the manifest descriptors for the route table.
func HTTPRoutes() []*pluginv1.HttpRouteDescriptor {
	descriptors := make([]*pluginv1.HttpRouteDescriptor, 0, len(routeTable))
	for _, r := range routeTable {
		descriptors = append(descriptors, &pluginv1.HttpRouteDescriptor{
			Id:              r.id,
			Method:          r.method,
			Path:            r.path,
			Access:          r.access,
			Navigable:       r.navigable,
			NavigationLabel: r.label,
			NavigationKind:  r.kind,
		})
	}
	return descriptors
}

// matches reports whether a request path selects this route. Only the asset
// route is a prefix; every other route is an exact path.
func (r route) matches(path string) bool {
	if prefix, ok := strings.CutSuffix(r.path, "*"); ok {
		return strings.HasPrefix(path, prefix)
	}
	return path == r.path
}

// dispatch serves the request. A known path with another method answers 405;
// an unknown path answers 404.
func (p *Provider) dispatch(ctx context.Context, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	pathKnown := false
	for _, r := range routeTable {
		if !r.matches(req.GetPath()) {
			continue
		}
		pathKnown = true
		if r.method == req.GetMethod() {
			return r.handle(p, ctx, req)
		}
	}
	if pathKnown {
		return httpResponse(http.StatusMethodNotAllowed, contentTypeText, "method not allowed")
	}
	return httpResponse(http.StatusNotFound, contentTypeText, "not found")
}

// startRoute reads the sign-in flow from the query and renders its page.
func (p *Provider) startRoute(ctx context.Context, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	var query map[string]any
	if req.GetQuery() != nil {
		query = req.GetQuery().AsMap()
	}
	flowID, _ := query["flow"].(string)
	claim, _ := query["claim"].(string)
	return p.startPage(ctx, req, flowID, claim)
}

// statusRoute reads the form and answers the sign-in status poll.
func (p *Provider) statusRoute(ctx context.Context, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	form, status := parsePublicForm(req)
	if status != http.StatusOK {
		return httpResponse(status, contentTypeText, "invalid request")
	}
	return p.status(ctx, form.Get("flow"), form.Get("claim"))
}

// assetRoute serves one embedded asset by its request path.
func (p *Provider) assetRoute(_ context.Context, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	return serveAsset(req.GetPath())
}
