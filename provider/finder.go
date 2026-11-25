package provider

// "Connect Plex" flow: the administrator signs in with Plex and selects the
// server whose users may sign in to Silo.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/httproute"
)

// The Plex Sign-In setup page lets a Silo administrator sign in with Plex and
// pick one of the servers the account owns. Selecting a server stores it with
// the owner's Plex account ID and token, then drops the pending flow.
const (
	finderPath       = "/admin/find-server"
	finderStartPath  = "/admin/find-server/start"
	finderStatusPath = "/admin/find-server/poll"
	finderSelectPath = "/admin/find-server/select"
)

// finderFlow is an administrator's pending "connect Plex" sign-in. It is bound
// to that administrator, kept in memory only, and holds the owner's token until
// a server is selected.
type finderFlow struct {
	pinID     int64
	pinCode   string
	adminID   int
	expiresAt time.Time
	token     string
	ownerUUID string
	servers   []foundServer
	complete  bool
	failed    bool
}

// foundServer is a Plex Media Server owned by the connecting account.
type foundServer struct {
	Name string
	ID   string
}

// requireAdmin returns the Silo viewer and whether they are an administrator.
// Silo also enforces admin access on these routes; this is defence in depth.
func requireAdmin(req *pluginv1.HandleHTTPRequest) (httproute.Viewer, bool) {
	viewer, ok := httproute.ViewerOf(req)
	return viewer, ok && viewer.Admin
}

// handleFinder routes the "connect Plex" pages: start, status polling and
// server selection. Every route requires a Silo administrator.
func (p *Provider) handleFinder(ctx context.Context, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	viewer, ok := requireAdmin(req)
	if !ok {
		return httpResponse(http.StatusForbidden, "text/plain; charset=utf-8", English.T("admin.forbidden"))
	}
	switch req.GetPath() {
	case finderPath:
		var query map[string]any
		if req.GetQuery() != nil {
			query = req.GetQuery().AsMap()
		}
		flowID, _ := query["flow"].(string)
		return p.finderPage(ctx, English, viewer, flowID)
	case finderStartPath:
		if req.GetMethod() != http.MethodPost {
			return httpResponse(http.StatusMethodNotAllowed, "text/plain; charset=utf-8", "method not allowed")
		}
		return p.finderCreate(ctx, viewer, req)
	case finderStatusPath:
		if req.GetMethod() != http.MethodPost {
			return httpResponse(http.StatusMethodNotAllowed, "text/plain; charset=utf-8", "method not allowed")
		}
		return p.finderPoll(ctx, viewer, req)
	case finderSelectPath:
		if req.GetMethod() != http.MethodPost {
			return httpResponse(http.StatusMethodNotAllowed, "text/plain; charset=utf-8", "method not allowed")
		}
		return p.finderSelect(ctx, viewer, req)
	default:
		return httpResponse(http.StatusNotFound, "text/plain; charset=utf-8", "not found")
	}
}

// finderPage is the data rendered by the connect Plex template.
type finderPage struct {
	Lang                                                                            Lang
	T                                                                               func(string, ...any) string
	CSP, Assets, Plex, Resume, Status, Problem, Token, Flow, PollToken, StartAction string
	Ready                                                                           bool
	Servers                                                                         []foundServer
}

// finderStart renders the connect page. Without flowID it creates a Plex PIN
// and a new flow; with one it shows that flow's progress or server list.
func (p *Provider) finderPage(_ context.Context, lang Lang, viewer httproute.Viewer, flowID string) *pluginv1.HandleHTTPResponse {
	data := finderPage{Lang: lang, T: lang.T, CSP: metaContentSecurityPolicy, Assets: assetsBase, Token: p.formToken()}
	if flowID == "" {
		data.StartAction = "find-server/start"
		return renderPage(http.StatusOK, "finder.html", data)
	}
	flow := p.finderFlowFor(viewer.UserID, flowID)
	if flow == nil {
		data.Problem = "finder.expired"
		return renderPage(http.StatusGone, "finder.html", data)
	}
	data.Flow, data.Token = flowID, p.formToken()
	data.Resume = "find-server?flow=" + url.QueryEscape(flowID)
	data.Status = "find-server/poll"
	data.StartAction = "find-server/start"
	data.PollToken = data.Token
	data.Ready, data.Servers = flow.complete, flow.servers
	data.Token = p.formToken()
	// The browser appends the absolute return URL (forwardUrl), which only it
	// knows; see admin.js.
	data.Plex = strings.TrimSuffix(plexAuthURL(flow.pinCode, ""), "&forwardUrl=")
	if flow.failed {
		data.Problem = "finder.unavailable"
	}
	if !flow.complete && !flow.failed {
		data.PollToken = data.Token
	}
	return renderPage(http.StatusOK, "finder.html", data)
}

// finderCreate starts the owner-connection flow after an explicit POST action.
func (p *Provider) finderCreate(ctx context.Context, viewer httproute.Viewer, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	_, status := p.adminForm(req)
	if status != http.StatusOK {
		return httpResponse(status, contentTypeText, English.T("admin.form.invalid"))
	}
	p.mu.Lock()
	p.pruneFlowsLocked(time.Now())
	full := len(p.flows)+p.pendingCreates >= maxFlows
	if !full {
		p.pendingCreates++
	}
	p.mu.Unlock()
	if full {
		return accessRedirect("access", "busy")
	}
	defer func() {
		p.mu.Lock()
		p.pendingCreates--
		p.mu.Unlock()
	}()
	pin, err := p.createPIN(ctx)
	if err != nil {
		return accessRedirect("access", "plex_unavailable")
	}
	flowID, err := randomID()
	if err != nil {
		return accessRedirect("access", "error_state")
	}
	flow := &finderFlow{pinID: pin.ID, pinCode: pin.Code, adminID: viewer.UserID, expiresAt: time.Now().Add(flowLifetime)}
	p.mu.Lock()
	p.pruneFlowsLocked(time.Now())
	if p.finders == nil {
		p.finders = make(map[string]*finderFlow)
	}
	p.finders[flowID] = flow
	p.mu.Unlock()
	return adminRedirect("../find-server?flow=" + url.QueryEscape(flowID))
}

// finderFlowFor returns adminID's unexpired flow, or nil. A flow started by
// another administrator is never returned.
func (p *Provider) finderFlowFor(adminID int, flowID string) *finderFlow {
	p.mu.Lock()
	defer p.mu.Unlock()
	flow := p.finders[flowID]
	if flow != nil && time.Now().After(flow.expiresAt) {
		delete(p.finders, flowID)
		flow = nil
	}
	if flow == nil || flow.adminID != adminID {
		return nil
	}
	copyOfFlow := *flow
	return &copyOfFlow
}

// finderPoll answers the connect page's status polling and, once Plex approves,
// loads the servers owned by the account.
func (p *Provider) finderPoll(ctx context.Context, viewer httproute.Viewer, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	form, status := p.adminForm(req)
	if status != http.StatusOK {
		return jsonResponse(status, `{"status":"invalid"}`)
	}
	flowID := form.Get("flow")
	flow := p.finderFlowFor(viewer.UserID, flowID)
	if flow == nil {
		return jsonResponse(http.StatusGone, `{"status":"expired"}`)
	}
	if flow.failed {
		return jsonResponse(http.StatusOK, `{"status":"failed"}`)
	}
	if flow.complete {
		return jsonResponse(http.StatusOK, encodeJSON(map[string]any{
			"status":  "done",
			"servers": flow.servers,
		}))
	}

	pin, err := p.pollPINFromPlex(ctx, flow.pinID, flow.pinCode)
	if err != nil {
		return jsonResponse(http.StatusServiceUnavailable, `{"status":"waiting"}`)
	}
	if pin.AuthToken == "" {
		return jsonResponse(http.StatusOK, `{"status":"waiting"}`)
	}
	owner, err := p.fetchUser(ctx, pin.AuthToken)
	var resources []plexResource
	if err == nil && owner.UUID == "" {
		err = errors.New("Plex account has no UUID")
	}
	if err == nil {
		resources, err = p.fetchResources(ctx, pin.AuthToken)
	}
	if err != nil {
		p.mu.Lock()
		if current := p.finders[flowID]; current != nil {
			current.failed = true
		}
		p.mu.Unlock()
		return jsonResponse(http.StatusOK, `{"status":"failed"}`)
	}
	servers := serversFrom(resources)
	p.mu.Lock()
	if current := p.finders[flowID]; current != nil {
		current.token = pin.AuthToken
		current.ownerUUID = owner.UUID
		current.servers = servers
		current.complete = true
	}
	p.mu.Unlock()
	return jsonResponse(http.StatusOK, encodeJSON(map[string]any{
		"status":  "done",
		"servers": servers,
	}))
}

// finderSelect saves the server chosen from the flow's list together with the
// owner token, then drops the flow.
func (p *Provider) finderSelect(ctx context.Context, viewer httproute.Viewer, req *pluginv1.HandleHTTPRequest) *pluginv1.HandleHTTPResponse {
	form, status := p.adminForm(req)
	if status != http.StatusOK {
		return httpResponse(status, contentTypeText, English.T("admin.form.invalid"))
	}
	flowID := form.Get("flow")
	selectedID := strings.TrimSpace(form.Get("server_id"))
	flow := p.finderFlowFor(viewer.UserID, flowID)
	if flow == nil || !flow.complete || flow.token == "" {
		return accessRedirect("access", "flow_expired")
	}
	var selected foundServer
	for _, server := range flow.servers {
		if server.ID == selectedID {
			selected = server
			break
		}
	}
	if selected.ID == "" {
		return adminRedirect("../find-server?flow=" + url.QueryEscape(flowID))
	}
	if err := p.saveConnection(ctx, plexConnection{
		ServerMachineID: selected.ID,
		ServerName:      selected.Name,
		OwnerUUID:       flow.ownerUUID,
		OwnerToken:      flow.token,
	}); err != nil {
		return accessRedirect("access", "error_state")
	}
	p.mu.Lock()
	delete(p.finders, flowID)
	p.mu.Unlock()
	return accessRedirect("access", "connected")
}

// serversFrom keeps only Plex Media Servers owned by the signed-in account.
// Servers merely shared with the account are not configuration candidates:
// the administrator is choosing their own server, not a friend's server.
func serversFrom(resources []plexResource) []foundServer {
	servers := make([]foundServer, 0, len(resources))
	for _, resource := range resources {
		if !resource.Owned || !providesServer(resource.Provides) || resource.ClientIdentifier == "" {
			continue
		}
		name := publicName(resource.Name)
		servers = append(servers, foundServer{Name: name, ID: resource.ClientIdentifier})
	}
	return servers
}
