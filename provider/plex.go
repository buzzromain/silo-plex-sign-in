package provider

// Plex HTTP client: every call to plex.tv lives in this file.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// plexUser is a Plex account as plex.tv returns it.
type plexUser struct {
	ID         int64  `json:"id"`
	UUID       string `json:"uuid"`
	Username   string `json:"username"`
	Title      string `json:"title"`
	Email      string `json:"email"`
	Thumb      string `json:"thumb"`
	Confirmed  *bool  `json:"confirmed"`
	Restricted bool   `json:"restricted"`
	Guest      bool   `json:"guest"`
}

// plexResource is one device/server the Plex account can see (plex.tv /resources).
type plexResource struct {
	Name             string `json:"name"`
	Product          string `json:"product"`
	ClientIdentifier string `json:"clientIdentifier"`
	Provides         string `json:"provides"`
	OwnerID          int64  `json:"ownerId"`
	Owned            bool   `json:"owned"`
}

// errPlexUnauthorized means Plex refused the token.
var errPlexUnauthorized = errors.New("Plex rejected the account token")

// plexPin is a Plex PIN authorization challenge.
type plexPin struct {
	ID        int64  `json:"id"`
	Code      string `json:"code"`
	AuthToken string `json:"authToken"`
}

// endpoint returns the absolute plex.tv URL for path. Tests point apiBaseURL
// at a local fake server.
func (p *Provider) endpoint(path string) string {
	return strings.TrimRight(p.apiBaseURL, "/") + path
}

// createPIN asks Plex for a new strong PIN challenge. The person approves it on
// app.plex.tv; the plugin then polls it with pollPINFromPlex.
func (p *Provider) createPIN(ctx context.Context) (*plexPin, error) {
	form := url.Values{"strong": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint("/api/v2/pins"), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("could not start Plex authorization")
	}
	p.setHeaders(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.New("Plex authorization service is unavailable")
	}
	defer resp.Body.Close()
	var pin plexPin
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&pin) != nil || pin.ID < 1 || pin.Code == "" {
		return nil, errors.New("Plex returned an invalid authorization challenge")
	}
	return &pin, nil
}

// pollPINFromPlex reads the PIN challenge. Its AuthToken is empty until the
// person approves the request on Plex.
func (p *Provider) pollPINFromPlex(ctx context.Context, id int64, pinCode string) (*plexPin, error) {
	endpoint := p.endpoint(fmt.Sprintf("/api/v2/pins/%d", id))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	p.setHeaders(req)
	query := req.URL.Query()
	query.Set("code", pinCode)
	req.URL.RawQuery = query.Encode()
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.New("Plex authorization service is unavailable")
	}
	defer resp.Body.Close()
	var pin plexPin
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&pin) != nil {
		return nil, errors.New("Plex returned an invalid authorization response")
	}
	return &pin, nil
}

// fetchUser returns the Plex account that owns token. It returns
// errPlexUnauthorized when Plex rejects the token.
func (p *Provider) fetchUser(ctx context.Context, token string) (*plexUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint("/api/v2/user"), nil)
	if err != nil {
		return nil, err
	}
	p.setHeaders(req)
	req.Header.Set("X-Plex-Token", token)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.New("Plex account lookup failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errPlexUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("Plex account lookup failed")
	}
	var user plexUser
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&user); err != nil {
		return nil, errors.New("Plex returned an invalid account")
	}
	return &user, nil
}

// checkEndpoint asks plex.tv for its resource list as the Silo connection
// test. It sends no token, so Plex answers 401; that still proves the service
// is reachable.
func (p *Provider) checkEndpoint(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint("/api/v2/resources?includeHttps=1"), nil)
	if err != nil {
		return errors.New("could not prepare Plex connection test")
	}
	p.setHeaders(req)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return errors.New("Plex sign-in service is unavailable")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	// A 401/403 is the expected answer without a token; anything else must be
	// a real success for the route we depend on.
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !ok && resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("Plex sign-in service returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// fetchResources lists the servers and devices the account can reach. Silo's
// Plex server appears here for its owner and for every user it is shared with.
// Plex documents clients.plex.tv for this call; plex.tv is tried first because
// it has served accounts for years, then the next host is used when the first
// answer carries no server at all.
func (p *Provider) fetchResources(ctx context.Context, token string) ([]plexResource, error) {
	hosts := p.resourceHosts
	if len(hosts) == 0 {
		hosts = []string{p.apiBaseURL}
	}
	var (
		best     []plexResource
		lastErr  error
		answered bool
	)
	for _, host := range hosts {
		resources, err := p.fetchResourcesAt(ctx, host, token)
		if err != nil {
			// A rejected token is final: another host would say the same.
			if errors.Is(err, errPlexUnauthorized) {
				return nil, err
			}
			lastErr = err
			continue
		}
		answered = true
		if hasServerResource(resources) {
			return resources, nil
		}
		if len(resources) > len(best) {
			best = resources
		}
	}
	if answered {
		return best, nil
	}
	return nil, lastErr
}

// fetchResourcesAt performs one resource listing against an explicit Plex host.
func (p *Provider) fetchResourcesAt(ctx context.Context, base, token string) ([]plexResource, error) {
	endpoint := strings.TrimRight(base, "/") + "/api/v2/resources?includeHttps=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	p.setHeaders(req)
	req.Header.Set("X-Plex-Token", token)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.New("Plex server lookup failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errPlexUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("Plex server lookup failed")
	}
	var resources []plexResource
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&resources); err != nil {
		return nil, errors.New("Plex returned an invalid server list")
	}
	return resources, nil
}

// hasServerResource reports whether any registration describes a media server.
func hasServerResource(resources []plexResource) bool {
	for _, resource := range resources {
		if isServerResource(resource) {
			return true
		}
	}
	return false
}

// setHeaders adds the client identification headers Plex expects on every
// request. The account token, when needed, is added by the caller.
func (p *Provider) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Plex-Client-Identifier", clientID)
	req.Header.Set("X-Plex-Product", productName)
	req.Header.Set("X-Plex-Version", Version)
}

// plexUserList decodes a Plex field that holds either one user or a list.
type plexUserList []plexUser

// UnmarshalJSON accepts null, a single user object or an array of users.
func (list *plexUserList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*list = nil
		return nil
	}
	if data[0] == '[' {
		var users []plexUser
		if err := json.Unmarshal(data, &users); err != nil {
			return err
		}
		*list = users
		return nil
	}
	var user plexUser
	if err := json.Unmarshal(data, &user); err != nil {
		return err
	}
	*list = []plexUser{user}
	return nil
}

// fetchHomeUsers lists the members of the owner's Plex Home. Plex answers with
// either a bare array or an object wrapping it; both are accepted.
func (p *Provider) fetchHomeUsers(ctx context.Context, token string) ([]plexUser, error) {
	data, err := p.fetchPlexJSON(ctx, "/api/v2/home/users", token)
	if err != nil {
		return nil, err
	}
	var users []plexUser
	if json.Unmarshal(data, &users) == nil {
		return users, nil
	}
	var wrapper struct {
		Users []plexUser `json:"users"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, errors.New("Plex returned an invalid Home user list")
	}
	return wrapper.Users, nil
}

// sharedPlexUser is a user the owner shares a server with. Shared is true only
// when that server is the one selected for Silo sign-in.
type sharedPlexUser struct {
	plexUser
	Shared bool
}

// fetchSharedServerUsers lists every user who accepted a share of one of the
// owner's servers, marking those who can reach serverMachineID.
func (p *Provider) fetchSharedServerUsers(ctx context.Context, token, serverMachineID string) ([]sharedPlexUser, error) {
	data, err := p.fetchPlexJSON(ctx, "/api/v2/shared_servers/owned/accepted", token)
	if err != nil {
		return nil, err
	}
	type sharedServer struct {
		MachineIdentifier string       `json:"machineIdentifier"`
		Invited           plexUserList `json:"invited"`
	}
	var servers []sharedServer
	if json.Unmarshal(data, &servers) != nil {
		var wrapper struct {
			SharedServers []sharedServer `json:"sharedServers"`
		}
		if err := json.Unmarshal(data, &wrapper); err != nil {
			return nil, errors.New("Plex returned an invalid shared server list")
		}
		servers = wrapper.SharedServers
	}
	var users []sharedPlexUser
	for _, server := range servers {
		for _, user := range server.Invited {
			users = append(users, sharedPlexUser{user, serverMachineID != "" && server.MachineIdentifier == serverMachineID})
		}
	}
	return users, nil
}

// fetchPlexJSON performs an authenticated GET on plex.tv and returns the body,
// capped at 2 MiB. It returns errPlexUnauthorized when Plex rejects the token.
func (p *Provider) fetchPlexJSON(ctx context.Context, path, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint(path), nil)
	if err != nil {
		return nil, err
	}
	p.setHeaders(req)
	req.Header.Set("X-Plex-Token", token)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, errors.New("Plex user directory is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errPlexUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("Plex user directory is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, errors.New("Plex user directory could not be read")
	}
	return data, nil
}
