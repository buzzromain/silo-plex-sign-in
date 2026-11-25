package provider

import (
	"context"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

func TestInitAuthorizeRefusesBeyondMaxFlows(t *testing.T) {
	p := testProvider((&fakePlex{userJSON: fullUser}).server(t))
	p.mu.Lock()
	for i := 0; i < maxFlows; i++ {
		p.flows[string(rune('a'+i%26))+time.Duration(i).String()] = &pendingFlow{expiresAt: time.Now().Add(time.Minute)}
	}
	p.mu.Unlock()
	_, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{State: signedSiloState(t, "inst-1"), RedirectUri: "https://silo.example.test/api/v2/auth/oauth/inst-1/callback"})
	if err == nil {
		t.Fatal("flow accepted beyond the limit")
	}
	p.mu.Lock()
	for id := range p.flows {
		p.flows[id].expiresAt = time.Now().Add(-time.Second)
	}
	p.mu.Unlock()
	if _, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{State: signedSiloState(t, "inst-1"), RedirectUri: "https://silo.example.test/api/v2/auth/oauth/inst-1/callback"}); err != nil {
		t.Fatalf("expired flows must free room: %v", err)
	}
}

func TestAnonymousActivityCannotEvictRealDecisions(t *testing.T) {
	var entries []ActivityEntry
	entries = pushActivity(entries, ActivityEntry{Ref: "REAL", UUID: "u-1", Outcome: outcomeRefuse})
	for i := 0; i < 500; i++ {
		entries = pushActivity(entries, ActivityEntry{Ref: newRef(), Outcome: outcomeRefuse})
	}
	found := false
	for _, e := range entries {
		found = found || e.Ref == "REAL"
	}
	if !found || len(entries) > maxAnonymous+1 {
		t.Fatalf("real entry kept=%v, len=%d", found, len(entries))
	}
}

func TestExpiredFlowDropsPlexToken(t *testing.T) {
	p := New()
	p.flows["f"] = &pendingFlow{token: "secret", expiresAt: time.Now().Add(-time.Second)}
	p.lookupFlow("f", "")
	if p.flows["f"].token != "" {
		t.Fatal("token kept after expiry")
	}
}

func TestResponsesDenyFraming(t *testing.T) {
	if got := httpResponse(200, contentTypeText, "").Headers["X-Frame-Options"]; got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
}
