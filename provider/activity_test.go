package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNewRefUsesTheAlphabet(t *testing.T) {
	seen := map[string]bool{}
	for range 500 {
		ref := newRef()
		if len(ref) != refLength {
			t.Fatalf("ref %q has length %d", ref, len(ref))
		}
		for _, r := range ref {
			if !strings.ContainsRune(refAlphabet, r) {
				t.Fatalf("ref %q contains %q", ref, r)
			}
		}
		seen[ref] = true
	}
	if len(seen) < 490 {
		t.Fatalf("refs repeat too often: %d unique of 500", len(seen))
	}
	for _, c := range "0O1IL" {
		if strings.ContainsRune(refAlphabet, c) {
			t.Fatalf("alphabet contains look-alike %q", c)
		}
	}
}

func TestPushActivityKeepsNewestHundred(t *testing.T) {
	var entries []ActivityEntry
	for i := range maxActivity + 20 {
		entries = pushActivity(entries, ActivityEntry{Ref: fmt.Sprint(i), At: time.Now(), UUID: "u-1"})
	}
	if len(entries) != maxActivity || entries[0].Ref != fmt.Sprint(maxActivity+19) || entries[maxActivity-1].Ref != "20" {
		t.Fatalf("len=%d first=%s last=%s", len(entries), entries[0].Ref, entries[len(entries)-1].Ref)
	}
}

func TestUntrustedAttributedFailuresCannotEvictRealDecisions(t *testing.T) {
	var entries []ActivityEntry
	entries = pushActivity(entries, ActivityEntry{Ref: "REAL", At: time.Now(), UUID: "u-real", Outcome: outcomeAllow})
	for i := 0; i < maxAnonymous+5; i++ {
		entries = pushActivity(entries, ActivityEntry{
			Ref: newRef(), At: time.Now(), UUID: "u-attacker", Reason: ReasonExpired, Outcome: outcomeRefuse,
		})
	}
	found := false
	untrusted := 0
	for _, entry := range entries {
		found = found || entry.Ref == "REAL"
		if entry.Reason == ReasonExpired || entry.Reason == ReasonClaimed || entry.UUID == "" {
			untrusted++
		}
	}
	if !found || untrusted > maxAnonymous || len(entries) > maxAnonymous+1 {
		t.Fatalf("real decision kept=%v, untrusted=%d, entries=%d", found, untrusted, len(entries))
	}
}

func TestNewActivityHoldsNoSecrets(t *testing.T) {
	yes := true
	user := plexUser{UUID: "u-1", Username: "alex", Title: "Alex", Email: "alex@example.test", Confirmed: &yes, Thumb: "https://evil.example/x"}
	allowed := newActivity("ABC234", Decision{Allowed: true, Rule: RuleServer}, user)
	if allowed.Outcome != outcomeAllow || allowed.Rule != RuleServer || allowed.Reason != ReasonNone || allowed.Thumb != "" {
		t.Fatalf("allowed = %+v", allowed)
	}
	refused := newActivity("ABC234", Decision{Reason: ReasonNotAllowed}, user)
	if refused.Outcome != outcomeRefuse || refused.Reason != ReasonNotAllowed {
		t.Fatalf("refused = %+v", refused)
	}
	if strings.Contains(fmt.Sprintf("%+v", refused), "example.test") {
		t.Fatal("activity must not hold an email")
	}
}

func TestRecordActivityStoresNewestFirst(t *testing.T) {
	p := New()
	p.state = newFakeStore()
	ctx := context.Background()
	p.recordActivity(ctx, ActivityEntry{Ref: "AAAAAA", At: time.Now()})
	p.recordActivity(ctx, ActivityEntry{Ref: "BBBBBB", At: time.Now()})
	entries, err := p.loadActivity(ctx)
	if err != nil || len(entries) != 2 || entries[0].Ref != "BBBBBB" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	p.state = nil
	p.recordActivity(ctx, ActivityEntry{Ref: "CCCCCC", At: time.Now()}) // must not panic or block
}

func TestActivityRetentionDropsOldDecisions(t *testing.T) {
	now := time.Now()
	old := ActivityEntry{Ref: "OLD111", At: now.Add(-activityRetention - time.Hour), Outcome: outcomeRefuse, Reason: ReasonNotAllowed, UUID: "u-old"}
	fresh := ActivityEntry{Ref: "NEW222", At: now.Add(-time.Hour), Outcome: outcomeRefuse, Reason: ReasonNotAllowed, UUID: "u-new"}

	p := New()
	store := withAccess(t, p, Settings{}, "")
	store.put(t, activityKey, []ActivityEntry{old, fresh})
	entries, err := p.loadActivity(context.Background())
	if err != nil || len(entries) != 1 || entries[0].Ref != "NEW222" {
		t.Fatalf("expired decisions must not be returned: %+v %v", entries, err)
	}

	pushed := pushActivity([]ActivityEntry{old}, fresh)
	if len(pushed) != 1 || pushed[0].Ref != "NEW222" {
		t.Fatalf("expired decisions must not be stored again: %+v", pushed)
	}
}

func TestActivityDocumentVersion(t *testing.T) {
	legacy := []byte(`[{"ref":"OLD111","at":"2026-01-01T00:00:00Z","outcome":"refused","reason":"not_allowed"}]`)
	if entries, err := decodeActivity(legacy); err != nil || len(entries) != 1 || entries[0].Ref != "OLD111" {
		t.Fatalf("legacy array must still decode: %+v %v", entries, err)
	}
	document := []byte(`{"version":1,"entries":[{"ref":"NEW222","at":"2026-01-01T00:00:00Z"}]}`)
	if entries, err := decodeActivity(document); err != nil || len(entries) != 1 || entries[0].Ref != "NEW222" {
		t.Fatalf("versioned document must decode: %+v %v", entries, err)
	}
	if _, err := decodeActivity([]byte(`{"version":2,"entries":[]}`)); err == nil {
		t.Fatal("a newer activity version must fail closed")
	}
}
