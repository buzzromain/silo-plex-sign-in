package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
)

// fakeStore is an in-memory instance state with versions, like Silo's.
// UpdateInstanceState retries on conflict as the SDK does.
type fakeStore struct {
	mu          sync.Mutex
	values      map[string][]byte
	versions    map[string]int64
	unversioned bool
	failReads   bool
	writes      int
}

func newFakeStore() *fakeStore {
	return &fakeStore{values: map[string][]byte{}, versions: map[string]int64{}}
}

func (f *fakeStore) ReadInstanceState(_ context.Context, key string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failReads {
		return nil, false, errors.New("state down")
	}
	v, ok := f.values[key]
	return append([]byte(nil), v...), ok, nil
}

func (f *fakeStore) WriteInstanceState(_ context.Context, key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[key] = append([]byte(nil), value...)
	f.versions[key]++
	f.writes++
	return nil
}

func (f *fakeStore) UpdateInstanceState(ctx context.Context, key string, update func([]byte, bool) ([]byte, error)) error {
	if f.unversioned {
		return runtimehost.ErrInstanceStateUnversioned
	}
	for range 50 {
		f.mu.Lock()
		if f.failReads {
			f.mu.Unlock()
			return errors.New("state down")
		}
		current, found, version := append([]byte(nil), f.values[key]...), false, f.versions[key]
		_, found = f.values[key]
		f.mu.Unlock()
		next, err := update(current, found)
		if err != nil {
			return err
		}
		f.mu.Lock()
		if f.versions[key] == version {
			f.values[key] = next
			f.versions[key]++
			f.writes++
			f.mu.Unlock()
			return nil
		}
		f.mu.Unlock()
	}
	return runtimehost.ErrInstanceStateConflict
}

func (f *fakeStore) put(t *testing.T, key string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	f.values[key] = data
	f.versions[key]++
}

func TestConcurrentUpdatesKeepEveryEntry(t *testing.T) {
	store := newFakeStore()
	p := New()
	p.state = store
	ctx := context.Background()
	if err := p.updateSettings(ctx, func(s *Settings) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := p.updateSettings(ctx, func(s *Settings) error {
				return s.add(ManualEntry{Input: fmt.Sprintf("user%d", i)})
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	settings, err := p.loadSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.Manual) != 40 || settings.Version != settingsVersion {
		t.Fatalf("lost entries: %d", len(settings.Manual))
	}
}

func TestUnversionedHostFallsBackToPlainWrite(t *testing.T) {
	store := newFakeStore()
	store.unversioned = true
	p := New()
	p.state = store
	ctx := context.Background()
	if err := p.updateSettings(ctx, func(s *Settings) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if settings, err := p.loadSettings(ctx); err != nil || settings.Version != settingsVersion {
		t.Fatalf("settings=%+v err=%v", settings, err)
	}
}

func TestNoChangeLeavesStateUntouched(t *testing.T) {
	store := newFakeStore()
	p := New()
	p.state = store
	ctx := context.Background()
	if _, err := p.loadSettings(ctx); err != nil {
		t.Fatal(err)
	}
	before := store.writes
	if err := p.updateSettings(ctx, func(*Settings) error { return errNoChange }); err != nil {
		t.Fatal(err)
	}
	if store.writes != before {
		t.Fatal("errNoChange must not write")
	}
}

func TestStateSchemaVersionsFailClosed(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	p := New()
	p.state = store

	store.put(t, settingsKey, Settings{Version: settingsVersion + 1})
	if _, err := p.loadSettings(ctx); err == nil {
		t.Fatal("unknown settings schema version must not be read as the current format")
	}
	if err := p.updateSettings(ctx, func(s *Settings) error {
		return s.add(ManualEntry{Input: "person"})
	}); err == nil {
		t.Fatal("unknown settings schema version must not be overwritten")
	}

	store.put(t, connectionKey, plexConnection{Version: connectionVersion + 1, ServerMachineID: "future-server", OwnerToken: "future-token"})
	if _, err := p.loadConnection(ctx); err == nil {
		t.Fatal("unknown connection schema version must not be read as the current format")
	}
	if err := p.saveConnection(ctx, plexConnection{ServerMachineID: "replacement"}); err == nil {
		t.Fatal("unknown connection schema version must not be overwritten")
	}
}

func TestStateUnavailable(t *testing.T) {
	p := New()
	p.state = nil
	if _, err := p.loadSettings(context.Background()); err == nil {
		t.Fatal("missing host must be an error")
	}
	store := newFakeStore()
	store.failReads = true
	p.state = store
	if _, _, err := p.accessState(context.Background()); err == nil {
		t.Fatal("failing reads must be an error")
	}
}

func TestConnectionRoundTripAndDisconnectKeepsSettings(t *testing.T) {
	p := New()
	p.state = newFakeStore()
	ctx := context.Background()
	if err := p.updateSettings(ctx, func(s *Settings) error {
		return s.add(ManualEntry{Input: "alex"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.saveConnection(ctx, plexConnection{ServerMachineID: " srv ", ServerName: "Home", OwnerToken: "tok"}); err != nil {
		t.Fatal(err)
	}
	c, err := p.loadConnection(ctx)
	if err != nil || c.ServerMachineID != "srv" || c.OwnerToken != "tok" {
		t.Fatalf("connection=%+v err=%v", c, err)
	}
	if err := p.saveConnection(ctx, plexConnection{}); err != nil {
		t.Fatal(err)
	}
	settings, _ := p.loadSettings(ctx)
	if len(settings.Manual) != 1 {
		t.Fatalf("disconnect must keep settings: %+v", settings)
	}
}
