package provider

// Persistence: settings and the Plex owner connection in Silo instance state.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	sdkruntime "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtimehost"
)

// Instance-state keys. All values live in Silo's encrypted instance state.
const (
	settingsKey   = "plex/settings/v1"
	connectionKey = "plex/connection/v1"
)

// stateStore is the part of Silo's runtime host the plugin uses for its
// instance state. *runtimehost.Client implements it.
type stateStore interface {
	ReadInstanceState(ctx context.Context, key string) ([]byte, bool, error)
	WriteInstanceState(ctx context.Context, key string, value []byte) error
	UpdateInstanceState(ctx context.Context, key string, update func(current []byte, found bool) ([]byte, error)) error
}

// errStateUnavailable means Silo's instance state cannot be reached.
var errStateUnavailable = errors.New("instance state is unavailable")

// errNoChange lets an update function leave the stored value as it is.
var errNoChange = errors.New("no change")

var unversionedOnce sync.Once

// store returns the state store: the test double when set, otherwise Silo's
// host connection, or nil outside Silo.
func (p *Provider) store() stateStore {
	if p.state != nil {
		return p.state
	}
	if host := sdkruntime.Host(); host != nil {
		return host
	}
	return nil
}

// update applies fn to the value stored at key with UpdateInstanceState, so
// API servers sharing the state never lose each other's writes. fn may run
// several times and must have no side effects. Returning errNoChange from
// fn leaves the value untouched. On a host that keeps no versions, update
// falls back to a plain read and write and logs it once.
func (p *Provider) update(ctx context.Context, key string, fn func(current []byte, found bool) ([]byte, error)) error {
	store := p.store()
	if store == nil {
		return errStateUnavailable
	}
	err := store.UpdateInstanceState(ctx, key, fn)
	if errors.Is(err, runtimehost.ErrInstanceStateUnversioned) {
		unversionedOnce.Do(func() {
			logger.Warn("instance state has no versions; concurrent writes from several API servers may be lost")
		})
		var current []byte
		var found bool
		if current, found, err = store.ReadInstanceState(ctx, key); err != nil {
			return fmt.Errorf("read %s: %w", key, err)
		}
		var next []byte
		if next, err = fn(current, found); err == nil {
			err = store.WriteInstanceState(ctx, key, next)
		}
	}
	if errors.Is(err, errNoChange) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("update %s: %w", key, err)
	}
	return nil
}

// read loads the JSON value at key into v and reports whether it was found.
func (p *Provider) read(ctx context.Context, key string, v any) (bool, error) {
	store := p.store()
	if store == nil {
		return false, errStateUnavailable
	}
	data, found, err := store.ReadInstanceState(ctx, key)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", key, err)
	}
	if !found || len(data) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("decode %s: %w", key, err)
	}
	return true, nil
}

// loadSettings returns the stored settings, or empty settings when nothing
// has been saved yet. Unknown schema versions fail closed instead of being
// interpreted as the current format.
func (p *Provider) loadSettings(ctx context.Context) (Settings, error) {
	var settings Settings
	found, err := p.read(ctx, settingsKey, &settings)
	if err != nil {
		return Settings{}, err
	}
	if !found {
		return Settings{Version: settingsVersion}, nil
	}
	if settings.Version != settingsVersion {
		return Settings{}, fmt.Errorf("unsupported settings version %d (want %d)", settings.Version, settingsVersion)
	}
	return settings, nil
}

// updateSettings applies fn to the stored settings. fn may run several
// times; returning errNoChange leaves them untouched.
func (p *Provider) updateSettings(ctx context.Context, fn func(*Settings) error) error {
	return p.update(ctx, settingsKey, func(current []byte, found bool) ([]byte, error) {
		var settings Settings
		if found {
			if err := json.Unmarshal(current, &settings); err != nil {
				return nil, fmt.Errorf("decode settings: %w", err)
			}
			if settings.Version != settingsVersion {
				return nil, fmt.Errorf("unsupported settings version %d (want %d)", settings.Version, settingsVersion)
			}
		}
		if err := fn(&settings); err != nil {
			return nil, err
		}
		settings.Version = settingsVersion
		return json.Marshal(settings)
	})
}

// plexConnection is the Plex owner connection made with the server finder.
// Version identifies the persisted JSON schema. The owner token reads the
// owner's server directory; it is never rendered or returned to a browser.
type plexConnection struct {
	Version         int    `json:"version"`
	ServerMachineID string `json:"server_machine_id"`
	ServerName      string `json:"server_name"`
	OwnerUUID       string `json:"owner_uuid"`
	OwnerToken      string `json:"owner_token"`
	UpdatedAt       string `json:"updated_at"`
}

// loadConnection returns the stored Plex connection, or the zero value when
// Plex was never connected.
func (p *Provider) loadConnection(ctx context.Context) (plexConnection, error) {
	var connection plexConnection
	found, err := p.read(ctx, connectionKey, &connection)
	if err != nil {
		return plexConnection{}, err
	}
	if found && connection.Version != connectionVersion {
		return plexConnection{}, fmt.Errorf("unsupported connection version %d (want %d)", connection.Version, connectionVersion)
	}
	connection.ServerMachineID = strings.TrimSpace(connection.ServerMachineID)
	connection.ServerName = strings.TrimSpace(connection.ServerName)
	connection.OwnerToken = strings.TrimSpace(connection.OwnerToken)
	return connection, nil
}

// saveConnection replaces the stored Plex connection. A zero connection
// forgets it.
func (p *Provider) saveConnection(ctx context.Context, connection plexConnection) error {
	connection.Version = connectionVersion
	connection.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(connection)
	if err != nil {
		return fmt.Errorf("encode connection: %w", err)
	}
	return p.update(ctx, connectionKey, func(current []byte, found bool) ([]byte, error) {
		if found {
			var existing plexConnection
			if err := json.Unmarshal(current, &existing); err != nil {
				return nil, fmt.Errorf("decode connection: %w", err)
			}
			if existing.Version != connectionVersion {
				return nil, fmt.Errorf("unsupported connection version %d (want %d)", existing.Version, connectionVersion)
			}
		}
		return data, nil
	})
}

// accessState loads what a sign-in decision needs.
func (p *Provider) accessState(ctx context.Context) (Settings, plexConnection, error) {
	settings, err := p.loadSettings(ctx)
	if err != nil {
		return Settings{}, plexConnection{}, err
	}
	connection, err := p.loadConnection(ctx)
	if err != nil {
		return Settings{}, plexConnection{}, err
	}
	return settings, connection, nil
}

// learnManual stores the UUID and display fields of the manual entry that
// matched user at sign-in. A failure is logged and never blocks sign-in.
func (p *Provider) learnManual(ctx context.Context, user plexUser) {
	err := p.updateSettings(ctx, func(s *Settings) error {
		if !s.learn(user) {
			return errNoChange
		}
		return nil
	})
	if err != nil {
		logger.Warn("store manual entry identity", "error", err)
	}
}
