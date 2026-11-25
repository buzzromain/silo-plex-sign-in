// Command plex-sign-in is the Plex Sign-In plugin binary for Silo.
//
// Run without arguments, it serves the plugin to Silo. Run as
// "plugin manifest", it prints the manifest with its HTTP routes.
package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/buzzromain/silo-plugin-auth-plex/provider"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed manifest.json
var manifestJSON []byte

// manifestWithHTTPRoutes loads manifest.json with the build's version and adds
// the HTTP routes: public sign-in pages and assets, admin-only pages.
func manifestWithHTTPRoutes() (*pluginv1.PluginManifest, error) {
	m, err := manifest.LoadWithChecksum(manifestJSON, version)
	if err != nil {
		return nil, err
	}
	if err := manifest.RegisterHTTPRoutes(m,
		&pluginv1.HttpRouteDescriptor{Id: "plex-start", Method: "GET", Path: "/plex/start", Access: "public"},
		&pluginv1.HttpRouteDescriptor{Id: "plex-status", Method: "POST", Path: "/plex/status", Access: "public"},
		&pluginv1.HttpRouteDescriptor{Id: "plex-assets", Method: "GET", Path: "/assets/*", Access: "public"},
		&pluginv1.HttpRouteDescriptor{Id: "access-page", Method: "GET", Path: "/admin/access", Access: "admin", Navigable: true, NavigationLabel: "Plex Sign-In", NavigationKind: "admin"},
		&pluginv1.HttpRouteDescriptor{Id: "people-add", Method: "POST", Path: "/admin/people/add", Access: "admin"},
		&pluginv1.HttpRouteDescriptor{Id: "people-remove", Method: "POST", Path: "/admin/people/remove", Access: "admin"},
		&pluginv1.HttpRouteDescriptor{Id: "activity-allow", Method: "POST", Path: "/admin/activity/allow", Access: "admin"},
		&pluginv1.HttpRouteDescriptor{Id: "plex-disconnect", Method: "POST", Path: "/admin/plex/disconnect", Access: "admin"},
		&pluginv1.HttpRouteDescriptor{Id: "find-server-page", Method: "GET", Path: "/admin/find-server", Access: "admin"},
		&pluginv1.HttpRouteDescriptor{Id: "find-server-start", Method: "POST", Path: "/admin/find-server/start", Access: "admin"},
		&pluginv1.HttpRouteDescriptor{Id: "find-server-poll", Method: "POST", Path: "/admin/find-server/poll", Access: "admin"},
		&pluginv1.HttpRouteDescriptor{Id: "find-server-select", Method: "POST", Path: "/admin/find-server/select", Access: "admin"},
	); err != nil {
		return nil, err
	}
	return m, nil
}

// main prints the manifest with "manifest", otherwise serves the plugin to
// Silo over the plugin runtime.
func main() {
	if len(os.Args) > 1 && os.Args[1] == "manifest" {
		m, err := manifestWithHTTPRoutes()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		out, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(m)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}
	flag.Parse()
	p := provider.New()
	m, err := manifestWithHTTPRoutes()
	if err != nil {
		panic(err)
	}
	manifestBytes, err := (protojson.MarshalOptions{}).Marshal(m)
	if err != nil {
		panic(err)
	}
	runtime.ServeManifestWithOptions(manifestBytes, version, runtime.CapabilityServers{AuthProvider: p, HttpRoutes: p},
		runtime.WithAuthProviderChecks(p),
		runtime.WithConfigure(p.Configure),
	)
}

const version = provider.Version

var _ pluginv1.AuthProviderServer = (*provider.Provider)(nil)
var _ pluginv1.AuthProviderChecksServer = (*provider.Provider)(nil)
var _ pluginv1.HttpRoutesServer = (*provider.Provider)(nil)
