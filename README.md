# Plex Sign-In for Silo

Plex Sign-In v0.1.0 is a community Silo plugin that adds a **Plex** button to
the Silo sign-in page. People sign in with their Plex account, and only people
you allow can get in: those Plex reports as able to access the server selected
in Silo, and people you add to a manual list.

> **Unofficial plugin.** Plex Sign-In is an independent community project. It
> is not a Plex product and is not affiliated with, sponsored, or endorsed by
> Plex, Inc. or by Silo. Plex and the Plex logo are trademarks of Plex, Inc.
> The Plex name and icon are used only to identify the service people sign in
> with. For help with this plugin, use this repository's issues, not Plex or
> Silo support.

![Plex Sign-In administration, Users tab](docs/screenshots/en-1440-people.png)

## What it does

- Adds a **Plex** login button to Silo (`auth_provider.v1`).
- People approve the sign-in on Plex's own website, so the plugin never sees
  their Plex password.
- After approval, the plugin allows the sign-in only when one of these sources
  matches:
  - **Selected Plex server**: Plex reports that the person can access the
    specific Plex Media Server selected in Silo. The plugin does not check
    access library by library;
  - **Manual list**: the person's Plex username, or confirmed Plex email, is on
    the list you manage, whether or not they can access that server.
- The **Users** tab can show the owner, eligible Plex Home members, and people
  invited to shares on any server owned by the connected Plex account. This is
  the owner's visible directory, not a list of everyone allowed by the
  selected-server rule. People in that directory who lack access to the
  selected server need to be added to the manual list to sign in.
- Plex Home managed users and guest accounts are always refused.
- Silo creates or links the Silo account; the plugin never assigns Silo roles
  or groups.
- Adds a **Plex Sign-In** page to Silo's administration (`http_routes.v1`) to
  connect the server, manage the manual list and review recent sign-ins.

The plugin reads Plex account and access information and creates sign-in PINs.
It never creates shares, sends invitations or changes Plex settings. The
interface is in English.

## Requirements

- A Silo server reachable over **HTTPS**. Sign-in is refused when Silo's
  callback URL is not HTTPS.
- Linux on amd64 or arm64.
- To allow a server's users: the Plex account that owns that Plex Media Server.
  The manual list works without it.

## Installation

**Planned distribution:** after the GitHub repository is created, the intended
installation path is Silo's plugin administration. The planned GitHub releases
will provide `plugin-linux-amd64` and `plugin-linux-arm64` binaries with a
`checksums.txt` file. Templates, styles and the icon are built into the binary;
there will be nothing else to install. The repository and its releases are not
publicly available yet, so catalog installation is not currently available.

## Usage

### Set up access

Open **Plex Sign-In** from Silo's administration navigation. The page has
three tabs.

- **Plex**: choose **Connect Plex**, approve the request on Plex with the
  account that owns your server, then select the server. People Plex reports as
  able to access that server can sign in. **Change server** picks another one;
  **Disconnect** forgets the stored Plex connection and keeps the manual list.
- **Users**: the list shows people allowed by the selected server, manual
  entries, and the owner account's visible Plex directory. That directory
  includes eligible Plex Home members and people invited to shares on any
  server owned by the connected account. People shared on another server are
  not automatically allowed by the selected-server rule. You can add them to
  the manual list. Each person's Plex ID and email appear after their first
  sign-in; a changed email is refreshed on later sign-ins.
- **Activity**: the latest 100 sign-in decisions, allowed or denied. A denied
  person can be added to the manual list from here with **Allow sign-in**,
  without changing Plex sharing. Once the person is on the manual list, the
  button becomes **Added to manual list** and their denied attempts stop
  counting in the tab badge.

The admin badge reports whether an access source is configured; it does not
check whether Plex is currently reachable or whether the owner's token is
valid. A server or one manual entry is enough to configure access, but sign-in
still depends on the required Plex requests succeeding. Until an access source is configured, every
Plex sign-in is refused.

Sign-in and server-connection flows are held in process memory for up to 10
minutes. If Silo routes a flow's return or polling request to another plugin
process, that process will not have the flow; the person must restart the
sign-in. Deployments with multiple plugin processes should use session affinity
for these routes, if available.

### Sign in

1. The person chooses **Plex** on the Silo sign-in page.
2. Plex opens and asks them to approve the request.
3. The plugin checks their account against the server and the manual list.
4. If they are allowed, Silo signs them in. If not, the page shows a short
   **sign-in reference** they can send to the administrator, who finds the same
   reference in **Activity**.

### Silo accounts

With Silo auto-provisioning enabled, a first sign-in can create a Silo account
from the Plex username, email and display name. Silo assigns its default group.

To link an existing Silo account instead, copy the person's Plex ID from
**Users** after their first sign-in and use Silo's own account-linking screen.
The plugin cannot see Silo accounts and does not call Silo's administration
API. If the Silo operator enables it, Silo may also match a confirmed Plex
email to an existing account.

### Access re-checks

Silo re-checks existing accounts from time to time. The plugin answers with the
person's Plex account, using the Plex token Silo kept from their sign-in:

- if Plex confirms that the person no longer matches the server or the manual
  list, access is withdrawn and Silo ends their sessions;
- if Plex cannot be reached, or the stored token no longer works, nobody is
  signed out by the plugin; Silo applies its own session limits.

## External services and network access

The plugin makes outbound HTTPS requests to `https://plex.tv`, and to the
`https://clients.plex.tv` address Plex documents for client resource lookups
when the first host returns no server:

- `POST /api/v2/pins` and `GET /api/v2/pins/<id>`: create and poll the sign-in
  PIN;
- `GET /api/v2/user`: read the signed-in Plex account;
- `GET /api/v2/resources`: check whether the account can reach the selected
  Plex Media Server, list the owner's servers when connecting, and probe
  Plex's availability for Silo's connection test;
- `GET /api/v2/home/users` and `GET /api/v2/shared_servers/owned/accepted`:
  list the connected owner's Plex Home members and users who accepted shares
  on any of that owner's servers, for the **Users** tab;

The person's browser is sent to `https://app.plex.tv` to approve the request.
The plugin contacts no other service and never connects to a Plex Media Server
directly.

## Data and privacy

- **Sent to Silo at sign-in:** Plex account ID, username, display name, email
  with Plex's confirmation status, avatar URL, and the person's Plex token.
  The plugin holds the token briefly in memory while finishing the flow, then
  returns it to Silo as refresh state. Silo stores it and sends it back for
  re-checks; the plugin does not persist the person's token.
- **Stored by the plugin in Silo instance state:** the manual list — what the
  administrator typed, plus the Plex account ID, username, display name,
  email, and avatar Plex returns for that person — the selected server, the
  server owner's Plex token, and the activity log. Silo is responsible for
  protecting its instance state.
- **Activity log:** stores the newest 100 sign-in attempts, not a fixed number
  of days. New attempts evict older entries. It records the Plex account ID and
  limited display fields, plus opaque lookup keys used to match an attempt
  with the manual list (a matching aid, not anonymisation); untrusted failures
  are capped separately.
- **Owner token:** used to read server-access information. **Disconnect**
  forgets it in the plugin; signing out of Silo does not revoke Plex tokens.
- **Pending sign-ins** are kept in memory for up to 10 minutes. After Plex
  approval, the person's Plex token is held in memory until Silo exchanges the
  one-time code or the flow expires; it is then returned to Silo as refresh
  state and is not persisted by the plugin. A plugin restart can require the
  person to start again.
- Sign-in uses Plex's PIN approval, not OpenID Connect. Keep plugin and OAuth
  callback URLs out of access logs and diagnostic captures: they carry
  short-lived sign-in values.
- A Plex sign-in uses a PIN approval. A person can be tricked into approving a
  PIN requested by someone else. Only approve a Plex request if they started
  this sign-in themselves and recognize the Silo server. After approval, the
  browser that opened the flow can finish it. Flows expire after 10 minutes.
- The server rule trusts what Plex reports for each account. A server the
  account owns only counts for the Plex account that connected it, so another
  person cannot get in by running a server with the same identifier.

Operators should provide their own retention and privacy information suited to
their deployment.

## Screenshots

The screenshots in [`docs/screenshots`](docs/screenshots/README.md) use
synthetic test data only: no real Plex identities, email addresses, tokens,
PINs or server URLs. They show the plugin's pages, not Plex's website.

## Development

Requires Go 1.26.11 or newer. No frontend build step is needed.

```sh
gofmt -l .
go vet ./...
go test -race -count=1 ./...
go run . manifest       # print the manifest with its HTTP routes
make check-version      # manifest.json, provider.Version and README agree
make build build-arm64  # dist/plugin-linux-amd64, dist/plugin-linux-arm64
```

Tests use local fake servers; they never contact plex.tv or a real Silo.

## Releases

Releases are built, signed and published by Silo's shared plugin release
workflow ([`.github/workflows/release.yml`](.github/workflows/release.yml)):

1. Merge a change that sets the new `version` in `manifest.json` and
   `provider.Version`.
2. Push the matching `v<version>` tag on `main`.

The workflow requires each release to raise the version and attaches the
binaries, `checksums.txt` and a signed provenance bundle to the GitHub release.

## Security

Report vulnerabilities privately; see [`SECURITY.md`](SECURITY.md).

## Support

Use this repository's
[issues](https://github.com/buzzromain/silo-plugin-auth-plex/issues) for
questions and bug reports about the plugin.

## License

Copyright (C) 2026 buzzromain

Plex Sign-In is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. It is distributed WITHOUT ANY WARRANTY; see [`LICENSE`](LICENSE)
for details. Third-party dependencies keep their own licenses.
