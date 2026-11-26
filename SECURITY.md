# Security Policy

Please do not report security vulnerabilities in a public issue.

Use GitHub's private vulnerability reporting for this repository: open the
**Security** tab and choose **Report a vulnerability**.

Only the latest release is supported with security fixes.

## Scope

Plex Sign-In handles Plex sign-in flows and access decisions for Silo. Reports
about the following are in scope:

- the connected Plex owner's token stored in Silo instance state: how it is
  stored, transmitted, logged or exposed;
- each person's Plex token passed to Silo as refresh state and used by account re-checks;
- the sign-in flow: state and callback validation, the one-time code, flow
  expiry and browser binding;
- access decisions: a person signing in without access to the selected Plex
  server or the manual list, or a managed or guest account being accepted;
- the administration pages: access control, form protection and escaping;
- the Plex account data passed to Silo or kept in the activity log.

Public sign-in starts are limited by a global cap of 1,000 pending flows, but
the plugin does not apply a per-client rate limit. Deployments should apply
request throttling at a trusted Silo or reverse-proxy boundary to reduce PIN
creation bursts and protect the shared Plex client identity from rate limits.
The plugin sets anti-framing headers on its responses, but the Silo
plugin-content proxy may not forward them; verify the headers on the browser-
facing response before relying on them to protect the admin pages.

Plex PIN approval carries a phishing risk: a person can be tricked into
approving a PIN requested by someone else. Only approve a Plex request if you
started the sign-in yourself and recognize the Silo server. After approval,
the browser that opened the flow completes the Silo sign-in. See the README
for user guidance.

Vulnerabilities in Plex or Silo themselves should be reported to those
projects. This plugin is not affiliated with Plex, Inc. or Silo.
