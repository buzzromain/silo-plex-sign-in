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

Known and accepted: a person who approves on Plex a sign-in link someone else
sent them signs that sender in as themselves. This is inherent to Plex's PIN
approval and is described in the README.

Vulnerabilities in Plex or Silo themselves should be reported to those
projects. This plugin is not affiliated with Plex, Inc. or Silo.
