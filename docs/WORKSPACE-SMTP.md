# Workspace SMTP

Workspace owners configure their own outgoing document-email transport in the
owner session API. This is separate from the installation transport used for
account authentication and recovery. No endpoint returns stored SMTP usernames,
passwords or ciphertext. Settings and credentials are encrypted together using
the existing application encryption key and purpose/organization/revision binding.
Keep that key and its existing rotation predecessor available for retained settings.

`GET /api/v1/workspace-smtp` returns revision, mode, safe host/TLS/sender metadata
and `username_set`/`password_set` booleans. `configured` means the workspace has its
own configuration; it does not prove a successful connection or mailbox delivery.
Responses are `Cache-Control: no-store` and require a live owner signed session.
There is no document-token or machine-key configuration endpoint.

`PUT /api/v1/workspace-smtp` requires `expected_revision`, `host`, `port`,
`tls_mode`, `sender_name`, `sender_email`, and `credentials_action`:

- `keep` omits both username/password properties and retains credentials only for
  the unchanged normalized host, port and TLS mode. Changing the endpoint requires
  explicit credential re-entry, preventing redirection of a stored secret.
- `replace` requires both `username` and `password` strings. Both empty explicitly
  selects an unauthenticated TLS relay; a partial credential pair is refused.

Ports/modes are `587`/`starttls` and `465`/`tls`. Both verify the server certificate
and hostname, require TLS1.2 or newer, and cap each attempt at30 seconds. The exact
resolved connect IP is checked by the shared public-egress guard on every dial;
private, loopback, link-local and shared-address destinations are refused in
production. Only the existing operator-selected local-development mode permits
private dialing; it does not disable certificate verification. There is no
per-workspace network or TLS-verification bypass.

UTF-8 byte limits are host253, sender name200, sender address254, username256 and
password4096. Host is an ASCII DNS name or IP. Sender email is a single addr-spec;
newlines and control characters are refused. Conflicts return409 and require
reload/review. `DELETE /api/v1/workspace-smtp` takes `expected_revision`, removes
the encrypted configuration and advances to `disabled`; it never restores an
installation-sender fallback.

## Synthetic connection test

`POST /api/v1/workspace-smtp/test` takes only `expected_revision`. It queues one
fixed, clearly synthetic message to the authenticated owner's current email.
The API accepts no recipient, subject, HTML or document data. It requires the
workspace's configured transport, permits one pending test and one request per60
seconds, and returns202 with a delivery ID. No SMTP operation occurs inside the
HTTP transaction. The worker rechecks the retained request's owner/email and
settings revision before the bounded attempt.

`GET /api/v1/workspace-smtp/test/{id}` reads that owner's scoped request status.
`pending`/`retrying` do not mean delivered. `smtp_accepted: true` means only that
the SMTP server accepted DATA; `inbox_delivery_confirmed` remainsfalse. A timeout
or unknown request outcome is not permission to repeat the POST automatically.

## Compatibility and deployment

Migration120 explicitly classifies only pre-existing outbox messages as retained
installation mail and only pre-existing workspaces as installation-compatible.
New workspaces must configure their own transport; new unattributed document mail
is refused. All ordinary producers stamp their actual native organization ID.
The worker uses that immutable route and never infers tenant identity from an
address, display name or header. Sealed account-recovery messages have a separate
explicit installation-authentication purpose.

A database claim nonce prevents a surviving older worker from leasing workspace
mail and sending it through its installation sender. New native claim/retry SQL
advances that nonce every attempt; older statements fail atomically before the
lease or network dispatch, including mixed batches. Rollback refuses retained
workspace settings, encrypted secrets, test requests or scoped outbox routes.
The empty/legacy-only Down preserves original authentication and message data.
This module adds no tracking, SMTP provider credentials, billing defaults, AI
provider calls, email-content replacement at delivery or full-layout editor.
