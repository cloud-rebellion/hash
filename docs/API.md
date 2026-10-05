# Hash API guide

Hash exposes separate browser, machine, signer, and webhook boundaries. Use the
[HTTP route inventory](API-ROUTES.md) to find every registered endpoint, handler,
middleware, and conditional dependency. The inventory is generated from the
router and checked with `go run ./cmd/apidocgen -check`.

## Authentication boundaries

| Surface | Authentication | Contract |
| --- | --- | --- |
| `/api/v1/*` | Sender session cookie from OIDC login | Browser API. API keys do not replace the cookie on this tree. Current membership, tenant and role are loaded on each request. |
| `/api/automation/v1/signature-requests` | Organization-wide API key | Dedicated sender/owner key with both `write:authoring` and `write:workflow`; stable `Idempotency-Key`. See [Automation API](AUTOMATION-API.md). |
| `/mcp` | API key, including supported document-scoped credentials | MCP entitlement, role, tool scopes and document scope apply independently. Discover actual tools and input schemas through MCP `tools/list`. |
| `/sign/{token}/*` | Recipient magic link | The URL token is a bearer credential bound to a recipient and ceremony. It does not grant sender or administrative access. |
| `/webhooks/brightcrm` | Timestamped HMAC and durable delivery correlation | Cache invalidation receiver; do not send an unauthenticated CRM event. Follow the current [receiver implementation](../internal/handler/brightcrm_webhook.go). |
| `/api/verify`, `/api/verify-bundle` | Anonymous through trusted production ingress | Verification does not authorize document access. Payload limits and verification rate limits apply. |

Sender login starts at `GET /auth/login` and returns through
`GET /auth/callback`. OIDC verifies the identity provider's claims; provider
configuration and allowed tenant membership must be correct before login can
work. The signed `hash_session` cookie lasts 24 hours and is `HttpOnly`,
`Secure`, and `SameSite=Strict`. Handshake cookies use their own short-lived
OIDC policy. `POST /auth/logout` requires a current session and advances the
account's database revocation generation, invalidating every existing Hash
browser cookie for that account. Collaboration sockets check that generation
on their next binary frame. A new OIDC login mints the current generation.
Browser form requests accepting HTML redirect to `/` with HTTP 303; machine
requests receive the JSON logout receipt. Database failures do not return a
successful revocation receipt.

Use HTTPS and same-origin browser requests. The browser mutation guard also
protects against requests from sibling subdomains. Supply the app's exact
`Origin`; broad CORS allowlists are not an authentication mechanism. Machine
keys use `Authorization: Bearer <key>` or the supported `X-API-Key` header on
the machine/MCP surfaces. Keep keys, signer URLs, OIDC callback query strings,
and action tokens out of logs and analytics. Production ingress additionally
authenticates the reverse proxy; external clients must not manufacture or
receive the host-only proxy credential.

## Roles and scopes

`viewer` is read-only, `sender` creates/edits/sends documents, and `owner` also
controls organization settings and membership. A role never authorizes another
tenant's document. A machine key's scopes narrow its role, and a document-scoped
credential narrows its target further. Missing scopes do not inherit full access.
See [role checks](../internal/auth/rbac.go) and
[MCP tool scopes](../internal/mcp/scope.go).

## Negotiation and legal lifecycle

Create a draft, configure its recipients/fields and lawful-basis disclosure,
review it, then send through the supported lifecycle API. Sending freezes the
ceremony content and allocates the durable notice epoch. Do not use direct
database writes to allocate `sent_at`, signatures, retention commitments, or
completion timestamps.

Send, Void, Revise and manual Remind bind the original admitted REST session or
MCP credential to the transaction. After parent/document and live-member lock
waits, they recheck current sender/owner membership and that same credential,
then check again immediately before commit. Session checks include the signed
identity, revocation generation and expiry. Machine checks include the verified
key identity, current scopes, document boundary, revocation and expiry; checking
again does not consume another document-token use. Automation materialization
applies the same checks to the original organization-wide API key, requiring
both `write:authoring` and `write:workflow`, including idempotent replays.
Credential expiry before commit returns HTTP 401; revoked permissions,
membership or credentials return 403. MCP reports these refusals as tool errors.

Recipient create, update and delete use that same original-credential authority
at a shared REST/MCP transaction boundary. Creation acquires the quota lock
before the fresh, undeleted draft and inherits its current locale/deadline.
The live sender/owner, recipient mutation and canonical audit commit together;
authorization or audit failure rolls everything back. Retained signing/field
evidence or sealing state, pending linked or organization-wide privacy requests,
and a contested privacy fence prevent recipient changes. See the
[recipient authoring contract](API-GUIDE.md#recipient-authoring).

Field creation and deletion also share a REST/MCP transaction boundary that
binds the original session/key, locks the current undeleted draft and member,
and rechecks authority before commit. PDF signature overlays require that
current PDF-source draft and its own recipient; captured evidence, sealing state
and open privacy review prevent field changes. Mutation and
`document.field_added`/`document.field_deleted` audit commit atomically.
REST geometry uses percentages; MCP creation uses basis points (`10000` = 100%),
while both return percent coordinates. Validated dropdown choices, positive
page-bounded rectangles and the 1000-field authoring cap apply across transports.
See the [field authoring contract](API-GUIDE.md#field-authoring) for defaults,
required-value parsing, MCP page limits and refusal/retry behavior.

Send's resolver preflight reads source data and stages resolved values and
binding observations without writing document variables or binding status.
Its authorized freeze transaction compares the original document, envelope
children and binding definitions before persisting the prepared values. It also
re-lists and validates recipients while holding the parent/document lock.
Frozen variables support both block-source and PDF-source documents. A changed
draft or binding preparation returns HTTP 409 from REST Send and the automation
command, or a tool error from MCP; fetch and review the current draft before
trying again.

Once Send commits an authorized sealing intent, `ResumeSendSealing` completes
that durable intent using its persisted actor and evidence state. Worker retries
do not require the original browser session or API key to remain live. Automatic
reminders similarly act on the locked, due reminder schedule created by the
authorized ceremony. They recheck document state and deadline and atomically
advance the schedule, rotate links, queue mail and record audit. These recovery
and scheduled paths cannot authorize a fresh manual lifecycle action.

Recipients use their portal to view, comment, sign/accept, decline, or request
changes. Mutations require the current notice evidence and an eligible
recipient in the current ceremony. A change request pauses the ceremony;
the sender reviews changes before revision and resend. A revision cannot erase
captured signatures, acknowledgements, or completed field evidence. Old notice
evidence and old recipient links cannot authorize the replacement ceremony.

Comments and change-request notices use the durable mail outbox. The owning
sender is identified by the document's `sender_id`; that is not automatically
the CRM deal assignee. A committed outbox entry proves queued delivery, not
delivery to an inbox. Verify the worker, SMTP provider and recipient inbox in
acceptance tests.

See [negotiation endpoints](API-GUIDE.md#negotiation-comments-and-change-resolution)
for comment limits, transactional session checks and change-resolution errors.
An unexpected database failure on an email approval returns a retryable error;
only a genuinely resolved request is reported as already handled.

Draft collaboration uses the session-authenticated WebSocket at
`/api/v1/documents/{id}/collab`. Every binary frame rechecks cookie expiry,
membership, sender/owner role and draft state. Saved Yjs updates replay in
separate frames; synchronization completes after the final update. CRDT
persistence is asynchronous. Do not treat a broadcast as a transactional
durability receipt or as a signed version of the document.

The release supports SES typed signatures. AES/QES endpoints are explicit
tombstones, and unsupported configurations must not be interpreted as a
higher-assurance ceremony. Behavioral signer telemetry is also disabled until
notice-versioned consent and withdrawal are persisted and enforced.

## Rate limits and retries

These current source defaults are per minute. They are process-local; production
supports one HTTP server under a database singleton lease.

| Boundary | Limit/key |
| --- | --- |
| Login/callback/logout group | 20 per IP |
| Public verification group | 30 per IP |
| MCP | 240 per IP |
| Automation | 6000 per IP plus 600 per organization |
| Signer aggregate | 1200 per IP |
| Signer reads | 240 per token |
| Signer legal mutations | 60 per token |
| PDF downloads | 30 per token plus 240 per IP |
| Clarification | 10 per token plus 60 per IP |

Rate keys derived from signer credentials use a one-way digest. Separate budgets
keep expensive downloads/AI from consuming legal-response capacity. Not every
sender-session route has its own explicit rate limiter; the generated inventory
shows registrations, and deployment resource/concurrency limits remain a
separate requirement. Do not add replicas without a reviewed shared-limit and
collaboration-state design.

For the automation command, retry ambiguous outcomes and retryable statuses
using the exact original idempotency key and body. Do not retry permanent
validation/collision errors as a new request. Other mutation routes do not
automatically share this idempotency contract. Follow endpoint-specific errors;
never assume every successful HTTP response implies mail delivery, signing
completion, or a completed downstream Reactor workflow.

## Integrations and documentation coverage

Hash's direct BrightCRM resolver fetches configured deal/contact endpoints with
a configured bearer token; live response fields and account permissions must
match the bindings. This is separate from OIDC sender login and does not
implement an automatic CRM OAuth authorization/refresh flow.

For the durable automation bridge, follow
[BrightCRM integration](../../brightcrm/docs/REACTOR-HASH-ESIGN.md) and
[Reactor bridge](../../reactor/docs/hash-esign-bridge.md). Persist the Hash
request/document IDs, verify signed callbacks, and distinguish queued ingress
from terminal success. Customer input must not choose routing URLs, credentials,
tenants or concrete template identities.

The automation contract and generated route inventory are available now. A full
reviewed OpenAPI request/response schema for the complete browser API is still
pending; the inventory does not substitute for it. Use MCP's registered tool
schemas for that interface. See [upload security](UPLOAD-SECURITY.md),
[deployment](../DEPLOY.md), and [backup/restore](../ops/BACKUP-RESTORE.md) for
the separate import and operational contracts.

Actual OIDC login, SMTP inbox receipt, CRM account ownership and field mappings,
Reactor callback/dispatch behavior, ClamAV scanning, and storage retention and
restore acceptance remain pending in the target environment. Local fixtures and
API documentation do not establish compliance certification or deployment.

Document PATCH edits require draft state and are serialized against send/seal
through a PostgreSQL document row lock with a fresh draft-state check. The live
member and original session credential are checked after that wait and again
after transactional audit logging, immediately before commit. Retained evidence,
sealing state and pending/contested privacy review also prevent edits. See
[document, block and binding authoring](API-GUIDE.md#document-block-and-variable-binding-authoring)
for the shared refusal and rollback contract.
`blocks_json` and `variables_json` are supported for block-source documents;
supplying either for a PDF-source document returns HTTP 400. Metadata edits
remain supported. PATCH requires `expected_updated_at` copied from the document response. Missing
preconditions return 428; malformed timestamps return 400; a mismatch against
the row locked for update returns 412 before mutation. Browser callers supply
the value, and the editor stops saving on conflict with a local draft download.
Migration 67 makes every document update advance its microsecond timestamp,
including writes in older transactions. This does not establish CRDT/REST
convergence. Full-tree MCP replacements, variable replacement, version restore,
and individual block replacement also have observation guards described below.
Append/delete/reorder and HTML/Markdown imports preserve their observation
requirements and use the same original-credential and privacy admission checks.

Document PATCH `default_locale` must identify a shipped signing language.
Supported regional tags such as `sv-SE` normalize to the base language `sv`,
using the same rules as recipient authoring. Unknown languages return400
before database mutation instead of creating an unusable recipient default.

Automatic reminder offsets (`days_after_send`) use the document's send
timestamp, not the previous reminder's processing time. The default second
reminder is day7 after send, rather than day10 after a day3 first reminder.
Overdue schedules remain due; delivered mail still requires outbox acceptance.
Manual Remind moves an existing schedule's `next_fire_at` to three days after
the manual transaction's time and records `last_fired_at`; it does not replenish
`fires_remaining` or recreate a missing schedule. Remaining automatic offsets
still use the original send timestamp.

Machine-readable request/response contracts for the automation command are in
[openapi-automation.json](openapi-automation.json), using
[OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html). They cover the
signature-request command only. UTF-8 byte limits are described and annotated
with `x-maxUtf8Bytes`; generic schema tooling does not enforce these extensions
or dynamic template, role, expiry and lifecycle rules. Server validation remains
authoritative. The Go contract test guards property/required-field drift.

CRM/scanner HTTP resolver responses must be unambiguous UTF-8 JSON objects.
Duplicate decoded keys anywhere in the response (including escaped aliases),
trailing values and nesting beyond 64 levels are rejected before contract
variables are resolved. Rejection messages do not include upstream values.
This protects response interpretation; live entity ownership and field mapping
still require integration acceptance against the configured CRM account.

Resolver caching is tenant-keyed, process-local and bounded to 1024 entries and
8 MiB of retained key/value text, with a 30-second TTL. Writes remove expired
entries and evict the oldest inserted values when capacity is reached. Cache
misses fetch the configured source again; this cache is not a durable record or
a reason to introduce Redis. Process memory also includes Go map/object overhead.

MCP `set_document_blocks`, `import_html`, and `import_markdown` require
`expected_updated_at` from the observed document. Their shared mutation helper
compares it under the document row lock before replacing the tree. Missing,
malformed or stale observations return tool errors; fetch and review before
resubmitting. Block/variable replacements and version restore are covered by
the original-credential transaction guard described in
[the authoring contract](API-GUIDE.md#document-block-and-variable-binding-authoring).
Replacement advances the collaboration generation; recovery retains the local
draft for explicit review and capture before shared editing is reset.

MCP `set_variables` also requires `expected_updated_at` and checks the locked
row before replacing values. MCP document reads return the database timestamp
with microsecond precision; use that value directly rather than truncating it.

REST `POST /api/v1/documents/{id}/versions/{n}/restore` requires a JSON body
`{"expected_updated_at":"<timestamp from the observed live document>"}`.
The same field is required by MCP `restore_document_version`. A stale live-row
observation is rejected before a restore snapshot, audit event or content write.
Do not use the historical version timestamp as the live document precondition.

MCP `update_block` requires the observed `expected_updated_at` too: replacing
one block can overwrite another client's edits even when the surrounding tree
is merged under a lock. REST single-block replacement has the matching guard
described below; append/delete/reorder coverage remains under review.

REST `PATCH /api/v1/documents/{id}/blocks/{bid}` likewise requires
`expected_updated_at` alongside `block`. The shared locked mutation helper
returns 428 for missing, 400 for malformed and 412 for stale observations before
replacing the block. The frontend `updateBlock` helper requires an explicit
observed timestamp; it does not fetch a newer timestamp to mask a stale edit.

REST HTML and Markdown replacement imports also require the observed timestamp:
`POST /api/v1/documents/{id}/import-html` accepts `html` and
`expected_updated_at`; `/import-md` accepts `markdown` and `expected_updated_at`.
The locked replacement rejects missing observations with 428, malformed timestamps
with 400, and stale observations with 412 before changing content or evidence.


### Replacement import limits and recovery

Both replacement endpoints require an authenticated session with write permission
and same-origin mutation checks. The JSON body is limited to 1 MiB including field
names, escaped content and the revision timestamp. MCP's 1 MiB limit applies to
its complete JSON-RPC envelope, including arguments. These are byte limits, so
non-ASCII and JSON escape sequences can consume more than one byte per character.

```json
{
  "html": "<p>Reviewed replacement content</p>",
  "expected_updated_at": "2026-10-05T10:00:00.123456Z"
}
```

Copy the timestamp exactly from the document you reviewed; the example timestamp
is illustrative. For Markdown use `markdown` in place of `html`.

| Result | Meaning and caller action |
| --- | --- |
| 200 | Replacement committed; use the returned document and its new timestamp. |
| 400 | Invalid input or content rejected by the scanner; review source before retry. |
| 428 | Observation missing; fetch and review the current document. |
| 412 | Document changed; preserve the local draft and review current content before a new replacement. |
| 429 | Shared import capacity occupied; respect `Retry-After: 2` and retry with the same observation. |
| 503 | Scanner unavailable; retry when scanning is healthy, keeping the original observation. |

Admission allows two expensive imports globally and one per organisation, shared
with other upload/import paths. The lease is held through scanning and canonical
persistence. Limits are process-local and rely on the HTTP singleton restriction.
A retry after 429/503 can subsequently return 412 if another writer changed the
document. Fetching a newer timestamp automatically would conceal the conflict.
MCP `import_html`/`import_markdown` use the same admission/scanning/revision gates,
but communicate errors through their JSON-RPC tool response instead of this HTTP
status table. See [malware scanning](MALWARE-SCANNING.md) for daemon requirements.

REST `POST /api/v1/documents/{id}/blocks/reorder` and MCP `reorder_blocks` require
`expected_updated_at` from the reviewed document alongside `block_ids`. A stale
permutation is rejected before reordering, even when the current block ID set
still matches. REST uses the same 428/400/412 revision responses as replacement
imports. Relative append/delete behavior remains under review.

REST `DELETE /api/v1/documents/{id}/blocks/{bid}` requires a JSON body containing
`expected_updated_at` from the reviewed live document; MCP `delete_block` requires
the same argument. Deleting a block whose document changed is rejected before
content/version/audit writes. REST returns428 missing,400 malformed,412 stale.
The frontend helper requires that caller-supplied observation explicitly.

REST `POST /api/v1/documents/{id}/blocks` and MCP `append_block` require
`expected_updated_at` from the reviewed document alongside `block`. Keep that
observation when retrying an ambiguous response: a committed first append advances
the timestamp, so a second request is rejected rather than duplicating the block.
This is conflict protection, not a stored idempotency receipt; fetch/review the
result after412 before deciding whether another append is needed. REST uses the
same428/400/412 observation statuses. Convenience authoring tools still require
separate review for equivalent semantics.

MCP `add_signature_field` also requires `expected_updated_at`. Every tool routed
through the canonical tree mutation helper now passes a mandatory observation;
the helper checks it unconditionally under the document lock. This removes the
previous tool-name allowlist that could omit a new convenience operation.

All six REST canonical tree mutation endpoints enforce the reviewed timestamp
unconditionally in their shared transactional helper. Its timestamp argument is
mandatory, eliminating a tool-name allowlist or optional omission for new callers.

Authenticated/machine API, MCP, and authentication endpoint responses use
`Cache-Control: no-store` and `Pragma: no-cache`, including redirects and
errors. Magic-link/action responses use the same policy. Public branding and
static assets retain their own caching policies. Verify the same headers at
the deployed reverse proxy; local middleware tests do not establish proxy or
service-worker behavior.

Sent-document variable resolution uses the document's frozen `variables_json`
values exclusively. Binding `last_value` and fallback fields are mutable
observations and cannot replace a snapshot value, populate a missing snapshot
variable, or turn a deliberately empty value into newer CRM content. Binding
rows remain available for source reporting. Agent overrides are refused in
frozen resolution. Live draft resolution and send-time materialization retain
their existing behavior.

Live variable resolution fails if the successful value or source error cannot
be persisted to the binding observation. Such failure returns no completed
variable map or send-time frozen result and never adds a new cache entry.
A recorded upstream error can still use the configured fallback. Observation
writes for earlier bindings may already have completed; this is not a single
transaction spanning all external fetches.

Successful live or cached source values remain authoritative even when empty.
An empty CRM field clears the resolved variable instead of reviving a static
value or configured fallback. Fallback applies when the source failed to resolve;
it does not substitute content for a successful empty response.

`org.setting` branding bindings now read the current tenant's stored branding.
Supported source paths are `branding.primary_hex`, `accent_hex`, `surface_hex`,
`text_hex`, `muted_hex`, `logo_url`, `logo_alt`, `font_heading`, `font_body`, and
`signature_color` (each with the `branding.` prefix). `source_ref` does not
select another tenant; identity comes from the authenticated document context.
An absent branding record reports not configured and follows normal recorded
fallback behavior. These live draft values use the resolver's bounded TTL cache;
sent documents use their frozen variables.
