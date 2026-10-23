# Hash API guide

Hash exposes separate browser, machine, signer, and webhook boundaries. Use the
[HTTP route inventory](API-ROUTES.md) to find every registered endpoint, handler,
middleware, and conditional dependency. The inventory is generated from the
router and checked with `go run ./cmd/apidocgen -check`.

The [later-amendment and agreed-notice API](LATER-AMENDMENTS-API.md) documents
the three agreement-selected processes, immutable original/proposal relation,
owner/session routes, purpose-only notice access, uncertain-result recovery and
signer disclosure. Mail progress is not signature, acknowledgement or legal
acceptance. Its public notice routes are an explicit exception to the ordinary
signed-session `/api/v1` boundary.

The [signing workflow/self-grant registry](PRE-SIGNING-REGISTRY-API.md) documents
the session-only review, consent, revocation and durable recovery contract.
Its registry does not enable document pre-signing or machine execution.
The internal [execution persistence contract](PRE-SIGNING-EXECUTION.md) adds
no public endpoint and does not enable that mode.

## Authentication boundaries

| Surface | Authentication | Contract |
| --- | --- | --- |
| `/api/v1/*`, except the purpose-only notice routes below | Sender session cookie from OIDC login | Browser API. API keys do not replace the cookie on this tree. Current membership, tenant and role are loaded on each request. |
| `/api/v1/notices/{notice_id}` and its documented access/file routes | Notice capability exchange, then a purpose-specific HttpOnly Secure cookie | Read-only exact notice/file access; no sender/signature/acknowledgement grant. See [later amendments](LATER-AMENDMENTS-API.md#public-notice-access-and-exact-downloads). |
| `/api/automation/v1/signature-requests` | Organization-wide API key | Dedicated sender/owner key with both `write:authoring` and `write:workflow`; stable `Idempotency-Key`. See [Automation API](AUTOMATION-API.md). |
| `/mcp` | API key, including supported document-scoped credentials | MCP entitlement, role, tool scopes and document scope apply independently. Discover actual tools and input schemas through MCP `tools/list`. |
| `/sign/{token}/*` | Recipient magic link | The URL token is a bearer credential bound to a recipient and ceremony. It does not grant sender or administrative access. |
| `/webhooks/brightcrm` | Legacy receiver, disabled in production wiring | Requires a reviewed tenant-bound producer protocol before activation; current BrightCRM does not emit the expected deal/contact CRUD callbacks. |
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
Logout requests accepting `text/html` redirect to `/` with HTTP 303; machine
requests receive the JSON logout receipt. Database failures do not return a
successful revocation receipt. The built-in “Sign out everywhere” control uses
a same-origin `fetch` POST with `mode: 'cors'`,
`credentials: 'same-origin'`, `Accept: text/html` and redirect following.
CORS mode preserves the browser's real `Origin` under Hash's global
`no-referrer` policy; it does not grant cross-origin access. The browser attaches
the `HttpOnly` session cookie without exposing it to JavaScript. Preserve the
normal same-origin mutation/CSRF guard rather than forging an Origin, reading
the cookie or relying on the Referer header. A failed or lost response is not
a confirmed revocation receipt.

Use HTTPS and same-origin browser requests. The browser mutation guard also
protects against requests from sibling subdomains. Supply the app's exact
`Origin`; broad CORS allowlists are not an authentication mechanism. Machine
keys use `Authorization: Bearer <key>` or the supported `X-API-Key` header on
the machine/MCP surfaces. Keep keys, signer URLs, OIDC callback query strings,
and action tokens out of logs and analytics. Production ingress additionally
authenticates the reverse proxy; external clients must not manufacture or
receive the host-only proxy credential.

MCP rejects malformed raw UTF-8, unpaired escaped surrogates and decoded NUL in
the whole JSON-RPC envelope before normalization or dispatch. These failures
return a parse error without echoing a normalized request ID. Valid Unicode and
properly paired escapes remain supported.

Internal deployments can use the explicit [operator mode](INTERNAL-OPERATOR-MODE.md).
Its authenticated billing status reports `billing_enabled: true`,
`payments_enabled: false`, provider `operator` and the approved finite plan.
Subscription is absent; invoices and purchase catalog are empty. Payment
operations are disabled while quotas and capabilities remain enforced.

Strict catalog admission also applies to ordinary authoring, Send and their MCP
counterparts. Missing or stale M95 plan metadata, or M96 metadata for retained
rules required by the operation, can return HTTP 503 even when login and health
checks succeed. Follow the [catalog maintenance runbook](CATALOG-MAINTENANCE.md)
for explicitly approved plan UUIDs and, where applicable, tenant/rule UUIDs,
exact source/version preparation and postflight. A fresh organization with no
rules needs no rule seeding. Do not treat this refusal as permission to retry
blindly, measure an unreviewed inventory or bypass the catalog guards.

## Sender package Send

The ordinary browser Send endpoint accepts the exact reviewed main-plus-attachment
selection and returns a durable asynchronous sealing receipt. Ordinary documents
omit that observation. See [document attachments API](DOCUMENT-ATTACHMENTS-API.md#send-the-reviewed-main-document-and-attachments)
for request fields, HTTP202, unknown commit handling and read-only reconciliation.

## Recipient PDF observations

For PDF documents, `GET /sign/{token}` returns `pdf_observation` with the exact
`document_id`, this `recipient_id`, and lowercase `pdf_sha256`. Registered HTML
materializations also include `html_source_commitment`, `page_count` and
`materialization_revision`. An older HTML origin may include a source commitment
without a registered page count or revision. Static PDFs omit these optional
HTML fields. A missing count is unknown; clients must inspect the exact PDF.

The original PDF read, field list and successful field-save receipt repeat the
same public observation in these headers:

| Header | Value |
| --- | --- |
| `X-Hash-Document-Id` | Observed document UUID |
| `X-Hash-Recipient-Id` | Authenticated recipient UUID |
| `X-Hash-PDF-SHA256` | Exact source PDF SHA-256 |
| `X-Hash-PDF-Pages` | Registered page count, when known |
| `X-Hash-HTML-Source-Commitment` | Validated HTML source commitment, when present |
| `X-Hash-Materialization-Revision` | Registered materialization sequence, when present |

Storage keys, object VersionIds, organization IDs and raw HTML source are not
part of this public witness. Use no-store reads and compare both the values and
the presence of optional headers with the original context. Verify the PDF
bytes before parsing, require every page to render, and verify field ownership
and geometry against that artifact. A failed or incomplete view must keep
adoption, signing and acceptance disabled. Dispose pending reads/render work
when the token, recipient, notice or artifact changes.

Context, PDF, rendered block document and field reads retain their original
magic-link admission and notice through database/render/storage waits. A final
short transaction locks the parent and exact recipient, then rechecks source,
normalized HTML history, notice and both original/current deadlines before
returning data. An expired original admission is not revived by an extended
deadline. These checks authorize a read; legal mutations retain their separate
notice, role, status and transaction guards.

Successful field saves return the source observation validated under the
retained document lock after the field/audit commit. Clients must confirm the
exact saved field and value before enabling signing. A later source change
requires a fresh view and mutation authorization; it does not retroactively
turn a durable field-save receipt into a failed save.

## Recipient package metadata

`GET /sign/{token}/package` uses the current recipient magic link and returns
`{"package":null}` for an ordinary ceremony without a bound package. A package
response contains `schema` (`hash-recipient-package-v1`), `package_id`, decimal
string `revision`, `manifest_sha256`, `legal_commitment_sha256`, `main` and ordered
`annexes`. Each member contains `title`, open-ended `category`, `pdf_sha256`,
`bytes` and `pages`. The response contains no object keys, provider version IDs
or internal source/intake-report bodies. Reads use `Cache-Control: no-store`.

The server resolves the exact completed Send and immutable capture for the
current ceremony epoch, validates its original recipient membership and checks
the current credential and captured members' privacy fences. Missing or
inconsistent current package history refuses delivery. An older aborted attempt
does not turn a later ordinary ceremony into a package ceremony.

This endpoint supplies descriptors only; reading it does not record consent.
The package-aware Send, frozen member PDF delivery, explicit incorporation consent,
signature binding and mandatory participant evidence report are implemented.
The controlled package browser and downloaded artifacts passed checkpoint423;
configured services and other business variants retain their separate gates.
See the [attachment API](DOCUMENT-ATTACHMENTS-API.md#recipient-frozen-package-descriptors)
and the package ceremony below for the actual request and consent contract.

## Recipient package PDF

`GET /sign/{token}/package/members/{position}/pdf` reads an exact frozen member
of the authenticated recipient's current package. Position `0` is the main
contract and positions `1` through `16` are the ordered attachments. Obtain both
commitments from the current package metadata response and supply one strong
`If-Match` tag in this format:

```text
"<64 lowercase hex manifest_sha256>.<64 lowercase hex legal_commitment_sha256>"
```

The tag is a precondition, not an access credential. Missing preconditions return
`428`; malformed, weak, wildcard or multiple tags return `400`; changed
commitments return `412`. An unavailable current member returns `404`. Expired,
revoked or privacy-blocked credentials never obtain document bytes. Clients must
reload the current ceremony after a refusal rather than retry with an older
package or a caller-selected object version.

Successful responses are `application/pdf` with `Cache-Control: no-store`, an
exact `Content-Length`, the matching `ETag`, and these member observations:

- `X-Hash-Package-Manifest-SHA256`
- `X-Hash-Package-Legal-Commitment-SHA256`
- `X-Hash-Package-Member-Position`
- `X-Hash-PDF-SHA256`, `X-Hash-PDF-Bytes` and `X-Hash-PDF-Pages`

The server resolves storage locators from the immutable completed Send capture
and its verified member-retention receipt. It reads the captured version and
checks its size and digest, then rechecks the original recipient, package,
source, notice and all captured privacy subjects before delivery. Storage keys
and provider version IDs are not exposed. Approved HTML contracts use their
captured reviewed PDFs without rerendering. These downloads share the signer
PDF rate limits and the package limits of sixteen attachments, 50 MiB and
500 pages in total.

A successful download does not record acceptance or a signature. Nonempty
package Send remains guarded until whole-package consent, signature binding and
the mandatory participant evidence report qualify together.

## Roles and scopes

`viewer` reads documents, `sender` creates/edits/sends documents, and `owner` also
controls organization settings and membership. A current viewer can still revoke
their own retained signing grant and inspect or explicitly close their own
registry requests. These exceptions preserve recovery after loss of sending
rights; they cannot create authority. A role never authorizes another
tenant's document. A machine key's scopes narrow its role, and a document-scoped
credential narrows its target further. Missing scopes do not inherit full access.
See [role checks](../internal/auth/rbac.go) and
[MCP tool scopes](../internal/mcp/scope.go).

`POST /api/v1/documents` and MCP `create_document` retain the original signed
session or organization-wide `write:authoring` key through quota, template,
member and audit waits. They always validate an active tenant template of the
matching source kind, including complete explicit overrides. Omitted block
content/variables copy the locked current defaults; explicit empty values stay
empty. PDF variables also populate document data, preserving exact template
source/version pins; they do not rewrite existing PDF text. Version-one named
party layouts create fresh recipients and positioned signature fields with an
exact template-version observation and complete new party identities. See
[document creation](API-GUIDE.md#document-creation) and
[reusable PDF signing layouts](API-GUIDE.md#reusable-pdf-signing-layouts).

Owner REST settings and credential writes use a separate live-owner transaction,
including change-approval mode, branding/logo, AI provider, API keys and webhooks.
Omitted values merge from the locked current state. New credentials are disclosed
only after commit. MCP branding and webhook creation/deletion retain the original
owner key through the same commit-time checks. Owner eIDAS/compliance policy
writes use that same boundary; routing-tier updates retain draft sender/owner
permission. AI requests and envelope mutations also revalidate their admitted
credentials after waits; incurred AI costs use independently durable receipts.
See [owner settings](API-GUIDE.md#owner-settings-and-organization-credentials).
See [AI requests](API-GUIDE.md#ai-requests-and-negotiation-metadata) and
[MCP envelope authoring](API-GUIDE.md#mcp-envelope-authoring).

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

CRM deal/contact/company bindings require a successful fresh typed source response at Send;
the preview cache and configured fallbacks cannot stand in for that response.
Missing source, failed fetch or invalidation during the request refuses sending.
REST returns503 when current CRM information cannot be verified. Prepared
observations use document and binding revision predicates and roll back with
the freeze transaction if any binding changed. The per-organization connection
and exact CRM account/record identity are rechecked; grouped record reads preserve
exact scalar values and explicit relationship checks. A CRM value differing from
the reviewed document returns409 for update/preview/review, with no silent Send
replacement. Reports retain connection/account/record/time/digest provenance,
and the final transaction retains the active connection generation and a bounded
observation deadline. Local synthetic acceptance still does not prove actual
configured account/business data or live integrations. See [CRM connector](CRM-CONNECTOR.md).

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
| HTML draft creation | 10 per organization/user |
| HTML creation request closure | 10 per organization/user |
| Template CRM context and creation recovery | 60 per organization/user, separate route budgets |
| Template CRM search and observation | 30 per organization/user, separate route budgets |

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

The BrightCRM resolver selects an encrypted owner-confirmed connection from the
document's Hash organization. It verifies the exact remote account before/after
grouped deal/contact/company reads, checks record ownership and selected links,
and accepts catalog scalars only. Global CRM tokens are retired. The owner API,
actor witnesses, credential rotation, bounds and migration contract are in
[CRM connector](CRM-CONNECTOR.md). This is separate from OIDC sender login;
automatic CRM OAuth authorization/refresh is not implemented. Actual credentials,
read scopes/expiry, source mappings and business record read-back remain live gates.

For the durable automation bridge, follow
[BrightCRM integration](../../brightcrm/docs/REACTOR-HASH-ESIGN.md) and
[Reactor bridge](../../reactor/docs/hash-esign-bridge.md). Persist the Hash
request/document IDs, verify signed callbacks, and distinguish queued ingress
from terminal success. Customer input must not choose routing URLs, credentials,
tenants or concrete template identities.
The current Reactor adapter omits mandatory template version/content-SHA pins;
its source/docs alone do not establish compatibility with the stricter Hash
command. Upgrade/review that producer and verify actual dispatch before use.

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

### Reminder scheduling and delivery

Automatic reminder offsets (`days_after_send`) use the document's send
timestamp, not the previous reminder's processing time. The default second
reminder is day7 after send, rather than day10 after a day3 first reminder.
Overdue schedules remain due. Manual Remind moves an existing schedule's
`next_fire_at` to three days after the manual transaction's time and records
`last_fired_at`; it does not replenish `fires_remaining` or recreate a missing
schedule. Remaining automatic offsets still use the original send timestamp.

REST `POST /api/v1/documents/{id}/remind` returns `{"reminded": count}` for the
actual pending recipients. It requires the current sender/owner authority and a
sent or in-progress, unexpired document. Expired credentials return401,
revoked credentials/permissions403, missing documents404 and a document outside
the remindable state409. MCP retains tool-error reporting and its original
API/document credential, scope, expiry and usage checks.

Both manual and scheduled reminders lock and recheck the actual family,
recipients and schedule. Rotated capabilities, schedule changes, durable queued
mail and fresh measured audit rows commit atomically; the final policy deadline
and manual credential are checked after waits. An exhausted, absent or non-due
automatic schedule produces no reminder effects. Concurrent workers do not fire
the same schedule twice. A reminder after a partial signature remains part of
the eventual mandatory report. This does not reserve future report headroom for
all later history writes.

Queued mail still needs worker/provider/inbox acceptance. A configured direct
mailer consumes the already rendered message after commit within a finite
delivery context; those real resources remain charged until its call finishes,
including after request cancellation. A nil mailer preserves link rotation and
audit without claiming delivery. Direct-message rendering errors refuse before
commit. No successful reminder response promises inbox delivery; configured
SMTP and outage/retry acceptance remain release gates.

Machine-readable request/response contracts for the automation command are in
[openapi-automation.json](openapi-automation.json), using
[OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html). They cover the
signature-request command only. UTF-8 byte limits are described and annotated
with `x-maxUtf8Bytes`; generic schema tooling does not enforce these extensions
or dynamic template, role, expiry and lifecycle rules. Server validation remains
authoritative. The Go contract test guards property/required-field drift.

CI runs route-inventory freshness and OpenAPI validation as separate required
steps. Run the same checks from the Hash module root:

~~~sh
go run ./cmd/apidocgen -check
bash scripts/check-automation-openapi.sh
~~~

The OpenAPI entrypoint requires CPython 3.11 through 3.14 with `venv` and pip.
Set `HASH_OPENAPI_PYTHON=/absolute/path/to/python3` when the default `python3`
is unsuitable. It creates and removes a private temporary environment, installs
only binary wheels from the complete version-and-SHA256 lock in
`scripts/requirements-openapi.txt`, checks dependency consistency, then runs
specification validation and all16 request-boundary fixtures. Missing tools,
dependencies, hash mismatches and validation errors fail the check, without
skipping it. Normal installation uses PyPI with certificate verification. For an
offline run, set `HASH_OPENAPI_WHEELHOUSE` to a local directory containing all
compatible locked wheels; pip then uses no index. No application or global
Python environment is changed.

The lock includes conditional `typing-extensions` for Python3.11 and3.12.
Dependency updates must resolve the full closure for supported Python versions,
retain reviewed wheel hashes and repeat successful and refusal checks; do not
replace the lock with a direct-package-only pin. Local qualification uses the
immutable official Python3.14.7 Linux image; other interpreter and architecture
combinations need their own execution receipts. Managed workers must provide
the interpreter and venv prerequisite before CI can pass.

These checks do not prove runtime response conformance, format enforcement,
dynamic authorization, UTF-8 byte limits or complete schemas for every route.
The current automation specification uses local references only; introducing
external references requires an explicit offline-bundling decision.

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

REST version history and `GET /api/v1/documents/{id}/versions/{n}` return
snapshot metadata, blocks and variables. They omit raw HTML provenance, inline
master assets and internal storage-version references at the SQL and response
boundaries. Full internal snapshots are retained for evidence. Use the declared
HTML source and PDF history endpoints below to inspect an HTML document.

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
frozen resolution.

REST HTML/resolve previews and MCP `preview_resolved_variables` are read-only:
they do not write binding values, errors, resolution times or timestamps.
Draft reads may use the bounded memory cache or configured fallback. Before
returning, the application checks the document and binding snapshots and the
original session/key after source/branding waits. A changed snapshot returns409;
deleted/foreign documents404; expired credentials401; revoked access403. Viewer
reads remain supported. MCP reports tool errors without claiming another token
use. External fetches occur outside document locks. See
[preview contracts](API-GUIDE.md#document-previews).

Only Send stages binding observations, then persists them atomically with frozen
document variables after authorization and exact document/binding revision
checks. Persistence or revision failure returns no frozen result and rolls back
all observations in that transaction. Preview reports therefore do not establish
send-time source freshness or a durable binding observation.

Successful source values remain authoritative even when empty.
An empty CRM field clears the resolved variable instead of reviving a static
value or configured fallback. CRM reads bypass the generic preview cache and
fail closed on unavailable/permission-null or invalid observations; fallback
cannot establish a verified contract source. Other source kinds retain their
documented preview fallback behavior.

`org.setting` branding bindings now read the current tenant's stored branding.
Supported source paths are `branding.primary_hex`, `accent_hex`, `surface_hex`,
`text_hex`, `muted_hex`, `logo_url`, `logo_alt`, `font_heading`, `font_body`, and
`signature_color` (each with the `branding.` prefix). `source_ref` does not
select another tenant; identity comes from the authenticated document context.
An absent branding record reports not configured and follows normal preview
fallback behavior. These live draft values use the resolver's bounded TTL cache;
sent documents use their frozen variables.

## HTML design draft API

This source draft adds reusable HTML designs separately from the PDF bytes used
for signing. It is not a deployed release. Declared-text document revision and
retained PDF history and reviewed contract profiles are described below.
The schema-3 automatic signing-page contract below has local source/runtime
acceptance and still requires managed release and exact-release acceptance.
Approved privacy disposal remains pending.

Sender sessions can create `POST /api/v1/templates/html` and edit
`PATCH /api/v1/templates/{id}/html`. Editing requires `expected_version`; every
edit creates a new immutable revision and requires new owner approval. The body
contains `name`, `html_master_json`, and optional `variables_json` defaults:

```json
{
  "name": "Ordinary agreement",
  "html_master_json": {
    "schema_version": 1,
    "html": "<h1>Agreement</h1><p>Customer: <span data-hash-value=\"customer\"></span></p><div data-hash-section=\"scope\"></div>",
    "values": [{"name": "customer", "required": true, "max_chars": 200}],
    "sections": [{"name": "scope", "default_text": "Approved scope text", "max_chars": 2000}]
  },
  "variables_json": {}
}
```

Values and editable sections are declared plain text. They are escaped when
inserted; templates cannot evaluate Go expressions or JavaScript. CSS and HTML
use the restricted grammar in `internal/htmlmaster`. Images and fonts must be
declared, bounded embedded assets referenced as `hash-asset:<name>`; remote URLs,
SVG, scripts, forms and arbitrary HTML section replacement are refused. The
master JSON is capped at 12 MiB, HTML at 256 KiB, CSS at 128 KiB and 16 assets
totaling 8 MiB.
An organization import slot bounds concurrent scanner/render work.

Preview a saved revision with `POST /api/v1/templates/{id}/html/preview`:

```json
{
  "expected_version": 1,
  "expected_content_sha256": "<saved revision SHA-256>",
  "values": {"customer": "Example customer"},
  "sections": {"scope": "Reviewed sample scope for this preview"}
}
```

Sender and owner sessions can preview. Declared sample values fill required
placeholders without changing saved defaults or creating a document. Optional
declared section samples are escaped plain text and affect only this preview;
omitted sections use saved defaults. Unknown keys, null maps/entries and
nonstring samples are refused. Unsaved HTML is not accepted by this endpoint. The
renderer output is scanned, sanitized and page-counted before disclosure, with
the shared import admission limit, a 15-second processing deadline, a 50 MiB PDF limit and
500-page limit. Rendering and worker calls occur outside database locks. The
original session, live author and exact current/retained revision are rechecked
before PDF bytes and a receipt are returned. A changed revision returns 409;
expired or revoked access returns 401/403.

The binary PDF response includes `X-Hash-Template-Id`,
`X-Hash-Template-Version`, `X-Hash-Template-Content-SHA256`,
`X-Hash-Materialization-SHA256`, `X-Hash-PDF-SHA256`, `X-Hash-PDF-Pages`,
`X-Hash-Preview-Receipt` and `X-Hash-Preview-Expires-At` headers. The PDF digest
commits to the final sanitized response bytes. The server-authenticated receipt
expires after ten minutes and binds the tenant, reviewer, original signed
session, saved revision/defaults, sample materialization, PDF digest and pages.
It is a separate purpose proof and cannot authenticate a login.

In Hash's editor, approval is enabled after every preview page renders and is
visited and the owner acknowledges the review. An owner approves the exact
current design using `POST /api/v1/templates/{id}/html/approve` with
`expected_version`, `expected_content_sha256`, `preview_receipt` and
`expected_preview_pdf_sha256`. Missing receipt/PDF pins return 400; an invalid,
expired or mismatched receipt returns 409 and requires a new preview. Another
reviewer or different signed session cannot reuse that receipt. The digest includes
the canonical master and its defaults. The original credential and receipt
deadline are checked again after the audit append, so expiry during a lock wait
rolls back approval and audit together. The chained audit records the preview
ID, materialization/PDF digests, pages and reviewer/time; it omits the receipt,
session fingerprint and sample text. Approval cannot carry over to a new
revision. The receipt authenticates the preview commitments and the owner
approval records intent; it does not prove that a person read or understood the
terms. Preview PDFs and sample text are not retained as contract artifacts.
Each derived contract still needs review of its own stored rendered PDF and
signing fields.

For HTML designs, `GET /api/v1/templates/{id}` includes `html_approval` with
`version` and `content_sha256` for that exact returned master and defaults.
`approved_by` and `approved_at` are both present after owner approval; both are
omitted for an unapproved revision. The detail validates the immutable revision
against the current template content. Concurrent edits can make the returned
pins stale; instantiation rechecks them and refuses a changed revision. List and
create/edit responses omit approval state; fetch detail before using a design.

`POST /api/v1/templates/{id}/html/documents` accepts `name`,
`expected_template_version`, `expected_template_content_sha256`, optional
`values` and `sections` string maps, optional future `expires_at`, and optional
nonzero canonical `request_id`. Explicit JSON null maps or entries are refused.
New browser callers also supply the optional paired canonical `expected_org_id`
and `expected_user_id` to refuse a changed session actor before any creation or
replay. The pair is part of the semantic command; legacy omitted pairs remain
compatible.
The approved revision is checked before preparation and in the final transaction.
Rendering, scanning, sanitization and versioned storage preparation occur outside
database locks. A short final transaction rechecks the original actor, template,
quota and deadline, then stores the draft and immutable authoring provenance.
New creation returns 201 with `document`, `page_count`, `review_required:true`
and `replayed:false`.

A supplied request UUID is bound to the original organization/user and complete
semantic creation command. A same-command committed replay returns 200 with
`replayed:true`; changed-input reuse returns 409. Responses with a request UUID
also contain original `org_id`/`user_id`, `request_id`, `input_digest` and immutable
original `creation` pins. Compare the exact actor pair with the pending request,
including on tombstones; a later session probe cannot substitute for it.
Read an uncertain result through
`GET /api/v1/templates/{id}/html/document-requests/{request_id}` using a current
session for that same original actor. A committed response contains `state`,
`request_id`, `org_id`, `user_id`, `input_digest`, `template_id`, current `document` and original
`creation`. The latter pins `document_id`, `html_materialization_id`,
`html_source_commitment`, `pdf_sha256`, `page_count` and `created_at`.
The current document can have a later revision or be null after deletion;
creation pins describe its original artifact. Recovery does not reuse an old
CRM receipt or call the provider/renderer. A 404 with `state:"unconfirmed"`
does not establish failure: an original preparation may still be running.
Keep that UUID pending and inspect again; do not create another request UUID.

To stop an uncommitted request explicitly, call
`POST /api/v1/templates/{id}/html/document-requests/{request_id}/close`.
The body is limited to 2 KiB and has exactly `expected_org_id`,
`expected_user_id` and `confirmed:true`. The actor IDs and path IDs must be
canonical nonzero UUIDs; query parameters, duplicate/case-alias/unknown keys,
nulls and trailing JSON are refused. A current original sender/owner session
and exact application origin are required. The expected actor pair must match
that admitted session before lookup or mutation; an owner cannot stop another
actor's request. The rate limit is 10/minute per organization/user.

Close and GET return `Cache-Control: no-store`. A 200 `state:"closed"` response
has exactly `state`, `org_id`, `user_id`, `template_id`, `request_id` and
`closed_at` (the durable UTC RFC3339Nano timestamp). GET can return this same
closed response, the existing committed envelope, or an unconfirmed 404.
Closing an already committed request returns its committed envelope, including
a null current document after deletion. It does not cancel the document or
change the original creation pins. Repeating Close for the same actor/template/
request is idempotent; a stopped nonce cannot later create a document.

Migration 80 adds an immutable terminal registry keyed by organization,
original actor and request UUID. Its state is `committed` or `closed`.
The final creation transaction and Close take the same unconditional database
quota lock, even for internal callers with billing disabled. If Close commits
first, an older preparation cannot attach or commit a draft; if creation commits
first, Close returns that committed result. Database guards require each
committed outcome to match its immutable migration-79 receipt and prohibit a
closed outcome from having one. Existing source domains and initial pins are
unchanged. Retained closed outcomes block migration-80 Down; organization
erasure can cascade the migration-79/80 metadata only after retained templates,
materialization history and other dependencies have been disposed of through
an approved retention workflow. These metadata guards do not enable a raw
whole-organization delete or establish a complete disposal workflow.

A malformed close returns 400; an expired session 401; revoked authoring
authority 403; a conflicting existing template scope 404; a changed actor or
stopped creation attempt 409; audit or other backend failure 500; and unavailable
closure dependencies, quota waits/deadline or an ambiguous commit 503.
Keep the original marker after any uncertain Close
or lost response and inspect or repeat Close for that exact UUID. An error
status or elapsed time does not establish a terminal outcome. Close performs
no CRM, renderer or object-storage work and needs no current template approval,
account or old review receipt.

The browser exposes **Stop this request** with explicit confirmation. Only
explicit acknowledgement of an exact actor/template/request-matched closed
response or readback clears the pending marker. A subsequent user-initiated
creation uses a new UUID after refreshing the current design and reviewing
fresh CRM observations. Resident manual values and sections are retained;
previous confirmation/receipt is invalidated. Reload retains only request
metadata, never contract text or CRM values. Committed outcomes still require
explicit Open or the existing deleted-document acknowledgement. Late responses
from an invalidated operation are not adopted.

Optional `crm_population` uses the separately witnessed template-scoped review
contract in [initial CRM population](CRM-CONNECTOR.md#initial-template-population).
It requires `request_id`. Fresh independently fetched data must equal the exact
confirmed observation, while unmapped values and human sections are preserved.
Both original and fresh observation deadlines, active account generation and
original actor/template approval are rechecked before and after the final audit.
Mappings, current review, source, parties, fields, creation receipt and audits
commit together. Every resulting PDF still needs its own review before Send.

HTML-derived document responses include `has_html_source:true` throughout their
lifetime, even after `html_review_required` becomes false and is omitted. Their
`source_kind` remains `pdf`. Use this provenance flag to preserve the static-PDF
template export restriction after review. Document responses also include
`html_source_commitment` and `html_materialization_revision` for the current
materialization. The source commitment changes when declared text changes even
if a renderer returns identical PDF bytes.

REST document and envelope-child lists fetch these provenance/review flags and
current revision pins without selecting either embedded HTML design. Scoped
MCP list/search and envelope-child reads likewise exclude those designs in SQL;
membership-only guards fetch only the document identity. Rendering, authoring,
manifest and signing paths retain their full validated source reads. These
projections reduce repeated source transfer; they are not a capacity guarantee.

The original sender or an owner must inspect `/api/v1/documents/{id}/pdf` and
explicitly review its current bytes with
`POST /api/v1/documents/{id}/html/review`, supplying the observed
`expected_updated_at`, `expected_pdf_sha256` and
`expected_html_source_commitment`. The source pin is required for registered
materializations; legacy unregistered documents retain their original review
compatibility. This records review of that exact materialization and PDF; it
does not validate contract terms or signature geometry. Sending
refuses absent review, altered provenance, or resolved variables that differ
from the printed values. New prose always needs this human review. Existing
field-design and recipient setup still apply to generic designs. Schema 3 uses
the protected generated fields described below; static PDF template export of an
HTML-authored document is refused. The automation API remains blocks-only.
An unrelated sender cannot record this review. Original-PDF downloads recheck
the original credential, live member and document revision after fetching the
exact object version, before returning bytes. A changed document returns 409;
expired/revoked access or deletion returns the relevant 401/403/404 refusal.

Template and version lists omit the large inline master. Explicit template and
version reads return it under the existing tenant/session authorization. Metadata
snapshots preserve the immutable document source. Source and completed template
approvals cannot be rewritten; migration rollback refuses retained HTML data.

### Reviewed contract profiles and intended parties

An HTML master with `schema_version:2` or `3` requires a `contract_profile`. Schema 1
remains the generic design format with its original canonical commitments; it
cannot carry a profile. Approval of a schema-2 template covers the profile and
its exact printed bindings as well as the design, assets and approved defaults.
Profile changes require a fresh template revision, preview and owner approval.

The profile has `id` (the existing lowercase declaration-name format), `version`
(1 to 1,000,000), `kind` (`proposal` or `b2b_services`), `parties` and `terms`.
Exactly two parties use slots `provider` and `customer`. Each party maps
`company_name`, `company_id`, `representative_name`, `representative_email` and
`representative_authority` to distinct required printed value declarations.
Representative names and addresses follow the ordinary recipient bounds and
validation; their exact casing is preserved. The two addresses and declared
company identifiers must differ. These are declared identity and authority
assertions, not external verification.

Each term has a unique `name` and exactly one `value` or `section` reference.
References are distinct across the profile; up to 16 terms are permitted.
Proposal profiles require `scope`, `price`, `currency`, `tax`, `payment_terms`
and `valid_until`. Services profiles require `scope`, `price`, `currency`, `tax`,
`payment_terms`, `effective_date`, `duration` and `termination`. Every declared
term must be nonblank, including approved section text or its human override.
The current owner approval preview supplies value and optional section samples.
Essential sections must resolve to nonblank text for that preview. Samples do
not change saved defaults; document creation independently requires complete
actual terms and fresh review.
Human document population and revision can override those defaults as plain text
and require fresh review of the generated artifact.
These are engineering checks for reviewed contract designs, not a universal
legal checklist. Hash does not write missing clauses or prove their visual
visibility, substantive suitability, authority or legal effect. Exact PDF
preview and human review remain required.

Instantiating an approved schema-2 design uses the existing HTML document
endpoint and declared inputs. Within the same authorized quota transaction,
Hash creates fresh provider/customer recipients from the printed representative
values. Source schema 2 binds those exact recipient UUIDs to the intended slots,
approved master, inputs and stored PDF. Both parties must sign; replacing a
recipient, deleting a party and its field, or switching to acknowledgement
cannot reduce that requirement. Generic recipient creation/deletion and changes
to bound name/email/role are refused. Locale/order edits can retain the identity.
Signature fields still require placement against the current PDF; exact PDF
review remains a separate step.

The dedicated current and historical source responses include
`contract_profile`, `contract_profile_digest` and `contract_parties` for these
documents. Each party includes `slot`, `role`, `recipient_id`, `name`, `email`,
`company_name`, `company_id` and `representative_authority`. These values come
from the selected immutable source, including for old revisions; a later live
template or current recipient row cannot rewrite past assertions. Legacy source
responses omit these fields.

A human HTML text revision can change a representative's declared name/address.
The transaction archives the old source, review, fields and recipient assertions
before updating that same pinned UUID and projecting the new PDF. It expires old
recipient links when identity changes and clears placement/review. Source,
recipient updates, history and audit commit together; stale pins, rendering
failure or revoked authority cannot partially change the intended parties.
Send and signing recheck both pinned identities. Recovery and finalization also
require each party's captured signature. Already-finalizing rebuild and resume
recheck these requirements under the document lock before source-version work,
rendering or evidence access. Scoped pre-sign delegation remains unfinished.
Per-organization CRM freshness and source provenance are locally verified at
the API/backend boundary; salesperson record-selection/mapping UI, reviewed
rendered CRM contracts and real private-provider acceptance remain open.

### Approved automatic branded signing page

This opt-in format uses `schema_version:3`, the reviewed contract profile above
and an explicit `signing_page` object. Existing schema-1/2 templates keep their
original commitments and layout; enabling the option creates a new saved
revision requiring complete owner preview and approval.

```json
{
  "version": 1,
  "policy": "hash-branded-signing-page-a4-v1",
  "branding": {
    "primary_hex": "#243047", "accent_hex": "#B78632",
    "surface_hex": "#FFFFFF", "text_hex": "#202938",
    "muted_hex": "#586575", "logo_url": "", "logo_alt": "",
    "font_heading": "Inter", "font_body": "Inter",
    "signature_color": "#243047"
  },
  "logo_asset": "", "logo_sha256": "", "logo_alt": "",
  "font_sha256": "3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62"
}
```

Every member is required. Colors are six-digit hex values. Text and muted labels
must contrast with the surface by at least 4.5:1; large headings and signature
borders need 3:1. The bundled Inter font is pinned by digest. This first policy
supports its Latin glyph set; unsupported identity characters are refused before
rendering. Company/representative/authority text is capped at 80 characters and
display units, company ID at 40 and email at 128. Outer whitespace, controls and
invisible direction/format characters are refused. These are page-layout limits,
not universal identity or email limits.

General branding logo URL and alt remain explicitly empty. An optional page
logo uses a declared bounded PNG/JPEG asset's name, exact SHA-256 and nonblank
plain alt text, capped at 80 characters/display units. Without a logo all three
page-logo members are empty. No remote or later live organization logo is used.

Hash renders the body and app-owned A4 suffix separately. Master CSS cannot
move or hide the suffix. The application applies the malware scanner gate to
both inputs before worker admission. The isolated worker inspects both PDFs,
refuses active PDF facilities, composes under the combined 50 MiB/500-page limits, then verifies
the body geometry and exactly one fixed suffix page. Its measured raw Chromium
A4 boxes are 594.959960 by 841.919980 points; manifest milli-points describe the
geometry without normalizing the PDF. A configured compatible worker is required
even in explicit development for this operation.

The immutable schema-3 source binds the approved brand/font/logo policy, printed
parties and stable recipient UUIDs, both component digests, merged-input and
sanitized-output digests, page count/geometry and fixed field plan. Within the
original authorization/quota/audit transaction, Hash creates exactly two required
signature fields on the last page: customer at x10/y42/w80/h7 percent, provider
at x10/y79/w80/h7 percent. Generic field CRUD is refused. Sender/signing/finalizing
and direct recovery validate the complete party/field/brand binding before
external effects. Deferred database guards refuse direct field, recipient,
branding or document-mode drift. This binds declared identities; it does not
externally verify identity, authority or legal suitability.

Current and historical HTML source responses add `source_schema_version`.
Schema 3 includes validated `signing_page` and `signing_artifact`; they expose
the approved policy, plan and component/geometry commitments, without storage
keys, VersionIDs, raw master or inline assets. The owner UI shows protected
signature locations and still requires all-page review of the actual contract.
Send remains closed if source validation, field readback or page rendering fails.

Text revisions archive the prior source/parties/fields/review/brand, preserve
party UUIDs, render a new page and create fresh field UUIDs with the new source
commitment. Review resets even when PDF bytes match. Old coordinates are never
adopted as the new plan. Migration76 allows only that per-render artifact to
change; the original approved master/policy/bindings remain fixed. Down refuses
retained schema-3 templates, revisions or document sources. Release requires the
matching app, schema and protocol-2 composition worker with old processing
drained; mixed incompatible workers must not be used.

### Revising declared document text

`GET /api/v1/documents/{id}/html/source` returns the current declared values and
plain-text sections, source commitment, PDF digest, page count and materialization
revision. It includes `can_edit`, computed from the live draft and original
sender/owner authority. It omits the HTML/CSS master, inline assets and storage
identifiers. Viewing source does not register a legacy materialization or write
history.

The original sender or an owner can call
`POST /api/v1/documents/{id}/html/revisions` for a draft:

```json
{
  "expected_updated_at": "<current document timestamp>",
  "expected_html_source_commitment": "<current source SHA-256>",
  "values": {"customer": "Updated customer"},
  "sections": {"scope": "Human-proposed wording for review"},
  "summary": "Updated customer and scope"
}
```

Omitted maps and entries preserve the current text. Explicit null, duplicate or
unknown keys, invalid Unicode and undeclared values/sections are refused. At
least one declared text change is required. Identical text or summary-only
requests return 409 without a revision, object or audit write. Values and sections remain escaped
plain text; the request cannot replace the frozen master, defaults, approved
template revision or assets. The request is capped at 1 MiB; each declared
limit also applies. The optional summary is limited to 500 characters.

Rendering, scanning, isolated PDF sanitation/page counting and versioned object
storage run outside database locks. The original credential, live author and
observed document/source are rechecked before committing. Successful revisions
append immutable history, archive the prior review, layout and party context,
switch the current materialization and clear unsigned fields and review. Old
coordinates are not reused. Each immutable PDF materialization and captured
snapshot retains its own source-sanitization report; the current PDF/report
projection changes atomically. Legacy unmeasured history stays unknown.
Captured signature, acceptance or field evidence,
unfinished sealing and pending privacy work refuse a revision. A changed source
requires fresh human review and fresh signature placement (generated again for
schema 3), including when the
new PDF digest is identical. Success is 201 with `document`,
`materialization_revision`, `page_count`, `review_required:true` and
`placement_reset:true`. No invitation is sent by this operation.

Missing or malformed observations return 428. Invalid text returns 400, changed
observations or forbidden state 409, import
capacity 429 with `Retry-After`, and unavailable processing dependencies 503.
401/403 apply to expired or revoked authority. A failed precommit write removes
only the newly owned object version. An ambiguous commit retains it for
canonical reconciliation; refresh history before retrying.

### Retained materialization history

`GET /api/v1/documents/{id}/html/history` returns the latest 200 immutable
materialization descriptors in `{revisions:[...]}`. Each entry identifies its
sequence, source/PDF commitments and whether it is current.
`GET /api/v1/documents/{id}/html/revisions/{sequence}/source` returns the retained
declared text with `can_edit:false`.
`GET /api/v1/documents/{id}/html/revisions/{sequence}/pdf` verifies the exact
retained storage version, digest and page count. It never falls back to the
latest object. Successful PDF responses are `no-store` and include
`X-Hash-Document-Id`, `X-Hash-Materialization-Revision`,
`X-Hash-HTML-Source-Commitment`, `X-Hash-PDF-SHA256` and `X-Hash-PDF-Pages`.
Authority and the document observation are rechecked after storage/worker waits.
Missing history returns 404; a missing or altered pinned object is an integrity
failure. Worker capacity/unavailability retains its 429/503 response.

HTML documents do not support block-version Diff or Restore; these operations
refuse rather than implying that different rendered documents contain zero
changes. Approving a negotiation change request on a PDF/HTML document records
acceptance of the request without automatically rewriting prose. The sender
must revise the declared text and review the fresh materialization.

Reopening an unsigned ceremony archives the original invitation epoch, notice,
review, layout, parties and persisted retention deadline before invalidating
links. Reopening does not extend the archived retention clock. Historical
objects remain protected by inventory, purge and privacy safeguards; disposal
still requires an approved retention/export workflow.

Recipient redaction and recipient-only exports cannot account for personal data
in retained HTML designs, defaults and source history. When any such inventory
exists in a tenant, automated erasure fulfillment and that export return 409 and
require separate privacy/retention review; requests can remain in progress.
The handler rechecks after the tenant audit lock to cover concurrent first-design
creation. Archiving preserves revisions. This is a preservation and truthful
refusal boundary, not an approved indefinite retention policy or a complete
HTML privacy disposal/export workflow.

### Designed PDF import size limits

The designed-HTML document import retains its 20 MiB JSON body limit and returns
413 for oversized JSON, including unknown-length trailing whitespace. Exactly
one JSON value is accepted before scanning or rendering. Raw HTML
and every growing sanitized HTML/CSS output are limited to 20 MiB; an expanding
attribute or CSS rewrite that exceeds this bound returns a specific 413 before
PDF rendering or persistence. The registered MCP create_pdf_document tool uses
the same sanitizer; its existing HTTP transport limit remains 1 MiB.

All application HTML-to-PDF requests are capped at 24 MiB for the complete
encoded multipart body, including assets, MIME headers, fields and closing
boundary. Oversize components are refused before header assembly or conversion
to request bytes, and exact serialization overflow is refused before HTTP
dispatch. Existing retries replay the same accepted body within one deadline.
This is a request-body limit, not a bound on HTTP headers or process memory.
The independent renderer listener ingress, timeout-retirement and operating
profile qualification remain separate release requirements.


## Response report-capacity admission

New `POST /sign/{token}/sign` and `POST /sign/{token}/accept` responses measure
the complete unsigned participant-report certificate payload in the same native
transaction as their provisional response, audit and optional package receipt.
A deterministic report/payload size refusal returns HTTP 409 with:

```json
{"error":"this negotiation's evidence report has reached Hash's size limit; contact the sender before continuing"}
```

That refusal rolls back legal response/receipt/audit/notification/finalization
database effects. The original authenticated link remains usable; another
response still refuses while the report exceeds its limit. Existing external
signature-object preparation can have occurred and is not a database rollback.
Missing measurements, malformed history, unavailable funding and native
availability failures return HTTP 503, rather than claiming a size conflict.
No history is silently dropped and the existing limits are unchanged.

The final required response atomically freezes the actual locked family before
committing. Its original deadline/credential is rechecked after admission work.
This boundary does not reserve future report headroom after partial responses;
later-writer admission and configured/browser qualification remain tracked in
`COMPLETION-STATUS.md`. A successful acknowledgement's cleanup checks its own
operation; unrelated pending consumers retain their resources independently.


## Completed contract and audit certificate downloads

A terminal successful signer `POST /sign/{token}/sign` or acknowledgement `POST /sign/{token}/accept` returns `completed: true` with `final_pdf_url` and `audit_cert_url`. Both relative routes carry the same freshly rotated completion credential. Pending responses provide neither link. A terminal context reload never recreates these credentials from the original invitation.

`GET /sign/{completed-token}/final-pdf` downloads the completed contract. `GET /sign/{completed-token}/audit-cert` downloads its separately stored audit certificate; it has no paid evidence-export requirement. Completion emails include both links for every eligible signed/accepted recipient and authenticated artifact links for the sender. Historical certificates retain their original scope. New participant reports bind the participant-visible negotiation/revision history at their stated cutoff; internal discussion is excluded.

Recipient download credentials are read-only and expire after24hours. Both routes use the existing download IP/token rate limits. The certificate route requires exact key/SHA-256/storage VersionId pins, verifies stored bytes, and rechecks the original credential deadline, current authority and certificate identity after storage work. A revoked/expired token, changed certificate or incomplete certificate commitment does not expose certificate bytes. Preserve the digital originals and certificate; the separate optional evidence-bundle export remains a different capability.


## Explicit package responses and archived originals

`POST /sign/{token}/sign` and `POST /sign/{token}/accept` accept an optional
`package_response` object. It is required when the current ceremony has a bound
package, and must be omitted for ordinary or legacy-envelope ceremonies:

```json
{"package_response":{"manifest_sha256":"<64 lowercase hex>","legal_commitment_sha256":"<64 lowercase hex>","incorporation_version":"hash-package-incorporation-v1","incorporation_sha256":"<server copy digest>","consent":true}}
```

Signing also supplies `typed_name` and `font`. The privacy-notice digest header
remains independently required; it cannot supply whole-package consent. Obtain
the incorporation copy and commitments from authenticated package metadata.
Missing package consent returns428, malformed/unchecked consent400, and changed
observations412. The same response transaction binds the real audit row,
signature where applicable, exact Send/capture and incorporation version. An
identical retry with a still-current credential observes the original receipt.

Successful terminal Sign/Accept responses additionally provide
`package_portal_url` at `/completed/{fresh-completion-token}`. Completion emails
include this reloadable read-only portal alongside final PDF and report links.
The invitation credential grants no terminal access. The fresh credential has
the same24-hour limit as final/report downloads; completed access does not reopen
the contract's former signing deadline or authorize a mutation.

`GET /sign/{completed-token}/completed-package` returns the same frozen public
package descriptor shape, including the server-authored incorporation copy, with
document/recipient binding headers and `Cache-Control: no-store`. Genuine
ordinary or legacy-envelope absence returns `{"package":null}`. Inconsistent or
unresolved current package history refuses delivery; it is never treated as
ordinary absence. Package presence requires that recipient's exact M107 response
and the M108 participant report tied to the published final/detached artifacts.
Historical ordinary absence does not invent a retrospective package or report.

`GET /sign/{completed-token}/completed-package/members/{position}/pdf` downloads
the exact original main document at position0 or ordered annex1..16. It requires
the same strong commitment-pair `If-Match` header and returns the same exact
length/SHA/pages/package headers as the active member endpoint. Missing or
malformed preconditions return428/400, stale observations412, absent members404,
and native availability failures503. Revoked, expired, nonparticipant or
privacy-blocked access never returns PDF bytes. It revalidates original expiry,
all captured subjects and exact receipt/artifact associations after provider IO.
Downloads are read-only and do not create consent or new contractual terms.

The active `/package` routes retain their active-only guards. These terminal
routes grant no Send authority. Native package Send requires the exact reviewed
capture, intent and retained completion guarded by migration110; legacy Send
cannot bypass that lifecycle. Current browser, configured-service and release
qualification is tracked separately in `COMPLETION-STATUS.md`.
