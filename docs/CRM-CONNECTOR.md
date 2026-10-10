# BrightCRM connector

The operator sets one approved `HASH_BRIGHTCRM_URL` origin and an independently
generated `HASH_CRM_ENCRYPTION_KEY` (32 random bytes encoded as 64 hex characters).
The previous key is accepted only during an explicit re-enrollment window.
Encryption binds each credential to its Hash organization, connection UUID,
generation, origin and exact CRM team/user. Copying encrypted credentials between
accounts or revisions cannot authenticate them. Reads never return credentials.
The development Compose server passes these optional variables with empty
defaults; the production service receives its approved environment file.

An organization owner opens **Settings → Integrations → BrightCRM**, submits a
canonical BrightCRM v1 key (64 lowercase hex characters), reviews the account
returned by `/api/v1/auth/me`, then explicitly enables that account. Saving a new
key creates a disabled candidate; replacing an active key disables the old
connection. Enable performs another account check and advances the encrypted
generation. Revocation clears the encrypted key without needing the keyring,
decryption or an upstream request. Each committed mutation rechecks the original
signed session and live owner and appends an audit event in the same transaction.

Use a separately provisioned read-only integration key. BrightCRM's account
response does not expose the key's scopes or expiry; Hash does not claim to
verify those properties. This API-key integration is separate from sender OIDC
login. Automatic CRM OAuth enrollment/refresh is not implemented.

The production transport currently permits HTTPS public destinations only;
private, loopback and Tailscale/CGNAT addresses are refused. The development
loopback exception used by synthetic tests is not a production configuration.
Connecting to the private CloudRebellion CRM requires a separately reviewed,
narrowly pinned transport policy and real account/read acceptance before use.

## Owner API

All routes require the original owner session and the application's exact
browser origin for writes. Responses use `Cache-Control: no-store`.

| Method | Path | Request |
|---|---|---|
| GET | `/api/v1/settings/crm/connection` | None |
| PUT | `/api/v1/settings/crm/connection` | Expected actor IDs, `expected_generation`, `token` |
| POST | `/api/v1/settings/crm/connection/enable` | Expected actor IDs/generation and exact `crm_team_id`, `crm_user_id` |
| DELETE | `/api/v1/settings/crm/connection` | Expected actor IDs and `expected_generation` |

Every mutation includes `expected_org_id` and `expected_user_id` as Hash UUIDs.
They must match the admitted session before network or mutation work begins.
An absent connection uses expected generation `"0"`; all revisions are canonical
decimal strings, preserving PostgreSQL bigint precision in the browser.
Generation exhaustion reserves enable and revoke successors; a terminal revoked
row requires operator reconciliation, never an unsafe integer wraparound.

Responses contain `org_id`, `user_id`, `available`, `configured`, `origin`,
`requires_reconfiguration` and `connection`. The actor witness must match the
captured browser actor. `connection` is null when absent; otherwise it has `id`,
`generation` (string), `status` (`candidate`, `active`, `revoked`), opaque
`crm_team_id`/`crm_user_id`, `verified_at` and `updated_at`. Remote IDs are exact
1–256 character ASCII letters/digits/underscore/hyphen strings, not UUIDs or
company registration numbers. A revoked row retains prior account IDs/time for
operator context. An operator-origin change requires reconfiguration; it cannot
silently reinterpret an existing encrypted account as a new service.

Invalid input returns 400; expired original sessions 401; revoked owner/session
authority 403; changed actor/account/generation 409; unavailable provider/config 503.
Refresh after a conflict or uncertain write before retrying. The API never
exposes raw provider error bodies. Enrollment has an additional 30/minute IP
limit. These process-local bounds are not measured production capacity.

## Contract observations

Draft resolution loads the active connection for the document's Hash organization,
checks the exact CRM account before and after fetching, and reads each selected
record once per resolution. CRM cache/fallback/static values cannot substitute
for a fresh typed observation. Missing or permission-null fields remain
unavailable; a successfully empty scalar remains empty. Decimal values remain
exact strings. Strict bounded UTF-8 JSON refuses duplicates and ambiguous keys.

Supported kinds are `crm.deal`, `crm.contact`, `crm.company`. Paths are unprefixed
catalog scalar names; whole objects and arbitrary nested paths are refused.
Examples are deal `title`, `value`, `currency`; contact `first_name`, `last_name`,
`email`, `full_name` (explicit trimmed first/last transformation), `role`; company
`name`, `legal_name`, `orgnr`, `tax_id`, billing address fields. Contact `role`
does not establish signing authority; company `id`, `orgnr`, and `tax_id` have
different meanings, and a tax ID is not automatically a VAT registration.
See the [catalog](../internal/crmconnection/catalog.go) for all supported fields.

V1 supports one selected deal/contact/company per document. A combined selection
must match the provider's exact deal→contact/company and contact→company foreign
IDs. Missing/null relationships or ambiguous multiple parties refuse resolution;
Hash does not guess joins. Record IDs/team IDs/updated timestamps are checked;
anonymized contacts refuse identity use. HTTP requests have a 10-second bound,
the total batch a 15-second bound, each JSON body 256 KiB and scalar 16 KiB. The
generic client permits 16 unique records/128 references; the contract adapter
applies the narrower one-record-per-kind relationship rule.

Preview reports show server-observed connection generation, canonical origin, account, record
timestamps/body SHA and actual value SHA. Agent overrides are explicitly labeled
and never inherit a CRM verification claim. After external waits, preview checks
the original member/credential, document/bindings and a shared active connection
lock. Send retains the same report through its final authorized transaction,
checks its 45-second deadline from batch completion again before commit (the
remote batch is separately bounded to 15 seconds), and records the exact source
origin/record/account and value/body digests in the immutable audit ledger.

Fresh CRM data must equal the document's reviewed values before Send. A changed
value returns 409 and requires updating the document, producing/reviewing the
appropriate PDF and binding signing fields again. HTML master source/review
guards also verify the printed values. Contract parties and authority still
need human review; these engineering observations do not certify legal validity.
This is a bounded **time-of-read observation**, not an atomic snapshot of the
remote CRM or proof that a record cannot change after the read.

## Document review API

All four routes require an original session belonging to the document sender or
an owner. Writes require the exact application origin. Responses use `no-store`.
Limits are process-local per admitted organization/user: context 60/minute,
search and observations 30/minute each, Apply 10/minute. They do not establish
provider concurrency or production capacity.

| Method | Document-relative path | Purpose |
|---|---|---|
| GET | `/crm/context` | Saved declared fields, redacted binding definitions, catalog and review/account witnesses |
| POST | `/crm/records/search` | Typed discovery; `kind`, canonical `query`, `offset` in 20-record steps |
| POST | `/crm/observations` | Read-only comparison of the complete desired `mappings` |
| POST | `/crm/apply` | Fresh confirmed Apply; same mappings, `reviewed_digest`, `confirmed: true` |

The prefix is `/api/v1/documents/{id}`. Every POST includes `expected_org_id`,
`expected_user_id`, exact `expected_updated_at`, `expected_html_source_commitment`
(empty for blocks), `expected_binding_fingerprint`, `expected_connection_id` and
canonical decimal-string `expected_connection_generation`. With no connection,
use empty ID and generation `"0"`. Context/readback returns these current pins
as `org_id`, `user_id`, `document_id`, `updated_at`, `html_source_commitment`,
`binding_fingerprint` and a safe `connection` object. Binding fingerprints cover
all rows and precise revisions; binding mutations alone need not change the
legacy document timestamp.

A mapping is `{variable,source_kind,source_ref,source_path}`. It must target a
declared field, use the catalog and select at most one record per kind. Omitted
existing CRM mappings are removed only on reviewed Apply; other source bindings
are preserved unless that same variable is explicitly selected. An explicit
empty array reviews unlinking and keeps saved text even without a working CRM.

Observations return canonical mappings, items with saved/fresh exact strings
and typed time-of-read provenance, `review_digest`, `can_apply`, `content_changed`
and `observed_at`. Null/absent or oversized scalars remain unavailable. Optional
`contract_issues` contains bounded readiness issues for candidate contract party
or commercial inputs; it disables Apply. It does not certify signing authority.
The review digest binds the original account/document/ledger and exact selected
values; a fresh equal-value observation may have new body/timestamp provenance.
Apply audits its independently fresh provenance, not a client-provided proof.
Declared context variables and observation items include `current_present`.
An omitted value and an explicitly stored empty string are distinct source
states even when their printed output is identical. Clients must compare both
presence and exact text when validating an observation.

Apply returns the updated document and witnesses. A changed HTML result also
returns `materialization_revision`, `page_count`, `review_required: true` and
`placement_reset: true`. A mapping-only equal-value Apply retains the exact
PDF/source/review, while advancing the document edit witness. Expired original
sessions return401, revoked permissions403, stale witnesses/reviews409, invalid
input400, render capacity429 and unavailable dependencies503. Errors are redacted.
After an uncertain write or a remote document change, explicitly inspect and
adopt the saved document before another write; dirty local wording is preserved.

Migration78 adds current mapping-review state bound to CRM membership/removals,
content, actual reviewer and active account generation. Send checks the parent
and every envelope child before observation writes and after the final variable
freeze. Generic REST/MCP binding edits cannot silently delete the freshness gate.
Legacy CRM drafts need explicit review and Apply. Ordinary no-CRM manual drafts
retain their existing behavior, including larger non-CRM ledgers. Reviewed CRM
ledgers are bounded to128 rows. The audit retains historical application lineage;
this current-state row does not alter signed bytes or source schema1/2/3 domains.
The reviewer FK prevents deleting a retained reviewer, with deferred validation
allowing an organization cascade through documents/reviews and users. Down
refuses any retained review row, including reviewed unlinking.

## Migration and delivery caveats

Apply migration 77 with the coordinated current schema/app/worker rollout and
drain old dispatch/admission before switching versions. The old instance-wide
`HASH_BRIGHTCRM_TOKEN` and `HASH_BRIGHTCRM_WEBHOOK_SECRET` are rejected when
nonempty. No plaintext/global fallback or synthetic account backfill is used.
Old draft bindings using `deal.amount`, nested names or whole-object paths need
explicit review and rebinding to the real catalog; historical signed/frozen
values are preserved. Rolling old SELECT-star readers/writers across this
candidate's other schema changes remain unsupported. Down refuses retained
connection rows and company bindings instead of erasing evidence/configuration.

The production legacy `/webhooks/brightcrm` receiver has no configured global
secret. BrightCRM currently does not emit the expected deal/contact CRUD events;
its general callback envelope lacks the mandatory tenant-bound routing contract.
Real invalidation callbacks remain a separate producer/protocol acceptance gate.
Direct fresh reads provide the current bounded correctness path.

The document draft now has a scoped CRM panel for the document's original sender
or an organization owner. It searches the selected record type, maps catalog
scalars to declared fields, compares saved and fresh values, and requires explicit
confirmation before Apply. Apply independently fetches again; changed values or
actor/document/source/binding/account witnesses return 409 without committing.
Manual sections and unmapped static values are retained. An HTML change appends
an immutable PDF/source revision and requires a fresh PDF review and placement;
blocks update their saved values and history. Dirty/unsynced editors block Apply
and Send. The local built salesperson journey now passes against actual
PostgreSQL/Chromium and the isolated PDF worker with protected synthetic CRM/S3
peers. It verifies changed values in the exact PDF, manual/static text preservation,
foreign-actor and fresh-value refusals, explicit unlink after provider revocation
and recovery by inspection/adoption after a committed response is lost. Three
two-page PDFs pass byte/source/variable/section reconciliation and all-page visual
review. Updated frontend checks pass 303 tests and the production build. Reviewed
HTML responses may omit the false review flag; invalid types are refused and
changed content still requires explicit true. Mobile CRM/PDF review fits 390px;
mobile field placement and recipient controls remain separate acceptance work.
No real provider, Send/signing or production acceptance follows from this fixture.

The earlier verified document-scoped unit did not include initial template
population or an optional value's first explicit empty string. The newer local
candidate adds the template API below and a narrow optional absent-to-empty
revision. Only a declared optional absent value can become exactly `""`, with
the approved origin, all existing text/sections and party identities unchanged.
It still creates a fresh immutable artifact, resets review and user placement,
and regenerates protected schema-3 fields. Repeated empty no-ops and required
empty values remain refused. Historical source domains/bytes are preserved.
Uploaded PDF text cannot be changed through this connector.

## Initial template population

This local candidate API is for approved HTML templates before a draft exists.
It uses the current sender/owner browser session. Discovery and observation are
read-only; they do not allocate a document, mappings or recipients. Prefix:
`/api/v1/templates/{id}/html/crm`.

| Method/path | Input and result |
| --- | --- |
| `GET /context` | Query `expected_template_version` and `expected_template_content_sha256`; returns original org/user, exact approved template pins, active connection identity/generation, declared variables/defaults and scalar catalog. |
| `POST /records/search` | Complete context witness plus `kind`, `query`, `offset`; typed bounded account-scoped record search. |
| `POST /observations` | Witness, `candidate` (`name`, `values`, optional `sections`/`expires_at`) and full `mappings`; returns exact saved/fresh values, canonical mappings, provenance, `review_digest`, `can_create`, observation/deadline and a purpose-separated `review_receipt` when creation is admissible. |

The witness fields are `expected_org_id`, `expected_user_id`,
`expected_template_version`, `expected_template_content_sha256`,
`expected_template_approved_by`, `expected_template_approved_at`,
`expected_connection_id` and `expected_connection_generation`. Approval time is
the exact RFC3339Nano value returned by context. Connection generation is a
decimal string; an unavailable account uses empty ID and generation `"0"`.
Explicit nulls are refused. Candidate values preserve the user's entered text;
mapped fresh values form a separate preview/create overlay. New legal wording
is never supplied by the connector.

After the user reviews and confirms exact values, create through the ordinary
HTML document endpoint with a stable `request_id` and `crm_population` containing
the witness, full mappings, `reviewed_digest`, `review_receipt` and
`confirmed:true`. The receipt binds the original signed session, approval,
candidate, mappings, account and observed exact values. It expires 45 seconds
after its original source snapshot completes; checking it does not refresh
that deadline. Creation fetches independently and retains a separate fresh
45-second deadline. Account/actor/template drift, changed fresh data, expired
observations and failed audit roll back creation. Provider/render/worker/storage
waits do not retain database locks. Review, mappings and creation evidence commit
atomically with the draft. Exact own-object compensation applies before commit;
an ambiguous commit retains the artifact for durable request recovery.

Keep uncertain creation pending under its original UUID. Authenticated recovery
and same-command replay return current document state plus immutable original
creation pins, including a tombstone after deletion. A 404 `unconfirmed` is not
permission to create another UUID. Recovery markers contain only actor/template/
request metadata and commitments, never contract text, CRM data or bearer tokens.
See [HTML creation/recovery contract](API.md#html-design-draft-api). Live provider,
private transport, actual scopes/callbacks and Reactor acceptance remain separate.

An original sender/owner can explicitly stop a pending request through
`POST /api/v1/templates/{id}/html/document-requests/{request_id}/close` with
exactly `expected_org_id`, `expected_user_id` and `confirmed:true` (2 KiB limit).
The canonical actor pair must match the admitted session; current authoring
authority and the exact browser origin are rechecked. Close is limited to
10/minute per organization/user. It uses no provider, renderer, object I/O,
current approval or expired observation receipt.

A successful Close returns either the existing committed envelope or
`state:"closed"` with exactly `org_id`, `user_id`, `template_id`, `request_id`
and durable `closed_at` in addition to `state`. GET recovery returns the same
closed union. Both use `no-store`. Repeating Close retains the original outcome;
closing an already committed request cannot undo it. After a lost response or
ambiguous commit, keep the UUID pending and inspect or repeat Stop for that
same original actor/template/request. A 404 alone still cannot release it.

Only explicit acknowledgement of a verified closed outcome clears the browser
marker. Resident manual values and scope wording remain, while prior
confirmation/receipt is invalidated. Refresh the current design, select/read
the current account and confirm fresh values before a new user-initiated creation
gets another UUID. A committed response follows the existing explicit Open or
deleted-document acknowledgement flow. The browser does not adopt a late
response from an invalidated operation. Reload stores identifiers only, so it
cannot restore lost manual prose or the original semantic command.

Migration 79 adds the actor-scoped creation ledger. Database guards derive its
initial pins from the exact normalized materialization and refuse pin rewrites,
manual detachment, ledger deletion while the organization exists and Down with
retained receipts. Document deletion can only detach the current pointer; an
organization cascade can remove this metadata once retained templates,
materialization history and other dependencies have been disposed of through
an approved retention workflow. This does not enable a raw whole-organization
delete or establish the complete disposal workflow. Member removal retains the
original opaque actor ID. Privacy inventory includes these records; controller retention
and disposal decisions remain required. Apply the coordinated schema/app/worker
release before using the new browser flow.

Migration 80 adds an immutable `committed|closed` registry keyed by organization,
original actor and request UUID, without rewriting migration-79 receipts or
historical schema-1/2/3 source bytes. Final creation and Close serialize through
the same unconditional quota lock, including internal nil-billing callers.
If closure commits first, an older in-flight preparation cannot commit a draft;
its exact uncommitted object is compensated. If creation commits first, Close
returns its immutable creation evidence. Deferred database guards require every
committed outcome to match its original receipt and every closed outcome to
have none. Terminal identity/state/time cannot be rewritten or individually
deleted while the organization exists. Both metadata tables permit an
organization cascade subject to the retained dependencies and approved disposal
workflow above; retained closed outcomes refuse migration-80 Down. Actual005
passes the local 38-test/103-outcome PostgreSQL suite, including closure races,
credential/audit rollback and terminal guards. It verifies closed metadata's
cascade in a tenant without retained HTML history; committed-history disposal
remains unverified. Browser003 also passes 373 checks for initial creation,
actual lost-response/reload recovery, drift refusals and explicit Stop/readback/
acknowledgement/fresh review. Its two unsigned three-page PDFs and selected
mobile screens were visually inspected; the local completion recap records
typography caveats. These synthetic fixtures do not establish live-provider,
final signing or production acceptance.

Hash outbound delivery now claims one job immediately before dispatch, retries
temporary endpoint/key/event dependency failures with bounded existing backoff,
binds the authenticated endpoint and original event to the same organization,
and marks only the exact still-live attempt/lease. DNS respects request deadlines.
Cancellation or a failed mark leaves the claim to expire for recovery. Only
fixed diagnostic codes are persisted; historical raw diagnostics are hidden
on read. At-least-once delivery requires receiver deduplication using the stable
event ID. Owner terminal-redrive and actual receiver recovery remain pending.

Reactor's current SDK request omits Hash's required template version/content-SHA
pins. Those safeguards remain mandatory; a reviewed upstream adapter change and
actual idempotent dispatch/callback acceptance are still required. Local synthetic
checks do not establish real CRM/SMTP/Reactor or production acceptance.
