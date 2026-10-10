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
and Send. The built salesperson browser and visibly rendered mapped-PDF journey
remain pending; source/UI checks alone do not establish that acceptance.

Initial template population before a document UUID exists is a separate extension.
Uploaded PDF text cannot be changed through this connector. An optional HTML field
that has never been materialized cannot be bound to an empty upstream string in
this unit: it reports `empty_value_not_materialized` and disables Apply, preserving
historical equal-content digest rules. Existing present-empty values are supported.

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
