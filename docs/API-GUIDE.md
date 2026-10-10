
# Hash API guide

Updated 2026-10-10 for the local candidate. Browser routes require a session
cookie; document writes require a sender or owner, while recovery, archive and
organization-setting writes require a current owner. Session generation, live role and expiry are checked at the operation
boundary. Mutations use the application's same-origin protection; responses
use `no-store`. See [route inventory](API-ROUTES.md) for middleware and the wider
API surface. This guide is not a complete OpenAPI contract for that surface.

## Connection and canonical save

`GET /api/v1/documents/{id}/collab?expected_updated_at={encoded timestamp}`
upgrades to a binary WebSocket. Supply exactly one `expected_updated_at` from the
document response. A stale observation returns 412 before upgrade; it is checked
again under the document lock before any initialization grant. Keep the local
draft and reload the current document when it changes. Server and frontend must
be released together; clients without this observation cannot connect.

For an active editing peer, `POST /api/v1/documents/{id}/collab/save` accepts:

```json
{
  "peer_id": "connection peer identity",
  "checkpoint": "64 lowercase hexadecimal characters from message 7",
  "generation": "1",
  "expected_updated_at": "2026-10-05T12:00:00.123456Z",
  "blocks_json": {"version": 1, "blocks": []}
}
```

The peer must belong to the session user. Canonical content, history association
and audit commit together; success returns `{document, generation}`. Message 8
sends the committed decimal generation and exact timestamp to connected peers.
Clients accept only newer receipts and update their reconnect observation without
replacing local editor content. A changed checkpoint returns 409: capture a fresh
checkpoint and retry. A changed canonical observation returns 412: preserve and
review the draft. The editor makes at most three checkpoint attempts per save.

## Owner recovery and archives

`GET /api/v1/documents/{id}/collab/recovery` returns the current `document`,
boolean `document_deleted`, decimal-string `generation`, and up to 16 archive metadata records. Each record
contains `id`, `origin` (`persisted` or `active_room`), decimal-string
`observed_canonical_generation`, nullable decimal-string `history_generation`,
`created_at`, `expires_at`, and `size_bytes`. Unknown legacy generation stays
`null`; the server does not guess its association.

After downloading the local draft and reviewing the saved document, an owner can
`POST` the same URL with:

```json
{
  "generation": "2",
  "expected_updated_at": "2026-10-05T12:00:00.123456Z",
  "acknowledged": true
}
```

Recovery archives both persisted and active room replay, keeps canonical content,
advances its generation, initializes an empty associated history, and commits the
audit atomically. It then closes and awaits old socket handlers before releasing
the join fence. Success returns `{document, generation}`. The editor preserves
the local draft; reloading requires a separate explicit confirmation. Recovery
requires an accessible block draft. Responses include 409 for a busy recovery or
required privacy review, 412 for changed observations, and 507 for archive
capacity. No existing archive is discarded to make room.

`GET /api/v1/documents/{id}/collab/recovery/archives/{archiveID}` downloads one
audited binary attachment. It contains a sequence of lib0 length-prefixed Yjs
updates, at most 8 MiB, rather than a canonical block-tree export. Never replay
older archives directly into a current room: inspect and merge approved content
separately. `DELETE` the same URL requires JSON `{"acknowledged": true}` and
commits its audit with deletion. Pending linked or org-wide access, portability
or restriction requests defer deletion.

Owners can list, download and explicitly delete archives during a draft's
soft-delete grace period through the same endpoints. The privacy-request page
provides archive review for a selected linked document. This mode exposes no
editing reset/reload action; `POST` recovery for a deleted document returns 409.
Live owner role, session generation and expiry are checked after document lock
waits, and privacy checks run with READ COMMITTED isolation.

Each document has a budget of 16 archives and 64 MiB. Archives have a durable
90-day recovery grace, separate from signing-evidence retention. The hourly
worker removes at most 100 expired archives per invocation, skips lock
contention, and defers linked or org-wide open/in-progress privacy requests.
Erasure fulfillment refuses while archives remain; recovery after fulfilled
erasure requires separate privacy review. Backup/PITR retention and broader
legal holds require the documented operator procedure.

`DELETE /api/v1/documents/{id}` requires a current sender or owner session and a
draft. It returns 204 after atomically recording soft deletion and its audit;
authorized retries return 204. It retains source files and recovery archives
through the 90-day grace period. Pending linked or organization-wide privacy
requests, or a contested privacy fence, return 409 without changing the draft.
The later worker purge uses the same privacy fences and exact source-version
identity. Storage refusal preserves the row for retry; shared source references
retain their bytes. Ordinary versioned S3 deletion only creates a marker, so the
worker uses the persisted version ID without retention bypass. See
[S3 version deletion](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeletingObjectVersions.html).

Drafts with captured signing/acceptance/field data, terminal artifact metadata or
pending sealing records are retained for review before source retirement. These
are anomalous draft states; deleting their parent would lose evidence references
even if the object itself were preserved.

Privacy-request creation/transitions and recipient inventory export keep the
existing sender-or-owner policy. They authorize the signed session again under
live user locks after waits, with bounded READ COMMITTED transactions and expiry
checks before commit. Membership changes require a live owner, preserve the last
owner, and serialize organization changes with `FOR NO KEY UPDATE` so pending
user authorization and audit foreign-key checks can complete without a lock cycle.

## Document creation

`POST /api/v1/documents` and MCP `create_document` create drafts from block
content or an existing PDF template. Both require a live sender or owner;
REST retains the original signed session and MCP retains the originally
verified organization-wide key with `write:authoring`. A document-scoped key
cannot create another document. Quota and operator-entitlement checks remain
part of the same transaction.

Creation uses READ COMMITTED with a ten-second deadline. It acquires the
organization quota lock, locks any referenced active tenant template, and
then verifies the live member and original credential. The template remains
locked while defaults/source pins are copied, quota is enforced and the audit
is appended. A final credential check precedes commit and event publication.
Expiry, demotion, logout/key revocation, quota refusal or persistence failure
roll back the draft, optional version snapshot and audit together.

Every supplied `template_id` must identify an unarchived template in the
caller's organization with the requested `source_kind`, even when both
`blocks_json` and `variables_json` are explicit. For block documents, omitted
content and variables copy the current locked template defaults. Explicit
values replace that component; an empty block tree or `{}` variables remain
explicit overrides. Without a block template, omitted components default to
an empty version-one tree and `{}`. Block IDs are normalized once for storage.
Variables must be a JSON object containing only string values; `null`, arrays,
numbers and null-valued members are refused.

PDF creation requires a PDF template and retains its exact storage key, digest,
version ID and evidence-pin policy. Its declared variable defaults or explicit
`variables_json` populate document data using the same string-map validation.
This does not replace text in the already-rendered PDF. A version-one named-party
signature layout materializes fresh recipients and positioned fields in the
same transaction; creation never copies a previous document's recipient UUIDs.

## Reusable PDF signing layouts

From an editable PDF draft, `POST /api/v1/documents/{id}/pdf-template` accepts:

```json
{
  "name": "Approved service contract layout",
  "expected_updated_at": "2026-10-10T09:00:00Z",
  "expected_field_ids": ["observed signature field UUIDs"],
  "parties": [
    {"recipient_id": "current field owner UUID", "role": "provider", "label": "Provider"},
    {"recipient_id": "current field owner UUID", "role": "client", "label": "Client"}
  ]
}
```

The server verifies the exact PDF object/version/digest and isolated page count,
then reads the locked draft's fresh recipients and fields. The observation and
complete party mapping must match. Signature fields must be required and fit
within the verified source pages. The stored `fields_json` is an explicit
`{version:1, parties:[{role,label}], fields:[{party_role,type,page,x_pct,y_pct,w_pct,h_pct,required,label}]}`
layout containing no recipient UUIDs, names, emails, tokens or captured values.
This version supports signature fields only. The fixed printed PDF text remains
the approved source content; variable data does not rewrite it.

REST document creation and MCP `create_document` require
`expected_template_version` and a complete `parties` array when that template
has a version-one layout. Each binding supplies `role`, fresh `name` and `email`,
and optional `locale`. The locked template revision must match. Every party
gets a fresh recipient UUID, token hash and assigned fields, with recipient
quotas enforced and canonical creation events committed atomically. Layout
documents default to parallel routing. Declared roles must be distinct; role
identity is separate from a person's email address. Historical array-shaped
templates retain their existing blank-designer creation behaviour.

The sender UI provides PDF **Save as template**, named party slots and the
template library's fresh-party form. A rejected save or stale template keeps the
form for review. New PDF template field updates validate the versioned layout;
unversioned nonempty arrays are refused with conversion guidance.

REST returns201 with the draft. Missing/foreign/archived templates return404,
wrong source or invalid input400, expired credentials401 and revoked authority403.
Existing quota/entitlement errors keep their billing statuses; unexpected
database/audit errors return generic500. MCP reports refusals as tool errors.
No invitation is queued by creation; review and Send remain separate operations.

## Document, block and variable-binding authoring

Document PATCH, every block mutation/import, MCP `set_variables`, binding
upsert/delete and version restore require a current sender or owner and an
undeleted draft. REST
retains the original signed session cookie. MCP retains the original admitted
key with `write:authoring` scope and document restriction, without claiming a
single-use document token twice. After the parent row lock, admission checks the
live member and original credential, retained signing/acceptance/field evidence,
sealing state, and linked or organization-wide open/in-progress privacy review.
A contested privacy fence returns promptly so the caller can retry.

These transactions use READ COMMITTED with a ten-second deadline and check the
original credential again after content/version writes and transactional audit
logging, immediately before commit. Expiry during an audit wait rolls everything
back. Audit records use the checked live actor; events publish only after commit.
Document PATCH now snapshots the committed name, source, blocks and variables
in the same transaction, matching the block/MCP authoring history path. Version
failures also roll back the edit. Source restrictions and timestamp conflict
checks remain in force. Metadata-only PATCH supports both block and PDF documents;
block content and variable replacement require block sources.

REST and MCP restore also require `expected_updated_at` from the observed live
document, preserve the scoped historical-version lookup, and refuse PDF-source
historical content. Successful restore commits historical blocks/variables,
new version history and audit together. Read/list version routes are unchanged.

Document PATCH and block mutations/imports require `expected_updated_at` copied
from the current document response. Missing observation returns 428, malformed
RFC3339 timestamps 400, and stale observations 412. Input errors return400,
expired credentials401, revoked authority403 and absent/foreign/deleted
parents404. Non-draft state, retained evidence/sealing state or pending/contested
privacy review return 409. Database/audit failures return generic500. MCP reports
refusals as tool errors and sanitizes unexpected database errors. Refused edits
preserve document content, metadata, versions/history and audit state.

| Binding REST route | Request | Success |
| --- | --- | --- |
| `PUT /api/v1/documents/{id}/variable-bindings/{name}` | `source_kind`; optional `source_ref`, `source_path`, `fallback` according to source | 200 with binding |
| `DELETE /api/v1/documents/{id}/variable-bindings/{name}` | No body | 204, including an already-absent binding on an admitted draft |

Binding names match `^[A-Za-z_][A-Za-z0-9_.]*$` and are at most128 UTF-8 bytes.
All stored binding strings must be valid UTF-8 without NUL. Source paths are at
most1024 bytes and fallback text at most16KiB; fallback newlines are preserved.
CRM deal/contact and scanner identifiers use the existing safe single-segment
ASCII alphabet and are at most256 bytes; path traversal, query separators and
URL fragments are refused. Other references are at most1024 bytes. REST permits
an empty source path to select the complete entity; MCP source tools retain their
required path contract. Static/agent references may be empty and `org.setting`
ignores the reference. REST upsert has a16KiB total JSON body cap, including JSON
overhead. Admission validates these inputs without fetching a CRM/scanner source
while database locks are held.

Binding authoring preserves existing resolver observations and delete
idempotence. Read-only preview and send-time observation rules are described
under [document previews](#document-previews). Real CRM record/mapping correctness
and deployed integration acceptance still require separate verification.

## Template and metadata authorization

REST block/starter/PDF template creation, update and archive retain the original
signed session and live sender/owner membership through commit. Update/archive
lock the current unarchived tenant template before filling omitted values.
Expired/revoked authorization returns401/403; missing, foreign or archived
templates return404. Audit/mutation failures return generic500 and roll back.
The organization template library remains shared among authorized senders and
owners. PDF templates require a positive page count before any object write.

MCP `set_expiry` uses `write:workflow`; `attach_metadata` uses `write:authoring`.
Both require an editable undeleted draft, the original admitted key/document
scope, live sender/owner, no retained evidence/sealing state and no pending
privacy fence. Credential expiry after an audit wait rolls back the entire
change. Clearing expiry remains supported. Neither tool consumes a document
token a second time. REST soft deletion similarly rechecks the original cookie
after audit and uses detached bounded rollback if canceled.

## Owner settings and organization credentials

REST change-approval mode, branding and logo uploads, AI-provider settings,
API-key creation/deletion and webhook creation/deletion retain the original
signed session and require a live owner inside the transaction. These routes
serialize organization writes, retain the current owner through audit and
check the same credential immediately before commit. Sender permission does
not authorize these settings. MCP `set_org_branding`, `create_webhook` and
`delete_webhook` apply the same owner boundary to their original
organization-wide `write:authoring` key. REST/MCP eIDAS agreement and compliance
baseline/status writes apply the same retained owner boundary. REST manual
compliance-feed checks perform network work before committing the tenant flag
updates and their run audit atomically under fresh owner authorization. Missing
audit rows are internal failures, not missing resources. Routing-tier changes
retain sender-or-owner permission and the current draft/document boundary.

Omitted branding and AI-provider values are resolved from the current row after
the organization lock, preserving a concurrent change that committed before
this operation. Effective merged fonts, logo URLs and provider settings are
validated again. A newly minted API key or webhook signing secret is returned
only after its row and audit commit successfully. Unexpected mutation/audit
failure rolls back, returns a generic error and discloses no new credential.
Logo uploads use unique asset identities; failed transactions compensate the
exact uploaded version/digest rather than replacing or deleting an older logo.
Custom logo uploads remain restricted to development; production support needs
its separate implementation and acceptance work.

REST reports HTTP 401 for expired credentials and HTTP 403 for revoked membership,
session or role. Input validation retains HTTP 400; genuine missing key/webhook
targets return HTTP 404. MCP failures retain its normal tool-error envelope.
Audit failure is distinct from a missing target and rolls the mutation back.
Shared audit, REST internal-error and MCP database-error logs record safe error
types rather than arbitrary database diagnostics, which can contain document
text or credentials. Webhook deletion removes endpoint delivery-attempt rows;
organization audit events remain.

## AI requests and negotiation metadata

Staff REST proposal/settings writes and their MCP counterparts retain the
original signed session or admitted scoped key. They lock the current document
and any parent envelope before checking the live sender/owner, active document
state and privacy fences. Proposals must reference the current block; a parent
proposal must belong to the same document and block. These metadata operations
do not apply new prose to frozen contract content. Terminal or sealing documents
and pending privacy review are refused.

Paid AI operations first commit an authorized `ai.requested` receipt, then
reacquire current document and credential authority before provider dispatch.
Usage rows refer to that exact receipt. Provider-reported usage and `ai.completed` cost
evidence persist independently of the result transaction, including when a
credential expires, the caller cancels or the result audit fails. Result delivery
requires the original credential again after provider and audit waits. A cost
receipt is not proof that a person saw or approved the result.

Public `POST /sign/{token}/clarify` retains the admitted magic link, its original
and current deadlines, current active ceremony and the exact acknowledged
Article 13 notice. Its request/cost events identify the actual recipient with no
staff actor. It does not manufacture a notice acknowledgement. Rotation, notice
epoch changes, privacy holds and late expiry prevent dispatch or result delivery.
The corresponding request outcome and provider-reported usage remain recorded
if dispatch occurred.

Audited requests disable completion-cache reuse and resolve BYOAI settings through
their request transaction. Provider lookup/decryption errors refuse the operation
instead of falling back to a different provider. The existing configured Shield
processing remains in the request path. Raw provider/database diagnostics are
excluded from public errors and usage/audit payloads.

Durable AI requests are conservatively serialized per actual application database
pool. Waiting requests hold no database connection; an admitted request reserves
an accounting connection before authorization locks. Pools with fewer than two
connections refuse these operations before dispatch. The normal singleton worker
lease needs its own connection as well. This bound protects cost persistence;
production AI throughput and queue behavior still need workload acceptance.

## MCP envelope authoring

`create_envelope`, `promote_to_envelope`, `attach_to_envelope`,
`detach_from_envelope` and `reorder_envelope_children` use the original
`write:authoring` credential and live sender/owner through parent, quota and audit
waits. Family topology is checked under parent-first draft locks, with retained
evidence and privacy fences. Attaching or detaching a child requires access to
the envelope itself; a child-only key cannot authorize its parent. Successful
mutations and their audit commit together. Refusal preserves topology, quota
state and audit history, and does not consume a one-use token again.

## Recipient authoring

Recipient authoring requires a sender or owner session and a fresh, undeleted
draft. MCP uses `add_recipient`, `update_recipient` and `delete_recipient`, with
the original admitted organization or document key and `write:authoring` scope.
The role, tenant, target and original credential are rechecked after lock waits
and immediately before commit; this does not claim a document token twice.

| REST route | Request | Success |
| --- | --- | --- |
| `POST /api/v1/documents/{id}/recipients` | `email`, `name`; optional `role`, `order_index`, `locale` | 201 with recipient |
| `PATCH /api/v1/documents/{id}/recipients/{rid}` | Supplied identity/routing fields only | 200 with recipient |
| `DELETE /api/v1/documents/{id}/recipients/{rid}` | No body | 204 |

Creation defaults to `signer`, order zero, and the locked document's current
locale (then `en`); its token deadline is bounded by that draft's current expiry.
Names and email addresses are trimmed. Email must be a simple address of at
most 254 bytes; name must be nonempty, at most 200 characters and 800 bytes.
Control characters are refused. Roles normalize to lowercase and match
`^[a-z][a-z0-9_-]{0,63}$`; `cc` and `viewer` delivery are unavailable. Order must
be 0–1000. Locale must map to a shipped language; supported regional tags such
as `sv-SE` normalize to their base language. Updates preserve omitted fields,
including token/status timestamps; explicit empty values are validated and
refused rather than treated as omissions.

Known input errors return 400, expired credentials 401, revoked authority 403,
and absent, foreign or mismatched document/recipient identities 404. Non-draft,
retained signing/acceptance/field evidence or sealing state, open/in-progress
linked or organization-wide privacy review, and contested privacy fencing return
409. Review the current document or privacy request before retrying. Unexpected
database/audit failures return generic 500 and preserve the exact original state.
MCP reports refusals as tool errors; unexpected SQL, connection or raw no-row
failures are logged server-side and return `internal error`. Genuine scoped
absence retains its explicit not-found error. Existing quota errors retain
their billing contract.

Recipient changes and their `recipient.created`, `recipient.updated` or
`recipient.deleted` audits commit atomically, with the live actor and canonical
recipient identity. Deletion cascades assigned fields, so retained evidence and
pending privacy review are checked first. Deleted subject UUIDs remain in the
immutable audit chain. Draft creation queues no invitation; `recipient.invited`
belongs to Send. Updated/deleted recipient audits are currently internal events,
outside the public webhook allowlist.

## Field authoring

Field creation and deletion require a current sender or owner and a fresh,
undeleted draft. REST uses the original signed session; MCP uses the original
admitted organization or document key with `write:authoring`. The shared
transaction rechecks the live member, tenant, document and original credential
after lock waits and before commit. It does not claim a document token a second
time. Caller-supplied identity or scope values cannot replace an authenticated
credential. Deletion resolves the field's actual owning document and checks that
target against the credential's document boundary.

| REST route | Request | Success |
| --- | --- | --- |
| `POST /api/v1/documents/{id}/fields` | `type`, positive `w_pct`/`h_pct`; optional recipient, page, position, required, label and options | 201 with field |
| `GET /api/v1/documents/{id}/fields` | No body | 200 with `{fields, count}` |
| `DELETE /api/v1/fields/{id}` | Empty for ordinary documents; HTML artifact pins below | 204 |

MCP provides `add_document_field`, `list_document_fields` and
`delete_document_field`. Creation takes `document_id`; deletion takes `field_id`.
REST coordinates use **0..100 percent**. MCP creation coordinates use integer
**0..10000 basis points**: `2500` means 25%, and `10000` means 100%. Both response
DTOs return percentages, including `x_pct`, `y_pct`, `w_pct` and `h_pct`.
Coordinates must be finite and within the page, with positive width/height and a
rectangle that fits wholly inside it. Stored percentages use four decimal places.

HTML-derived documents require `expected_pdf_sha256` and
`expected_html_source_commitment` on both create and delete. REST accepts them
in the JSON body, including DELETE; MCP accepts the same named arguments.
Copy the current digest and source commitment from the document/source read.
MCP `get_document` provides both `expected_*` pins explicitly. Missing or stale
pins return 409/tool refusal without changing fields. Registered HTML pages must
also fall within the current materialization's verified page count. Revision
clears prior unsigned fields, so fresh placement uses the newly reviewed PDF.

Omitted MCP position defaults to `(0, 0)`, width to `1500` (15%), height to `400`
(4%), and page to 1. Explicit zero width/height is invalid. An explicit MCP page
must be an integer from 1 to 1000. REST preserves its legacy page default of 1
for an omitted/nonpositive page and requires positive dimensions in the request.
REST `required` is a boolean, defaulting to true when omitted; MCP preserves the
legacy string form and accepts only empty/omitted, `"true"` or `"false"`, with
empty/omitted defaulting to true. Other strings are rejected.

Allowed fillable types are `text`, `date`, `checkbox`, `dropdown` and `initial`.
An omitted/empty `recipient_id` permits any eligible recipient to fill that
field. An assigned recipient must belong to the current document and tenant.
`signature` overlays require the locked draft's current source kind to be `pdf`
and a document-owned recipient. Block-source signatures come from the block tree;
the authoring endpoints do not insert `date_signed` or `name_auto` fields.

`options` must be a JSON object, defaulting to `{}`, of at most 16 KiB.
Nested metadata must fit within 32 containers, contain valid Unicode without
NUL, and use numbers within PostgreSQL's supported range. The projected JSON
representation, including decimal expansion of exponents, must also fit within
16 KiB. Unsupported input is rejected before the database write; accepted raw
options are preserved.
Dropdowns require `{"choices":["First option","Second option"]}` with 1–100
unique, nonempty UTF-8 choices. Each choice is at most 512 bytes and contains no
control characters. Signer values must match a configured choice exactly.
Labels must be valid UTF-8, contain no control characters, and fit within 200
characters and 800 bytes. Each document has an authoring cap of **1000 fields**,
checked while holding the parent lock so concurrent additions cannot exceed it.

Known input errors return 400, expired credentials 401, revoked authority 403,
and genuinely absent/foreign document, field or recipient identities 404.
Non-draft state, the field cap, retained signing/acceptance/field evidence or
sealing state, open/in-progress linked or organization-wide privacy requests,
and contested privacy fencing return 409 without changing existing fields.
Field mutation and its `document.field_added` or `document.field_deleted` audit
commit together with the live actor; authorization, mutation or audit failure
rolls back rows, field values and audit state. Unexpected database/audit failures
return generic REST 500 or MCP `internal error`, with technical details confined
to server logs. Genuine scoped absence keeps its readable tool error.

## Standalone PDF signing parties

A signature-required PDF needs one recipient per signing role and at least one
required placed signature field for each party. New named-party ceremonies use
signature fields only and support parallel or sequential routing. The legacy
single `signer` ceremony still supports its assigned fillable fields. Visible
values cannot be filled after any party has captured a signature.

Send, signature capture, finalization and finalization retries resolve required
parties from the current document-owned fields. Completion requires every party's
captured signature bound to that exact recipient and one of its required fields;
recipient status alone cannot authorize completion. Original magic-link hashes
and both admitted/current document and recipient deadlines are checked again
after document/audit waits and before capture commits. Extending a deadline does
not rescue a request whose original admission has expired; the client must begin
a fresh authorized request.

Finalization verifies the committed source object/version/digest, preserves its
page geometry and stamps signatures at the designed page percentages. The
separate audit certificate binds the final PDF digest and canonical ceremony
event set. Storage-provider retention, backup and independent restore acceptance
remain release gates.

## Negotiation comments and change resolution

`GET /api/v1/documents/{id}/comments` returns `{comments}`. Each comment includes
`id`, `author_name`, `author_side` (`sender` or `signer`), `body` and `created_at`.
Document access is organization-scoped. Posting requires a sender or owner
session and `POST` to the same URL with JSON `{"body":"Your message"}`.
Success returns the comment with status 201. The body must contain non-whitespace
text, valid UTF-8, at most 10,000 characters and at most 40 KiB. The document must
be `sent`, `in_progress` or `changes_requested`.

The sender mutation locks the document, then the live organization member. It
checks the original signed session generation and expiry after waits and again
before commit. The author name comes from that locked member. Comment, sender
audit identity and notification outbox commit together; refusal rolls all three
back. Known body errors return 400, expired sessions 401, revoked sessions or
permissions 403, missing documents 404, and non-interactive document states 409.
Unexpected failures return a generic 500, with details confined to server logs.
This queue evidence does not establish real inbox delivery.

`GET /api/v1/documents/{id}/change-requests` returns `{change_requests}`.
`POST /api/v1/documents/{id}/change-requests/{crid}/approve` or `/deny` resolves
one open request on a document paused in `changes_requested`. Success returns
`{"status":"resolved","resolution":"approved"}` or `"denied"`. A missing,
foreign or mismatched request returns 404. A resolved request, changed document
state or an auto-apply operation that would destroy captured evidence returns
409. Database and audit failures return a generic 500 and preserve the open
request and original content for retry. Sender approval and denial retain the
live sender/owner member lock and recheck the original signed session after
parent waits and immediately before commit, including waits in transactional
audit. Expired sessions return 401; revoked sessions or permissions return 403.
The canonical locked member supplies the audit actor. Refusal rolls back the
resolution and any auto-applied text together with its audit. A suppressed
resolution UPDATE is an internal failure, not a successful replay.

The signed email confirmation route `POST /a/cr` reports “Already handled” only
for a genuinely resolved request. Missing requests return 404, state/evidence
conflicts 409, and unexpected failures 500 with retry guidance. Legacy email
comment-reply routes remain non-mutating 410 tombstones; use the normal portal
link to converse. The paused signer portal retains document and chat access
while withholding sign/accept/decline and field writes.

Send, Void, Revise and manual Remind recheck the original signed session against
the live sender/owner after parent/document and member lock waits, then again
before commit. Expired credentials return 401; revoked membership, session or
permissions return 403. MCP workflow calls bind the original admitted API or
document credential to current scopes, document boundaries and expiry, and report
refusals as tool errors. Automation materialization checks its original API key
in the same way. See the [lifecycle contract](API.md#negotiation-and-legal-lifecycle)
for the read-only send preflight, authorized block/PDF variable freeze and HTTP
409 when preparation changed.

Sealing recovery uses the committed send intent; automatic reminders use the
locked due schedule. These worker operations do not require the original user
credential to remain live. Manual Remind rotates pending recipients' links and
moves an existing schedule's `next_fire_at` three days ahead without replenishing
`fires_remaining`. Outbox commit still does not prove inbox delivery.

## Document previews

`GET /api/v1/documents/{id}/preview` serves the saved block document as inert
HTML. `GET /api/v1/documents/{id}/pdf` serves the verified source PDF. Both
require a session and organization-scoped document access; responses remain
`no-store`. Only successful preview responses permit same-origin framing, using
`SAMEORIGIN` and `frame-ancestors 'self'`. Other pages and refused previews retain
frame denial. HTML previews prohibit scripts, network writes and forms and use
a sandbox; the editor also applies a restrictive iframe sandbox. See the
[CSP framing and sandbox specification](https://w3c.github.io/webappsec-csp/#directive-frame-ancestors).

`GET /api/v1/documents/{id}/resolve-preview` and MCP
`preview_resolved_variables` return the variable map, per-binding report and
`frozen` flag. These and HTML preview do not persist `last_value`, `last_error`,
`last_resolved_at` or binding timestamps. Draft previews may use the bounded
in-memory cache and configured fallback; a preview is not a send-time freshness
receipt. Non-draft resolution uses only frozen document variables, with no live
CRM fetch and no agent override of those frozen values.

After external source/branding waits, a short READ COMMITTED check verifies the
same document status/timestamp, complete binding definitions and original read
credential under tenant/member locks. Viewers retain read access. Deleted/foreign
documents return404; changed document/binding snapshots409; expired credentials401;
revoked access403. MCP reports corresponding tool errors and does not consume a
second document-token use. External fetches do not hold document row locks.
Refresh and review after409 instead of displaying a mixed snapshot.

Send bypasses preview cache values and requires a successful current response
for every CRM deal/contact binding. Missing source, fetch failure or invalidation
during fetch fails closed; a static value or fallback cannot substitute for CRM
data at this boundary. REST Send returns503 when current CRM information cannot
be verified. Binding observations are staged in memory and written only inside
the authorized freeze transaction, with both document and binding revision
predicates. A changed draft/binding returns409 and leaves no partial observations,
frozen variables, audit or invitation. Review actual CRM identifiers, tenant
mapping and required data before enabling a workflow.

Preview displays saved content. A draft block editor remains mounted while its
preview is visible, preserving unsaved edits and the dirty navigation guard.
Switch back to editing to review those edits. A same-document search/hash change
does not reset the editor or conversation draft. Leaving for another document
requires confirmation before discarding an unsent conversation message.
Recipient add/edit and lawful-basis drafts also require explicit discard when
leaving or replacing them. Canceling navigation preserves the form; same-document
URL changes and Preview/Edit preserve it. A submitted save may still complete
after an explicitly confirmed departure, but its late receipt cannot repaint
the next document or invoke that document's callbacks. Failed recipient refresh
keeps the last known rows and exposes a retry.

## Verification scope

Local PostgreSQL, actual HTTPS/WebSocket and rendered Chromium evidence covers
two-user convergence/save/reload, role demotion, owner recovery after external
replacement, archive download/denial, local draft preservation and explicit
reload. Deleted-draft archive review, exact download bytes, privacy deferral and
viewer/tenant denial also have rendered Go HTTPS/PostgreSQL evidence. These
fixtures use synthetic sessions. The sender recipient fixture also holds actual
reads and save receipts across document navigation and verifies current-document
create/edit calls, canceled discard, preview and URL draft retention with no
browser exceptions. Its receipt is
`/private/tmp/hash-browser-sender-panel-receipt.json`; it performs no send or SMTP
operation. That earlier frontend checkpoint passed 126 tests and check/build;
later source-unit results are recorded in [completion status](COMPLETION-STATUS.md).
Real OIDC, SMTP inbox receipt, CRM/Reactor integration, ClamAV scanning, storage
retention/restore, deployment, workload capacity and broader signing acceptance
remain separate gates. These results are not compliance certification.
