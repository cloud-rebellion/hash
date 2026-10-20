# Draft document attachments API

These staff endpoints select and observe draft attachments. The ordinary Send
endpoint dispatches the exact reviewed saved selection through the native
package capture, retention and invitation workflow. Package Send requires the
forward lifecycle migration110; older legacy callers cannot omit selected annexes.


## Send the reviewed main document and attachments

POST /api/v1/documents/{id}/send uses the existing signed sender session,
same-origin mutation guard and current owner/assigned-sender authorization.
For a nonempty attachment selection its JSON body is:

```json
{"lawful_basis":"contract","package_send":{"expected_updated_at":"2026-10-19T12:03:04.123456Z","package_id":"4e972fb2-ae22-4c84-a52d-93d66507b080","generation":"7"}}
```

The timestamp, package ID and decimal-string generation must come from the
reviewed, fresh attachment inventory for this root. They are observations,
not credentials. Omit package_send for ordinary documents and empty draft
headers. Omission with saved annexes or stale selections refuses before capture,
retention or invitations. Legacy envelopes keep their separate existing path.
Unsupported delegated/pre-sign package workflows remain refused.

Hash measures every exact saved PDF outside the retired preparation SQL session,
then atomically captures that selection and commits its sealing intent under the
root lock. Initial success is HTTP202 with status=sealing, links=[], and
package_send={attempt_id,outcome:"active",reconciliation_required:true}. The
existing recovery worker retains every member and atomically queues invitations;
202 alone does not mean an invitation was sent or a contract was signed.

A repeated POST with the identical reviewed observation returns the unique
persisted attempt/status without another capture, token rotation or invitation.
It does not resume arbitrary jobs. A failed or uncertain initial commit can
return HTTP503 with package_send={attempt_id,outcome:"unknown",
reconciliation_required:true}; that identity is only an inspection selector.
Do not infer success or automatically replay that response. Inspect the exact
attempt with the GET below and refresh the saved document. An aborted attempt
requires a fresh document/selection review. No response reconstructs signing
links from historical outbox data.

The sender UI retains an uncertain outcome, blocks repeat clicks and provides
read-only status inspection; a sealing document can also be reloaded and checked.
Recipient package consent remains separate from sender lawful-basis confirmation
and recipient Article13 notice acknowledgement. See the recipient package and
completion portal sections in [API guide](API.md).

## MCP package Send and inspection

`send_document` accepts exactly `document_id`, `lawful_basis` and optional
`package_send`, with the same three selection fields as REST above. Runtime
parsing rejects unknown/duplicate/case-alias fields, explicit null and numeric
generations. The common scalar parser preserves exact int64 decimal generations.
Use `get_document_attachments` to obtain the reviewed root timestamp, package
ID and generation; read permission does not grant the separate `write:workflow`
scope required to Send. Existing current-user/tenant/document checks, MCP
entitlement and same native Send policy still apply. Delegated/pre-sign package
execution is not enabled.

MCP uses its normal JSON-RPC HTTP200 envelope, not REST HTTP202. Its text JSON
result contains `document_id`, `status`, `links` and, for packages, `package_send`.
A committed queued package has `status:"sealing"`, `links:[]`,
`outcome:"active"` and `reconciliation_required:true`. A unique recorded completed
Send returns its current supported status and `outcome:"completed"`; it never
reconstructs recipient links. This means Send completed, not necessarily that
all recipients have signed.

An uncertain commit returns `isError:true`, fixed public error copy,
`status:"unknown"`, empty links, and the exact attempt selector with
`outcome:"unknown"`/`reconciliation_required:true`. Internal error details and
credentials are excluded. Do not turn this into success or automatically repeat
it. The real response owner remains retained through JSON serialization.

`get_document_send_attempt` accepts exactly `{document_id,attempt_id}`. It requires
`read` scope and the current sender/owner role, confines document tokens to their
actual document, and runs live credential authorization before and after the
same native read-only history owner as REST. It returns exactly `attempt_id`,
`outcome` and `retry_authorized:false`; supported outcomes are active, completed,
aborted and not_recorded. It sends no invitations and returns no replacement
links or source/storage locators. Use a document read to refresh current status.

## Inspect one persisted Send attempt

GET /api/v1/documents/{id}/send-attempts/{attempt_id} is a staff session history
read with a separate 30/minute organization/user budget and a 15-second overall
deadline. The current owner or assigned sender must authorize with a live signed
session inside the native transaction, before and after the exact history read.
This can use a fresh login after the original request has ended. Historical
initiating identity is preserved; it is not used as authentication.

The no-store response has exactly attempt_id, outcome and retry_authorized=false.
Outcomes are active, completed, aborted and not_recorded. not_recorded means no
such durable job was found in the authorized root; it does not prove that an
unacknowledged original Send rolled back or that its backend retired. No outcome
grants Send replay or automatically creates another attempt. The endpoint reads
only bounded immutable scalar capture/subject history, checks privacy for every
original member, and makes no provider calls. Policy/privacy/inconsistent history
or unjoined SQL refuse delivery. The MCP equivalent is described above. Neither
inspection transport grants public signer access or automatic worker resumption.

## Recipient frozen package descriptors

`GET /sign/{token}/package` is a separate read using the current recipient's
magic link. It returns `{"package":null}` for a genuine ordinary ceremony, or
an object with schema `hash-recipient-package-v1`, `package_id`, decimal string
`revision`, both `manifest_sha256` and `legal_commitment_sha256`, `main` and ordered
`annexes`. Members expose only `title`, `category`, `pdf_sha256`, `bytes` and
`pages`; categories remain open-ended. Storage keys, version IDs, organization
IDs, intake reports and internal source commitments are omitted.

The read derives identity from the original registered token reader. Under fresh
native locks it resolves the exact completed M103/M106 Send, original invite
membership and current sent epoch, then validates the immutable capture header
and both commitments before funding its payload decode. It checks privacy for
every captured member. Response ownership remains live through the writer's last
use; cancellation does not refund a body still being written. Current credential
and root source/notice policy are rechecked before delivery. Responses are
no-store. Invalid, expired, revoked, privacy-blocked or inconsistent reads refuse
instead of supplying a different or current draft package. A terminal attempt
from an older epoch does not shadow a genuinely later ordinary Send.

Descriptors grant no consent, signature, Send replay or access to arbitrary
source documents. Exact member PDF delivery, explicit incorporation consent,
package response receipts and mandatory participant report delivery have distinct
native owners. The forward lifecycle migration replaces M99's temporary guard
only for that complete package workflow. Later amendments retain the agreement-selected
signature, acknowledgement or agreed-notice process and the immutable original
signed package.

## Background recovery boundary

With migration104 installed, the existing serial Send worker also discovers
pending package attempts in pages of at most50, ordered by created_at and the
complete attempt UUID. A cursor records position only. Each discovered slot is
inspected through a private process-owned batch that reloads the exact recorded
attempt and original subjects under native root-first locks. It does not reuse
the initiating user's old login or accept caller-supplied IDs as worker authority.
Privacy and inconsistent-state refusals consume their queue position, so a bad
first page does not hide later pending jobs. An empty page wraps the next pass.

Migration105 adds durable member retention progress. The private worker reads
the exact canonical capture and immutable member pins, binds the original
constructor's provider namespace, and commits the start checkpoint before any
provider mutation. Actual native SQL retires before each storage call. The
storage owner verifies exact version, size and SHA before retention and afterward,
and reads back COMPLIANCE through at least the original persisted deadline.
Development-only byte verification cannot mint this receipt. Retries preserve
that deadline, accept a longer provider deadline and use already confirmed
same-namespace member receipts without repeating storage work.

Database guards refuse aggregate or new terminal completion unless every
captured member has a matching verified receipt. Existing completed history is
preserved without fabricated backfill; its sent status alone does not establish
this new receipt proof. Started or uncertain member history blocks rollback.
Privacy is rechecked at every durable phase. PostgreSQL and Object Lock are
separate systems: a review arriving after retention starts can pause confirmation
and completion, but cannot undo a provider write or reopen an ordinary draft.

Migration106 adds private worker Send completion for a genuinely prepared
exact package attempt. Fresh measured source, frozen branding, disclosure, parties
and field checks precede retention and repeat in the final transaction. Actual
recipient counts fund output/audit controls before provider activity; there is
no new acknowledgement-party quota. The transaction writes tokens, invitations
to the durable email queue, reminders, chained package-bound audit events, exact
completion receipts and terminal attempt/intent state together. It has no direct
SMTP fallback. Unknown COMMIT does not publish hooks or reconstruct links.

Native output and audit collections reserve their measured aggregate costs,
including each returned email row's fixed database overhead, before provider
activity. Each event and output retains its own exact scope and result checks.
Existing byte, grant-count and tenant limits still apply; an admission refusal
does not authorize starting retention. Closed recovery batches remain pending
cleanup until their actual callbacks, SQL and provider resources have retired.

Immutable invite receipts retain exact outbox/event identities, token hashes
and expiry, and message commitments. The immutable summary binds the original
attempt, epoch, deadline and complete effect set. Later token rotation or mail
cleanup does not change this historical association. New terminal completion
requires those receipts; pre106 history receives no fabricated backfill. Any
receipt blocks rollback. SMTP delivery remains at-least-once, separate from the
single committed initial invitation set.

Before retention starts, an expired or too-short original deadline can abort
the exact attempt to draft without invitations. After retention may have started,
expiry finishes the original epoch and atomically lands in expired, with no
invitations or usable links; it never reopens an ordinary draft. This is Send
publication, not final signed-PDF publication or the full attachment ceremony.

Nonempty packages stay blocked. Native, plan and provider loans remain owned through
actual cleanup and observation delivery. A cancelled provider call may return
before local I/O joins; its exact receipt remains registered in the native batch
until storage confirms actual retirement. Cancellation alone cannot retire the
batch or its plan. The legacy Send pass precedes it in the
same loop, so the five-second ticker is not a scheduling-latency guarantee.
Whole-worker shutdown, uncertain-commit/restart recovery, configured-provider
conformance and the full recipient/annex consent, signature binding and mandatory
participant report remain separate qualification work. These private worker
primitives do not activate a public package Send or amendment endpoint.

## Authentication and observation

Session REST requires the original signed cookie and a current sender/owner.
Senders must own the agreement and the candidate; owners may act within their
organization. Mutations enforce the normal same-origin policy. Both paths use
no-store responses and per-organization/user budgets: 10 selections/minute and
60 observations/minute on REST. MCP retains its central credential/rate limits.
Original credential, role, scope, draft, evidence and privacy policy are checked
inside native transactions, including after waits and before commit.

- GET /api/v1/documents/{id}/attachments
- MCP get_document_attachments with exactly {"document_id":"<root UUID>"}; read scope.

The response contains schema hash-document-attachments-v1, document_id,
updated_at, package_id, generation, requires_reselection and ordered members.
An absent package has package_id "", generation "0" and members []. Existing
generations are positive decimal strings, preserving the full bigint range.
Each member has document_id, ordinal, title, category, pdf_version_id,
pdf_sha256, pdf_bytes and pdf_pages. These are frozen selected metadata;
subsequent edits/deletion of the original source do not replace them. No storage
key or internal intake report body is returned. Observation makes no provider
call and does not establish current PDF eligibility, malware clearance or Send
readiness. requires_reselection marks legacy selections missing intake proof.

The observation endpoint is for editable standalone PDF drafts, including
reviewed HTML materializations. Retained signing evidence or pending privacy
review prevents this editing view. It is not a public recipient/history API.
A document-agent read token may observe only its authorized root agreement.

## Select one attachment

- POST /api/v1/documents/{id}/attachments with application/json.
- MCP add_document_attachment with write:authoring scope; organization API keys
  only. Document-agent tokens are refused even with that write scope.

REST accepts exactly these eight required fields:

    {
      "member_document_id": "<standalone candidate UUID>",
      "expected_updated_at": "<observed root RFC3339 timestamp>",
      "expected_member_updated_at": "<observed candidate RFC3339 timestamp>",
      "expected_package_id": "",
      "expected_generation": "0",
      "ordinal": 1,
      "title": "Data processing agreement",
      "category": "DPA"
    }

MCP adds the required document_id field for the root. REST takes it only from
the path. Read current root/candidate clocks and package observation first;
copy its existing package_id/generation when a header already exists. Do not
predict generation increments. ordinal is an unused integer position from 1
through 16; title is 1-512 UTF-8 bytes, category is 0-128 bytes and remains an
open-ended business label. Empty category must still be supplied. Clocks are
compared as exact instants, with database precision retained.

The decoder caps actual request/argument bytes at 4096 and refuses duplicate,
unknown or case-aliased fields, supplied storage/source pins, numeric generation,
non-integer ordinal, invalid Unicode, nulls and trailing values. The service
owns source lookup, original authorization, reviewed HTML/source validation,
exact-version PDF measurement and selected proof. It saves the immutable
selection and dedicated chained audit together, moving the root clock and
package generation atomically.

## Outcomes and recovery

A known acknowledged commit returns HTTP 201 and state committed, with
attachment identity, exact stored generation/root clock and event_id. A cleanup
or publication problem after commit still returns the committed identity and
reconciliation_required true; do not create a duplicate selection.

If COMMIT was dispatched without acknowledgement, HTTP 202 returns state unknown
and reconciliation_required true. MCP expresses both committed and unknown as
successful tool results so clients retain the outcome. Do not retry blindly.
Reload the package observation and compare the intended member/position and
current clocks; an operator must reconcile the outcome if it is still unclear.
A lost transport response likewise does not prove the operation rolled back.
There is no client-supplied idempotency key on this endpoint.

Ordinary precommit failures have safe fixed messages: 400 invalid selection,
401 original login expired, 403 permission/scope refused, 404 missing document,
409 changed/noneditable/ineligible/occupied/privacy state, 413 oversized input,
422 exact PDF package verification failure, 503 unavailable capacity/service.
MCP returns these as tool errors through its standard RPC envelope. Stale clocks
or generations require reload and review; failures never authorize weaker pins.

## Product boundary

The planned signing package incorporates the main agreement and named business
attachments in one deliberate acceptance of exact presented bytes. The separate
automatic negotiation/signature evidence report remains mandatory. Later changes
will follow the agreement's configured process: a new signature, acknowledgement
or agreed notice. A changed file does not universally force re-signing. Original
signed bytes/evidence must remain preserved and later versions linked. The
selected process must be permitted by that agreement, including the notice
channel and effective-date conditions; a notice must never appear as a signature
or an explicit acknowledgement. These
amendment/report/signing workflows are planned and are not enabled by these draft
selection APIs; technical evidence alone is not a legal sufficiency decision.


## Save selected order, labels and removals

PATCH /api/v1/documents/{id}/attachments is a staff session mutation. MCP
save_document_attachments requires an organization key with write:authoring;
document-agent credentials are refused even when they carry that scope.
REST has a separate 10 saves/minute per-organization/user route budget.

Supply exactly expected_updated_at, expected_package_id, expected_generation
and members. MCP additionally requires document_id. The package must already
exist, including an existing empty header. Example:

    {
      "expected_updated_at": "<observed root RFC3339 timestamp>",
      "expected_package_id": "<observed package UUID>",
      "expected_generation": "<positive canonical decimal string>",
      "members": [
        {"document_id":"<already selected UUID>","title":"DPA","category":"Privacy"},
        {"document_id":"<already selected UUID>","title":"Service terms","category":""}
      ]
    }

members is the complete desired ordered subset of the current selections;
array position defines contiguous ordinals from1. Omitted IDs are detached.
An empty array explicitly detaches every member while retaining the package
header. Each retained member has exactly document_id/title/category. Duplicate
IDs/keys, unknown pins, nulls, extra fields and more than16 members are refused.
The actual request cap is16384 bytes, supporting16 maximum-size labels. UUID,
Unicode, title/category and generation rules match selection above. Stale
root clocks or package generations require reload and review.

A layout save cannot add a document, replace its PDF/source/report pins or
refresh a selection from its live source. Use explicit attachment selection for
new IDs. Atomic same-source replacement/reselection remains future work.
Relabelling/reordering/removing existing selections works after old-source
changes/deletion and for legacy missing-proof rows. Missing proof remains
missing and marked requires_reselection; it does not become Send-eligible.
Privacy/evidence refusal still applies to every original selected subject,
including a member being removed. No provider call or PDF remeasurement occurs.

HTTP200 state committed returns layout with package_id, string generation,
updated_at, changed_rows and event_id. One dedicated document.attachments_updated
chained event records complete before/after identity/order/labels. Every changed
or removed row increments generation, so clients must use the returned/read-back
generation. Unchanged rows are skipped. An exact no-op returns state unchanged,
changed_rows0 and nil UUID event_id without changing clocks/generation/audit.

Committed results survive cleanup/publication problems as above. A dispatched
unacknowledged COMMIT returns HTTP202 state unknown with reconciliation_required;
reload the authoritative inventory before any retry. Safe precommit error
statuses match the selection contract. The original actor/credential is checked
again after audit and before COMMIT. These metadata APIs do not enable preview,
package Send/signing or amendment notices; those workflows remain pending.


## Exact selected-version PDF preview

GET /api/v1/documents/{id}/attachments/{member_id}/pdf requires the current
signed staff session and the root's sender or an organisation owner. It previews
an existing selected attachment; it neither selects nor reviews/approves it.
The three required query keys are expected_updated_at (exact inventory UTC
RFC3339Nano timestamp), expected_package_id (canonical nonzero UUID) and
expected_generation (canonical positive decimal int64 string). Unknown or
repeated keys, over1024byte query strings and invalid identities are refused.
Rate limit:30/minute per organisation/user for this route.

The native reader derives the private storage key and immutable version/SHA,
bytes/pages under root/package/generation/member and subject privacy fences.
Initial physical SQL retirement precedes exact-version HEAD/GET. A fresh native
stage repeats original session/role/owner/privacy/selection checks after fetch;
stale or revoked observations return an error without PDF bytes. There is no
latest-version or mutable-source fallback, including after source deletion.

Success is application/pdf, no-store, inline selected-attachment.pdf and the
existing private preview frame policy. Identity headers: X-Hash-Document-Id,
X-Hash-Document-Updated-At, X-Hash-Package-Id, X-Hash-Package-Generation,
X-Hash-Member-Document-Id, X-Hash-PDF-Version (UTF8 version encoded as unpadded
base64url), X-Hash-PDF-SHA256 (lowercase hex), X-Hash-PDF-Bytes and
X-Hash-PDF-Pages. Content-Length matches PDF bytes. Storage keys/internal intake
reports are never returned. Clients must validate the complete observation and
actual length/SHA before parsing, and the parsed page count before display.

The registered native owner retains byte credit through the actual synchronous
HTTP response write. Copy-close/cancellation is not completion of an active
consumer. This read proves selected byte identity, not malware clearance,
source eligibility, signer package consent or legal sufficiency. Legacy missing
intake proofs still require explicit reselection before package signing.
