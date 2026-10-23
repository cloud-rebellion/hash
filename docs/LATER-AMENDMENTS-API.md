# Later amendments and agreed-notice API

This describes the current later-amendment implementation. It does not establish deployed
availability, configured mail/provider acceptance or legal enforceability. The
original agreement determines which process is permitted; Hash records the
selected basis and technical events without deciding legal effectiveness.

An amendment is a new, separately prepared document linked to an immutable
completed original. It does not edit or replace the original's signed PDF,
package, capture or mandatory participant report. The latest proposed relation
is the history **head**, not an assertion that the proposal is effective.

| Mode | Subsequent process |
| --- | --- |
| `signature` | Ordinary fresh Send and signature ceremony on the separate amendment; its own mandatory evidence report. |
| `acknowledgement` | Ordinary fresh Send and explicit acknowledgement on the separate amendment; its own mandatory evidence report. |
| `agreed_notice` | Separate reviewed email-notice issue operation and read-only exact-file access. Ordinary Send/sign/ack is refused for this linked candidate. |

There is no default mode and no universal requirement to re-sign every later
change. A selected process must be permitted by the saved agreement policy or
an explicitly attributed owner review of an existing clause. Queueing, SMTP
acceptance, reading and downloading are not signatures, acknowledgements,
verified delivery receipts or legal-effectiveness decisions.

## Staff routes and permission boundary

All five routes below are under the real signed-session API. Organization keys,
document-agent keys and recipient/notice capabilities cannot replace the staff
cookie. The production ingress gate and same-origin mutation guard still apply.
Native operations recheck the original credential, current tenant/role, all
subject privacy fences and the saved file/head observations at use/commit.

| Method | Path | Permission | Success response |
| --- | --- | --- | --- |
| GET | `/api/v1/documents/{id}/amendments` | Owner, or sender who owns the original document | `200` inventory |
| POST | `/api/v1/documents/{id}/amendments` | Current organization owner | `201` committed/exact replay, or `202` unknown outcome |
| GET | `/api/v1/documents/{id}/amendment` | Owner, or sender who owns this candidate document | `200` saved candidate relation; `404` if no relation |
| POST | `/api/v1/documents/{id}/amendments/{amendmentId}/notice` | Current organization owner | `201` committed/exact replay, or `202` unknown outcome |
| POST | `/api/v1/documents/{id}/amendments/{amendmentId}/notice/access/{accessId}/revoke` | Current organization owner | `200` committed/exact repeat, or `202` unknown outcome |

For inventory/create/notice/revoke, `{id}` is the completed original agreement.
For the singular `/amendment` lookup it is the separate candidate document.
`amendmentId` is a relation ID, not the candidate document ID. `accessId` is the
nonsecret access ID exposed on a saved notice delivery.

Each staff route has its own per-organization/user minute budget: 60 requests
for a read route and 10 for a mutation route. Responses use `no-store`. These
are session REST contracts; this implementation adds no amendment MCP tool,
organization-key route or independent machine-notice endpoint.

## Read the original and proposed history

`GET /api/v1/documents/{originalID}/amendments` returns `InventoryV1`:

| Field | Meaning |
| --- | --- |
| `schema` | `hash-later-amendments-v1` |
| `original_document_id` | The completed original ID |
| `head_id`, `head_revision` | Nullable latest proposed relation ID and canonical decimal revision string; initially `null`, `"0"` |
| `original` | `document_id`, `name`, `completed_at`, `final_pdf_sha256`, canonical `report_sha256`, and optional `package_commitment_sha256` |
| `can_create` | Current owner eligibility; a read response is not authority for a later write |
| `frozen_policies` | Server-resolved basis records for the presented original; empty `[]` if none |
| `amendments` | Complete saved chain in ascending revision order, up to 64 relations; empty `[]` if none |

A saved amendment has `id`, `request_id`, decimal `revision`, nullable
`predecessor_id`, `document_id`, `document_name`, current `document_status`,
`mode`, `basis`, `file_commitment_sha256`, `created_at`, `created_by`, and an
optional `notice`. Its immutable relation/files are distinct from the current
ordinary document status. `basis` carries the resolved basis fields plus
`sha256`, `reviewed_by`, `reviewed_at` and explicit `attribution`.

The singular candidate lookup returns `schema`, `original_document_id` and
`amendment` with that same saved record. A normal unlinked candidate returns
`404`; a transport/capacity failure must not be treated as proof of no relation.

## Select an agreement basis

For an existing frozen policy, the create request supplies only:

```json
{"kind":"frozen_agreement_policy","frozen_policy_id":"00000000-0000-4000-8000-000000000101"}
```

Use an actual ID returned by the original's inventory. Do not include client
copies of clause text, allowed modes/channels or effective conditions in this
request basis. Native state resolves the record for that original and checks
its full basis and reviewed source/PDF/version commitments.

For an older agreement with no applicable frozen policy, `basis.kind` may be
`reviewed_legacy_clause`. Supply `clause_reference`, the exact `reviewed_clause`,
`allowed_modes`, `allowed_channels` and `effective_condition`; omit
`frozen_policy_id`. This is the current owner's attributed review of a clause,
not inferred signatory consent or a legal determination.

Legacy clause/reference/condition are nonempty UTF-8 strings with no NUL or
outer whitespace, bounded to 8,192 / 512 / 2,048 bytes respectively.
`allowed_modes` contains one to three distinct supported modes and must include
the selected mode. The only supported notice channel is `email`; an agreed
notice request requires `allowed_channels: ["email"]`. Preserve the reviewed
array order and text on replay; the server does not silently rewrite them.

### Visible policy for a new agreement

The existing owner-approved HTML master's `contract_profile.amendment_policy`
can declare `term`, `clause_reference`, `allowed_modes`, `allowed_channels` and
`effective_condition`. This is part of the template/source pipeline, not a new
policy-install REST endpoint. `term` names an existing printed ContractTerm.
Its actual materialized value/section must contain both the quoted reference
and effective condition; the server derives `reviewed_clause` from that exact
printed text. It does not generate legal wording or infer a policy from a title.

The term name is 1–64 lowercase ASCII letters/digits/underscore, beginning with
a letter. Reference/condition/clause have the byte limits above and the stricter
HTML contract-text checks. Allowed modes are distinct and canonicalized by the
master validator. Declare `allowed_channels: []` without agreed notice, or
`["email"]` when agreed notice is allowed. Template approval and review of the
actual document PDF remain required.

Only the final native ordinary standalone Send-completion transaction, after
retention completes, freezes the server-created policy against the actual
source commitment, presented PDF SHA/version and current actor. An aborted
reversible Send does not leave a policy that prevents editing and retrying.
Declared-policy `sealing` to `sent` cannot bypass this exact freeze. The
corresponding pre-signing/delegated and envelope path is not supported for this
declaration; it is refused until an equivalent native freeze exists. Documents
without a declaration retain their supported existing paths. A client flag or
an arbitrary policy ID does not create frozen authority.

## Link an independently prepared draft

Prepare, render and review the separate draft and its complete file set before
linking it. It must be an eligible same-tenant standalone PDF document, still
`draft` and unsent, with exact PDF/version/intake pins and no existing signing
evidence. HTML-derived PDFs retain their current source/PDF review requirement.
`requires_signature` must be true for `signature`, false for the other modes;
a schema-3 signature contract cannot be converted into acknowledgement/notice
by toggling a profile. The amendment cannot itself serve as another original.

`POST /api/v1/documents/{originalID}/amendments` requires `application/json`
and a body no larger than 32,768 bytes:

```json
{
  "request_id": "00000000-0000-4000-8000-000000000201",
  "expected_head_id": null,
  "expected_head_revision": "0",
  "amendment_document_id": "00000000-0000-4000-8000-000000000301",
  "expected_document_updated_at": "2026-10-21T12:00:00.123456Z",
  "mode": "signature",
  "basis": {
    "kind": "frozen_agreement_policy",
    "frozen_policy_id": "00000000-0000-4000-8000-000000000101"
  },
  "cover_reviewed": true
}
```

IDs above are illustrative. Use freshly loaded actual head and candidate
observations. Head `"0"` requires `expected_head_id: null`; later heads require
the exact nonnull ID and revision. Revision strings have no signs, padding or
leading zeros. `cover_reviewed` records the owner's explicit review that the
independently rendered amendment identifies the original, proposed file set
and process. It is not a signer's acceptance or a substitute for rendering.

Linking commits a new immutable proposed relation, original evidence pins,
exact source/package/file commitment and attributed audit event. It also queues
a separate operational alert to the original document owner. Linked source,
party identities, layout and attachments cannot subsequently be edited in place.
Use a fresh separately prepared document and reviewed next relation for a change.
For signature/acknowledgement, continue through ordinary fresh Send and its
normal checks; the linked `agreed_notice` candidate must use notice issue below.
Original files/evidence and earlier proposed relations remain preserved.

## Mutation outcomes and uncertain responses

Create and notice issue return `OutcomeV1`: `state`, `request_id`, optional
`reconciliation_required`, and the saved `amendment` or `notice` where known.
This outcome has no top-level `schema` field. Its states are:

| State | Meaning |
| --- | --- |
| `committed` | The durable operation committed; this is not a delivery or acceptance result |
| `unchanged` | Exact previously committed request found; no duplicate relation/audit/mail |
| `unknown` | Commit dispatch may have occurred, but no confirmed outcome; HTTP `202` and `reconciliation_required: true` |

Use one stable nonzero `request_id` and preserve the exact reviewed request,
including order, observations, mode/basis and text. Reusing it with changed
content conflicts. A lost HTTP response does not prove rollback. Reload the
original inventory and locate the saved create/notice `request_id`; compare
all reviewed fields before accepting reconciliation. If still uncertain, retry
the exact original request under the same ID. Do not create a new ID to evade an
unknown result or substitute newly loaded pins into the old reviewed request.
Current permission and credential checks still apply to replays.
`reconciliation_required` may also accompany a known committed operation when
post-commit observation/cleanup requires review; do not turn it into a new Send.

## Issue the agreed notice

There is one immutable notice per agreed-notice relation. The relation must be
the current proposed head, the candidate must remain the exact linked draft
with `requires_signature: false`, and its resolved basis must allow email notice.
Review the exact subject, text, ordered recipient list and linked file commitment
before explicitly issuing:

```json
{
  "request_id": "00000000-0000-4000-8000-000000000401",
  "expected_head_revision": "1",
  "expected_document_updated_at": "2026-10-21T12:00:00.123456Z",
  "subject": "Reviewed amendment notice",
  "text": "Exact owner-reviewed notice text.",
  "recipient_emails": ["recipient@example.test"],
  "reviewed": true
}
```

POST this JSON to the notice route for the actual original and relation IDs.
These sample strings are not agreement terms. Body limit is 32,768 bytes;
subject is 1–256 UTF-8 bytes, text 1–16,384 bytes, without outer whitespace/NUL.
Subject cannot contain CR/LF. Supply 1–32 exact plain email addresses (no display
names), at most 254 bytes each, with no case-insensitive duplicates. Recipient
and mode/channel order is significant to the reviewed/replayed request.

Native preparation verifies and retains every exact version before a fresh
transaction rechecks authority, original/head and complete file commitment.
The notice bytes, recipients, audit, capability identities and real email
outbox references commit together. Notice access supports at most 17 files,
50 MiB in total and 500 pages in total. Issue does not sign, acknowledge or
mark the agreement legally effective.

The saved `notice` contains `id`, `request_id`, exact `subject` and `text`,
`sha256`, `file_commitment_sha256`, `issued_at`, `issued_by`, `deliveries` and
`verified_receipts`. Delivery order matches the reviewed recipient order.
Each delivery exposes nonsecret `access_id`, optional `revoked_at`,
`email_delivery_id`, `recipient_email`, `state`, `attempts` and optional
`provider_accepted_at`. Raw capability tokens and private object locators do
not appear in this staff DTO.

| Delivery state | Observation |
| --- | --- |
| `queued` | Real outbox row is pending |
| `retrying` | Mail delivery is being retried |
| `provider_accepted` | Mail transport accepted it; recipient delivery is unproven |
| `failed` | Mail delivery failed |

`verified_receipts` is a separate array, currently empty: this cut provides no
public provider-receipt ingestion endpoint. SMTP states are never projected as
verified receipts. A future authenticated receipt adapter is not implemented
by this API. Operational owner alerts are separate from this exact legal-notice
audience and do not create an extra notice-recipient or acceptance record.

## Revoke one notice recipient's access

POST `{}` (or an empty body) to the access revoke route, using a saved
`deliveries[].access_id`. This one-way owner operation returns
`schema: "hash-later-amendments-v1"`, `state`, `access_id`, optional `revoked_at`
and optional `reconciliation_required`. First commit is `committed`; an exact
repeat is `unchanged` with the original timestamp and no duplicate audit. An
uncertain commit is `unknown`/HTTP `202`; do not claim access is revoked until
the saved delivery shows `revoked_at` or exact replay confirms it.

Revocation does not recall an already downloaded PDF, withdraw an email,
change the original/notice, shorten evidence retention or assert legal effect.
The final bounded reader and revocation serialize so an admitted response's
owned use finishes before revocation is acknowledged.

## Public notice access and exact downloads

A private notice email links to `/notice/{noticeID}#access=hn1.…`. The fragment
is a bearer capability: keep it out of logs, query strings, evidence, analytics
and third-party resources. It is not a signer token or staff session. The
purpose-specific HTTP routes are mounted separately from the signed-session
`/api/v1` tree, although they use the same URL prefix:

| Method | Path | Credential / result |
| --- | --- | --- |
| POST | `/api/v1/notices/{notice_id}/access` | Canonical JSON fragment-token exchange; `200` schema and absolute capability expiry plus notice-only cookie |
| GET | `/api/v1/notices/{notice_id}` | That notice's purpose cookie; `200` immutable public presentation |
| GET | `/api/v1/notices/{notice_id}/files/{position}` | Same cookie plus exact `If-Match`; `200` exact retained PDF |

The production ingress gate still applies. Exchange requires exactly one real
`Origin` equal to the configured public origin, `application/json`, and no
cross-site fetch signal. Body is at most 128 bytes and must be the exact compact
JSON serialization `{"token":"hn1.<43 unpadded base64url characters>"}` with no
extra fields, whitespace or newline. The token is 47 bytes and canonical;
never put an actual token in documentation or a shell example.

Success returns `schema: "hash-amendment-notice-access-v1"` and `expires_at`
(the absolute capability deadline). The cookie is `HttpOnly`, `Secure`,
`SameSite=Strict`, scoped to `/api/v1/notices/{noticeID}`, and purpose-bound to
this exact notice/access identity. Its lifetime is at most 10 minutes and never
beyond the capability. The capability expires seven days after issue; exchanging
it again cannot extend that deadline. Expiry and revocation do not release the
separately retained notice/file evidence. No endpoint here responds for a
recipient, creates a signature or appends an acknowledgement/receipt.

The presentation uses that schema and returns `notice_id`, `original_document_id`,
`document_id`, `subject`, `text`, `issued_at`, `expires_at`,
`file_commitment_sha256` and ordered `files`. Each file exposes only `position`,
`title`, `pdf_sha256`, `pdf_bytes`, `pdf_pages` and `file_version_sha256`.
`file_version_sha256` commits to private exact-version metadata; it is not an
object VersionId or a storage URL. Positions are canonical zero-based decimal
strings in the file URL, without padding or signs.

Send exactly one `If-Match` header with the quoted value
`"<file_commitment_sha256>.<pdf_sha256>"` from that presentation. `Range` is not
supported. A successful attachment response includes `ETag`, `Content-Length`,
`X-Hash-Notice-Id`, `X-Hash-Notice-File-Commitment-SHA256`,
`X-Hash-PDF-SHA256`, `X-Hash-PDF-Bytes`, `X-Hash-PDF-Pages`,
`X-Hash-Notice-File-Position` and `X-Hash-Notice-File-Version-SHA256`.
Validate the declared size/hash and saved commitment; there is no latest-version
fallback. JSON/PDF responses use `no-store` and `no-referrer`.

All public notice routes share a 240/minute IP gate. Presentation adds a
240/minute purpose-credential gate; file download adds 60/minute by IP and
30/minute by purpose credential. Invalid credentials share an invalid-access
bucket. These are bounded process-local budgets, not a distributed quota claim.

## Existing signer context for signature and acknowledgement amendments

The existing `GET /sign/{token}` JSON may contain `amendment_context` only for
an eligible linked signature/acknowledgement ceremony. Its exact fields are:
`schema: "hash-signer-amendment-context-v1"`, `amendment_id`, decimal `revision`,
`document_id`, `original_document_id`, `original_name`,
`original_final_pdf_sha256`, `original_report_sha256`,
`original_report_pdf_sha256`, `mode` and `file_commitment_sha256`.

`original_report_sha256` is the canonical mandatory participant-report digest;
`original_report_pdf_sha256` is the rendered report PDF digest. They are not
interchangeable. The disclosure is retained and freshly checked with the exact
ceremony/source/version; it grants no original-artifact URL or access. It does
not replace PDF review, privacy disclosure, deliberate consent or the ordinary
signature/acknowledgement operation. Agreed notice does not use this ceremony.

## Refusal and retry behavior

Staff operations use `400` invalid reviewed input, `401` original session
expired, `403` current permission refused, `404` document/relation missing,
`409` changed head/proposal or pending/changing privacy review, `415` wrong
content type for create/notice, and `503` unavailable/uncertain processing
capacity. Rate gates may return `429`. A successful HTTP outcome is still subject
to its `state`/`reconciliation_required` contract above.

Public notice access deliberately returns `404` for invalid, revoked, expired
or foreign notice credentials; it does not disclose which check failed. Missing
or changed exact file preconditions and any `Range` request return `412`.
Unavailable exact storage/version/capacity returns `503`; rate gates may return
`429`. After response bytes begin, a failed/partial write cannot be converted
into a new JSON error or a success receipt. Treat truncated bytes, lost responses
and failed verification as unconfirmed outcomes; do not weaken pins or treat
an error as permission to use another version.

## Source and verification boundary

The staff registration and adapter are in `internal/handler/server.go` and
`later_amendments_v1.go`; closed DTOs/validation are in `internal/amendments`.
Public registration, cookie/exact-file behavior and public DTOs are in
`internal/noticeaccess`. Initial policy declaration/freeze uses
`internal/htmlmaster/amendment_policy_v1.go`, native Send completion and
migration115. Generated route inventory must be regenerated and checked on the
adopted source, including the delegated notice module. Controlled tests, source
presence and this document do not establish configured email delivery, real
browser/PDF acceptance, recovery, capacity or a released application.
