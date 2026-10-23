# Later amendments

This implementation is a development candidate. Source, database/native tests,
browser journeys, configured delivery, rollout and operational acceptance are
separate qualifications. Do not claim a completed feature from these sources.

A later amendment is a separately authored and reviewed document. Its immutable
relation pins the original completed document, its four exact final/report
artifact versions, mandatory report hash, and any original package/capture/Send
receipt. It also freezes the new proposal's exact reviewed PDF and selected
attachment versions. The original document, recipients, signatures, report and
captured package are never rewritten. The relation head is the latest proposal;
it does not decide which terms are legally effective.

Prepare the independent candidate, its response mode, parties and any signature
layout before linking. Linking freezes source, attachment selection, party
identity and layout. A correction requires a new separate proposal. Ordinary
Send rotates fresh credentials and continues the existing signature or explicit
Accept flow. A notice candidate never enters ordinary Send/sign/Accept.

The selected process must be permitted by a policy actually frozen with the
presented agreement, or an explicitly attributed owner review of an existing
agreement clause. An owner's clause attestation is not signatory consent or a
legal determination. A frozen policy request contains only its saved ID; the
server resolves its actual clause/modes/channels/conditions. A client cannot
create permission through invisible metadata. Initial HTML policy production
and source/declaration/PDF freeze are a separate coordinated implementation.

## Staff API

These authenticated session endpoints require current tenant and credential
checks. Creating, issuing and revoking require an owner. Authorized senders may
read their own document's relation. Writes use exact head/timestamp preconditions
and are independently fenced in PostgreSQL.

- `GET /api/v1/documents/{originalID}/amendments`: bounded complete proposal
  chain, original evidence digests, available frozen policies and delivery state.
- `POST /api/v1/documents/{originalID}/amendments`: link a prepared independent
  draft. Request fields: `request_id`, `expected_head_id` (explicit null for the
  initial proposal), `expected_head_revision` (canonical decimal string),
  `amendment_document_id`, `expected_document_updated_at`, `mode`, `basis`, and
  explicit `cover_reviewed`. Modes are `signature`, `acknowledgement`, and
  `agreed_notice`. This operation does not Send the draft.
- `GET /api/v1/documents/{candidateID}/amendment`: resolve the saved relation
  from the candidate's direct staff page. A normal unlinked document returns404.
- `POST /api/v1/documents/{originalID}/amendments/{amendmentID}/notice`: issue the
  separately reviewed email notice. Request fields: `request_id`,
  `expected_head_revision`, `expected_document_updated_at`, `subject`, `text`,
  ordered `recipient_emails`, and `reviewed: true`.
- `POST /api/v1/documents/{originalID}/amendments/{amendmentID}/notice/access/{accessID}/revoke`:
  body `{}` or empty. Owner revocation is one way and intrinsically idempotent.

`basis.kind=reviewed_legacy_clause` requires a clause reference, reviewed clause,
permitted modes/channels and effective-condition text. `basis.kind=
frozen_agreement_policy` accepts only `frozen_policy_id` beside its kind.

Creation/notice responses contain `state=committed|unchanged|unknown`,
`request_id`, and the saved amendment/notice when known. Exact same request replay
preserves its original identity, audience and bytes; changed replay conflicts.
An unknown result is not permission to issue a new request ID: reload inventory
and reconcile the existing request, or safely retry that exact request. Revocation
uses its access ID and returns the actual saved `revoked_at` only when known.

History is capped at64 proposals. All JSON list fields are arrays, including
empty frozen-policy and verified-receipt lists. Clause reference is at most512
UTF8 bytes, reviewed clause8192, condition2048, notice subject256 and text16384.
Notice audience is1–32 exact plain email addresses without duplicates. The file
set has at most17 files,50MiB and500 pages total. Supplied file keys, versions,
digests, sizes, raw notice access tokens and signing credentials are never request
fields for these operations.

## Notice evidence and access

Notice preparation runs after initial SQL has actually retired. The independent
notice access adapter verifies exact versioned file bytes and actual COMPLIANCE
retention, using seven calendar years from this new notice's issue time. A fresh
paired transaction then rechecks original pins, current proposal head/file set,
actor credential and sender identity before atomically saving the notice, audit,
real email deliveries, immutable message references and private recipient access.
A storage retention effect can survive a later refused/unknown SQL operation;
this never authorizes an email or a fabricated acceptance.

Notice deliveries contain exactly the reviewed audience in order. There is no
hidden owner/CC addition. An original-owner operational alert is a distinct
pending integration and must not be counted from the issue actor or audit alone.

The mail worker's `pending`, `retrying`, `sent`, `failed` states are projected as
`queued`, `retrying`, `provider_accepted`, `failed`. SMTP acceptance proves no
recipient delivery, signature, acknowledgement, verified receipt or legal
effectiveness. A verified-receipt list stays empty until an authenticated receipt
adapter really exists. Expired/revoked access does not erase retained evidence.

Each private access URL uses a notice-specific credential, not an old signer or
staff credential. Public exchange/read/download belongs to the separately
implemented notice access service. Only nonsecret access IDs are exposed to the
owner for revocation. Evidence and logs retain hashes, not raw credentials.

## Qualification still required

Compose the core, initial-policy producer, notice-access and frontend partitions
before formatting/code generation and native qualification. Run additive/occupied
migration/replay/Down tests, real PostgreSQL all-three-mode flows, response-loss
and concurrent-head/request tests, credential and source mutations, atomic
outbox/audit failures, actual versioned provider retention/read/restore, public
access/revocation, ordinary mandatory-report verification and browser journeys.

The separate new report includes its own amendment-origin audit event and original
reference digest; the original report's historical cutoff and bytes stay intact.
The `cover_reviewed` owner attestation is not machine proof that arbitrary PDF
text actually identifies the original and process. Public signer-visible origin
context and/or a genuinely verified cover producer remains an explicit acceptance
requirement. Exact-version recovery and every privacy/purge/cleanup reference
caller must include both originals and later file sets. Older worker/rollback
images do not automatically understand the new references; rollback compatibility
must be qualified before any records can be created in a release environment.
