# Agreed notice: exact recipient files

This adapter implements recipient access for an owner's reviewed agreed-notice
amendment. It does not decide whether the agreement legally permits a notice,
whether its conditions were met, or whether a recipient accepted or received it.
The separate native amendment record preserves the attributed review, selected
process, completed original pins and immutable later file set.

An issue commits the notice, real email queue rows, delivery references, access
capabilities and audit event in one native transaction. Before that transaction,
the actual configured provider independently verifies each exact version's
bytes/hash, extends COMPLIANCE retention when necessary, then verifies policy and
bytes again. SQL retires before provider work and the second native transaction
freshly rechecks actor, subjects, head, policy and frozen bytes. Failed preparation
does not enqueue mail. It may have safely extended an existing object's retention.
Exact issue replay reuses the committed notice/outbox; it never issues a new token.

The legal notice audience is exactly the owner's reviewed recipient list. A
separate operational alert to the original negotiation owner remains a dispatcher
integration requirement; this adapter does not silently add that owner to the
legal audience.

## Recipient API

Email links use `/notice/{notice_id}#access=hn1.<43 base64url characters>`.
The random 256-bit capability expires seven days after issuance. Only its
purpose-separated SHA-256 is stored in the access table. Raw links exist only in
the private queued message and recipient browser; they are excluded from audit,
public DTOs, logs and telemetry. Frontend fragment removal and disabled notice-page
telemetry are supplied by the companion public-view implementation.

| Method and path | Input | Result |
| --- | --- | --- |
| POST `/api/v1/notices/{id}/access` | Exact same-origin `Origin`, JSON content type, canonical `{"token":"hn1.…"}`; at most128 bytes | Purpose-specific read cookie; metadata with absolute link expiry |
| GET `/api/v1/notices/{id}` | Notice read cookie | Closed `hash-amendment-notice-access-v1` public metadata |
| GET `/api/v1/notices/{id}/files/{position}` | Notice read cookie, one exact `If-Match: "<file commitment>.<PDF hash>"`, no Range | Verified complete pinned PDF bytes |

The cookie is Secure, HttpOnly, SameSite=Strict, has no Domain, uses a distinct
`__Secure-hash_notice_{id}` name and `/api/v1/notices/{id}` path, and lasts at most
ten minutes and no longer than the original link. Reopen the original email link
to obtain another cookie while that link remains valid. Staff, signer, completed
artifact and other-purpose cookies/tokens do not grant notice access. Every read
freshly checks organization/notice/access binding, expiry, revocation and all
native document subjects. A final SQL SHARE guard serializes bounded actual
response writes with revocation. Revocation cannot acknowledge while an already
admitted writer still holds that guard. No new read starts after revocation.

Metadata contains subject/text, original and later document IDs, issue/expiry,
file commitment, and each zero-based contiguous file's title, hash, bytes, pages
and opaque version digest. It contains no storage key, provider VersionID, email
address, acceptance, identity, signature or legal-effect field. Up to17 PDFs are
supported, at most50MiB and500 pages across the whole set (and within each file).

PDF responses bind `ETag`, `Content-Length`, `X-Hash-Notice-Id`,
`X-Hash-Notice-File-Commitment-SHA256`, `X-Hash-PDF-SHA256`, `X-Hash-PDF-Bytes`,
`X-Hash-PDF-Pages`, `X-Hash-Notice-File-Position` and
`X-Hash-Notice-File-Version-SHA256` before bytes. Files have an attachment filename;
all responses use no-store and no-referrer. An absent/damaged pinned version fails;
there is no latest-object fallback. PDF grants remain funded through actual
provider retirement and bounded response use. The fixed physical handle registry
retains unresolved provider handles rather than treating cancellation as capacity.

Wrong/expired/revoked/foreign authority returns a uniform404. Wrong file commitment
or Range returns412. Capacity, malformed retained evidence or unavailable provider
returns503 with a closed message. Per-IP and per-purpose-credential budgets apply.
Read/write deadlines bound actual network IO as well as request contexts. Metadata
and exchange default to15 seconds, PDF reads30 seconds. Authentication and state
errors do not expose private token, object, body or provider diagnostics.

The companion authenticated owner endpoint revokes one recipient access ID:
POST `/api/v1/documents/{original}/amendments/{amendment}/notice/access/{access}/revoke`.
It freshly admits both native subjects and current owner credentials, appends the
native audit only on first revoke, and returns the original timestamp on replay.
Recipient metadata/reads/downloads create no response, signature, report, open or
delivery receipt. Queue states distinguish queued/retrying/provider accepted/failed;
SMTP acceptance is not verified recipient delivery.

## Retention, reference inventory and release compatibility

Every issued notice retains its frozen PDFs until the canonical S3 whole-second
UTC deadline derived from NEW issued_at plus seven calendar years, not from the
original agreement's older sent_at. Capability expiry and revocation never shorten
that deadline or delete reference/evidence records. Native migration115 owns the
immutable relation/notice/access/delivery constraints, owner-only one-way revoke,
subject deletion guards, and RESTRICT linkage to actual email rows. This adapter
must be adopted with that migration, its native issuer and generated queries.

`ops/recovery-object-inventory.sql` now enumerates every immutable amendment file,
including proposed/unissued relations, with exact `(object_key, version_id)` and
SHA. Issued notices contribute their new retain_until. Canonical grouping and the
existing restore script use key+version pairs. Destructive draft purge and source
compensation guards include original/candidate/annex references. DSR targeted
recipient export/erasure takes the existing manual-review path while amendment,
policy, notice, delivery or access records exist; it must not claim completeness
while those records retain personal data.

An explicit supported evidence-erasure/export procedure after legal retention is
not implemented by this adapter. Current immutable rows retain evidence rather
than allowing automatic purge. The first-install bucket transition checker in
`internal/storage/unused_bucket.go` still indexes expected references by object key
and conservatively refuses two referenced versions sharing a key; ordinary access
and the canonical recovery inventory/script support exact pairs. That transition
checker is a separate qualification gap. A synthetic script fixture is not an
actual object-store restore or Object Lock acceptance receipt.

Once any amendment relation/policy/notice row exists, old Hash images/workers that
lack these new reference guards must NOT be selected automatically for rollback.
An old worker can attempt object deletion before a DB deletion trigger refuses,
especially for proposed files not yet under COMPLIANCE retention. Deploy the new
server AND workers coherently; retain only source-compatible supported rollback
images, with a concrete lifecycle guard and exact test gates before dispatch.
This source packet does not change Stage's lifecycle contract. It requires the
release owner to add and qualify that guard before enabling new writers. This is
development migration qualification, not an active incident claim.

## Qualification

The source packet authors unit and actual native/TLS tests; they were NOT RUN by
the author. The native tests use genuine import/render/complete/issue operations,
actual PostgreSQL constraints, real TLS cookie/deadline writes and an authenticated
version-aware protocol peer. They verify exact reads and queue-message SQL digest
parity, original immutability, no response/report synthesis, foreign authority,
wrong preconditions/ranges, provider hash/missing-object refusal, owner revoke and
absolute link expiry. Expiry's isolated schema-owner historical-row fixture only
constructs a negative authorization state; it does not prove historical issuance.
The provider peer is not a production Object Lock/SMTP delivery/restore receipt.

The release owner must compose the companion schema/native/UI/policy partitions,
generate SQL, format/compile, run selected tests and broader required gates, then
perform actual provider/SMTP/browser/recovery acceptance on the exact deployment.
The public view, original-owner operational alert, source-compatible lifecycle,
real delivery and restore gates must be tracked independently from source readiness.
