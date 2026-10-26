# Hash standalone automation API

Hash operates independently and accepts integrations from any authorized product.
Its machine API supports reading a prepared document, sending it to its configured
recipients, querying status, and downloading completed files. Another application
can also create and send from an approved template. These operations do not
require browser cookies, MCP, CloudRebellion, a CRM, or Reactor. Customer-specific
record mappings belong in the integrating application or an optional adapter.

MCP serves AI document/settings authoring. A CRM, workflow service or other
product calls the HTTP API and consumes Hash's signed lifecycle webhooks. Hash
owns the document snapshot, customer invitation, signing ceremony and evidence;
the source system need not remain available for signing.

## Prepared documents and status

Use an organization-wide key with explicit `read` for discovery and downloads,
and explicit `write:workflow` for Send. The issuer must currently have the
appropriate Hash role. Document-scoped agent tokens cannot use this machine API.
New keys default to read/authoring; enable workflow permission deliberately for
an integration that sends documents. Existing keys are not rewritten.

| Method | Path under `/api/automation/v1` | Result |
| --- | --- | --- |
| GET | `/documents` | Organization document list; normal pagination/filter rules apply. |
| GET | `/documents/{id}` | Current document metadata, including lifecycle `status`. |
| GET | `/documents/{id}/pdf` | Saved source PDF; this is not the executed final contract. |
| GET | `/documents/{id}/attachments` | Saved attachment inventory and current package observation. |
| POST | `/documents/{id}/send` | Send an already prepared document through the normal signing engine. |
| GET | `/documents/{id}/send-attempts/{attempt_id}` | Inspect a package Send outcome without dispatching another ceremony. |
| GET | `/documents/{id}/final-pdf` | Exact completed PDF; an unfinished document returns 409. |
| GET | `/documents/{id}/audit-cert` | Completed audit certificate; an unfinished document returns409. |
| GET | `/templates` | Organization template list. |
| GET | `/templates/{id}` | Template content and current version/digest pins. |

These routes apply tenant/credential authorization and the existing artifact
version/digest checks. They return no storage credentials or customer signing
links. Delegated/pre-sign source documents keep their separate purpose-specific
access rules. The source PDF endpoint can report unavailability when a document
has no saved PDF source; metadata alone does not prove a downloadable PDF exists.

Send requires `Content-Type: application/json` and one strict UTF-8 JSON object,
limited to 8 KiB. Unknown/duplicate fields, trailing values and explicit null
inputs are rejected. For an ordinary document:

```http
POST /api/automation/v1/documents/09bc3de6-931a-4b7c-a3ec-07f6fd8b103b/send
Authorization: Bearer mth_<prefix>_<secret>
Content-Type: application/json

{"lawful_basis":"contract"}
```

Use the exact reviewed `package_send` observation from the attachment inventory
for a saved nonempty package; see [package Send](DOCUMENT-ATTACHMENTS-API.md).
Do not derive or increment its timestamp, package UUID or generation. Send uses
the same role, quota, content-review, signature-field, immutable snapshot,
attachment, audit and invitation controls as the Hash application.

A confirmed ordinary result is 200 with `document_id` and `status`. Package Send
can return 202 with `status:"sealing"` and
`package_send:{attempt_id,outcome:"active",reconciliation_required:true}`.
Sealing is pending work, not proof that invitations were sent. A 503 containing
an attempt ID requires inspection of that exact attempt. Signing URLs are never
returned by this machine operation; Hash delivers the customer invitations.

The existing document UUID is the target of this operation; this route does not
create an idempotency-key record or accept the template command's replay contract.
An ordinary repeat after Send returns 409 instead of sending twice. After a lost
response, read the same document's status and, for a package, inspect the returned
attempt. Do not create a replacement document or blindly retry an uncertain
ceremony. `retry_authorized:false` in inspection is not permission to resubmit.
An attempt's `outcome:"completed"` means Send finished; it does not mean the
contract has been signed. Use the document status and completion event below.

Consume `document.signed` for individual signing progress and
`document.completed` for the completed ceremony, correlating by document UUID.
For signature requests, completion awaits all required signers and finalization.
Other ceremony types retain their own acknowledgement/acceptance meaning; do not
interpret an acknowledgement as a signature. Fetch final files only when the
document is completed. Webhook consumers verify the signature, deduplicate by
event UUID, and reconcile current status through GET when events are delayed,
duplicated or arrive out of order. A receiver updates its own product through
that product's API; Hash does not assume a CRM-specific record schema.

The existing IP/organization automation rate limits also cover these routes.
Respect429 and `Retry-After`; PDF/evidence resource admission can independently
return temporary unavailability. See [rate limits](API.md#rate-limits).

The template creation command below remains limited to pinned blocks templates. It has no attachment
selection or `package_send` input; those fields are rejected, rather than ignored.
A nonempty saved package requires its explicit reviewed package observation.
Prepare and review it in Hash, then use the prepared-document Send route above.
This template command does not execute delegated/pre-sign package signatures.

## Create a signature request

`POST /api/automation/v1/signature-requests`

Required headers:

```http
Authorization: Bearer mth_<prefix>_<secret>
Content-Type: application/json
Idempotency-Key: <stable request or delivery id>
```

`X-API-Key` is accepted instead of `Authorization`. Send exactly one
`Idempotency-Key`, between 1 and 200 UTF-8 bytes with no surrounding whitespace
or control characters. Do not use an email address as the key. Reactor derives
the key from an operator-owned, globally unique namespace for the target Hash
organization plus the immutable workflow slug and inbound event id. The
namespace must differ for separate partner/integration trust boundaries even
when their tenant-local workflow slugs happen to match. Direct callers should
apply the same producer/operation namespace rule.
The request body must be one valid UTF-8 JSON object; malformed byte sequences,
duplicate or unknown members, and trailing JSON values are rejected.

The API key must belong to a `sender` or `owner`, be organization-wide rather
than document-scoped, and carry both existing scopes:

- `write:authoring`
- `write:workflow`

API-key issuance is a core Hash capability and is not gated on the optional MCP
feature. Calling `/mcp` with that key remains plan-gated independently.

Every automation request must pin the exact operator-approved blocks-template
snapshot in every environment. Hash does not accept an unpinned development or
legacy form of this command. From an authenticated template read, copy the
blocks template's `version` and `content_sha256` into the trusted integration
configuration:

`GET /api/automation/v1/templates/44bf21a1-26f8-4d85-a444-968649ba891d`

```json
{
  "id": "44bf21a1-26f8-4d85-a444-968649ba891d",
  "source_kind": "blocks",
  "version": 7,
  "content_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

The authenticated `GET /api/automation/v1/templates` list exposes the same fields. Review
the returned block content and default variables before approving those pins;
do not let webhook or customer input select them. A later template edit always
increments `version`. Even if an edit produces the same content digest, the old
version pin no longer authorizes that revision.

Request body:

```json
{
  "template_id": "44bf21a1-26f8-4d85-a444-968649ba891d",
  "template_version": 7,
  "template_content_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "name": "Partner agreement — Ada Lovelace",
  "variables": {
    "customer.name": "Ada Lovelace",
    "customer.external_id": "crm-1042",
    "company.name": "Example AB"
  },
  "recipients": [
    {
      "role": "signer",
      "email": "ada@example.com",
      "name": "Ada Lovelace",
      "order_index": 0,
      "locale": "en"
    }
  ],
  "lawful_basis": "contract",
  "expires_at": "2026-09-30T12:00:00Z"
}
```

`template_version` must be a positive JSON integer.
`template_content_sha256` must be exactly 64 lowercase hexadecimal characters;
uppercase, prefixes such as `sha256:`, and surrounding whitespace are rejected.

Hash computes `content_sha256` deterministically from the persisted normalized
block tree and the template's default variables—not from request overlays or
the template name. The canonical payload is the UTF-8 sequence
`{"blocks":<canonical-block-tree>,"variables":<canonical-defaults>}` with no
insignificant whitespace. The block tree is decoded through Hash's strict v1
schema, must already contain every persisted block ID, and is re-encoded in
schema field order with object keys sorted. Defaults are decoded as the strict
`map[string]string` contract and re-encoded with keys sorted. The lowercase
digest is:

```text
hex(SHA-256("hash:template-content:v1\0" || canonical-payload))
```

The authenticated response value is authoritative and avoids differences
between JSON encoders. Standalone verification tooling that computes the value
itself must reproduce the algorithm in `internal/templatepin.Canonicalize`
exactly and use the persisted template response, not a pre-create authoring tree
whose missing block IDs have not yet been assigned.

`variables` may be omitted and otherwise accepts at most 256 string values.
Every variable name must match `^[A-Za-z_][A-Za-z0-9_.]*$`, and each decoded
UTF-8 value is limited to 64 KiB. Every value must be a JSON string; explicit
`null`, numbers, booleans, arrays, and objects are rejected rather than coerced
to empty text. Numeric contractual values must also be sent as strings so their
authored form is not rounded or reformatted. The request accepts 1–50
recipients. `role`
defaults to `signer`, `locale` defaults to `en`, and `expires_at` is optional.
Hash stores recipient locales in its reviewed base-language catalog. A regional
tag whose base language is supported is canonicalized at this boundary (for
example, `sv-SE` becomes `sv` and `en_GB` becomes `en`); malformed tags and
unknown base languages are rejected rather than silently falling back.
When supplied, `expires_at` uses strict RFC 3339 with uppercase `T`/`Z`, a
dot-prefixed fraction of at most nine digits, and an offset no larger than
`+23:59`/`-23:59`; comma fractions, longer fractions, and `+24:00` are rejected.
It must also be more than five minutes in the future so an invitation cannot be
born expired. Only the currently implemented `contract` lawful basis is
accepted.

This endpoint intentionally supports block templates only. It copies the
template's canonical block tree and default variables, overlays the supplied
variables, atomically creates recipients, an initial version, audit events, and
the durable idempotency binding, then invokes Hash's normal send/sealing engine.
The template must therefore contain a valid required signature field and the
request must provide exactly the signing roles that template requires.
The organization-scoped template row is read and held through materialization,
so a concurrent edit either wins first and returns a clean pin-precondition
failure, or waits while Hash commits one self-consistent pinned snapshot. It
cannot mix blocks, defaults, or version from different revisions. The immutable
`document.created` audit payload records the template id, version, and content
digest used for the copy.

New success returns `201 Created`:

```json
{
  "automation_request_id": "ed452068-8faa-44ef-968f-a34027eb8b6e",
  "document_id": "09bc3de6-931a-4b7c-a3ec-07f6fd8b103b",
  "status": "sent",
  "replayed": false
}
```

An equivalent replay returns the same ids with `200 OK` and `replayed: true`.
The status is the document's current status, so a later replay can report a
subsequent state such as `in_progress`, `completed`, `declined`, `voided`, or
`expired`.

The response never contains recipient magic links or other signer bearer
credentials. Hash delivers invitations through its configured mail path.

## Lifecycle correlation

When an outbound Hash webhook event belongs to a document created by this API,
the event includes the same Hash-owned correlation at the top level:

```json
{
  "event_id": "5fbf907a-3900-4b9f-951c-3bd07632728c",
  "kind": "document.completed",
  "automation_request_id": "ed452068-8faa-44ef-968f-a34027eb8b6e",
  "document": {"id": "09bc3de6-931a-4b7c-a3ec-07f6fd8b103b"}
}
```

Persist `automation_request_id` and `document_id` from the command result in the
source automation record. A Reactor lifecycle workflow or another receiver can
then apply signed callbacks idempotently without Hash storing the producer's raw
event ID. The public document lifecycle kinds are `document.created`,
`document.sent`, `document.opened`, `document.viewed`,
`document.field_filled`, `document.signed`, `document.completed`,
`document.declined`, `document.changes_requested`, `document.voided`, and
`document.expired`; recipient creation, invitation, and bounce events are also
available. Events for documents created through other Hash surfaces omit
`automation_request_id`.

Hash webhook endpoint creation returns a newly generated signing `secret`
exactly once. A receiver such as Reactor must store that returned value as the
verifier key for the endpoint; a secret generated earlier by the receiver is
not automatically shared with Hash. Treat the creation response as
non-cacheable one-time credential material and rotate/recreate the endpoint if
the value is lost. Hash preserves those exact 64 lowercase ASCII-hex bytes and
stores only an AES-256-GCM encrypted copy at rest, authenticated to the owning
organization and endpoint UUID. Endpoint list and fan-out queries do not fetch
secret material.

## Idempotency and errors

Hash stores domain-separated SHA-256 correlations for the key and canonical
request, not the raw delivery id or customer payload. The canonical request hash
includes both template pins, so reusing an accepted idempotency key with a
different version or digest returns `409`. Concurrent equivalent requests
converge on one automation request and one document. A send interrupted in the
durable `sealing` state is resumed through the normal recovery path.

Relevant responses:

| Status | Meaning |
| --- | --- |
| `200` | Equivalent replay returned the existing request. |
| `201` | New document was created and sent. |
| `400` | Invalid JSON, header, recipient, variable, expiry, or lawful basis. |
| `401` | Missing or invalid API key. |
| `402` | Organization document quota is exhausted. |
| `403` | Insufficient role/scopes or a document-scoped credential was used. |
| `404` | The organization cannot access the selected template. |
| `409` | The idempotency key was reused with different canonical content, or the send lifecycle has a conflict. |
| `410` | The bound draft was deleted and later hard-purged; its replay tombstone prevents recreation. |
| `412` | The accessible template's current version or canonical content digest does not match the required pin. Nothing was materialized. |
| `415` | The request did not provide exactly one UTF-8 `application/json` content type. |
| `422` | The selected template is not a valid block-template automation source. |
| `503` | A required entitlement/provider dependency is temporarily unavailable. |

Treat only a well-formed `200` or `201` response as confirmed success. Do not
retry permanent `4xx` validation or collision responses with the same payload.
Transport failures, timeouts, an ambiguous or malformed `2xx`, `408`, `425`,
`429`, and retryable `5xx` responses may be retried with the exact same
idempotency key and body.

Hash uses `412 Precondition Failed` for template-pin drift and reserves `409`
for an already-established idempotency or lifecycle conflict. After a `412`, an
operator must read and review the new template snapshot before changing the
trusted pins; automatic refresh would defeat the approval boundary. Because the
failed claim is rolled back, retrying the reviewed body with the original key is
safe unless another request established that key in the meantime, in which case
Hash returns `409`.

A replay can recover the original ceremony but cannot authorize a new one. If
a human has revised a change-requested document back to draft, replaying the
old command returns `409`; the sender must review and send that revision through
a newly authorized workflow. Template pins, quota, and stable
template/recipient validation run before the materialization transaction
commits, so a rejected `400`, `402`, `412`, or `422` does not leave an
idempotency row, unreported draft, recipient, version, audit, or outbox record
behind. A transient failure after durable send preparation remains recoverable
by retrying the same key.
