# Pre-sign execution, approved-data sources and linked drafts

This describes the isolated implementation candidate. `PreSignExecutionEnabled`
is false by default and dependency availability is also required. Source,
component tests and migration rehearsals do not establish a configured CRM,
Reactor delivery, successful final signing, deployment or release acceptance.
Use [the registry API](PRE-SIGNING-REGISTRY-API.md) to approve a workflow and give
a named member's own revocable, finite authority before selecting execution.
A registry approval is not a document signature or an independent verification
of the member's claimed representative authority.

## Credentials and separate request identities

Browser execution and linked-draft creation require the current session, live
organization membership and sender/owner authorization. Mutations require the
exact application origin. Responses are `no-store`.

Machine execution uses a regular verified API credential belonging to the exact
executor in the approved workflow, with authoring and workflow privileges
(`write:authoring` and `write:workflow`, or an existing broader privilege that
satisfies both checks). The key must have a non-null, finite `expires_at` strictly
in the future. A non-expiring key may work on ordinary API routes and is still
ineligible for pre-sign workflow authority. Current credential identity, scopes,
membership and natural expiry are rechecked under the authority transaction.
A document-agent token, MCP identity, replacement API key or arbitrary actor
UUID is not this original executor. Creating/recovering a source and executing
pre-signing have separate request IDs and retained outcomes; preserve both.

## Execution routes

The browser prefix is `/api/v1/presign`; the machine prefix is
`/api/automation/v1/presign`. The execution suffixes are shared:

| Method | Suffix | Purpose |
| --- | --- | --- |
| GET | `/executions/documents/{document_id}/eligibility` | Bounded current exact source, authority and preparation eligibility. |
| POST | `/executions/preview` | Read-only review and original-credential-bound confirmation receipt. |
| POST | `/executions` | Confirm the exact previewed command and consume one use atomically with the retained execution. |
| GET | `/executions/requests/{request_id}` | Inspect the original preparation/committed/closed outcome. |
| POST | `/executions/requests/{request_id}/close` | Explicitly resolve the exact original request; never infer closure from a timeout or 404. |

Use the policy reference returned by the workflow view, not its distinct
workflow-definition reference. The exact command types live in
[`internal/presignexecute`](../internal/presignexecute). Eligibility is an
observation: confirmation rechecks current source/materialization, policy/grant,
credential and live data. An unfinished owned preparation remains pending;
changing its command conflicts. Revocation prevents new uses; recovery of a
previously committed execution retains the original evidence and does not
consume another use.

The supported candidate is an actual standalone approved schema-3 HTML contract
with its printed two-party profile, parallel historical signing and protected
signature fields. Selected annexes, envelopes and explicit fitted/manual-layout
combinations with delegated execution are refused rather than silently losing
content or substituting another source. Customer access begins only after actual
retention and publication. Its `pre_sign_context` and PDF observation must bind
the same retained visible derivative. Ordinary customer signing composes over
that exact derivative; the already represented provider is not stamped again.
The original source and historical evidence remain immutable.

## API birth of an approved-data source

These are machine-only routes under `/api/automation/v1/presign`:

| Method | Suffix | Purpose |
| --- | --- | --- |
| POST | `/documents` | Produce a fresh schema-3 document using the selected approved-data policy and original API executor. |
| GET | `/documents/requests/{request_id}` | Inspect the original committed/closed source request. |
| POST | `/documents/requests/{request_id}/close` | Explicitly close that exact source request or recover its existing outcome. |

The closed POST body has `request_id`, `expected_org_id`, `expected_user_id`,
`policy`, `grant` and `document_name`; optional `crm_records` is an array of at
most three `{kind,id}` record selections in strict kind order. Optional `prior`
selects a linked replacement of the exact terminal pre-signed agreement as
described below; omission preserves the original source command identity.
`policy` and
`grant` each contain exactly `{id,revision,sha256}`. The body is at most 8 KiB.
Do not submit values, HTML, PDF bytes, provider identity, a reviewed flag or a
fabricated human confirmation. The actual approved template produces fresh
printed parties and protected fields. Values and text follow only stored
`approved_data_send_v1` default, literal, named-grantor or authorized CRM rules.

For CRM, the stored scope selects the current account/tenant/generation and
allowed record kinds, paths and fixed/execution record selection. Hash performs
the genuine protected `CRMClient.ReadRecords` resolution and freshness checks;
the caller selects only records where that policy permits selection. It cannot
replace provider evidence with submitted field values. Contact `full_name`
retains its fixed native `trim-first-and-last-name-v1` transformation in canonical
admission evidence. Configured real CRM/Reactor execution remains a separate
native acceptance requirement.

A committed response binds the fresh document observation, materialization,
source commitment and base-PDF digest/page count. Use those actual observations
in the separate execution command. Replay must use the original API credential,
request and identical input tuple. A changed tuple conflicts. An unavailable
response or unconfirmed 404 is not permission to create another request; inspect
or explicitly close the original. This route does not replace the ordinary
block-only automation signature-request format.

## Create a linked replacement draft

The staff document screen offers this separate choice for a terminal pre-signed
agreement. Ordinary Later amendments still offers its existing agreed-notice
versus new-signing choice. Neither choice rewrites an old signed PDF, signature,
audit trail or conversation.

These session-only routes use `/api/v1/presign/supersessions`:

| Method | Suffix | Purpose |
| --- | --- | --- |
| GET | `/documents/{document_id}/context` | Current authenticated owner or owning sender obtains the exact original parent pins and current approved template declarations/defaults; no query parameters. |
| POST | empty | Create one fresh unreviewed signing draft, atomically linked to the terminal execution. |
| GET | `/requests/{request_id}` | Recover that original member's exact linked outcome. |

The parent must be an accessible standalone, nondeleted terminal document
(`completed`, `declined`, `voided` or `expired`) with its actual complete retained
execution/publication cohort and exact original source/template/materialization.
A privacy or authority conflict refuses the context or creation. A ready context
has exactly `schema_version:1`, `state:"ready"`, `org_id`, `user_id`,
`creation_available`, `prior` and `template`. An already-linked context has
exactly `schema_version:1`, `state:"linked"`, `org_id`, `user_id`,
`prior_document_id` and `document_id`; open that successor instead of creating
another. The response is bounded to 1 MiB and excludes private storage keys,
raw template HTML, original source values and signature assets.

The POST root is exactly `{prior,template_id,source}`. Preserve `prior` from the
context without reconstructing timestamps or numeric revisions. It contains
`execution_id`, `execution_sha256`, `document_id`, `source_commitment`,
`materialization_id`, `materialization_revision` and `template`. The original
template pin is exactly `{id,version,content_sha256,approved_by,approved_at}`.
`template_id` must name that same template. `source` uses the existing genuine
HTML document input, including fresh `request_id`, `expected_org_id`,
`expected_user_id`, current `expected_template_version` and
`expected_template_content_sha256`, document `name`, declared `values` and
`sections`. The whole closed wrapper is at most 1 MiB. The new source is rendered
from the current approved template, not cloned from old values or signatures.

The browser starts with current defaults/editable text, requires an explicit
create-only confirmation and navigates to the fresh document. Review its new
PDF and parties before choosing manual signing or a separately approved new
pre-sign execution and send. Creating this draft sends no invitation and
consumes no pre-sign use. A linked committed response is exactly
`{schema_version:1,request_id,state:"committed",prior_execution_id,
prior_document_id,document_id,source_commitment}`.

Before POST, the browser stores only original opaque actor/request/parent/template
IDs in a session marker. An uncertain response keeps creation blocked. Inspect
with the original member; if the linked request is absent, the client may read
the actual original HTML-creation outcome at
`GET /api/v1/templates/{template_id}/html/document-requests/{request_id}`.
Only its exact authenticated closed tombstone resolves closure. Explicit closure
reuses `POST` to that path plus `/close`, with exactly
`{expected_org_id,expected_user_id,confirmed:true}`. It serializes with actual
HTML creation; a generic committed HTML response is not a verified supersession
link. A 404 is still unconfirmed. Acknowledge confirmed closure before clearing
the original marker or preparing a new request.

## Policy-derived API replacement

The same machine `POST /api/automation/v1/presign/documents` can include optional
`prior` with exactly the parent shape above. It is part of the same original
command digest. Preserve the prior execution/source/materialization observations
from the original retained outcomes and the exact original approved template pin
from the workflow configuration; do not reconstruct approval timestamps. These
are expected observations, not authority. A missing or mismatched observation
refuses; there is no fallback to an ordinary source or a second request.

The actual current policy must select that same template ID and fresh eligible
approved schema-3 revision. The actual current API user must be an owner or the
sender owning the terminal parent. This does not require equality with the old
execution's historical credential; it requires the genuine current policy/API
credential, grant, parent and privacy fences. The native parent/retained-cohort
check precedes CRM/provider, rendering, upload and new document effects. All new
values and printed parties still come only from the approved-data policy and
actual protected CRM witness; `prior` never permits caller-supplied values,
cloned signatures or manual review flags.

The real HTML creation's final transactional callback seals both the immutable
original API source receipt and the linked replacement/audit against that same
M79 request before the same commit. It never adds a link after committing a
standalone source. The existing source POST/replay response remains the original
source receipt; the handler also reads and compares its actual same linked
outcome before acknowledging a replacement. Original source GET/close routes
and credential-scoped recovery are unchanged. Replay of the identical original
request does not acquire a new use or require fresh grant/template eligibility;
current original API credential/member checks still apply. An altered parent,
policy, grant, record selection or credential conflicts with that request.

The session authoring flow remains separate from policy-derived API creation.
Configured CRM/Reactor integration, native API-linked birth/rollback/concurrency
qualification, browser interaction and recovery, whole-journey signing and exact
release gates remain pending. The default-disabled switch is not enabled by
this source change.
