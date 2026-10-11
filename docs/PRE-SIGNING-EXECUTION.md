# Delegated execution persistence

This supporting backend unit does not enable pre-signing or automatic sending.
The default remains the existing two-party manual ceremony. See
[the full integration contract](PRE-SIGNING-DESIGN.md) and
[workflow and self-grant API](PRE-SIGNING-REGISTRY-API.md).

## What is stored

Migration 82 adds an immutable exact-document execution, a contiguous selected
grant-revision use ledger and an original-executor request outcome. The complete
transaction pairs the execution with its provider signature/status, retained
sealing intent, source materialization and chained audit event. Partial pairs
cannot commit. Closing an uncommitted original nonce is terminal.

`internal/presignexecute` exposes typed command construction/strict decoding,
`NewRecord`, caller-owned `AppendAtomic`, integrity-only `LoadOutcome`, and an
exact nonsecret audit payload. Commands bind the full document snapshot and the
original admitted credential commitment. These methods neither authenticate nor
commit, publish events, render, store artifacts or send mail. A descriptor and
its SHA cannot establish an authorized operation or an actual artifact read.

The database checks the selected policy/grant, real source-schema-3 plan, both
printed parties and protected fields, materialization/base version, execution,
request and audit pairing. A delegated provider has an explicit signature kind
and no fabricated manual IP, user agent, invitation or portal visit. Its public
credential is disabled using an empty token hash and the exact finite UTC Unix
epoch expiry. The existing token NOT NULL constraints remain; neither sentinel
value is a record of an invitation. A committed provider credential cannot be
renewed. The customer remains unsigned at the initial commit.

The new intent allocates the real ceremony epoch before publication. During
sealing, the document may retain NULL or an earlier finite epoch. Published
states require the exact committed epoch. The intent and committed execution
remain retained even before artifact retention starts; ordinary send recovery
refuses them and excludes them from its manual retry queue.

Migration 81's immutable `consumed_uses` remains zero. The new append-only
execution-use ledger supplies actual selected-revision allowance. A registry/UI
projection of that ledger is still required before execution is enabled.

## Data admission and partial validation

`presignregistry.EvaluateExecutionData` enforces every stored value/section rule
against the actual draft source and exact approved template. Approved defaults,
literals, absent values and named-grantor fields are distinct. Reviewed values
require real matching review. CRM values require original private account,
record, mapping and scalar witnesses, without fallback or transformations.
Fresh CRM evidence expires after the existing 45-second observation window.

The separately versioned admission commitment binds the source, values,
effective sections, template, workflow/policy, named grantor and relied-on review.
Approved-data mode records explicit nonreliance on human review; it does not
invent a review or claim that the document was never reviewed. Strict decoding
of committed evidence is separate from fresh observation and authorization.

`pdflayout.ValidateProviderPartialSignatureRows` verifies the supported provider
partial state against the committed descriptors, exact stored data admission,
both protected fields, signature span and archived font bytes. It preserves
`ValidateSignatureRows`, which still requires both parties for final completion.
The partial validator does not prove a storage read or a provider-visible PDF,
branding/disclosure provenance, authentication or permission to publish.

## Caller and recovery obligations

Before any enabled integration, the orchestrator must prepare and verify the
provider derivative outside long SQL locks, retain the original credential and
natural deadlines, and use a reviewed consistent lock order, taking the original
request lock early and live user locks before the grant head. It must verify
actual source, selected approval, CRM/data rules, protected
fields and archived artifact/branding/copy/recipe pins, then recheck live
authority and deadlines after audit waits immediately before commit. Never
compensate prepared evidence after an ambiguous commit.

Authenticated original-executor recovery loads the committed result without
freshly consuming allowance. Grant revocation or expiry does not erase a prior
execution. `LoadOutcome` checks recorded integrity rather than current sending
eligibility; the caller still retains actual read authorization and its deadline.
Closed readback relies on the immutable insert-time audit guard. Independent
cryptographic audit-chain verification is a separate evidence/recovery check.

Dedicated artifact retention/recovery, first customer view of the exact signed
provider derivative with truthful disclosure, customer-only invitation/reminders,
real manual customer signature, final rendering/certificate/export, and linked
superseding negotiation remain required. The fresh adapter must derive the
captured branding observation using an explicitly specified recipe. No new
branding digest recipe or assurance claim is supplied by this persistence unit.

Local package/PostgreSQL checks do not establish renderer/storage acceptance,
real CRM/Reactor dispatch, production deployment, legal sufficiency or whole-app
readiness. Exact-source managed CI and live release acceptance remain required.
