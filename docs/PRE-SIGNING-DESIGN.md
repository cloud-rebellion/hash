# Scoped sender pre-signing

This is the implementation contract for the approved roadmap feature. The
authorization/evidence model is implemented and verified locally; pre-signing
is not enabled in Hash. Both parties continue to sign through the existing portal
by default.
No foundation-only check establishes a working delegated signing journey.

## Required behavior

A named provider representative may grant revocable authority for an approved,
pinned template and a reviewed workflow policy. An owner approves that policy;
the named signer grants their own authority. An owner or API key cannot fabricate
the signer's grant, privacy acknowledgment, portal visit or manual signature.
Each use records a separate exact-document execution. The provider-visible signed
PDF must be durable before invitation and contain the signature in the customer's
first verified view. Do not fabricate prior customer viewing evidence.

Revocation prevents future executions. It does not delete or rewrite a committed
execution. A lost response is recovered from the original authenticated scope
and immutable execution, without consuming another use or silently switching
signing modes. Grant creation and execution do not establish representative
authority, legal sufficiency, or an advanced/qualified signature.

## Eligibility and policy

The first integration uses the existing reviewed source-schema-3 standalone
provider/customer contract, its exact approved origin and its two protected
signature fields. The provider's printed representative name/email must match
the grant and current named Hash member. Current organization membership and
sender/owner role must be checked at execution. Account declarations do not
independently verify identity or company authority.

The initial model also requires the grantor to be the document's original
sender/author. A separately bound workflow executor may act under that grant.
Supporting a document authored by another member requires an independently
pinned provider-member relationship and reviewed authorization; the current
`sender_id` alone cannot supply that relationship.

An approved historical template revision may remain usable under the existing
HTML design contract. Match the selected revision and its approval/version/SHA;
do not mistake the latest template head for the selected revision. An archived
template, missing approval or changed selected-origin/policy binding refuses use.

The policy must bind a real server-owned workflow revision, its permitted
executor and operation, and approved template/wording/recipient/data rules.
An external workflow label is descriptive data, not authorization. Machine
execution additionally binds the originally verified credential, live scopes,
expiry and revocation at the actual dispatch boundary. Current automation accepts
block templates only; extending it to reviewed HTML and delegated authority is
required work, not compatibility already provided by a new descriptor.

New contract prose requires human review. Manual document review and unattended
approved-data execution are distinct policy paths. Neither a broad template
grant nor a CRM job title may approve arbitrary new wording. Existing fresh CRM
account, record, mapping and value witnesses remain necessary on that path.

## Evidence and transaction boundaries

Use new, purpose-separated policy, grant and execution schemas/domains. Preserve
existing source-schema-1/2/3 and manual signing/notice/certificate canonical bytes.
Immutable grant snapshots are separate from current revocation, membership,
identity, expiry and consumed-use observations. A pure validator cannot establish
that its supplied observations are authoritative or locked.

Prepare the signature and provider-visible PDF outside long-lived SQL locks.
Before committing an execution, retain the authoritative document, selected
template/policy, relevant members/credential and grant using a reviewed consistent
lock order. Recheck permission, identity, grant/policy state, finite use allowance,
exact document/source/materialization/field pins and natural deadlines after
external work and audit waits, immediately before commit.

Persist the exact execution, provider signature/status and durable sealing plan
atomically at the draft-to-sealing boundary. A revocation race either prevents
that use or follows an already committed use. No ordinary provider signing token,
invitation or reminder is created for the delegated signature. Recovery consumes
the committed plan rather than taking a fresh grant admission.

Keep the original reviewed source PDF and the derived provider-visible PDF as
separate versioned objects with exact SHAs and VersionIds. Bind both, the ceremony,
materialization, provider recipient/field, signature image and delegation evidence
in the execution and new evidence schema. Verify the partial render separately;
do not weaken the final all-required-parties signature validator. Customer
invitations wait until that exact derived artifact is durable and verified.

The recipient PDF/context/field observations must agree on the derived view.
Disclose that the provider signature was applied under a named grant. Do not
reuse the public manual Sign path with synthetic Article 13 evidence. Preserve
the customer's real notice acknowledgment and manual signing journey.

## Negotiation and a new ceremony

Current RequestChanges and Revise refuse captured signing evidence. Pre-signing
must not bypass those safeguards or erase a signature to reopen a draft.
Implement a linked superseding document and new ceremony for changed terms,
preserving the earlier execution, PDFs, audit and conversation references.
Create fresh recipient/field identities, links, source materialization and review;
any subsequent delegated signature is a new explicitly authorized use.

Until linked supersession, customer-visible signed rendering and full execution
are implemented and verified, the pre-sign mode remains unavailable. Ordinary
negotiation and both-party manual signing remain supported through their existing
paths. A settings selector or grant snapshot alone does not complete this feature.

## Frontend lifecycle

Capture the original actor and exact source/account/policy/grant observations.
Invalidate confirmation and late responses after identity changes, document or
recipient edits, or CRM Apply. Validate the returned actor and all exact witnesses
before adopting a result. Preserve local wording and drafts on refusals or unknown
outcomes. Persist only opaque pending-request identifiers across reload; a network
error or unconfirmed404 never clears the marker or authorizes a new request.
Inspect the original request and require explicit adoption of its authoritative
document/execution. These controls must be exercised through the current built UI,
including switched credentials and lost responses, rather than inferred from API
types or unit fixtures.

## Verification required before enabling

- Actual database grant/policy creation, self-authorization, revocation and
  permission/expiry/quota races, including waits and audit failures.
- One execution under concurrent retries; recover committed uses after revocation
  without another signature/use/invitation; refuse foreign actor/tenant/template,
  altered policy/data/source/field/artifact pins and malformed input.
- Current built-browser self-grant and revocation, explicit mode selection,
  lost-response recovery, customer-visible provider signature, truthful disclosure,
  real customer signing, final PDF/evidence and linked negotiation/new ceremony.
- Real reviewed Reactor/CRM dispatch, credential scope/expiry/revocation and
  permitted-data/recipient enforcement; no fallback to manual signing or new prose.
- Exact-version immutable storage, historical manual evidence verification and
  independent recovery, followed by managed exact-source CI/release and live inbox
  acceptance. Pure foundation tests do not cover these gates.

## Source and assurance references

The current manual Sign path requires a real recipient credential and notice
evidence (`internal/sign/flow.go`, Sign and ValidateLockedNoticeEvidence).
`internal/send/engine.go` persists the sealing intent and later queues invitations.
`internal/handler/fields.go` freezes PDF values after a captured signature.
`internal/pdflayout` already refuses multiparty PDF layouts containing non-signature
fields: a second fillable PDF party cannot be stranded through supported Send
gates. Supplemental block field behavior is a separate scope; do not broaden that
freeze without a complete shared-readiness and compatibility design.

[eIDAS Articles 3, 25 and 26](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A02014R0910-20241018)
distinguish signature definitions, legal treatment and advanced-signature
requirements. This engineering design supplies no legal-effect or higher-assurance
certification. Intended use, controller notices and applicable contract requirements
still need their own reviewed acceptance.
