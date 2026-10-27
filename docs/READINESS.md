# Hash readiness

## Current checkpoint: standalone source implemented; installation acceptance pending

Updated 2026-10-27. Hash implements the agreed standalone document-signing
workflow. Its source and controlled qualification are distinct from a configured
installation, managed release and real customer acceptance. This page does not
claim that an installation is deployed, that external email has arrived, or that
an operator's legal/privacy arrangements have been completed.

### Implemented application scope

- Native email/password staff registration, mailbox verification, invitations,
  login, logout and recovery use the existing secure session cookie, live
  membership/session checks and encrypted durable account-mail queue. An invited
  colleague retains the assigned workspace and role. The first operator workspace
  has a bounded maintenance setup path; it does not seed a password or session.
  Optional OIDC is not required for native login. See [staff login](STAFF-LOGIN.md).
- Approved HTML designs support declared values and parties in fresh documents.
  Saved PDF masters retain their printed text and support signature-field overlays.
  Both paths support PDF review, supported signature fields, negotiation,
  revisions and ordinary signing. Saved attachment packages use an explicit
  reviewed observation before Send. Completion preserves the final PDF, audit
  certificate and retained evidence. Completed originals remain immutable;
  linked drafts and later amendments retain their own history and selected
  policy. A change notice does not itself create a new signature. See
  [attachments](DOCUMENT-ATTACHMENTS-API.md) and [API contracts](API.md).
- Any authorized external product can use the standalone HTTP API to read
  prepared documents/templates, send an existing document, inspect Send/status,
  and download completed files. Template-based creation has its own pinned
  blocks-template contract. Signed lifecycle webhooks provide progress and
  completion events. Neither CRM/Reactor nor MCP is required for this integration.
  See [automation API](AUTOMATION-API.md).
- MCP provides AI authoring/settings tools. New keys default to read/authoring;
  outward workflow tools require explicit workflow scope and the current role.
  API/MCP permissions, plan features, quotas and live credential checks remain
  enforced. Configuring a service does not bypass document review or signing.

### Explicit source limits

Production Send/finalization deliberately refuses mutable image-block/storage
references and the unsupported `initial_field`, `text_field`, `date_field` and
`checkbox` block types. These are block-editor limitations; the supported
signature-field and HTML/PDF-master paths are separate. Production organisation
logo upload and nonempty `logo_url` branding updates are also disabled until
exact-version evidence binding is implemented. Color/font branding is frozen
per document. See [production evidence limits](../DEPLOY.md#block-evidence-production-limitations)
and [branding limits](../DEPLOY.md#branding-evidence-limitation).

### Deployment scaling boundary

Production currently permits one HTTP server per database. Aggregate rate limits
and Yjs collaboration state are process-local. Horizontal HTTP scaling requires
shared coordination/state and measured capacity evidence; starting another server
or multiplying these limits does not supply that support. The separate worker
remains part of the supported deployment. No Redis or other scaling implementation
is required for the existing single-server profile.

Delegated/pre-sign execution remains optional, disabled by default and restricted
to its documented supported scope. It is not needed for ordinary signing.
BankID/higher assurance, paid SaaS, CRM/Reactor adapters and a broader connector
catalogue are outside the first-use requirement. No Redis, gRPC or unrelated
feature expansion is required merely to finish this standalone path.

## Qualification and remaining installation work

Controlled source qualification has exercised native accounts and migrations,
ordinary two-party signing, final PDF/hash/certificate consistency, package/API
journeys and the filtered public build/test/scan path. Results apply to the exact
source and fixtures tested. They do not establish intended-host cookies/TLS,
external inbox delivery, configured provider behavior or measured capacity.
This documentation update is not a new application test or deployment receipt.

| Area | Remaining installation or acceptance outcome |
| --- | --- |
| Coherent release and first use | Adopt the reviewed server, worker, frontend, renderer and migrations together through the operator's release procedure. Bind the real workspace, owner, finite plan/catalog, keys and process allocations. Preserve any retained installation and verify the applicable cutover/recovery path. See [deployment](../DEPLOY.md). |
| Owner and signer journey | On the intended origin, verify native owner setup/login/recovery, approved design and fresh PDF review, parties/fields, negotiation/revise/resend, attachment observation, both required signatures, readable final downloads/certificate and retained history. Include current role, tenant/origin and expired/revoked-link refusals. Obtain actual user acceptance. |
| Delivered communication and integrations | Configure verified STARTTLS SMTP and prove invitations, owner alerts, reminders, account setup/recovery and completion links in the intended inboxes. SMTP acceptance or a queued event is insufficient. Exercise the chosen HTTP client and signed-webhook receiver, including duplicate/delayed events and uncertain Send reconciliation. Optional SSO/CRM/Reactor need acceptance only when enabled. |
| Storage, imports and observability | Qualify the configured S3 exact-version/retention/legal-hold behavior, key continuity, scanner/signature freshness and fail-closed import outages. Bind errors, logs, metrics and backlog monitoring to the release and verify actual alerts/recovery. Source instrumentation or a heartbeat alone is insufficient. See [observability](OBSERVABILITY.md). |
| Deployment capacity | Assign and verify process/database/renderer allocations for the chosen deployment and expected load. Measure overload and recovery before claiming a capacity target. Logical limits and earlier planning targets are not measured headroom or a supported tenant count. See [work configuration](WORK-RUNTIME.md). |
| Backup and restore policy | Choose and record the deployment's backup policy. An explicit offhost-backup deferral is not a passed backup or restore drill, and does not waive primary storage retention or key continuity. Restore integrity and measured RPO/RTO remain unproven until tested. See [backup/restore](../ops/BACKUP-RESTORE.md). |
| Operator notices | Supply the actual operator identity, working privacy contact, applicable authority and published operator policy URL/content. The bundled legal pages are general information and do not supply those facts. An operator policy may use a same-origin HTTPS URL; a separate website is not required by the code. No legal assurance or retention choice follows merely from the app or its hash chain. |

Configuration still requires the supported PostgreSQL, versioned S3/Object Lock,
SMTP, scanner and renderer/native-worker contracts. Operator keys, plan/catalog
and resource settings must follow the documented setup path. Source validation,
pushed source, exact CI, merge, deployment and configured-service acceptance are
separate states. Optional integration configuration is not a prerequisite for
standalone signing.
