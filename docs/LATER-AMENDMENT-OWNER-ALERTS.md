# Operational original-owner alerts

A newly linked later amendment and a newly issued agreed-process notice each
queue one separate operational email to the original document's current SenderID.
The actor, first organization owner and legal notice recipient list do not select
that target. Native SQL freshly requires the SenderID's current same-tenant member
to have owner/sender rights and a canonical bounded current mailbox; all-subject
actor/privacy checks remain in the existing amendment route. A missing, revoked
or unavailable current owner refuses the entire new mutation rather than silently
mailing someone else or committing a partial alert.

The generic subject/body contains an authenticated `/documents/{original}` staff
link. It contains no contract name, clause, party identity, notice capability,
signer action or legal-effect claim. Notice issuance's operational subject says
"notice queued"; it never says the recipient received or accepted anything. The
owner is not added to the reviewed legal notice audience. An explicitly reviewed
legal recipient can independently be the same mailbox; those are separate queue
rows with separate purposes and records.

The implementation reuses the existing actual email_deliveries transactional
outbox and SMTP worker used by negotiation/comment/completion alerts. No existing
generic event dispatcher handles the two amendment event kinds, so this native
hook is necessary; it does not duplicate an existing automatic fan-out. No new
alert receipt store, authentication system, provider or endpoint is introduced.

The immutable relation/notice row stores owner_alert_user_id,
owner_alert_email_delivery_id and owner_alert_message_sha256. Its existing
transactional audit event carries the same nonsecret IDs/hash and initial queued
fact. A native guard independently checks current owner/privacy, actual message,
existing SQL queue digest and event references. Message identity/body cannot be
changed afterward; the queue's ordinary retry/sent/failed lifecycle remains
mutable. FK RESTRICT retains the actual queue reference. These additional
identifiers and private mailbox/message remain part of retained evidence and
existing manual DSR/export review; they must not be silently erased or omitted.
No new object-storage references or PDFs are created by these alerts.

The queue insert, mutation, event and references commit together. A later failure
rolls them all back. Exact replay or reconciliation of a committed request takes
the existing immutable result before queueing, preserving the original delivery
ID. SMTP remains at-least-once under its existing unknown/provider/acknowledgement
semantics; this code does not invent exactly-once mailbox delivery.

A reserved internal header selects an additional fresh worker check. The header
alone grants nothing: the native immutable relation/notice/event/queue binding,
current original ownership, same tenant, role, mailbox, privacy state and message
hash must still match. An unavailable check prevents SMTP and leaves the existing
lease for later recovery. An ineligible target is durably failed with the closed
owner_alert_not_eligible category and zero SMTP calls. Ordinary mail is unchanged.
Changes after this finite preflight or after an SMTP attempt cannot retract an
email; every click still requires current staff authentication/RBAC. No message
or queue state proves recipient delivery, signature, acknowledgement or effect.

The current application has no per-user/org notification-preference fields or
settings. These alerts follow its existing mandatory transactional notification
policy; no preference system or hidden opt-out bypass is invented. If preferences
are added later, their supported native row, mutation and final worker semantics
must be integrated explicitly and tested. The present check must not be described
as honoring preferences that do not exist.

Source-only successor to sealed core b860e149 and notice305b9116. Migration115 is
still unadopted, so the new NOT NULL native reference columns require no live-data
backfill. Compose narrow table/function changes with the separate policy freeze,
signer-context and dispatch-fence successors. Server, generated schema and worker
must move coherently, and only compatible images may dispatch or roll back after
new writers run. The packet does not modify Stage's separate lifecycle contract.

Authored unit and actual native PostgreSQL tests remain UNRUN by the author.
They cover bounded generic messages/URL and header rejection, real queue/audit/SQL
digest references, another owner acting on the original owner's agreement,
request replay, separate legal audience, current owner refusal with no partial
mutation/audit/mail, immutable queue references, and role/email/privacy changes
before dispatch. A worker test refuses before SMTP when the actual eligibility
store is unavailable. Root owns formatting, codegen, compilation/native execution,
SMTP/browser/provider acceptance and final Mesh writeback.
