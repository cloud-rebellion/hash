# Lifecycle6: later amendments and safe maintenance

This source cut introduces application/worker lifecycle6 for migration115. It
covers immutable later-amendment links, frozen policy/file pins, notice access,
exact legal audience and separate owner operational mail. The new worker's
cleanup query retains amendment members/file references; an older worker's
embedded query cannot discover these new references. A failed final SQL DELETE
or FK restriction is insufficient after an old worker has already deleted an
object from storage. Existing Object Lock and exact-version semantics remain.

The existing schema4 release manifest carries lifecycle6; its JSON schema does
not change. Stage/CI accept historical lifecycle1..5 for reading and
qualified compatible recovery, but never approve an ordinary lifecycle downgrade.
M115-bearing source must prove a canonical lifecycle6 and exact embedded migration
digest from the staged content-addressed image's `hash-rollbackcheck
--lifecycle-contract`, run read-only with no network or secrets. This dedicated
mode reads no database configuration. Historical M115-absent source retains the
prior lifecycle5 semantics rather than being relabeled by Stage's new maximum.

Production checks both the previous release and the actual canonical PostgreSQL
schema. It refuses a lower candidate regardless of schema-compatibility or
maintenance approval. A single READ ONLY psql snapshot checks all five M115
catalog identities and Goose history. Any M115 table or any version115 ledger
entry establishes floor6, including an empty schema, interrupted/current5 upgrade
or a historical down attempt. A version above115 is unknown and refuses. Missing
or failed observations refuse; they never prove an old image safe. The check
runs after old writers are quiesced and again after migrations/audits before
writer cutover. It is not complete-schema or full data-integrity validation.

Storage-contract.json and database-contract.json remain schema1 physical
continuity contracts. They identify encryption/endpoint/bucket or actual database
identity; rewriting them cannot grant a lifecycle downgrade. Existing identity,
SSE-C, exact-version, archive, backup, migration, lawful-basis and audit gates stay
active. Bootstrap ingress consumers reuse the new maximum and retain all other
manifest checks. The cold-backup archive still binds the actual release manifest,
its lifecycle field, migration bytes and physical contract snapshots.

## Mandatory runtime maintenance boundary

Source gates do not control an old process already running during migration.
Before M115, drain ingress and scheduled work, establish the supported maintenance
window, inventory every server, worker, job/CLI, replica and external automation
that can write/clean storage/send mail, stop dispatch, cancel and join local
owners, and prove no old eligible writer or old deploy-capable Stage worker can
restart. Review unresolved provider/COMMIT/delete/SMTP outcomes; a timeout or
unacknowledged cancellation is not successful retirement. Preserve private
configuration and old containers/images as recovery evidence, without restart.

The existing production quiesce helper stops the two canonical server/worker
containers before migrations. That is useful enforcement, but it does not prove
absence of additional workers, a generic deployment, detached jobs or external
I/O still unresolved. Docker stop/absence and source tests alone must not be
reported as complete fleet/process/journal retirement. Actual owner/job/daemon
and configured runtime evidence is required. Deployment-capable Stage workers
must all have the new guards before Hash's schema/write boundary; no mixed old
worker rollout or rolling downgrade is permitted.

On migration or candidate failure, keep writers stopped in maintenance whenever
contracts differ. Retained same-contract6 recovery remains available through the
existing archive/physical image, configuration, source, database, lawful-basis,
audit and rollback-state proofs. Historical manifests may be inspected and an
old pointer restored for explicit recovery, but this does not authorize starting
an old cleanup worker against the upgraded database. To recover a pre6 writer,
make a separate reviewed paired restoration of database and exact retained
object/version/encryption estate from the same qualified backup, validate all
original continuity/integrity gates and select the matching historical release.
Do not remove M115 rows/tables or edit Goose/current/manifests to manufacture a
rolling downgrade. The M115 occupied-history Down refusal remains unchanged.

## Required qualification (not performed by this source author)

1. Compose current M115/cleanup/notice/owner/signer/policy sources and both
   Stage/CI companion guards; format and execute the authored native
   tests and existing release/storage/database/bootstrap/rollback tests.
2. Build exact Hash image and execute the capability flag with network disabled,
   no DB env and a read-only root. Independently match reported migration digest
   to the actual staged tree and image metadata; old images must refuse.
3. Execute the exact Stage psql script against disposable actual PostgreSQL16:
   empty/no ledger ->5, ordinary pre115 ->5, M115 tables ->6, ledger115/current
   pointer5 ->6, down/false115 history ->6, higher116 ->refusal, missing permissions,
   malformed history/error/extra output ->refusal. Confirm one read-only snapshot
   and no writes; command-recording tests alone do not prove PostgreSQL behavior.
4. Verify ordinary6→5 is refused despite all approval booleans, same6→6 recovery
   remains eligible only with existing retained state proofs, historical4→5
   maintenance behavior remains exact and old lifecycle manifests still load.
5. Perform real full writer stop/join and failed-migration/recovery rehearsal
   with exact host/process/image/source/runtime receipts before enabling writes.

This is unadopted source preparation. No native/compiler/SQL/Docker/runtime or
managed release was executed by this packet's author. Parent owns integrated
qualification, adoption, release decisions and final Mesh writeback.
