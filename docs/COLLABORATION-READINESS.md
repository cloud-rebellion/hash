# Collaboration completion evidence

## Current acceptance state (2026-10-05)

The current candidate has local PostgreSQL and rendered two-user acceptance for
canonical saves, generation receipts, live role demotion, and owner recovery
after an external canonical replacement. Recovery preserves old server replay
in bounded archives and retains the local draft until a separately confirmed
reload. Socket initialization now requires the exact fetched canonical
timestamp, preventing an old tab from seeding a newly recovered generation.
The earlier findings and pending statements below are historical evidence;
the current owner recovery/API contract is in [API-GUIDE.md](API-GUIDE.md).

Latest evidence: `/private/tmp/hash-rendered-recovery-final.log`,
`/private/tmp/hash-browser-collaboration-receipt.json`, and
`/private/tmp/hash-browser-archive-replay-receipt.json`. The latter replays the
actual downloaded 297-byte/12-update archive with installed Yjs and verifies
that it preserves `Initial contract alpha beta` without the replacement tree.
The rendered fixture verifies the current canonical tree is exactly one
`Replacement contract` paragraph after the explicit reload.

Preview preservation follow-up: `/private/tmp/hash-preview-draft-rendered-go-race.log`
passed with real HTTPS/WebSocket/PostgreSQL and Chromium (Go race detector,
handler10.203s). The same editor instance preserves a demoted user's rejected
local draft and its dirty navigation guard while preview is open. An owner's
in-flight canonical save can be held, toggled through Preview/Edit without losing
local text, then resumed and verified from the canonical API. Preview shows the
saved content while that save is held. The updated collaboration receipt records
all four preview assertions with zero browser errors; its screenshot was inspected.

Deleted-draft archive review now has rendered Go HTTPS/PostgreSQL acceptance:
owners can select a linked privacy request, inspect metadata and download exact
opaque bytes during soft-delete grace. An open access request defers explicit
archive deletion; the page exposes no reset/reload action. Viewer and foreign
owner denial are verified. Receipts:
`/private/tmp/hash-dsr-archives-rendered.log` and
`/private/tmp/hash-dsr-deleted-archives-receipt.json`.

The separate parent/source retirement worker now holds an exact lease, parent
lock and shared organization privacy fence through version-specific source
cleanup and row commit. Actual PostgreSQL race tests verify pending linked/global
requests, lock contention, stale leases, rollback/retry and concurrent closed
request orphaning. Receipt: `/private/tmp/hash-protected-parent-purge-fixed.log`.
Source files remain in backup inventory during grace; the canonical inventory
query passed `/private/tmp/hash-canonical-recovery-inventory.log`. The coupled
restore rerun stopped at its unavailable pinned MinIO image preflight.

Sender recipient draft preservation has rendered HTTPS/PostgreSQL/Chromium race
acceptance in `/private/tmp/hash-browser-sender-panel-receipt.json`. It verifies
cancelled edit discard and document navigation, same-document query/hash changes,
Preview/Edit retention, and isolation of delayed recipient reads and committed
save receipts, plus current-document create/edit/delete/recreate. Exactly five
intended recipient mutations occurred, with a new recreated UUID and retained
deleted-subject audit, and no
browser errors or send, sealing-intent or mail-outbox side effects. The frontend
suite passed 126 tests with zero Svelte errors/warnings and a production build.
The current recipient database/browser race run passed
(handler30.773s/recipients5.342s) in
`/private/tmp/hash-recipient-rendered-db-race-final.log`; the complete Go
race suite passed in `/private/tmp/hash-recipient-full-go-race-final.log`.
The recipient receipt establishes that rendered journey, rather than live
identity-provider or mail-delivery acceptance.

The lifecycle authority contract binds Send, Void, Revise, manual Remind and
automation materialization to the original session or machine credential after
parent/document and live-member waits and again before commit. REST/automation
return 401 for expired credentials and 403 for revoked permissions; MCP returns
tool errors. Send preflight stages values and binding observations read-only;
the authorized transaction verifies the original draft and binding definitions,
revalidates recipients and freezes values for block/PDF sources. Changed
preparation returns HTTP 409. Manual reminder authorization and rollback passed
the focused engine and actual REST/MCP runs; both manual and automatic reminders
roll back if the document deadline passes before commit. API expiry is sampled
from the database clock after its credential row lock; an actual natural-expiry
wait regression demonstrated and corrected a stale pre-lock clock evaluation.
Committed sealing recovery and
automatic reminders retain their durable intent/schedule authority rather than
requiring a still-live user credential. A manual reminder moves `next_fire_at`
three days ahead without replenishing `fires_remaining`.

Synthetic sessions and loopback HTTPS do not establish real OIDC login, SMTP
inbox receipt, CRM account/field mapping, Reactor callback/dispatch, ClamAV
scanning, storage retention/restore or deployment acceptance. Local verification
does not establish compliance certification. The HTTP/collaboration process
remains a singleton. Archive merge authoring, general legal holds, broader
object/backup retention, coupled restore and workload capacity need further
acceptance. Archives are operational recovery data, not signing evidence.

## Verified initialization defect

Two fresh Y.Doc clients both pass the editor's empty-history bootstrap test.
If each inserts the same canonical paragraph before receiving the other's
update, Yjs correctly merges two independently authored paragraph identities.
Both clients converge to two paragraphs rather than the intended one. This was
reproduced with the installed Yjs package, not a mocked CRDT implementation:
`/private/tmp/hash-yjs-double-bootstrap.json` records bothSeeded=[true,true],
clientAElements=2, clientBElements=2, expectedElements=1.

The empty-state-vector check already protects intentional deletions from being
reseeded. It cannot elect an initializer across clients.

## Required next implementation

The server must designate one initializer for a room with no persisted history
and communicate that designation before completing initial synchronization.
Only the designated initializer may seed canonical content; other clients must
receive that seed through ordinary Yjs replication. If the initializer leaves
before publishing, ownership needs bounded reassignment to a remaining peer.
Loading existing history must never allocate a new seed owner, including when
that history encodes an intentional empty document. Initialization ownership
must share the room's existing mutex and authorization boundary.

Tests must use real Yjs updates to show simultaneous fresh clients produce one
canonical tree, owner disconnect recovers, intentional empty history remains
empty, and reconnect does not reseed. The server protocol and client behavior
must be verified together. No initialized client should silently discard local
content to repair a conflict.

External canonical replacements need a separate room-generation/reconciliation
contract so old Yjs history cannot reintroduce a replaced tree. Multi-client
canonical save receipts also require reconciliation with the editor's revision
preconditions. These are open completion requirements, not deployment evidence.

## Candidate ownership protocol

The local server/editor candidate adds message type 5 carrying an initializer
grant. The server sends it before initial sync, permits one fresh-room seed
publisher, ignores exact empty Yjs handshake updates, and reassigns ownership
when an unpublished owner leaves. The editor seeds only after a grant. Server
race tests cover election, non-owner rejection, no-op handling, reassignment,
and normal post-seed updates; frontend checks pass. Server and editor must be
released together. Real two-browser/socket replay acceptance, legacy persisted
no-op-history handling and external replacement reconciliation remain pending.

The candidate loader now removes exact empty handshake records from legacy
persisted logs after validating their framing. No-op-only logs permit a seed
owner; logs containing other updates keep their initialized status and content.
Server race regressions cover both cases. This does not decode or certify Yjs
update semantics, and real socket/two-browser acceptance remains pending.

The editor now uses the same `bootstrapIfGranted` policy for initial sync and
owner reassignment. Real Yjs regressions exchange updates between two fresh
clients and verify exactly one canonical paragraph, repeated grants do not
duplicate content, and reassignment never resurrects deleted history. All 33
frontend tests pass; Svelte reports zero errors and warnings. These tests exercise
client seed policy, not WebSocket transport or multi-browser acceptance.

Provider-level regressions now dispatch binary grant and sync-step-2 frames
through the installed y-websocket provider using an in-process socket double.
They verify grant-before-sync ordering, reassignment after sync and repeated
grants. The production grant decoder rejects invalid values and trailing bytes.
Frontend: 35 tests pass; Svelte: zero errors/warnings. A socket double does not
prove the Go WebSocket transport, authentication or real browser reconnects.

## Cross-language compaction replay verification

From the Hash directory:

```sh
go test -race -v ./internal/collab -run '^TestCompactionRealYjsConcurrentUpdateReplay$' > /private/tmp/hash-real-yjs-compaction.log
cd frontend
bun scripts/verify-compaction-replay.ts /private/tmp/hash-real-yjs-compaction.log
```

The Go room processes real Yjs incremental update vectors, accepts a snapshot
from before the second edit, and emits its resulting SyncFrames. The verifier
feeds those frames into installed y-protocols/Yjs and requires text `first second`
and sync completion only on the final frame. Verified locally. This checks real
content replay across languages; it does not exercise network, DB durability,
authentication, multiple browsers or arbitrary snapshot semantic correctness.

## Shutdown allowance

The server allocates 10 seconds for HTTP draining and five separate seconds for
final collaboration persistence. Both development and production Compose give
the Hash HTTP container `stop_grace_period: 20s`, including five seconds of
scheduling margin. Compose configuration was verified locally. Any external
supervisor or explicit stop-timeout override must allow at least that interval;
this change does not verify deployed container configuration or persistence
success during a real shutdown. Failed final writes are reported as errors and
retained only in process memory for retry; they do not survive forced termination.

## Rendered frontend recovery fixtures

With the local frontend preview on loopback5179, from the Hash directory run:

```sh
bun frontend/scripts/verify-chat-recovery.ts
bun frontend/scripts/verify-editor-conflict.ts
```

These scripts reuse this monorepo's installed BrightCRM e2e Playwright and cached
Chromium. Set `HASH_PREVIEW_URL` for another local preview. All API responses are
synthetic fixtures: chat verifies retry/error/history/new-draft retention; editor
verifies exact observation submission, conflict text retention, actual recovery
JSON download and declining the unsaved-navigation dialog. The download goes to
`/private/tmp/hash-rendered-conflict-draft.json`. These tests were verified in
Chromium. They do not prove real authentication, REST persistence, SMTP delivery,
Yjs transport or multi-client canonical/CRDT reconciliation.

## Active room capacity

The singleton hub admits at most 64 rooms globally and 16 per organisation,
16 peers per room, 64 peers per organisation, and eight peers per user across
rooms. Admission is serialized with room creation and peer insertion; rejected
joins cannot create a room or replace an existing peer identity. Retained rooms
with failed final persistence continue to consume room capacity to bound
in-memory retention. Leaving releases peer capacity. Capacity failures close
upgraded sockets with code 1013 (retry later).

Race tests verify each capacity boundary, tenant isolation, release/reacquisition,
duplicate identity rejection, and concurrent same-user admission. These are
process-local limits, not capacity sizing evidence or shared replica quotas.
They apply at hub admission after WebSocket upgrade; a separate limit on pending
handshakes/requests has not been established. Canonical/CRDT replacement and
multi-client save reconciliation remain open requirements.

Pending setup is now separately bounded to 32 requests per HTTP server instance,
after identity/role/scope checks and before document lookup or socket upgrade.
Excess setup returns HTTP 429 with Retry-After. The lease covers lookup, upgrade,
join and initial replay; it is released on every exit or after initial sync,
with idempotent release. Initial grant and replay writes share a ten-second
context budget. This supersedes the preceding missing-pending-admission caveat.
It does not establish a whole-setup wall-clock bound (the hub mutex still has
bounded database work ahead of a join), tenant fairness for pending setup, or
real network cancellation acceptance. Tests verify the actual HTTP refusal
before nil database access and 128 simultaneous acquisitions admitting 32.

## Reproduced canonical replacement gap

Run `bun frontend/scripts/reproduce-canonical-replay.ts` from Hash. Optional
`HASH_REPLAY_EVIDENCE` writes the result to a local JSON receipt. Exit code 2
means the known stale-replay defect was reproduced, not acceptance success.
The installed Yjs/y-protocols replay and production bootstrap policy retain
`original contract` when the canonical replacement is `replacement contract`.
Receipt: `/private/tmp/hash-canonical-replay-gap.json`. No database or network
is involved in this protocol reproduction.

Source trace: REST block mutations/imports use `handler/blocks.go`;
full-document PATCH uses `handler/documents.go`; restore uses
`handler/versions.go`; MCP mutations/imports/restore use shared
`mcp/tools_authoring.go` and the versions engine. Their block writes do not
reconcile the separate `collab_doc_states` update log, whose current upsert is
unconditional. Reconnect loads that log and suppresses bootstrap correctly for
existing history, so canonical observation preconditions alone cannot fix this.

The implementation must cover the following as one contract:

1. Canonical replacement allocates a durable generation in the same document
   transaction. Persisted CRDT state and each live room are bound to it.
2. Old room updates and delayed flushes cannot overwrite a newer generation;
   comparison occurs at the database write boundary, including shutdown/retry.
3. Clients receiving a generation change preserve unsaved drafts, leave the old
   provider, and reconnect from the current canonical snapshot. A history delete
   alone is insufficient because a live room can flush the old log afterward.
4. Ordinary collaborative saves must carry generation and a durable save receipt
   so one client's acknowledgement does not cause another client's valid draft
   to fail silently or replace newer content. Server/client CRDT semantics must
   agree on what a canonical save represents.
5. Concurrent replacement/flush, REST/MCP/restore twins, fresh owner election,
   multiple writers, reconnect and intentionally empty history require real
   Yjs plus PostgreSQL/socket acceptance. Deploy paired server/editor versions.

This requirement remains unresolved. Do not ship a history-clearing workaround
or mark the document-change/collaboration requirement complete from this test.

## Durable generation foundation (migration 68)

`collab_document_generations` now records a positive generation per document.
Migration 68 backfills existing documents at generation 1; document creation
allocates generation 1; a committed change to `blocks_json` advances it in the
same transaction. Equal trees and non-content updates do not advance it, and
rollback undoes the increment. Concurrent canonical writers cannot lose an
increment. Down refuses to discard any advanced generation.

PostgreSQL acceptance used an isolated bounded tmpfs-only PostgreSQL 16 fixture:
backfill, new document, equal tree, transaction rollback, two concurrent changes,
and rollback refusal passed with race instrumentation. Receipt:
`/private/tmp/hash-collab-generation-migration.log`. The fixture was stopped and
auto-removed; no production database was changed.

This is a foundation, not the completed reconciliation fix. Existing CRDT logs
have no generation association yet; current room/flush/client code does not use
this ledger and stale replay remains reproducible. Next implementation must
associate stored history with a validated generation, fence conditional CRDT
writes under the document lock, and implement room/client transition and save
receipts. Treat migration/server/editor release as one unfinished candidate;
do not promote it as a stale-content fix. Legacy history needs explicit recovery
when its canonical association cannot be established.

## Generation-fenced persistence primitive (migration 69)

`hash_persist_collab_generation` locks the parent draft/blocks document first,
then reads its current generation in a fresh statement. It refuses a stale
expected generation or different tenant, checks state/count bounds and author
tenant, and atomically writes CRDT state plus `collab_state_generations`.
Legacy logs are not backfilled with guessed associations. Down refuses to drop
recorded associations. Generated queries expose current document generation,
state with nullable association, and conditional persistence acceptance.

Real PostgreSQL acceptance observes a flush waiting on a canonical replacement's
row lock, commits replacement, and requires refusal of the old generation.
It verifies preserved prior state, successful current-generation write, stale
retry refusal without altering the new state, tenant refusal, and generated Go
query lookups. Race-instrumented receipt:
`/private/tmp/hash-collab-generation-fence.log`. The exact bounded temporary
container was stopped and auto-removed.

**Runtime wiring remains pending:** the current room still calls the original
unconditional upsert. The new primitive is not an enforcement claim until that
path is retired and room/client transitions use the associated generation.
Do not deploy this intermediate candidate as the canonical replay fix. Next
wire room loading/persistence and frame checks, preserve recovery for unknown
legacy associations, then finish editor generation changes/save receipts.

## Persistence lock-order prerequisite

Room persistence now captures a snapshot under its mutex, releases that mutex
for database I/O, and serializes writes with a cancellable persistence gate.
The five-second persistence context includes gate admission. Snapshot receipts
clear dirty state only when no newer state revision exists; newer edits remain
dirty, and update-count acknowledgement respects compaction's count reset.
Final close reserves the room against new mutations until its write succeeds;
a failed write retains the open room for retry.

Race tests hold database completion, verify an edit can still take the room
mutex, and require the old receipt to retain that edit. A second case compacts
and edits during the write and verifies final bytes/counts; gate deadline and
recovery are verified. Existing failed-flush/shutdown tests and dependent handler
and server race suites pass. This removes the room-mutex/document-lock inversion
before generation-fenced persistence is wired. Runtime still uses the original
upsert; generation/client reconciliation remains incomplete.

## Runtime generation enforcement (current candidate)

This supersedes the pending runtime wiring statements above. Production
`generated.Queries` implements the generation store: rooms load the tenant's
canonical generation and require persisted history to have that exact recorded
association. Unknown legacy associations and mismatches refuse admission.
Persistence uses migration 69's conditional writer; refusal retains pending
state, marks the room stale, and rejects further edits and joins. Legacy upsert
support remains only for non-generation test adapters.

Initial synchronization and subsequent binary frames check the room generation
inside the same document/session authorization transaction, under the document
lock. Generation/recovery admission failures close with policy violation 1008;
capacity retains 1013. The adapter reads no extra database connection inside
that transaction.

Real PostgreSQL tests exercise the generated adapter: initial persistence,
associated reconnect, a canonical replacement, refused old-room flush, unchanged
persisted bytes/association, rejected stale join, and non-clean shutdown receipt.
The live role/draft frame authorization regression also passes. Receipt:
`/private/tmp/hash-collab-generation-adapter.log`; its exact temporary container
was stopped and auto-removed. Collab, handler and server race suites pass.
The database payloads test framing and persistence, not real Yjs convergence.

**Reconciliation is still incomplete.** Ordinary canonical autosaves also advance
the generation; without matching save receipts and client/server transitions,
a legitimate save makes its existing room stale. Retained stale rooms still
occupy capacity until explicit recovery. Legacy associations must not be guessed.
Finish generation-aware client recovery and save receipts, then verify real
multi-client WebSocket/browser convergence. Do not deploy this intermediate
candidate as a completed collaboration fix.

## Client generation identity

The server sends message 6 before initializer grant and initial sync, carrying
its generation as a lib0 decimal string. This preserves PostgreSQL bigint values
above JavaScript's safe integer limit. The editor records it across reconnects;
invalid, trailing, overflow or changed generations disconnect with a visible
recovery error while preserving local editor content. Tests cover full int64
precision, malformed payloads, same-generation reconnect and changed-generation
refusal, including the Go frame's wire layout. Go frame construction is tested.
Frontend suites pass (56 tests before the additional wire-vector case; the
four-case generation suite passes afterward); Svelte reports zero diagnostics.
Scoped collab/handler/server race checks pass using the default Go cache.

This adds generation identity, not canonical save acknowledgement. No normal
save transition, legacy association repair or real transport convergence is
claimed; those requirements remain open as described above.

## Exact update-record duplicate detection

The previous duplicate check compared an incoming framed update against any
byte suffix of the entire history. A shorter distinct record could therefore
match bytes inside the prior record's payload and be silently omitted from
persistence. Rooms now track the final complete record length and suppress only
an equal whole trailing record. Loading validates and records boundaries;
compaction maintains the tail record boundary or selects the replacement
snapshot boundary when there is no tail. This avoids scanning the full history
for every edit.

Regression fixtures reproduce the suffix collision both in a fresh room and
a loaded room, require both distinct records to remain, and still suppress exact
retransmission. Scoped collab/handler/server race suites pass. These are opaque
record-framing regressions; they do not establish semantic Yjs save convergence.
Canonical save receipts and generation transitions remain the next requirement.

## Exact save checkpoint primitive

A room can capture a detached replay snapshot with an opaque token binding its
random room lifetime, tenant/document, peer, canonical generation, state revision
and exact replay bytes. Another peer, reconstructed room, changed generation or
later update cannot reuse that checkpoint. A locked validation callback prevents
an edit from entering between validation and the canonical save transaction;
its caller must already hold the document database lock and use that same
transaction/connection. No hub/room lookup or separate pool connection is allowed
inside the callback. This follows the existing document-before-room lock order.

Regression tests refuse peer/state/generation/lifetime mismatches before callback
dispatch, reject departed peers/stale rooms, and prove detached snapshots cannot
mutate live history. Collab/handler/server race suites pass.

This is a room primitive, not a wired save endpoint. Next implement authenticated
checkpoint transport, atomically commit canonical blocks plus associated replay,
advance the room generation and notify all peers with the new canonical receipt.
Clients must serialize their save against that observed state and recover newer
local drafts on conflict. The primitive cannot certify semantic equivalence of
client blocks and opaque Yjs bytes. Ordinary autosave remains incomplete.

## Authenticated checkpoint delivery

Message 7 request consists of subtype 0 and exactly 16 correlation-nonce bytes.
The existing binary frame route performs live session, role, draft and generation
checks before capture. The room sends its captured replay through ordinary sync
frames, then a subtype 1 response containing the nonce, peer ID, decimal bigint
generation, decimal uint64 revision and fixed 32-byte checkpoint token. The token
still binds the captured replay even if subsequent edits arrive; save validation
must refuse it after state changes. Replay failure returns before receipt send.

The frontend codec preserves numeric precision, returns the token as lowercase
hex and rejects malformed identities, overflow and trailing/truncated payloads.
Server tests require replay before receipt and reject malformed requests without
sending frames. Codec tests and scoped Go race suites pass; Svelte has zero
diagnostics. These tests do not establish actual Go/browser WebSocket acceptance.

The editor has not yet registered the checkpoint response handler or submitted
its receipt to a coordinated save transaction. Next wire a bounded correlated
request, capture canonical blocks after checkpoint replay, validate the token
under document/room locks, atomically persist content/history and publish the
new generation/updated-at receipt. Ordinary save remains incomplete.

## Room advancement after canonical commit

`CommitSaveCheckpoint` validates the observed token under the room lock and
supplies its detached replay and pending-update count to a database callback.
The callback must hold the document lock first and atomically commit content,
associated replay and exactly the next generation before returning success.
Every save, including unchanged canonical blocks, must advance the generation
to fence older background writes. Only success advances the room, clears the
committed dirty/count state, invalidates old checkpoint tokens and cancels old
compaction requests. Failure leaves the room and its draft unchanged.

Background persistence captures its generation with the snapshot under the
mutex. A receipt for a superseded generation cannot mark the new room stale or
acknowledge subsequent edits. Tests hold an old writer, commit a checkpoint,
append another edit, then release a generation refusal; the room remains current
and the later edit remains dirty/pending. Rollback/success/token replay tests and
scoped collab/handler/server race suites pass.

This callback contract still requires production PostgreSQL transaction wiring,
including explicit generation advancement for equal canonical content. No HTTP
save handler or editor has switched to it yet. Real database and multi-client
acceptance of the complete save remains pending.

## Atomic canonical/history database save (migration 70)

`hash_save_canonical_collab` locks the tenant's draft block document, checks its
exact observed timestamp and generation plus author tenant, and writes canonical
content and the associated replay in one transaction. Changed trees advance once
through migration 68's trigger; equal trees explicitly advance once. Both cases
fence older flushes. History validation/association failure raises, rolling back
the canonical update rather than returning a partially successful refusal.
The generated `SaveCanonicalCollab` query exposes this transaction primitive.
Callers still must normalize/validate canonical blocks and recheck live role and
session; the SQL primitive is not a replacement for those authorization checks.

Race-instrumented real PostgreSQL 16 acceptance verifies explicit rollback,
equal-tree generation/timestamp advance, associated bytes, old-flush refusal,
stale-save refusal, exactly one changed-tree advance, invalid-history rollback
and tenant refusal. Command: `go test -tags e2e -race -p 1 ./internal/e2e -run
'^TestCanonicalCollabSaveAtomicGenerationE2E$' -count=1` with the temporary DB URL.
The exact bounded temporary container `85f2500424fc` was stopped and auto-removed.
Database and dependent package checks pass.

Runtime save-handler/editor wiring and all-peer receipts remain pending; this
primitive's database evidence does not establish complete collaboration readiness.

## Coordinated save API

`POST /api/v1/documents/{id}/collab/save` now consumes `peer_id`, lowercase hex
`checkpoint`, decimal `generation`, exact `expected_updated_at` and normalized
`blocks_json`. It requires the session user to own that live peer in the tenant's
room. It obtains the document lock before the room lock, rechecks the user's
current role/session generation under a user lock, and checks cookie expiry again
inside checkpoint validation. The transaction writes canonical content/history,
adds the audit event and commits before advancing the room. Failure rolls back;
checkpoint conflicts return 412 while preserving the room draft. Success returns
`document` and exact decimal next `generation`; audit publishes after commit.

Actual HTTP-route/PostgreSQL race acceptance verifies anonymous 401, successful
equal-tree save with timestamp/generation/history receipt, checkpoint replay 412,
and demoted user's copied-cookie 403 without history changes. Receipt:
`/private/tmp/hash-collab-save-handler.log`. The bounded temporary database
`0bc352775b20` was stopped and auto-removed. Peer/user/tenant unit checks and scoped
collab/handler/server race suites pass; API inventory regenerated and drift check
passes. Framing payloads are opaque fixtures, not semantic browser acceptance.

The editor still uses ordinary PATCH autosave. Register its bounded correlated
checkpoint flow, switch it to this API, and deliver canonical save receipts to
all connected peers before claiming ordinary saves preserve collaboration.
Legacy association recovery and full multi-client acceptance also remain open.

## Editor coordinated autosave and peer receipts

This supersedes prior statements that editor autosave still uses PATCH. It now
requests a checkpoint over its synchronized socket with one outstanding request,
random 16-byte nonce, five-second timeout and disconnect/disposal cancellation.
Unmatched/late receipts cannot complete another request. It serializes canonical
blocks after captured replay, submits the coordinated save API, and validates the
returned document and exact successor generation. New edits during the HTTP save
remain dirty. Disposal before checkpoint completion prevents HTTP dispatch.
A 412 currently preserves the draft and stops further automatic saves for review.

Successful server saves publish message 8 to every attached peer with exact
next generation and updated-at string. Editors acknowledge only newer receipt
generations, retaining timestamp microseconds and ignoring reordered older
receipts. Receipt handling never replaces editor content or clears local dirty
state. Older HTTP completion cannot regress a newer peer acknowledgement.
Same-origin BroadcastChannel replication is disabled so every edit crosses the
server's document/session authorization gate.

Frontend: 67 tests pass, covering nonce correlation, timeout/send/disconnect
failure, replay-before-serialization, edits in flight, disposal, malformed save
acknowledgement and reordered receipts; Svelte has zero diagnostics. Production
build passes (before the final disableBc option change, which uses the installed
provider's supported option). Go all-peer receipt and scoped race suites pass.
API inventory drift passes. These are local fixtures, not real browser/server
transport convergence. Previous rendered conflict fixture needs adaptation to
the new checkpoint transport before it can validate this candidate.

Remaining: full authenticated multi-browser checkpoint/save/receipt/reconnect
acceptance, bounded recovery for ordinary concurrent checkpoint conflicts,
external canonical replacements/import transitions and unknown legacy histories.
Do not claim full collaboration or Hash readiness from these checks.

## Real authenticated Go socket acceptance

`TestCollabTwoSocketCanonicalSaveAndReconnectE2E` starts the actual Go routes on
a loopback HTTP listener against PostgreSQL 16. Two cookie-authenticated WebSocket
clients receive generation/grant/sync ordering, relay real Yjs update vectors,
request checkpoint replay and save through the actual HTTP route. Both receive
committed save receipts; the second client then checkpoints and saves at the
advanced generation. Reconnect receives generation 3 and both retained updates.
The race-instrumented test passes; evidence `/private/tmp/hash-real-socket-save.log`.
The exact bounded temporary database `831e7f10f683` was stopped and auto-removed.

`bun frontend/scripts/verify-socket-save-replay.ts
/private/tmp/hash-real-socket-save.log` (from Hash) feeds the captured actual socket
checkpoint frames into installed Yjs/y-protocols and verifies `first second` with
sync completion only on the last frame. It passes. The vectors use a Y.Text named
`test`; they verify transported CRDT history, not semantic correspondence to the
editor's canonical block tree. The fixture's canonical tree is intentionally empty.
These are two Go socket clients sharing a synthetic owner session, not rendered
browser editors or real OIDC. Full rendered editor/canonical convergence,
ordinary concurrent checkpoint recovery and external/legacy reconciliation remain
required before readiness.

## Bounded concurrent-checkpoint recovery

This supersedes prior blanket-412 checkpoint refusal. A changed checkpoint returns
409; canonical timestamp/generation refusal still returns 412. The editor retries
409 with a newly captured checkpoint and newly serialized replayed content, at
most three attempts per save invocation. It never reuses a rejected token.
Exhaustion keeps the draft dirty and displays the error without disconnecting.
A 412 still preserves the draft and stops automatic saves for explicit review.

Production-function tests verify updated replay content/new token on retry,
successful recovery without disconnect, exactly three attempts on exhaustion,
visible retained draft, and existing external-observation recovery. Frontend
69 tests pass; Svelte zero diagnostics; scoped Go races/API inventory drift pass.
Real PostgreSQL/HTTP test verifies old checkpoint 409 versus fresh checkpoint
with stale canonical timestamp 412, alongside anonymous/demotion protection.
Receipt `/private/tmp/hash-checkpoint-conflict-handler.log`; temporary database
`805cf9427557` stopped and auto-removed. This tests conflict classification and
local retry behavior, not rendered two-browser contention acceptance.

## Rendered canonical/editor convergence acceptance

The opt-in `TestRenderedCollabCanonicalSaveAndReloadE2E` serves the freshly built
frontend over a temporary Go HTTPS listener with actual API/WebSocket routes,
PostgreSQL 16 and strict CSP. Bootstrap hashes use the same extracted production
`internal/frontend.InlineScriptCSP` helper; CSP was not weakened. Two independent
cached Chromium contexts receive synthetic HttpOnly/Secure/Lax owner cookies,
initialize one canonical paragraph, type sequential edits in each context, receive
live replication, finish coordinated autosaves and compare the canonical API
block tree against rendered content. Both reload, preserve one paragraph and
finish autosave again. Database checks require canonical text plus current
history association. Race-instrumented acceptance passes at generation 5 with
zero browser exceptions. Cursor decorations are excluded from content assertions.

Evidence: `/private/tmp/hash-rendered-collab.log`,
`/private/tmp/hash-browser-collaboration-receipt.json`, and visually inspected
`/private/tmp/hash-browser-collaboration.png`. Build receipt:
`/private/tmp/hash-browser-candidate-build.log`. Exact bounded PostgreSQL fixture
`a2179b233d8d` was stopped and auto-removed. Shared CSP/server/handler/collab package
checks also pass. Run from Hash after `cd frontend && bun run build`:
`HASH_BROWSER_E2E=1 HASH_E2E_DB_URL=<disposable-test-db> go test -tags e2e -race
-v -p 1 ./internal/handler -run '^TestRenderedCollabCanonicalSaveAndReloadE2E$'
-count=1`. Browser dependencies must already be installed/cached.

This supersedes the missing ordinary rendered canonical/save/reload evidence.
Scope remains synthetic shared owner sessions and sequential two-editor edits,
not actual OIDC, independent user roles, sustained contention/capacity, external
canonical replacement/import transitions or unknown legacy history recovery.
Those requirements remain open; this is not full Hash readiness.

## Distinct-user rendered RBAC and recovery

The rendered fixture now uses separate synthetic owner and sender identities and
checks their actual `/me` responses. Both collaborate/save/reload. The owner then
demotes the sender to viewer through the real members API. Subsequent sender edits
remain local: the canonical API content stays unchanged, the editor shows its
collaboration recovery warning, and the downloaded local draft includes the
rejected edit. Race acceptance passes with no browser exceptions and current
canonical/history generation 5. This supersedes the shared-owner-session caveat
for this fixture, while the sessions remain synthetic rather than real OIDC.

This uncovered a client recovery gap: browsers can conceal a failed-upgrade HTTP
status as close 1006. On connection loss the editor now rechecks current session,
tenant and role. Viewer/different-tenant or 401/403 stops reconnect and shows
recovery; current owner/sender and transient network/server errors retain reconnect
behavior. Only one access check may be in flight; late results cannot mutate a
disposed editor. Policy close 1008 remains immediately terminal. Production
callback tests cover these cases. Frontend 73 tests pass, Svelte zero diagnostics
and current production build passes. Actual rendered role/draft-download acceptance
passes under Go race instrumentation.

Evidence `/private/tmp/hash-rendered-rbac.log`, current browser receipt
`/private/tmp/hash-browser-collaboration-receipt.json`, recovered draft
`/private/tmp/hash-demoted-local-draft.json`, build
`/private/tmp/hash-rendered-rbac-build.log`. Temporary DB `9c905fa74354` was stopped
and auto-removed. Real OIDC, sustained contention/capacity, external canonical
replacement/import transitions and legacy association recovery remain incomplete.

## Loss-preserving recovery database primitive (migration 71)

External canonical replacements and unknown legacy associations cannot be fixed
by deleting history or guessing its generation. `RecoverCanonicalCollab` now
provides an explicit acknowledged owner-only transaction: lock the tenant's exact
observed draft, preserve persisted replay with its nullable original association,
preserve any distinct supplied active-room replay with its known generation,
advance the canonical generation/timestamp, and initialize empty history associated
with the new generation. Canonical blocks themselves remain unchanged. Recovery
archives retain original bytes and are bounded to 8 MiB each; parent hard deletion
cascades. Migration rollback refuses to discard retained archives. Oversized legacy
histories require separate recovery rather than truncation.

Actual PostgreSQL race test verifies rollback preserves unknown history, absence
of acknowledgement refuses, wrong tenant/non-owner refuse, both persisted and
active bytes survive, unknown association stays NULL, new state is empty/current,
old flush cannot revive history, rollback cannot discard archives and parent
hard deletion leaves no orphan. Receipt
`/private/tmp/hash-collab-recovery-archive.log`; temporary bounded database
`d41185a2fff1` was stopped/auto-removed. Generated queries and dependent database,
collab, handler and server checks pass.

This is not runtime recovery wiring. The caller must capture/retire the active
room under document-before-room locks, commit recovery plus audit before removing
it, notify all old peers to preserve local drafts, and permit fresh-room bootstrap.
Add owner recovery/export UI and explicit archive retention/privacy policy before
exposing it. Parent cascade alone does not prove complete retention/DSR handling.
External import/replacement and legacy recovery therefore remain unfinished.

Recovery room retirement follow-up (2026-10-05): CommitRecovery captures detached active replay under the document-before-room lock contract and retires only after the archive callback commits. Rollback retains pending edits, compaction and the running worker. Retirement keeps peers counted until transport teardown; closed rooms reject joins and old flush receipts cannot modify retired state. `go test -race ./internal/collab` passed. This primitive is not exposed as an owner recovery endpoint: bounded socket teardown, identity-safe hub removal, owner export/UI and archive retention/privacy handling remain required.
