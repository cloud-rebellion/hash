# Hash observability and Flare acceptance

Status: **source guidance; next-deploy acceptance UNPROVEN** (2026-10-20).

This guide defines useful monitoring for the next Hash deployment. It does not
record a deployment or certify existing telemetry. Consult the current
[completion status](COMPLETION-STATUS.md) for exact local application qualification;
that is separate from configured dependencies, browser acceptance, managed release
and Flare delivery. Historical completion recaps retain their own evidence and dates.

The original source/privacy audit baseline is dated 2026-10-19. The matrix below
now distinguishes the applied central source foundation from its remaining gaps:
runtime public browser configuration, direct credential-free ingestion, fixed
safe signals, explicit identity and process-bound telemetry lifecycle are present
in the selected source. This guide is not a local qualification receipt; exact
local results remain in [completion status](COMPLETION-STATUS.md) after the selected
checks are reconciled. No browser ingest relay or Stage change is added. A fixed
12-slot worker observation inventory and parent PDF attempt observations extend
the central foundation. Ten slots report invocation state; the original email
and finalizer slots retain their selected-row sample contract. A fixed safe native delivery-diagnostics projection, typed OIDC outcomes and
five-dependency observations are also implemented. Other domain producers, SDK
discard-report verification, durable backlog and configured acceptance remain
separate requirements; this does not implement every matrix row.

## Current transport operation

Errors and transactions use the supported asynchronous SDK HTTP transport with
an explicit queue setting of 30, a 3s HTTP timeout and redirect refusal. Capture
enqueues locally; network I/O stays on the background worker. This selects the
SDK batch-drain barrier instead of its default telemetry scheduler's reviewed
poll-to-enqueue flush window. A completed flush still does not prove the collector
accepted or stored an event, or that an alert was delivered.

Hash uses its own fixed-schema native log shipper. SDK log and metric producers
are disabled; adding metrics needs explicit safe producers and receiver/export
qualification. `SnapshotOperations` and `DeliveryDiagnostics` remain local APIs,
but the lifecycle also exports a fixed 15-scalar native-log projection from the
latter every two minutes, with service/release/environment/process epoch and
`sdk_delivery_accounted=false`. This is not an SDK queue-loss or metrics series.
A finite close can fail or leave buffered records undelivered; inspect its result
and reconcile loss with receiver records. Do not infer an SDK idle-worker join
from flush completion.

## What counts as monitored

For every required surface, preserve the exact deployed release, environment and
role, prove a useful signal is stored by the intended Flare project, and prove
that the relevant failure or silence reaches the authorized alert destination.
A DSN, source hook, successful enqueue, HTTP200, project card or process heartbeat
alone cannot establish this. A normal log row does not establish issue-rule
execution; an accepted trace does not establish an error or metric producer.

Record source, local qualification, exact CI, managed merge, deployment and live
acceptance separately. An open matrix row stays visibly open. Deployment and
broad monitoring acceptance are separate decisions; do not mark the Flare
cutover checkbox complete while its required evidence is missing.

## Private-free signal contract

Use closed operation, category, error-code and outcome values. Include fixed
service/role, full release, environment, HTTP method and route template/status
class where relevant, bounded counts/durations/queue age/saturation, and validated
content-free request/trace/span or canary correlation. Keep grouping keys low in
cardinality. Retain only safe static code locations, with no stack locals. Full
release and exact environment must survive receiver normalization on each pillar.

Never export contract/PDF/attachment content or filenames, negotiation or change
text, AI prompts or restored results, signatures, names, company details, emails,
addresses, IPs, user agents, mail/CRM/webhook/provider bodies, upstream diagnostic
strings, raw errors/panics/rejection objects, arbitrary log attributes, headers,
cookies, credentials, DSN keys, query/fragment data or bearer-bearing URLs. Sign,
completed, envelope, billing and QES handles need the same policy on every egress
surface. Hash's mandatory evidence report, audit preimages, hash-chain data and
private signing records remain in Hash; their existence permits a fixed outcome
signal, not their export. Recipient behavioral tracking stays disabled for the
first release; technical monitoring must not enable it indirectly.

Regex redaction is defense in depth. Fixed producer schemas must reject unsafe
values and bound strings, collections and encoded bytes before copying or
marshaling them. Do not invoke arbitrary custom marshalers/getters to produce
telemetry. Intentional HTTP aborts and expected user cancellation/refusals are
separate from internal failures. Preserve streaming interfaces, request latency,
authority, admission limits and the existing slog recursion guard.

## Remaining delivery and unfinished-work acceptance

The fixed diagnostic snapshot enters the existing native log queue directly and
bypasses ordinary info-level filters; `off` remains off. Ordinary info outcomes
can be filtered by both `HASH_LOG_LEVEL` and `FLARE_LOG_LEVEL`. Neither successful
enqueue nor HTTP/flush completion proves Flare persistence or alert delivery.
Keep the supported concrete SDK transport: wrapping `ClientOptions.Transport`
would disable its concrete-type discard-recorder setup. Receiver verification of
native SDK `client_report` discards remains a separate gate.

Selected email/finalizer samples do not measure durable unfinished-work queues.
Qualify safe cached pending/retrying mail and unfinished finalization counts and
ages, including leased/backoff and stranded/preparation states. Distinguish total
age from overdue age; do not use retry-reset `updated_at` as creation age. Bound
query cost, label truncation/lower bounds and expose stale/unavailable reads.
Do not add document, recipient or organization labels to Flare. The next deploy
must connect a stored runtime signal to an issue/rule and delivered alert, then
independently prove silence/collector-outage detection and recovery.

## Coverage matrix

All live acceptance in this table is **UNPROVEN**. Implemented means current
reviewed source, not a passed local check or receipt from a deployed process.
The HTTP/browser/MCP/CRM/transport cells reflect the applied central foundation.
The worker invocation inventory and parent PDF attempt observations extend it;
the remaining domain requirements stay open.
Qualify existing exports and implement the remaining producers before claiming
that coverage. The controlled package-browser run does not prove Flare ingestion.

| Surface | Implemented source and remaining gap | Required at the next deploy |
| --- | --- | --- |
| HTTP role `hash` | Fixed unsampled handled5xx/panic signals, actual route-template/status tracing, safe structured logs and process readiness/shutdown wiring are implemented. Expected aborts and ordinary refusals are distinct. This does not provide every domain-specific failure or external startup/absence monitoring. | Normal and controlled handled500/panic produce distinct fixed outcomes, stored release/environment/role and safe route/status. Prove one issue rule and delivered alert. External functional health must cover startup failure and abrupt absence. |
| Staff, signer and completed browser portals | Public runtime configuration, narrow matching CSP origin, fixed error/rejection/resource/render categories and bounded same-origin compiled-code frames are implemented. Direct keepalive fetch omits credentials; no raw error/object/resource URL is sent. Bounded early render/PDF errors can queue before valid config under the existing count/byte/time limits; config failure, pre-SPA failure and abrupt absence still need independent checks. | Running image loads the chosen runtime public configuration in all three portals, uses the exact validated collector origin under real CSP, and emits safe error/rejection/resource canaries. Independently verify stored events. External frontend checks cover config/startup failure. |
| MCP | Fixed internal, dependency, unavailable and serialization signals now cover the reviewed tool/JSON-RPC failure boundaries even when HTTP200 is returned; expected auth/argument refusals stay separate. This is central protocol coverage, not a claim that every tool/domain producer is instrumented. | Normal result and controlled internal/tool or serialization failure have distinct fixed operations/outcomes and stored correlation. Auth/argument refusals remain expected outcomes. Prove actionable internal failure alerting without exporting arguments or results. |
| Worker `hash-worker` and critical jobs | Fatal supervision, process heartbeat and post-invocation checkins/safe scalar logs cover the fixed inventory below, including a separate package-recovery observation within the Send loop. Ten additions carry state and duration only; email/finalizer retain selected-row samples. Global backlog, durable business-state completion, SDK loss accounting and configured job-silence rules remain open; the fixed native delivery-diagnostics projection is exported separately. | Separate server/worker identity; persist real normal/pending/error observations for every deployed enabled job, with the correct monitor suffix and state meaning. Prove relevant error and missing-job alert delivery and recovery from a resumed invocation. Independently qualify oldest unfinished age, retry and terminal-failure business outcomes. |
| Invitations, SMTP, reminders and negotiation notifications | Email dispatch reports selected/attempted counts, durable sent/retry/terminal acknowledgements, checkpoint failures, duration and sampled ages. Reminder invocation observations now surface fixed failure states, including failures returned by per-item helpers. Poll success and SMTP acceptance do not prove mailbox delivery; owner-notification domain outcomes and end-to-end delivery monitors remain open. | Safe queued/attempt/retry/terminal outcomes, backlog age and a delivered message to an authorized test mailbox. Complete invitation, owner-change notification and due-reminder canaries; distinguish SMTP acceptance from mailbox receipt. Alert on sustained failure/stale queue and prove recovery. |
| Signing, Send and package finalization | `finalize_retry` reports invocation, selected/attempted/returned/failed counts, duration and sampled ages. Send sealing and package recovery separately report fixed invocation states after their existing synchronous work and deferred cleanup return. A nil attempt return or `returned` state is not a completed PDF/report; `pending` explicitly permits nonterminal work. End-to-end durable Send/signing/finalization state monitors and exported phase metrics remain open. | Observe send/sealing/finalizing/completed/refused outcomes, attempt duration and oldest unfinished age. Complete real main+attachments review/revision/resend/sign with final PDF and mandatory report/download. Recover a controlled retry without duplicate effects. |
| Evidence/report/export | Hash verifies signed metadata, preimages and protected artifacts. This is product evidence, not Flare instrumentation. | Emit only report readiness/verification/export outcome and duration; alert on stuck or failed generation/verification. Check actual artifacts in Hash. Keep their bytes, event payloads, IDs and certificate material out of Flare. |
| PDF parser child and Gotenberg | Parent-only typed attempt observation runs after the existing runner returns/cleanup defers. It reports safe duration and fixed outcomes through the existing `pdf` operation path; unavailable merges startup/crash/protocol and rejected merges invalid input/capacity. Full subtype/capacity/success series, outer consumer retirement, renderer operations and exported aggregates remain open. | Verify actual child/process cleanup separately from telemetry. Error outcomes reach the safe SDK/error log path; the default warn log floor filters nonerror info outcomes. Qualify any chosen info export and capacity series, plus renderer availability/latency independently. Keep the child free of Flare dependencies/configuration/credentials and preserve its network isolation and raw-stderr boundary. |
| Import/malware scanner | Fail-closed gate and health probes exist; no accepted operational outcome/freshness series is established. | Controlled safe scanner rejection and scanner-unavailable cases remain fail-closed and observable. Record scan duration/outcome and scanner availability/definition freshness where supported; prove an unavailable/stale alert and recovery. Never upload actual malware for this check. |
| CRM connector | The actual transport now reports fixed outcome/duration after response-body close; credential/not-found/rate/cancel refusals stay expected and private upstream data is excluded. Higher-level record semantics, binding freshness, lag and callbacks are not covered by that transport observer; accepted exported series remain unproven. | Configured authenticated fetch returns correct authorized CRM data and binding freshness; callback/retry succeeds once. Record fixed operation/status/duration and lag, not CRM bodies. Prove upstream failure and recovered connector alerting. |
| Reactor and webhooks | Durable outbound retry surfaces exist; Hash acceptance does not prove downstream workflow completion or adapter compatibility. | Follow a real configured test workflow through authenticated delivery, downstream completion/callback and retry/idempotency. Record each service's own safe outcome and correlation. Prove stale/failing callback alert and recovery without payload/signature export. |
| Authentication, RBAC and rate limits | Canonical denials/statuses and shared access traces exist; no configured-provider journey or aggregate outcome/saturation acceptance is established. | Test real OIDC/OAuth/magic-link dependency and expected scope/role/expiry/rate refusals. Aggregate outcomes without identities or tokens; page on system/dependency failure, not every expected403/409/429. Verify isolation and recovery separately. |
| Object storage and recovery | Health pings and protected artifact controls exist; operation latency/failure and recovery-age alert proof are absent. | Safe exact-operation outcomes/durations, unavailable/recovery and configured backup/restore freshness checks. A health200 is not Object Lock, exact-version retrieval, paired restore or key-continuity acceptance; keep those cutover gates separate. |
| Database and native admission | Health ping and bounded native resource ownership exist. No accepted DB/native-session saturation or wait/error series is established. | Observe bounded pool/native session use, waiting/denial/timeout, query-operation latency and recovery, without SQL/args/rows. Exercise a bounded dedicated saturation canary under existing limits. Host/container/DB capacity and backup signals need explicit collectors/checks. |
| Telemetry transport itself | Fixed bounded log projection, queue/rate limits, response-status accounting and finite joined shutdown are implemented. `DeliveryDiagnostics` and `SnapshotOperations` expose local APIs; the former also has a fixed safe native-log projection, including `CheckinResponses` after bounded body read, close and 2xx. That response handling does not prove storage or alert delivery. SDK discard-report ingestion, durable backlog and accepted metrics/admin/alert series remain open. Browser no-cors response remains opaque. | Export and monitor the safe diagnostics with independent receiver/collector health. Reconcile actual completed Flare receipts and stored records, local drops/failures/rejections and shutdown results so collector loss cannot hide itself. |

## Applied worker and PDF observations

The worker inventory has 12 fixed observation slots. There are ten additional
state-only slots alongside the original `email_dispatch` and `finalize_retry`
selected-sample slots. This is an observation inventory, not 12 independent
scheduler goroutines: package recovery runs serially after sealing within the
existing Send loop, and compliance runs only when its feed and flagger are
configured.

| Job observation | Monitor suffix | Source ticker period | Observation kind |
| --- | --- | --- | --- |
| `email_dispatch` | `mail` | 1 second | Selected sample, at most 50 rows per invocation |
| `finalize_retry` | `finalize` | 2 minutes | Selected sample, at most 50 rows per invocation |
| `reminders` | `remind` | 1 hour | Invocation state and duration |
| `expirations` | `expire` | 1 hour | Invocation state and duration |
| `webhook_redrive` | `webhook` | 30 seconds | Invocation state and duration |
| `telemetry_rollup` | `rollup` | 1 hour | Invocation state and duration |
| `quota_warnings` | `quota` | 6 hours | Invocation state and duration |
| `soft_delete_purge` | `purge` | 6 hours | Invocation state and duration |
| `collab_archive_purge` | `archive` | 1 hour | Invocation state and duration |
| `send_sealing` | `seal` | 5 seconds | Invocation state and duration |
| `package_send_recovery` | `package` | Same 5-second Send loop, after sealing returns | Invocation state and duration |
| `compliance_rollup` | `comply` | 24 hours, when configured | Invocation state and duration |

These suffixes follow the configured monitor prefix and `hash-worker` role.
Ticker periods are source scheduling inputs, not invocation deadlines, completion
SLAs or safe monitor grace defaults. Work within each loop remains synchronous;
a long invocation can delay the next tick, including package recovery after
sealing. Inventory the actual deployed loops and record each enabled observation's
last completion, monitor interval/grace and recovery semantics from its real
workload and contract. Disabled optional compliance is recorded as disabled,
without a fake healthy tick. A required loop that cannot start is an unavailable
worker condition, not a successful no-work poll. Preserve all existing task,
SQL, process and memory limits.

Every slot reuses the existing process-owned Lifecycle sender and its fixed
queue of 16 scalar reports. Normal reports aggregate over 30 seconds as real
ticks arrive; actual problem/recovery transitions are reported promptly subject
to the existing queue, rate and transport bounds. No periodic timer invents a
completed invocation. Reporting occurs only after the original synchronous helper
returns, including its deferred cleanup. Cancellation and panic do not create a
healthy completion. No new SQL, task concurrency or sender goroutine is introduced.

The ten additions use the following closed vocabulary. Each job maps only the
states its existing helper can observe; these are invocation facts, not proof of
mailbox delivery, artifact finality, legal effect or physical owner retirement.

| Invocation state | Checkin status | Meaning and limit |
| --- | --- | --- |
| `returned` | `ok` | Helper returned without an observed failure; this can include an empty poll or an already terminal historical item. It does not establish that a new business operation completed. |
| `pending` | `ok` | Helper returned with observed active work still nonterminal. Configure separate stuck-work checks; a healthy invocation cannot clear unfinished business work. |
| `partial` | `error` | An existing per-item operation or durable checkpoint reported a failure. Successful sibling items do not hide it. |
| `unavailable` | `error` | Required engine/runtime, discovery or dependency work was unavailable, or the observed invocation reached its existing cancellation/deadline boundary. |
| `unobservable` | `error` | A missing or unsupported fixed observation prevents a reliable invocation outcome. This must not become fabricated healthy state. |

The fixed logs identify `observation_kind` as `invocation` or `selected_sample`.
State-only rows carry no selected/attempted/returned/failed row counts, queue age
or throughput; their zero-valued row fields are reserved schema values, not proof
of empty queues. Aggregation retains the worst observed fixed state in its window
and the real last-invocation timestamp. Job logs bypass the generic warn floor
while retaining the existing native shipper bounds. An error checkin or log is
not evidence that Flare created an issue, evaluated a rule or delivered an alert;
prove the configured path separately. `pending` requires its own durable-state
and age checks even when its checkin is `ok`.

Only `email_dispatch` and `finalize_retry` select at most 50 existing rows per
invocation under this telemetry sample contract. The exported oldest selected
age and batch-limit flag cannot establish oldest global pending age, total queue
size or unique work throughput. Repeated selection can count a row again. Age
policies are explicit optional deployment inputs:
`HASH_FLARE_EMAIL_SAMPLE_MAX_AGE_SECONDS` and
`HASH_FLARE_FINALIZE_SAMPLE_MAX_AGE_SECONDS`; unset or zero disables that sampled
age policy. Choose and record thresholds from the actual job/mail/finalization
contract. Invalid settings or unknown ages under an enabled policy are visible
errors, not fabricated zero-age health. There is no invented default SLA. The
other jobs keep their original batch/scoping behavior and do not inherit a
50-row execution limit.

Read, close, non-2xx and cancellation failures remain failures in checkin response
accounting. A receiver arrival or completed HTTP response is not persisted Flare
evidence. Mail checkins describe invocation health separately from an SMTP issue:
an empty healthy poll cannot resolve a prior delivery failure. Global backlog,
durable domain-state/phase metrics and native SDK discard-report accounting remain
explicit gaps. The fixed native queue/drop/rejection/response diagnostic projection
is exported through the existing log queue; `SnapshotOperations` stays local.
Neither is an accepted metrics series or an independent collector health monitor.
Require persisted signals, actionable alerts and silence/recovery
proof for the actual deployed release before marking the worker covered.

The PDF observer is installed once by trusted server/worker boot code. Only a
closed typed operation/outcome and elapsed duration cross the parent callback;
probe traffic is excluded. It observes the runner's return boundary, which can
also be a preflight rejection with no child. It does not attest outer native
consumer retirement, saved PDF/report durability or recovery. The adapter groups
supported PDF suboperations under the existing safe `pdf` operation. Timeout,
unavailable and internal outcomes emit issues/error logs; expected refusal and
cancellation remain separate. Nonerror info logs require an explicitly qualified
log-level/export choice. Do not equate local operation snapshots with an exported
metrics or capacity series. The isolated PDF child has no Flare/Sentry module
record in the qualified binary; runtime isolation requires its own evidence.

## Local qualification before promotion

The implementation owner must first qualify the selected code with a local,
private-free receiver and browser tests. These tests do not deliver alerts or
establish the current configuration of Flare.

- Encode synthetic private markers through panic/error objects, nested log maps,
  exported error fields, custom marshalers, browser Error/string/object rejection,
  URL/stack/resource and Unicode/oversize cases. Assert markers never leave Hash
  on any enabled egress; fixed category and safe code location remain useful.
- Verify all bearer routes, encoded token paths, query/fragment and completed
  links are omitted, including traces and logs. Never use real customer material.
- Prove fixed identity and safe HTTP500/panic/MCP classifications; intentional
  aborts and ordinary4xx/conflict/rate/cancel outcomes must not become noisy pages.
  Check panic deduplication and writer streaming interfaces.
- With only a local fake receiver, exercise queue/rate/byte saturation, rejected
  4xx/5xx responses, bounded response drain, unreachable transport, browser
  synchronous fetch throw/rejection and graceful close. Require bounded completion,
  visible local drop/failure counters and no recursive self-reporting or retry
  storm. Do not create an outage at the shared collector to test local loss.
- Prove no healthy-ready signal before actual listener/dependency/worker readiness;
  cancel, join and finitely flush telemetry on graceful shutdown. An abrupt crash
  still requires an independent external silence monitor.

Inspect the applied instrumentation and its actual validation receipts before
recording a new accepted state in this guide. Do not infer broad domain spans/metrics/checkins from a central error
wrapper. Trace sampling remains explicit and independent of critical errors.
Sentry transactions can populate spans; setting an OTLP endpoint alone does not
initialize an exporter, and adding OTLP is unnecessary merely to use supported
native metrics/checkins.

## Next-deploy acceptance procedure

1. **Bind the actual deployment.** Record UTC window, approved source/full release,
   server and worker image digests, frontend artifact/runtime identity, renderer
   image, runtime environment, ingress, intended Flare org/project and deployed
   receiver release/schema. Verify private DSN endpoint/project/auth in place
   without printing values. Do not inherit a runner's project key. Production
   env-file wiring and local/staging worker wiring differ; check each real role.
2. **Check runtime public browser configuration.** Expose only the validated
   ingest-public DSN, enabled state, full release and environment. Never echo the
   raw server DSN/password, private member key or arbitrary environment. Require
   a fixed no-store schema and a narrow configured HTTPS collector origin for
   production CSP. Send directly with a text/plain keepalive fetch using
   `mode: 'no-cors'` and `credentials: 'omit'`, without an Authorization header.
   Validate real proxy/CSP behavior in staff, signer and completed portals.
   No new Hash relay or Stage build edit is part
   of this design. A deliberately public ingest key is still omitted from notes.
   Bounded early render/PDF failures can queue before valid runtime configuration
   under the existing count/byte/time limits. Config failure, pre-SPA failures and
   abrupt absence still require an independent functional browser probe.
3. **Run private-free canaries.** Use dedicated test identities/documents and
   content-free correlation. Trigger errors only through reviewed test seams or
   an isolated canary workload, never a new public fault-injection endpoint.
   Exercise each required matrix outcome and its normal/recovered counterpart.
   Keep real contracts and signing evidence in Hash. Do not stop unrelated
   services or disturb customer work to obtain a failure signal.
4. **Reconcile ingestion and storage.** For events/logs/spans/metrics, read
   authenticated org+project-scoped Flare ingest receipts for the exact UTC
   window (the reviewed API exposes `/api/projects/{id}/ingest-receipts`). Require
   `completed_at`, positive `accepted_count` and `persisted_count`, and reconcile
   received/accepted/persisted/rejected/dropped counts, rejection reasons,
   outcome/status and retryability. Fetch the actual corresponding stored signal;
   show the same full release, environment, role and canary/trace correlation.
   A receipt's request ID is not assumed to be the producer event ID: use actual
   receiver-supported association/window and the unique safe canary. Checkins
   may use monitor history rather than ingest receipts; verify the actual scoped
   monitor state/history and receiver evidence instead of inventing a receipt.
5. **Prove actionable alerting.** Select a real project issue rule, supported
   new/regression/spike behavior and authorized routed channel. Demonstrate
   accepted actionable error → durable issue → rule evaluation → successful
   destination delivery → operator/receiver acknowledgment. Record IDs/times,
   then resolution/regression and recovery as applicable. A native log row alone
   does not page. Verify any proposed metric-threshold alert is actually
   supported/configured before relying on it; use an explicit check where needed.
6. **Prove freshness, silence and recovery.** Separately configure server and
   worker role absence, critical-job missing/error, functional availability and
   backlog/dependency checks with explicit positive interval/grace. Stop or pause
   only the dedicated canary. Require the missing/stale alert, destination
   delivery and actual recovered state after a resumed role/job completion.
   A process heartbeat cannot clear an unfinished business operation.
7. **Review loss, privacy and readiness.** Inspect local sender diagnostics and
   scoped rejected/dropped receipts; explain every expected refusal and any
   loss. Verify bounded queues/resources and shutdown after actual joins. Inspect
   encoded canary records for private markers, full URLs and unwanted fields.
   Unexplained partial/retryable intake, missing correlation or missing alert
   delivery keeps acceptance open. Save evidence and update the current Mesh
   checkpoint only after actual results; retain earlier failed receipts.

For external mail/CRM/Reactor/provider availability, distinguish configured
integration acceptance from local synthetic peers. Verify the intended release
uses the canonical collector endpoint without publishing keys; an old alias or
source configuration alone is not migration acceptance. Third-party/host/backup
coverage needs explicit collectors or probes and its own receipt/history evidence.

## Evidence to retain

Keep a concise private-free ledger per matrix row. At this guide's creation every
row has status **UNPROVEN**; do not prefill successful IDs or mark a configured
check as passed.

| Evidence field | Required record |
| --- | --- |
| Deployment identity | Exact full source/release, role/service, environment, image/artifact digest, UTC window, intended project and receiver release/schema |
| Source and local proof | Applied instrumentation paths, exact validation receipt, covered signal/outcome and remaining gaps |
| Ingest and stored signal | Completed receipt ID/pillar/protocol/counts/status or actual checkin history; stored event/log/span/metric ID and safe correlation |
| Alert | Rule/monitor and evaluation ID, finite interval/grace, destination identifier without address/secret, actual delivery receipt and acknowledgment |
| Recovery | Real successful operation/tick, recovered monitor/issue state, timestamp and duplicate-effect check |
| Privacy and loss | Encoded synthetic marker check; local queue/drop/transport result; reconciled receiver rejections/drops; no raw payloads or keys |
| Verdict | Accepted for this surface/release, or OPEN with exact missing signal/evidence and next action |

Store restricted evidence in the approved release evidence location; put only
safe references and outcomes in Mesh. This runbook changes no existing legal,
security, restore, capacity, managed-release or application readiness gate.

## Source references

Original audit and current foundation: `internal/flarereport/{config,signals,operations,flarereport,logship,tracing,heartbeat}.go`,
`internal/handler/{flare_config,server,panic_middleware}.go`, `internal/mcp/mcp.go`,
`frontend/src/lib/flare-client.ts`, `frontend/src/routes/+layout.svelte`,
`cmd/{server,worker}/main.go`,
`internal/flarereport/{jobs,job_invocation385,pdf_worker_v1}.go`,
`cmd/worker/{job_invocation385,package_send_recovery_v1,finalize_retry,telemetry_rollup,quota_warnings,operator_quota_warnings,soft_delete_purge,collab_archive_purge,compliance_rollup}.go`,
`internal/telemetry/rollup.go`, `internal/sanitize/pdf_worker.go`,
`internal/crmconnection/client.go`, `internal/dispatch/webhook.go`,
`internal/malwarescan/gate.go`, `docker-compose{,.prod}.yml`.

The baseline source/privacy audit is dated 2026-10-19, with Mesh estate and
signal-scope guidance read at authoring. Those inputs are source or historical
knowledge, not a fresh live Hash audit. The broad acceptance above
also applies to any later instrumentation revision; qualify its actual bytes and
configuration before recording a new accepted state.
