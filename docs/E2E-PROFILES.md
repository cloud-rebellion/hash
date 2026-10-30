# Disposable integration profiles

Run `sh scripts/test-e2e-profiles.sh` from a Linux environment with the source's
Go toolchain and caller-owned PostgreSQL 16.15, S3-compatible storage and Gotenberg.
The native measurement protocol currently supports PostgreSQL `160015`; preflight
checks the live server version as well as the supplied database identity.
The runner builds the real isolated PDF worker before starting timed tests.
Its two temporary binaries and package lists live in one `TMPDIR` child and are
removed on exit. It preserves the normal Go build and module caches.

Each profile writes its package inventory, native `go test -json` stream/stderr,
structured summary and pending skipped-test IDs. These files follow the caller's
scratch/container retention policy; a CI owner may remove the whole workspace
when the run ends. Their creation does not establish durable retention. By default
they live in a fresh directory under the caller's original `TMPDIR`. Alternatively
set `HASH_E2E_EVIDENCE_DIR` to a fresh absolute directory outside the checkout
and assign its owner, size budget and retention before running. The runner never
copies a runtime tree. Event streams contain ordinary test diagnostics and must
remain private. The summary also prints bounded, redacted failure diagnostics
to stdout so the native CI journal can preserve useful failures after workspace
cleanup. It includes failed-test source assertion tails, package panic headers
and tails, and at most 128 unfinished-test IDs when a timeout/panic or truncated
stream prevents terminal test events. Malformed/incomplete accounting still fails;
observed counts and diagnostics do not turn it into a passing result.

Diagnostic context is limited to 24 records and 16 KiB of identity/state/text bytes
including at most 4 KiB of unfinished-test IDs, with 2 panic-header rows and 6 tail
rows per record, each at most 256 UTF-8 bytes.
Test tails prioritize the last 4 source assertion rows over verbose logs. Collection
is bounded to 160 streams and 1024 running test IDs; truncation is explicit. These
limits apply to diagnostic context, not the authoritative pass/failure counts or
existing identity lists. Diagnostic redaction removes URL userinfo/query values,
authentication tokens and credential-shaped header/JSON/key-value lines plus
multiline continuations. Reported source IDs receive the same redaction after
accounting/skip classification. Unlabelled arbitrary sensitive strings cannot be
identified reliably; keep fixtures synthetic and never deliberately log secrets.
Passing-test output is not published in diagnostic summaries.

The caller creates, verifies and ultimately retires the disposable services.
Supply three **fresh, distinct** databases; none may contain public relations.
The PostgreSQL identity must have database-creation authority because several
fixtures create and drop uniquely named child databases. Never point this runner
at an application, production, retained or shared developer database.

| Input | Required value or purpose |
| --- | --- |
| `HASH_E2E_DB_URL` | Fresh ordinary integration database and administrative parent for isolated child fixtures. |
| `HASH_E2E_BACKLOG_DB_URL` | Fresh database named `hash_backlog_<unique suffix>`, using `127.0.0.1`, `localhost` or `::1`. All connection fallbacks must also be loopback. |
| `HASH_E2E_RECIPIENT_LOCK_DB_URL` | Fresh database named `hash_recipient_lock_<unique suffix>`, with the same loopback rule. The runner applies normal embedded migrations only after all preflight checks pass. |
| `HASH_E2E_OWNED_PG`, `HASH_E2E_BACKLOG_OWNED_PG`, `HASH_E2E_RECIPIENT_LOCK_OWNED_PG`, `HASH_E2E_ORIGINALS_OWNED_PG` | Explicit caller acknowledgements, each `1`, after establishing disposable ownership. Names and acknowledgements alone do not establish ownership. |
| `HASH_E2E_EXPECT_MIGRATIONS_SHA256` | Caller-pinned full current migration-tree SHA-256. The helper compares it with both compiled migrations and current files, requiring contiguous versions. |
| `HASH_E2E_S3_ENDPOINT`, `HASH_E2E_S3_ACCESS_KEY`, `HASH_E2E_S3_SECRET_KEY` | Existing disposable storage service settings. Preserve the normal SSE/Object Lock configuration. The usual ephemeral fixture also supplies `HASH_E2E_S3_EPHEMERAL_BUCKET=true`. |
| `HASH_E2E_GOTENBERG_URL`, `HASH_E2E_RENDERER_URL` | Existing confined renderer's origin, also supplied to ordinary branded-page fixtures. |

Migration hashing uses SQL filenames sorted lexically, each followed by NUL,
its exact bytes and another NUL. Pin this digest from the reviewed source before
execution; the runner verifies the pin and does not authorize a new one.
Connection strings and underlying connection errors are never printed by the
preflight helper. Other test diagnostics retain their existing behavior.

For containerized callers, sharing the PostgreSQL container's network namespace
allows true loopback connections without publishing database ports. Keep that
namespace on the private test network so the ordinary tests can still reach
storage and the renderer. The owner must retain container/database provenance
and clean up the exact services it created, including child fixtures left after
an interrupted run. This script never deletes caller-owned databases or services.

The package inventory comes from `go list -tags=e2e ./...`. Its partition is:

| Profile | Whole packages run exactly once |
| --- | --- |
| Ordinary | Every package except the four below; existing service environment is preserved. |
| Backlog | `cmd/worker` against the owned backlog database. Its temporary-relation tests need no schema; other worker fixtures create isolated migrated child databases. |
| Recipient lock | `internal/db` against the normally migrated recipient-lock database, with the exact migration pin passed to its existing guard. |
| Original capture | `internal/fitprepare`, using the owned administrative parent and original-capture acknowledgement. |
| Fit selection | `internal/fitselect`, using the owned administrative parent and migration pin. |

Every invocation uses `-json -tags=e2e -count=1 -timeout=180s` and bounds package
and independent test-case parallelism with `-p=2 -parallel=2`. This limits concurrent
fresh-database and checkpoint work; each test still runs its own explicit concurrency
and lock interleavings. No test-name filter, timeout increase or ownership-guard
override is applied. A failed profile does
not suppress the remaining profiles; the combined result fails. Missing service
configuration, ownership, source identity or database preconditions fails before
the first migration or test. Test-level assertions still decide schema and
behavior compatibility; a stale fixture pin remains a failure requiring repair.
The JSON audit also verifies that each expected package has exactly one terminal
event. Its retained, same-tag `go list` inventory distinguishes packages without
test files: those may report a package-level skip as compiled/no-tests. Packages
with test files must emit test terminal events and may not skip as a package.

Only the exact 36 test IDs in
[`scripts/e2eprofile/optional_skips.go`](../scripts/e2eprofile/optional_skips.go)
may skip: 22 externally controlled browser tests, four owned provider/real-stack
tests, nine fitted-output journal cases and one first-install test. Their declared
owner flags must be **unset** in this runner. These tests remain pending with the
explicit state `separate profile not run`; they never increase passed-test counts.
Their separate owners must provide qualification evidence before claiming that
coverage. Fitted-output's historical migration pin remains a separate unresolved
qualification requirement. No readiness claim follows from an allowed skip.
Native passing parent tests with skipped child cases are also reported pending
and excluded from passed-test counts.

Any uncatalogued test skip fails the run even if native Go exits zero. This
includes ordinary database/worker, Send/signature and Object Lock tests. New or
renamed optional tests require an explicit catalog review; names are never
auto-allowed from observed events, prefixes or skip messages.

External browser handoff tests remain an explicit, separate qualification with
their own browser, HTTPS origin, fresh paths and controller. This runner does
not enable `HASH_BROWSER_E2E`, and rejects it when enabled. It makes no browser
acceptance claim and does not globally reinterpret optional test skips. The
separate live Playwright suite in `e2e/` must also run against the built runtime
when a release requires browser acceptance.
