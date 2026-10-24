# Process work admission configuration

Each server or worker process may construct one opaque work runtime from its actual application PostgreSQL pool. The runtime creates one shared coordinator, fixed cost adapter and native session factory. The HTTP HTML creator and signing journal use that same factory; the engine installs one persistent private journal at startup. Repeated initializer calls return that same journal, while a closed engine cannot create a replacement. The journal does not create an independent budget or observer registry.

All values are explicit operator allocations. They are admission ceilings, not measured spare memory, RSS bounds, spare database connections, durable storage quotas, renderer/provider authority, READY, or controller/retirement evidence. Qualify aggregate process and child allocations against actual deployment measurements and account for every other server, worker and service before use. Assign server and worker allocations separately.

If none of the following 17 environment keys is present, configuration remains absent. Existing startup, authentication and health behavior is preserved. No coordinator or factory is manufactured. Fresh HTML creation reaches the existing HTTP 503 response, `HTML document creation is temporarily unavailable`, when its writer needs the missing factory. The fitted-request journal refuses a missing runtime. Configuring these resource ceilings alone does not activate fitted signing; its genuine readiness, controller, ownership and immutable request gates remain required. A health response is not proof that those gated journeys are available.

If any key is present, all 17 must be explicitly set. Empty, negative, malformed, overflowing, out-of-range or inconsistent values are a startup configuration error; partial configuration does not silently disable admission. Zero explicitly disables a vector dimension. The global SQL session allocation must be positive so a configured native factory has a declared direct-session ceiling. Both grant limits and the total DB allocation must be positive.

| Environment key prefix | Required vector suffixes | Bounds |
| --- | --- | --- |
| `HASH_WORK_GLOBAL_` | `PARENT_BYTES`, `DB_STAGING_BYTES`, `CHILD_ADDRESS_BYTES` | 0 through 2^40 bytes each |
| `HASH_WORK_GLOBAL_` | `PDF_WORKERS`, `SQL_SESSIONS`, `PROVIDER_STREAMS`, `RENDERER_REQUESTS` | 0 through 2^16 operations each; SQL must be positive |
| `HASH_WORK_ORG_` | Same seven suffixes | Same bounds; each dimension cannot exceed its global allocation |

The remaining keys are `HASH_WORK_MAX_GRANTS` (1 through 2^16), `HASH_WORK_MAX_ORG_GRANTS` (1 through the global grant limit), and `HASH_WORK_DB_CONNECTION_ALLOCATION` (a positive signed 64-bit integer).

The runtime uses the actual pool's maximum and effective connection configuration. Its existing pool maximum plus the global direct SQL-session limit must fit the assigned total DB connection allocation. Direct sessions include observers. Validation uses subtraction before addition to avoid overflow. Pool capacity covers existing application borrowers, including the server singleton lease; the direct limit does not reserve imaginary pool headroom. The fixed native factory preserves its connection-profile refusal and does not replace unsupported callbacks, fallback routes or TLS behavior with an injected connector.

During normal server shutdown, HTTP and collaboration shutdown run first. The engine then receives a fresh bounded five-second local journal cleanup context. The runtime receives its own fresh bounded five-second factory cleanup context before the pool is closed. Journal close drains only its retained owners and never closes the shared authoring/process factory. Unknown cleanup retains the original journal and owners for fresh-context cleanup; it cannot create a replacement operation or journal. The worker cancels its existing loops and attempts the same bounded owned cleanup; loop cancellation by itself does not prove those loops joined or that the whole process retired. Abnormal supervisor process exit remains a separate disposition.

Consumer closure, cancellation and logical commit never authorize a resource refund. Actual session/client retirement, retained consumers and admission registry closure retain their existing conjunction. The final observer can be physically gone yet remain charged after public factory Close because that factory cannot prove its own final observer retirement. The real PG qualifier observed exactly one retained final observer grant and an independently absent backend. Genuine whole-process/controller retirement remains a production gate; this runtime does not reset or credit that debt or claim a zero final coordinator.

No deployment capacity values are supplied by this change. Operator measurement, production lifecycle acceptance, bounded authoring readers and the remaining fitted signing gates must be completed separately.

## Running the synthetic browser stack

The browser CI job includes `docker-compose.browser-e2e.yml` after the base and
local-MinIO files. This supplies the existing real-render/browser fixture profile
explicitly to both server and worker. It caps each application pool at 8 and each
process's total database allocation at 16, so the two processes together have a
32-connection ceiling. The PostgreSQL instance must accommodate that aggregate
and its other clients.

For the same controlled local test stack, include the same overlay:

```sh
docker compose -f docker-compose.yml -f docker-compose.local-minio.yml \
  -f docker-compose.browser-e2e.yml up -d --build
```

This is a synthetic integration-test allocation, not a production deployment
profile. Production and other workloads still require their own explicit values.
After seeding its disposable identity, browser CI explicitly prepares only the
`free` and `enterprise` plans with `scripts/prepare-browser-e2e-catalog.sh`. The
script checks acknowledged measurements and independently checks for remaining
maintenance database sessions. It is restricted to the synthetic browser identity;
other environments follow [catalog maintenance](CATALOG-MAINTENANCE.md).

The unchanged existing browser signing case has passed actual server/worker
startup, authoring, both signatures and PDF download with this configuration. A
separate run using a fresh versioned local bucket also passed the strict audit
verifier and downloaded a PDF matching the stored completion digest. Ordinary
unversioned development storage does not satisfy that strict release verifier.

## Supplying per-process values in development Compose

The base `docker-compose.yml` has explicit environment maps and does not forward
`HASH_WORK_*` from the project `.env` file. Create two private files in the Hash
root, `.env.work-runtime.server` and `.env.work-runtime.worker`. Put all 17 keys
listed above in each file, with explicit decimal allocations for that process.
Keep these files private; the existing `.env.*` ignore rule covers them. Do not
leave values blank or assume one allocation can be counted independently for
every process.

Create `.env.work-runtime.compose.yml` (also ignored) containing:

```yaml
services:
  hash:
    env_file:
      - .env.work-runtime.server
  worker:
    env_file:
      - .env.work-runtime.worker
```

Include this overlay after the selected storage topology. For the bundled local
MinIO topology, validate configuration without printing environment values:

```sh
docker compose -f docker-compose.yml -f docker-compose.local-minio.yml \
  -f .env.work-runtime.compose.yml config --quiet
```

Use those same three files when starting the development stack. Missing env files
are errors; omitting this overlay preserves the existing unconfigured behavior.
This only supplies configuration. Validate the actual runtime against the actual
pool and exercise authoring/signing, provider failure and shutdown before claiming
those journeys work. `hash-config-check` validates parsing, not runtime pool
allocation or readiness.

## Controlled test allocation reference

`internal/handler/owned_real_render_browser_v1_e2e_test.go` and
`owned_public_signer_read_v1_e2e_test.go` contain an exercised logical integration
profile: global/organisation parent bytes 2147483648, DB staging bytes 402653184,
SQL sessions 8/4, provider streams 1/1 and grants 128/64. Other vector dimensions
are explicitly zero. Its DB allocation is the fixture pool maximum plus 8. These
are fixture-specific ceilings, not deployment defaults, measured RSS/headroom,
physical resource reclamation or fitted-signing readiness. Derive deployment
values from the intended workload and aggregate process measurements.
