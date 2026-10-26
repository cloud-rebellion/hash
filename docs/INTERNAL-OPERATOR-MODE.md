# Production internal-operator mode

`HASH_BILLING_PROVIDER=operator` runs Hash for approved internal organizations
without collecting payments. It is a production mode: staff authentication, secure cookies,
proxy authentication, stable audit keys, scanner, storage, capability checks and
all other production requirements remain mandatory. Unset or mock billing is
still rejected outside loopback development.

## Provisioning and approval

Through the managed configuration/database change process, review an active
`billing_plans` row with **positive finite** document and recipient quotas and
the required boolean feature flags. Invalid feature objects fail closed. Review the real organization identity, quota size,
feature flags and the authorization/run reference together. This mode does not
create a plan, subscription, customer, invoice or payment. A missing,
deactivated or unbounded assigned plan fails closed, including after startup.

Before allowing document creation or Send, explicitly prepare each distinct
assigned plan through the existing controlled M95 measurement command and pass
the [catalog maintenance acceptance gate](CATALOG-MAINTENANCE.md). A plan row and
valid operator binding alone are insufficient: startup validates the business
plan, but does not prepare or certify its intrinsic wire measurement. This also
applies to a fresh database, because migration95 deliberately does not backfill
the plans seeded by migration21. Missing measurements continue to fail closed.

Configure **both HTTP server and worker with the same approved bindings**:

```text
HASH_BILLING_PROVIDER=operator
HASH_OPERATOR_ENTITLEMENTS=[{"org_id":"REPLACE_WITH_INTERNAL_ORG_UUID","plan_slug":"internal-sales","review_ref":"REPLACE_WITH_MANAGED_REVIEW_REFERENCE"}]
```

The entitlement array must be nonempty (maximum 100 organizations / 64 KiB),
with unique non-nil organization UUIDs, plan slugs and review references.
Unknown fields, duplicate fields and trailing input are rejected. Unassigned
organizations have no entitlement; existing payment subscriptions do not grant
access in this mode. Server and worker verify all assigned organizations and
plans before starting. Do not set this variable in Mollie mode.

For a fresh installation, establish the real first workspace and pending owner
with the exact image's `hash-bootstrapowner` maintenance command before starting
operator mode; see [staff login](STAFF-LOGIN.md#first-internal-workspace). Bind
the returned organization UUID through managed configuration. The command does
not grant a plan or create a password, session or payment subscription.

Quota usage counts actual authoring documents and recipients, serialized at the
existing transactional authoring boundary and checked again at send. Internal
quotas use UTC calendar months. Size the reviewed plan for drafts as well as
sent contracts; 1,000 documents/day with two parties requires up to 31,000
documents and 62,000 recipients/month before draft headroom. These are planning
figures, not measured capacity or an SLA. There is no new seat-limit claim.

Changes to plan quotas/features are managed database changes and take effect
on the next check. A feature/source update that invalidates M95 metadata also
requires controlled remeasurement and the catalog gate before authoring resumes. Changes to bindings require a coordinated server/worker
restart. Preserve the reviewed configuration receipt; `review_ref` is
provenance, not an authorization token or proof that an external approval was
verified by Hash. Hash has no public endpoint for self-granting entitlements.

## Read-only status and disabled payments

The existing billing status APIs remain authenticated and expose the assigned
plan with `billing_enabled: true`, `payments_enabled: false` and provider
`operator`. There is no subscription and invoices are an empty array. The plan
catalog is empty: this mode offers no self-service purchases. The settings page
shows internal entitlement status and quotas, without checkout/cancel controls.
REST checkout/cancellation and all underlying billing engine payment methods
reject requests before writing payment intent or touching a payment provider.
Retired public billing webhook paths return an explicit denial, preventing a
payment callback from receiving the SPA shell as success.

The worker checks assigned organizations for 80-percent quota warnings. It
uses the same org quota lock, queues mail and commits an actual audit event
atomically, and deduplicates once per UTC month. It does not create a subscription
just to track warnings or apply the SaaS overdue-subscription logic to internal
organizations. Failed transactions remain retryable. Each warning attempt is
limited to 20 seconds; cancellation stops the scan and rolls back pending work
with a separate bounded cleanup context. Warning events must remain
available for their current month; deleting them can permit another warning.

Existing Mollie-mode behavior and its subscription quota periods are unchanged.
Switching payment modes does not cancel external subscriptions. Before switching
an existing paying deployment, reconcile/cancel recurring provider obligations
through a separately reviewed billing operation. Do not fabricate cancellation
receipts or edit historical evidence.
