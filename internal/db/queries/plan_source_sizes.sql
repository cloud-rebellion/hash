-- Full actual models are read only after native scalar/header-derived loans.
-- Parent SHARE then cache SHARE remains held in the SAME actual transaction.
-- Missing/stale caches refuse; no SELECT body performs refresh or backfill.
-- name: GetPlanSourceHeaderByIDV1 :one
-- Scalar source pins only. The shared catalog is not tenant authorization.
WITH parent AS MATERIALIZED (
 SELECT p.id,p.created_at,p.active,p.document_quota_monthly,p.recipient_quota_monthly,
  (octet_length(p.slug)::numeric+octet_length(p.name)+octet_length(p.description)+octet_length(p.currency))::bigint AS raw_text_bytes
 FROM billing_plans p WHERE p.id=sqlc.arg(plan_id)::uuid FOR SHARE OF p
), cache AS MATERIALIZED (
 SELECT m.plan_id,m.plan_created_at,m.features_wire_bytes,m.measurement_server_version_num
 FROM billing_plan_feature_sizes_v1 m JOIN parent p ON p.id=m.plan_id AND p.created_at=m.plan_created_at
 FOR SHARE OF m
)
SELECT p.id,p.created_at,p.active,p.document_quota_monthly,p.recipient_quota_monthly,p.raw_text_bytes,
 COALESCE(m.features_wire_bytes,-1::bigint)::bigint AS features_wire_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent p LEFT JOIN cache m ON m.plan_id=p.id;

-- name: GetPlanSourceHeaderBySlugV1 :one
-- Scalar source pins only. The shared catalog is not tenant authorization.
WITH parent AS MATERIALIZED (
 SELECT p.id,p.created_at,p.active,p.document_quota_monthly,p.recipient_quota_monthly,
  (octet_length(p.slug)::numeric+octet_length(p.name)+octet_length(p.description)+octet_length(p.currency))::bigint AS raw_text_bytes
 FROM billing_plans p
 -- Original configured operator grants are<=100bytes; free is literal4.
 -- The catalog itself remains unconstrained: subscription ByID prices any
 -- genuine longer slug. This CASE avoids unpriced long legacy slug expansion.
 WHERE (CASE WHEN octet_length(p.slug)<=100 THEN p.slug ELSE NULL::text END)=sqlc.arg(slug)::text
  AND octet_length(sqlc.arg(slug)::text)<=100 FOR SHARE OF p
), cache AS MATERIALIZED (
 SELECT m.plan_id,m.plan_created_at,m.features_wire_bytes,m.measurement_server_version_num
 FROM billing_plan_feature_sizes_v1 m JOIN parent p ON p.id=m.plan_id AND p.created_at=m.plan_created_at
 FOR SHARE OF m
)
SELECT p.id,p.created_at,p.active,p.document_quota_monthly,p.recipient_quota_monthly,p.raw_text_bytes,
 COALESCE(m.features_wire_bytes,-1::bigint)::bigint AS features_wire_bytes,
 COALESCE(m.measurement_server_version_num,-1::integer)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent p LEFT JOIN cache m ON m.plan_id=p.id;

-- name: ReadPlanSourceV1 :one
SELECT p.* FROM billing_plans p JOIN billing_plan_feature_sizes_v1 m
 ON m.plan_id=p.id AND m.plan_created_at=p.created_at
WHERE p.id=sqlc.arg(plan_id)::uuid AND p.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND (octet_length(p.slug)::numeric+octet_length(p.name)+octet_length(p.description)+octet_length(p.currency))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint
 AND m.features_wire_bytes=sqlc.arg(expected_features_wire_bytes)::bigint
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer;

-- name: GetPlanSourceSubscriptionHeaderV1 :one
-- Absence is a point-in-time observation for the ORIGINAL free-plan fallback,
-- never a stable absence/body grant. Only an existing row is locked and sized.
SELECT s.id,s.org_id,s.plan_id,s.created_at,s.updated_at,
 (octet_length(s.provider)::numeric+COALESCE(octet_length(s.provider_customer_id),0)+COALESCE(octet_length(s.provider_subscription_id),0)+octet_length(s.status))::bigint AS raw_text_bytes
FROM org_subscriptions s WHERE s.org_id=sqlc.arg(org_id)::uuid FOR SHARE OF s;

-- name: ReadPlanSourceSubscriptionV1 :one
SELECT s.* FROM org_subscriptions s
WHERE s.id=sqlc.arg(subscription_id)::uuid AND s.org_id=sqlc.arg(org_id)::uuid
 AND s.plan_id=sqlc.arg(expected_plan_id)::uuid
 AND s.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND s.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND (octet_length(s.provider)::numeric+COALESCE(octet_length(s.provider_customer_id),0)+COALESCE(octet_length(s.provider_subscription_id),0)+octet_length(s.status))::bigint=sqlc.arg(expected_raw_text_bytes)::bigint;

-- name: CreateFreshPlanSourceV1 :one
-- Only a genuine reviewed operator/catalog producer with a retained exact-input
-- loan may use this additive creation primitive. It does not authorize enrollment
-- or update old catalog rows. A separate subsequent same-TX measurement derives
-- server metadata only after this actual fresh INSERT acknowledges its real ID.
INSERT INTO billing_plans(slug,name,description,monthly_price_cents,yearly_price_cents,currency,
 document_quota_monthly,recipient_quota_monthly,features_json,active,sort_order)
VALUES(sqlc.arg(slug)::text,sqlc.arg(name)::text,sqlc.arg(description)::text,
 sqlc.arg(monthly_price_cents)::integer,sqlc.arg(yearly_price_cents)::integer,sqlc.arg(currency)::text,
 sqlc.arg(document_quota_monthly)::integer,sqlc.arg(recipient_quota_monthly)::integer,
 sqlc.arg(features_json)::jsonb,sqlc.arg(active)::boolean,sqlc.arg(sort_order)::integer)
RETURNING *;

-- name: MeasurePlanSourceFeaturesV1 :one
-- Expanded measurement ONLY after genuine fresh-input or independently proven
-- controlled-backfill ownership. Neither a caller ceiling nor the plan UUID is
-- authority. Existing compressed/uncached rows are not automatically admitted.
WITH parent AS MATERIALIZED (
 SELECT p.id,p.created_at FROM billing_plans p
 WHERE p.id=sqlc.arg(plan_id)::uuid AND p.created_at=sqlc.arg(expected_created_at)::timestamptz
 FOR UPDATE OF p NOWAIT
), cache AS MATERIALIZED (
 SELECT m.plan_id FROM billing_plan_feature_sizes_v1 m JOIN parent p ON p.id=m.plan_id
 FOR UPDATE OF m NOWAIT
), cache_done AS MATERIALIZED (SELECT count(*)::bigint AS n FROM cache)
INSERT INTO billing_plan_feature_sizes_v1(plan_id,plan_created_at,features_wire_bytes,measurement_server_version_num,measured_at)
SELECT p.id,p.created_at,0,0,clock_timestamp() FROM parent p CROSS JOIN cache_done c
ON CONFLICT(plan_id) DO UPDATE SET plan_created_at=EXCLUDED.plan_created_at
RETURNING *;

-- name: GetPlanSourceControlledBackfillHeaderV1 :one
-- Explicit operator-controlled maintenance ONLY, never normal read repair.
-- Actual heap-column metadata functions inspect stored TOAST/varlena headers,
-- not JSONB::text or scalar values. The plan UPDATE lock is retained through
-- genuine size-derived loan acquisition and subsequent intrinsic measurement.
-- Bound proof is pinned to official PostgreSQL16.15/UTF8, direct stored JSONB:
-- L=storageBytes+4 bounds uncompressed flat bytes; J<=floor(L/4) from uint32
-- JEntries. Max stored numeric text147457; other syntax<=8J+2 and strings<=6L.
-- Compressed/other-version sources deliberately have upper=-1 and stay refused.
WITH parent AS MATERIALIZED (
 SELECT p.id,p.created_at,
  (octet_length(p.slug)::numeric+octet_length(p.name)+octet_length(p.description)+octet_length(p.currency))::bigint AS raw_text_bytes,
  (pg_column_compression(p.features_json) IS NULL)::boolean AS features_uncompressed,
  pg_column_size(p.features_json)::bigint AS features_storage_bytes
 FROM billing_plans p WHERE p.id=sqlc.arg(plan_id)::uuid FOR UPDATE OF p NOWAIT
)
SELECT p.id,p.created_at,p.raw_text_bytes,p.features_uncompressed,p.features_storage_bytes,
 (CASE WHEN p.features_uncompressed AND p.features_storage_bytes>0
   AND current_setting('server_version_num')::integer=160015
  THEN 6*(p.features_storage_bytes::numeric+4)
   +147465*floor((p.features_storage_bytes::numeric+4)/4)+2
  ELSE -1 END)::bigint AS features_wire_upper_bound,
 current_setting('server_version_num')::integer AS server_version_num
FROM parent p;
