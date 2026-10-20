-- These scalar/read APIs do not grant tenant, mutation, decision or work
-- authority. A genuine native owner retains doc->org order, real header/body
-- loans, these exact org/rule/cache locks and the original request deadline.

-- name: GetActiveEIDASRuleSetHeaderV1 :one
-- Org UPDATE is a complete-set fence: all actual rule I/U/D and cache I/U/D
-- take the SAME org fence NOWAIT. No active rule, predicate or text is omitted.
WITH parent AS MATERIALIZED (
 SELECT o.id FROM orgs o WHERE o.id=sqlc.arg(org_id)::uuid FOR UPDATE OF o NOWAIT
), totals AS MATERIALIZED (
 SELECT count(*)::bigint AS rule_count,
  count(s.rule_id) FILTER(WHERE s.org_id=r.org_id AND s.rule_created_at=r.created_at
   AND s.rule_updated_at=r.updated_at AND s.measurement_server_version_num=current_setting('server_version_num')::integer)::bigint AS measured_rule_count,
  COALESCE(sum(octet_length(r.name)::numeric+octet_length(r.required_tier)+octet_length(r.reason)),0)::numeric AS raw_total,
  COALESCE(sum(s.predicate_wire_bytes::numeric) FILTER(WHERE s.org_id=r.org_id AND s.rule_created_at=r.created_at
   AND s.rule_updated_at=r.updated_at AND s.measurement_server_version_num=current_setting('server_version_num')::integer),0)::numeric AS wire_total
 FROM eidas_routing_rules r JOIN parent p ON p.id=r.org_id
 LEFT JOIN eidas_rule_wire_sizes_v1 s ON s.rule_id=r.id
 WHERE r.active=TRUE
), sizes AS MATERIALIZED (
 SELECT rule_count,measured_rule_count,
  (CASE WHEN raw_total BETWEEN 0 AND 9223372036854775807::numeric THEN raw_total::bigint ELSE -1::bigint END)::bigint AS raw_text_bytes,
  (CASE WHEN measured_rule_count=rule_count AND wire_total BETWEEN 0 AND 9223372036854775807::numeric THEN wire_total::bigint ELSE -1::bigint END)::bigint AS predicate_wire_bytes,
  (CASE WHEN measured_rule_count=rule_count THEN current_setting('server_version_num')::integer ELSE -1 END)::integer AS measurement_server_version_num
 FROM totals
)
SELECT p.id AS org_id,s.rule_count,s.measured_rule_count,s.raw_text_bytes,s.predicate_wire_bytes,
 s.measurement_server_version_num,current_setting('server_version_num')::integer AS server_version_num
FROM parent p CROSS JOIN sizes s;

-- name: LockActiveEIDASRuleSetPinsV1 :one
-- ONLY after a real complete-count/raw/wire-derived loan. Lock all rows in
-- UUID order, with no LIMIT or ID array returned. Inversions refuse NOWAIT.
-- Fresh GetActiveEIDASRuleSetHeaderV1 equality is mandatory after these pins.
WITH parent AS MATERIALIZED (
 SELECT o.id FROM orgs o WHERE o.id=sqlc.arg(org_id)::uuid FOR UPDATE OF o NOWAIT
), rules AS MATERIALIZED (
 SELECT r.id FROM eidas_routing_rules r JOIN parent p ON p.id=r.org_id
 WHERE r.active=TRUE ORDER BY r.id FOR SHARE OF r NOWAIT
), measured AS MATERIALIZED (
 SELECT s.rule_id FROM eidas_rule_wire_sizes_v1 s JOIN rules r ON r.id=s.rule_id
 ORDER BY s.rule_id FOR SHARE OF s NOWAIT
)
SELECT p.id AS org_id,(SELECT count(*)::bigint FROM rules) AS rule_count,
 (SELECT count(*)::bigint FROM measured) AS measured_rule_count FROM parent p;

-- name: ReadActiveEIDASRuleSetV1 :many
-- Complete actual generated models, original priority/created_at ordering.
-- Retained same-org fence and NOWAIT row/cache pins precede this body SQL.
WITH parent AS MATERIALIZED (
 SELECT o.id FROM orgs o WHERE o.id=sqlc.arg(org_id)::uuid FOR UPDATE OF o NOWAIT
), totals AS MATERIALIZED (
 SELECT count(*)::bigint AS rule_count,
  count(s.rule_id) FILTER(WHERE s.org_id=r.org_id AND s.rule_created_at=r.created_at
   AND s.rule_updated_at=r.updated_at AND s.measurement_server_version_num=current_setting('server_version_num')::integer)::bigint AS measured_rule_count,
  COALESCE(sum(octet_length(r.name)::numeric+octet_length(r.required_tier)+octet_length(r.reason)),0)::numeric AS raw_total,
  COALESCE(sum(s.predicate_wire_bytes::numeric) FILTER(WHERE s.org_id=r.org_id AND s.rule_created_at=r.created_at
   AND s.rule_updated_at=r.updated_at AND s.measurement_server_version_num=current_setting('server_version_num')::integer),0)::numeric AS wire_total
 FROM eidas_routing_rules r JOIN parent p ON p.id=r.org_id
 LEFT JOIN eidas_rule_wire_sizes_v1 s ON s.rule_id=r.id
 WHERE r.active=TRUE
), sizes AS MATERIALIZED (
 SELECT rule_count,measured_rule_count,
  (CASE WHEN raw_total BETWEEN 0 AND 9223372036854775807::numeric THEN raw_total::bigint ELSE -1::bigint END)::bigint AS raw_text_bytes,
  (CASE WHEN measured_rule_count=rule_count AND wire_total BETWEEN 0 AND 9223372036854775807::numeric THEN wire_total::bigint ELSE -1::bigint END)::bigint AS predicate_wire_bytes,
  (CASE WHEN measured_rule_count=rule_count THEN current_setting('server_version_num')::integer ELSE -1 END)::integer AS measurement_server_version_num
 FROM totals
)
SELECT r.* FROM eidas_routing_rules r JOIN parent p ON p.id=r.org_id CROSS JOIN sizes s
WHERE r.active=TRUE AND s.rule_count=sqlc.arg(expected_rule_count)::bigint
 AND s.measured_rule_count=s.rule_count AND s.raw_text_bytes=sqlc.arg(expected_raw_text_bytes)::bigint
 AND s.raw_text_bytes>=0 AND s.predicate_wire_bytes=sqlc.arg(expected_predicate_wire_bytes)::bigint
 AND s.predicate_wire_bytes>=0 AND s.measurement_server_version_num=sqlc.arg(expected_measurement_server_version_num)::integer
 AND s.measurement_server_version_num=current_setting('server_version_num')::integer
ORDER BY r.priority ASC,r.created_at ASC;

-- name: CreateFreshEIDASRuleSourceV1 :one
-- A genuine bounded input producer owns canonical input/SQL staging before
-- this INSERT, then measures SAME returned native UUID in SAME transaction.
-- Fixed scalar return avoids expanding predicate/text again before its loan.
INSERT INTO eidas_routing_rules(org_id,name,priority,predicate_json,required_tier,reason,active)
VALUES(sqlc.arg(org_id)::uuid,sqlc.arg(name)::text,sqlc.arg(priority)::integer,
 sqlc.arg(predicate_json)::jsonb,sqlc.arg(required_tier)::text,sqlc.arg(reason)::text,sqlc.arg(active)::boolean)
RETURNING id,org_id,created_at,updated_at;

-- name: MeasureEIDASRuleSourceV1 :one
-- Explicit fresh producer or separately controlled admitted backfill ONLY.
-- Trigger derives actual scope/timestamps/wire/version/clock and overwrites
-- every supplied value. No read path calls this and no mutation auto-refreshes.
INSERT INTO eidas_rule_wire_sizes_v1(rule_id,org_id,rule_created_at,rule_updated_at,predicate_wire_bytes,measurement_server_version_num,measured_at)
SELECT r.id,r.org_id,r.created_at,r.updated_at,1,1,clock_timestamp()
FROM eidas_routing_rules r WHERE r.id=sqlc.arg(rule_id)::uuid AND r.org_id=sqlc.arg(org_id)::uuid
 AND r.created_at=sqlc.arg(expected_created_at)::timestamptz AND r.updated_at=sqlc.arg(expected_updated_at)::timestamptz
ON CONFLICT(rule_id) DO UPDATE SET predicate_wire_bytes=EXCLUDED.predicate_wire_bytes
RETURNING rule_id,org_id,rule_created_at,rule_updated_at,predicate_wire_bytes,measurement_server_version_num,measured_at;

-- name: GetEIDASRuleControlledBackfillHeaderV1 :one
-- Explicit maintenance control only, never ordinary Send/read fallback.
-- Direct stored JSONB + uncompressed physical size has proven finite text
-- upper U=6L+147465*floor(L/4)+2, L=pg_column_size+4 on exact PG16.15 UTF8.
-- Any compressed/unsupported/null/overflow case returns -1, never expands.
WITH parent AS MATERIALIZED (
 SELECT o.id FROM orgs o WHERE o.id=sqlc.arg(org_id)::uuid FOR UPDATE OF o NOWAIT
), source AS MATERIALIZED (
 SELECT r.id,r.org_id,r.created_at,r.updated_at,
  (octet_length(r.name)::numeric+octet_length(r.required_tier)+octet_length(r.reason))::bigint AS raw_text_bytes,
  pg_column_size(r.predicate_json)::bigint AS stored_bytes,
  (pg_column_compression(r.predicate_json) IS NULL)::boolean AS is_uncompressed
 FROM eidas_routing_rules r JOIN parent p ON p.id=r.org_id
 WHERE r.id=sqlc.arg(rule_id)::uuid FOR UPDATE OF r NOWAIT
), upper_bound AS MATERIALIZED (
 SELECT s.*,(6*(stored_bytes::numeric+4)+147465*floor((stored_bytes::numeric+4)/4)+2)::numeric AS wire_upper
 FROM source s
)
SELECT id AS rule_id,org_id,created_at,updated_at,raw_text_bytes,stored_bytes,is_uncompressed,
 (CASE WHEN current_setting('server_encoding')='UTF8' AND current_setting('server_version_num')::integer=160015
  AND is_uncompressed AND stored_bytes>0 AND wire_upper BETWEEN 1 AND 9223372036854775807::numeric
  THEN wire_upper::bigint ELSE -1::bigint END)::bigint AS predicate_wire_upper_bytes,
 current_setting('server_version_num')::integer AS server_version_num FROM upper_bound;
