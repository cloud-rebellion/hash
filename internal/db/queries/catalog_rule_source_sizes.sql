-- Owner policy mutations retain the original blocking organization fence.
-- No source body, new permission, active filter, or read repair is provided.

-- name: GetCatalogRuleOrgExistenceV1 :one
SELECT o.id FROM orgs o WHERE o.id=sqlc.arg(org_id)::uuid
FOR NO KEY UPDATE OF o;

-- name: GetCatalogRuleSourceHeaderV1 :one
WITH parent AS MATERIALIZED (
 SELECT o.id FROM orgs o WHERE o.id=sqlc.arg(org_id)::uuid FOR NO KEY UPDATE OF o
), source AS MATERIALIZED (
 SELECT r.id AS rule_id,r.org_id,r.created_at,r.updated_at,
  (octet_length(r.name)::numeric+octet_length(r.required_tier)+octet_length(r.reason))::bigint AS raw_text_bytes
 FROM eidas_routing_rules r JOIN parent p ON p.id=r.org_id
 WHERE r.id=sqlc.arg(rule_id)::uuid FOR SHARE OF r NOWAIT
), measured AS MATERIALIZED (
 SELECT s.rule_id,s.org_id,s.rule_created_at,s.rule_updated_at,s.predicate_wire_bytes,s.measurement_server_version_num
 FROM eidas_rule_wire_sizes_v1 s JOIN source r ON r.rule_id=s.rule_id FOR SHARE OF s NOWAIT
)
SELECT r.rule_id,r.org_id,r.created_at,r.updated_at,r.raw_text_bytes,
 (CASE WHEN s.org_id=r.org_id AND s.rule_created_at=r.created_at AND s.rule_updated_at=r.updated_at
  AND s.measurement_server_version_num=current_setting('server_version_num')::integer
  THEN s.predicate_wire_bytes ELSE -1::bigint END)::bigint AS predicate_wire_bytes,
 (CASE WHEN s.org_id=r.org_id AND s.rule_created_at=r.created_at AND s.rule_updated_at=r.updated_at
  AND s.measurement_server_version_num=current_setting('server_version_num')::integer
  THEN s.measurement_server_version_num ELSE -1::integer END)::integer AS measurement_server_version_num,
 current_setting('server_version_num')::integer AS server_version_num
FROM source r LEFT JOIN measured s ON s.rule_id=r.rule_id;

-- name: ReadCatalogRuleSourceV1 :one
WITH parent AS MATERIALIZED (
 SELECT o.id FROM orgs o WHERE o.id=sqlc.arg(org_id)::uuid FOR NO KEY UPDATE OF o
)
SELECT r.* FROM eidas_routing_rules r JOIN parent p ON p.id=r.org_id
JOIN eidas_rule_wire_sizes_v1 s ON s.rule_id=r.id AND s.org_id=r.org_id
WHERE r.id=sqlc.arg(rule_id)::uuid AND r.created_at=sqlc.arg(expected_created_at)::timestamptz
 AND r.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND (octet_length(r.name)::numeric+octet_length(r.required_tier)+octet_length(r.reason))=sqlc.arg(expected_raw_text_bytes)::bigint
 AND sqlc.arg(expected_raw_text_bytes)::bigint>=0
 AND s.rule_created_at=r.created_at AND s.rule_updated_at=r.updated_at
 AND s.predicate_wire_bytes=sqlc.arg(expected_predicate_wire_bytes)::bigint AND s.predicate_wire_bytes>0
 AND s.measurement_server_version_num=sqlc.arg(expected_measurement_server_version_num)::integer
 AND s.measurement_server_version_num=current_setting('server_version_num')::integer;
