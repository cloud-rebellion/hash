-- Exact UTF8 PostgreSQL JSONB text-wire metadata for the shared plan catalog.
-- This cache is measurement metadata only, never tenant permission, entitlement,
-- quota, work-loan or source freshness authority. Fresh bounded producers acquire
-- their actual loan BEFORE measurement. No old-row backfill or read repair here.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('server_encoding') <> 'UTF8' THEN
  RAISE EXCEPTION 'plan feature wire sizes require UTF8' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- No pre-cutover writer or row-locking reader can cross the trigger install.
-- Ordinary unadmitted readers are not granted authority by this migration.
LOCK TABLE billing_plans IN ACCESS EXCLUSIVE MODE NOWAIT;
CREATE TABLE billing_plan_feature_sizes_v1 (
 plan_id UUID PRIMARY KEY REFERENCES billing_plans(id) ON DELETE CASCADE,
 plan_created_at TIMESTAMPTZ NOT NULL,
 features_wire_bytes BIGINT NOT NULL CHECK(features_wire_bytes>=1),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at))
);
-- +goose StatementBegin
CREATE FUNCTION hash_derive_plan_feature_sizes_v1() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_created_at TIMESTAMPTZ;features JSONB;
BEGIN
 IF NEW.plan_id IS NULL THEN
  RAISE EXCEPTION 'plan feature size identity required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.plan_id IS DISTINCT FROM OLD.plan_id THEN
  RAISE EXCEPTION 'plan feature size identity is immutable' USING ERRCODE='23514';
 END IF;
 -- Parent precedes cache. A direct cache writer holding the opposite row order
 -- refuses immediately rather than waiting on an admitted parent/header owner.
 SELECT p.created_at INTO STRICT actual_created_at FROM billing_plans p
  WHERE p.id=NEW.plan_id FOR UPDATE OF p NOWAIT;
 -- Expanded work exists ONLY in this explicitly admitted measurement path.
 -- Neither cache headers nor invalidation execute JSONB::text/equality scans.
 SELECT p.features_json INTO STRICT features FROM billing_plans p WHERE p.id=NEW.plan_id;
 NEW.plan_created_at:=actual_created_at;
 NEW.features_wire_bytes:=octet_length(features::text)::bigint;
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'plan feature size source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_plan_feature_sizes_v1 BEFORE INSERT OR UPDATE
 ON billing_plan_feature_sizes_v1 FOR EACH ROW EXECUTE FUNCTION hash_derive_plan_feature_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_plan_feature_sizes_v1() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 -- Delete only, including same-value UPDATE and JSON numeric spelling changes.
 DELETE FROM billing_plan_feature_sizes_v1 WHERE plan_id=OLD.id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_plan_feature_sizes_v1 AFTER UPDATE OF id,created_at,features_json
 ON billing_plans FOR EACH ROW EXECUTE FUNCTION hash_invalidate_plan_feature_sizes_v1();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE billing_plans IN ACCESS EXCLUSIVE MODE NOWAIT;
 LOCK TABLE billing_plan_feature_sizes_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM billing_plan_feature_sizes_v1) THEN
  RAISE EXCEPTION 'retained plan feature measurements prevent down' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER invalidate_plan_feature_sizes_v1 ON billing_plans;
DROP TRIGGER derive_plan_feature_sizes_v1 ON billing_plan_feature_sizes_v1;
DROP FUNCTION hash_invalidate_plan_feature_sizes_v1();
DROP FUNCTION hash_derive_plan_feature_sizes_v1();
DROP TABLE billing_plan_feature_sizes_v1;
