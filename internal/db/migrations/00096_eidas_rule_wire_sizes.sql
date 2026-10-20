-- Complete eIDAS rule wire metadata. No rules are validated, enabled, measured
-- or backfilled by installation. Original rule and evaluation policy remains.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('server_encoding')<>'UTF8' THEN
  RAISE EXCEPTION 'eidas rule wire sizes require UTF8' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- Exclude pre-cutover readers and writers, including row-locking readers.
LOCK TABLE orgs IN ACCESS EXCLUSIVE MODE NOWAIT;
LOCK TABLE eidas_routing_rules IN ACCESS EXCLUSIVE MODE NOWAIT;
CREATE TABLE eidas_rule_wire_sizes_v1 (
 rule_id UUID PRIMARY KEY REFERENCES eidas_routing_rules(id) ON DELETE CASCADE,
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 rule_created_at TIMESTAMPTZ NOT NULL,
 rule_updated_at TIMESTAMPTZ NOT NULL,
 predicate_wire_bytes BIGINT NOT NULL CHECK(predicate_wire_bytes>=1),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at))
);
-- +goose StatementBegin
CREATE FUNCTION hash_fence_eidas_rule_set_v1() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE scope UUID;scopes UUID[];
BEGIN
 IF TG_OP='INSERT' THEN scopes:=ARRAY[NEW.org_id];
 ELSIF TG_OP='DELETE' THEN scopes:=ARRAY[OLD.org_id];
 ELSE scopes:=ARRAY[OLD.org_id,NEW.org_id]; END IF;
 -- Rule/cache writers may already hold a child row. Never wait child->org.
 -- Each real caller retains this org fence through the entire transaction.
 FOR scope IN SELECT DISTINCT s FROM unnest(scopes) AS u(s) WHERE s IS NOT NULL ORDER BY s LOOP
  PERFORM 1 FROM orgs o WHERE o.id=scope FOR UPDATE OF o NOWAIT;
  IF NOT FOUND AND TG_OP<>'DELETE' THEN
   RAISE EXCEPTION 'eidas rule organization missing' USING ERRCODE='23514';
  END IF;
  -- DELETE-only absence is the genuine same-transaction FK org cascade.
  -- Validated FK excludes a committed orphan under ordinary table writes.
 END LOOP;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER fence_eidas_rule_set_v1 BEFORE INSERT OR UPDATE OR DELETE
 ON eidas_routing_rules FOR EACH ROW EXECUTE FUNCTION hash_fence_eidas_rule_set_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_derive_eidas_rule_wire_sizes_v1() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE source_org UUID;locked_org UUID;source_created_at TIMESTAMPTZ;source_updated_at TIMESTAMPTZ;predicate JSONB;
BEGIN
 IF NEW.rule_id IS NULL OR (TG_OP='UPDATE' AND NEW.rule_id IS DISTINCT FROM OLD.rule_id) THEN
  RAISE EXCEPTION 'eidas rule wire size identity required and immutable' USING ERRCODE='23514';
 END IF;
 -- Preliminary fixed UUID lookup carries no JSON body. After the org fence,
 -- lock/recheck the actual source before any expansion; a moved row refuses.
 SELECT r.org_id INTO STRICT source_org FROM eidas_routing_rules r WHERE r.id=NEW.rule_id;
 PERFORM 1 FROM orgs o WHERE o.id=source_org FOR UPDATE OF o NOWAIT;
 IF NOT FOUND THEN RAISE NO_DATA_FOUND; END IF;
 SELECT r.org_id,r.created_at,r.updated_at INTO STRICT locked_org,source_created_at,source_updated_at
  FROM eidas_routing_rules r WHERE r.id=NEW.rule_id FOR UPDATE OF r NOWAIT;
 IF locked_org IS DISTINCT FROM source_org THEN
  RAISE EXCEPTION 'eidas rule wire source changed scope' USING ERRCODE='23514';
 END IF;
 SELECT r.predicate_json INTO STRICT predicate FROM eidas_routing_rules r WHERE r.id=NEW.rule_id;
 NEW.org_id:=source_org;
 NEW.rule_created_at:=source_created_at;
 NEW.rule_updated_at:=source_updated_at;
 NEW.predicate_wire_bytes:=octet_length(predicate::text)::bigint;
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'eidas rule wire source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_eidas_rule_wire_sizes_v1 BEFORE INSERT OR UPDATE
 ON eidas_rule_wire_sizes_v1 FOR EACH ROW EXECUTE FUNCTION hash_derive_eidas_rule_wire_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_fence_eidas_rule_wire_delete_v1() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
BEGIN
 -- Cache deletion is also part of the measured set. NOWAIT prevents cache->org
 -- inversion. An absent org is allowed only for this real FK cascade DELETE.
 PERFORM 1 FROM orgs o WHERE o.id=OLD.org_id FOR UPDATE OF o NOWAIT;
 RETURN OLD;
END $$;
-- +goose StatementEnd
CREATE TRIGGER fence_eidas_rule_wire_delete_v1 BEFORE DELETE ON eidas_rule_wire_sizes_v1
 FOR EACH ROW EXECUTE FUNCTION hash_fence_eidas_rule_wire_delete_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_eidas_rule_wire_sizes_v1() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
BEGIN
 -- Cheap deletion only on EVERY rule UPDATE, including equal JSON, changed
 -- numeric scale, scope/identity/time/activation/order/name/tier/reason changes.
 DELETE FROM eidas_rule_wire_sizes_v1 WHERE rule_id=OLD.id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_eidas_rule_wire_sizes_v1 AFTER UPDATE ON eidas_routing_rules
 FOR EACH ROW EXECUTE FUNCTION hash_invalidate_eidas_rule_wire_sizes_v1();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE orgs IN ACCESS EXCLUSIVE MODE NOWAIT;
 LOCK TABLE eidas_routing_rules IN ACCESS EXCLUSIVE MODE NOWAIT;
 LOCK TABLE eidas_rule_wire_sizes_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM eidas_rule_wire_sizes_v1) THEN
  RAISE EXCEPTION 'retained eidas rule measurements prevent down' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER invalidate_eidas_rule_wire_sizes_v1 ON eidas_routing_rules;
DROP TRIGGER fence_eidas_rule_wire_delete_v1 ON eidas_rule_wire_sizes_v1;
DROP TRIGGER derive_eidas_rule_wire_sizes_v1 ON eidas_rule_wire_sizes_v1;
DROP TRIGGER fence_eidas_rule_set_v1 ON eidas_routing_rules;
DROP FUNCTION hash_invalidate_eidas_rule_wire_sizes_v1();
DROP FUNCTION hash_fence_eidas_rule_wire_delete_v1();
DROP FUNCTION hash_derive_eidas_rule_wire_sizes_v1();
DROP FUNCTION hash_fence_eidas_rule_set_v1();
DROP TABLE eidas_rule_wire_sizes_v1;
