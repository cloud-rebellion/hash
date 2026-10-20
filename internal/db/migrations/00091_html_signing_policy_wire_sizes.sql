-- SOURCE-ONLY FORWARD FOUNDATION PROPOSAL. Not installed or qualified.
-- Requires reviewed UTF8 database and admitted writers/backfill BEFORE use.
-- These current-row caches contain server-derived PostgreSQL JSONB text-wire
-- lengths, not compressed storage sizes, canonical Go bytes or READY authority.
-- No eager historical backfill, JSONB::text preflight, quota or writer-role grant.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('server_encoding') <> 'UTF8' THEN
  RAISE EXCEPTION 'HTML policy wire sizes require UTF8' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
CREATE TABLE document_signing_policy_sizes_v1 (
 document_id UUID PRIMARY KEY,
 org_id UUID NOT NULL,
 html_origin_wire_bytes BIGINT NOT NULL CHECK(html_origin_wire_bytes>=0),
 html_current_wire_bytes BIGINT NOT NULL CHECK(html_current_wire_bytes>=0),
 variables_wire_bytes BIGINT NOT NULL CHECK(variables_wire_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at)),
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE CASCADE
);
CREATE TABLE field_signing_policy_sizes_v1 (
 field_id UUID PRIMARY KEY REFERENCES document_fields(id) ON DELETE CASCADE,
 document_id UUID NOT NULL,
 org_id UUID NOT NULL,
 options_wire_bytes BIGINT NOT NULL CHECK(options_wire_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at)),
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE CASCADE
);
-- +goose StatementBegin
CREATE FUNCTION hash_derive_document_policy_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_org UUID;origin_json JSONB;current_json JSONB;variables JSONB;
BEGIN
 -- This is expanded measurement, NEVER a cheap metadata/readiness operation.
 -- Native caller holds the real measurement/writer work loan and parent lock.
 -- Table declarations cannot understate: supplied sizes and timestamps are
 -- replaced from the actual locked source, including direct SQL cache writes.
 IF NEW.document_id IS NULL OR NEW.org_id IS NULL THEN
  RAISE EXCEPTION 'HTML policy size scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.document_id IS DISTINCT FROM OLD.document_id THEN
  RAISE EXCEPTION 'HTML policy size identity is immutable' USING ERRCODE='23514';
 END IF;
 SELECT org_id INTO STRICT actual_org FROM documents
  WHERE id=NEW.document_id ORDER BY id FOR UPDATE NOWAIT;
 IF actual_org IS DISTINCT FROM NEW.org_id THEN
  RAISE EXCEPTION 'HTML policy size scope differs' USING ERRCODE='23514';
 END IF;
 SELECT html_source_json,html_current_source_json,variables_json
  INTO STRICT origin_json,current_json,variables FROM documents
  WHERE id=NEW.document_id AND org_id=actual_org;
 NEW.html_origin_wire_bytes:=COALESCE(octet_length(origin_json::text)::bigint,0);
 NEW.html_current_wire_bytes:=COALESCE(octet_length(current_json::text)::bigint,0);
 NEW.variables_wire_bytes:=COALESCE(octet_length(variables::text)::bigint,0);
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'HTML policy size source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_document_policy_sizes_v1 BEFORE INSERT OR UPDATE
 ON document_signing_policy_sizes_v1 FOR EACH ROW
 EXECUTE FUNCTION hash_derive_document_policy_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_derive_field_policy_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_org UUID;actual_document UUID;options JSONB;parents UUID[];
BEGIN
 IF NEW.field_id IS NULL OR NEW.document_id IS NULL OR NEW.org_id IS NULL THEN
  RAISE EXCEPTION 'field policy size scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.field_id IS DISTINCT FROM OLD.field_id THEN
  RAISE EXCEPTION 'field policy size identity is immutable' USING ERRCODE='23514';
 END IF;
 parents:=ARRAY[NEW.document_id];
 IF TG_OP='UPDATE' THEN parents:=array_append(parents,OLD.document_id);END IF;
 -- A move preserves normal old/new parent ordering. The actual bound writer
 -- must have acquired the complete set BEFORE field/cache row locks.
 PERFORM 1 FROM documents WHERE id=ANY(parents) ORDER BY id FOR UPDATE NOWAIT;
 SELECT f.document_id,d.org_id INTO STRICT actual_document,actual_org
  FROM document_fields f JOIN documents d ON d.id=f.document_id
  WHERE f.id=NEW.field_id;
 IF actual_document IS DISTINCT FROM NEW.document_id OR actual_org IS DISTINCT FROM NEW.org_id THEN
  RAISE EXCEPTION 'field policy size scope differs' USING ERRCODE='23514';
 END IF;
 SELECT options_json INTO STRICT options FROM document_fields
  WHERE id=NEW.field_id AND document_id=actual_document;
 NEW.options_wire_bytes:=COALESCE(octet_length(options::text)::bigint,0);
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'field policy size source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_field_policy_sizes_v1 BEFORE INSERT OR UPDATE
 ON field_signing_policy_sizes_v1 FOR EACH ROW
 EXECUTE FUNCTION hash_derive_field_policy_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_document_policy_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 -- Cheap invalidation only. No raw JSONB comparison, output, hashing or size
 -- derivation may run as an automatic refresh. Missing cache refuses reads.
 DELETE FROM document_signing_policy_sizes_v1 WHERE document_id=NEW.id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_document_policy_sizes_v1 AFTER UPDATE OF
 html_source_json,html_current_source_json,variables_json ON documents
 FOR EACH ROW EXECUTE FUNCTION hash_invalidate_document_policy_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_field_policy_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 DELETE FROM field_signing_policy_sizes_v1 WHERE field_id=NEW.id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_field_policy_sizes_v1 AFTER UPDATE OF
 document_id,options_json ON document_fields
 FOR EACH ROW EXECUTE FUNCTION hash_invalidate_field_policy_sizes_v1();
-- +goose Down
-- Current measurement records are not historical evidence, yet rollback must
-- be explicit: do not silently remove the trusted sizing gate from retained use.
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE documents,document_fields,document_signing_policy_sizes_v1,field_signing_policy_sizes_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM document_signing_policy_sizes_v1) OR EXISTS(SELECT 1 FROM field_signing_policy_sizes_v1) THEN
  RAISE EXCEPTION 'policy size records require reviewed disposition before rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER invalidate_field_policy_sizes_v1 ON document_fields;
DROP TRIGGER invalidate_document_policy_sizes_v1 ON documents;
DROP TRIGGER derive_field_policy_sizes_v1 ON field_signing_policy_sizes_v1;
DROP TRIGGER derive_document_policy_sizes_v1 ON document_signing_policy_sizes_v1;
DROP FUNCTION hash_invalidate_field_policy_sizes_v1();
DROP FUNCTION hash_invalidate_document_policy_sizes_v1();
DROP FUNCTION hash_derive_field_policy_sizes_v1();
DROP FUNCTION hash_derive_document_policy_sizes_v1();
DROP TABLE field_signing_policy_sizes_v1;
DROP TABLE document_signing_policy_sizes_v1;
