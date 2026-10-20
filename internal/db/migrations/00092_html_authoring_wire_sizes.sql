-- Source-only forward foundation: exact PostgreSQL UTF8 JSONB text-wire sizes.
-- A cache row is measurement metadata, never approval, quota, work-loan or READY
-- authority. Native fresh producers retain a real bounded loan and parent locks
-- BEFORE these expanded measurements. Historical rows remain uncached/refused;
-- no migration backfill, automatic JSONB refresh or application writer grant.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('server_encoding') <> 'UTF8' THEN
  RAISE EXCEPTION 'HTML authoring wire sizes require UTF8' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
CREATE TABLE html_authoring_template_sizes_v1 (
 template_id UUID PRIMARY KEY,
 org_id UUID NOT NULL,
 master_wire_bytes BIGINT NOT NULL CHECK(master_wire_bytes>=0),
 variables_wire_bytes BIGINT NOT NULL CHECK(variables_wire_bytes>=0),
 blocks_wire_bytes BIGINT NOT NULL CHECK(blocks_wire_bytes>=0),
 fields_wire_bytes BIGINT NOT NULL CHECK(fields_wire_bytes>=0),
 sanitization_wire_bytes BIGINT NOT NULL CHECK(sanitization_wire_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at)),
 FOREIGN KEY(template_id,org_id) REFERENCES templates(id,org_id) ON DELETE CASCADE
);
CREATE TABLE html_authoring_revision_sizes_v1 (
 template_id UUID NOT NULL,
 org_id UUID NOT NULL,
 version INTEGER NOT NULL CHECK(version>0),
 master_wire_bytes BIGINT NOT NULL CHECK(master_wire_bytes>=0),
 variables_wire_bytes BIGINT NOT NULL CHECK(variables_wire_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at)),
 PRIMARY KEY(template_id,version),
 FOREIGN KEY(template_id,version) REFERENCES html_template_revisions(template_id,version) ON DELETE CASCADE,
 FOREIGN KEY(template_id,org_id) REFERENCES templates(id,org_id) ON DELETE CASCADE
);
CREATE TABLE html_creation_response_sizes_v1 (
 document_id UUID PRIMARY KEY,
 org_id UUID NOT NULL,
 blocks_wire_bytes BIGINT NOT NULL CHECK(blocks_wire_bytes>=0),
 metadata_wire_bytes BIGINT NOT NULL CHECK(metadata_wire_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at)),
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE CASCADE
);
-- +goose StatementBegin
CREATE FUNCTION hash_derive_html_authoring_template_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_org UUID;master JSONB;variables JSONB;blocks JSONB;fields JSONB;sanitization JSONB;
BEGIN
 IF NEW.template_id IS NULL OR NEW.org_id IS NULL THEN
  RAISE EXCEPTION 'HTML template size scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.template_id IS DISTINCT FROM OLD.template_id THEN
  RAISE EXCEPTION 'HTML template size identity is immutable' USING ERRCODE='23514';
 END IF;
 -- Parent precedes cache. A direct cache mutation taking the wrong order fails
 -- NOWAIT instead of waiting on a parent held by the native header/writer.
 SELECT org_id INTO STRICT actual_org FROM templates
  WHERE id=NEW.template_id ORDER BY id FOR UPDATE NOWAIT;
 IF actual_org IS DISTINCT FROM NEW.org_id THEN
  RAISE EXCEPTION 'HTML template size scope differs' USING ERRCODE='23514';
 END IF;
 SELECT html_master_json,variables_json,blocks_json,fields_json,pdf_sanitization_report
  INTO STRICT master,variables,blocks,fields,sanitization FROM templates
  WHERE id=NEW.template_id AND org_id=actual_org AND source_kind='html' AND archived_at IS NULL;
 NEW.master_wire_bytes:=COALESCE(octet_length(master::text)::bigint,0);
 NEW.variables_wire_bytes:=COALESCE(octet_length(variables::text)::bigint,0);
 NEW.blocks_wire_bytes:=COALESCE(octet_length(blocks::text)::bigint,0);
 NEW.fields_wire_bytes:=COALESCE(octet_length(fields::text)::bigint,0);
 NEW.sanitization_wire_bytes:=COALESCE(octet_length(sanitization::text)::bigint,0);
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'active HTML template size source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_html_authoring_template_sizes_v1 BEFORE INSERT OR UPDATE
 ON html_authoring_template_sizes_v1 FOR EACH ROW
 EXECUTE FUNCTION hash_derive_html_authoring_template_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_derive_html_authoring_revision_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_org UUID;revision_org UUID;master JSONB;variables JSONB;
BEGIN
 IF NEW.template_id IS NULL OR NEW.org_id IS NULL OR NEW.version IS NULL THEN
  RAISE EXCEPTION 'HTML revision size scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND (NEW.template_id IS DISTINCT FROM OLD.template_id OR NEW.version IS DISTINCT FROM OLD.version) THEN
  RAISE EXCEPTION 'HTML revision size identity is immutable' USING ERRCODE='23514';
 END IF;
 SELECT org_id INTO STRICT actual_org FROM templates
  WHERE id=NEW.template_id AND source_kind='html' AND archived_at IS NULL ORDER BY id FOR UPDATE NOWAIT;
 IF actual_org IS DISTINCT FROM NEW.org_id THEN
  RAISE EXCEPTION 'HTML revision size scope differs' USING ERRCODE='23514';
 END IF;
 -- Caller acquired parent then revision BEFORE cache. No revision model/body
 -- is selected until this admitted expanded-measurement operation.
 SELECT r.org_id INTO STRICT revision_org FROM html_template_revisions r
  WHERE r.template_id=NEW.template_id AND r.version=NEW.version FOR SHARE OF r NOWAIT;
 IF revision_org IS DISTINCT FROM actual_org THEN
  RAISE EXCEPTION 'HTML revision size source scope differs' USING ERRCODE='23514';
 END IF;
 SELECT html_master_json,variables_json INTO STRICT master,variables
  FROM html_template_revisions WHERE template_id=NEW.template_id AND version=NEW.version AND org_id=actual_org;
 NEW.master_wire_bytes:=COALESCE(octet_length(master::text)::bigint,0);
 NEW.variables_wire_bytes:=COALESCE(octet_length(variables::text)::bigint,0);
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'active HTML revision size source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_html_authoring_revision_sizes_v1 BEFORE INSERT OR UPDATE
 ON html_authoring_revision_sizes_v1 FOR EACH ROW
 EXECUTE FUNCTION hash_derive_html_authoring_revision_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_derive_html_creation_response_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_org UUID;blocks JSONB;metadata_json JSONB;
BEGIN
 IF NEW.document_id IS NULL OR NEW.org_id IS NULL THEN
  RAISE EXCEPTION 'HTML response size scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.document_id IS DISTINCT FROM OLD.document_id THEN
  RAISE EXCEPTION 'HTML response size identity is immutable' USING ERRCODE='23514';
 END IF;
 SELECT org_id INTO STRICT actual_org FROM documents
  WHERE id=NEW.document_id ORDER BY id FOR UPDATE NOWAIT;
 IF actual_org IS DISTINCT FROM NEW.org_id THEN
  RAISE EXCEPTION 'HTML response size scope differs' USING ERRCODE='23514';
 END IF;
 SELECT blocks_json,metadata INTO STRICT blocks,metadata_json FROM documents
  WHERE id=NEW.document_id AND org_id=actual_org AND deleted_at IS NULL;
 NEW.blocks_wire_bytes:=COALESCE(octet_length(blocks::text)::bigint,0);
 NEW.metadata_wire_bytes:=COALESCE(octet_length(metadata_json::text)::bigint,0);
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'active HTML response size source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_html_creation_response_sizes_v1 BEFORE INSERT OR UPDATE
 ON html_creation_response_sizes_v1 FOR EACH ROW
 EXECUTE FUNCTION hash_derive_html_creation_response_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_html_authoring_template_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 -- Deletion only: no JSONB equality, ::text expansion or remeasurement here.
 DELETE FROM html_authoring_template_sizes_v1 WHERE template_id=OLD.id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_html_authoring_template_sizes_v1 AFTER UPDATE OF
 id,org_id,html_master_json,variables_json,blocks_json,fields_json,pdf_sanitization_report ON templates
 FOR EACH ROW EXECUTE FUNCTION hash_invalidate_html_authoring_template_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_html_authoring_revision_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 DELETE FROM html_authoring_revision_sizes_v1 WHERE template_id=OLD.template_id AND version=OLD.version;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_html_authoring_revision_sizes_v1 AFTER UPDATE OF
 template_id,org_id,version,html_master_json,variables_json ON html_template_revisions
 FOR EACH ROW EXECUTE FUNCTION hash_invalidate_html_authoring_revision_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_html_creation_response_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 DELETE FROM html_creation_response_sizes_v1 WHERE document_id=OLD.id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_html_creation_response_sizes_v1 AFTER UPDATE OF
 id,org_id,blocks_json,metadata ON documents
 FOR EACH ROW EXECUTE FUNCTION hash_invalidate_html_creation_response_sizes_v1();
-- +goose Down
-- Never silently remove a retained cache sizing gate. Cache disposition needs
-- a separately reviewed bounded operation; this rollback is empty-only.
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE templates,html_template_revisions,documents,html_authoring_template_sizes_v1,html_authoring_revision_sizes_v1,html_creation_response_sizes_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM html_authoring_template_sizes_v1)
  OR EXISTS(SELECT 1 FROM html_authoring_revision_sizes_v1)
  OR EXISTS(SELECT 1 FROM html_creation_response_sizes_v1) THEN
  RAISE EXCEPTION 'HTML authoring size records require reviewed disposition before rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER invalidate_html_creation_response_sizes_v1 ON documents;
DROP TRIGGER invalidate_html_authoring_revision_sizes_v1 ON html_template_revisions;
DROP TRIGGER invalidate_html_authoring_template_sizes_v1 ON templates;
DROP TRIGGER derive_html_creation_response_sizes_v1 ON html_creation_response_sizes_v1;
DROP TRIGGER derive_html_authoring_revision_sizes_v1 ON html_authoring_revision_sizes_v1;
DROP TRIGGER derive_html_authoring_template_sizes_v1 ON html_authoring_template_sizes_v1;
DROP FUNCTION hash_invalidate_html_creation_response_sizes_v1();
DROP FUNCTION hash_invalidate_html_authoring_revision_sizes_v1();
DROP FUNCTION hash_invalidate_html_authoring_template_sizes_v1();
DROP FUNCTION hash_derive_html_creation_response_sizes_v1();
DROP FUNCTION hash_derive_html_authoring_revision_sizes_v1();
DROP FUNCTION hash_derive_html_authoring_template_sizes_v1();
DROP TABLE html_creation_response_sizes_v1;
DROP TABLE html_authoring_revision_sizes_v1;
DROP TABLE html_authoring_template_sizes_v1;
