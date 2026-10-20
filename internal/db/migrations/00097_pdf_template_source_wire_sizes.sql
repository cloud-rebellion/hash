-- Exact source wire measurements for reusable PDF and blocks templates.
-- The legacy SQL/table names are retained for source compatibility; explicit
-- intrinsic source_kind pins keep both purposes distinct. HTML stays M92.
-- Metadata is
-- sizing only: no user/approval/READY/quota authority, no automatic backfill.
-- Fresh native producers retain exact input/old-source work before measuring.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('server_encoding')<>'UTF8' THEN
  RAISE EXCEPTION 'PDF template source sizes require UTF8' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
CREATE TABLE pdf_template_source_sizes_v1 (
 template_id UUID PRIMARY KEY,
 org_id UUID NOT NULL,
 source_kind TEXT NOT NULL CHECK(source_kind IN ('pdf','blocks')),
 template_created_at TIMESTAMPTZ NOT NULL CHECK(isfinite(template_created_at)),
 template_updated_at TIMESTAMPTZ NOT NULL CHECK(isfinite(template_updated_at)),
 template_version INTEGER NOT NULL CHECK(template_version>0),
 master_wire_bytes BIGINT NOT NULL CHECK(master_wire_bytes>=0),
 variables_wire_bytes BIGINT NOT NULL CHECK(variables_wire_bytes>=0),
 blocks_wire_bytes BIGINT NOT NULL CHECK(blocks_wire_bytes>=0),
 fields_wire_bytes BIGINT NOT NULL CHECK(fields_wire_bytes>=0),
 sanitization_wire_bytes BIGINT NOT NULL CHECK(sanitization_wire_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at)),
 FOREIGN KEY(template_id,org_id) REFERENCES templates(id,org_id) ON DELETE CASCADE
);
-- +goose StatementBegin
CREATE FUNCTION hash_derive_pdf_template_source_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_org UUID;actual_created TIMESTAMPTZ;actual_updated TIMESTAMPTZ;actual_version INTEGER;actual_kind TEXT;
 master JSONB;variables JSONB;blocks JSONB;fields JSONB;sanitization JSONB;
BEGIN
 IF NEW.template_id IS NULL OR NEW.org_id IS NULL THEN
  RAISE EXCEPTION 'PDF template source size scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.template_id IS DISTINCT FROM OLD.template_id THEN
  RAISE EXCEPTION 'PDF template source size identity is immutable' USING ERRCODE='23514';
 END IF;
 -- A direct cache writer cannot invert the native parent's lock direction.
 SELECT org_id INTO STRICT actual_org FROM templates WHERE id=NEW.template_id FOR UPDATE NOWAIT;
 IF actual_org IS DISTINCT FROM NEW.org_id THEN
  RAISE EXCEPTION 'PDF template source size scope differs' USING ERRCODE='23514';
 END IF;
 SELECT created_at,updated_at,version,source_kind,html_master_json,variables_json,blocks_json,fields_json,pdf_sanitization_report
 INTO STRICT actual_created,actual_updated,actual_version,actual_kind,master,variables,blocks,fields,sanitization
 FROM templates WHERE id=NEW.template_id AND org_id=actual_org AND source_kind IN ('pdf','blocks') AND archived_at IS NULL;
 NEW.source_kind:=actual_kind;
 NEW.template_created_at:=actual_created;
 NEW.template_updated_at:=actual_updated;
 NEW.template_version:=actual_version;
 -- ALL full Template JSON bodies are measured. A source kind alone is not
 -- assumed to imply absent arbitrary legacy blocks or HTML-master values.
 NEW.master_wire_bytes:=COALESCE(octet_length(master::text)::bigint,0);
 NEW.variables_wire_bytes:=COALESCE(octet_length(variables::text)::bigint,0);
 NEW.blocks_wire_bytes:=COALESCE(octet_length(blocks::text)::bigint,0);
 NEW.fields_wire_bytes:=COALESCE(octet_length(fields::text)::bigint,0);
 NEW.sanitization_wire_bytes:=COALESCE(octet_length(sanitization::text)::bigint,0);
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'active non-HTML template source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_pdf_template_source_sizes_v1 BEFORE INSERT OR UPDATE ON pdf_template_source_sizes_v1
 FOR EACH ROW EXECUTE FUNCTION hash_derive_pdf_template_source_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_fence_pdf_template_source_size_delete_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 -- Missing parent is legitimate only for FK source deletion. Existing parents,
 -- including archived templates, retain the same source-before-cache order.
 PERFORM 1 FROM templates WHERE id=OLD.template_id FOR UPDATE NOWAIT;
 RETURN OLD;
END $$;
-- +goose StatementEnd
CREATE TRIGGER fence_pdf_template_source_size_delete_v1 BEFORE DELETE ON pdf_template_source_sizes_v1
 FOR EACH ROW EXECUTE FUNCTION hash_fence_pdf_template_source_size_delete_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_pdf_template_source_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 -- Cheap deletion only. No expanded equality/text conversion/read repair.
 DELETE FROM pdf_template_source_sizes_v1 WHERE template_id=OLD.id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_pdf_template_source_sizes_v1 AFTER UPDATE OF
 id,org_id,source_kind,version,created_at,updated_at,archived_at,
 html_master_json,variables_json,blocks_json,fields_json,pdf_sanitization_report ON templates
 FOR EACH ROW EXECUTE FUNCTION hash_invalidate_pdf_template_source_sizes_v1();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE templates,pdf_template_source_sizes_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM pdf_template_source_sizes_v1) THEN
  RAISE EXCEPTION 'PDF template source size records require reviewed disposition before rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER invalidate_pdf_template_source_sizes_v1 ON templates;
DROP TRIGGER fence_pdf_template_source_size_delete_v1 ON pdf_template_source_sizes_v1;
DROP TRIGGER derive_pdf_template_source_sizes_v1 ON pdf_template_source_sizes_v1;
DROP FUNCTION hash_invalidate_pdf_template_source_sizes_v1();
DROP FUNCTION hash_fence_pdf_template_source_size_delete_v1();
DROP FUNCTION hash_derive_pdf_template_source_sizes_v1();
DROP TABLE pdf_template_source_sizes_v1;
