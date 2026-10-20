-- Source-only signer-read sizing foundation; no backfill or activation.
-- Exact UTF8 JSONB text-wire report size belongs to the actual scoped document.
-- Native admitted fresh producers measure only under their real parent loan;
-- metadata, timestamps, UUIDs and cache rows never supply work/READY authority.
-- The fixed32 token index builds over existing scalar keys. Its populated-
-- estate build, temporary/maintenance capacity and actual plan/timeout cost are
-- explicit operator release gates; this is not a cost-free historical scan.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('server_encoding') <> 'UTF8' THEN
  RAISE EXCEPTION 'signer read wire sizes require UTF8' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
CREATE INDEX idx_recipients_token32_scope_v1 ON recipients
 ((CASE WHEN octet_length(magic_token_hash)=32 THEN magic_token_hash ELSE NULL::bytea END))
 WHERE octet_length(magic_token_hash)=32;
CREATE TABLE document_read_report_sizes_v1 (
 document_id UUID PRIMARY KEY,
 org_id UUID NOT NULL,
 report_wire_bytes BIGINT NOT NULL CHECK(report_wire_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at)),
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE CASCADE
);
-- +goose StatementBegin
CREATE FUNCTION hash_derive_document_read_report_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_org UUID;report JSONB;
BEGIN
 IF NEW.document_id IS NULL OR NEW.org_id IS NULL THEN
  RAISE EXCEPTION 'signer report size scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.document_id IS DISTINCT FROM OLD.document_id THEN
  RAISE EXCEPTION 'signer report size identity is immutable' USING ERRCODE='23514';
 END IF;
 -- Native parent-before-cache order. A direct inverse-order cache mutation
 -- refuses NOWAIT instead of waiting on the actual header/writer parent.
 SELECT org_id INTO STRICT actual_org FROM documents
  WHERE id=NEW.document_id ORDER BY id FOR UPDATE NOWAIT;
 IF actual_org IS DISTINCT FROM NEW.org_id THEN
  RAISE EXCEPTION 'signer report size scope differs' USING ERRCODE='23514';
 END IF;
 SELECT metadata_redaction_report INTO STRICT report FROM documents
  WHERE id=NEW.document_id AND org_id=actual_org AND deleted_at IS NULL;
 NEW.report_wire_bytes:=COALESCE(octet_length(report::text)::bigint,0);
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'active signer report size source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_document_read_report_sizes_v1 BEFORE INSERT OR UPDATE
 ON document_read_report_sizes_v1 FOR EACH ROW
 EXECUTE FUNCTION hash_derive_document_read_report_sizes_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_document_read_report_sizes_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 -- Cheap deletion only: no comparison, JSONB::text or automatic refresh.
 DELETE FROM document_read_report_sizes_v1 WHERE document_id=OLD.id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_document_read_report_sizes_v1 AFTER UPDATE OF
 id,org_id,metadata_redaction_report ON documents
 FOR EACH ROW EXECUTE FUNCTION hash_invalidate_document_read_report_sizes_v1();
-- +goose Down
-- A retained sizing gate is never silently removed from actual use.
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE documents,recipients,document_read_report_sizes_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM document_read_report_sizes_v1) THEN
  RAISE EXCEPTION 'signer report size records require reviewed disposition before rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER invalidate_document_read_report_sizes_v1 ON documents;
DROP TRIGGER derive_document_read_report_sizes_v1 ON document_read_report_sizes_v1;
DROP FUNCTION hash_invalidate_document_read_report_sizes_v1();
DROP FUNCTION hash_derive_document_read_report_sizes_v1();
DROP TABLE document_read_report_sizes_v1;
DROP INDEX idx_recipients_token32_scope_v1;
