-- +goose Up
-- Provenance is separate from canonical HTML source/signing domains. Historical
-- rows remain NULL: an unmeasured report must never acquire fresh attestation.
ALTER TABLE templates ADD COLUMN pdf_sanitization_report JSONB;
ALTER TABLE html_document_materializations ADD COLUMN metadata_redaction_report JSONB;
ALTER TABLE html_document_materialization_snapshots ADD COLUMN metadata_redaction_report JSONB;
ALTER TABLE templates ADD CONSTRAINT template_pdf_sanitization_report_shape CHECK (
    pdf_sanitization_report IS NULL OR (source_kind = 'pdf' AND jsonb_typeof(pdf_sanitization_report) = 'object'
        AND octet_length(pdf_sanitization_report::text) <= 65536));
ALTER TABLE html_document_materializations ADD CONSTRAINT html_materialization_report_shape CHECK (
    metadata_redaction_report IS NULL OR (jsonb_typeof(metadata_redaction_report) = 'object'
        AND octet_length(metadata_redaction_report::text) <= 65536));
ALTER TABLE html_document_materialization_snapshots ADD CONSTRAINT html_snapshot_report_shape CHECK (
    metadata_redaction_report IS NULL OR (jsonb_typeof(metadata_redaction_report) = 'object'
        AND octet_length(metadata_redaction_report::text) <= 65536));

-- +goose StatementBegin
CREATE FUNCTION hash_guard_html_report_projection() RETURNS trigger AS $$
DECLARE m html_document_materializations%ROWTYPE;
BEGIN
    IF NEW.html_current_materialization_id IS NOT NULL THEN
        SELECT * INTO STRICT m FROM html_document_materializations
        WHERE id = NEW.html_current_materialization_id AND document_id = NEW.id AND org_id = NEW.org_id;
        -- Existing pre-migration projections retain their recorded legacy
        -- report. Every new projection copies its immutable row, including NULL.
        IF (m.metadata_redaction_report IS NOT NULL
            OR NEW.html_current_materialization_id IS DISTINCT FROM OLD.html_current_materialization_id)
            AND NEW.metadata_redaction_report IS DISTINCT FROM COALESCE(m.metadata_redaction_report, '{}'::jsonb) THEN
            RAISE EXCEPTION 'HTML report differs from its immutable PDF materialization' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE FUNCTION hash_guard_html_snapshot_report() RETURNS trigger AS $$
DECLARE d documents%ROWTYPE;
BEGIN
    SELECT * INTO STRICT d FROM documents WHERE id = NEW.document_id AND org_id = NEW.org_id FOR UPDATE;
    IF NEW.metadata_redaction_report IS DISTINCT FROM d.metadata_redaction_report THEN
        RAISE EXCEPTION 'HTML snapshot report differs from its captured PDF' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER document_html_report_projection BEFORE UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION hash_guard_html_report_projection();
CREATE TRIGGER html_snapshot_report_insert BEFORE INSERT ON html_document_materialization_snapshots
    FOR EACH ROW EXECUTE FUNCTION hash_guard_html_snapshot_report();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    LOCK TABLE templates, html_document_materializations, html_document_materialization_snapshots IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM templates WHERE pdf_sanitization_report IS NOT NULL)
        OR EXISTS (SELECT 1 FROM html_document_materializations WHERE metadata_redaction_report IS NOT NULL)
        OR EXISTS (SELECT 1 FROM html_document_materialization_snapshots WHERE metadata_redaction_report IS NOT NULL) THEN
        RAISE EXCEPTION 'PDF sanitization provenance prevents destructive rollback' USING ERRCODE = '23514';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER html_snapshot_report_insert ON html_document_materialization_snapshots;
DROP TRIGGER document_html_report_projection ON documents;
DROP FUNCTION hash_guard_html_snapshot_report();
DROP FUNCTION hash_guard_html_report_projection();
ALTER TABLE html_document_materialization_snapshots DROP COLUMN metadata_redaction_report;
ALTER TABLE html_document_materializations DROP COLUMN metadata_redaction_report;
ALTER TABLE templates DROP COLUMN pdf_sanitization_report;
