-- +goose Up
-- HTML masters retain their own immutable authoring revisions. Instantiated
-- documents remain PDF-source documents; existing signing/evidence kinds do
-- not acquire a third rendering interpretation.
ALTER TABLE templates ADD COLUMN html_master_json JSONB;
ALTER TABLE templates ADD COLUMN html_content_sha256 BYTEA;
ALTER TABLE templates DROP CONSTRAINT templates_source_kind_check;
ALTER TABLE templates ADD CONSTRAINT templates_source_kind_check
    CHECK (source_kind IN ('blocks', 'pdf', 'html'));
ALTER TABLE templates DROP CONSTRAINT templates_source_consistent;
ALTER TABLE templates ADD CONSTRAINT templates_source_consistent CHECK (
    (source_kind = 'blocks' AND blocks_json IS NOT NULL
        AND html_master_json IS NULL AND html_content_sha256 IS NULL)
    OR (source_kind = 'pdf' AND pdf_storage_key IS NOT NULL
        AND html_master_json IS NULL AND html_content_sha256 IS NULL)
    OR (source_kind = 'html' AND html_master_json IS NOT NULL
        AND jsonb_typeof(html_master_json) = 'object'
        AND html_content_sha256 IS NOT NULL AND octet_length(html_content_sha256) = 32
        AND blocks_json IS NULL AND pdf_storage_key IS NULL)
);
ALTER TABLE templates ADD CONSTRAINT templates_id_org_unique UNIQUE (id, org_id);

CREATE TABLE html_template_revisions (
    template_id       UUID NOT NULL,
    version           INTEGER NOT NULL CHECK (version > 0),
    org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
    html_master_json  JSONB NOT NULL CHECK (jsonb_typeof(html_master_json) = 'object'),
    variables_json    JSONB NOT NULL CHECK (jsonb_typeof(variables_json) = 'object'),
    content_sha256    BYTEA NOT NULL CHECK (octet_length(content_sha256) = 32),
    created_by        UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by       UUID REFERENCES users(id) ON DELETE RESTRICT,
    approved_at       TIMESTAMPTZ,
    PRIMARY KEY (template_id, version),
    FOREIGN KEY (template_id, org_id) REFERENCES templates(id, org_id) ON DELETE RESTRICT,
    CONSTRAINT html_template_revision_approval_coherent CHECK (
        (approved_by IS NULL AND approved_at IS NULL)
        OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)
    )
);
CREATE INDEX html_template_revisions_org ON html_template_revisions(org_id, template_id, version);

-- Content, attribution and completed approvals cannot be rewritten. Archiving
-- a template preserves its revisions. Deletion needs a separately reviewed
-- retention/erasure procedure rather than silently cascading approved prose.
-- +goose StatementBegin
CREATE FUNCTION hash_guard_html_template_revision() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'HTML template revisions require reviewed retention disposal'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.template_id IS DISTINCT FROM OLD.template_id
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.org_id IS DISTINCT FROM OLD.org_id
       OR NEW.html_master_json IS DISTINCT FROM OLD.html_master_json
       OR NEW.variables_json IS DISTINCT FROM OLD.variables_json
       OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.approved_by IS NOT NULL
       OR NEW.approved_by IS NULL OR NEW.approved_at IS NULL THEN
        RAISE EXCEPTION 'HTML template revision content and completed approval are immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER html_template_revision_immutable
BEFORE UPDATE OR DELETE ON html_template_revisions
FOR EACH ROW EXECUTE FUNCTION hash_guard_html_template_revision();

ALTER TABLE documents ADD COLUMN html_source_json JSONB;
ALTER TABLE documents ADD COLUMN html_reviewed_pdf_sha256 BYTEA;
ALTER TABLE documents ADD COLUMN html_reviewed_by UUID REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE documents ADD COLUMN html_reviewed_at TIMESTAMPTZ;
ALTER TABLE documents ADD CONSTRAINT document_html_source_pdf CHECK (
    html_source_json IS NULL
    OR (source_kind = 'pdf' AND jsonb_typeof(html_source_json) = 'object')
);
ALTER TABLE documents ADD CONSTRAINT document_html_review_coherent CHECK (
    (html_reviewed_pdf_sha256 IS NULL AND html_reviewed_by IS NULL AND html_reviewed_at IS NULL)
    OR (html_source_json IS NOT NULL AND source_kind = 'pdf'
        AND html_reviewed_pdf_sha256 IS NOT NULL AND octet_length(html_reviewed_pdf_sha256) = 32
        AND html_reviewed_by IS NOT NULL AND html_reviewed_at IS NOT NULL
        AND pdf_sha256 IS NOT NULL AND html_reviewed_pdf_sha256 = pdf_sha256)
);

-- Materialization provenance is set only once, on a new draft. Subsequent
-- negotiation/rerendering needs a paired authoring and object-history protocol.
-- +goose StatementBegin
CREATE FUNCTION hash_guard_document_html_source() RETURNS trigger AS $$
BEGIN
    IF OLD.html_source_json IS NOT NULL
       AND NEW.html_source_json IS DISTINCT FROM OLD.html_source_json THEN
        RAISE EXCEPTION 'HTML document materialization is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF OLD.html_source_json IS NULL AND NEW.html_source_json IS NOT NULL THEN
        IF OLD.status <> 'draft' OR NEW.status <> 'draft' OR OLD.deleted_at IS NOT NULL
           OR NEW.deleted_at IS NOT NULL OR NEW.source_kind <> 'pdf' THEN
            RAISE EXCEPTION 'HTML materialization requires an active PDF draft'
                USING ERRCODE = '23514';
        END IF;
        NEW.html_reviewed_pdf_sha256 := NULL;
        NEW.html_reviewed_by := NULL;
        NEW.html_reviewed_at := NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER document_html_source_immutable
BEFORE UPDATE ON documents
FOR EACH ROW EXECUTE FUNCTION hash_guard_document_html_source();

ALTER TABLE document_versions ADD COLUMN html_source_json JSONB;
ALTER TABLE document_versions ADD CONSTRAINT document_version_html_source_pdf CHECK (
    html_source_json IS NULL
    OR (source_kind = 'pdf' AND jsonb_typeof(html_source_json) = 'object')
);

-- +goose Down
-- A rollback cannot silently orphan approved masters or their frozen document
-- inputs. Export/reconcile these records under a reviewed migration first.
-- +goose StatementBegin
DO $$
BEGIN
    -- Keep the empty-state decision and destructive DDL in one fence. A
    -- concurrent create/instantiate must not arrive after the refusal check.
    LOCK TABLE templates, html_template_revisions, documents, document_versions
        IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM templates WHERE source_kind = 'html'
           OR html_master_json IS NOT NULL OR html_content_sha256 IS NOT NULL)
       OR EXISTS (SELECT 1 FROM html_template_revisions)
       OR EXISTS (SELECT 1 FROM documents WHERE html_source_json IS NOT NULL
           OR html_reviewed_pdf_sha256 IS NOT NULL OR html_reviewed_by IS NOT NULL OR html_reviewed_at IS NOT NULL)
       OR EXISTS (SELECT 1 FROM document_versions WHERE html_source_json IS NOT NULL) THEN
        RAISE EXCEPTION 'HTML master/materialization records prevent safe migration rollback'
            USING ERRCODE = '23514';
    END IF;
END;
$$;
-- +goose StatementEnd
ALTER TABLE document_versions DROP CONSTRAINT document_version_html_source_pdf;
ALTER TABLE document_versions DROP COLUMN html_source_json;
DROP TRIGGER document_html_source_immutable ON documents;
DROP FUNCTION hash_guard_document_html_source();
ALTER TABLE documents DROP CONSTRAINT document_html_review_coherent;
ALTER TABLE documents DROP CONSTRAINT document_html_source_pdf;
ALTER TABLE documents DROP COLUMN html_reviewed_at;
ALTER TABLE documents DROP COLUMN html_reviewed_by;
ALTER TABLE documents DROP COLUMN html_reviewed_pdf_sha256;
ALTER TABLE documents DROP COLUMN html_source_json;
DROP TRIGGER html_template_revision_immutable ON html_template_revisions;
DROP FUNCTION hash_guard_html_template_revision();
DROP TABLE html_template_revisions;
ALTER TABLE templates DROP CONSTRAINT templates_id_org_unique;
ALTER TABLE templates DROP CONSTRAINT templates_source_consistent;
ALTER TABLE templates DROP CONSTRAINT templates_source_kind_check;
ALTER TABLE templates DROP COLUMN html_content_sha256;
ALTER TABLE templates DROP COLUMN html_master_json;
ALTER TABLE templates ADD CONSTRAINT templates_source_kind_check CHECK (source_kind IN ('blocks', 'pdf'));
ALTER TABLE templates ADD CONSTRAINT templates_source_consistent CHECK (
    (source_kind = 'blocks' AND blocks_json IS NOT NULL)
    OR (source_kind = 'pdf' AND pdf_storage_key IS NOT NULL)
);
