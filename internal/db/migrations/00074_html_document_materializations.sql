-- +goose Up
-- Preserve 00073's first-set provenance. A current projection selects an
-- append-only materialization; it never rewrites the original source.
ALTER TABLE documents ADD CONSTRAINT documents_id_org_materialization_unique UNIQUE (id, org_id);
CREATE TABLE html_document_materializations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    org_id UUID NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    parent_id UUID,
    parent_commitment BYTEA,
    origin_commitment BYTEA NOT NULL CHECK (octet_length(origin_commitment) = 32),
    source_json JSONB NOT NULL CHECK (jsonb_typeof(source_json) = 'object'),
    source_commitment BYTEA NOT NULL CHECK (octet_length(source_commitment) = 32),
    pdf_key TEXT NOT NULL CHECK (pdf_key <> '' AND pdf_key = btrim(pdf_key)),
    pdf_sha256 BYTEA NOT NULL CHECK (octet_length(pdf_sha256) = 32),
    pdf_version_id TEXT NOT NULL CHECK (pdf_version_id <> '' AND pdf_version_id = btrim(pdf_version_id) AND length(pdf_version_id) <= 1024),
    page_count INTEGER NOT NULL CHECK (page_count BETWEEN 1 AND 500),
    summary TEXT NOT NULL DEFAULT '' CHECK (char_length(summary) <= 500),
    changed_sections TEXT[] NOT NULL DEFAULT '{}',
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (document_id, sequence),
    UNIQUE (id, document_id, org_id),
    UNIQUE (id, document_id, org_id, source_commitment),
    FOREIGN KEY (document_id, org_id) REFERENCES documents(id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_id, document_id, org_id, parent_commitment)
        REFERENCES html_document_materializations(id, document_id, org_id, source_commitment) ON DELETE RESTRICT,
    CHECK ((sequence = 1 AND parent_id IS NULL AND parent_commitment IS NULL AND source_commitment = origin_commitment)
        OR (sequence > 1 AND parent_id IS NOT NULL AND parent_commitment IS NOT NULL AND octet_length(parent_commitment) = 32))
);
ALTER TABLE documents ADD COLUMN html_current_materialization_id UUID;
ALTER TABLE documents ADD COLUMN html_current_source_json JSONB;
ALTER TABLE documents ADD COLUMN html_current_page_count INTEGER;
ALTER TABLE documents ADD COLUMN html_current_materialization_sequence INTEGER;
ALTER TABLE documents ADD COLUMN html_reviewed_materialization_id UUID;
ALTER TABLE documents ADD COLUMN html_effective_source_commitment TEXT
    GENERATED ALWAYS AS (COALESCE(html_current_source_json, html_source_json) ->> 'commitment') STORED;
ALTER TABLE documents ADD CONSTRAINT document_html_effective_commitment_shape CHECK (
    html_effective_source_commitment IS NULL OR html_effective_source_commitment ~ '^[0-9a-f]{64}$'
);
ALTER TABLE documents ADD CONSTRAINT document_html_current_materialization_fk
    FOREIGN KEY (html_current_materialization_id, id, org_id)
    REFERENCES html_document_materializations(id, document_id, org_id) ON DELETE RESTRICT;
ALTER TABLE documents ADD CONSTRAINT document_html_current_projection_shape CHECK (
    (html_current_materialization_id IS NULL AND html_current_source_json IS NULL AND html_current_page_count IS NULL AND html_current_materialization_sequence IS NULL AND html_reviewed_materialization_id IS NULL)
    OR (html_source_json IS NOT NULL AND source_kind = 'pdf' AND html_current_materialization_id IS NOT NULL
        AND html_current_source_json IS NOT NULL AND jsonb_typeof(html_current_source_json) = 'object'
        AND html_current_page_count IS NOT NULL AND html_current_page_count BETWEEN 1 AND 500
        AND html_current_materialization_sequence IS NOT NULL AND html_current_materialization_sequence > 0
        AND ((html_reviewed_pdf_sha256 IS NULL AND html_reviewed_materialization_id IS NULL)
            OR (html_reviewed_pdf_sha256 IS NOT NULL AND html_reviewed_materialization_id IS NOT NULL
                AND html_reviewed_materialization_id = html_current_materialization_id)))
);

-- Snapshots preserve review/unsigned layout and retired ceremony context even
-- when the live document returns to draft. Exact normalized pins are inventory
-- inputs; historical JSON is never the only cleanup/recovery reference.
CREATE TABLE html_document_materialization_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    org_id UUID NOT NULL,
    materialization_id UUID,
    kind TEXT NOT NULL CHECK (kind IN ('draft_superseded', 'ceremony_retired')),
    captured_updated_at TIMESTAMPTZ NOT NULL,
    source_json JSONB NOT NULL CHECK (jsonb_typeof(source_json) = 'object'),
    source_commitment BYTEA NOT NULL CHECK (octet_length(source_commitment) = 32),
    pdf_key TEXT NOT NULL CHECK (pdf_key <> '' AND pdf_key = btrim(pdf_key)),
    pdf_sha256 BYTEA NOT NULL CHECK (octet_length(pdf_sha256) = 32),
    pdf_version_id TEXT NOT NULL CHECK (pdf_version_id <> '' AND pdf_version_id = btrim(pdf_version_id) AND length(pdf_version_id) <= 1024),
    page_count INTEGER CHECK (page_count BETWEEN 1 AND 500),
    rendered_pdf_key TEXT,
    rendered_pdf_sha256 BYTEA,
    rendered_pdf_version_id TEXT,
    reviewed_pdf_sha256 BYTEA,
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    fields_json JSONB NOT NULL CHECK (jsonb_typeof(fields_json) = 'array'),
    recipients_json JSONB NOT NULL CHECK (jsonb_typeof(recipients_json) = 'array'),
    notice_context_json JSONB NOT NULL CHECK (jsonb_typeof(notice_context_json) = 'object'),
    ceremony_events_json JSONB NOT NULL CHECK (jsonb_typeof(ceremony_events_json) = 'array'),
    notice_epoch_at TIMESTAMPTZ,
    retain_until TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (document_id, org_id) REFERENCES documents(id, org_id) ON DELETE RESTRICT,
    FOREIGN KEY (materialization_id, document_id, org_id) REFERENCES html_document_materializations(id, document_id, org_id) ON DELETE RESTRICT,
    CHECK ((kind = 'draft_superseded' AND retain_until IS NULL)
        OR (kind = 'ceremony_retired' AND notice_epoch_at IS NOT NULL AND isfinite(notice_epoch_at)
            AND retain_until IS NOT NULL AND isfinite(retain_until)
            AND retain_until >= hash_evidence_retain_until(notice_epoch_at, 7))),
    CHECK ((rendered_pdf_key IS NULL AND rendered_pdf_sha256 IS NULL AND rendered_pdf_version_id IS NULL)
        OR (rendered_pdf_key IS NOT NULL AND rendered_pdf_key <> '' AND rendered_pdf_sha256 IS NOT NULL
            AND octet_length(rendered_pdf_sha256) = 32 AND rendered_pdf_version_id IS NOT NULL AND rendered_pdf_version_id <> '')),
    CHECK ((reviewed_pdf_sha256 IS NULL AND reviewed_by IS NULL AND reviewed_at IS NULL)
        OR (reviewed_pdf_sha256 IS NOT NULL AND reviewed_pdf_sha256 = pdf_sha256 AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL))
);
CREATE INDEX html_materialization_history ON html_document_materializations(org_id, document_id, sequence);
CREATE INDEX html_materialization_snapshot_history ON html_document_materialization_snapshots(org_id, document_id, created_at);

-- +goose StatementBegin
-- A single canonical projection is shared by snapshot insertion and its guard.
-- Recipient credentials are deliberately excluded; party identity and state,
-- complete field bindings, notice/branding and existing audit evidence remain.
CREATE FUNCTION hash_html_materialization_snapshot_context(target_document_id UUID)
RETURNS TABLE(fields_json JSONB, recipients_json JSONB, notice_context_json JSONB, ceremony_events_json JSONB) AS $$
    SELECT
        COALESCE((SELECT jsonb_agg(to_jsonb(f) ORDER BY f.page, f.y_pct, f.x_pct, f.id)
            FROM document_fields f WHERE f.document_id = d.id), '[]'::jsonb),
        COALESCE((SELECT jsonb_agg(jsonb_build_object('id', r.id, 'document_id', r.document_id,
            'email', r.email, 'name', r.name, 'role', r.role, 'status', r.status,
            'order_index', r.order_index, 'locale', r.locale, 'created_at', r.created_at)
            ORDER BY r.order_index, r.id) FROM recipients r WHERE r.document_id = d.id), '[]'::jsonb),
        jsonb_build_object('schema', d.article13_notice_schema, 'epoch_at', d.article13_notice_epoch_at,
            'sent_at', d.sent_at, 'epoch_committed', d.article13_notice_epoch_v61_committed,
            'lawful_basis', d.lawful_basis, 'expires_at', d.expires_at,
            'branding', (SELECT to_jsonb(b) FROM document_branding_override b WHERE b.document_id = d.id)),
        COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.created_at, e.id)
            FROM events e WHERE e.document_id = d.id), '[]'::jsonb)
    FROM documents d WHERE d.id = target_document_id;
$$ LANGUAGE sql STABLE;
CREATE FUNCTION hash_guard_html_materialization_history() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'HTML materialization history requires reviewed retention disposal' USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;
CREATE FUNCTION hash_guard_html_materialization_insert() RETURNS trigger AS $$
DECLARE d documents%ROWTYPE; p html_document_materializations%ROWTYPE;
BEGIN
    SELECT * INTO STRICT d FROM documents WHERE id = NEW.document_id AND org_id = NEW.org_id FOR UPDATE;
    IF d.html_source_json IS NULL OR d.source_kind <> 'pdf' OR d.status <> 'draft' OR d.deleted_at IS NOT NULL
       OR NEW.origin_commitment IS DISTINCT FROM decode(d.html_source_json ->> 'commitment', 'hex')
       OR NEW.source_commitment IS DISTINCT FROM decode(NEW.source_json ->> 'commitment', 'hex')
       OR NEW.pdf_key IS DISTINCT FROM NEW.source_json ->> 'pdf_key'
       OR NEW.pdf_sha256 IS DISTINCT FROM decode(NEW.source_json ->> 'pdf_sha256', 'hex')
       OR NEW.pdf_version_id IS DISTINCT FROM NEW.source_json ->> 'pdf_version_id'
       OR NEW.source_json ->> 'document_id' IS DISTINCT FROM d.id::text
       OR NEW.source_json ->> 'org_id' IS DISTINCT FROM d.org_id::text
       OR EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.created_by AND u.org_id <> d.org_id) THEN
        RAISE EXCEPTION 'HTML materialization identity is inconsistent' USING ERRCODE = '23514';
    END IF;
    IF NEW.sequence = 1 THEN
        IF d.html_current_materialization_id IS NOT NULL OR NEW.source_json IS DISTINCT FROM d.html_source_json THEN
            RAISE EXCEPTION 'HTML materialization origin is inconsistent' USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT * INTO STRICT p FROM html_document_materializations WHERE id = NEW.parent_id AND document_id = d.id AND org_id = d.org_id;
        IF p.sequence + 1 <> NEW.sequence OR p.source_commitment IS DISTINCT FROM NEW.parent_commitment
           OR d.html_current_materialization_id IS DISTINCT FROM p.id THEN
            RAISE EXCEPTION 'HTML materialization parent is not current' USING ERRCODE = '23514';
        END IF;
    END IF;
    -- New text inputs never replace the original approved design/approval.
    IF (NEW.source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment'])
        IS DISTINCT FROM (d.html_source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment']) THEN
        RAISE EXCEPTION 'HTML materialization changed its approved origin' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE FUNCTION hash_guard_html_current_projection() RETURNS trigger AS $$
DECLARE m html_document_materializations%ROWTYPE; canonical_context RECORD;
BEGIN
    IF OLD.html_current_materialization_id IS NOT NULL AND NEW.html_current_materialization_id IS NULL THEN
        RAISE EXCEPTION 'HTML current materialization cannot be cleared' USING ERRCODE = '23514';
    END IF;
    IF NEW.html_current_materialization_id IS NOT NULL THEN
        SELECT * INTO STRICT m FROM html_document_materializations WHERE id = NEW.html_current_materialization_id AND document_id = NEW.id AND org_id = NEW.org_id;
        IF NEW.html_current_source_json IS DISTINCT FROM m.source_json OR NEW.html_current_page_count IS DISTINCT FROM m.page_count
           OR NEW.html_current_materialization_sequence IS DISTINCT FROM m.sequence
           OR NEW.pdf_storage_key IS DISTINCT FROM m.pdf_key OR NEW.pdf_sha256 IS DISTINCT FROM m.pdf_sha256
           OR NEW.pdf_storage_version_id IS DISTINCT FROM m.pdf_version_id
           OR NEW.variables_json IS DISTINCT FROM m.source_json -> 'values' THEN
            RAISE EXCEPTION 'HTML current projection differs from its immutable row' USING ERRCODE = '23514';
        END IF;
        IF NEW.html_current_materialization_id IS DISTINCT FROM OLD.html_current_materialization_id THEN
            IF OLD.status <> 'draft' OR NEW.status <> 'draft' OR OLD.deleted_at IS NOT NULL OR NEW.deleted_at IS NOT NULL
                OR (m.sequence = 1 AND (OLD.pdf_storage_key IS DISTINCT FROM m.pdf_key OR OLD.pdf_sha256 IS DISTINCT FROM m.pdf_sha256
                    OR OLD.pdf_storage_version_id IS DISTINCT FROM m.pdf_version_id OR OLD.variables_json IS DISTINCT FROM m.source_json -> 'values'))
                OR (OLD.html_current_materialization_id IS NOT NULL AND m.parent_id IS DISTINCT FROM OLD.html_current_materialization_id)
                OR EXISTS (SELECT 1 FROM signatures WHERE document_id = NEW.id)
                OR EXISTS (SELECT 1 FROM recipients WHERE document_id = NEW.id AND (status IN ('signed','accepted') OR signed_at IS NOT NULL))
                OR EXISTS (SELECT 1 FROM document_fields WHERE document_id = NEW.id AND (value IS NOT NULL OR completed_at IS NOT NULL))
                OR EXISTS (SELECT 1 FROM send_sealing_intents WHERE document_id = NEW.id)
                OR EXISTS (SELECT 1 FROM document_finalization_intents WHERE document_id = NEW.id)
                OR OLD.final_pdf_key IS NOT NULL OR OLD.final_pdf_sha IS NOT NULL OR OLD.final_pdf_version_id IS NOT NULL
                OR OLD.audit_cert_key IS NOT NULL OR OLD.audit_cert_sha256 IS NOT NULL OR OLD.audit_cert_version_id IS NOT NULL
                OR OLD.audit_payload_key IS NOT NULL OR OLD.audit_payload_sha256 IS NOT NULL OR OLD.audit_payload_version_id IS NOT NULL
                OR OLD.audit_signature_key IS NOT NULL OR OLD.audit_signature_sha256 IS NOT NULL OR OLD.audit_signature_version_id IS NOT NULL THEN
                RAISE EXCEPTION 'HTML current materialization is not safely editable' USING ERRCODE = '23514';
            END IF;
            -- Registering the unchanged first source preserves its exact review;
            -- every later materialization resets review even for identical PDFs.
            IF m.sequence > 1 THEN
                SELECT * INTO STRICT canonical_context FROM hash_html_materialization_snapshot_context(OLD.id);
                IF EXISTS (SELECT 1 FROM document_fields WHERE document_id = NEW.id)
                   OR NOT EXISTS (SELECT 1 FROM html_document_materialization_snapshots s
                       WHERE s.document_id = OLD.id AND s.org_id = OLD.org_id AND s.kind = 'draft_superseded'
                         AND s.captured_updated_at = OLD.updated_at
                         AND s.materialization_id IS NOT DISTINCT FROM OLD.html_current_materialization_id
                         AND s.source_json IS NOT DISTINCT FROM COALESCE(OLD.html_current_source_json, OLD.html_source_json)
                         AND s.source_commitment = decode(COALESCE(OLD.html_current_source_json, OLD.html_source_json) ->> 'commitment', 'hex')
                         AND s.pdf_key IS NOT DISTINCT FROM OLD.pdf_storage_key AND s.pdf_sha256 IS NOT DISTINCT FROM OLD.pdf_sha256
                         AND s.pdf_version_id IS NOT DISTINCT FROM OLD.pdf_storage_version_id AND s.page_count IS NOT DISTINCT FROM OLD.html_current_page_count
                         AND s.rendered_pdf_key IS NOT DISTINCT FROM OLD.rendered_pdf_key AND s.rendered_pdf_sha256 IS NOT DISTINCT FROM OLD.rendered_pdf_sha
                         AND s.rendered_pdf_version_id IS NOT DISTINCT FROM OLD.rendered_pdf_version_id
                         AND s.reviewed_pdf_sha256 IS NOT DISTINCT FROM OLD.html_reviewed_pdf_sha256
                         AND s.reviewed_by IS NOT DISTINCT FROM OLD.html_reviewed_by AND s.reviewed_at IS NOT DISTINCT FROM OLD.html_reviewed_at
                         AND s.recipients_json IS NOT DISTINCT FROM canonical_context.recipients_json
                         AND s.notice_context_json IS NOT DISTINCT FROM canonical_context.notice_context_json
                         AND s.ceremony_events_json IS NOT DISTINCT FROM canonical_context.ceremony_events_json) THEN
                    RAISE EXCEPTION 'HTML revision requires archived current context and fresh field placement' USING ERRCODE = '23514';
                END IF;
                NEW.html_reviewed_pdf_sha256 := NULL; NEW.html_reviewed_by := NULL; NEW.html_reviewed_at := NULL;
                NEW.html_reviewed_materialization_id := NULL;
            ELSIF NEW.html_reviewed_pdf_sha256 IS NOT NULL THEN
                NEW.html_reviewed_materialization_id := m.id;
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE FUNCTION hash_guard_html_snapshot_insert() RETURNS trigger AS $$
DECLARE d documents%ROWTYPE; expected_deadline TIMESTAMPTZ; canonical_context RECORD;
BEGIN
    SELECT * INTO STRICT d FROM documents WHERE id = NEW.document_id AND org_id = NEW.org_id FOR UPDATE;
    SELECT * INTO STRICT canonical_context FROM hash_html_materialization_snapshot_context(d.id);
    IF d.html_source_json IS NULL OR d.deleted_at IS NOT NULL
       OR NEW.captured_updated_at IS DISTINCT FROM d.updated_at
       OR NEW.source_json IS DISTINCT FROM COALESCE(d.html_current_source_json, d.html_source_json)
       OR NEW.source_commitment IS DISTINCT FROM decode(NEW.source_json ->> 'commitment', 'hex')
       OR NEW.materialization_id IS DISTINCT FROM d.html_current_materialization_id
       OR NEW.pdf_key IS DISTINCT FROM d.pdf_storage_key OR NEW.pdf_sha256 IS DISTINCT FROM d.pdf_sha256
       OR NEW.pdf_version_id IS DISTINCT FROM d.pdf_storage_version_id OR NEW.page_count IS DISTINCT FROM d.html_current_page_count
       OR NEW.rendered_pdf_key IS DISTINCT FROM d.rendered_pdf_key OR NEW.rendered_pdf_sha256 IS DISTINCT FROM d.rendered_pdf_sha
       OR NEW.rendered_pdf_version_id IS DISTINCT FROM d.rendered_pdf_version_id
       OR NEW.reviewed_pdf_sha256 IS DISTINCT FROM d.html_reviewed_pdf_sha256
       OR NEW.reviewed_by IS DISTINCT FROM d.html_reviewed_by OR NEW.reviewed_at IS DISTINCT FROM d.html_reviewed_at
       OR NEW.fields_json IS DISTINCT FROM canonical_context.fields_json
       OR NEW.recipients_json IS DISTINCT FROM canonical_context.recipients_json
       OR NEW.notice_context_json IS DISTINCT FROM canonical_context.notice_context_json
       OR NEW.ceremony_events_json IS DISTINCT FROM canonical_context.ceremony_events_json
       OR (NEW.created_by IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.created_by AND u.org_id = d.org_id)) THEN
        RAISE EXCEPTION 'HTML history snapshot differs from its current document' USING ERRCODE = '23514';
    END IF;
    IF NEW.kind = 'ceremony_retired' THEN
        SELECT GREATEST(d.finalization_retain_until, hash_evidence_retain_until(d.article13_notice_epoch_at, 7), max(si.retain_until))
          INTO expected_deadline FROM send_sealing_intents si WHERE si.document_id = d.id AND si.retention_started_at IS NOT NULL;
        IF d.status <> 'changes_requested' OR NEW.notice_epoch_at IS DISTINCT FROM d.article13_notice_epoch_at
           OR NEW.retain_until IS DISTINCT FROM expected_deadline THEN
            RAISE EXCEPTION 'HTML retired ceremony deadline differs from its committed epoch' USING ERRCODE = '23514';
        END IF;
    ELSIF d.status <> 'draft' OR NEW.notice_epoch_at IS NOT NULL THEN
        RAISE EXCEPTION 'HTML draft snapshot requires a draft' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER html_materializations_immutable BEFORE UPDATE OR DELETE ON html_document_materializations FOR EACH ROW EXECUTE FUNCTION hash_guard_html_materialization_history();
CREATE TRIGGER html_materialization_snapshots_immutable BEFORE UPDATE OR DELETE ON html_document_materialization_snapshots FOR EACH ROW EXECUTE FUNCTION hash_guard_html_materialization_history();
CREATE TRIGGER html_materializations_insert BEFORE INSERT ON html_document_materializations FOR EACH ROW EXECUTE FUNCTION hash_guard_html_materialization_insert();
CREATE TRIGGER document_html_current_projection BEFORE UPDATE ON documents FOR EACH ROW EXECUTE FUNCTION hash_guard_html_current_projection();
CREATE TRIGGER html_materialization_snapshots_insert BEFORE INSERT ON html_document_materialization_snapshots FOR EACH ROW EXECUTE FUNCTION hash_guard_html_snapshot_insert();

ALTER TABLE document_versions ADD COLUMN html_materialization_id UUID;
ALTER TABLE document_versions ADD CONSTRAINT document_version_html_materialization_fk
    FOREIGN KEY (html_materialization_id, document_id, org_id) REFERENCES html_document_materializations(id, document_id, org_id) ON DELETE RESTRICT;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    LOCK TABLE documents, document_versions, html_document_materializations, html_document_materialization_snapshots IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM html_document_materializations) OR EXISTS (SELECT 1 FROM html_document_materialization_snapshots)
       OR EXISTS (SELECT 1 FROM documents WHERE html_current_materialization_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM document_versions WHERE html_materialization_id IS NOT NULL) THEN
        RAISE EXCEPTION 'HTML materialization history prevents safe rollback' USING ERRCODE = '23514';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE document_versions DROP CONSTRAINT document_version_html_materialization_fk;
ALTER TABLE document_versions DROP COLUMN html_materialization_id;
DROP TRIGGER document_html_current_projection ON documents;
DROP FUNCTION hash_guard_html_current_projection();
ALTER TABLE documents DROP CONSTRAINT document_html_current_projection_shape;
ALTER TABLE documents DROP CONSTRAINT document_html_current_materialization_fk;
ALTER TABLE documents DROP CONSTRAINT document_html_effective_commitment_shape;
ALTER TABLE documents DROP COLUMN html_effective_source_commitment;
ALTER TABLE documents DROP COLUMN html_reviewed_materialization_id;
ALTER TABLE documents DROP COLUMN html_current_page_count;
ALTER TABLE documents DROP COLUMN html_current_materialization_sequence;
ALTER TABLE documents DROP COLUMN html_current_source_json;
ALTER TABLE documents DROP COLUMN html_current_materialization_id;
DROP TABLE html_document_materialization_snapshots;
DROP FUNCTION hash_guard_html_snapshot_insert();
DROP FUNCTION hash_html_materialization_snapshot_context(UUID);
DROP TABLE html_document_materializations;
DROP FUNCTION hash_guard_html_materialization_insert();
DROP FUNCTION hash_guard_html_materialization_history();
ALTER TABLE documents DROP CONSTRAINT documents_id_org_materialization_unique;
