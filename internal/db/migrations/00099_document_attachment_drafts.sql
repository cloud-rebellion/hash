-- +goose Up
-- Draft attachment selection is separate from the legacy blocks envelope.
-- These are selected immutable PDF/source pins, not live-following pointers.
-- Actual storage bytes/pages, source validity, authority and resource admission
-- must be established by the owned application adapter before selection.
-- Exact Go unicode.IsSpace set, independent of database locale/btrim defaults.
-- +goose StatementBegin
CREATE FUNCTION hash_package_trim_v1(value TEXT) RETURNS TEXT AS $$
 SELECT btrim(value, chr(9)||chr(10)||chr(11)||chr(12)||chr(13)||chr(32)||chr(133)||chr(160)||chr(5760)
  ||chr(8192)||chr(8193)||chr(8194)||chr(8195)||chr(8196)||chr(8197)||chr(8198)||chr(8199)||chr(8200)||chr(8201)||chr(8202)
  ||chr(8232)||chr(8233)||chr(8239)||chr(8287)||chr(12288));
$$ LANGUAGE sql IMMUTABLE STRICT;
CREATE FUNCTION hash_package_opaque_v1(value TEXT) RETURNS BOOLEAN AS $$
 SELECT octet_length(value) BETWEEN 1 AND 1024 AND hash_package_trim_v1(value)<>''
 AND value !~ ('['||chr(1)||'-'||chr(31)||chr(127)||'-'||chr(159)||']');
$$ LANGUAGE sql IMMUTABLE STRICT;
CREATE FUNCTION hash_package_label_v1(value TEXT,cap INTEGER,optional BOOLEAN) RETURNS BOOLEAN AS $$
 SELECT (optional AND value='') OR (octet_length(value) BETWEEN 1 AND cap AND value=hash_package_trim_v1(value)
 AND value !~ ('['||chr(1)||'-'||chr(31)||chr(127)||'-'||chr(159)||chr(8232)||chr(8233)||']'));
$$ LANGUAGE sql IMMUTABLE STRICT;
CREATE FUNCTION hash_package_key_v1(value TEXT,tenant UUID) RETURNS BOOLEAN AS $$
 SELECT hash_package_opaque_v1(value) AND value=hash_package_trim_v1(value)
 AND left(value,length(tenant::text)+5)='org/'||tenant::text||'/' AND position(chr(92) IN value)=0
 AND NOT EXISTS(SELECT 1 FROM unnest(string_to_array(value,'/')) segment WHERE segment IN ('','.','..'));
$$ LANGUAGE sql IMMUTABLE STRICT;
-- +goose StatementEnd

CREATE TABLE document_packages_v1 (
    id UUID PRIMARY KEY,
    document_id UUID NOT NULL UNIQUE,
    org_id UUID NOT NULL,
    draft_generation BIGINT NOT NULL DEFAULT 1 CHECK (draft_generation > 0),
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (id, org_id),
    FOREIGN KEY (document_id, org_id) REFERENCES documents(id, org_id) ON DELETE RESTRICT,
    CHECK (id <> '00000000-0000-0000-0000-000000000000')
);
CREATE TABLE document_attachment_drafts_v1 (
    package_id UUID NOT NULL,
    org_id UUID NOT NULL,
    member_document_id UUID NOT NULL,
    ordinal SMALLINT NOT NULL CHECK (ordinal BETWEEN 1 AND 16),
    title TEXT NOT NULL CHECK (hash_package_label_v1(title,512,false)),
    category TEXT NOT NULL DEFAULT '' CHECK (hash_package_label_v1(category,128,true)),
    pdf_key TEXT NOT NULL CHECK (hash_package_key_v1(pdf_key,org_id)),
    pdf_version_id TEXT NOT NULL CHECK (hash_package_opaque_v1(pdf_version_id) AND hash_package_trim_v1(pdf_version_id) NOT IN ('null','hash:unversioned-development')),
    pdf_sha256 BYTEA NOT NULL CHECK (octet_length(pdf_sha256) = 32 AND pdf_sha256 <> decode(repeat('00',32),'hex')),
    pdf_bytes BIGINT NOT NULL CHECK (pdf_bytes BETWEEN 1 AND 52428800),
    pdf_pages INTEGER NOT NULL CHECK (pdf_pages BETWEEN 1 AND 500),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('pdf-import','html-origin','html-materialization')),
    source_commitment BYTEA,
    origin_commitment BYTEA,
    materialization_id UUID,
    materialization_sequence INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (package_id, member_document_id),
    UNIQUE (package_id, ordinal) DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (package_id, pdf_key, pdf_version_id),
    FOREIGN KEY (package_id, org_id) REFERENCES document_packages_v1(id, org_id) ON DELETE RESTRICT,
    -- Subject identity deliberately is not a live document FK. The selected
    -- immutable source must survive later edits; purge/reference queries below
    -- separately protect its actual selected object. Normalized HTML history
    -- has a real immutable identity, and retains its existing composite FK.
    FOREIGN KEY (materialization_id, member_document_id, org_id, source_commitment)
        REFERENCES html_document_materializations(id, document_id, org_id, source_commitment) ON DELETE RESTRICT,
    CHECK (member_document_id <> '00000000-0000-0000-0000-000000000000'),
    CHECK (source_commitment IS NULL OR source_commitment <> decode(repeat('00',32),'hex')),
    CHECK (origin_commitment IS NULL OR origin_commitment <> decode(repeat('00',32),'hex')),
    CHECK (materialization_id IS NULL OR materialization_id <> '00000000-0000-0000-0000-000000000000'),
    CHECK ((source_kind = 'pdf-import' AND source_commitment IS NULL AND origin_commitment IS NULL AND materialization_id IS NULL AND materialization_sequence IS NULL)
        OR (source_kind = 'html-origin' AND octet_length(source_commitment) = 32 AND source_commitment IS NOT NULL
            AND source_commitment = origin_commitment AND origin_commitment IS NOT NULL AND materialization_id IS NULL AND materialization_sequence IS NULL)
        OR (source_kind = 'html-materialization' AND source_commitment IS NOT NULL AND octet_length(source_commitment) = 32
            AND origin_commitment IS NOT NULL AND octet_length(origin_commitment) = 32 AND materialization_id IS NOT NULL
            AND materialization_sequence IS NOT NULL AND materialization_sequence > 0
            AND (materialization_sequence <> 1 OR source_commitment = origin_commitment)))
);
CREATE INDEX document_attachment_subject_v1 ON document_attachment_drafts_v1(org_id,member_document_id);
CREATE INDEX document_attachment_object_v1 ON document_attachment_drafts_v1(pdf_key);

-- +goose StatementBegin
CREATE FUNCTION hash_package_has_signing_evidence_v1(target_document UUID,target_org UUID) RETURNS BOOLEAN AS $$
SELECT EXISTS(
  SELECT 1 FROM documents d
    WHERE d.id = target_document AND d.org_id = target_org
      AND (d.final_pdf_key IS NOT NULL OR d.final_pdf_sha IS NOT NULL OR d.final_pdf_version_id IS NOT NULL
        OR d.audit_cert_key IS NOT NULL OR d.audit_cert_sha256 IS NOT NULL OR d.audit_cert_version_id IS NOT NULL
        OR d.audit_payload_key IS NOT NULL OR d.audit_payload_sha256 IS NOT NULL OR d.audit_payload_version_id IS NOT NULL
        OR d.audit_signature_key IS NOT NULL OR d.audit_signature_sha256 IS NOT NULL OR d.audit_signature_version_id IS NOT NULL)
  UNION ALL
  SELECT 1 FROM document_finalization_intents WHERE document_id = target_document
  UNION ALL
  SELECT 1 FROM send_sealing_intents WHERE document_id = target_document
  UNION ALL
  SELECT 1 FROM signatures WHERE document_id = target_document
  UNION ALL
  SELECT 1 FROM recipients WHERE document_id = target_document
    AND (status IN ('signed','accepted') OR signed_at IS NOT NULL)
  UNION ALL
  SELECT 1 FROM document_fields WHERE document_id = target_document
    AND (value IS NOT NULL OR completed_at IS NOT NULL)
) AS retained;
$$ LANGUAGE sql STABLE;
CREATE FUNCTION hash_guard_document_package_draft_v1() RETURNS trigger AS $$
DECLARE target UUID; tenant UUID; actor UUID; allow_deleted BOOLEAN := false;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target := OLD.document_id; tenant := OLD.org_id; actor := OLD.created_by;
        allow_deleted := NOT EXISTS(SELECT 1 FROM document_attachment_drafts_v1 WHERE package_id=OLD.id);
    ELSE
        target := NEW.document_id; tenant := NEW.org_id; actor := NEW.created_by;
    END IF;
    PERFORM 1 FROM documents WHERE id=target AND org_id=tenant AND status='draft'
        AND (deleted_at IS NULL OR allow_deleted) FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'package root is not editable' USING ERRCODE='23514'; END IF;
    IF TG_OP='INSERT' THEN
        IF NOT EXISTS (SELECT 1 FROM documents WHERE id=target AND source_kind='pdf' AND NOT is_envelope AND parent_envelope_id IS NULL)
           OR NOT EXISTS (SELECT 1 FROM users WHERE id=actor AND org_id=tenant)
           OR hash_package_has_signing_evidence_v1(target,tenant) THEN
            RAISE EXCEPTION 'package root or actor is ineligible' USING ERRCODE='23514';
        END IF;
    ELSIF TG_OP='UPDATE' THEN
        IF ROW(NEW.id,NEW.document_id,NEW.org_id,NEW.created_by,NEW.created_at)
            IS DISTINCT FROM ROW(OLD.id,OLD.document_id,OLD.org_id,OLD.created_by,OLD.created_at)
            OR NEW.draft_generation <> OLD.draft_generation + 1 THEN
            RAISE EXCEPTION 'package identity or generation is immutable' USING ERRCODE='23514';
        END IF;
    END IF;
    UPDATE documents SET updated_at=GREATEST(clock_timestamp(),updated_at + interval '1 microsecond') WHERE id=target AND org_id=tenant;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_package_draft_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_packages_v1
    FOR EACH ROW EXECUTE FUNCTION hash_guard_document_package_draft_v1();

CREATE FUNCTION hash_guard_document_attachment_draft_v1() RETURNS trigger AS $$
DECLARE p document_packages_v1%ROWTYPE; root UUID; tenant UUID; pkg UUID; selected RECORD;
BEGIN
    IF TG_OP='DELETE' THEN pkg:=OLD.package_id; tenant:=OLD.org_id;
    ELSE pkg:=NEW.package_id; tenant:=NEW.org_id; END IF;
    SELECT document_id INTO STRICT root FROM document_packages_v1 WHERE id=pkg AND org_id=tenant;
    -- Native callers lock the union of root/source document IDs globally sorted
    -- before package rows. NOWAIT also makes direct-query lock inversion refuse
    -- rather than wait while holding a member row in an opposite lock order.
    IF TG_OP='INSERT' THEN
        PERFORM id FROM documents WHERE org_id=tenant AND id IN (root,NEW.member_document_id) ORDER BY id FOR UPDATE NOWAIT;
    ELSE
        PERFORM id FROM documents WHERE id=root AND org_id=tenant FOR UPDATE NOWAIT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM documents WHERE id=root AND org_id=tenant AND status='draft' AND deleted_at IS NULL
        AND source_kind='pdf' AND NOT is_envelope AND parent_envelope_id IS NULL)
        OR hash_package_has_signing_evidence_v1(root,tenant) THEN
        RAISE EXCEPTION 'attachment root is not editable' USING ERRCODE='23514';
    END IF;
    SELECT * INTO STRICT p FROM document_packages_v1 WHERE id=pkg AND org_id=tenant FOR UPDATE NOWAIT;
    IF TG_OP='INSERT' THEN
        SELECT d.id,d.pdf_storage_key,d.pdf_sha256,d.pdf_storage_version_id,d.html_source_json ->> 'commitment' AS origin,
            COALESCE(d.html_current_source_json,d.html_source_json) ->> 'commitment' AS current_commitment,
            d.html_source_json IS NOT NULL AS is_html,d.html_current_materialization_id,d.html_current_materialization_sequence,
            d.html_current_page_count,d.html_reviewed_pdf_sha256,d.html_reviewed_by,d.html_reviewed_at,d.html_reviewed_materialization_id
        INTO STRICT selected FROM documents d WHERE d.id=NEW.member_document_id AND d.org_id=tenant AND d.id<>root
            AND d.status='draft' AND d.deleted_at IS NULL AND d.source_kind='pdf' AND NOT d.is_envelope AND d.parent_envelope_id IS NULL;
        IF NEW.pdf_key IS DISTINCT FROM selected.pdf_storage_key OR NEW.pdf_sha256 IS DISTINCT FROM selected.pdf_sha256
            OR NEW.pdf_version_id IS DISTINCT FROM selected.pdf_storage_version_id
            OR hash_package_has_signing_evidence_v1(NEW.member_document_id,tenant)
            OR EXISTS(SELECT 1 FROM documents WHERE id=root AND pdf_storage_key=NEW.pdf_key AND pdf_storage_version_id=NEW.pdf_version_id)
            OR EXISTS (SELECT 1 FROM document_packages_v1 nested JOIN document_attachment_drafts_v1 a ON a.package_id=nested.id WHERE nested.document_id=NEW.member_document_id) THEN
            RAISE EXCEPTION 'selected attachment identity differs from source' USING ERRCODE='23514';
        END IF;
        IF NOT selected.is_html THEN
            IF NEW.source_kind <> 'pdf-import' THEN RAISE EXCEPTION 'attachment source kind differs' USING ERRCODE='23514'; END IF;
        ELSE
            IF NEW.source_commitment IS DISTINCT FROM decode(selected.current_commitment,'hex')
                OR NEW.origin_commitment IS DISTINCT FROM decode(selected.origin,'hex')
                OR selected.html_reviewed_pdf_sha256 IS DISTINCT FROM NEW.pdf_sha256
                OR selected.html_reviewed_by IS NULL OR selected.html_reviewed_at IS NULL
                OR selected.html_reviewed_materialization_id IS DISTINCT FROM selected.html_current_materialization_id
                OR NEW.materialization_id IS DISTINCT FROM selected.html_current_materialization_id
                OR NEW.materialization_sequence IS DISTINCT FROM selected.html_current_materialization_sequence
                OR (selected.html_current_page_count IS NOT NULL AND NEW.pdf_pages <> selected.html_current_page_count)
                OR NEW.source_kind IS DISTINCT FROM (CASE WHEN selected.html_current_materialization_id IS NULL THEN 'html-origin' ELSE 'html-materialization' END) THEN
                RAISE EXCEPTION 'selected HTML attachment differs from reviewed source' USING ERRCODE='23514';
            END IF;
        END IF;
    ELSIF TG_OP='UPDATE' THEN
        IF ROW(NEW.package_id,NEW.org_id,NEW.member_document_id,NEW.pdf_key,NEW.pdf_version_id,NEW.pdf_sha256,NEW.pdf_bytes,NEW.pdf_pages,
            NEW.source_kind,NEW.source_commitment,NEW.origin_commitment,NEW.materialization_id,NEW.materialization_sequence,NEW.created_at)
            IS DISTINCT FROM ROW(OLD.package_id,OLD.org_id,OLD.member_document_id,OLD.pdf_key,OLD.pdf_version_id,OLD.pdf_sha256,OLD.pdf_bytes,OLD.pdf_pages,
            OLD.source_kind,OLD.source_commitment,OLD.origin_commitment,OLD.materialization_id,OLD.materialization_sequence,OLD.created_at) THEN
            RAISE EXCEPTION 'selected attachment pins require explicit replacement' USING ERRCODE='23514';
        END IF;
    END IF;
    UPDATE document_packages_v1 SET draft_generation=draft_generation+1 WHERE id=pkg AND org_id=tenant;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_attachment_draft_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_attachment_drafts_v1
    FOR EACH ROW EXECUTE FUNCTION hash_guard_document_attachment_draft_v1();

-- Deliberate temporary compatibility gate: legacy Send cannot omit selected
-- annexes and still represent a package signature. Replace only with verified
-- package-aware sealing/presentation/consent, never a feature-flag bypass.
CREATE FUNCTION hash_guard_unhandled_document_package_v1() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM document_packages_v1 p JOIN document_attachment_drafts_v1 a ON a.package_id=p.id WHERE p.document_id=OLD.id)
       AND (NEW.status <> 'draft' OR NEW.is_envelope OR NEW.parent_envelope_id IS NOT NULL OR NEW.source_kind <> 'pdf' OR NEW.deleted_at IS NOT NULL) THEN
        RAISE EXCEPTION 'attachment package requires package-aware workflow' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER unhandled_document_package_guard_v1 BEFORE UPDATE OF status,is_envelope,parent_envelope_id,source_kind,deleted_at ON documents
    FOR EACH ROW EXECUTE FUNCTION hash_guard_unhandled_document_package_v1();
-- +goose StatementEnd

-- +goose Down
-- No lossy rollback of selected contractual inputs, even though dispatch is
-- disabled. Explicitly dispose of the empty draft workflow first.
-- +goose StatementBegin
DO $$ BEGIN
    LOCK TABLE documents,document_packages_v1,document_attachment_drafts_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
    IF EXISTS (SELECT 1 FROM document_packages_v1) OR EXISTS (SELECT 1 FROM document_attachment_drafts_v1) THEN
        RAISE EXCEPTION 'draft attachment data prevents rollback' USING ERRCODE='23514';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER unhandled_document_package_guard_v1 ON documents;
DROP FUNCTION hash_guard_unhandled_document_package_v1();
DROP TRIGGER document_attachment_draft_guard_v1 ON document_attachment_drafts_v1;
DROP FUNCTION hash_guard_document_attachment_draft_v1();
DROP TRIGGER document_package_draft_guard_v1 ON document_packages_v1;
DROP FUNCTION hash_guard_document_package_draft_v1();
DROP TABLE document_attachment_drafts_v1;
DROP TABLE document_packages_v1;

DROP FUNCTION hash_package_has_signing_evidence_v1(UUID,UUID);
DROP FUNCTION hash_package_key_v1(TEXT,UUID);
DROP FUNCTION hash_package_label_v1(TEXT,INTEGER,BOOLEAN);
DROP FUNCTION hash_package_opaque_v1(TEXT);
DROP FUNCTION hash_package_trim_v1(TEXT);
