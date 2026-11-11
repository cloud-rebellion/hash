-- +goose Up
-- M124: edit drafts in place. (1) A draft's HTML materialization may move
-- forward to a higher approved revision of the same template. (2) Imported PDFs
-- on a draft get an append-only revision history and a review record, and a
-- draft whose latest PDF revision is unreviewed cannot be sent or sealed.
-- Additive. The origin stays immutable: only design keys are compared to the
-- parent row, everything else is still compared to the origin.
LOCK TABLE documents, html_document_materializations, html_template_revisions, send_sealing_intents, document_attachment_drafts_v1, document_package_capture_members_v1 IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION hash_guard_html_materialization_insert() RETURNS trigger AS $$
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
    IF COALESCE(NEW.source_json->>'schema_version','') <> '3'
       AND NEW.source_json ? 'signing_artifact' THEN
        RAISE EXCEPTION 'Legacy source cannot carry signing artifact' USING ERRCODE = '23514';
    END IF;
    -- New text inputs never replace the original approved design/approval.
    IF (NEW.source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment','signing_artifact','template_version','template_content_sha256','template_approved_by','template_approved_at','master','default_values','master_digest'])
        IS DISTINCT FROM (d.html_source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment','signing_artifact','template_version','template_content_sha256','template_approved_by','template_approved_at','master','default_values','master_digest']) THEN
        RAISE EXCEPTION 'HTML materialization changed its approved origin or schema/parties' USING ERRCODE = '23514';
    END IF;
    -- A design move is allowed only forward to an approved revision of the same
    -- template; schema, identity and party slots were compared above.
    IF NEW.sequence > 1 AND (NEW.source_json -> 'template_version', NEW.source_json -> 'template_content_sha256', NEW.source_json -> 'template_approved_by',
            NEW.source_json -> 'template_approved_at', NEW.source_json -> 'master', NEW.source_json -> 'default_values', NEW.source_json -> 'master_digest')
        IS DISTINCT FROM (p.source_json -> 'template_version', p.source_json -> 'template_content_sha256', p.source_json -> 'template_approved_by',
            p.source_json -> 'template_approved_at', p.source_json -> 'master', p.source_json -> 'default_values', p.source_json -> 'master_digest') THEN
        IF (NEW.source_json ->> 'template_version')::integer IS NULL
           OR (NEW.source_json ->> 'template_version')::integer <= (p.source_json ->> 'template_version')::integer
           OR NOT EXISTS (SELECT 1 FROM html_template_revisions r
                WHERE r.template_id = (NEW.source_json ->> 'template_id')::uuid AND r.org_id = d.org_id
                  AND r.version = (NEW.source_json ->> 'template_version')::integer
                  AND r.approved_by IS NOT NULL AND r.approved_at IS NOT NULL
                  AND r.approved_by = (NEW.source_json ->> 'template_approved_by')::uuid
                  AND r.approved_at = (NEW.source_json ->> 'template_approved_at')::timestamptz
                  AND r.content_sha256 = decode(NEW.source_json ->> 'template_content_sha256', 'hex')) THEN
            RAISE EXCEPTION 'HTML materialization design move requires a newer approved template version' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION hash_document_purpose_v1(meta JSONB) RETURNS TEXT AS $$
 -- Absent or malformed purpose keeps the historical meaning: signing.
 SELECT CASE WHEN jsonb_typeof(meta) = 'object' AND meta #>> ARRAY['hash:document-purpose:v1','purpose'] IN ('document','presentation')
        THEN meta #>> ARRAY['hash:document-purpose:v1','purpose'] ELSE 'signing' END;
$$ LANGUAGE sql IMMUTABLE;
-- Who performed each HTML review. The subject is the current materialization, or
-- the document itself while no materialization row exists. Reviews recorded
-- before M124 have no row here and are left as they were.
CREATE TABLE document_review_kinds_v1 (
 id UUID PRIMARY KEY,
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 document_id UUID NOT NULL,
 subject_id UUID NOT NULL,
 pdf_sha256 BYTEA NOT NULL CHECK (octet_length(pdf_sha256) = 32),
 reviewer_kind TEXT NOT NULL CHECK (reviewer_kind IN ('human','agent')),
 reviewed_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (document_id, org_id) REFERENCES documents(id, org_id) ON DELETE RESTRICT
);
CREATE INDEX document_review_kinds_latest_v1 ON document_review_kinds_v1(document_id, subject_id, created_at DESC);
CREATE TABLE document_pdf_revisions_v1 (
 id UUID PRIMARY KEY,
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 document_id UUID NOT NULL,
 sequence INTEGER NOT NULL CHECK (sequence > 0),
 parent_id UUID REFERENCES document_pdf_revisions_v1(id) ON DELETE RESTRICT,
 previous_pdf_key TEXT NOT NULL, previous_pdf_sha256 BYTEA NOT NULL CHECK (octet_length(previous_pdf_sha256) = 32),
 previous_pdf_version_id TEXT NOT NULL,
 pdf_key TEXT NOT NULL CHECK (pdf_key <> ''), pdf_sha256 BYTEA NOT NULL CHECK (octet_length(pdf_sha256) = 32),
 pdf_version_id TEXT NOT NULL CHECK (pdf_version_id <> ''),
 page_count INTEGER NOT NULL CHECK (page_count BETWEEN 1 AND 500),
 metadata_redaction_report JSONB NOT NULL CHECK (jsonb_typeof(metadata_redaction_report) = 'object'),
 fields_json JSONB NOT NULL, recipients_json JSONB NOT NULL,
 summary TEXT NOT NULL CHECK (octet_length(summary) <= 2000),
 created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (document_id, org_id) REFERENCES documents(id, org_id) ON DELETE RESTRICT,
 UNIQUE (document_id, sequence), UNIQUE (id, document_id, org_id),
 CHECK ((sequence = 1 AND parent_id IS NULL) OR (sequence > 1 AND parent_id IS NOT NULL))
);
CREATE TABLE document_pdf_reviews_v1 (
 id UUID PRIMARY KEY,
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 document_id UUID NOT NULL,
 revision_id UUID NOT NULL,
 pdf_sha256 BYTEA NOT NULL CHECK (octet_length(pdf_sha256) = 32),
 reviewer_kind TEXT NOT NULL CHECK (reviewer_kind IN ('human','agent')),
 reviewed_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 visually_reviewed BOOLEAN NOT NULL CHECK (visually_reviewed),
 reviewed_pages INTEGER NOT NULL CHECK (reviewed_pages > 0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (revision_id, document_id, org_id) REFERENCES document_pdf_revisions_v1(id, document_id, org_id) ON DELETE RESTRICT,
 UNIQUE (revision_id, reviewer_kind)
);
CREATE FUNCTION hash_pdf_revision_append_only_v1() RETURNS trigger AS $$
BEGIN
 -- The one exception: the erasure function below (document deletion purge and
 -- DSR erasure) names the document in a transaction-local setting. Ordinary
 -- updates and deletes stay refused.
 IF TG_OP = 'DELETE' AND current_setting('hash.erase_document_history', true) = OLD.document_id::text THEN
  RETURN OLD;
 END IF;
 RAISE EXCEPTION 'PDF revision history is append-only' USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;
-- Remembers that a live document's replaced-PDF history was erased, so the send
-- gate cannot be passed by the absence of the review it removed. Cascades with
-- the document.
CREATE TABLE document_pdf_history_erasures_v1 (
 document_id UUID PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
 org_id UUID NOT NULL,
 erased_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
-- Erase a document's PDF revision history. purge = true is the hard delete of a
-- soft-deleted draft (also drops the review-kind records that would block the
-- parent row); purge = false is DSR erasure of a live document, which keeps the
-- document and records the erasure. Returns the number of revisions removed.
CREATE FUNCTION hash_erase_document_pdf_history_v1(target UUID, purge BOOLEAN) RETURNS bigint AS $$
DECLARE d documents%ROWTYPE; n bigint := 0; r RECORD;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id = target FOR UPDATE;
 IF purge AND (d.deleted_at IS NULL OR d.status <> 'draft') THEN
  RAISE EXCEPTION 'only a soft-deleted draft can be purged' USING ERRCODE = '23514';
 END IF;
 PERFORM set_config('hash.erase_document_history', target::text, true);
 DELETE FROM document_pdf_reviews_v1 WHERE document_id = target;
 FOR r IN SELECT id FROM document_pdf_revisions_v1 WHERE document_id = target ORDER BY sequence DESC LOOP
  DELETE FROM document_pdf_revisions_v1 WHERE id = r.id;
  n := n + 1;
 END LOOP;
 IF purge THEN
  DELETE FROM document_review_kinds_v1 WHERE document_id = target;
 ELSIF n > 0 THEN
  INSERT INTO document_pdf_history_erasures_v1 (document_id, org_id) VALUES (target, d.org_id)
   ON CONFLICT (document_id) DO UPDATE SET erased_at = clock_timestamp();
 END IF;
 PERFORM set_config('hash.erase_document_history', '', true);
 RETURN n;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_pdf_revisions_append_only_v1 BEFORE UPDATE OR DELETE ON document_pdf_revisions_v1 FOR EACH ROW EXECUTE FUNCTION hash_pdf_revision_append_only_v1();
CREATE TRIGGER document_pdf_reviews_append_only_v1 BEFORE UPDATE OR DELETE ON document_pdf_reviews_v1 FOR EACH ROW EXECUTE FUNCTION hash_pdf_revision_append_only_v1();
CREATE TRIGGER document_review_kinds_append_only_v1 BEFORE UPDATE OR DELETE ON document_review_kinds_v1 FOR EACH ROW EXECUTE FUNCTION hash_pdf_revision_append_only_v1();
CREATE FUNCTION hash_guard_review_kind_insert_v1() RETURNS trigger AS $$
DECLARE d documents%ROWTYPE;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id = NEW.document_id AND org_id = NEW.org_id FOR UPDATE;
 IF d.html_source_json IS NULL OR d.status <> 'draft' OR d.deleted_at IS NOT NULL
    OR NEW.pdf_sha256 IS DISTINCT FROM d.html_reviewed_pdf_sha256 OR NEW.reviewed_by IS DISTINCT FROM d.html_reviewed_by
    OR NEW.subject_id IS DISTINCT FROM COALESCE(d.html_current_materialization_id, d.id)
    OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.reviewed_by AND u.org_id = d.org_id) THEN
  RAISE EXCEPTION 'review kind must describe the document''s current review' USING ERRCODE = '23514';
 END IF;
 IF NEW.reviewer_kind = 'agent' AND hash_document_purpose_v1(d.metadata) = 'signing' THEN
  RAISE EXCEPTION 'a signing document is reviewed by a human in a staff session' USING ERRCODE = '23514';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_review_kinds_insert_v1 BEFORE INSERT ON document_review_kinds_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_review_kind_insert_v1();

CREATE FUNCTION hash_guard_pdf_revision_insert_v1() RETURNS trigger AS $$
DECLARE d documents%ROWTYPE; p document_pdf_revisions_v1%ROWTYPE; ctx RECORD;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id = NEW.document_id AND org_id = NEW.org_id FOR UPDATE;
 IF d.status <> 'draft' OR d.deleted_at IS NOT NULL OR d.source_kind <> 'pdf' OR d.html_source_json IS NOT NULL OR d.is_envelope
    OR d.template_id IS NOT NULL OR d.parent_envelope_id IS NOT NULL
    OR NEW.previous_pdf_key IS DISTINCT FROM d.pdf_storage_key OR NEW.previous_pdf_sha256 IS DISTINCT FROM d.pdf_sha256
    OR NEW.previous_pdf_version_id IS DISTINCT FROM d.pdf_storage_version_id
    OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.created_by AND u.org_id = d.org_id)
    OR d.final_pdf_key IS NOT NULL OR d.final_pdf_sha IS NOT NULL OR d.final_pdf_version_id IS NOT NULL
    OR d.audit_cert_key IS NOT NULL OR d.audit_payload_key IS NOT NULL OR d.audit_signature_key IS NOT NULL
    OR EXISTS (SELECT 1 FROM signatures WHERE document_id = d.id)
    OR EXISTS (SELECT 1 FROM recipients WHERE document_id = d.id AND (status IN ('signed','accepted') OR signed_at IS NOT NULL))
    OR EXISTS (SELECT 1 FROM document_fields WHERE document_id = d.id AND (value IS NOT NULL OR completed_at IS NOT NULL))
    OR EXISTS (SELECT 1 FROM send_sealing_intents WHERE document_id = d.id)
    OR EXISTS (SELECT 1 FROM document_finalization_intents WHERE document_id = d.id) THEN
  RAISE EXCEPTION 'PDF revision requires an unsent unsigned imported draft' USING ERRCODE = '23514';
 END IF;
 SELECT * INTO p FROM document_pdf_revisions_v1 WHERE document_id = d.id ORDER BY sequence DESC LIMIT 1;
 IF (NOT FOUND AND (NEW.sequence <> 1 OR NEW.parent_id IS NOT NULL))
    OR (FOUND AND (NEW.sequence <> p.sequence + 1 OR NEW.parent_id IS DISTINCT FROM p.id
        OR NEW.previous_pdf_sha256 IS DISTINCT FROM p.pdf_sha256 OR NEW.previous_pdf_key IS DISTINCT FROM p.pdf_key)) THEN
  RAISE EXCEPTION 'PDF revision parent is not current' USING ERRCODE = '23514';
 END IF;
 -- The archived layout and recipients must be the canonical current context.
 SELECT * INTO STRICT ctx FROM hash_html_materialization_snapshot_context(d.id);
 IF NEW.fields_json IS DISTINCT FROM ctx.fields_json OR NEW.recipients_json IS DISTINCT FROM ctx.recipients_json THEN
  RAISE EXCEPTION 'PDF revision archive differs from the current context' USING ERRCODE = '23514';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_pdf_revisions_insert_v1 BEFORE INSERT ON document_pdf_revisions_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_pdf_revision_insert_v1();

CREATE FUNCTION hash_guard_pdf_review_insert_v1() RETURNS trigger AS $$
DECLARE r document_pdf_revisions_v1%ROWTYPE; d documents%ROWTYPE;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id = NEW.document_id AND org_id = NEW.org_id FOR UPDATE;
 SELECT * INTO STRICT r FROM document_pdf_revisions_v1 WHERE id = NEW.revision_id;
 IF d.status <> 'draft' OR d.deleted_at IS NOT NULL
    OR r.sequence IS DISTINCT FROM (SELECT max(sequence) FROM document_pdf_revisions_v1 WHERE document_id = d.id)
    OR NEW.pdf_sha256 IS DISTINCT FROM r.pdf_sha256 OR d.pdf_sha256 IS DISTINCT FROM r.pdf_sha256
    OR d.pdf_storage_key IS DISTINCT FROM r.pdf_key OR d.pdf_storage_version_id IS DISTINCT FROM r.pdf_version_id
    OR NEW.reviewed_pages <> r.page_count
    OR (NEW.reviewer_kind = 'agent' AND hash_document_purpose_v1(d.metadata) = 'signing')
    OR (NEW.reviewer_kind = 'agent' AND EXISTS (SELECT 1 FROM document_pdf_reviews_v1 v WHERE v.revision_id = NEW.revision_id))
    OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.reviewed_by AND u.org_id = d.org_id) THEN
  RAISE EXCEPTION 'PDF review must cover every page of the current latest revision' USING ERRCODE = '23514';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_pdf_reviews_insert_v1 BEFORE INSERT ON document_pdf_reviews_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_pdf_review_insert_v1();

-- The one review gate for the bytes of a document's PDF. Send, envelope
-- membership, attachment selection, package capture and template capture all
-- call it. A document whose PDF was never replaced is not gated. A replaced PDF
-- needs a review of its latest revision; a signing document needs a human one.
-- root_signing is set for a member of a signing package or envelope: its bytes
-- reach signers, so it counts as signing whatever its own purpose says, and an
-- HTML member needs the same human review as a document sent on its own.
CREATE FUNCTION hash_pdf_bytes_reviewed_v1(target UUID, root_signing BOOLEAN DEFAULT false) RETURNS void AS $$
DECLARE r document_pdf_revisions_v1%ROWTYPE; d documents%ROWTYPE;
BEGIN
 IF root_signing THEN PERFORM hash_require_human_review_v1(target, true); END IF;
 SELECT * INTO r FROM document_pdf_revisions_v1 WHERE document_id = target ORDER BY sequence DESC LIMIT 1;
 IF NOT FOUND THEN
  IF EXISTS (SELECT 1 FROM document_pdf_history_erasures_v1 e WHERE e.document_id = target) THEN
   RAISE EXCEPTION 'Replaced PDF requires review before sending' USING ERRCODE = '23514';
  END IF;
  RETURN;
 END IF;
 SELECT * INTO STRICT d FROM documents WHERE id = target;
 IF d.pdf_sha256 IS DISTINCT FROM r.pdf_sha256 OR d.pdf_storage_key IS DISTINCT FROM r.pdf_key
    OR NOT EXISTS (SELECT 1 FROM document_pdf_reviews_v1 v WHERE v.revision_id = r.id AND v.pdf_sha256 = r.pdf_sha256) THEN
  RAISE EXCEPTION 'Replaced PDF requires review before sending' USING ERRCODE = '23514';
 END IF;
 IF (root_signing OR hash_document_purpose_v1(d.metadata) = 'signing')
    AND NOT EXISTS (SELECT 1 FROM document_pdf_reviews_v1 v WHERE v.revision_id = r.id AND v.pdf_sha256 = r.pdf_sha256 AND v.reviewer_kind = 'human') THEN
  RAISE EXCEPTION 'Signing document requires a fresh human review before sending' USING ERRCODE = '23514';
 END IF;
END;
$$ LANGUAGE plpgsql;
-- HTML drafts: a signing document needs a recorded human review.
CREATE FUNCTION hash_require_human_review_v1(target UUID, force BOOLEAN DEFAULT false) RETURNS void AS $$
DECLARE d documents%ROWTYPE; kind TEXT;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id = target;
 IF NOT force AND hash_document_purpose_v1(d.metadata) <> 'signing' THEN RETURN; END IF;
 IF d.html_source_json IS NOT NULL AND d.html_reviewed_pdf_sha256 IS NOT NULL THEN
  SELECT k.reviewer_kind INTO kind FROM document_review_kinds_v1 k
   WHERE k.document_id = d.id AND k.subject_id = COALESCE(d.html_current_materialization_id, d.id)
     AND k.pdf_sha256 = d.html_reviewed_pdf_sha256 ORDER BY k.created_at DESC, k.id DESC LIMIT 1;
  IF kind IS DISTINCT FROM 'human' THEN
   RAISE EXCEPTION 'Signing document requires a fresh human review before sending' USING ERRCODE = '23514';
  END IF;
 END IF;
END;
$$ LANGUAGE plpgsql;
CREATE FUNCTION hash_guard_pdf_review_send_v1() RETURNS trigger AS $$
BEGIN
 IF TG_TABLE_NAME = 'documents' THEN
  IF OLD.status = 'draft' AND NEW.status <> 'draft' THEN
   PERFORM hash_pdf_bytes_reviewed_v1(NEW.id); PERFORM hash_require_human_review_v1(NEW.id);
  END IF;
 ELSE
  PERFORM hash_pdf_bytes_reviewed_v1(NEW.document_id); PERFORM hash_require_human_review_v1(NEW.document_id);
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_pdf_review_send_v1 BEFORE UPDATE OF status ON documents FOR EACH ROW EXECUTE FUNCTION hash_guard_pdf_review_send_v1();
CREATE TRIGGER document_pdf_review_sealing_v1 BEFORE INSERT ON send_sealing_intents FOR EACH ROW EXECUTE FUNCTION hash_guard_pdf_review_send_v1();

-- Whether the root of a package is a signing document. Fails closed.
CREATE FUNCTION hash_package_root_signing_v1(pkg UUID) RETURNS boolean AS $$
 SELECT COALESCE((SELECT hash_document_purpose_v1(d.metadata) = 'signing'
   FROM document_packages_v1 p JOIN documents d ON d.id = p.document_id AND d.org_id = p.org_id WHERE p.id = pkg), true);
$$ LANGUAGE sql STABLE;
CREATE FUNCTION hash_guard_pdf_member_review_v1() RETURNS trigger AS $$
BEGIN
 IF TG_TABLE_NAME = 'documents' THEN
  IF NEW.parent_envelope_id IS NOT NULL AND OLD.parent_envelope_id IS DISTINCT FROM NEW.parent_envelope_id THEN
   PERFORM hash_pdf_bytes_reviewed_v1(NEW.id, COALESCE((SELECT hash_document_purpose_v1(e.metadata) = 'signing' FROM documents e WHERE e.id = NEW.parent_envelope_id), true));
  END IF;
 ELSE
  PERFORM hash_pdf_bytes_reviewed_v1(NEW.member_document_id, hash_package_root_signing_v1(NEW.package_id));
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_pdf_review_envelope_child_v1 BEFORE UPDATE OF parent_envelope_id ON documents FOR EACH ROW EXECUTE FUNCTION hash_guard_pdf_member_review_v1();
CREATE TRIGGER document_pdf_review_attachment_v1 BEFORE INSERT ON document_attachment_drafts_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_pdf_member_review_v1();
CREATE TRIGGER document_pdf_review_capture_member_v1 BEFORE INSERT ON document_package_capture_members_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_pdf_member_review_v1();
-- +goose StatementEnd

-- +goose Down
LOCK TABLE documents, html_document_materializations, document_pdf_revisions_v1, document_pdf_reviews_v1, document_review_kinds_v1, document_pdf_history_erasures_v1 IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM document_pdf_revisions_v1) OR EXISTS (SELECT 1 FROM document_pdf_reviews_v1) OR EXISTS (SELECT 1 FROM document_review_kinds_v1)
    OR EXISTS (SELECT 1 FROM document_pdf_history_erasures_v1)
    OR EXISTS (SELECT 1 FROM html_document_materializations m JOIN documents d ON d.id = m.document_id
         WHERE m.sequence > 1 AND (m.source_json -> 'template_version') IS DISTINCT FROM (d.html_source_json -> 'template_version')) THEN
  RAISE EXCEPTION 'retained in-place edit history forbids migration rollback' USING ERRCODE = '23514';
 END IF;
END $$;
DROP TRIGGER document_pdf_review_sealing_v1 ON send_sealing_intents;
DROP TRIGGER document_pdf_review_send_v1 ON documents;
DROP FUNCTION hash_guard_pdf_review_send_v1();
DROP FUNCTION hash_require_human_review_v1(UUID, BOOLEAN);
DROP TRIGGER document_pdf_review_capture_member_v1 ON document_package_capture_members_v1;
DROP TRIGGER document_pdf_review_attachment_v1 ON document_attachment_drafts_v1;
DROP TRIGGER document_pdf_review_envelope_child_v1 ON documents;
DROP FUNCTION hash_guard_pdf_member_review_v1();
DROP FUNCTION hash_package_root_signing_v1(UUID);
DROP FUNCTION hash_pdf_bytes_reviewed_v1(UUID, BOOLEAN);
DROP TRIGGER document_pdf_reviews_insert_v1 ON document_pdf_reviews_v1;
DROP FUNCTION hash_guard_pdf_review_insert_v1();
DROP TRIGGER document_pdf_revisions_insert_v1 ON document_pdf_revisions_v1;
DROP FUNCTION hash_guard_pdf_revision_insert_v1();
DROP TRIGGER document_review_kinds_insert_v1 ON document_review_kinds_v1;
DROP FUNCTION hash_guard_review_kind_insert_v1();
DROP TABLE document_review_kinds_v1;
DROP FUNCTION hash_document_purpose_v1(JSONB);
DROP TABLE document_pdf_reviews_v1;
DROP TABLE document_pdf_revisions_v1;
DROP FUNCTION hash_erase_document_pdf_history_v1(UUID, BOOLEAN);
DROP TABLE document_pdf_history_erasures_v1;
DROP FUNCTION hash_pdf_revision_append_only_v1();
CREATE OR REPLACE FUNCTION hash_guard_html_materialization_insert() RETURNS trigger AS $$
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
    IF COALESCE(NEW.source_json->>'schema_version','') <> '3'
       AND NEW.source_json ? 'signing_artifact' THEN
        RAISE EXCEPTION 'Legacy source cannot carry signing artifact' USING ERRCODE = '23514';
    END IF;
    -- New text inputs never replace the original approved design/approval.
    IF (NEW.source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment','signing_artifact'])
        IS DISTINCT FROM (d.html_source_json - ARRAY['values','sections','content_digest','pdf_key','pdf_sha256','pdf_version_id','commitment','signing_artifact']) THEN
        RAISE EXCEPTION 'HTML materialization changed its approved origin' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
