-- Lifecycle writer contract10: quiesce every old Hash writer before Up.
-- The release identity is not a SQL-session fence. Down preserves retained
-- preferences, saved editions and Swedish package consent by refusing rollback.
-- +goose Up
-- Presentation preferences are independent of SMTP credentials, browser UI
-- language, and document/recipient language. Absence retains English/revision0.
CREATE TABLE org_email_preferences_v1 (
    org_id UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK (revision > 0 AND revision <= 9007199254740991),
    locale TEXT NOT NULL CHECK (locale IN ('en','sv')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- The two existing native producers now select immutable saved editions.
-- M119's applied bytes, history trigger, design constraints and heads stay intact.
ALTER TABLE org_email_template_revisions_v1
    DROP CONSTRAINT org_email_template_revisions_v1_kind_check;
ALTER TABLE org_email_template_revisions_v1
    ADD CONSTRAINT org_email_template_revisions_v1_kind_check CHECK (
        kind IN ('email.invite','email.reminder','email.completed_signer',
                 'email.completed_sender','email.changes_requested',
                 'email.new_comment','email.declined','email.quota_warning_80')
    );

-- +goose StatementBegin
-- Existing Send attempts retain their exact English V1 meaning. This is a
-- forward freeze field, never an inference from today's mutable locale.
CREATE FUNCTION hash_package_incorporation_text_for_version_v128(version TEXT) RETURNS TEXT AS $$
 SELECT CASE version
  WHEN 'hash-package-incorporation-v1' THEN hash_package_incorporation_text_v1()
  WHEN 'hash-package-incorporation-sv-v1' THEN 'Jag har granskat och godkänner huvuddokumentet och varje bilaga som anges i detta avtalspaket. Min signatur eller bekräftelse gäller hela paketet som identifieras av de visade kontrollvärdena.'::text
 END;
$$ LANGUAGE sql IMMUTABLE STRICT;
CREATE FUNCTION hash_package_incorporation_sha256_for_version_v128(version TEXT) RETURNS BYTEA AS $$
 SELECT sha256(convert_to(hash_package_incorporation_text_for_version_v128(version),'UTF8'));
$$ LANGUAGE sql IMMUTABLE STRICT;
ALTER TABLE document_package_send_attempts_v1
 ADD COLUMN incorporation_version TEXT NOT NULL DEFAULT 'hash-package-incorporation-v1',
 ADD CONSTRAINT package_send_incorporation_version_v128 CHECK(incorporation_version IN ('hash-package-incorporation-v1','hash-package-incorporation-sv-v1'));
CREATE FUNCTION hash_guard_package_send_incorporation_v128() RETURNS trigger AS $$
DECLARE expected TEXT;
BEGIN
 -- Existing guard already locks the exact root and checks actor/capture/privacy.
 SELECT CASE WHEN d.default_locale='sv' THEN 'hash-package-incorporation-sv-v1' ELSE 'hash-package-incorporation-v1' END INTO STRICT expected
 FROM documents d WHERE d.id=NEW.document_id AND d.org_id=NEW.org_id FOR UPDATE NOWAIT;
 IF NEW.incorporation_version IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'package incorporation differs from the frozen root language' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER package_send_incorporation_guard_v128 BEFORE INSERT ON document_package_send_attempts_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_incorporation_v128();
-- M103's original to_jsonb identity guard also makes this new field immutable.
-- Drop exactly the old one-column constant checks, independent of PostgreSQL's
-- generated/truncated constraint names. No other response constraint is touched.
DO $$ DECLARE item RECORD;
BEGIN
 FOR item IN SELECT c.conname FROM pg_constraint c WHERE c.conrelid='document_package_responses_v1'::regclass AND c.contype='c'
  AND c.conkey IN (ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=c.conrelid AND attname='incorporation_version')]::smallint[],
                  ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=c.conrelid AND attname='incorporation_sha256')]::smallint[])
 LOOP EXECUTE format('ALTER TABLE document_package_responses_v1 DROP CONSTRAINT %I',item.conname); END LOOP;
END $$;
ALTER TABLE document_package_responses_v1 ADD CONSTRAINT package_response_incorporation_pair_v128 CHECK(
 incorporation_version IN ('hash-package-incorporation-v1','hash-package-incorporation-sv-v1')
 AND incorporation_sha256=hash_package_incorporation_sha256_for_version_v128(incorporation_version));
CREATE OR REPLACE FUNCTION hash_package_response_matches_v1(aid UUID,rid UUID) RETURNS BOOLEAN AS $$
DECLARE x document_package_responses_v1%ROWTYPE; a document_package_send_attempts_v1%ROWTYPE;
 e events%ROWTYPE; r recipients%ROWTYPE; s signatures%ROWTYPE; d documents%ROWTYPE; p JSONB;
BEGIN
 SELECT * INTO x FROM document_package_responses_v1 WHERE attempt_id=aid AND recipient_id=rid;
 IF NOT FOUND OR NOT hash_package_response_binding_matches_v1(x.attempt_id,x.org_id,x.document_id) THEN RETURN false; END IF;
 SELECT * INTO STRICT a FROM document_package_send_attempts_v1 WHERE attempt_id=x.attempt_id;
 SELECT * INTO STRICT d FROM documents WHERE id=x.document_id AND org_id=x.org_id;
 SELECT * INTO STRICT r FROM recipients WHERE id=x.recipient_id AND document_id=x.document_id;
 IF ROW(x.package_id,x.capture_revision,x.manifest_sha256,x.legal_commitment_sha256,x.sent_at,x.article13_notice_epoch_at)
  IS DISTINCT FROM ROW(a.package_id,a.capture_revision,a.manifest_sha256,a.legal_commitment_sha256,d.sent_at,a.article13_notice_epoch_at)
  OR x.incorporation_version IS DISTINCT FROM a.incorporation_version
  OR x.incorporation_sha256 IS DISTINCT FROM hash_package_incorporation_sha256_for_version_v128(a.incorporation_version)
  OR r.status<>x.response_kind OR r.role IN ('cc','viewer')
  OR NOT EXISTS(SELECT 1 FROM document_package_send_initial_invite_receipts_v1 i WHERE i.attempt_id=a.attempt_id
   AND i.org_id=x.org_id AND i.document_id=x.document_id AND i.recipient_id=r.id) THEN RETURN false; END IF;
 SELECT * INTO STRICT e FROM events WHERE id=x.response_event_id;
 IF ROW(e.org_id,e.document_id,e.recipient_id,e.kind,e.row_hash,e.created_at)
  IS DISTINCT FROM ROW(x.org_id,x.document_id,x.recipient_id,'document.'||x.response_kind,x.response_event_row_sha256,x.response_event_created_at)
  OR e.actor_user_id IS NOT NULL OR e.payload_hashed IS NULL OR e.row_hash IS DISTINCT FROM hash_package_response_audit_row_sha256_v1(e.id) THEN RETURN false; END IF;
 p:=convert_from(e.payload_hashed,'UTF8')::jsonb;
 IF p->>'package_response_schema' IS DISTINCT FROM 'hash-package-response-v1'
  OR p->>'package_send_attempt_id' IS DISTINCT FROM a.attempt_id::text
  OR p->>'package_id' IS DISTINCT FROM a.package_id::text OR p->>'capture_revision' IS DISTINCT FROM a.capture_revision::text
  OR p->>'manifest_sha256' IS DISTINCT FROM encode(x.manifest_sha256,'hex')
  OR p->>'legal_commitment_sha256' IS DISTINCT FROM encode(x.legal_commitment_sha256,'hex')
  OR p->>'incorporation_version' IS DISTINCT FROM x.incorporation_version
  OR p->>'incorporation_sha256' IS DISTINCT FROM encode(x.incorporation_sha256,'hex')
  OR p->'package_consent' IS DISTINCT FROM 'true'::jsonb OR p->>'response_kind' IS DISTINCT FROM x.response_kind
  OR p->>'notice_schema' IS DISTINCT FROM 'hash-a13-2026-08-31'
  OR jsonb_typeof(p->'notice_snapshot') IS DISTINCT FROM 'object'
  OR p->'notice_snapshot'->>'schema' IS DISTINCT FROM 'hash-a13-2026-08-31'
  OR p->'notice_snapshot'->>'org_id' IS DISTINCT FROM x.org_id::text
  OR p->'notice_snapshot'->>'document_id' IS DISTINCT FROM x.document_id::text
  OR p->'notice_snapshot'->>'recipient_id' IS DISTINCT FROM x.recipient_id::text
  OR p->'notice_snapshot'->>'sent_at' IS DISTINCT FROM hash_article13_canonical_sent_at(x.article13_notice_epoch_at)
  OR p->>'notice_digest' IS NULL OR p->>'notice_digest' !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
 IF x.response_kind='signed' THEN
  SELECT * INTO STRICT s FROM signatures WHERE id=x.signature_id;
  IF NOT d.requires_signature OR r.signed_at IS NULL OR s.document_id<>x.document_id OR s.recipient_id<>x.recipient_id
   OR s.signature_kind NOT IN ('manual','manual_pdf_fit_v1') OR s.presign_execution_id IS NOT NULL
   OR NOT s.image_version_pin_required OR s.image_version_id IS NULL OR NOT hash_package_opaque_v1(s.image_version_id)
   OR hash_package_trim_v1(s.image_version_id) IN ('null','hash:unversioned-development')
   OR NOT hash_package_key_v1(s.image_storage_key,x.org_id) OR octet_length(s.image_sha256)<>32
   OR s.image_sha256=decode(repeat('00',32),'hex') OR NOT isfinite(s.signed_at) OR s.signed_at>e.created_at
   OR s.signer_ip IS DISTINCT FROM e.ip OR COALESCE(s.signer_ua,'')<>COALESCE(e.ua,'')
   OR p->>'signature_id' IS DISTINCT FROM s.id::text OR p->>'image_sha256' IS DISTINCT FROM encode(s.image_sha256,'hex')
   OR p->>'font' IS DISTINCT FROM s.font OR p->>'typed_name' IS DISTINCT FROM s.typed_name
   OR NOT EXISTS(SELECT 1 FROM document_fields f WHERE f.id=s.field_id AND f.document_id=s.document_id AND f.recipient_id=s.recipient_id AND f.type='signature') THEN RETURN false; END IF;
 ELSE
  IF d.requires_signature OR x.signature_id IS NOT NULL OR p->>'signature_id' IS NOT NULL
   OR EXISTS(SELECT 1 FROM signatures WHERE document_id=x.document_id AND recipient_id=x.recipient_id) THEN RETURN false; END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$ LANGUAGE plpgsql STABLE;
-- +goose StatementEnd

-- +goose Down
LOCK TABLE org_email_preferences_v1,org_email_template_heads_v1,org_email_template_revisions_v1,
    document_package_send_attempts_v1,document_package_responses_v1 IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM org_email_preferences_v1)
       OR EXISTS (SELECT 1 FROM org_email_template_revisions_v1
                  WHERE kind IN ('email.declined','email.quota_warning_80')) THEN
        RAISE EXCEPTION 'retained workspace email preferences or editions forbid rollback' USING ERRCODE='23514';
    END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM document_package_send_attempts_v1 WHERE incorporation_version='hash-package-incorporation-sv-v1')
 OR EXISTS(SELECT 1 FROM document_package_responses_v1 WHERE incorporation_version='hash-package-incorporation-sv-v1') THEN
  RAISE EXCEPTION 'retained Swedish package consent prevents M128 downgrade' USING ERRCODE='23514'; END IF;
END $$;
CREATE OR REPLACE FUNCTION hash_package_response_matches_v1(aid UUID,rid UUID) RETURNS BOOLEAN AS $$
DECLARE x document_package_responses_v1%ROWTYPE; a document_package_send_attempts_v1%ROWTYPE;
 e events%ROWTYPE; r recipients%ROWTYPE; s signatures%ROWTYPE; d documents%ROWTYPE; p JSONB;
BEGIN
 SELECT * INTO x FROM document_package_responses_v1 WHERE attempt_id=aid AND recipient_id=rid;
 IF NOT FOUND OR NOT hash_package_response_binding_matches_v1(x.attempt_id,x.org_id,x.document_id) THEN RETURN false; END IF;
 SELECT * INTO STRICT a FROM document_package_send_attempts_v1 WHERE attempt_id=x.attempt_id;
 SELECT * INTO STRICT d FROM documents WHERE id=x.document_id AND org_id=x.org_id;
 SELECT * INTO STRICT r FROM recipients WHERE id=x.recipient_id AND document_id=x.document_id;
 IF ROW(x.package_id,x.capture_revision,x.manifest_sha256,x.legal_commitment_sha256,x.sent_at,x.article13_notice_epoch_at)
  IS DISTINCT FROM ROW(a.package_id,a.capture_revision,a.manifest_sha256,a.legal_commitment_sha256,d.sent_at,a.article13_notice_epoch_at)
  OR x.incorporation_version<>hash_package_incorporation_version_v1() OR x.incorporation_sha256<>hash_package_incorporation_sha256_v1()
  OR r.status<>x.response_kind OR r.role IN ('cc','viewer')
  OR NOT EXISTS(SELECT 1 FROM document_package_send_initial_invite_receipts_v1 i WHERE i.attempt_id=a.attempt_id
   AND i.org_id=x.org_id AND i.document_id=x.document_id AND i.recipient_id=r.id) THEN RETURN false; END IF;
 SELECT * INTO STRICT e FROM events WHERE id=x.response_event_id;
 IF ROW(e.org_id,e.document_id,e.recipient_id,e.kind,e.row_hash,e.created_at)
  IS DISTINCT FROM ROW(x.org_id,x.document_id,x.recipient_id,'document.'||x.response_kind,x.response_event_row_sha256,x.response_event_created_at)
  OR e.actor_user_id IS NOT NULL OR e.payload_hashed IS NULL OR e.row_hash IS DISTINCT FROM hash_package_response_audit_row_sha256_v1(e.id) THEN RETURN false; END IF;
 p:=convert_from(e.payload_hashed,'UTF8')::jsonb;
 IF p->>'package_response_schema' IS DISTINCT FROM 'hash-package-response-v1'
  OR p->>'package_send_attempt_id' IS DISTINCT FROM a.attempt_id::text
  OR p->>'package_id' IS DISTINCT FROM a.package_id::text OR p->>'capture_revision' IS DISTINCT FROM a.capture_revision::text
  OR p->>'manifest_sha256' IS DISTINCT FROM encode(x.manifest_sha256,'hex')
  OR p->>'legal_commitment_sha256' IS DISTINCT FROM encode(x.legal_commitment_sha256,'hex')
  OR p->>'incorporation_version' IS DISTINCT FROM x.incorporation_version
  OR p->>'incorporation_sha256' IS DISTINCT FROM encode(x.incorporation_sha256,'hex')
  OR p->'package_consent' IS DISTINCT FROM 'true'::jsonb OR p->>'response_kind' IS DISTINCT FROM x.response_kind
  OR p->>'notice_schema' IS DISTINCT FROM 'hash-a13-2026-08-31'
  OR jsonb_typeof(p->'notice_snapshot') IS DISTINCT FROM 'object'
  OR p->'notice_snapshot'->>'schema' IS DISTINCT FROM 'hash-a13-2026-08-31'
  OR p->'notice_snapshot'->>'org_id' IS DISTINCT FROM x.org_id::text
  OR p->'notice_snapshot'->>'document_id' IS DISTINCT FROM x.document_id::text
  OR p->'notice_snapshot'->>'recipient_id' IS DISTINCT FROM x.recipient_id::text
  OR p->'notice_snapshot'->>'sent_at' IS DISTINCT FROM hash_article13_canonical_sent_at(x.article13_notice_epoch_at)
  OR p->>'notice_digest' IS NULL OR p->>'notice_digest' !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
 IF x.response_kind='signed' THEN
  SELECT * INTO STRICT s FROM signatures WHERE id=x.signature_id;
  IF NOT d.requires_signature OR r.signed_at IS NULL OR s.document_id<>x.document_id OR s.recipient_id<>x.recipient_id
   OR s.signature_kind NOT IN ('manual','manual_pdf_fit_v1') OR s.presign_execution_id IS NOT NULL
   OR NOT s.image_version_pin_required OR s.image_version_id IS NULL OR NOT hash_package_opaque_v1(s.image_version_id)
   OR hash_package_trim_v1(s.image_version_id) IN ('null','hash:unversioned-development')
   OR NOT hash_package_key_v1(s.image_storage_key,x.org_id) OR octet_length(s.image_sha256)<>32
   OR s.image_sha256=decode(repeat('00',32),'hex') OR NOT isfinite(s.signed_at) OR s.signed_at>e.created_at
   OR s.signer_ip IS DISTINCT FROM e.ip OR COALESCE(s.signer_ua,'')<>COALESCE(e.ua,'')
   OR p->>'signature_id' IS DISTINCT FROM s.id::text OR p->>'image_sha256' IS DISTINCT FROM encode(s.image_sha256,'hex')
   OR p->>'font' IS DISTINCT FROM s.font OR p->>'typed_name' IS DISTINCT FROM s.typed_name
   OR NOT EXISTS(SELECT 1 FROM document_fields f WHERE f.id=s.field_id AND f.document_id=s.document_id AND f.recipient_id=s.recipient_id AND f.type='signature') THEN RETURN false; END IF;
 ELSE
  IF d.requires_signature OR x.signature_id IS NOT NULL OR p->>'signature_id' IS NOT NULL
   OR EXISTS(SELECT 1 FROM signatures WHERE document_id=x.document_id AND recipient_id=x.recipient_id) THEN RETURN false; END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$ LANGUAGE plpgsql STABLE;
ALTER TABLE document_package_responses_v1 DROP CONSTRAINT package_response_incorporation_pair_v128;
ALTER TABLE document_package_responses_v1
 ADD CONSTRAINT package_response_incorporation_version_v107 CHECK(incorporation_version=hash_package_incorporation_version_v1()),
 ADD CONSTRAINT package_response_incorporation_sha256_v107 CHECK(incorporation_sha256=hash_package_incorporation_sha256_v1());
DROP TRIGGER package_send_incorporation_guard_v128 ON document_package_send_attempts_v1;
DROP FUNCTION hash_guard_package_send_incorporation_v128();
ALTER TABLE document_package_send_attempts_v1 DROP COLUMN incorporation_version;
DROP FUNCTION hash_package_incorporation_sha256_for_version_v128(TEXT);
DROP FUNCTION hash_package_incorporation_text_for_version_v128(TEXT);
-- +goose StatementEnd
ALTER TABLE org_email_template_revisions_v1
    DROP CONSTRAINT org_email_template_revisions_v1_kind_check;
ALTER TABLE org_email_template_revisions_v1
    ADD CONSTRAINT org_email_template_revisions_v1_kind_check CHECK (
        kind IN ('email.invite','email.reminder','email.completed_signer',
                 'email.completed_sender','email.changes_requested','email.new_comment')
    );
DROP TABLE org_email_preferences_v1;
