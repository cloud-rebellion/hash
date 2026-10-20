-- +goose Up
-- One mandatory separate report reuses the existing AuditCertificate artifacts.
-- No historical bytes, old consent or retrospective history proof is invented.
CREATE TABLE document_participant_reports_v1 (
 document_id UUID NOT NULL,org_id UUID NOT NULL,completion_effective_at TIMESTAMPTZ NOT NULL CHECK(isfinite(completion_effective_at)),
 schema_version TEXT NOT NULL CHECK(schema_version='hash-participant-report-v1'),
 cutoff TIMESTAMPTZ NOT NULL CHECK(isfinite(cutoff)),history_rows BIGINT NOT NULL CHECK(history_rows BETWEEN 0 AND 10000),
 report_sha256 BYTEA NOT NULL CHECK(octet_length(report_sha256)=32),
 final_pdf_sha256 BYTEA NOT NULL CHECK(octet_length(final_pdf_sha256)=32),
 audit_cert_sha256 BYTEA NOT NULL CHECK(octet_length(audit_cert_sha256)=32),
 audit_payload_sha256 BYTEA NOT NULL CHECK(octet_length(audit_payload_sha256)=32),
 audit_signature_sha256 BYTEA NOT NULL CHECK(octet_length(audit_signature_sha256)=32),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(document_id,completion_effective_at)
);
-- Only exact pre-migration retained intents are grandfathered, without calling
-- their old payload a complete participant report. New intents cannot opt out.
CREATE TABLE document_participant_report_legacy_intents_v1 (
 document_id UUID PRIMARY KEY,org_id UUID NOT NULL,completion_effective_at TIMESTAMPTZ NOT NULL,
 audit_payload_sha256 BYTEA NOT NULL
);
INSERT INTO document_participant_report_legacy_intents_v1
 SELECT document_id,org_id,completion_effective_at,audit_payload_sha256 FROM document_finalization_intents;
CREATE TABLE document_participant_report_deliveries_v1 (
 document_id UUID NOT NULL,org_id UUID NOT NULL,completion_effective_at TIMESTAMPTZ NOT NULL,
 audience TEXT NOT NULL CHECK(audience IN ('sender','recipient')),recipient_id UUID NOT NULL,
 email_delivery_id UUID NOT NULL UNIQUE,message_sha256 BYTEA NOT NULL CHECK(octet_length(message_sha256)=32),
 final_pdf_sha256 BYTEA NOT NULL CHECK(octet_length(final_pdf_sha256)=32),
 audit_cert_sha256 BYTEA NOT NULL CHECK(octet_length(audit_cert_sha256)=32),
 PRIMARY KEY(document_id,completion_effective_at,audience,recipient_id),
 FOREIGN KEY(document_id,completion_effective_at) REFERENCES document_participant_reports_v1(document_id,completion_effective_at) ON DELETE RESTRICT,
 CHECK((audience='sender' AND recipient_id='00000000-0000-0000-0000-000000000000') OR (audience='recipient' AND recipient_id<>'00000000-0000-0000-0000-000000000000'))
);
-- +goose StatementBegin
CREATE FUNCTION hash_guard_participant_report_immutable_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION 'participant report evidence is immutable' USING ERRCODE='23514';END $$;
CREATE TRIGGER participant_report_immutable_v1 BEFORE UPDATE OR DELETE ON document_participant_reports_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_participant_report_immutable_v1();
CREATE TRIGGER participant_report_delivery_immutable_v1 BEFORE UPDATE OR DELETE ON document_participant_report_deliveries_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_participant_report_immutable_v1();
CREATE TRIGGER participant_report_legacy_immutable_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_participant_report_legacy_intents_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_participant_report_immutable_v1();
CREATE FUNCTION hash_guard_participant_report_intent_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE i document_finalization_intents%ROWTYPE;r document_participant_reports_v1%ROWTYPE;
BEGIN
 SELECT * INTO i FROM document_finalization_intents WHERE document_id=NEW.document_id;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT * INTO r FROM document_participant_reports_v1 WHERE document_id=i.document_id AND completion_effective_at=i.completion_effective_at;
 IF NOT FOUND OR r.org_id<>i.org_id OR r.final_pdf_sha256<>i.final_pdf_sha256 OR r.audit_cert_sha256<>i.audit_cert_sha256 OR r.audit_payload_sha256<>i.audit_payload_sha256 OR r.audit_signature_sha256<>i.audit_signature_sha256 THEN
  RAISE EXCEPTION 'new finalization intent requires exact participant report' USING ERRCODE='23514';
 END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER participant_report_intent_v1 AFTER INSERT ON document_finalization_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_participant_report_intent_v1();
CREATE FUNCTION hash_guard_participant_report_receipt_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE d documents%ROWTYPE;i document_finalization_intents%ROWTYPE;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO STRICT i FROM document_finalization_intents WHERE document_id=d.id AND org_id=d.org_id;
 IF d.status<>'finalizing' OR d.completion_effective_at IS DISTINCT FROM NEW.completion_effective_at OR NEW.cutoff<>d.updated_at
 OR i.completion_effective_at<>NEW.completion_effective_at OR i.final_pdf_sha256<>NEW.final_pdf_sha256 OR i.audit_cert_sha256<>NEW.audit_cert_sha256 OR i.audit_payload_sha256<>NEW.audit_payload_sha256 OR i.audit_signature_sha256<>NEW.audit_signature_sha256 THEN
 RAISE EXCEPTION 'participant report differs from retained finalization intent' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER participant_report_receipt_v1 BEFORE INSERT ON document_participant_reports_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_participant_report_receipt_v1();
CREATE FUNCTION hash_guard_participant_report_delivery_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE d documents%ROWTYPE;e email_deliveries%ROWTYPE;r document_participant_reports_v1%ROWTYPE;target TEXT;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id;
 SELECT * INTO STRICT r FROM document_participant_reports_v1 WHERE document_id=d.id AND completion_effective_at=NEW.completion_effective_at;
 SELECT * INTO STRICT e FROM email_deliveries WHERE id=NEW.email_delivery_id;
 IF NEW.audience='sender' THEN SELECT email INTO STRICT target FROM users WHERE id=d.sender_id AND org_id=d.org_id;
 ELSE SELECT email INTO STRICT target FROM recipients WHERE id=NEW.recipient_id AND document_id=d.id;END IF;
 IF d.status<>'completed' OR d.completion_effective_at<>NEW.completion_effective_at OR NEW.final_pdf_sha256<>r.final_pdf_sha256 OR NEW.audit_cert_sha256<>r.audit_cert_sha256 OR e.to_email<>target OR e.status<>'pending' OR NEW.message_sha256<>hash_package_send_message_sha256_v1(e.id) THEN
 RAISE EXCEPTION 'participant report delivery differs from completion outbox' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER participant_report_delivery_v1 BEFORE INSERT ON document_participant_report_deliveries_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_participant_report_delivery_v1();
-- This consumes a fresh credential actually persisted by the existing native
-- completion owner. It neither grants credentials nor independently derives
-- conditional required signature roles or enables unsupported recipient roles.
CREATE FUNCTION hash_report_delivery_for_issued_credential_v1(requires_signature BOOLEAN,recipient_role TEXT,recipient_status TEXT,token_expires_at TIMESTAMPTZ) RETURNS BOOLEAN LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(recipient_role<>'cc'
 AND ((requires_signature AND recipient_status='signed') OR (NOT requires_signature AND recipient_status='accepted'))
 AND token_expires_at>transaction_timestamp(),FALSE)
$$;
CREATE FUNCTION hash_guard_participant_report_completion_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE d documents%ROWTYPE;r document_participant_reports_v1%ROWTYPE;n BIGINT;
BEGIN
 IF NEW.status<>'completed' OR OLD.status='completed' OR NEW.parent_envelope_id IS NOT NULL THEN RETURN NULL;END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.id AND org_id=NEW.org_id;
 IF EXISTS(SELECT 1 FROM document_participant_report_legacy_intents_v1 l WHERE l.document_id=d.id AND l.org_id=d.org_id AND l.completion_effective_at=d.completion_effective_at AND l.audit_payload_sha256=d.audit_payload_sha256) THEN RETURN NULL;END IF;
 SELECT * INTO r FROM document_participant_reports_v1 WHERE document_id=d.id AND completion_effective_at=d.completion_effective_at;
 IF NOT FOUND OR r.org_id<>d.org_id OR r.final_pdf_sha256<>d.final_pdf_sha OR r.audit_cert_sha256<>d.audit_cert_sha256 OR r.audit_payload_sha256<>d.audit_payload_sha256 OR r.audit_signature_sha256<>d.audit_signature_sha256 THEN RAISE EXCEPTION 'completion requires exact mandatory participant report' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM document_participant_report_deliveries_v1 x WHERE x.document_id=d.id AND x.completion_effective_at=d.completion_effective_at AND x.audience='sender') THEN RAISE EXCEPTION 'completion requires sender report delivery reference' USING ERRCODE='23514';END IF;
 -- The existing native required-role owner decides actual eligibility. It
 -- first expires EVERY ceremony credential at transaction_timestamp(), then
 -- reissues a distinct completion credential only for its exact eligible
 -- signed required roles (or non-CC acceptors). Consume that persisted effect
 -- instead of inventing a second SQL conditional-block/role interpreter.
 SELECT count(*) INTO n FROM recipients p WHERE p.document_id=d.id
 AND hash_report_delivery_for_issued_credential_v1(d.requires_signature,p.role,p.status,p.magic_token_expires_at)
 AND NOT EXISTS(SELECT 1 FROM document_participant_report_deliveries_v1 x WHERE x.document_id=d.id AND x.completion_effective_at=d.completion_effective_at AND x.audience='recipient' AND x.recipient_id=p.id);
 IF n<>0 THEN RAISE EXCEPTION 'completion requires all participant report delivery references' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER participant_report_completion_v1 AFTER UPDATE OF status ON documents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_participant_report_completion_v1();
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM document_participant_reports_v1) OR EXISTS(SELECT 1 FROM document_participant_report_deliveries_v1) THEN RAISE EXCEPTION 'retained participant report evidence prevents rollback';END IF;END $$;
DROP TRIGGER participant_report_completion_v1 ON documents;
DROP TRIGGER participant_report_delivery_v1 ON document_participant_report_deliveries_v1;
DROP TRIGGER participant_report_receipt_v1 ON document_participant_reports_v1;
DROP TRIGGER participant_report_intent_v1 ON document_finalization_intents;
DROP TABLE document_participant_report_deliveries_v1,document_participant_reports_v1,document_participant_report_legacy_intents_v1;
DROP FUNCTION hash_guard_participant_report_completion_v1(),hash_guard_participant_report_delivery_v1(),hash_guard_participant_report_receipt_v1(),hash_guard_participant_report_intent_v1(),hash_guard_participant_report_immutable_v1();
DROP FUNCTION hash_report_delivery_for_issued_credential_v1(BOOLEAN,TEXT,TEXT,TIMESTAMPTZ);
-- +goose StatementEnd
