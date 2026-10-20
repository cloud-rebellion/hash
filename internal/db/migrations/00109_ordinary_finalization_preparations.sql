-- +goose Up
-- Ordinary finalization freezes its original four outputs before provider PUT.
-- This is separate from fitted M86 authority and preserves existing M46/M108
-- publication, retention and notification owners.
CREATE TABLE document_ordinary_finalization_preparations_v1 (
 document_id UUID PRIMARY KEY, org_id UUID NOT NULL, mode TEXT NOT NULL CHECK(mode IN('signature','acknowledgement')),
 completion_effective_at TIMESTAMPTZ NOT NULL CHECK(isfinite(completion_effective_at)),
 cutoff TIMESTAMPTZ NOT NULL CHECK(isfinite(cutoff)),retain_until TIMESTAMPTZ NOT NULL CHECK(isfinite(retain_until)),
 final_pdf_sha256 BYTEA NOT NULL CHECK(octet_length(final_pdf_sha256)=32),
 certificate_render_html BYTEA,certificate_render_sha256 BYTEA,
 report_cutoff TIMESTAMPTZ,history_rows BIGINT,report_sha256 BYTEA,
 staged_at TIMESTAMPTZ CHECK(staged_at IS NULL OR isfinite(staged_at)),published_at TIMESTAMPTZ CHECK(published_at IS NULL OR isfinite(published_at)),bodies_retired_at TIMESTAMPTZ CHECK(bodies_retired_at IS NULL OR isfinite(bodies_retired_at)),
 certificate_input_frozen BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(document_id,org_id),
 FOREIGN KEY(document_id,org_id,retain_until) REFERENCES documents(id,org_id,finalization_retain_until) ON DELETE RESTRICT,
 CHECK(retain_until=hash_evidence_retain_until(completion_effective_at,7)),
 CHECK((NOT certificate_input_frozen AND certificate_render_html IS NULL AND certificate_render_sha256 IS NULL AND report_cutoff IS NULL AND history_rows IS NULL AND report_sha256 IS NULL)
 OR (certificate_input_frozen AND certificate_render_sha256 IS NOT NULL AND octet_length(certificate_render_sha256)=32
 AND report_cutoff IS NOT NULL AND report_cutoff=cutoff AND history_rows IS NOT NULL AND history_rows BETWEEN 0 AND 10000 AND report_sha256 IS NOT NULL AND octet_length(report_sha256)=32
 AND ((bodies_retired_at IS NULL AND certificate_render_html IS NOT NULL AND octet_length(certificate_render_html) BETWEEN 1 AND 25165824 AND digest(certificate_render_html,'sha256')=certificate_render_sha256)
 OR (bodies_retired_at IS NOT NULL AND certificate_render_html IS NULL)))),
 CHECK(staged_at IS NULL OR certificate_input_frozen),
 CHECK(published_at IS NULL OR staged_at IS NOT NULL),
 CHECK(bodies_retired_at IS NULL OR published_at IS NOT NULL)
);
CREATE TABLE document_ordinary_finalization_outputs_v1 (
 document_id UUID NOT NULL,org_id UUID NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('final_pdf','certificate_pdf','certificate_payload','certificate_signature')),
 storage_key TEXT NOT NULL,sha256 BYTEA NOT NULL CHECK(octet_length(sha256)=32),bytes BIGINT NOT NULL,
 content_type TEXT NOT NULL,payload BYTEA,
 version_id TEXT CHECK(version_id IS NULL OR (octet_length(version_id) BETWEEN 1 AND 1024 AND btrim(version_id)<>'')),
 verified_at TIMESTAMPTZ CHECK(verified_at IS NULL OR isfinite(verified_at)),
 PRIMARY KEY(document_id,kind),
 FOREIGN KEY(document_id,org_id) REFERENCES document_ordinary_finalization_preparations_v1(document_id,org_id) ON DELETE RESTRICT,
 CHECK(payload IS NULL OR (octet_length(payload)=bytes AND digest(payload,'sha256')=sha256)),
 CHECK((kind IN('final_pdf','certificate_pdf') AND bytes BETWEEN 1 AND 62914560 AND content_type='application/pdf')
 OR (kind='certificate_payload' AND bytes BETWEEN 1 AND 4194304 AND content_type='text/html; charset=utf-8')
 OR (kind='certificate_signature' AND bytes BETWEEN 1 AND 256 AND content_type='text/plain; charset=utf-8')),
 CHECK(storage_key='org/'||org_id::text||'/documents/'||document_id::text||'/'||
 CASE kind WHEN 'final_pdf' THEN 'final-' WHEN 'certificate_pdf' THEN 'audit-' WHEN 'certificate_payload' THEN 'audit-payload-' ELSE 'audit-signature-' END||encode(sha256,'hex')||CASE WHEN kind IN('final_pdf','certificate_pdf') THEN '.pdf' ELSE '.txt' END),
 CHECK(verified_at IS NULL OR version_id IS NOT NULL)
);
-- Exact retained intents at installation remain on their original byte/pin
-- tuple. This exemption cannot be inserted or changed by a later caller.
CREATE TABLE document_ordinary_finalization_legacy_intents_v1 AS SELECT document_id,org_id,mode,completion_effective_at,retain_until,evidence_version_pins_required,
final_pdf_key,final_pdf_sha256,final_pdf_version_id,audit_cert_key,audit_cert_sha256,audit_cert_version_id,
audit_payload_key,audit_payload_sha256,audit_payload_version_id,audit_signature_key,audit_signature_sha256,audit_signature_version_id
FROM document_finalization_intents;
ALTER TABLE document_ordinary_finalization_legacy_intents_v1 ADD PRIMARY KEY(document_id);
-- +goose StatementBegin
CREATE FUNCTION hash_guard_ordinary_finalization_legacy_v1() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'ordinary legacy intent exemption is immutable' USING ERRCODE='23514';END $$;
CREATE TRIGGER ordinary_finalization_legacy_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_ordinary_finalization_legacy_intents_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_ordinary_finalization_legacy_v1();
CREATE FUNCTION hash_ordinary_finalization_legacy_matches_v1(i document_finalization_intents) RETURNS BOOLEAN LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(SELECT 1 FROM document_ordinary_finalization_legacy_intents_v1 x WHERE
 (x.document_id,x.org_id,x.mode,x.completion_effective_at,x.retain_until,x.final_pdf_key,x.final_pdf_sha256,x.audit_cert_key,x.audit_cert_sha256,x.audit_payload_key,x.audit_payload_sha256,x.audit_signature_key,x.audit_signature_sha256)
 IS NOT DISTINCT FROM (i.document_id,i.org_id,i.mode,i.completion_effective_at,i.retain_until,i.final_pdf_key,i.final_pdf_sha256,i.audit_cert_key,i.audit_cert_sha256,i.audit_payload_key,i.audit_payload_sha256,i.audit_signature_key,i.audit_signature_sha256)
 AND ((x.final_pdf_version_id,x.audit_cert_version_id,x.audit_payload_version_id,x.audit_signature_version_id) IS NOT DISTINCT FROM (i.final_pdf_version_id,i.audit_cert_version_id,i.audit_payload_version_id,i.audit_signature_version_id)
 OR (NOT x.evidence_version_pins_required AND x.final_pdf_version_id IS NULL AND x.audit_cert_version_id IS NULL AND x.audit_payload_version_id IS NULL AND x.audit_signature_version_id IS NULL AND i.evidence_version_pins_required)))
$$;
CREATE FUNCTION hash_guard_ordinary_finalization_preparation_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE d documents%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT d FROM documents WHERE id=OLD.document_id AND org_id=OLD.org_id FOR UPDATE;
  IF OLD.retain_until>=clock_timestamp() OR d.deleted_at IS NULL OR EXISTS(SELECT 1 FROM data_subject_requests r WHERE r.org_id=d.org_id AND (r.document_id=d.id OR r.document_id IS NULL) AND r.status IN('open','in_progress')) THEN RAISE EXCEPTION 'ordinary finalization source is retained' USING ERRCODE='23514';END IF;RETURN OLD;
 END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  IF d.status<>'finalizing' OR NOT d.completion_effective_at_bound OR NEW.completion_effective_at IS DISTINCT FROM d.completion_effective_at OR NEW.cutoff IS DISTINCT FROM d.updated_at OR NEW.retain_until IS DISTINCT FROM d.finalization_retain_until OR (NEW.mode='signature') IS DISTINCT FROM d.requires_signature OR d.fits_index_required OR EXISTS(SELECT 1 FROM signatures s WHERE s.document_id=d.id AND s.signature_kind='manual_pdf_fit_v1') THEN
   RAISE EXCEPTION 'ordinary finalization preparation differs from frozen root' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.document_id,NEW.org_id,NEW.mode,NEW.completion_effective_at,NEW.cutoff,NEW.retain_until,NEW.final_pdf_sha256,NEW.created_at) IS DISTINCT FROM (OLD.document_id,OLD.org_id,OLD.mode,OLD.completion_effective_at,OLD.cutoff,OLD.retain_until,OLD.final_pdf_sha256,OLD.created_at)
   OR (OLD.certificate_input_frozen AND (NOT NEW.certificate_input_frozen OR (NEW.certificate_render_sha256,NEW.report_cutoff,NEW.history_rows,NEW.report_sha256) IS DISTINCT FROM (OLD.certificate_render_sha256,OLD.report_cutoff,OLD.history_rows,OLD.report_sha256)))
   OR (OLD.certificate_input_frozen AND NEW.certificate_render_html IS DISTINCT FROM OLD.certificate_render_html AND NOT(NEW.certificate_render_html IS NULL AND NEW.bodies_retired_at IS NOT NULL AND NEW.published_at IS NOT NULL))
   OR (OLD.bodies_retired_at IS NOT NULL AND NEW.bodies_retired_at IS DISTINCT FROM OLD.bodies_retired_at)
   OR (OLD.staged_at IS NOT NULL AND NEW.staged_at IS DISTINCT FROM OLD.staged_at) OR (OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at)
   OR (NEW.published_at IS NULL AND d.status<>'finalizing') OR (NEW.published_at IS NOT NULL AND d.status<>'completed') THEN
   RAISE EXCEPTION 'ordinary finalization preparation is immutable' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER ordinary_finalization_preparation_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_ordinary_finalization_preparations_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_ordinary_finalization_preparation_v1();
CREATE FUNCTION hash_guard_ordinary_finalization_output_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE p document_ordinary_finalization_preparations_v1%ROWTYPE;d documents%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT d FROM documents WHERE id=OLD.document_id AND org_id=OLD.org_id FOR UPDATE;
  IF d.deleted_at IS NULL OR EXISTS(SELECT 1 FROM data_subject_requests r WHERE r.org_id=d.org_id AND (r.document_id=d.id OR r.document_id IS NULL) AND r.status IN('open','in_progress')) OR NOT EXISTS(SELECT 1 FROM document_ordinary_finalization_preparations_v1 x WHERE x.document_id=OLD.document_id AND x.org_id=OLD.org_id AND x.retain_until<clock_timestamp()) THEN RAISE EXCEPTION 'ordinary finalization output is retained' USING ERRCODE='23514';END IF;RETURN OLD;
 END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO STRICT p FROM document_ordinary_finalization_preparations_v1 WHERE document_id=d.id AND org_id=d.org_id;
 IF TG_OP='UPDATE' AND p.bodies_retired_at IS NOT NULL AND p.published_at IS NOT NULL AND d.status='completed' AND NEW.payload IS NULL
 AND (NEW.document_id,NEW.org_id,NEW.kind,NEW.storage_key,NEW.sha256,NEW.bytes,NEW.content_type,NEW.version_id,NEW.verified_at) IS NOT DISTINCT FROM (OLD.document_id,OLD.org_id,OLD.kind,OLD.storage_key,OLD.sha256,OLD.bytes,OLD.content_type,OLD.version_id,OLD.verified_at) THEN RETURN NEW;END IF;
 IF d.status<>'finalizing' OR p.staged_at IS NOT NULL OR NEW.payload IS NULL THEN RAISE EXCEPTION 'ordinary finalization output is frozen' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND ((NEW.document_id,NEW.org_id,NEW.kind,NEW.storage_key,NEW.sha256,NEW.bytes,NEW.content_type,NEW.payload) IS DISTINCT FROM (OLD.document_id,OLD.org_id,OLD.kind,OLD.storage_key,OLD.sha256,OLD.bytes,OLD.content_type,OLD.payload)
 OR (OLD.version_id IS NOT NULL AND NEW.version_id IS DISTINCT FROM OLD.version_id) OR (OLD.verified_at IS NOT NULL AND NEW.verified_at IS DISTINCT FROM OLD.verified_at)) THEN
 RAISE EXCEPTION 'ordinary finalization output identity is immutable' USING ERRCODE='23514';END IF;
 IF NEW.kind='final_pdf' AND NEW.sha256<>p.final_pdf_sha256 THEN RAISE EXCEPTION 'ordinary finalization PDF differs' USING ERRCODE='23514';END IF;
 IF NEW.kind<>'final_pdf' AND NOT p.certificate_input_frozen THEN RAISE EXCEPTION 'ordinary certificate input must be frozen first' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER ordinary_finalization_output_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_ordinary_finalization_outputs_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_ordinary_finalization_output_v1();
CREATE FUNCTION hash_ordinary_finalization_intent_matches_v1(i document_finalization_intents) RETURNS BOOLEAN LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(SELECT 1 FROM document_ordinary_finalization_preparations_v1 p
 WHERE p.document_id=i.document_id AND p.org_id=i.org_id AND p.mode=i.mode AND p.completion_effective_at=i.completion_effective_at AND p.retain_until=i.retain_until AND p.staged_at IS NOT NULL AND p.certificate_input_frozen
 AND EXISTS(SELECT 1 FROM document_participant_reports_v1 r WHERE r.document_id=p.document_id AND r.org_id=p.org_id AND r.completion_effective_at=p.completion_effective_at AND r.cutoff=p.report_cutoff AND r.history_rows=p.history_rows AND r.report_sha256=p.report_sha256)
 AND (SELECT count(*) FROM document_ordinary_finalization_outputs_v1 o WHERE o.document_id=p.document_id AND o.org_id=p.org_id AND o.version_id IS NOT NULL AND o.verified_at IS NOT NULL
 AND (CASE o.kind WHEN 'final_pdf' THEN (o.storage_key=i.final_pdf_key AND o.sha256=i.final_pdf_sha256 AND o.version_id=i.final_pdf_version_id) WHEN 'certificate_pdf' THEN (o.storage_key=i.audit_cert_key AND o.sha256=i.audit_cert_sha256 AND o.version_id=i.audit_cert_version_id) WHEN 'certificate_payload' THEN (o.storage_key=i.audit_payload_key AND o.sha256=i.audit_payload_sha256 AND o.version_id=i.audit_payload_version_id) ELSE (o.storage_key=i.audit_signature_key AND o.sha256=i.audit_signature_sha256 AND o.version_id=i.audit_signature_version_id) END))=4)
$$;
CREATE FUNCTION hash_guard_ordinary_finalization_intent_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 -- Validate the immutable triggering tuple even if a caller inserted and
 -- deleted the intent in one transaction. Missing live rows are not a bypass.
 IF NEW.fitted_preparation_id IS NULL AND NOT hash_ordinary_finalization_legacy_matches_v1(NEW) AND NOT hash_ordinary_finalization_intent_matches_v1(NEW) THEN RAISE EXCEPTION 'ordinary intent requires exact durable original outputs' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER ordinary_finalization_intent_guard_v1 AFTER INSERT OR UPDATE ON document_finalization_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_ordinary_finalization_intent_v1();
CREATE FUNCTION hash_guard_ordinary_finalization_completion_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE p document_ordinary_finalization_preparations_v1%ROWTYPE;
BEGIN
 IF NEW.status<>'completed' OR OLD.status='completed' OR NEW.parent_envelope_id IS NOT NULL OR NEW.fits_index_required THEN RETURN NULL;END IF;
 IF EXISTS(SELECT 1 FROM document_ordinary_finalization_legacy_intents_v1 x WHERE
 (x.document_id,x.org_id,x.completion_effective_at,x.retain_until,x.final_pdf_key,x.final_pdf_sha256,x.audit_cert_key,x.audit_cert_sha256,x.audit_payload_key,x.audit_payload_sha256,x.audit_signature_key,x.audit_signature_sha256)
 IS NOT DISTINCT FROM (NEW.id,NEW.org_id,NEW.completion_effective_at,NEW.finalization_retain_until,NEW.final_pdf_key,NEW.final_pdf_sha,NEW.audit_cert_key,NEW.audit_cert_sha256,NEW.audit_payload_key,NEW.audit_payload_sha256,NEW.audit_signature_key,NEW.audit_signature_sha256)
 AND ((x.final_pdf_version_id,x.audit_cert_version_id,x.audit_payload_version_id,x.audit_signature_version_id) IS NOT DISTINCT FROM (NEW.final_pdf_version_id,NEW.audit_cert_version_id,NEW.audit_payload_version_id,NEW.audit_signature_version_id)
 OR (NOT x.evidence_version_pins_required AND x.final_pdf_version_id IS NULL AND x.audit_cert_version_id IS NULL AND x.audit_payload_version_id IS NULL AND x.audit_signature_version_id IS NULL AND NEW.evidence_version_pins_required))) THEN RETURN NULL;END IF;
 SELECT * INTO p FROM document_ordinary_finalization_preparations_v1 x WHERE x.document_id=NEW.id AND x.org_id=NEW.org_id;
 IF NOT FOUND OR p.published_at IS NULL OR p.bodies_retired_at IS NULL OR p.completion_effective_at IS DISTINCT FROM NEW.completion_effective_at OR p.final_pdf_sha256 IS DISTINCT FROM NEW.final_pdf_sha
 OR (SELECT count(*) FROM document_ordinary_finalization_outputs_v1 o WHERE o.document_id=NEW.id AND o.org_id=NEW.org_id AND o.payload IS NULL AND o.verified_at IS NOT NULL AND
 (CASE o.kind WHEN 'final_pdf' THEN (o.storage_key=NEW.final_pdf_key AND o.sha256=NEW.final_pdf_sha AND o.version_id=NEW.final_pdf_version_id) WHEN 'certificate_pdf' THEN (o.storage_key=NEW.audit_cert_key AND o.sha256=NEW.audit_cert_sha256 AND o.version_id=NEW.audit_cert_version_id) WHEN 'certificate_payload' THEN (o.storage_key=NEW.audit_payload_key AND o.sha256=NEW.audit_payload_sha256 AND o.version_id=NEW.audit_payload_version_id) ELSE (o.storage_key=NEW.audit_signature_key AND o.sha256=NEW.audit_signature_sha256 AND o.version_id=NEW.audit_signature_version_id) END))<>4 THEN
 RAISE EXCEPTION 'ordinary completion requires published exact original outputs and retired database bodies' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER ordinary_finalization_completion_guard_v1 AFTER UPDATE OF status ON documents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_ordinary_finalization_completion_v1();
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM document_ordinary_finalization_preparations_v1) THEN RAISE EXCEPTION 'retained ordinary finalization source prevents rollback';END IF;END $$;
DROP TRIGGER ordinary_finalization_completion_guard_v1 ON documents;
DROP TRIGGER ordinary_finalization_intent_guard_v1 ON document_finalization_intents;
DROP TABLE document_ordinary_finalization_outputs_v1,document_ordinary_finalization_preparations_v1,document_ordinary_finalization_legacy_intents_v1;
DROP FUNCTION hash_guard_ordinary_finalization_completion_v1(),hash_guard_ordinary_finalization_intent_v1(),hash_ordinary_finalization_intent_matches_v1(document_finalization_intents),hash_guard_ordinary_finalization_output_v1(),hash_guard_ordinary_finalization_preparation_v1(),hash_ordinary_finalization_legacy_matches_v1(document_finalization_intents),hash_guard_ordinary_finalization_legacy_v1();
-- +goose StatementEnd
