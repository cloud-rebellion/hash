-- +goose Up
-- Later changes are separate documents. This migration never edits original
-- contracts, recipients, response/report bytes, or historical artifact pins.
CREATE TABLE document_amendments_v1 (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 org_id UUID NOT NULL,original_document_id UUID NOT NULL,document_id UUID NOT NULL UNIQUE,
 revision BIGINT NOT NULL CHECK(revision BETWEEN 1 AND 64),
 previous_revision BIGINT NOT NULL CHECK(previous_revision=revision-1),predecessor_id UUID,
 request_id UUID NOT NULL,request_sha256 BYTEA NOT NULL CHECK(octet_length(request_sha256)=32),
 mode TEXT NOT NULL CHECK(mode IN ('signature','acknowledgement','agreed_notice')),
 basis BYTEA NOT NULL CHECK(octet_length(basis) BETWEEN 2 AND 16384),
 basis_sha256 BYTEA NOT NULL CHECK(octet_length(basis_sha256)=32 AND basis_sha256=sha256(convert_to('hash:later-amendment-basis:v1','UTF8')||decode('00','hex')||basis)),
 original_pins BYTEA NOT NULL CHECK(octet_length(original_pins) BETWEEN 2 AND 32768),
 original_pins_sha256 BYTEA NOT NULL CHECK(original_pins_sha256=sha256(original_pins)),
 file_set BYTEA NOT NULL CHECK(octet_length(file_set) BETWEEN 2 AND 65536),
 file_commitment_sha256 BYTEA NOT NULL CHECK(file_commitment_sha256=sha256(convert_to('hash:later-amendment-files:v1','UTF8')||decode('00','hex')||file_set)),
 created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 owner_alert_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 owner_alert_email_delivery_id UUID NOT NULL UNIQUE REFERENCES email_deliveries(id) ON DELETE RESTRICT,
 owner_alert_message_sha256 BYTEA NOT NULL CHECK(octet_length(owner_alert_message_sha256)=32),
 event_id UUID NOT NULL UNIQUE,
 UNIQUE(original_document_id,revision),UNIQUE(original_document_id,previous_revision),
 UNIQUE(org_id,original_document_id,request_id),UNIQUE(id,org_id),
 CHECK(original_document_id<>document_id),
 CHECK((previous_revision=0)=(predecessor_id IS NULL)),
 FOREIGN KEY(predecessor_id,org_id) REFERENCES document_amendments_v1(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(original_document_id,org_id) REFERENCES documents(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE RESTRICT
);
CREATE INDEX document_amendments_original_v1 ON document_amendments_v1(org_id,original_document_id,revision);
-- A policy row is usable only after an actual source producer and Send freeze
-- installs it. There is deliberately no client flag or metadata-to-policy cast.
CREATE TABLE document_amendment_policies_v1 (
 id UUID PRIMARY KEY,org_id UUID NOT NULL,document_id UUID NOT NULL,
 basis BYTEA NOT NULL CHECK(octet_length(basis) BETWEEN 2 AND 16384),
 basis_sha256 BYTEA NOT NULL CHECK(basis_sha256=sha256(convert_to('hash:later-amendment-basis:v1','UTF8')||decode('00','hex')||basis)),
 presented_source_sha256 BYTEA NOT NULL CHECK(octet_length(presented_source_sha256)=32),
 presented_pdf_sha256 BYTEA NOT NULL CHECK(octet_length(presented_pdf_sha256)=32),
 presented_pdf_version_id TEXT NOT NULL CHECK(hash_package_opaque_v1(presented_pdf_version_id)),
 frozen_at TIMESTAMPTZ NOT NULL CHECK(isfinite(frozen_at)),
 frozen_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 UNIQUE(id,org_id,document_id),UNIQUE(org_id,document_id),
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE RESTRICT
);
CREATE TABLE document_amendment_notices_v1 (
 id UUID PRIMARY KEY,amendment_id UUID NOT NULL UNIQUE,org_id UUID NOT NULL,
 request_id UUID NOT NULL,request_sha256 BYTEA NOT NULL CHECK(octet_length(request_sha256)=32),
 subject TEXT NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 256 AND subject !~ E'[\\r\\n]'),
 text_body TEXT NOT NULL CHECK(octet_length(text_body) BETWEEN 1 AND 16384),
 notice_bytes BYTEA NOT NULL CHECK(octet_length(notice_bytes) BETWEEN 2 AND 32768),
 notice_sha256 BYTEA NOT NULL CHECK(notice_sha256=sha256(convert_to('hash:later-amendment-notice:v1','UTF8')||decode('00','hex')||notice_bytes)),
 file_commitment_sha256 BYTEA NOT NULL CHECK(octet_length(file_commitment_sha256)=32),
 issued_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(issued_at)),
 retain_until TIMESTAMPTZ NOT NULL CHECK(isfinite(retain_until) AND retain_until=hash_evidence_retain_until(issued_at,7)),
 owner_alert_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 owner_alert_email_delivery_id UUID NOT NULL UNIQUE REFERENCES email_deliveries(id) ON DELETE RESTRICT,
 owner_alert_message_sha256 BYTEA NOT NULL CHECK(octet_length(owner_alert_message_sha256)=32),
 event_id UUID NOT NULL UNIQUE,UNIQUE(id,org_id),UNIQUE(org_id,amendment_id,request_id),
 FOREIGN KEY(amendment_id,org_id) REFERENCES document_amendments_v1(id,org_id) ON DELETE RESTRICT
);
CREATE TABLE document_amendment_notice_deliveries_v1 (
 notice_id UUID NOT NULL,org_id UUID NOT NULL,position SMALLINT NOT NULL CHECK(position BETWEEN 0 AND 31),
 email_delivery_id UUID NOT NULL UNIQUE REFERENCES email_deliveries(id) ON DELETE RESTRICT,recipient_email TEXT NOT NULL CHECK(octet_length(recipient_email) BETWEEN 3 AND 254),
 message_sha256 BYTEA NOT NULL CHECK(octet_length(message_sha256)=32),
 PRIMARY KEY(notice_id,position),UNIQUE(notice_id,recipient_email),
 FOREIGN KEY(notice_id,org_id) REFERENCES document_amendment_notices_v1(id,org_id) ON DELETE RESTRICT
);
CREATE TABLE document_amendment_notice_access_v1 (
 id UUID PRIMARY KEY,org_id UUID NOT NULL,notice_id UUID NOT NULL,
 email_delivery_id UUID NOT NULL UNIQUE REFERENCES email_deliveries(id) ON DELETE RESTRICT,recipient_email TEXT NOT NULL CHECK(octet_length(recipient_email) BETWEEN 3 AND 254),
 token_sha256 BYTEA NOT NULL UNIQUE CHECK(octet_length(token_sha256)=32),
 file_commitment_sha256 BYTEA NOT NULL CHECK(octet_length(file_commitment_sha256)=32),
 created_at TIMESTAMPTZ NOT NULL,expires_at TIMESTAMPTZ NOT NULL,
 revoked_at TIMESTAMPTZ,revoked_by UUID REFERENCES users(id) ON DELETE RESTRICT,
 CHECK(isfinite(created_at) AND isfinite(expires_at) AND expires_at=created_at+interval '7 days'),
 CHECK((revoked_at IS NULL)=(revoked_by IS NULL)),CHECK(revoked_at IS NULL OR (isfinite(revoked_at) AND revoked_at>=created_at)),
 FOREIGN KEY(notice_id,org_id) REFERENCES document_amendment_notices_v1(id,org_id) ON DELETE RESTRICT
);
-- +goose StatementBegin
CREATE FUNCTION hash_guard_amendment_notice_access_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'notice capability identity is retained' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' THEN
 IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revoked_by IS NULL
 OR (to_jsonb(NEW)-ARRAY['revoked_at','revoked_by']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['revoked_at','revoked_by'])
 OR NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.revoked_by AND org_id=NEW.org_id AND role='owner') THEN
 RAISE EXCEPTION 'notice capability permits only owner one-way revocation' USING ERRCODE='23514';END IF;
 ELSE
 IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL OR NOT EXISTS(
 SELECT 1 FROM document_amendment_notices_v1 n JOIN document_amendment_notice_deliveries_v1 x ON x.notice_id=n.id AND x.org_id=n.org_id
 WHERE n.id=NEW.notice_id AND n.org_id=NEW.org_id AND n.file_commitment_sha256=NEW.file_commitment_sha256
 AND x.email_delivery_id=NEW.email_delivery_id AND x.recipient_email=NEW.recipient_email AND NEW.created_at=n.issued_at) THEN
 RAISE EXCEPTION 'notice capability differs from exact notice and outbox' USING ERRCODE='23514';END IF;END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER amendment_notice_access_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_amendment_notice_access_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_notice_access_v1();
CREATE FUNCTION hash_amendment_original_pins_v1(target UUID,tenant UUID) RETURNS JSONB
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,public AS $$
DECLARE d documents%ROWTYPE;r document_participant_reports_v1%ROWTYPE;p JSONB;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id=target AND org_id=tenant AND deleted_at IS NULL;
 SELECT * INTO STRICT r FROM document_participant_reports_v1 WHERE document_id=d.id AND org_id=d.org_id AND completion_effective_at=d.completion_effective_at;
 IF d.status<>'completed' OR d.is_envelope OR d.parent_envelope_id IS NOT NULL
 OR octet_length(d.name) NOT BETWEEN 1 AND 512 OR btrim(d.name,U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')='' OR d.name ~ '[[:cntrl:]]' OR d.name ~ U&'[\007F-\009F]'
 OR d.final_pdf_key IS NULL OR d.final_pdf_version_id IS NULL OR octet_length(d.final_pdf_sha) IS DISTINCT FROM 32
 OR d.audit_cert_key IS NULL OR d.audit_cert_version_id IS NULL OR octet_length(d.audit_cert_sha256) IS DISTINCT FROM 32
 OR d.audit_payload_key IS NULL OR d.audit_payload_version_id IS NULL OR octet_length(d.audit_payload_sha256) IS DISTINCT FROM 32
 OR d.audit_signature_key IS NULL OR d.audit_signature_version_id IS NULL OR octet_length(d.audit_signature_sha256) IS DISTINCT FROM 32
 OR r.schema_version IS DISTINCT FROM d.participant_report_schema OR octet_length(r.report_sha256) IS DISTINCT FROM 32
 OR r.final_pdf_sha256<>d.final_pdf_sha OR r.audit_cert_sha256<>d.audit_cert_sha256
 OR r.audit_payload_sha256<>d.audit_payload_sha256 OR r.audit_signature_sha256<>d.audit_signature_sha256 THEN
 RAISE EXCEPTION 'completed original lacks exact final/report pins' USING ERRCODE='23514';END IF;
 IF NOT hash_package_key_v1(d.final_pdf_key,tenant) OR NOT hash_package_key_v1(d.audit_cert_key,tenant)
 OR NOT hash_package_key_v1(d.audit_payload_key,tenant) OR NOT hash_package_key_v1(d.audit_signature_key,tenant)
 OR NOT hash_package_opaque_v1(d.final_pdf_version_id) OR NOT hash_package_opaque_v1(d.audit_cert_version_id)
 OR NOT hash_package_opaque_v1(d.audit_payload_version_id) OR NOT hash_package_opaque_v1(d.audit_signature_version_id) THEN
 RAISE EXCEPTION 'invalid original version pins' USING ERRCODE='23514';END IF;
 SELECT jsonb_build_object('package_id',a.package_id,'capture_revision',a.capture_revision::text,
 'manifest_sha256',encode(a.manifest_sha256,'hex'),'legal_commitment_sha256',encode(a.legal_commitment_sha256,'hex'),
 'send_attempt_id',a.attempt_id) INTO p FROM document_package_send_attempts_v1 a
 JOIN document_package_send_completions_v1 c ON c.attempt_id=a.attempt_id AND c.org_id=a.org_id AND c.document_id=a.document_id
 WHERE a.document_id=target AND a.org_id=tenant AND a.terminal_outcome='completed' AND c.outcome='sent'
 AND a.article13_notice_epoch_at=d.sent_at ORDER BY a.created_at DESC LIMIT 1;
 IF p IS NULL AND EXISTS(SELECT 1 FROM document_packages_v1 pkg JOIN document_attachment_drafts_v1 members ON members.package_id=pkg.id AND members.org_id=pkg.org_id WHERE pkg.document_id=d.id AND pkg.org_id=d.org_id) THEN RAISE EXCEPTION 'completed package lacks exact Send/capture receipt' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('document_id',d.id,'original_name',d.name,'completion_effective_at',d.completion_effective_at,
 'final_pdf',jsonb_build_object('key',d.final_pdf_key,'version_id',d.final_pdf_version_id,'sha256',encode(d.final_pdf_sha,'hex')),
 'report_pdf',jsonb_build_object('key',d.audit_cert_key,'version_id',d.audit_cert_version_id,'sha256',encode(d.audit_cert_sha256,'hex')),
 'report_payload',jsonb_build_object('key',d.audit_payload_key,'version_id',d.audit_payload_version_id,'sha256',encode(d.audit_payload_sha256,'hex')),
 'report_signature',jsonb_build_object('key',d.audit_signature_key,'version_id',d.audit_signature_version_id,'sha256',encode(d.audit_signature_sha256,'hex')),
 'report_sha256',encode(r.report_sha256,'hex'),'package',p);
END $$;
CREATE FUNCTION hash_amendment_file_set_v1(target UUID,tenant UUID) RETURNS JSONB
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,public AS $$
DECLARE d documents%ROWTYPE;p document_packages_v1%ROWTYPE;item JSONB;main JSONB;files JSONB;matches INTEGER;n INTEGER;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id=target AND org_id=tenant AND deleted_at IS NULL;
 IF d.source_kind<>'pdf' OR d.is_envelope OR d.parent_envelope_id IS NOT NULL OR octet_length(d.name)>512
 OR hash_package_key_v1(d.pdf_storage_key,tenant) IS DISTINCT FROM TRUE OR hash_package_opaque_v1(d.pdf_storage_version_id) IS DISTINCT FROM TRUE
 OR d.pdf_storage_version_id IN ('null','hash:unversioned-development') OR octet_length(d.pdf_sha256) IS DISTINCT FROM 32 THEN
 RAISE EXCEPTION 'amendment requires exact standalone PDF' USING ERRCODE='23514';END IF;
 IF d.html_source_json IS NOT NULL AND (d.html_reviewed_by IS NULL OR d.html_reviewed_at IS NULL
 OR d.html_reviewed_pdf_sha256 IS DISTINCT FROM d.pdf_sha256
 OR d.html_reviewed_materialization_id IS DISTINCT FROM d.html_current_materialization_id) THEN
 RAISE EXCEPTION 'amendment requires reviewed current HTML PDF' USING ERRCODE='23514';END IF;
 SELECT count(*) INTO matches FROM jsonb_array_elements(d.metadata_redaction_report->'items') x
 WHERE x->>'content_type'='application/pdf' AND x->'pdf'->>'output_sha256'=encode(d.pdf_sha256,'hex');
 IF matches<>1 THEN RAISE EXCEPTION 'amendment requires exact intake measurement' USING ERRCODE='23514';END IF;
 SELECT x INTO item FROM jsonb_array_elements(d.metadata_redaction_report->'items') x
 WHERE x->>'content_type'='application/pdf' AND x->'pdf'->>'output_sha256'=encode(d.pdf_sha256,'hex');
 IF (item->>'bytes_after')::bigint NOT BETWEEN 1 AND 52428800 OR (item->'pdf'->>'pages_after')::integer NOT BETWEEN 1 AND 500 THEN
 RAISE EXCEPTION 'amendment PDF dimension bounds' USING ERRCODE='23514';END IF;
 main:=jsonb_build_object('position',0,'document_id',d.id,'title',d.name,'key',d.pdf_storage_key,'version_id',d.pdf_storage_version_id,
 'sha256',encode(d.pdf_sha256,'hex'),'bytes',(item->>'bytes_after')::bigint,'pages',(item->'pdf'->>'pages_after')::integer,
 'intake_report_sha256',encode(sha256(convert_to(d.metadata_redaction_report::text,'UTF8')),'hex'));
 SELECT * INTO p FROM document_packages_v1 WHERE document_id=target AND org_id=tenant;
 SELECT count(*),COALESCE(jsonb_agg(jsonb_build_object('position',(SELECT count(*) FROM document_attachment_drafts_v1 prior WHERE prior.package_id=a.package_id AND prior.ordinal<=a.ordinal),'document_id',a.member_document_id,'title',a.title,
 'key',a.pdf_key,'version_id',a.pdf_version_id,'sha256',encode(a.pdf_sha256,'hex'),'bytes',a.pdf_bytes,'pages',a.pdf_pages,
 'intake_report_sha256',encode(a.pdf_intake_report_sha256,'hex')) ORDER BY a.ordinal),'[]'::jsonb) INTO n,files
 FROM document_attachment_drafts_v1 a WHERE a.package_id=p.id AND a.org_id=tenant;
 IF n>16 OR EXISTS(SELECT 1 FROM document_attachment_drafts_v1 a WHERE a.package_id=p.id AND a.org_id=tenant AND a.pdf_intake_report_sha256 IS NULL)
 OR (SELECT sum((x->>'bytes')::bigint) FROM jsonb_array_elements(jsonb_build_array(main)||files) x)>52428800
 OR (SELECT sum((x->>'pages')::integer) FROM jsonb_array_elements(jsonb_build_array(main)||files) x)>500 THEN
 RAISE EXCEPTION 'amendment package dimensions or intake proof differ' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('schema','hash-amendment-files-v1','document_id',d.id,'source_commitment_sha256',
 COALESCE(COALESCE(d.html_current_source_json,d.html_source_json)->>'commitment',''),'package_id',p.id,
 'package_generation',COALESCE(p.draft_generation,0)::text,'files',jsonb_build_array(main)||files);
END $$;
CREATE FUNCTION hash_guard_amendment_immutable_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'later amendment evidence is append only' USING ERRCODE='23514';END $$;
CREATE TRIGGER amendment_immutable_v1 BEFORE UPDATE OR DELETE ON document_amendments_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_immutable_v1();
CREATE TRIGGER amendment_policy_immutable_v1 BEFORE UPDATE OR DELETE ON document_amendment_policies_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_immutable_v1();
CREATE TRIGGER amendment_notice_immutable_v1 BEFORE UPDATE OR DELETE ON document_amendment_notices_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_immutable_v1();
CREATE TRIGGER amendment_notice_delivery_immutable_v1 BEFORE UPDATE OR DELETE ON document_amendment_notice_deliveries_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_immutable_v1();
CREATE FUNCTION hash_guard_amendment_insert_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE d documents%ROWTYPE;o documents%ROWTYPE;head document_amendments_v1%ROWTYPE;b JSONB;subject UUID;policy document_amendment_policies_v1%ROWTYPE;
BEGIN
 -- Same globally sorted subjects as the native paired reader. Reverse direct
 -- DML refuses rather than waiting while holding a relation/package lock.
 FOR subject IN SELECT id FROM documents WHERE org_id=NEW.org_id AND id IN (NEW.original_document_id,NEW.document_id) ORDER BY id LOOP
 PERFORM 1 FROM documents WHERE id=subject AND org_id=NEW.org_id FOR UPDATE NOWAIT;END LOOP;
 SELECT * INTO STRICT o FROM documents WHERE id=NEW.original_document_id AND org_id=NEW.org_id AND deleted_at IS NULL;
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id AND deleted_at IS NULL;
 IF o.status<>'completed' OR d.status<>'draft' OR d.sent_at IS NOT NULL OR hash_package_has_signing_evidence_v1(d.id,d.org_id)
 OR NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.created_by AND org_id=NEW.org_id AND role='owner')
 OR EXISTS(SELECT 1 FROM document_amendments_v1 WHERE document_id=o.id)
 OR EXISTS(SELECT 1 FROM document_amendments_v1 WHERE original_document_id=d.id)
 OR (NEW.mode='signature') IS DISTINCT FROM d.requires_signature
 OR (NEW.mode<>'signature' AND COALESCE(d.html_source_json->>'schema_version','')='3') THEN
 RAISE EXCEPTION 'amendment source, mode or owner differs' USING ERRCODE='23514';END IF;
 IF convert_from(NEW.original_pins,'UTF8')::jsonb IS DISTINCT FROM hash_amendment_original_pins_v1(o.id,o.org_id)
 OR convert_from(NEW.file_set,'UTF8')::jsonb IS DISTINCT FROM hash_amendment_file_set_v1(d.id,d.org_id) THEN
 RAISE EXCEPTION 'amendment exact original or proposed pins changed' USING ERRCODE='23514';END IF;
 SELECT * INTO head FROM document_amendments_v1 WHERE original_document_id=o.id AND org_id=o.org_id ORDER BY revision DESC LIMIT 1;
 IF COALESCE(head.revision,0)<>NEW.previous_revision OR head.id IS DISTINCT FROM NEW.predecessor_id THEN
 RAISE EXCEPTION 'amendment head changed' USING ERRCODE='23514';END IF;
 b:=convert_from(NEW.basis,'UTF8')::jsonb;
 IF b->>'kind'='reviewed_legacy_clause' THEN
 IF octet_length(b->>'clause_reference') NOT BETWEEN 1 AND 512 OR octet_length(b->>'reviewed_clause') NOT BETWEEN 1 AND 8192
 OR octet_length(b->>'effective_condition') NOT BETWEEN 1 AND 2048 OR NOT (b->'allowed_modes' ? NEW.mode)
 OR (NEW.mode='agreed_notice' AND NOT (b->'allowed_channels' ? 'email')) THEN
 RAISE EXCEPTION 'reviewed agreement clause does not permit selected mode' USING ERRCODE='23514';END IF;
 ELSIF b->>'kind'='frozen_agreement_policy' THEN
 SELECT * INTO STRICT policy FROM document_amendment_policies_v1 WHERE id=(b->>'frozen_policy_id')::uuid AND org_id=o.org_id AND document_id=o.id;
 IF policy.presented_pdf_sha256 IS DISTINCT FROM o.pdf_sha256 OR policy.presented_pdf_version_id IS DISTINCT FROM o.pdf_storage_version_id
 OR policy.presented_source_sha256 IS DISTINCT FROM decode(COALESCE(o.html_current_source_json,o.html_source_json)->>'commitment','hex')
 OR convert_from(policy.basis,'UTF8')::jsonb IS DISTINCT FROM b
 OR NOT ((convert_from(policy.basis,'UTF8')::jsonb)->'allowed_modes' ? NEW.mode)
 OR (NEW.mode='agreed_notice' AND NOT ((convert_from(policy.basis,'UTF8')::jsonb)->'allowed_channels' ? 'email')) THEN
 RAISE EXCEPTION 'frozen agreement policy differs' USING ERRCODE='23514';END IF;
 ELSE RAISE EXCEPTION 'unknown later amendment basis' USING ERRCODE='23514';END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hash_collab_archive_dsr_lock_key(NEW.org_id)) THEN
 RAISE EXCEPTION 'amendment privacy review is changing' USING ERRCODE='55P03';END IF;
 FOR subject IN SELECT DISTINCT value::uuid FROM jsonb_array_elements_text(jsonb_build_array(o.id::text,d.id::text)||
 (SELECT jsonb_agg(x->>'document_id') FROM jsonb_array_elements(convert_from(NEW.file_set,'UTF8')::jsonb->'files') x)) ORDER BY value::uuid LOOP
 IF NOT hash_try_document_package_privacy_fence_v1(NEW.org_id,subject) THEN RAISE EXCEPTION 'amendment privacy review changing' USING ERRCODE='55P03';END IF;
 IF EXISTS(SELECT 1 FROM data_subject_requests WHERE org_id=NEW.org_id AND status IN ('open','in_progress') AND (document_id IS NULL OR document_id=subject)) THEN
 RAISE EXCEPTION 'amendment privacy review pending' USING ERRCODE='23514';END IF;END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER amendment_insert_v1 BEFORE INSERT ON document_amendments_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_insert_v1();
CREATE FUNCTION hash_guard_amendment_document_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE a document_amendments_v1%ROWTYPE;
BEGIN
 -- A declared visible policy may not silently disappear through an older,
 -- private or delegated Send path. Only the actual trusted freeze row from
 -- retained native completion permits the original sealing->sent transition.
 -- No declaration remains neutral; declared delegated Send stays unsupported
 -- until it has an equivalent actual native freeze with its own authority.
 IF OLD.status='sealing' AND NEW.status='sent'
 AND COALESCE(OLD.html_current_source_json,OLD.html_source_json)#>'{master,contract_profile,amendment_policy}' IS NOT NULL
 AND COALESCE(OLD.html_current_source_json,OLD.html_source_json)#>'{master,contract_profile,amendment_policy}'<>'null'::jsonb THEN
 IF NOT EXISTS(SELECT 1 FROM document_amendment_policies_v1 p WHERE p.document_id=OLD.id AND p.org_id=OLD.org_id
 AND p.presented_source_sha256=decode(COALESCE(OLD.html_current_source_json,OLD.html_source_json)->>'commitment','hex')
 AND p.presented_pdf_sha256=OLD.pdf_sha256 AND p.presented_pdf_version_id=OLD.pdf_storage_version_id
 AND hash_amendment_policy_source_matches_v1(COALESCE(OLD.html_current_source_json,OLD.html_source_json),convert_from(p.basis,'UTF8')::jsonb) IS TRUE) THEN
 RAISE EXCEPTION 'declared later-change policy requires exact retained native freeze before Send' USING ERRCODE='23514';END IF;
 END IF;
 -- Completed original artifacts/response/evidence remain owned by their
 -- existing guards. New relation adds no rewrite or report-expansion path.
 SELECT * INTO a FROM document_amendments_v1 WHERE document_id=OLD.id AND org_id=OLD.org_id;
 IF FOUND THEN
 IF OLD.status='draft' AND NEW.status<>'draft' AND
 (a.revision IS DISTINCT FROM (SELECT max(revision) FROM document_amendments_v1 WHERE original_document_id=a.original_document_id AND org_id=a.org_id)
 OR convert_from(a.file_set,'UTF8')::jsonb IS DISTINCT FROM hash_amendment_file_set_v1(OLD.id,OLD.org_id)) THEN
 RAISE EXCEPTION 'amendment proposal head or file set changed before Send' USING ERRCODE='23514';END IF;
 IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id OR NEW.deleted_at IS NOT NULL OR NEW.is_envelope OR NEW.parent_envelope_id IS NOT NULL
 OR (a.mode='agreed_notice' AND NEW.status<>'draft')
 OR ROW(NEW.name,NEW.pdf_storage_key,NEW.pdf_storage_version_id,NEW.pdf_sha256,NEW.html_source_json,NEW.html_current_source_json,
 NEW.html_current_materialization_id,NEW.html_current_materialization_sequence,NEW.requires_signature,NEW.routing_mode,NEW.variables_json,NEW.blocks_json)
 IS DISTINCT FROM ROW(OLD.name,OLD.pdf_storage_key,OLD.pdf_storage_version_id,OLD.pdf_sha256,OLD.html_source_json,OLD.html_current_source_json,
 OLD.html_current_materialization_id,OLD.html_current_materialization_sequence,OLD.requires_signature,OLD.routing_mode,OLD.variables_json,OLD.blocks_json) THEN
 RAISE EXCEPTION 'linked amendment file set or process is immutable; author a new proposal' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER amendment_document_v1 BEFORE UPDATE ON documents FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_document_v1();
CREATE FUNCTION hash_guard_amendment_attachment_configuration_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE root UUID;pid UUID;
BEGIN
 IF TG_TABLE_NAME='document_packages_v1' THEN
 IF TG_OP='INSERT' THEN root:=NEW.document_id;ELSE root:=OLD.document_id;END IF;
 ELSE
 IF TG_OP='INSERT' THEN pid:=NEW.package_id;ELSE pid:=OLD.package_id;END IF;
 SELECT document_id INTO STRICT root FROM document_packages_v1 WHERE id=pid;
 END IF;
 IF EXISTS(SELECT 1 FROM document_amendments_v1 WHERE document_id=root) THEN
 RAISE EXCEPTION 'linked amendment attachment selection is frozen' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;
CREATE TRIGGER amendment_package_configuration_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_packages_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_attachment_configuration_v1();
CREATE TRIGGER amendment_attachment_configuration_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_attachment_drafts_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_attachment_configuration_v1();
CREATE FUNCTION hash_guard_amendment_document_deletion_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF (TG_OP='DELETE' OR (NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL)) AND EXISTS(
 SELECT 1 FROM document_amendments_v1 a WHERE a.org_id=OLD.org_id AND
 (a.original_document_id=OLD.id OR a.document_id=OLD.id OR EXISTS(
 SELECT 1 FROM jsonb_array_elements(convert_from(a.file_set,'UTF8')::jsonb->'files') f WHERE f->>'document_id'=OLD.id::text))) THEN
 RAISE EXCEPTION 'frozen amendment subject requires retained-evidence privacy review' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;
CREATE TRIGGER amendment_document_deletion_v1 BEFORE UPDATE OF deleted_at OR DELETE ON documents FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_document_deletion_v1();
CREATE FUNCTION hash_guard_amendment_response_configuration_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE target UUID;
BEGIN
 IF TG_OP='INSERT' THEN target:=NEW.document_id;ELSE target:=OLD.document_id;END IF;
 IF EXISTS(SELECT 1 FROM document_amendments_v1 WHERE document_id=target) THEN
 IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'linked amendment response configuration is frozen' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='recipients' THEN
 IF ROW(NEW.id,NEW.document_id,NEW.email,NEW.name,NEW.role,NEW.order_index,NEW.locale)
 IS DISTINCT FROM ROW(OLD.id,OLD.document_id,OLD.email,OLD.name,OLD.role,OLD.order_index,OLD.locale) THEN
 RAISE EXCEPTION 'linked amendment party identity is frozen' USING ERRCODE='23514';END IF;
 ELSE
 IF (to_jsonb(NEW)-ARRAY['value','completed_at','updated_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['value','completed_at','updated_at']) THEN
 RAISE EXCEPTION 'linked amendment field layout is frozen' USING ERRCODE='23514';END IF;END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;
CREATE TRIGGER amendment_recipient_configuration_v1 BEFORE INSERT OR UPDATE OR DELETE ON recipients FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_response_configuration_v1();
CREATE TRIGGER amendment_field_configuration_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_fields FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_response_configuration_v1();
CREATE FUNCTION hash_amendment_policy_source_matches_v1(source JSONB,basis JSONB)
RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $$
DECLARE p JSONB;term JSONB;clause TEXT;expected JSONB;terms INTEGER;defaults INTEGER;
BEGIN
 IF jsonb_typeof(source)<>'object' OR jsonb_typeof(basis)<>'object' THEN RETURN FALSE;END IF;
 p:=source->'master'->'contract_profile'->'amendment_policy';
 IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR jsonb_typeof(p->'term') IS DISTINCT FROM 'string'
 OR jsonb_typeof(p->'clause_reference') IS DISTINCT FROM 'string' OR jsonb_typeof(p->'effective_condition') IS DISTINCT FROM 'string'
 OR p->>'term' !~ '^[a-z][a-z0-9_]{0,63}$'
 OR jsonb_typeof(p->'allowed_modes') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p->'allowed_channels') IS DISTINCT FROM 'array' THEN RETURN FALSE;END IF;
 IF jsonb_array_length(p->'allowed_modes') NOT BETWEEN 1 AND 3 OR jsonb_array_length(p->'allowed_channels')>1
 OR octet_length(p->>'clause_reference') NOT BETWEEN 1 AND 512
 OR octet_length(p->>'effective_condition') NOT BETWEEN 1 AND 2048 THEN RETURN FALSE;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p->'allowed_modes') x WHERE jsonb_typeof(x)<>'string' OR x#>>'{}' NOT IN ('signature','acknowledgement','agreed_notice'))
 OR (SELECT count(*) FROM jsonb_array_elements(p->'allowed_modes'))<>(SELECT count(DISTINCT x) FROM jsonb_array_elements(p->'allowed_modes') x)
 OR ((p->'allowed_modes') ? 'agreed_notice') IS DISTINCT FROM ((p->'allowed_channels')=jsonb_build_array('email'))
 OR (NOT ((p->'allowed_modes') ? 'agreed_notice') AND jsonb_array_length(p->'allowed_channels')<>0) THEN RETURN FALSE;END IF;
 IF jsonb_typeof(source->'master'->'contract_profile'->'terms') IS DISTINCT FROM 'array' THEN RETURN FALSE;END IF;
 SELECT count(*) INTO terms FROM jsonb_array_elements(source->'master'->'contract_profile'->'terms') t WHERE t->>'name'=p->>'term';
 IF terms<>1 THEN RETURN FALSE;END IF;
 SELECT t INTO term FROM jsonb_array_elements(source->'master'->'contract_profile'->'terms') t WHERE t->>'name'=p->>'term';
 IF COALESCE(term->>'value','')<>'' AND COALESCE(term->>'section','')='' THEN clause:=source->'values'->>(term->>'value');
 ELSIF COALESCE(term->>'section','')<>'' AND COALESCE(term->>'value','')='' THEN
  IF source->'sections' ? (term->>'section') THEN clause:=source->'sections'->>(term->>'section');
  ELSE
   IF jsonb_typeof(source->'master'->'sections') IS DISTINCT FROM 'array' THEN RETURN FALSE;END IF;
   SELECT count(*) INTO defaults FROM jsonb_array_elements(source->'master'->'sections') s WHERE s->>'name'=term->>'section';
   IF defaults<>1 THEN RETURN FALSE;END IF;
   SELECT s->>'default_text' INTO clause FROM jsonb_array_elements(source->'master'->'sections') s WHERE s->>'name'=term->>'section';
  END IF;
 ELSE RETURN FALSE;END IF;
 IF clause IS NULL OR octet_length(clause) NOT BETWEEN 1 AND 8192
 OR strpos(clause,p->>'clause_reference')=0 OR strpos(clause,p->>'effective_condition')=0 THEN RETURN FALSE;END IF;
 expected:=jsonb_strip_nulls(jsonb_build_object('kind','frozen_agreement_policy','frozen_policy_id',basis->'frozen_policy_id',
 'clause_reference',p->>'clause_reference','reviewed_clause',clause,'allowed_modes',
 (SELECT jsonb_agg(x ORDER BY x) FROM jsonb_array_elements(p->'allowed_modes') x),
 'allowed_channels',CASE WHEN jsonb_array_length(p->'allowed_channels')=0 THEN NULL ELSE p->'allowed_channels' END,
 'effective_condition',p->>'effective_condition'));
 RETURN COALESCE(basis=expected,FALSE);
END $$;
CREATE FUNCTION hash_guard_amendment_policy_insert_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE d documents%ROWTYPE;b JSONB;source JSONB;
BEGIN
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE NOWAIT;
 source:=COALESCE(d.html_current_source_json,d.html_source_json);b:=convert_from(NEW.basis,'UTF8')::jsonb;
 IF d.status<>'sealing' OR d.source_kind<>'pdf' OR d.is_envelope OR d.parent_envelope_id IS NOT NULL OR d.deleted_at IS NOT NULL
 OR d.html_source_json IS NULL OR source IS NULL OR d.html_reviewed_by IS NULL OR d.html_reviewed_at IS NULL
 OR d.html_reviewed_pdf_sha256 IS DISTINCT FROM d.pdf_sha256 OR d.html_reviewed_materialization_id IS DISTINCT FROM d.html_current_materialization_id
 OR NEW.presented_pdf_sha256 IS DISTINCT FROM d.pdf_sha256 OR NEW.presented_pdf_version_id IS DISTINCT FROM d.pdf_storage_version_id
 OR NEW.presented_source_sha256 IS DISTINCT FROM decode(source->>'commitment','hex')
 OR b->>'kind' IS DISTINCT FROM 'frozen_agreement_policy' OR b->>'frozen_policy_id' IS DISTINCT FROM NEW.id::text
 OR NOT EXISTS(SELECT 1 FROM send_sealing_intents intent WHERE intent.document_id=d.id AND intent.org_id=d.org_id
 AND intent.actor_user_id=NEW.frozen_by AND intent.retention_started_at IS NOT NULL AND intent.retention_completed_at IS NOT NULL AND intent.presign_execution_id IS NULL)
 OR NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.frozen_by AND org_id=NEW.org_id AND (role='owner' OR (role='sender' AND d.sender_id=NEW.frozen_by)))
 OR hash_amendment_policy_source_matches_v1(source,b) IS DISTINCT FROM TRUE THEN
 RAISE EXCEPTION 'policy is not the visible declaration in this reviewed source and exact PDF' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER amendment_policy_insert_v1 BEFORE INSERT ON document_amendment_policies_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_policy_insert_v1();
CREATE FUNCTION hash_guard_amendment_notice_insert_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE a document_amendments_v1%ROWTYPE;j JSONB;subject UUID;
BEGIN
 SELECT * INTO STRICT a FROM document_amendments_v1 WHERE id=NEW.amendment_id AND org_id=NEW.org_id;
 FOR subject IN SELECT id FROM documents WHERE org_id=a.org_id AND id IN (a.original_document_id,a.document_id) ORDER BY id LOOP
 PERFORM 1 FROM documents WHERE id=subject AND org_id=a.org_id FOR UPDATE NOWAIT;END LOOP;
 IF a.mode<>'agreed_notice' OR a.file_commitment_sha256<>NEW.file_commitment_sha256
 OR a.revision<>(SELECT max(revision) FROM document_amendments_v1 WHERE org_id=a.org_id AND original_document_id=a.original_document_id)
 OR NOT EXISTS(SELECT 1 FROM documents WHERE id=a.document_id AND org_id=a.org_id AND status='draft' AND NOT requires_signature AND deleted_at IS NULL)
 OR NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.issued_by AND org_id=a.org_id AND role='owner')
 OR convert_from(a.file_set,'UTF8')::jsonb IS DISTINCT FROM hash_amendment_file_set_v1(a.document_id,a.org_id)
 OR convert_from(a.original_pins,'UTF8')::jsonb IS DISTINCT FROM hash_amendment_original_pins_v1(a.original_document_id,a.org_id)
 OR NOT ((convert_from(a.basis,'UTF8')::jsonb)->'allowed_modes' ? 'agreed_notice')
 OR NOT ((convert_from(a.basis,'UTF8')::jsonb)->'allowed_channels' ? 'email') THEN
 RAISE EXCEPTION 'notice differs from current exact agreed process and file set' USING ERRCODE='23514';END IF;
 j:=convert_from(NEW.notice_bytes,'UTF8')::jsonb;
 IF j->>'request_id' IS DISTINCT FROM NEW.request_id::text OR j->>'subject' IS DISTINCT FROM NEW.subject OR j->>'text' IS DISTINCT FROM NEW.text_body
 OR j->'reviewed' IS DISTINCT FROM 'true'::jsonb OR j->>'expected_head_revision' IS DISTINCT FROM a.revision::text
 OR jsonb_typeof(j->'recipient_emails') IS DISTINCT FROM 'array' OR jsonb_array_length(j->'recipient_emails') NOT BETWEEN 1 AND 32
 OR NEW.request_sha256<>NEW.notice_sha256 THEN
 RAISE EXCEPTION 'notice exact reviewed bytes differ' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER amendment_notice_insert_v1 BEFORE INSERT ON document_amendment_notices_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_notice_insert_v1();
CREATE FUNCTION hash_guard_amendment_notice_effects_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE n document_amendment_notices_v1%ROWTYPE;a document_amendments_v1%ROWTYPE;e events%ROWTYPE;recipients JSONB;counted INTEGER;
BEGIN
 SELECT * INTO STRICT n FROM document_amendment_notices_v1 WHERE id=NEW.id AND org_id=NEW.org_id;
 SELECT * INTO STRICT a FROM document_amendments_v1 WHERE id=n.amendment_id AND org_id=n.org_id;
 SELECT * INTO STRICT e FROM events WHERE id=n.event_id AND org_id=n.org_id;
 recipients:=convert_from(n.notice_bytes,'UTF8')::jsonb->'recipient_emails';
 SELECT count(*) INTO counted FROM document_amendment_notice_deliveries_v1 x WHERE x.notice_id=n.id AND x.org_id=n.org_id;
 IF counted<>jsonb_array_length(recipients) OR e.actor_user_id IS DISTINCT FROM n.issued_by OR e.document_id IS DISTINCT FROM a.original_document_id
 OR e.kind<>'document.amendment_notice_queued' OR e.payload_json->>'notice_id' IS DISTINCT FROM n.id::text
 OR e.payload_json->>'notice_sha256' IS DISTINCT FROM encode(n.notice_sha256,'hex')
 OR e.payload_json->>'file_commitment_sha256' IS DISTINCT FROM encode(n.file_commitment_sha256,'hex')
 OR e.payload_hashed IS NULL OR convert_from(e.payload_hashed,'UTF8')::jsonb IS DISTINCT FROM e.payload_json OR octet_length(e.row_hash) IS DISTINCT FROM 32
 OR EXISTS(SELECT 1 FROM document_amendment_notice_deliveries_v1 x LEFT JOIN email_deliveries mail ON mail.id=x.email_delivery_id
 LEFT JOIN document_amendment_notice_access_v1 c ON c.email_delivery_id=x.email_delivery_id AND c.notice_id=x.notice_id AND c.org_id=x.org_id
 WHERE x.notice_id=n.id AND x.org_id=n.org_id AND (mail.id IS NULL OR mail.status<>'pending' OR mail.subject<>n.subject
 OR mail.to_email<>x.recipient_email OR recipients->>x.position<>x.recipient_email
 OR x.message_sha256 IS DISTINCT FROM hash_package_send_message_sha256_v1(mail.id)
 OR c.id IS NULL OR c.file_commitment_sha256<>n.file_commitment_sha256 OR c.recipient_email<>x.recipient_email OR c.created_at<>n.issued_at)) THEN
 RAISE EXCEPTION 'notice requires exact atomic audit, private capability and real outbox references' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER amendment_notice_effects_v1 AFTER INSERT ON document_amendment_notices_v1 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_notice_effects_v1();
CREATE FUNCTION hash_guard_amendment_audit_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE e events%ROWTYPE;
BEGIN
 SELECT * INTO STRICT e FROM events WHERE id=NEW.event_id AND org_id=NEW.org_id;
 IF e.actor_user_id IS DISTINCT FROM NEW.created_by OR e.document_id IS DISTINCT FROM NEW.document_id
 OR e.payload_json->>'original_document_id' IS DISTINCT FROM NEW.original_document_id::text
 OR e.kind<>'document.amendment_linked' OR e.payload_json->>'amendment_id' IS DISTINCT FROM NEW.id::text
 OR e.payload_json->>'file_commitment_sha256' IS DISTINCT FROM encode(NEW.file_commitment_sha256,'hex')
 OR e.payload_json->>'basis_sha256' IS DISTINCT FROM encode(NEW.basis_sha256,'hex')
 OR e.payload_json->>'original_pins_sha256' IS DISTINCT FROM encode(NEW.original_pins_sha256,'hex')
 OR e.payload_json->>'request_id' IS DISTINCT FROM NEW.request_id::text
 OR e.payload_hashed IS NULL OR convert_from(e.payload_hashed,'UTF8')::jsonb IS DISTINCT FROM e.payload_json OR octet_length(e.row_hash) IS DISTINCT FROM 32 THEN
 RAISE EXCEPTION 'amendment requires exact transactional audit' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER amendment_audit_v1 AFTER INSERT ON document_amendments_v1 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_audit_v1();
-- +goose StatementEnd
-- +goose StatementBegin
-- Operational owner alerts are separate from the reviewed legal notice audience.
-- They reuse the native mutation event and actual email_deliveries row, without
-- a new receipt/acceptance table or recipient capability.
CREATE FUNCTION hash_guard_amendment_owner_alert_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE original UUID;kind TEXT;subject TEXT;u users%ROWTYPE;d documents%ROWTYPE;e events%ROWTYPE;m email_deliveries%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='document_amendments_v1' THEN original:=NEW.original_document_id;kind:='document.amendment_linked';subject:='Hash: later agreement proposal';
 ELSE SELECT original_document_id INTO STRICT original FROM document_amendments_v1 WHERE id=NEW.amendment_id AND org_id=NEW.org_id;kind:='document.amendment_notice_queued';subject:='Hash: agreement notice queued';END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=original AND org_id=NEW.org_id FOR SHARE;
 SELECT * INTO STRICT u FROM users WHERE id=d.sender_id AND org_id=d.org_id FOR SHARE;
 SELECT * INTO STRICT m FROM email_deliveries WHERE id=NEW.owner_alert_email_delivery_id FOR SHARE;
 SELECT * INTO STRICT e FROM events WHERE id=NEW.event_id AND org_id=NEW.org_id;
 IF u.id IS DISTINCT FROM NEW.owner_alert_user_id OR u.role NOT IN ('owner','sender') OR d.deleted_at IS NOT NULL OR d.status<>'completed'
 OR m.to_email IS DISTINCT FROM u.email OR m.subject IS DISTINCT FROM subject OR m.from_name<>'Hash' OR m.reply_to<>''
 OR m.headers_json IS DISTINCT FROM jsonb_build_object('X-Hash-Operational-Event','amendment-owner-v1')
 OR m.status<>'pending' OR m.last_error<>'' OR NEW.owner_alert_message_sha256 IS DISTINCT FROM hash_package_send_message_sha256_v1(m.id)
 OR EXISTS(SELECT 1 FROM document_amendments_v1 WHERE owner_alert_email_delivery_id=m.id)
 OR EXISTS(SELECT 1 FROM document_amendment_notices_v1 WHERE owner_alert_email_delivery_id=m.id)
 OR e.kind IS DISTINCT FROM kind OR e.payload_json#>>'{owner_alert,user_id}' IS DISTINCT FROM u.id::text
 OR e.payload_json#>>'{owner_alert,email_delivery_id}' IS DISTINCT FROM m.id::text
 OR e.payload_json#>>'{owner_alert,message_sha256}' IS DISTINCT FROM encode(NEW.owner_alert_message_sha256,'hex')
 OR e.payload_json#>>'{owner_alert,state}' IS DISTINCT FROM 'queued'
 OR NOT hash_try_document_package_privacy_fence_v1(d.org_id,d.id)
 OR EXISTS(SELECT 1 FROM data_subject_requests p WHERE p.org_id=d.org_id AND p.status IN ('open','in_progress') AND (p.document_id IS NULL OR p.document_id=d.id)) THEN
 RAISE EXCEPTION 'owner alert differs from current owner, privacy, event or actual queue' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER amendment_owner_alert_v1 BEFORE INSERT ON document_amendments_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_owner_alert_v1();
CREATE TRIGGER amendment_notice_owner_alert_v1 BEFORE INSERT ON document_amendment_notices_v1 FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_owner_alert_v1();
CREATE FUNCTION hash_guard_amendment_owner_message_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF (EXISTS(SELECT 1 FROM document_amendments_v1 WHERE owner_alert_email_delivery_id=OLD.id) OR EXISTS(SELECT 1 FROM document_amendment_notices_v1 WHERE owner_alert_email_delivery_id=OLD.id))
 AND ROW(NEW.id,NEW.to_email,NEW.subject,NEW.html_body,NEW.text_body,NEW.reply_to,NEW.from_name,NEW.headers_json)
 IS DISTINCT FROM ROW(OLD.id,OLD.to_email,OLD.subject,OLD.html_body,OLD.text_body,OLD.reply_to,OLD.from_name,OLD.headers_json) THEN
 RAISE EXCEPTION 'retained operational owner message is immutable' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER amendment_owner_message_v1 BEFORE UPDATE ON email_deliveries FOR EACH ROW EXECUTE FUNCTION hash_guard_amendment_owner_message_v1();
CREATE FUNCTION hash_amendment_owner_alert_dispatch_eligible_v1(delivery UUID) RETURNS BOOLEAN LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 WITH refs AS(
 SELECT a.org_id,a.original_document_id,a.owner_alert_user_id,a.owner_alert_email_delivery_id,a.owner_alert_message_sha256,a.event_id FROM document_amendments_v1 a WHERE a.owner_alert_email_delivery_id=delivery
 UNION ALL SELECT n.org_id,a.original_document_id,n.owner_alert_user_id,n.owner_alert_email_delivery_id,n.owner_alert_message_sha256,n.event_id FROM document_amendment_notices_v1 n JOIN document_amendments_v1 a ON a.id=n.amendment_id AND a.org_id=n.org_id WHERE n.owner_alert_email_delivery_id=delivery
 ), eligible AS(SELECT r.* FROM refs r JOIN documents d ON d.id=r.original_document_id AND d.org_id=r.org_id
 JOIN users u ON u.id=r.owner_alert_user_id AND u.org_id=d.org_id AND u.id=d.sender_id AND u.role IN ('owner','sender')
 JOIN email_deliveries m ON m.id=r.owner_alert_email_delivery_id AND m.to_email=u.email
 JOIN events e ON e.id=r.event_id AND e.org_id=r.org_id
 WHERE d.deleted_at IS NULL AND d.status='completed' AND m.headers_json=jsonb_build_object('X-Hash-Operational-Event','amendment-owner-v1')
 AND m.status IN ('pending','retrying') AND r.owner_alert_message_sha256=hash_package_send_message_sha256_v1(m.id)
 AND e.payload_json#>>'{owner_alert,email_delivery_id}'=m.id::text
 AND NOT EXISTS(SELECT 1 FROM data_subject_requests p WHERE p.org_id=d.org_id AND p.status IN ('open','in_progress') AND (p.document_id IS NULL OR p.document_id=d.id)))
 SELECT (SELECT count(*) FROM refs)=1 AND (SELECT count(*) FROM eligible)=1
$$;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE document_amendments_v1,document_amendment_policies_v1,document_amendment_notices_v1,document_amendment_notice_deliveries_v1,document_amendment_notice_access_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM document_amendments_v1) OR EXISTS(SELECT 1 FROM document_amendment_policies_v1) OR EXISTS(SELECT 1 FROM document_amendment_notices_v1) OR EXISTS(SELECT 1 FROM document_amendment_notice_deliveries_v1) OR EXISTS(SELECT 1 FROM document_amendment_notice_access_v1) THEN
 RAISE EXCEPTION 'retained later amendment evidence prevents rollback' USING ERRCODE='23514';END IF;END $$;
-- +goose StatementEnd
DROP FUNCTION hash_amendment_owner_alert_dispatch_eligible_v1(UUID);
DROP TRIGGER amendment_owner_message_v1 ON email_deliveries;
DROP FUNCTION hash_guard_amendment_owner_message_v1();
DROP TRIGGER amendment_owner_alert_v1 ON document_amendments_v1;
DROP TRIGGER amendment_notice_owner_alert_v1 ON document_amendment_notices_v1;
DROP FUNCTION hash_guard_amendment_owner_alert_v1();
DROP TRIGGER amendment_policy_insert_v1 ON document_amendment_policies_v1;
DROP FUNCTION hash_guard_amendment_policy_insert_v1();
DROP TRIGGER amendment_notice_effects_v1 ON document_amendment_notices_v1;
DROP FUNCTION hash_guard_amendment_notice_effects_v1();
DROP TRIGGER amendment_notice_insert_v1 ON document_amendment_notices_v1;
DROP FUNCTION hash_guard_amendment_notice_insert_v1();
DROP TRIGGER amendment_audit_v1 ON document_amendments_v1;
DROP FUNCTION hash_guard_amendment_audit_v1();
DROP TRIGGER amendment_package_configuration_v1 ON document_packages_v1;
DROP TRIGGER amendment_attachment_configuration_v1 ON document_attachment_drafts_v1;
DROP FUNCTION hash_guard_amendment_attachment_configuration_v1();
DROP TRIGGER amendment_document_deletion_v1 ON documents;
DROP FUNCTION hash_guard_amendment_document_deletion_v1();
DROP TRIGGER amendment_recipient_configuration_v1 ON recipients;
DROP TRIGGER amendment_field_configuration_v1 ON document_fields;
DROP FUNCTION hash_guard_amendment_response_configuration_v1();
DROP TRIGGER amendment_document_v1 ON documents;
DROP FUNCTION hash_guard_amendment_document_v1();
DROP TRIGGER amendment_insert_v1 ON document_amendments_v1;
DROP FUNCTION hash_guard_amendment_insert_v1();
DROP TABLE document_amendment_notice_access_v1;
DROP FUNCTION hash_guard_amendment_notice_access_v1();
DROP TABLE document_amendment_notice_deliveries_v1;
DROP TABLE document_amendment_notices_v1;
DROP TABLE document_amendment_policies_v1;
DROP TABLE document_amendments_v1;
DROP FUNCTION hash_guard_amendment_immutable_v1();
DROP FUNCTION hash_amendment_policy_source_matches_v1(JSONB,JSONB);
DROP FUNCTION hash_amendment_file_set_v1(UUID,UUID);
DROP FUNCTION hash_amendment_original_pins_v1(UUID,UUID);
