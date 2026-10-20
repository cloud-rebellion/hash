-- +goose Up
-- Durable exact Send identity survives the ephemeral sealing intent. This does
-- not relax M99 or enable attachment Send, recipient consent or signatures.
CREATE UNIQUE INDEX document_package_capture_send_identity_v1 ON document_package_captures_v1
 (package_id,revision,org_id,document_id,captured_root_updated_at,captured_draft_generation,manifest_sha256,legal_commitment_sha256,created_by);
CREATE TABLE document_package_send_attempts_v1 (
 attempt_id UUID PRIMARY KEY CHECK(attempt_id<>'00000000-0000-0000-0000-000000000000'),
 org_id UUID NOT NULL,document_id UUID NOT NULL,package_id UUID NOT NULL,
 capture_revision BIGINT NOT NULL CHECK(capture_revision>0),
 previous_revision BIGINT NOT NULL CHECK(previous_revision>=0 AND previous_revision<capture_revision),
 manifest_bytes INTEGER NOT NULL CHECK(manifest_bytes BETWEEN 1 AND 65536),
 member_count SMALLINT NOT NULL CHECK(member_count BETWEEN 1 AND 17),
 pdf_bytes BIGINT NOT NULL CHECK(pdf_bytes BETWEEN 1 AND 52428800),
 pdf_pages INTEGER NOT NULL CHECK(pdf_pages BETWEEN 1 AND 500),
 captured_root_updated_at TIMESTAMPTZ NOT NULL CHECK(isfinite(captured_root_updated_at)),
 captured_draft_generation BIGINT NOT NULL CHECK(captured_draft_generation>0),
 manifest_sha256 BYTEA NOT NULL CHECK(octet_length(manifest_sha256)=32),
 legal_commitment_sha256 BYTEA NOT NULL CHECK(octet_length(legal_commitment_sha256)=32),
 actor_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 article13_notice_epoch_at TIMESTAMPTZ NOT NULL CHECK(isfinite(article13_notice_epoch_at)),
 retain_until TIMESTAMPTZ NOT NULL CHECK(isfinite(retain_until) AND retain_until=hash_evidence_retain_until(article13_notice_epoch_at,7)),
 retention_started_at TIMESTAMPTZ CHECK(retention_started_at IS NULL OR isfinite(retention_started_at)),
 retention_completed_at TIMESTAMPTZ CHECK(retention_completed_at IS NULL OR isfinite(retention_completed_at)),
 terminal_outcome TEXT CHECK(terminal_outcome IN ('completed','aborted')),
 terminal_at TIMESTAMPTZ CHECK(terminal_at IS NULL OR isfinite(terminal_at)),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 UNIQUE(attempt_id,org_id,document_id),
 FOREIGN KEY(package_id,capture_revision,org_id,document_id,captured_root_updated_at,captured_draft_generation,manifest_sha256,legal_commitment_sha256,actor_user_id)
  REFERENCES document_package_captures_v1(package_id,revision,org_id,document_id,captured_root_updated_at,captured_draft_generation,manifest_sha256,legal_commitment_sha256,created_by) ON DELETE RESTRICT,
 CHECK((terminal_outcome IS NULL)=(terminal_at IS NULL)),
 CHECK(retention_completed_at IS NULL OR retention_started_at IS NOT NULL),
 CHECK(terminal_outcome IS DISTINCT FROM 'aborted' OR (retention_started_at IS NULL AND retention_completed_at IS NULL)),
 CHECK(terminal_outcome IS DISTINCT FROM 'completed' OR (retention_started_at IS NOT NULL AND retention_completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX document_package_one_active_send_v1 ON document_package_send_attempts_v1(document_id) WHERE terminal_outcome IS NULL;
CREATE INDEX document_package_send_history_v1 ON document_package_send_attempts_v1(org_id,document_id,created_at,attempt_id);
ALTER TABLE send_sealing_intents ADD COLUMN package_send_attempt_id UUID,
 ADD CONSTRAINT send_package_attempt_scope_v1 FOREIGN KEY(package_send_attempt_id,org_id,document_id)
  REFERENCES document_package_send_attempts_v1(attempt_id,org_id,document_id) ON DELETE RESTRICT,
 ADD CONSTRAINT send_package_not_delegated_v1 CHECK(package_send_attempt_id IS NULL OR presign_execution_id IS NULL);

-- +goose StatementBegin
CREATE FUNCTION hash_package_send_main_matches_v1(target UUID,tenant UUID,pid UUID,rev BIGINT) RETURNS BOOLEAN AS $$
 SELECT EXISTS(
 SELECT 1 FROM documents d JOIN document_package_capture_members_v1 m
  ON m.package_id=pid AND m.revision=rev AND m.org_id=tenant AND m.member_position=0
 WHERE d.id=target AND d.org_id=tenant AND m.member_document_id=d.id
  AND NOT d.is_envelope AND d.parent_envelope_id IS NULL AND d.source_kind='pdf' AND d.deleted_at IS NULL
  AND ROW(m.title,m.pdf_key,m.pdf_version_id,m.pdf_sha256)
   IS NOT DISTINCT FROM ROW(d.name,d.pdf_storage_key,d.pdf_storage_version_id,d.pdf_sha256)
  AND ((d.html_source_json IS NULL AND m.source_kind='pdf-import')
   OR (d.html_source_json IS NOT NULL
    AND m.source_kind=CASE WHEN d.html_current_materialization_id IS NULL THEN 'html-origin' ELSE 'html-materialization' END
    AND m.source_commitment=decode(COALESCE(d.html_current_source_json,d.html_source_json)->>'commitment','hex')
    AND m.origin_commitment=decode(d.html_source_json->>'commitment','hex')
    AND m.materialization_id IS NOT DISTINCT FROM d.html_current_materialization_id
    AND m.materialization_sequence IS NOT DISTINCT FROM d.html_current_materialization_sequence
    AND d.html_reviewed_pdf_sha256=m.pdf_sha256 AND d.html_reviewed_by IS NOT NULL AND d.html_reviewed_at IS NOT NULL
    AND d.html_reviewed_materialization_id IS NOT DISTINCT FROM d.html_current_materialization_id))
 );
$$ LANGUAGE sql STABLE;
CREATE FUNCTION hash_package_send_privacy_clear_v1(tenant UUID,pid UUID,rev BIGINT) RETURNS VOID AS $$
DECLARE subject UUID;
BEGIN
  IF NOT pg_try_advisory_xact_lock_shared(hash_collab_archive_dsr_lock_key(tenant)) THEN
   RAISE EXCEPTION 'tenant privacy review is changing' USING ERRCODE='55P03'; END IF;
  FOR subject IN SELECT DISTINCT m.member_document_id FROM document_package_capture_members_v1 m
   WHERE m.package_id=pid AND m.revision=rev AND m.org_id=tenant ORDER BY m.member_document_id LOOP
   IF NOT hash_try_document_package_privacy_fence_v1(tenant,subject) THEN
    RAISE EXCEPTION 'package subject privacy review is changing' USING ERRCODE='55P03'; END IF;
  END LOOP;
  IF EXISTS(SELECT 1 FROM data_subject_requests r WHERE r.org_id=tenant AND r.status IN ('open','in_progress')
   AND (r.document_id IS NULL OR EXISTS(SELECT 1 FROM document_package_capture_members_v1 m
    WHERE m.package_id=pid AND m.revision=rev AND m.org_id=tenant AND m.member_document_id=r.document_id))) THEN
   RAISE EXCEPTION 'package subject privacy review is pending' USING ERRCODE='23514'; END IF;
END;
$$ LANGUAGE plpgsql;
CREATE FUNCTION hash_guard_package_send_attempt_v1() RETURNS trigger AS $$
DECLARE root RECORD; intent send_sealing_intents%ROWTYPE; generation BIGINT; subject UUID;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'package Send history is immutable' USING ERRCODE='23514'; END IF;
 -- Reverse direct-DML lock orders refuse, never wait intent/attempt -> root.
 SELECT d.id,d.org_id,d.status,d.updated_at,d.sender_id,d.sent_at,d.article13_notice_epoch_at,
  d.article13_notice_schema,d.article13_notice_epoch_v61_committed
 INTO STRICT root FROM documents d WHERE d.id=NEW.document_id AND d.org_id=NEW.org_id FOR UPDATE NOWAIT;
 IF TG_OP='INSERT' THEN
  IF NEW.terminal_outcome IS NOT NULL OR NEW.terminal_at IS NOT NULL OR NEW.retention_started_at IS NOT NULL OR NEW.retention_completed_at IS NOT NULL
   OR root.status<>'draft' OR root.updated_at IS DISTINCT FROM NEW.captured_root_updated_at
   OR NEW.article13_notice_epoch_at<=COALESCE(root.article13_notice_epoch_at,'-infinity'::timestamptz)
   OR hash_package_has_signing_evidence_v1(root.id,root.org_id)
   OR NOT EXISTS(SELECT 1 FROM users u WHERE u.id=NEW.actor_user_id AND u.org_id=NEW.org_id
    AND (u.role='owner' OR (u.role='sender' AND root.sender_id=u.id))) THEN
   RAISE EXCEPTION 'package Send attempt root or actor differs' USING ERRCODE='23514'; END IF;
  SELECT p.draft_generation INTO STRICT generation FROM document_packages_v1 p
   WHERE p.id=NEW.package_id AND p.document_id=NEW.document_id AND p.org_id=NEW.org_id FOR UPDATE NOWAIT;
  IF generation<>NEW.captured_draft_generation
   OR NOT EXISTS(SELECT 1 FROM document_package_captures_v1 c WHERE c.package_id=NEW.package_id AND c.revision=NEW.capture_revision
     AND c.org_id=NEW.org_id AND c.document_id=NEW.document_id
     AND c.captured_root_updated_at=NEW.captured_root_updated_at AND c.captured_draft_generation=NEW.captured_draft_generation
     AND c.manifest_sha256=NEW.manifest_sha256 AND c.legal_commitment_sha256=NEW.legal_commitment_sha256 AND c.created_by=NEW.actor_user_id
     AND c.previous_revision=NEW.previous_revision AND octet_length(c.manifest)=NEW.manifest_bytes
     AND c.member_count=NEW.member_count AND c.pdf_bytes=NEW.pdf_bytes AND c.pdf_pages=NEW.pdf_pages)
   OR EXISTS(SELECT 1 FROM document_package_captures_v1 c WHERE c.package_id=NEW.package_id AND c.revision>NEW.capture_revision)
   OR (SELECT count(*) FROM document_package_capture_members_v1 m WHERE m.package_id=NEW.package_id AND m.revision=NEW.capture_revision AND m.org_id=NEW.org_id)<>NEW.member_count
   OR EXISTS(SELECT 1 FROM document_package_capture_members_v1 m WHERE m.package_id=NEW.package_id AND m.revision=NEW.capture_revision AND m.org_id=NEW.org_id AND (m.pdf_intake_report IS NULL OR m.pdf_intake_report_sha256 IS NULL))
   OR NOT hash_package_send_main_matches_v1(NEW.document_id,NEW.org_id,NEW.package_id,NEW.capture_revision) THEN
   RAISE EXCEPTION 'package Send capture differs' USING ERRCODE='23514'; END IF;
  PERFORM hash_package_send_privacy_clear_v1(NEW.org_id,NEW.package_id,NEW.capture_revision);
 ELSE
  IF OLD.terminal_outcome IS NOT NULL OR
   (to_jsonb(NEW)-ARRAY['retention_started_at','retention_completed_at','terminal_outcome','terminal_at'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['retention_started_at','retention_completed_at','terminal_outcome','terminal_at'])
   OR (OLD.retention_started_at IS NOT NULL AND NEW.retention_started_at IS DISTINCT FROM OLD.retention_started_at)
   OR (OLD.retention_completed_at IS NOT NULL AND NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at) THEN
   RAISE EXCEPTION 'package Send identity or terminal outcome is immutable' USING ERRCODE='23514'; END IF;
  IF NEW.terminal_outcome IS DISTINCT FROM 'aborted' THEN
   PERFORM hash_package_send_privacy_clear_v1(NEW.org_id,NEW.package_id,NEW.capture_revision);
  END IF;
  SELECT * INTO STRICT intent FROM send_sealing_intents i WHERE i.document_id=NEW.document_id AND i.org_id=NEW.org_id
   AND i.package_send_attempt_id=NEW.attempt_id;
  IF ROW(NEW.retention_started_at,NEW.retention_completed_at)
   IS DISTINCT FROM ROW(intent.retention_started_at,intent.retention_completed_at) THEN
   RAISE EXCEPTION 'package retention progress differs from exact intent' USING ERRCODE='23514'; END IF;
  IF NEW.terminal_outcome='completed' AND
   (root.status NOT IN ('sent','expired') OR NEW.retention_started_at IS NULL OR NEW.retention_completed_at IS NULL
    OR root.sent_at IS DISTINCT FROM NEW.article13_notice_epoch_at OR root.article13_notice_epoch_at IS DISTINCT FROM NEW.article13_notice_epoch_at
    OR root.article13_notice_schema='' OR NOT root.article13_notice_epoch_v61_committed) THEN
   RAISE EXCEPTION 'package Send completion differs' USING ERRCODE='23514'; END IF;
  IF NEW.terminal_outcome='aborted' AND (root.status<>'draft' OR NEW.retention_started_at IS NOT NULL OR NEW.retention_completed_at IS NOT NULL) THEN
   RAISE EXCEPTION 'package Send cannot reverse retained evidence' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER package_send_attempt_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_package_send_attempts_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_attempt_v1();

CREATE FUNCTION hash_guard_package_send_intent_v1() RETURNS trigger AS $$
DECLARE a document_package_send_attempts_v1%ROWTYPE;
BEGIN
 IF TG_OP='UPDATE' AND NEW.package_send_attempt_id IS DISTINCT FROM OLD.package_send_attempt_id THEN
  RAISE EXCEPTION 'intent cannot adopt or replace package identity' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF OLD.package_send_attempt_id IS NULL THEN RETURN OLD; END IF;
  PERFORM 1 FROM documents WHERE id=OLD.document_id AND org_id=OLD.org_id FOR UPDATE NOWAIT;
  SELECT * INTO STRICT a FROM document_package_send_attempts_v1 WHERE attempt_id=OLD.package_send_attempt_id
   AND org_id=OLD.org_id AND document_id=OLD.document_id;
  IF a.terminal_outcome IS NULL THEN RAISE EXCEPTION 'package attempt must terminalize before intent deletion' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF NEW.package_send_attempt_id IS NULL THEN RETURN NEW; END IF;
 PERFORM 1 FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE NOWAIT;
 SELECT * INTO STRICT a FROM document_package_send_attempts_v1 WHERE attempt_id=NEW.package_send_attempt_id
  AND org_id=NEW.org_id AND document_id=NEW.document_id;
 IF a.terminal_outcome IS NOT NULL OR NEW.presign_execution_id IS NOT NULL
  OR NEW.actor_user_id IS DISTINCT FROM a.actor_user_id
  OR NEW.article13_notice_epoch_at IS DISTINCT FROM a.article13_notice_epoch_at OR NEW.retain_until IS DISTINCT FROM a.retain_until THEN
  RAISE EXCEPTION 'package intent scope, actor or retention differs' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.retention_started_at IS NOT NULL OR NEW.retention_completed_at IS NOT NULL OR NEW.attempts<>0 OR NEW.last_error IS NOT NULL THEN
   RAISE EXCEPTION 'new package intent has progress' USING ERRCODE='23514'; END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['retention_started_at','retention_completed_at','attempts','last_error','updated_at'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['retention_started_at','retention_completed_at','attempts','last_error','updated_at'])
   OR NEW.attempts<OLD.attempts
   OR (OLD.retention_started_at IS NOT NULL AND NEW.retention_started_at IS DISTINCT FROM OLD.retention_started_at)
   OR (OLD.retention_completed_at IS NOT NULL AND NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at)
   OR (NEW.retention_completed_at IS NOT NULL AND NEW.retention_started_at IS NULL) THEN
   RAISE EXCEPTION 'package intent core/progress is immutable' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER package_send_intent_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON send_sealing_intents
 FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_intent_v1();

CREATE FUNCTION hash_check_package_send_pair_v1(aid UUID) RETURNS VOID AS $$
DECLARE a document_package_send_attempts_v1%ROWTYPE; i send_sealing_intents%ROWTYPE; state TEXT; generation BIGINT; has_intent BOOLEAN;
BEGIN
 SELECT * INTO a FROM document_package_send_attempts_v1 WHERE attempt_id=aid;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO i FROM send_sealing_intents WHERE package_send_attempt_id=aid;
 has_intent:=FOUND;
 IF a.terminal_outcome IS NOT NULL THEN
  IF a.terminal_outcome='completed' THEN
   PERFORM hash_package_send_privacy_clear_v1(a.org_id,a.package_id,a.capture_revision);
   IF NOT hash_package_send_main_matches_v1(a.document_id,a.org_id,a.package_id,a.capture_revision)
    OR NOT EXISTS(SELECT 1 FROM document_packages_v1 p WHERE p.id=a.package_id AND p.org_id=a.org_id AND p.document_id=a.document_id AND p.draft_generation=a.captured_draft_generation) THEN
    RAISE EXCEPTION 'completed package main or generation differs at commit' USING ERRCODE='23514'; END IF;
  END IF;
  IF has_intent THEN RAISE EXCEPTION 'terminal package attempt retains an active intent' USING ERRCODE='23514'; END IF;
  IF (a.terminal_outcome='aborted' AND NOT EXISTS(SELECT 1 FROM documents d WHERE d.id=a.document_id AND d.org_id=a.org_id AND d.status='draft'))
   OR (a.terminal_outcome='completed' AND NOT EXISTS(SELECT 1 FROM documents d WHERE d.id=a.document_id AND d.org_id=a.org_id
    AND d.status IN ('sent','expired') AND d.sent_at=a.article13_notice_epoch_at AND d.article13_notice_epoch_at=a.article13_notice_epoch_at
    AND d.article13_notice_schema<>'' AND d.article13_notice_epoch_v61_committed)) THEN
   RAISE EXCEPTION 'terminal package outcome differs at commit' USING ERRCODE='23514'; END IF;
  RETURN;
 END IF;
 IF NOT has_intent OR ROW(i.org_id,i.document_id,i.actor_user_id,i.article13_notice_epoch_at,i.retain_until,i.retention_started_at,i.retention_completed_at)
  IS DISTINCT FROM ROW(a.org_id,a.document_id,a.actor_user_id,a.article13_notice_epoch_at,a.retain_until,a.retention_started_at,a.retention_completed_at) THEN
  RAISE EXCEPTION 'active package Send pair differs or is missing' USING ERRCODE='23514'; END IF;
 PERFORM hash_package_send_privacy_clear_v1(a.org_id,a.package_id,a.capture_revision);
 SELECT d.status INTO STRICT state FROM documents d WHERE d.id=a.document_id AND d.org_id=a.org_id;
 SELECT p.draft_generation INTO STRICT generation FROM document_packages_v1 p WHERE p.id=a.package_id AND p.org_id=a.org_id AND p.document_id=a.document_id;
 IF EXISTS(SELECT 1 FROM data_subject_requests r WHERE r.org_id=a.org_id AND r.status IN ('open','in_progress')
  AND (r.document_id IS NULL OR EXISTS(SELECT 1 FROM document_package_capture_members_v1 m WHERE m.package_id=a.package_id AND m.revision=a.capture_revision AND m.org_id=a.org_id AND m.member_document_id=r.document_id))) THEN
  RAISE EXCEPTION 'active package subject privacy review is pending' USING ERRCODE='23514'; END IF;
 IF state<>'sealing' OR generation<>a.captured_draft_generation
  OR NOT hash_package_send_main_matches_v1(a.document_id,a.org_id,a.package_id,a.capture_revision) THEN
  RAISE EXCEPTION 'active package root or main no longer matches capture' USING ERRCODE='23514'; END IF;
END;
$$ LANGUAGE plpgsql;
CREATE FUNCTION hash_guard_package_send_pair_v1() RETURNS trigger AS $$
DECLARE aid UUID;
BEGIN
 IF TG_TABLE_NAME='documents' THEN
  FOR aid IN SELECT attempt_id FROM document_package_send_attempts_v1 WHERE document_id=NEW.id AND terminal_outcome IS NULL LOOP
   PERFORM hash_check_package_send_pair_v1(aid);
  END LOOP;
 ELSIF TG_TABLE_NAME='send_sealing_intents' THEN
  IF TG_OP='DELETE' THEN aid:=OLD.package_send_attempt_id; ELSE aid:=NEW.package_send_attempt_id; END IF;
  IF aid IS NOT NULL THEN PERFORM hash_check_package_send_pair_v1(aid); END IF;
 ELSE
  PERFORM hash_check_package_send_pair_v1(NEW.attempt_id);
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER package_send_attempt_pair_v1 AFTER INSERT OR UPDATE ON document_package_send_attempts_v1
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_pair_v1();
CREATE CONSTRAINT TRIGGER package_send_intent_pair_v1 AFTER INSERT OR UPDATE OR DELETE ON send_sealing_intents
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_pair_v1();
CREATE CONSTRAINT TRIGGER package_send_document_pair_v1 AFTER UPDATE ON documents
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_pair_v1();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE documents,document_packages_v1,document_package_captures_v1,document_package_capture_members_v1,
  document_package_send_attempts_v1,send_sealing_intents,data_subject_requests IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM document_package_send_attempts_v1)
  OR EXISTS(SELECT 1 FROM send_sealing_intents WHERE package_send_attempt_id IS NOT NULL) THEN
  RAISE EXCEPTION 'durable package Send history prevents rollback' USING ERRCODE='23514'; END IF;
END $$;
DROP TRIGGER package_send_document_pair_v1 ON documents;
DROP TRIGGER package_send_intent_pair_v1 ON send_sealing_intents;
DROP TRIGGER package_send_attempt_pair_v1 ON document_package_send_attempts_v1;
DROP FUNCTION hash_guard_package_send_pair_v1();
DROP FUNCTION hash_check_package_send_pair_v1(UUID);
DROP TRIGGER package_send_intent_guard_v1 ON send_sealing_intents;
DROP FUNCTION hash_guard_package_send_intent_v1();
DROP TRIGGER package_send_attempt_guard_v1 ON document_package_send_attempts_v1;
DROP FUNCTION hash_guard_package_send_attempt_v1();
DROP FUNCTION hash_package_send_privacy_clear_v1(UUID,UUID,BIGINT);
DROP FUNCTION hash_package_send_main_matches_v1(UUID,UUID,UUID,BIGINT);
ALTER TABLE send_sealing_intents DROP CONSTRAINT send_package_attempt_scope_v1,DROP CONSTRAINT send_package_not_delegated_v1,DROP COLUMN package_send_attempt_id;
DROP TABLE document_package_send_attempts_v1;
DROP INDEX document_package_capture_send_identity_v1;
-- +goose StatementEnd
