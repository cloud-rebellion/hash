-- +goose Up
-- Per-member progress is bound to the original immutable Send attempt/capture.
-- Existing completed history is preserved without fabricated provider receipts.
-- This does not relax M99 or qualify provider recovery or the signing ceremony.
CREATE TABLE document_package_send_member_retention_v1 (
 attempt_id UUID NOT NULL,org_id UUID NOT NULL,document_id UUID NOT NULL,
 member_position SMALLINT NOT NULL CHECK(member_position BETWEEN 0 AND 16),
 provider_namespace_sha256 BYTEA NOT NULL CHECK(octet_length(provider_namespace_sha256)=32
  AND provider_namespace_sha256<>decode(repeat('00',32),'hex')),
 started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(started_at)),
 verified_at TIMESTAMPTZ,
 observed_mode TEXT,
 observed_retain_until TIMESTAMPTZ,
 verifier_profile TEXT,
 PRIMARY KEY(attempt_id,member_position),
 FOREIGN KEY(attempt_id,org_id,document_id)
  REFERENCES document_package_send_attempts_v1(attempt_id,org_id,document_id) ON DELETE RESTRICT,
 CHECK((verified_at IS NULL AND observed_mode IS NULL AND observed_retain_until IS NULL AND verifier_profile IS NULL)
  OR (verified_at IS NOT NULL AND isfinite(verified_at) AND observed_mode IS NOT NULL AND observed_mode='COMPLIANCE'
   AND observed_retain_until IS NOT NULL AND isfinite(observed_retain_until)
   AND verifier_profile IS NOT NULL AND verifier_profile='s3-compliance-digest-v1'))
);

-- +goose StatementBegin
CREATE FUNCTION hash_package_send_member_retention_version_v1() RETURNS INTEGER AS $$
 SELECT 1;
$$ LANGUAGE sql STABLE;

CREATE FUNCTION hash_package_send_members_retained_v1(aid UUID) RETURNS BOOLEAN AS $$
 SELECT COALESCE((
  SELECT
   (SELECT count(*) FROM document_package_capture_members_v1 m
    WHERE m.package_id=a.package_id AND m.revision=a.capture_revision AND m.org_id=a.org_id)=a.member_count
   AND (SELECT count(*) FROM document_package_send_member_retention_v1 r WHERE r.attempt_id=a.attempt_id)=a.member_count
   AND (SELECT count(DISTINCT r.provider_namespace_sha256) FROM document_package_send_member_retention_v1 r
    WHERE r.attempt_id=a.attempt_id)=1
   AND NOT EXISTS(
    SELECT 1 FROM document_package_capture_members_v1 m
    LEFT JOIN document_package_send_member_retention_v1 r ON r.attempt_id=a.attempt_id AND r.member_position=m.member_position
    WHERE m.package_id=a.package_id AND m.revision=a.capture_revision AND m.org_id=a.org_id
     AND (m.member_position<0 OR m.member_position>=a.member_count OR r.attempt_id IS NULL
      OR r.org_id<>a.org_id OR r.document_id<>a.document_id OR r.verified_at IS NULL
      OR r.observed_mode IS DISTINCT FROM 'COMPLIANCE' OR r.verifier_profile IS DISTINCT FROM 's3-compliance-digest-v1'
      OR r.observed_retain_until IS NULL OR NOT isfinite(r.observed_retain_until) OR r.observed_retain_until<a.retain_until))
  FROM document_package_send_attempts_v1 a WHERE a.attempt_id=aid
 ),false);
$$ LANGUAGE sql STABLE;

CREATE FUNCTION hash_guard_package_send_member_retention_v1() RETURNS trigger AS $$
DECLARE a document_package_send_attempts_v1%ROWTYPE; i send_sealing_intents%ROWTYPE; root_status TEXT;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'package member retention history is immutable' USING ERRCODE='23514'; END IF;
 -- Scope is stored only to find and lock the real root before reading attempt,
 -- intent or member data. The composite FK and exact checks prevent adoption.
 SELECT d.status INTO root_status FROM documents d
  WHERE d.id=NEW.document_id AND d.org_id=NEW.org_id AND d.deleted_at IS NULL FOR UPDATE NOWAIT;
 IF NOT FOUND OR root_status<>'sealing' THEN
  RAISE EXCEPTION 'package member retention root is unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO a FROM document_package_send_attempts_v1
  WHERE attempt_id=NEW.attempt_id AND org_id=NEW.org_id AND document_id=NEW.document_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR a.terminal_outcome IS NOT NULL THEN
  RAISE EXCEPTION 'package member retention requires the active exact attempt' USING ERRCODE='23514'; END IF;
 SELECT * INTO i FROM send_sealing_intents
  WHERE package_send_attempt_id=a.attempt_id AND org_id=a.org_id AND document_id=a.document_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR a.retention_started_at IS NULL OR i.retention_started_at IS NULL
  OR ROW(i.actor_user_id,i.article13_notice_epoch_at,i.retain_until,i.retention_started_at,i.retention_completed_at)
   IS DISTINCT FROM ROW(a.actor_user_id,a.article13_notice_epoch_at,a.retain_until,a.retention_started_at,a.retention_completed_at) THEN
  RAISE EXCEPTION 'package member retention requires mirrored started intent' USING ERRCODE='23514'; END IF;
 IF NEW.member_position<0 OR NEW.member_position>=a.member_count OR NOT EXISTS(
  SELECT 1 FROM document_package_capture_members_v1 m
   WHERE m.package_id=a.package_id AND m.revision=a.capture_revision AND m.org_id=a.org_id AND m.member_position=NEW.member_position) THEN
  RAISE EXCEPTION 'package member retention does not match the immutable capture' USING ERRCODE='23514'; END IF;
 -- Ledger-only mutations do not schedule M103's pair constraint triggers.
 -- Repeat its sorted immutable-subject fences and fresh pending-request check.
 PERFORM hash_package_send_privacy_clear_v1(a.org_id,a.package_id,a.capture_revision);
 IF EXISTS(SELECT 1 FROM document_package_send_member_retention_v1 r WHERE r.attempt_id=a.attempt_id
  AND r.provider_namespace_sha256 IS DISTINCT FROM NEW.provider_namespace_sha256) THEN
  RAISE EXCEPTION 'package member provider namespace differs' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.verified_at IS NOT NULL OR NEW.observed_mode IS NOT NULL OR NEW.observed_retain_until IS NOT NULL OR NEW.verifier_profile IS NOT NULL THEN
   RAISE EXCEPTION 'new package member progress cannot claim provider verification' USING ERRCODE='23514'; END IF;
 ELSE
  IF ROW(NEW.attempt_id,NEW.org_id,NEW.document_id,NEW.member_position,NEW.provider_namespace_sha256,NEW.started_at)
   IS DISTINCT FROM ROW(OLD.attempt_id,OLD.org_id,OLD.document_id,OLD.member_position,OLD.provider_namespace_sha256,OLD.started_at)
   OR (OLD.verified_at IS NOT NULL AND ROW(NEW.verified_at,NEW.observed_mode,NEW.observed_retain_until,NEW.verifier_profile)
    IS DISTINCT FROM ROW(OLD.verified_at,OLD.observed_mode,OLD.observed_retain_until,OLD.verifier_profile)) THEN
   RAISE EXCEPTION 'package member retention identity or verification is immutable' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.verified_at IS NOT NULL AND (NEW.observed_retain_until IS NULL OR NEW.observed_retain_until<a.retain_until) THEN
  RAISE EXCEPTION 'package member observed retention is below the original target' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER package_send_member_retention_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_package_send_member_retention_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_member_retention_v1();

CREATE FUNCTION hash_guard_package_send_member_completion_v1() RETURNS trigger AS $$
DECLARE aid UUID;
BEGIN
 IF TG_TABLE_NAME='send_sealing_intents' THEN
  IF NEW.package_send_attempt_id IS NULL OR NEW.retention_completed_at IS NULL THEN RETURN NEW; END IF;
  IF TG_OP='UPDATE' AND OLD.retention_completed_at IS NOT NULL THEN RETURN NEW; END IF;
  aid:=NEW.package_send_attempt_id;
 ELSE
  IF NEW.terminal_outcome IS DISTINCT FROM 'completed' THEN RETURN NEW; END IF;
  IF TG_OP='UPDATE' AND OLD.terminal_outcome='completed' THEN RETURN NEW; END IF;
  aid:=NEW.attempt_id;
 END IF;
 PERFORM 1 FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR NOT hash_package_send_members_retained_v1(aid) THEN
  RAISE EXCEPTION 'package completion requires every exact member retention receipt' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER package_send_member_intent_completion_guard_v1 BEFORE INSERT OR UPDATE ON send_sealing_intents
 FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_member_completion_v1();
CREATE TRIGGER package_send_member_attempt_completion_guard_v1 BEFORE INSERT OR UPDATE ON document_package_send_attempts_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_member_completion_v1();
-- +goose StatementEnd

-- +goose Down
-- Unknown provider work and verified receipts are both durable history. Empty
-- rollback requires quiesced consumers; it does not promise old/new binaries
-- can roll together or waive M103's independent occupied-history protection.
-- +goose StatementBegin
LOCK TABLE documents,document_package_send_attempts_v1,send_sealing_intents,document_package_send_member_retention_v1
 IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM document_package_send_member_retention_v1) THEN
  RAISE EXCEPTION 'package member retention history prevents rollback' USING ERRCODE='23514'; END IF;
END $$;
DROP TRIGGER package_send_member_attempt_completion_guard_v1 ON document_package_send_attempts_v1;
DROP TRIGGER package_send_member_intent_completion_guard_v1 ON send_sealing_intents;
DROP FUNCTION hash_guard_package_send_member_completion_v1();
DROP TRIGGER package_send_member_retention_guard_v1 ON document_package_send_member_retention_v1;
DROP FUNCTION hash_guard_package_send_member_retention_v1();
DROP FUNCTION hash_package_send_members_retained_v1(UUID);
DROP FUNCTION hash_package_send_member_retention_version_v1();
DROP TABLE document_package_send_member_retention_v1;
-- +goose StatementEnd
