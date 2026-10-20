-- +goose Up
-- Immutable associations for one exact initial Send effect set. Historical
-- completions are not backfilled, and M99 remains closed for nonempty packages.
CREATE TABLE document_package_send_initial_invite_receipts_v1 (
 attempt_id UUID NOT NULL,org_id UUID NOT NULL,document_id UUID NOT NULL,
 recipient_id UUID NOT NULL CHECK(recipient_id<>'00000000-0000-0000-0000-000000000000'),
 email_delivery_id UUID NOT NULL UNIQUE CHECK(email_delivery_id<>'00000000-0000-0000-0000-000000000000'),
 invited_event_id UUID NOT NULL UNIQUE CHECK(invited_event_id<>'00000000-0000-0000-0000-000000000000'),
 invited_event_row_sha256 BYTEA NOT NULL CHECK(octet_length(invited_event_row_sha256)=32 AND invited_event_row_sha256<>decode(repeat('00',32),'hex')),
 token_hash BYTEA NOT NULL CHECK(octet_length(token_hash)=32 AND token_hash<>decode(repeat('00',32),'hex')),
 token_expires_at TIMESTAMPTZ NOT NULL CHECK(isfinite(token_expires_at)),
 message_sha256 BYTEA NOT NULL CHECK(octet_length(message_sha256)=32 AND message_sha256<>decode(repeat('00',32),'hex')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 PRIMARY KEY(attempt_id,recipient_id),
 FOREIGN KEY(attempt_id,org_id,document_id)
  REFERENCES document_package_send_attempts_v1(attempt_id,org_id,document_id) ON DELETE RESTRICT
);
CREATE TABLE document_package_send_completions_v1 (
 attempt_id UUID PRIMARY KEY,org_id UUID NOT NULL,document_id UUID NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('sent','expired')),
 manifest_sha256 BYTEA NOT NULL CHECK(octet_length(manifest_sha256)=32 AND manifest_sha256<>decode(repeat('00',32),'hex')),
 legal_commitment_sha256 BYTEA NOT NULL CHECK(octet_length(legal_commitment_sha256)=32 AND legal_commitment_sha256<>decode(repeat('00',32),'hex')),
 article13_notice_epoch_at TIMESTAMPTZ NOT NULL CHECK(isfinite(article13_notice_epoch_at)),
 retain_until TIMESTAMPTZ NOT NULL CHECK(isfinite(retain_until)),
 recipient_count INTEGER NOT NULL CHECK(recipient_count>=0),
 invite_count INTEGER NOT NULL CHECK(invite_count>=0),
 sent_event_id UUID NOT NULL UNIQUE CHECK(sent_event_id<>'00000000-0000-0000-0000-000000000000'),
 sent_event_row_sha256 BYTEA NOT NULL CHECK(octet_length(sent_event_row_sha256)=32 AND sent_event_row_sha256<>decode(repeat('00',32),'hex')),
 expired_event_id UUID UNIQUE,expired_event_row_sha256 BYTEA,
 effect_sha256 BYTEA NOT NULL CHECK(octet_length(effect_sha256)=32 AND effect_sha256<>decode(repeat('00',32),'hex')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 FOREIGN KEY(attempt_id,org_id,document_id)
  REFERENCES document_package_send_attempts_v1(attempt_id,org_id,document_id) ON DELETE RESTRICT,
 CHECK((outcome='sent' AND invite_count=recipient_count AND expired_event_id IS NULL AND expired_event_row_sha256 IS NULL)
  OR (outcome='expired' AND invite_count=0 AND expired_event_id IS NOT NULL
   AND expired_event_id<>'00000000-0000-0000-0000-000000000000' AND expired_event_row_sha256 IS NOT NULL
   AND octet_length(expired_event_row_sha256)=32 AND expired_event_row_sha256<>decode(repeat('00',32),'hex')))
);
-- No FK to mutable recipient/outbox/event projections: later cleanup/redaction
-- cannot delete or relabel the scalar historical association proven at insert.
-- Reserved, bounded new audit identities are unique; no legacy row is deduped.
CREATE UNIQUE INDEX document_package_send_audit_identity_v1 ON events
 (org_id,document_id,(payload_json->>'package_send_attempt_id'),kind,
  (COALESCE(recipient_id,'00000000-0000-0000-0000-000000000000'::uuid)))
 WHERE payload_json->>'package_send_schema'='hash-package-send-v1'
  AND octet_length(payload_json->>'package_send_attempt_id')=36
  AND kind IN ('document.sent','recipient.invited','document.expired');

-- +goose StatementBegin
CREATE FUNCTION hash_package_send_completion_version_v1() RETURNS INTEGER AS $$ SELECT 1; $$ LANGUAGE sql STABLE;
CREATE FUNCTION hash_package_send_completion_frame_v1(value TEXT) RETURNS BYTEA AS $$
 SELECT int8send(octet_length(convert_to(value,'UTF8'))::bigint)||convert_to(value,'UTF8');
$$ LANGUAGE sql IMMUTABLE STRICT;
CREATE FUNCTION hash_package_send_message_sha256_v1(eid UUID) RETURNS BYTEA AS $$
 SELECT sha256(convert_to('hash:package-send-message:v1','UTF8')||decode('00','hex')
  ||hash_package_send_completion_frame_v1(e.to_email)||hash_package_send_completion_frame_v1(e.subject)
  ||hash_package_send_completion_frame_v1(e.html_body)||hash_package_send_completion_frame_v1(e.text_body)
  ||hash_package_send_completion_frame_v1(e.reply_to)||hash_package_send_completion_frame_v1(e.from_name)
  ||hash_package_send_completion_frame_v1(e.headers_json::text)) FROM email_deliveries e WHERE e.id=eid;
$$ LANGUAGE sql STABLE;
-- Only a fixed43-byte candidate is extracted, never a collection of body links.
-- The native fixed renderer independently owns the configured URL origin.
CREATE FUNCTION hash_package_send_message_token_matches_v1(body TEXT,expected BYTEA) RETURNS BOOLEAN AS $$
 SELECT COALESCE(octet_length(expected)=32 AND sha256(convert_to(
  substring(body FROM '/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)'),'UTF8'))=expected,false);
$$ LANGUAGE sql IMMUTABLE STRICT;

CREATE FUNCTION hash_package_send_event_matches_v1(eid UUID,aid UUID,expected_kind TEXT,expected_recipient UUID) RETURNS BOOLEAN AS $$
DECLARE e events%ROWTYPE; a document_package_send_attempts_v1%ROWTYPE;
BEGIN
 SELECT * INTO a FROM document_package_send_attempts_v1 WHERE attempt_id=aid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO e FROM events WHERE id=eid;
 IF NOT FOUND OR e.org_id<>a.org_id OR e.document_id IS DISTINCT FROM a.document_id OR e.kind<>expected_kind
  OR e.recipient_id IS DISTINCT FROM expected_recipient OR octet_length(e.row_hash) IS DISTINCT FROM 32
  OR e.row_hash=decode(repeat('00',32),'hex') OR (e.prev_hash IS NOT NULL AND octet_length(e.prev_hash)<>32)
  OR e.created_at IS NULL OR NOT isfinite(e.created_at) OR e.payload_hashed IS NULL
  OR convert_from(e.payload_hashed,'UTF8')::jsonb IS DISTINCT FROM e.payload_json
  OR e.payload_json->>'package_send_schema' IS DISTINCT FROM 'hash-package-send-v1'
  OR e.payload_json->>'package_send_attempt_id' IS DISTINCT FROM a.attempt_id::text
  OR e.payload_json->>'package_id' IS DISTINCT FROM a.package_id::text
  OR e.payload_json->>'capture_revision' IS DISTINCT FROM a.capture_revision::text
  OR e.payload_json->>'manifest_sha256' IS DISTINCT FROM encode(a.manifest_sha256,'hex')
  OR e.payload_json->>'legal_commitment_sha256' IS DISTINCT FROM encode(a.legal_commitment_sha256,'hex') THEN RETURN false; END IF;
 IF expected_kind IN ('document.sent','recipient.invited') AND e.actor_user_id IS DISTINCT FROM a.actor_user_id THEN RETURN false; END IF;
 IF expected_kind='document.expired' AND e.actor_user_id IS NOT NULL AND e.actor_user_id<>a.actor_user_id THEN RETURN false; END IF;
 IF expected_kind='document.sent' AND NOT hash_article13_marker_matches(e.payload_json,e.payload_hashed,'hash-a13-2026-08-31',a.article13_notice_epoch_at) THEN RETURN false; END IF;
 IF expected_kind='document.expired' AND (e.payload_json->'before_invite' IS DISTINCT FROM 'true'::jsonb
  OR e.payload_json->'irreversible_sealing_recovery' IS DISTINCT FROM 'true'::jsonb) THEN RETURN false; END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END;
$$ LANGUAGE plpgsql STABLE;
CREATE FUNCTION hash_package_send_event_id_v1(aid UUID,expected_kind TEXT,expected_recipient UUID) RETURNS UUID AS $$
DECLARE found_id UUID; matches INTEGER;
BEGIN
 SELECT count(*)::integer,min(v.id::text)::uuid INTO matches,found_id FROM (
  SELECT e.id FROM document_package_send_attempts_v1 a JOIN events e ON e.org_id=a.org_id AND e.document_id=a.document_id
  WHERE a.attempt_id=aid AND e.kind=expected_kind AND e.kind IN ('document.sent','recipient.invited','document.expired')
   AND e.recipient_id IS NOT DISTINCT FROM expected_recipient
   AND e.payload_json->>'package_send_schema'='hash-package-send-v1'
   AND octet_length(e.payload_json->>'package_send_attempt_id')=36
   AND e.payload_json->>'package_send_attempt_id'=a.attempt_id::text LIMIT 2
 ) v;
 IF matches<>1 OR NOT hash_package_send_event_matches_v1(found_id,aid,expected_kind,expected_recipient) THEN RETURN NULL; END IF;
 RETURN found_id;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE FUNCTION hash_package_send_invite_matches_v1(aid UUID,rid UUID,eid UUID,invited_id UUID,invited_hash BYTEA,token_hash BYTEA,token_expiry TIMESTAMPTZ,message_hash BYTEA) RETURNS BOOLEAN AS $$
 SELECT COALESCE((SELECT
  r.status='sent' AND r.magic_token_hash=token_hash AND isfinite(r.magic_token_expires_at)
  AND r.magic_token_expires_at=token_expiry AND r.magic_token_expires_at>clock_timestamp()
  AND (d.expires_at IS NULL OR (d.expires_at>clock_timestamp() AND r.magic_token_expires_at<=d.expires_at))
  AND e.to_email=r.email AND e.status='pending' AND e.attempts=0 AND e.sent_at IS NULL AND e.last_error=''
  AND e.headers_json='{}'::jsonb AND hash_package_send_message_sha256_v1(e.id)=message_hash
  AND hash_package_send_message_token_matches_v1(e.text_body,r.magic_token_hash)
  AND hash_package_send_message_token_matches_v1(e.html_body,r.magic_token_hash)
  AND hash_package_send_event_id_v1(a.attempt_id,'recipient.invited',r.id)=invited_id
  AND ev.row_hash=invited_hash AND ev.payload_json->>'email'=r.email AND ev.payload_json->>'role'=r.role
 FROM document_package_send_attempts_v1 a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id
 JOIN recipients r ON r.document_id=a.document_id AND r.id=rid JOIN email_deliveries e ON e.id=eid
 JOIN events ev ON ev.id=invited_id WHERE a.attempt_id=aid),false);
$$ LANGUAGE sql VOLATILE;

-- Every actual initial invite receipt enters this digest. Domain separation,
-- fixed binary UUID/int/timestamp encodings and explicit optional markers avoid
-- dependence on JSON rendering or raw token/mail/URL retention in the receipt.
CREATE FUNCTION hash_package_send_completion_effect_v1(aid UUID,finished TEXT,nrec INTEGER,ninv INTEGER,sent_id UUID,expired_id UUID) RETURNS BYTEA AS $$
 SELECT CASE WHEN finished IN ('sent','expired') AND nrec>=0 AND ninv>=0 THEN
  sha256(convert_to('hash:package-send-completion:v1','UTF8')||decode('00','hex')
   ||uuid_send(a.attempt_id)||uuid_send(a.org_id)||uuid_send(a.document_id)||uuid_send(a.package_id)||int8send(a.capture_revision)
   ||a.manifest_sha256||a.legal_commitment_sha256||timestamptz_send(a.article13_notice_epoch_at)||timestamptz_send(a.retain_until)
   ||hash_package_send_completion_frame_v1(finished)||int4send(nrec)||int4send(ninv)||uuid_send(sent_id)||se.row_hash
   ||CASE WHEN expired_id IS NULL THEN decode('00','hex') ELSE decode('01','hex')||uuid_send(expired_id)||ee.row_hash END
   ||sha256(COALESCE((SELECT string_agg(uuid_send(r.recipient_id)||uuid_send(r.email_delivery_id)||uuid_send(r.invited_event_id)
      ||r.invited_event_row_sha256||r.token_hash||timestamptz_send(r.token_expires_at)||r.message_sha256,''::bytea ORDER BY r.recipient_id)
     FROM document_package_send_initial_invite_receipts_v1 r WHERE r.attempt_id=a.attempt_id),''::bytea)))
  ELSE NULL END
 FROM document_package_send_attempts_v1 a JOIN events se ON se.id=sent_id LEFT JOIN events ee ON ee.id=expired_id WHERE a.attempt_id=aid;
$$ LANGUAGE sql STABLE;

CREATE FUNCTION hash_package_send_completion_matches_v1(aid UUID) RETURNS BOOLEAN AS $$
DECLARE a document_package_send_attempts_v1%ROWTYPE; c document_package_send_completions_v1%ROWTYPE;
 d documents%ROWTYPE; nrec INTEGER; ninv INTEGER; nevents INTEGER; r document_package_send_initial_invite_receipts_v1%ROWTYPE;
BEGIN
 SELECT * INTO a FROM document_package_send_attempts_v1 WHERE attempt_id=aid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM document_package_send_completions_v1 WHERE attempt_id=aid;
 IF NOT FOUND OR c.org_id<>a.org_id OR c.document_id<>a.document_id
  OR c.manifest_sha256 IS DISTINCT FROM a.manifest_sha256 OR c.legal_commitment_sha256 IS DISTINCT FROM a.legal_commitment_sha256
  OR c.article13_notice_epoch_at IS DISTINCT FROM a.article13_notice_epoch_at OR c.retain_until IS DISTINCT FROM a.retain_until
  OR NOT hash_package_send_members_retained_v1(aid) THEN RETURN false; END IF;
 SELECT * INTO d FROM documents WHERE id=a.document_id AND org_id=a.org_id;
 IF NOT FOUND OR d.deleted_at IS NOT NULL OR d.status<>c.outcome OR d.sent_at IS DISTINCT FROM a.article13_notice_epoch_at
  OR d.article13_notice_epoch_at IS DISTINCT FROM a.article13_notice_epoch_at OR d.article13_notice_schema<>'hash-a13-2026-08-31'
  OR NOT d.article13_notice_epoch_v61_committed OR NOT d.evidence_version_pins_required THEN RETURN false; END IF;
 SELECT count(*)::integer INTO nrec FROM recipients WHERE document_id=a.document_id;
 SELECT count(*)::integer INTO ninv FROM document_package_send_initial_invite_receipts_v1 WHERE attempt_id=aid;
 SELECT count(*)::integer INTO nevents FROM events WHERE org_id=a.org_id AND document_id=a.document_id
  AND kind='recipient.invited' AND payload_json->>'package_send_schema'='hash-package-send-v1'
  AND octet_length(payload_json->>'package_send_attempt_id')=36 AND payload_json->>'package_send_attempt_id'=a.attempt_id::text;
 IF nrec<>c.recipient_count OR ninv<>c.invite_count OR nevents<>ninv
  OR hash_package_send_event_id_v1(aid,'document.sent',NULL) IS DISTINCT FROM c.sent_event_id
  OR NOT EXISTS(SELECT 1 FROM events WHERE id=c.sent_event_id AND row_hash=c.sent_event_row_sha256
   AND payload_json->>'recipient_count'=c.invite_count::text) THEN RETURN false; END IF;
 IF c.outcome='expired' THEN
  IF d.expires_at IS NULL OR d.expires_at>clock_timestamp() OR ninv<>0
   OR hash_package_send_event_id_v1(aid,'document.expired',NULL) IS DISTINCT FROM c.expired_event_id
   OR NOT EXISTS(SELECT 1 FROM events WHERE id=c.expired_event_id AND row_hash=c.expired_event_row_sha256)
   OR EXISTS(SELECT 1 FROM recipients WHERE document_id=a.document_id AND magic_token_expires_at>clock_timestamp())
   OR EXISTS(SELECT 1 FROM reminders WHERE document_id=a.document_id) THEN RETURN false; END IF;
 ELSE
  IF ninv<>nrec OR (d.expires_at IS NOT NULL AND d.expires_at<=clock_timestamp())
   OR c.expired_event_id IS NOT NULL OR EXISTS(SELECT 1 FROM events WHERE org_id=a.org_id AND document_id=a.document_id
    AND kind='document.expired' AND payload_json->>'package_send_schema'='hash-package-send-v1'
    AND payload_json->>'package_send_attempt_id'=a.attempt_id::text) THEN RETURN false; END IF;
  FOR r IN SELECT * FROM document_package_send_initial_invite_receipts_v1 WHERE attempt_id=aid ORDER BY recipient_id LOOP
   IF r.org_id<>a.org_id OR r.document_id<>a.document_id OR NOT hash_package_send_invite_matches_v1(aid,r.recipient_id,r.email_delivery_id,
    r.invited_event_id,r.invited_event_row_sha256,r.token_hash,r.token_expires_at,r.message_sha256) THEN RETURN false; END IF;
  END LOOP;
 END IF;
 RETURN COALESCE(c.effect_sha256=hash_package_send_completion_effect_v1(aid,c.outcome,c.recipient_count,c.invite_count,c.sent_event_id,c.expired_event_id),false);
END;
$$ LANGUAGE plpgsql VOLATILE;

CREATE FUNCTION hash_guard_package_send_completion_receipt_v1() RETURNS trigger AS $$
DECLARE a document_package_send_attempts_v1%ROWTYPE; i send_sealing_intents%ROWTYPE; state TEXT;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'package Send effect receipts are immutable' USING ERRCODE='23514'; END IF;
 SELECT status INTO state FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id AND deleted_at IS NULL FOR UPDATE NOWAIT;
 IF NOT FOUND OR state NOT IN ('sent','expired') THEN RAISE EXCEPTION 'package completion root is unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO a FROM document_package_send_attempts_v1 WHERE attempt_id=NEW.attempt_id AND org_id=NEW.org_id AND document_id=NEW.document_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR a.terminal_outcome IS NOT NULL OR a.retention_started_at IS NULL OR a.retention_completed_at IS NULL THEN
  RAISE EXCEPTION 'package completion requires active retained exact attempt' USING ERRCODE='23514'; END IF;
 SELECT * INTO i FROM send_sealing_intents WHERE package_send_attempt_id=a.attempt_id AND org_id=a.org_id AND document_id=a.document_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR ROW(i.actor_user_id,i.article13_notice_epoch_at,i.retain_until,i.retention_started_at,i.retention_completed_at)
  IS DISTINCT FROM ROW(a.actor_user_id,a.article13_notice_epoch_at,a.retain_until,a.retention_started_at,a.retention_completed_at) THEN
  RAISE EXCEPTION 'package completion intent differs' USING ERRCODE='23514'; END IF;
 PERFORM hash_package_send_privacy_clear_v1(a.org_id,a.package_id,a.capture_revision);
 IF NOT hash_package_send_members_retained_v1(a.attempt_id) THEN RAISE EXCEPTION 'package completion member receipts are incomplete' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='document_package_send_initial_invite_receipts_v1' THEN
  IF state<>'sent' OR EXISTS(SELECT 1 FROM document_package_send_completions_v1 WHERE attempt_id=a.attempt_id)
   OR NOT hash_package_send_invite_matches_v1(a.attempt_id,NEW.recipient_id,NEW.email_delivery_id,NEW.invited_event_id,
    NEW.invited_event_row_sha256,NEW.token_hash,NEW.token_expires_at,NEW.message_sha256) THEN
   RAISE EXCEPTION 'package initial invite effect differs from live rows' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.outcome<>state OR NEW.manifest_sha256 IS DISTINCT FROM a.manifest_sha256 OR NEW.legal_commitment_sha256 IS DISTINCT FROM a.legal_commitment_sha256
   OR NEW.article13_notice_epoch_at IS DISTINCT FROM a.article13_notice_epoch_at OR NEW.retain_until IS DISTINCT FROM a.retain_until
   OR NEW.sent_event_id IS DISTINCT FROM hash_package_send_event_id_v1(a.attempt_id,'document.sent',NULL)
   OR NEW.effect_sha256 IS DISTINCT FROM hash_package_send_completion_effect_v1(a.attempt_id,NEW.outcome,NEW.recipient_count::integer,NEW.invite_count::integer,NEW.sent_event_id,NEW.expired_event_id) THEN
   RAISE EXCEPTION 'package completion summary differs from exact effect set' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER package_send_initial_invite_receipt_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_package_send_initial_invite_receipts_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_completion_receipt_v1();
CREATE TRIGGER package_send_completion_receipt_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_package_send_completions_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_package_send_completion_receipt_v1();

CREATE FUNCTION hash_require_package_send_completion_receipt_v1() RETURNS trigger AS $$
DECLARE aid UUID;
BEGIN
 IF TG_TABLE_NAME='document_package_send_attempts_v1' THEN
  IF NEW.terminal_outcome IS DISTINCT FROM 'completed' THEN RETURN NULL; END IF;
  IF TG_OP='UPDATE' AND OLD.terminal_outcome='completed' THEN RETURN NULL; END IF;
 END IF;
 aid:=NEW.attempt_id;
 PERFORM 1 FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM document_package_send_attempts_v1 WHERE attempt_id=aid AND terminal_outcome='completed')
  OR EXISTS(SELECT 1 FROM send_sealing_intents WHERE package_send_attempt_id=aid) THEN
  RAISE EXCEPTION 'completed package Send requires its exact atomic effect receipts' USING ERRCODE='23514'; END IF;
 -- Each child requires its immutable summary in this transaction. Full effect
 -- validation is scheduled by that summary and the new terminal transition,
 -- avoiding one full collection scan for every individual invite receipt.
 IF TG_TABLE_NAME='document_package_send_initial_invite_receipts_v1' THEN
  IF NOT EXISTS(SELECT 1 FROM document_package_send_completions_v1 WHERE attempt_id=aid AND org_id=NEW.org_id AND document_id=NEW.document_id) THEN
   RAISE EXCEPTION 'package initial invite requires its atomic completion summary' USING ERRCODE='23514'; END IF;
 ELSIF hash_package_send_completion_matches_v1(aid) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'completed package Send requires its exact atomic effect receipts' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER package_send_completion_attempt_receipt_v1 AFTER INSERT OR UPDATE ON document_package_send_attempts_v1
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_require_package_send_completion_receipt_v1();
CREATE CONSTRAINT TRIGGER package_send_completion_effect_receipt_v1 AFTER INSERT ON document_package_send_completions_v1
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_require_package_send_completion_receipt_v1();
CREATE CONSTRAINT TRIGGER package_send_completion_invite_receipt_v1 AFTER INSERT ON document_package_send_initial_invite_receipts_v1
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_require_package_send_completion_receipt_v1();
-- +goose StatementEnd

-- +goose Down
-- Started effect associations are evidence even if a caller has not observed
-- COMMIT. Never erase them to make an old binary appear compatible.
-- +goose StatementBegin
LOCK TABLE documents,document_package_send_attempts_v1,send_sealing_intents,document_package_send_initial_invite_receipts_v1,document_package_send_completions_v1,events
 IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM document_package_send_initial_invite_receipts_v1) OR EXISTS(SELECT 1 FROM document_package_send_completions_v1) THEN
  RAISE EXCEPTION 'package Send completion history prevents rollback' USING ERRCODE='23514'; END IF;
END $$;
DROP TRIGGER package_send_completion_invite_receipt_v1 ON document_package_send_initial_invite_receipts_v1;
DROP TRIGGER package_send_completion_effect_receipt_v1 ON document_package_send_completions_v1;
DROP TRIGGER package_send_completion_attempt_receipt_v1 ON document_package_send_attempts_v1;
DROP FUNCTION hash_require_package_send_completion_receipt_v1();
DROP TRIGGER package_send_completion_receipt_guard_v1 ON document_package_send_completions_v1;
DROP TRIGGER package_send_initial_invite_receipt_guard_v1 ON document_package_send_initial_invite_receipts_v1;
DROP FUNCTION hash_guard_package_send_completion_receipt_v1();
DROP FUNCTION hash_package_send_completion_matches_v1(UUID);
DROP FUNCTION hash_package_send_completion_effect_v1(UUID,TEXT,INTEGER,INTEGER,UUID,UUID);
DROP FUNCTION hash_package_send_invite_matches_v1(UUID,UUID,UUID,UUID,BYTEA,BYTEA,TIMESTAMPTZ,BYTEA);
DROP FUNCTION hash_package_send_event_id_v1(UUID,TEXT,UUID);
DROP FUNCTION hash_package_send_event_matches_v1(UUID,UUID,TEXT,UUID);
DROP FUNCTION hash_package_send_message_token_matches_v1(TEXT,BYTEA);
DROP FUNCTION hash_package_send_message_sha256_v1(UUID);
DROP FUNCTION hash_package_send_completion_frame_v1(TEXT);
DROP FUNCTION hash_package_send_completion_version_v1();
DROP INDEX document_package_send_audit_identity_v1;
DROP TABLE document_package_send_completions_v1;
DROP TABLE document_package_send_initial_invite_receipts_v1;
-- +goose StatementEnd
