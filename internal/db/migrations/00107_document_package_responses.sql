-- +goose Up
-- No historical consent is invented. This forward foundation leaves M99
-- CLOSED and requires one exact atomic response receipt for current packages.
-- +goose StatementBegin
CREATE FUNCTION hash_package_response_version_v1() RETURNS INTEGER AS $$ SELECT 1; $$ LANGUAGE sql STABLE;
CREATE FUNCTION hash_package_incorporation_version_v1() RETURNS TEXT AS $$ SELECT 'hash-package-incorporation-v1'::text; $$ LANGUAGE sql IMMUTABLE;
CREATE FUNCTION hash_package_incorporation_text_v1() RETURNS TEXT AS $$
 SELECT 'I have reviewed and agree to the main document and every attachment listed in this contract package. My signature or acknowledgement applies to the complete package identified by the displayed commitments.'::text;
$$ LANGUAGE sql IMMUTABLE;
CREATE FUNCTION hash_package_incorporation_sha256_v1() RETURNS BYTEA AS $$
 SELECT sha256(convert_to(hash_package_incorporation_text_v1(),'UTF8'));
$$ LANGUAGE sql IMMUTABLE;
-- +goose StatementEnd

CREATE TABLE document_package_responses_v1 (
 attempt_id UUID NOT NULL,org_id UUID NOT NULL,document_id UUID NOT NULL,
 recipient_id UUID NOT NULL CHECK(recipient_id<>'00000000-0000-0000-0000-000000000000'),
 package_id UUID NOT NULL,capture_revision BIGINT NOT NULL CHECK(capture_revision>0),
 manifest_sha256 BYTEA NOT NULL CHECK(octet_length(manifest_sha256)=32 AND manifest_sha256<>decode(repeat('00',32),'hex')),
 legal_commitment_sha256 BYTEA NOT NULL CHECK(octet_length(legal_commitment_sha256)=32 AND legal_commitment_sha256<>decode(repeat('00',32),'hex')),
 sent_at TIMESTAMPTZ NOT NULL CHECK(isfinite(sent_at)),
 article13_notice_epoch_at TIMESTAMPTZ NOT NULL CHECK(isfinite(article13_notice_epoch_at) AND article13_notice_epoch_at=sent_at),
 incorporation_version TEXT NOT NULL CHECK(incorporation_version=hash_package_incorporation_version_v1()),
 incorporation_sha256 BYTEA NOT NULL CHECK(incorporation_sha256=hash_package_incorporation_sha256_v1()),
 response_kind TEXT NOT NULL CHECK(response_kind IN ('signed','accepted')),
 signature_id UUID UNIQUE,
 response_event_id UUID NOT NULL UNIQUE CHECK(response_event_id<>'00000000-0000-0000-0000-000000000000'),
 response_event_row_sha256 BYTEA NOT NULL CHECK(octet_length(response_event_row_sha256)=32 AND response_event_row_sha256<>decode(repeat('00',32),'hex')),
 response_event_created_at TIMESTAMPTZ NOT NULL CHECK(isfinite(response_event_created_at) AND response_event_created_at>=sent_at),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 PRIMARY KEY(attempt_id,recipient_id),
 FOREIGN KEY(attempt_id,org_id,document_id) REFERENCES document_package_send_attempts_v1(attempt_id,org_id,document_id) ON DELETE RESTRICT,
 CHECK((response_kind='signed' AND signature_id IS NOT NULL AND signature_id<>'00000000-0000-0000-0000-000000000000')
  OR (response_kind='accepted' AND signature_id IS NULL))
);
CREATE INDEX document_package_response_scope_v1 ON document_package_responses_v1(org_id,document_id,recipient_id);
CREATE UNIQUE INDEX document_package_response_audit_identity_v1 ON events(org_id,document_id,recipient_id,(payload_json->>'package_send_attempt_id'))
 WHERE payload_json->>'package_response_schema'='hash-package-response-v1' AND kind IN ('document.signed','document.accepted');

-- +goose StatementBegin
-- Match Go audit.ChainHashRecord's v2 wire format, including its uint32
-- frames and exact canonical payload bytes. This verifies one row, not the
-- continuity of the interleaved organization chain.
CREATE FUNCTION hash_package_response_audit_frame_v1(value BYTEA) RETURNS BYTEA AS $$
 SELECT int4send(octet_length(value))||value;
$$ LANGUAGE sql IMMUTABLE STRICT;
CREATE FUNCTION hash_package_response_audit_row_sha256_v1(eid UUID) RETURNS BYTEA AS $$
 SELECT CASE WHEN e.payload_hashed IS NOT NULL AND isfinite(e.created_at)
  AND (e.prev_hash IS NULL OR octet_length(e.prev_hash)=32) THEN sha256(
  COALESCE(e.prev_hash,decode(repeat('00',32),'hex'))
  ||hash_package_response_audit_frame_v1(convert_to('hash.audit.chain.v2','UTF8'))
  ||hash_package_response_audit_frame_v1(uuid_send(e.org_id))
  ||hash_package_response_audit_frame_v1(uuid_send(COALESCE(e.document_id,'00000000-0000-0000-0000-000000000000'::uuid)))
  ||hash_package_response_audit_frame_v1(uuid_send(COALESCE(e.recipient_id,'00000000-0000-0000-0000-000000000000'::uuid)))
  ||hash_package_response_audit_frame_v1(uuid_send(COALESCE(e.actor_user_id,'00000000-0000-0000-0000-000000000000'::uuid)))
  ||hash_package_response_audit_frame_v1(convert_to(e.kind,'UTF8'))
  ||hash_package_response_audit_frame_v1(convert_to(COALESCE(host(e.ip),''),'UTF8'))
  ||hash_package_response_audit_frame_v1(convert_to(COALESCE(e.ua,''),'UTF8'))
  -- ChainHashRecord writes the fixed-width timestamp directly; only its
  -- variable-length fields receive a uint32 frame.
  ||int8send((extract(epoch FROM e.created_at)*1000000000)::bigint)
  ||hash_package_response_audit_frame_v1(e.payload_hashed)) END
 FROM events e WHERE e.id=eid;
$$ LANGUAGE sql STABLE;

CREATE FUNCTION hash_has_current_package_response_history_v1(tenant UUID,target UUID) RETURNS BOOLEAN AS $$
 SELECT EXISTS(SELECT 1 FROM documents d JOIN document_package_send_attempts_v1 a ON a.org_id=d.org_id AND a.document_id=d.id
  WHERE d.org_id=tenant AND d.id=target AND (a.terminal_outcome IS NULL OR a.article13_notice_epoch_at=d.article13_notice_epoch_at))
 OR EXISTS(SELECT 1 FROM documents d JOIN document_package_send_completions_v1 c ON c.org_id=d.org_id AND c.document_id=d.id
  WHERE d.org_id=tenant AND d.id=target AND c.article13_notice_epoch_at=d.article13_notice_epoch_at);
$$ LANGUAGE sql STABLE;

CREATE FUNCTION hash_package_response_binding_matches_v1(aid UUID,tenant UUID,target UUID) RETURNS BOOLEAN AS $$
 SELECT COALESCE((SELECT a.terminal_outcome='completed' AND a.retention_started_at IS NOT NULL AND a.retention_completed_at IS NOT NULL
  AND d.deleted_at IS NULL AND d.status IN ('sent','in_progress','changes_requested','finalizing','completed','declined','voided','expired')
  AND d.sent_at=a.article13_notice_epoch_at AND d.article13_notice_epoch_at=a.article13_notice_epoch_at
  AND d.article13_notice_schema='hash-a13-2026-08-31' AND d.article13_notice_epoch_v61_committed AND d.evidence_version_pins_required
  AND c.outcome='sent' AND c.manifest_sha256=a.manifest_sha256 AND c.legal_commitment_sha256=a.legal_commitment_sha256
  AND c.article13_notice_epoch_at=a.article13_notice_epoch_at AND c.retain_until=a.retain_until
  AND (SELECT count(*) FROM document_package_send_attempts_v1 other WHERE other.org_id=tenant AND other.document_id=target
   AND (other.terminal_outcome IS NULL OR other.article13_notice_epoch_at=d.article13_notice_epoch_at))=1
  AND hash_package_send_members_retained_v1(a.attempt_id)
  AND hash_package_send_main_matches_v1(d.id,d.org_id,a.package_id,a.capture_revision)
 FROM document_package_send_attempts_v1 a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id
 JOIN document_package_send_completions_v1 c ON c.attempt_id=a.attempt_id AND c.org_id=a.org_id AND c.document_id=a.document_id
 WHERE a.attempt_id=aid AND a.org_id=tenant AND a.document_id=target),false);
$$ LANGUAGE sql STABLE;

CREATE FUNCTION hash_package_response_matches_v1(aid UUID,rid UUID) RETURNS BOOLEAN AS $$
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

CREATE FUNCTION hash_guard_package_response_v1() RETURNS trigger AS $$
DECLARE d documents%ROWTYPE; r recipients%ROWTYPE; a document_package_send_attempts_v1%ROWTYPE; e events%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'package response receipts are immutable' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE NOWAIT;
 SELECT * INTO STRICT r FROM recipients WHERE id=NEW.recipient_id AND document_id=NEW.document_id FOR UPDATE NOWAIT;
 SELECT * INTO STRICT a FROM document_package_send_attempts_v1 WHERE attempt_id=NEW.attempt_id AND org_id=NEW.org_id AND document_id=NEW.document_id;
 SELECT * INTO STRICT e FROM events WHERE id=NEW.response_event_id;
 IF d.status NOT IN ('sent','in_progress') OR NOT hash_package_response_binding_matches_v1(a.attempt_id,a.org_id,a.document_id)
  OR ROW(NEW.package_id,NEW.capture_revision,NEW.manifest_sha256,NEW.legal_commitment_sha256,NEW.sent_at,NEW.article13_notice_epoch_at)
   IS DISTINCT FROM ROW(a.package_id,a.capture_revision,a.manifest_sha256,a.legal_commitment_sha256,d.sent_at,a.article13_notice_epoch_at)
  OR ROW(e.org_id,e.document_id,e.recipient_id,e.kind,e.row_hash,e.created_at)
   IS DISTINCT FROM ROW(NEW.org_id,NEW.document_id,NEW.recipient_id,'document.'||NEW.response_kind,NEW.response_event_row_sha256,NEW.response_event_created_at)
  OR e.payload_hashed IS NULL OR convert_from(e.payload_hashed,'UTF8')::jsonb IS DISTINCT FROM e.payload_json
  OR r.magic_token_expires_at IS NULL OR r.magic_token_expires_at<=clock_timestamp()
  OR (d.expires_at IS NOT NULL AND d.expires_at<=clock_timestamp()) THEN
  RAISE EXCEPTION 'package response differs from the current exact response transaction' USING ERRCODE='23514'; END IF;
 PERFORM hash_package_send_privacy_clear_v1(a.org_id,a.package_id,a.capture_revision);
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'package response exact scope is unavailable' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER package_response_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_package_responses_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_package_response_v1();

CREATE FUNCTION hash_require_package_response_v1() RETURNS trigger AS $$
DECLARE target UUID; rid UUID; tenant UUID; aid UUID; n INTEGER;
BEGIN
 IF TG_TABLE_NAME='recipients' THEN
  IF NEW.status NOT IN ('signed','accepted') THEN RETURN NULL; END IF;
  target:=NEW.document_id;rid:=NEW.id;
 ELSIF TG_TABLE_NAME='signatures' THEN target:=NEW.document_id;rid:=NEW.recipient_id;
 ELSIF TG_TABLE_NAME='events' THEN
  IF NEW.kind NOT IN ('document.signed','document.accepted') THEN RETURN NULL; END IF;
  target:=NEW.document_id;rid:=NEW.recipient_id;
 ELSE target:=NEW.document_id;rid:=NEW.recipient_id;
 END IF;
 SELECT org_id INTO tenant FROM documents WHERE id=target FOR UPDATE NOWAIT;
 IF NOT FOUND THEN
  IF TG_TABLE_NAME='document_package_responses_v1' THEN RAISE EXCEPTION 'package response root is unavailable' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 END IF;
 IF TG_TABLE_NAME<>'document_package_responses_v1' AND NOT hash_has_current_package_response_history_v1(tenant,target) THEN
  IF TG_TABLE_NAME='events' THEN
   IF NEW.payload_json->>'package_response_schema'='hash-package-response-v1' THEN
    RAISE EXCEPTION 'package response event has no current captured package' USING ERRCODE='23514'; END IF;
  END IF;
  RETURN NULL;
 END IF;
 PERFORM 1 FROM recipients WHERE id=rid AND document_id=target FOR UPDATE NOWAIT;
 SELECT count(*)::integer,min(x.attempt_id::text)::uuid INTO n,aid FROM document_package_responses_v1 x JOIN documents d ON d.id=x.document_id AND d.org_id=x.org_id
  WHERE x.org_id=tenant AND x.document_id=target AND x.recipient_id=rid AND x.article13_notice_epoch_at=d.article13_notice_epoch_at;
 IF n<>1 OR hash_package_response_matches_v1(aid,rid) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'current package response requires its exact atomic consent receipt' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='document_package_responses_v1' AND NOT EXISTS(
  SELECT 1 FROM recipients r JOIN documents d ON d.id=r.document_id WHERE r.id=rid AND d.id=target
   AND r.magic_token_expires_at>clock_timestamp() AND (d.expires_at IS NULL OR d.expires_at>clock_timestamp())) THEN
  RAISE EXCEPTION 'package response credential expired before commit' USING ERRCODE='23514'; END IF;
 -- Resolve table-specific record fields only within their actual branch.
 -- A receipt row has no id; a Boolean AND does not defer field resolution.
 IF TG_TABLE_NAME='events' THEN
  IF NOT EXISTS(SELECT 1 FROM document_package_responses_v1 x WHERE x.attempt_id=aid AND x.recipient_id=rid AND x.response_event_id=NEW.id) THEN
   RAISE EXCEPTION 'package response audit event differs from its exact receipt' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='signatures' THEN
  IF NOT EXISTS(SELECT 1 FROM document_package_responses_v1 x WHERE x.attempt_id=aid AND x.recipient_id=rid AND x.signature_id=NEW.id) THEN
   RAISE EXCEPTION 'package signature differs from its exact receipt' USING ERRCODE='23514'; END IF;
 END IF;
 PERFORM hash_package_send_privacy_clear_v1(tenant,(SELECT package_id FROM document_package_send_attempts_v1 WHERE attempt_id=aid),
  (SELECT capture_revision FROM document_package_send_attempts_v1 WHERE attempt_id=aid));
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER package_response_recipient_pair_v1 AFTER INSERT OR UPDATE ON recipients
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_require_package_response_v1();
CREATE CONSTRAINT TRIGGER package_response_signature_pair_v1 AFTER INSERT OR UPDATE ON signatures
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_require_package_response_v1();
CREATE CONSTRAINT TRIGGER package_response_event_pair_v1 AFTER INSERT ON events
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_require_package_response_v1();
CREATE CONSTRAINT TRIGGER package_response_receipt_pair_v1 AFTER INSERT ON document_package_responses_v1
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_require_package_response_v1();

-- These are scalar historical associations rather than mutating FKs to the
-- recipient/audit projections. Preserve forensic rows and actual signature
-- pins, while allowing recipient PII and event display JSON redaction.
CREATE FUNCTION hash_guard_package_response_evidence_v1() RETURNS trigger AS $$
BEGIN
 IF TG_TABLE_NAME='signatures' THEN
  IF EXISTS(SELECT 1 FROM document_package_responses_v1 x WHERE x.signature_id=OLD.id)
   AND (TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD) THEN RAISE EXCEPTION 'package response signature evidence is immutable' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='events' THEN
  IF EXISTS(SELECT 1 FROM document_package_responses_v1 x WHERE x.response_event_id=OLD.id) THEN
   IF TG_OP='DELETE' THEN RAISE EXCEPTION 'package response audit evidence is retained' USING ERRCODE='23514'; END IF;
   IF (to_jsonb(NEW)-'payload_json') IS DISTINCT FROM (to_jsonb(OLD)-'payload_json') THEN
    RAISE EXCEPTION 'package response canonical audit evidence is immutable' USING ERRCODE='23514'; END IF;
  END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM document_package_responses_v1 x WHERE x.recipient_id=OLD.id AND x.document_id=OLD.document_id) THEN
   IF TG_OP='DELETE' THEN RAISE EXCEPTION 'package response recipient association is retained' USING ERRCODE='23514'; END IF;
   IF ROW(NEW.id,NEW.document_id,NEW.status,NEW.signed_at,NEW.role,NEW.order_index) IS DISTINCT FROM ROW(OLD.id,OLD.document_id,OLD.status,OLD.signed_at,OLD.role,OLD.order_index) THEN
    RAISE EXCEPTION 'package response recipient association is immutable' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER package_response_signature_evidence_v1 BEFORE UPDATE OR DELETE ON signatures FOR EACH ROW EXECUTE FUNCTION hash_guard_package_response_evidence_v1();
CREATE TRIGGER package_response_event_evidence_v1 BEFORE UPDATE OR DELETE ON events FOR EACH ROW EXECUTE FUNCTION hash_guard_package_response_evidence_v1();
CREATE TRIGGER package_response_recipient_evidence_v1 BEFORE UPDATE OR DELETE ON recipients FOR EACH ROW EXECUTE FUNCTION hash_guard_package_response_evidence_v1();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
LOCK TABLE documents,recipients,signatures,events,document_package_send_attempts_v1,document_package_responses_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM document_package_responses_v1)
  OR EXISTS(SELECT 1 FROM events WHERE payload_json->>'package_response_schema'='hash-package-response-v1'
   OR (payload_hashed IS NOT NULL AND convert_from(payload_hashed,'UTF8')::jsonb->>'package_response_schema'='hash-package-response-v1')) THEN
  RAISE EXCEPTION 'package response evidence prevents rollback' USING ERRCODE='23514'; END IF;
END $$;
DROP TRIGGER package_response_recipient_evidence_v1 ON recipients;
DROP TRIGGER package_response_event_evidence_v1 ON events;
DROP TRIGGER package_response_signature_evidence_v1 ON signatures;
DROP FUNCTION hash_guard_package_response_evidence_v1();
DROP TRIGGER package_response_receipt_pair_v1 ON document_package_responses_v1;
DROP TRIGGER package_response_event_pair_v1 ON events;
DROP TRIGGER package_response_signature_pair_v1 ON signatures;
DROP TRIGGER package_response_recipient_pair_v1 ON recipients;
DROP FUNCTION hash_require_package_response_v1();
DROP TRIGGER package_response_guard_v1 ON document_package_responses_v1;
DROP FUNCTION hash_guard_package_response_v1();
DROP FUNCTION hash_package_response_matches_v1(UUID,UUID);
DROP FUNCTION hash_package_response_binding_matches_v1(UUID,UUID,UUID);
DROP FUNCTION hash_has_current_package_response_history_v1(UUID,UUID);
DROP FUNCTION hash_package_response_audit_row_sha256_v1(UUID);
DROP FUNCTION hash_package_response_audit_frame_v1(BYTEA);
DROP INDEX document_package_response_audit_identity_v1;
DROP TABLE document_package_responses_v1;
DROP FUNCTION hash_package_incorporation_sha256_v1();
DROP FUNCTION hash_package_incorporation_text_v1();
DROP FUNCTION hash_package_incorporation_version_v1();
DROP FUNCTION hash_package_response_version_v1();
-- +goose StatementEnd
