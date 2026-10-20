-- +goose Up
-- Forward immutable original-request / accepted-intent binding only.
-- This unit does not activate pdf-static-v1, READY, a controller, provider I/O,
-- credential-rotation reuse, slot replacement, or a signing driver. SQL identities
-- and byte commitments are not proof a token was presented or notice acknowledged.
-- The private application must hold actual metadata/body/process admission, its
-- engine-issued receipt/intent, and the owned READ COMMITTED session first.
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'request binding installation requires read committed' USING ERRCODE='23514';
 END IF;
 IF getdatabaseencoding()<>'UTF8' THEN RAISE EXCEPTION 'request binding byte-accounting requires UTF8 database encoding' USING ERRCODE='23514';END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE signature_fit_preparations ADD COLUMN request_binding_creation_xid XID8;
ALTER TABLE documents
 ADD COLUMN signature_fit_request_binding_bytes BIGINT NOT NULL DEFAULT 0 CHECK(signature_fit_request_binding_bytes BETWEEN 0 AND 67108864),
 ADD COLUMN signature_fit_request_binding_count INTEGER NOT NULL DEFAULT 0 CHECK(signature_fit_request_binding_count BETWEEN 0 AND 128);

CREATE TABLE signature_fit_request_bindings (
 preparation_id UUID PRIMARY KEY CHECK(preparation_id<>'00000000-0000-0000-0000-000000000000'),
 org_id UUID NOT NULL,document_id UUID NOT NULL,recipient_id UUID NOT NULL,
 ceremony_epoch TIMESTAMPTZ NOT NULL CHECK(isfinite(ceremony_epoch)),
 admission_id UUID NOT NULL,static_basis_sha256 BYTEA NOT NULL CHECK(octet_length(static_basis_sha256)=32),
 authority_sha256 BYTEA NOT NULL CHECK(octet_length(authority_sha256)=32),
 original_request_payload BYTEA NOT NULL,
 original_request_sha256 BYTEA NOT NULL CHECK(octet_length(original_request_sha256)=32),
 original_request_bytes BIGINT NOT NULL CHECK(original_request_bytes BETWEEN 1 AND 1048576),
 accepted_intent_payload BYTEA NOT NULL,
 accepted_intent_sha256 BYTEA NOT NULL CHECK(octet_length(accepted_intent_sha256)=32),
 accepted_intent_semantic_sha256 BYTEA NOT NULL CHECK(octet_length(accepted_intent_semantic_sha256)=32),
 accepted_intent_bytes BIGINT NOT NULL CHECK(accepted_intent_bytes BETWEEN 1 AND 1048576),
 binding_sha256 BYTEA NOT NULL CHECK(octet_length(binding_sha256)=32),
 captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(captured_at)),
 captured_transaction_id XID8 NOT NULL DEFAULT pg_current_xact_id(),
 creator_backend_pid INTEGER NOT NULL CHECK(creator_backend_pid>0),
 creator_backend_start TIMESTAMPTZ NOT NULL CHECK(isfinite(creator_backend_start)),
 creator_database_oid BIGINT NOT NULL CHECK(creator_database_oid BETWEEN 1 AND 4294967295),
 creator_user_oid BIGINT NOT NULL CHECK(creator_user_oid BETWEEN 1 AND 4294967295),
 creator_server_address TEXT NOT NULL CHECK(octet_length(creator_server_address)<=128),
 creator_server_port INTEGER NOT NULL CHECK(creator_server_port BETWEEN 0 AND 65535),
 creator_postmaster_start TIMESTAMPTZ NOT NULL CHECK(isfinite(creator_postmaster_start)),
 CHECK(octet_length(original_request_payload)=original_request_bytes AND digest(original_request_payload,'sha256')=original_request_sha256),
 CHECK(octet_length(accepted_intent_payload)=accepted_intent_bytes AND digest(accepted_intent_payload,'sha256')=accepted_intent_sha256),
 -- Closed v1 intent has only stable scope/epoch/name/font/full Article13 Evidence;
 -- no origin hash, credential, expiry, lease owner or rotating key is in its body.
 CHECK(accepted_intent_semantic_sha256=accepted_intent_sha256),
 UNIQUE(org_id,document_id,recipient_id,ceremony_epoch,admission_id,static_basis_sha256,authority_sha256,accepted_intent_semantic_sha256),
 FOREIGN KEY(preparation_id,org_id,document_id,recipient_id,ceremony_epoch)
  REFERENCES signature_fit_preparations(id,org_id,document_id,recipient_id,ceremony_epoch) ON DELETE RESTRICT,
 FOREIGN KEY(preparation_id,org_id,document_id)
  REFERENCES signature_fit_original_authorities(preparation_id,org_id,document_id) ON DELETE RESTRICT,
 FOREIGN KEY(admission_id,org_id,document_id)
  REFERENCES document_signing_admissions(id,org_id,document_id) ON DELETE RESTRICT,
 FOREIGN KEY(admission_id,recipient_id)
  REFERENCES document_signing_admission_slots(admission_id,recipient_id) ON DELETE RESTRICT
);
CREATE INDEX signature_fit_request_binding_inventory ON signature_fit_request_bindings(org_id,document_id,preparation_id);

-- +goose StatementBegin
CREATE FUNCTION hash_signature_fit_request_stamp_v1(value TIMESTAMPTZ) RETURNS JSONB LANGUAGE sql STABLE AS $$
 SELECT jsonb_build_object('valid',value IS NOT NULL,'value',CASE WHEN value IS NULL THEN '' ELSE hash_article13_canonical_sent_at(value) END);
$$;
CREATE FUNCTION hash_signature_fit_request_uuid_v1(value UUID) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_build_object('valid',value IS NOT NULL,'value',COALESCE(value::text,''));
$$;
CREATE FUNCTION hash_signature_fit_request_text_commitment_v1(value TEXT) RETURNS JSONB LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT jsonb_build_object('sha256',encode(digest(convert_to(value,'UTF8'),'sha256'),'hex'),'bytes',octet_length(value));
$$;
CREATE FUNCTION hash_signature_fit_request_identity_v1(value signature_fit_request_bindings) RETURNS BYTEA LANGUAGE sql STABLE STRICT AS $$
 SELECT digest(convert_to('hash-fit-request-binding-v1','UTF8')||uuid_send(value.preparation_id)||uuid_send(value.org_id)||uuid_send(value.document_id)||uuid_send(value.recipient_id)||uuid_send(value.admission_id)||
  int8send(octet_length(hash_article13_canonical_sent_at(value.ceremony_epoch))::bigint)||convert_to(hash_article13_canonical_sent_at(value.ceremony_epoch),'UTF8')||
  value.static_basis_sha256||value.authority_sha256||value.original_request_sha256||int8send(value.original_request_bytes)||value.accepted_intent_sha256||value.accepted_intent_semantic_sha256||int8send(value.accepted_intent_bytes)||
  convert_to(jsonb_build_array(value.captured_transaction_id::text,value.creator_backend_pid,hash_article13_canonical_sent_at(value.creator_backend_start),value.creator_database_oid,value.creator_user_oid,value.creator_server_address,value.creator_server_port,hash_article13_canonical_sent_at(value.creator_postmaster_start))::text,'UTF8'),'sha256');
$$;
-- Raw JSON duplicate closure is independent of jsonb's last-key projection.
-- The private canonical Go decoder remains mandatory before this SQL boundary.
CREATE FUNCTION hash_signature_fit_request_json_unique_v1(raw BYTEA) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE result BOOLEAN;
BEGIN
 IF octet_length(raw) NOT BETWEEN 1 AND 1048576 THEN RETURN FALSE;END IF;
 WITH RECURSIVE nodes(value,depth) AS (
  SELECT convert_from(raw,'UTF8')::json,0
  UNION ALL
  SELECT child.value,n.depth+1 FROM nodes n CROSS JOIN LATERAL (
   SELECT e.value FROM json_each(CASE WHEN json_typeof(n.value)='object' THEN n.value ELSE '{}'::json END) e
   UNION ALL SELECT e.value FROM json_array_elements(CASE WHEN json_typeof(n.value)='array' THEN n.value ELSE '[]'::json END) e
  ) child WHERE n.depth<8
 ) SELECT count(*)<=256 AND bool_and(depth<8 AND CASE WHEN json_typeof(value)='object' THEN
  (SELECT count(*)=count(DISTINCT e.key) FROM json_each(value) e) ELSE TRUE END) INTO result FROM nodes;
 RETURN COALESCE(result,FALSE);
EXCEPTION WHEN invalid_text_representation OR character_not_in_repertoire OR invalid_parameter_value THEN RETURN FALSE;
END $$;
CREATE FUNCTION hash_signature_fit_request_birth_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE policy TEXT;
BEGIN
 IF NEW.request_binding_creation_xid IS NOT NULL THEN RAISE EXCEPTION 'request birth marker is server-owned' USING ERRCODE='23514';END IF;
 SELECT signing_admission_policy INTO STRICT policy FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF policy='pdf-static-v1' THEN NEW.request_binding_creation_xid:=pg_current_xact_id();END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER ab_signature_fit_request_birth BEFORE INSERT ON signature_fit_preparations FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_request_birth_v1();

-- +goose StatementBegin
CREATE FUNCTION hash_signature_fit_request_trim_v1(value TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT btrim(value,U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000');
$$;
CREATE FUNCTION hash_signature_fit_request_finite_v1(value TIMESTAMPTZ) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
 SELECT COALESCE(value IS NOT NULL AND isfinite(value) AND value<>'0001-01-01 00:00:00+00'::timestamptz AND extract(year FROM value) BETWEEN 1 AND 9999,FALSE);
$$;
CREATE FUNCTION hash_signature_fit_request_payloads_match_v1(
 binding signature_fit_request_bindings,doc documents,recipient_row recipients,
 confirmation document_lawful_basis_confirmations,controller_org orgs,original signature_fit_original_authorities
) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE origin_json JSONB;intent_raw JSON;intent_json JSONB;notice JSONB;snapshot JSONB;copy JSONB;member RECORD;value TEXT;limit_value INTEGER;
BEGIN
 IF NOT hash_signature_fit_request_json_unique_v1(binding.original_request_payload) OR NOT hash_signature_fit_request_json_unique_v1(binding.accepted_intent_payload) THEN RETURN FALSE;END IF;
 origin_json:=convert_from(binding.original_request_payload,'UTF8')::jsonb;
 intent_raw:=convert_from(binding.accepted_intent_payload,'UTF8')::json;intent_json:=intent_raw::jsonb;
 IF origin_json IS DISTINCT FROM jsonb_build_object(
  'schema','hash-presented-request-origin-v1',
  'issuer','hash-presented-magic-link-v1',
  'org_id',doc.org_id::text,
  'document_id',doc.id::text,
  'recipient_id',recipient_row.id::text,
  'token_sha256',encode(recipient_row.magic_token_hash,'hex'),
  'recipient_expiry',hash_signature_fit_request_stamp_v1(recipient_row.magic_token_expires_at),
  'document_expiry',hash_signature_fit_request_stamp_v1(doc.expires_at),
  'sent_at',hash_signature_fit_request_stamp_v1(doc.sent_at),
  'notice_epoch',hash_signature_fit_request_stamp_v1(doc.article13_notice_epoch_at),
  'notice_schema',doc.article13_notice_schema,
  'notice_committed',doc.article13_notice_epoch_v61_committed,
  'document_name',doc.name,
  'lawful_basis',hash_signature_fit_request_text_commitment_v1(doc.lawful_basis),
  'role',recipient_row.role,
  'recipient_status',recipient_row.status,
  'document_status',doc.status,
  'signing_policy',doc.signing_admission_policy,
  'source_kind',doc.source_kind,
  'routing_tier',doc.routing_tier,
  'requires_signature',doc.requires_signature,
  'is_envelope',doc.is_envelope,
  'parent_envelope_id',hash_signature_fit_request_uuid_v1(doc.parent_envelope_id),
  'document_deleted_at',hash_signature_fit_request_stamp_v1(doc.deleted_at),
  'confirmation_by',hash_signature_fit_request_uuid_v1(confirmation.confirmed_by),
  'confirmation_at',hash_signature_fit_request_stamp_v1(confirmation.confirmed_at),
  'confirmation_via',confirmation.via,
  'controller_name',hash_signature_fit_request_text_commitment_v1(confirmation.controller_name),
  'controller_contact',hash_signature_fit_request_text_commitment_v1(confirmation.controller_contact),
  'confirmation_basis',hash_signature_fit_request_text_commitment_v1(confirmation.lawful_basis),
  'controller_org_name',hash_signature_fit_request_text_commitment_v1(controller_org.name)
 ) THEN RETURN FALSE;END IF;
 IF (intent_json-'notice') IS DISTINCT FROM jsonb_build_object('schema','hash-accepted-fitted-intent-v1','org_id',doc.org_id::text,'document_id',doc.id::text,'recipient_id',recipient_row.id::text,
  'ceremony_epoch',hash_article13_canonical_sent_at(binding.ceremony_epoch),'typed_name',convert_from(original.authority_payload,'UTF8')::jsonb->>'typed_name','font',convert_from(original.authority_payload,'UTF8')::jsonb->>'font') THEN RETURN FALSE;END IF;
 IF octet_length(intent_json->>'typed_name') NOT BETWEEN 1 AND 800 OR intent_json->>'font' NOT IN('Caveat','Dancing Script','Great Vibes','Sacramento','Homemade Apple') THEN RETURN FALSE;END IF;
 notice:=intent_json->'notice';snapshot:=notice->'snapshot';copy:=snapshot->'copy';
 IF jsonb_typeof(notice) IS DISTINCT FROM 'object' OR (SELECT array_agg(e.key ORDER BY e.key) FROM jsonb_object_keys(notice) e(key)) IS DISTINCT FROM ARRAY['digest','schema','snapshot']::text[]
  OR notice->>'schema' IS DISTINCT FROM doc.article13_notice_schema OR notice->>'schema' IS DISTINCT FROM 'hash-a13-2026-08-31'
  OR notice->>'digest' IS DISTINCT FROM encode(digest(convert_to((intent_raw->'notice'->'snapshot')::text,'UTF8'),'sha256'),'hex')
  OR jsonb_typeof(snapshot) IS DISTINCT FROM 'object' OR (SELECT array_agg(e.key ORDER BY e.key) FROM jsonb_object_keys(snapshot) e(key)) IS DISTINCT FROM ARRAY['controller','controller_contact','copy','document_id','dsr_capability','legal_basis_disclosure','org_id','policy_url','processor','processor_contact','purpose_summary','recipient_id','retention_years','schema','sent_at','supervisory_authority']::text[]
  OR snapshot->>'schema' IS DISTINCT FROM notice->>'schema' OR snapshot->>'document_id' IS DISTINCT FROM doc.id::text OR snapshot->>'org_id' IS DISTINCT FROM doc.org_id::text OR snapshot->>'recipient_id' IS DISTINCT FROM recipient_row.id::text
  OR snapshot->>'sent_at' IS DISTINCT FROM hash_article13_canonical_sent_at(binding.ceremony_epoch)
  OR snapshot->>'controller' IS DISTINCT FROM hash_signature_fit_request_trim_v1(confirmation.controller_name)
  OR snapshot->>'controller_contact' IS DISTINCT FROM hash_signature_fit_request_trim_v1(confirmation.controller_contact)
  OR snapshot->'retention_years' IS DISTINCT FROM '7'::jsonb OR snapshot->>'dsr_capability' IS DISTINCT FROM 'signer_request_submission'
  OR jsonb_typeof(copy) IS DISTINCT FROM 'object' OR (SELECT array_agg(e.key ORDER BY e.key) FROM jsonb_object_keys(copy) e(key)) IS DISTINCT FROM ARRAY['acknowledgement_label','authority_label','controller_contact_label','controller_label','dsr_access_label','dsr_erasure_label','dsr_objection_label','dsr_portability_label','dsr_rectification_label','dsr_restriction_label','fine_print','intro','kind_label','legal_basis_label','note_label','note_placeholder','processor_label','purpose_label','read_policy_label','request_received','retention_label','retention_value','rights_body','rights_summary','send_request_label','submit_request_label','title']::text[] THEN RETURN FALSE;END IF;
 FOR member IN SELECT * FROM jsonb_each(copy) LOOP
  IF jsonb_typeof(member.value) IS DISTINCT FROM 'string' OR octet_length(member.value#>>'{}') NOT BETWEEN 1 AND 4000 THEN RETURN FALSE;END IF;
 END LOOP;
 FOR member IN SELECT * FROM jsonb_each(snapshot) WHERE key IN('controller','controller_contact','processor','processor_contact','purpose_summary','legal_basis_disclosure','supervisory_authority','policy_url') LOOP
  limit_value:=CASE member.key WHEN 'controller' THEN 200 WHEN 'processor' THEN 200 WHEN 'controller_contact' THEN 254 WHEN 'processor_contact' THEN 254 WHEN 'purpose_summary' THEN 2000 WHEN 'legal_basis_disclosure' THEN 2000 WHEN 'supervisory_authority' THEN 300 ELSE 2048 END;
  IF jsonb_typeof(member.value) IS DISTINCT FROM 'string' OR octet_length(member.value#>>'{}') NOT BETWEEN 1 AND limit_value THEN RETURN FALSE;END IF;
 END LOOP;
 RETURN TRUE;
EXCEPTION WHEN invalid_text_representation OR character_not_in_repertoire OR invalid_parameter_value OR numeric_value_out_of_range THEN RETURN FALSE;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION hash_signature_fit_request_binding_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE doc documents%ROWTYPE;recipient_row recipients%ROWTYPE;admission document_signing_admissions%ROWTYPE;
 original signature_fit_original_authorities%ROWTYPE;prep signature_fit_preparations%ROWTYPE;slot document_signing_admission_slots%ROWTYPE;
 confirmation document_lawful_basis_confirmations%ROWTYPE;controller_org orgs%ROWTYPE;body_bytes BIGINT;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'request binding is immutable and retained' USING ERRCODE='23514';END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'request binding requires read committed' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM signing_resource_control WHERE singleton AND state='ready') THEN RAISE EXCEPTION 'request binding requires verified resource inventory' USING ERRCODE='23514';END IF;
 PERFORM hash_signing_resource_entities_v1(NEW.org_id,NEW.document_id);
 SELECT * INTO STRICT doc FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO STRICT recipient_row FROM recipients WHERE id=NEW.recipient_id AND document_id=doc.id FOR UPDATE;
 SELECT * INTO STRICT admission FROM document_signing_admissions WHERE id=NEW.admission_id AND org_id=doc.org_id AND document_id=doc.id FOR UPDATE;
 SELECT * INTO STRICT slot FROM document_signing_admission_slots WHERE admission_id=admission.id AND recipient_id=recipient_row.id FOR UPDATE;
 SELECT * INTO STRICT prep FROM signature_fit_preparations WHERE id=NEW.preparation_id AND org_id=doc.org_id AND document_id=doc.id AND recipient_id=recipient_row.id FOR UPDATE;
 SELECT * INTO STRICT original FROM signature_fit_original_authorities WHERE preparation_id=prep.id AND org_id=doc.org_id AND document_id=doc.id FOR UPDATE;
 SELECT * INTO STRICT confirmation FROM document_lawful_basis_confirmations WHERE document_id=doc.id AND org_id=doc.org_id FOR SHARE;
 SELECT * INTO STRICT controller_org FROM orgs WHERE id=doc.org_id FOR SHARE;
 IF doc.signing_admission_policy<>'pdf-static-v1' OR doc.signing_admission_active_id IS DISTINCT FROM admission.id OR doc.status NOT IN('sent','in_progress') OR doc.deleted_at IS NOT NULL
  OR doc.source_kind<>'pdf' OR NOT doc.requires_signature OR doc.routing_tier<>'SES' OR doc.is_envelope OR doc.parent_envelope_id IS NOT NULL OR NOT doc.evidence_version_pins_required
  OR NOT doc.article13_notice_epoch_v61_committed OR doc.article13_notice_schema<>'hash-a13-2026-08-31'
  OR NOT hash_signature_fit_request_finite_v1(doc.sent_at) OR doc.sent_at IS DISTINCT FROM doc.article13_notice_epoch_at OR doc.sent_at IS DISTINCT FROM NEW.ceremony_epoch
  OR admission.ceremony_epoch IS DISTINCT FROM NEW.ceremony_epoch OR admission.static_basis_sha256 IS DISTINCT FROM NEW.static_basis_sha256 OR admission.status NOT IN('staging','ready','sealed')
  OR NOT hash_pdf_admission_current_matches_v1(admission.id,doc.org_id,doc.id)
  OR recipient_row.status NOT IN('pending','sent','viewed') OR recipient_row.role IN('cc','viewer') OR octet_length(recipient_row.magic_token_hash)<>32
  OR NOT hash_signature_fit_request_finite_v1(recipient_row.magic_token_expires_at) OR recipient_row.magic_token_expires_at<=clock_timestamp()
  OR (doc.expires_at IS NOT NULL AND (NOT hash_signature_fit_request_finite_v1(doc.expires_at) OR doc.expires_at<=clock_timestamp()))
  OR NOT hash_signature_fit_request_finite_v1(confirmation.confirmed_at) OR hash_signature_fit_request_trim_v1(confirmation.lawful_basis)<>'contract'
  OR hash_signature_fit_request_trim_v1(doc.lawful_basis)<>'contract' OR octet_length(doc.name)>65536
  OR prep.request_binding_creation_xid IS DISTINCT FROM pg_current_xact_id() OR NEW.captured_transaction_id IS DISTINCT FROM pg_current_xact_id()
  OR prep.ceremony_epoch IS DISTINCT FROM NEW.ceremony_epoch OR prep.authority_sha256 IS DISTINCT FROM NEW.authority_sha256 OR original.authority_sha256 IS DISTINCT FROM NEW.authority_sha256
  OR prep.status<>'staging' OR prep.lease_until<=clock_timestamp() OR prep.selection_commit_attempted_at IS NOT NULL OR prep.selection_not_committed_at IS NOT NULL
  OR (slot.designated_preparation_id IS NOT NULL AND slot.designated_preparation_id<>prep.id)
  OR EXISTS(SELECT 1 FROM signature_fit_objects WHERE preparation_id=prep.id) OR EXISTS(SELECT 1 FROM signature_fit_selections WHERE preparation_id=prep.id)
  OR EXISTS(SELECT 1 FROM signatures WHERE document_id=doc.id AND recipient_id=recipient_row.id) THEN
  RAISE EXCEPTION 'request binding lacks exact fresh85/87/88 scope' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM signing_resource_debts WHERE org_id=doc.org_id AND document_id=doc.id AND admission_id=admission.id AND operation_id=prep.id AND kind='fit' AND member_kind='' AND page=0 AND captured_transaction_id=pg_current_xact_id())
  OR NOT EXISTS(SELECT 1 FROM signing_resource_debts WHERE org_id=doc.org_id AND document_id=doc.id AND admission_id=admission.id AND operation_id=prep.id AND kind='authority' AND member_kind='' AND page=0 AND captured_transaction_id=pg_current_xact_id())
  OR NOT EXISTS(SELECT 1 FROM signing_resource_debts WHERE org_id=doc.org_id AND document_id=doc.id AND admission_id=admission.id AND operation_id=prep.id AND kind='payload' AND member_kind='span' AND page=0 AND captured_transaction_id=pg_current_xact_id()) THEN
  RAISE EXCEPTION 'request binding cannot manufacture retrospective request provenance' USING ERRCODE='23514';END IF;
 IF NEW.creator_backend_pid IS NOT NULL OR NEW.creator_backend_start IS NOT NULL OR NEW.creator_database_oid IS NOT NULL OR NEW.creator_user_oid IS NOT NULL OR NEW.creator_server_address IS NOT NULL OR NEW.creator_server_port IS NOT NULL OR NEW.creator_postmaster_start IS NOT NULL THEN
  RAISE EXCEPTION 'request backend identity is server-owned' USING ERRCODE='23514';END IF;
 SELECT a.pid,a.backend_start,a.datid::bigint,a.usesysid::bigint,COALESCE(pg_catalog.inet_server_addr()::text,''),COALESCE(pg_catalog.inet_server_port(),0),pg_catalog.pg_postmaster_start_time()
 INTO STRICT NEW.creator_backend_pid,NEW.creator_backend_start,NEW.creator_database_oid,NEW.creator_user_oid,NEW.creator_server_address,NEW.creator_server_port,NEW.creator_postmaster_start
 FROM pg_catalog.pg_stat_activity a WHERE a.pid=pg_catalog.pg_backend_pid();
 IF NOT hash_signature_fit_request_finite_v1(NEW.creator_backend_start) OR NOT hash_signature_fit_request_finite_v1(NEW.creator_postmaster_start) THEN RAISE EXCEPTION 'request creator session identity is unknown' USING ERRCODE='23514';END IF;
 IF NOT hash_signature_fit_request_payloads_match_v1(NEW,doc,recipient_row,confirmation,controller_org,original) THEN RAISE EXCEPTION 'request payloads differ from admitted scope' USING ERRCODE='23514';END IF;
 NEW.binding_sha256:=hash_signature_fit_request_identity_v1(NEW);NEW.captured_at:=clock_timestamp();
 body_bytes:=octet_length(NEW.original_request_payload)::bigint+octet_length(NEW.accepted_intent_payload)::bigint;
 UPDATE documents SET signature_fit_request_binding_bytes=signature_fit_request_binding_bytes+body_bytes,signature_fit_request_binding_count=signature_fit_request_binding_count+1
 WHERE id=doc.id AND org_id=doc.org_id AND signature_fit_request_binding_count<128 AND signature_fit_request_binding_bytes+body_bytes<=67108864;
 IF NOT FOUND THEN RAISE EXCEPTION 'retained request binding budget exhausted' USING ERRCODE='23514';END IF;
 RETURN NEW;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION 'request binding scoped parent or backend metadata missing' USING ERRCODE='23514';
END $$;
CREATE FUNCTION hash_signature_fit_request_budget_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE doc_id UUID;actual_bytes BIGINT;actual_count BIGINT;expected_bytes NUMERIC;expected_count BIGINT;
BEGIN
 IF TG_TABLE_NAME='documents' THEN doc_id:=NEW.id;ELSE doc_id:=NEW.document_id;END IF;
 SELECT signature_fit_request_binding_bytes,signature_fit_request_binding_count INTO STRICT actual_bytes,actual_count FROM documents WHERE id=doc_id;
 SELECT COALESCE(sum(octet_length(original_request_payload)::numeric+octet_length(accepted_intent_payload)::numeric),0),count(*) INTO expected_bytes,expected_count FROM signature_fit_request_bindings WHERE document_id=doc_id;
 IF ROW(actual_bytes::numeric,actual_count) IS DISTINCT FROM ROW(expected_bytes,expected_count) THEN RAISE EXCEPTION 'retained request inventory differs from counters' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE FUNCTION hash_signature_fit_request_slot_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.designated_preparation_id IS NOT NULL AND NEW.designated_preparation_id IS DISTINCT FROM OLD.designated_preparation_id THEN
  -- No settled-outcome/whole-process disposition authority exists in this unit.
  -- Legitimate replacement needs that future authority or a revised/new epoch;
  -- cleaned/status/TTL/caller booleans do not authorize it here.
  RAISE EXCEPTION 'request designation replacement requires settled outcome authority' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER aa_signing_resource_request_binding BEFORE INSERT ON signature_fit_request_bindings FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER signature_fit_request_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON signature_fit_request_bindings FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_request_binding_guard_v1();
CREATE CONSTRAINT TRIGGER signature_fit_request_budget_document AFTER INSERT OR UPDATE ON documents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_request_budget_v1();
CREATE CONSTRAINT TRIGGER signature_fit_request_budget_body AFTER INSERT OR UPDATE OR DELETE ON signature_fit_request_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_request_budget_v1();
CREATE TRIGGER ab_signature_fit_request_slot_guard BEFORE UPDATE ON document_signing_admission_slots FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_request_slot_guard_v1();

ALTER TABLE signing_resource_debts DROP CONSTRAINT signing_resource_debts_kind_check;
ALTER TABLE signing_resource_debts ADD CONSTRAINT signing_resource_debts_kind_check CHECK(kind IN('candidate','ordinary','fit','authority','payload','request_binding','finalization','output','audit_input','certificate_input'));
-- Two additional conservative logical4096-byte metadata charges cover the
-- retained binding row/index and derived debt row. No physical disk/RSS/WAL claim.
-- Provider/object debt is zero; no existing fit entitlement is silently widened.
-- +goose StatementBegin
CREATE FUNCTION hash_signing_resource_request_db_v1(value signature_fit_request_bindings) RETURNS BIGINT LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT octet_length(value.original_request_payload)::bigint+octet_length(value.accepted_intent_payload)::bigint+8192;
$$;
CREATE OR REPLACE FUNCTION hash_signing_resource_entities_v1(org UUID,doc UUID) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE document_row documents%ROWTYPE; admission_id_value UUID;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'signing resource scope requires read committed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT document_row FROM documents WHERE id=doc AND org_id=org FOR UPDATE;
 IF document_row.signing_admission_policy='historical' THEN RETURN NULL; END IF;
 IF document_row.signing_admission_policy<>'pdf-static-v1' THEN RAISE EXCEPTION 'signing resource policy unavailable' USING ERRCODE='23514'; END IF;
 -- Parent serialization also fences all guarded child writers. No body decoding
 -- or provider I/O, and no account is locked until these entity locks are owned.
 IF (SELECT count(*) FROM recipients WHERE document_id=doc)>100 OR (SELECT count(*) FROM signature_fit_preparations WHERE document_id=doc)>1024 OR (SELECT count(*) FROM document_signing_admissions WHERE document_id=doc)>8 OR (SELECT count(*) FROM signature_fit_request_bindings WHERE document_id=doc)>128 THEN
  RAISE EXCEPTION 'signing resource entity inventory exceeds profile' USING ERRCODE='23514';
 END IF;
 PERFORM 1 FROM recipients WHERE document_id=doc ORDER BY id FOR UPDATE;
 PERFORM 1 FROM document_signing_admissions WHERE document_id=doc AND org_id=org ORDER BY id FOR UPDATE;
 PERFORM 1 FROM document_signing_admission_slots WHERE document_id=doc AND org_id=org ORDER BY admission_id,recipient_id FOR UPDATE;
 PERFORM 1 FROM signature_fit_preparations WHERE document_id=doc AND org_id=org ORDER BY id FOR UPDATE;
 PERFORM 1 FROM signature_fit_original_authorities WHERE document_id=doc AND org_id=org ORDER BY preparation_id FOR UPDATE;
 PERFORM 1 FROM signature_fit_request_bindings WHERE document_id=doc AND org_id=org ORDER BY preparation_id FOR UPDATE;
 PERFORM 1 FROM document_finalization_preparations WHERE document_id=doc AND org_id=org ORDER BY id FOR UPDATE;
 admission_id_value:=COALESCE(document_row.signing_admission_sealed_id,document_row.signing_admission_active_id);
 RETURN admission_id_value;
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_debt_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE a document_signing_admissions%ROWTYPE; prep signature_fit_preparations%ROWTYPE;
 ordinary document_signing_admission_bodies%ROWTYPE; original signature_fit_original_payloads%ROWTYPE; authority signature_fit_original_authorities%ROWTYPE;
 finalization document_finalization_preparations%ROWTYPE; output document_finalization_outputs%ROWTYPE; request_binding signature_fit_request_bindings%ROWTYPE;
 expected_capacity BIGINT:=0; expected_retained BIGINT:=0; expected_provider BIGINT:=0; expected_objects BIGINT:=0; expected_identity BYTEA;
 fit_bytes NUMERIC; fit_db NUMERIC; fit_objects NUMERIC; slots_db NUMERIC; epoch TIMESTAMPTZ;
 account_global signing_resource_accounts%ROWTYPE; account_tenant signing_resource_accounts%ROWTYPE; account_key_value UUID;
BEGIN
 IF NEW.org_id='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'signing resource tenant is invalid' USING ERRCODE='23514'; END IF;
 IF NEW.captured_transaction_id IS DISTINCT FROM pg_current_xact_id() OR EXISTS(SELECT 1 FROM signing_resource_debit_batches WHERE captured_transaction_id=pg_current_xact_id()) THEN RAISE EXCEPTION 'signing resource transaction is already account-sealed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT a FROM document_signing_admissions WHERE id=NEW.admission_id AND org_id=NEW.org_id AND document_id=NEW.document_id;
 epoch:=a.ceremony_epoch;
 IF NEW.kind='candidate' THEN
  IF NEW.operation_id<>a.id OR NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'signing resource candidate identity differs' USING ERRCODE='23514'; END IF;
  SELECT COALESCE(sum(sl.fit_bytes_limit::numeric),0),COALESCE(sum(hash_signing_resource_fit_db_v1(sl.fit_bytes_limit,sl.expected_objects)::numeric),0),COALESCE(sum(sl.expected_objects::numeric),0),COALESCE(sum((4096+16*sl.target_count+4*sl.page_count)::numeric),0)
   INTO fit_bytes,fit_db,fit_objects,slots_db FROM document_signing_admission_slots sl WHERE sl.admission_id=a.id;
  IF fit_bytes>1152921504606846976 OR fit_db>1152921504606846976 OR fit_objects>1000000000 THEN RAISE EXCEPTION 'signing resource entitlement overflow' USING ERRCODE='23514'; END IF;
  expected_retained:=hash_signing_resource_candidate_db_v1(a)+slots_db::bigint;
  expected_capacity:=expected_retained+a.base_bytes_limit+LEAST(8388608::bigint,cardinality(a.expected_ordinary_pages)::bigint*1048576)+8192*cardinality(a.expected_ordinary_pages)::bigint+hash_signing_resource_common_db_v1(a)+fit_db::bigint;
  expected_provider:=hash_signing_resource_common_provider_v1(a)+fit_bytes::bigint;
  expected_objects:=cardinality(a.expected_ordinary_pages)+5+fit_objects::bigint;expected_identity:=a.static_basis_body_sha256;
 ELSIF NEW.kind='ordinary' THEN
  SELECT * INTO STRICT ordinary FROM document_signing_admission_bodies WHERE admission_id=a.id AND org_id=a.org_id AND document_id=a.document_id AND kind=NEW.member_kind AND page=NEW.page;
  IF NEW.operation_id<>a.id THEN RAISE EXCEPTION 'signing resource ordinary identity differs' USING ERRCODE='23514'; END IF;
  expected_retained:=ordinary.bytes+octet_length(ordinary.plan_payload)+4096;expected_identity:=digest(ordinary.sha256||ordinary.plan_sha256||ordinary.package_sha256||ordinary.report_sha256||ordinary.inspection_sha256,'sha256');
 ELSIF NEW.kind='fit' THEN
  SELECT * INTO STRICT prep FROM signature_fit_preparations WHERE id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND ceremony_epoch=a.ceremony_epoch;
  IF NEW.member_kind<>'' OR NEW.page<>0 OR NOT EXISTS(SELECT 1 FROM document_signing_admission_slots sl WHERE sl.admission_id=a.id AND sl.recipient_id=prep.recipient_id AND prep.expected_objects=sl.expected_objects AND prep.reserved_bytes<=sl.fit_bytes_limit) THEN RAISE EXCEPTION 'signing resource preparation differs from slot' USING ERRCODE='23514'; END IF;
  IF NOT EXISTS(SELECT 1 FROM signing_resource_fit_transfers tr WHERE tr.admission_id=a.id AND tr.recipient_id=prep.recipient_id AND tr.preparation_id=prep.id) THEN
   expected_capacity:=hash_signing_resource_fit_db_v1(prep.reserved_bytes,prep.expected_objects);expected_provider:=prep.reserved_bytes;expected_objects:=prep.expected_objects;
  END IF;
  expected_retained:=4096+octet_length(prep.source_storage_key)+octet_length(prep.source_version_id);expected_identity:=prep.authority_sha256;
 ELSIF NEW.kind='authority' THEN
  IF NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'signing resource authority member differs' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT authority FROM signature_fit_original_authorities WHERE preparation_id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND ceremony_epoch=a.ceremony_epoch;
  expected_retained:=authority.authority_bytes+4096+4*cardinality(authority.occupied_pages);expected_identity:=authority.authority_sha256;
 ELSIF NEW.kind='payload' THEN
  SELECT * INTO STRICT original FROM signature_fit_original_payloads WHERE preparation_id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND kind=NEW.member_kind AND page=NEW.page;
  expected_retained:=original.bytes+4096+octet_length(original.storage_key)+octet_length(original.content_type);expected_identity:=original.sha256;
 ELSIF NEW.kind='request_binding' THEN
  IF NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'request resource member differs' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT request_binding FROM signature_fit_request_bindings WHERE preparation_id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND admission_id=a.id AND ceremony_epoch=a.ceremony_epoch;
  IF request_binding.captured_transaction_id IS DISTINCT FROM NEW.captured_transaction_id THEN RAISE EXCEPTION 'request resource capture transaction differs' USING ERRCODE='23514';END IF;
  expected_capacity:=hash_signing_resource_request_db_v1(request_binding);expected_retained:=expected_capacity;expected_identity:=request_binding.binding_sha256;
 ELSIF NEW.kind IN('finalization','output','audit_input','certificate_input') THEN
  IF NEW.kind IN('audit_input','certificate_input') AND (NEW.member_kind<>'' OR NEW.page<>0) THEN RAISE EXCEPTION 'signing resource input member differs' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT finalization FROM document_finalization_preparations WHERE id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND ceremony_epoch=a.ceremony_epoch;
  IF NEW.kind='finalization' THEN
   IF NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'signing resource finalization identity differs' USING ERRCODE='23514'; END IF;
   IF NOT EXISTS(SELECT 1 FROM signing_resource_finalization_transfers tr WHERE tr.admission_id=a.id AND tr.preparation_id=finalization.id) THEN
    expected_capacity:=hash_signing_resource_common_db_v1(a);expected_provider:=hash_signing_resource_common_provider_v1(a);expected_objects:=cardinality(a.expected_ordinary_pages)+5;
   END IF;
   expected_retained:=4096+octet_length(finalization.geometry_pages_payload)+octet_length(finalization.field_snapshot_payload)+octet_length(finalization.original_document_name)+octet_length(finalization.source_storage_key)+octet_length(finalization.source_version_id);expected_identity:=finalization.field_snapshot_sha256;
  ELSIF NEW.kind='output' THEN
   SELECT * INTO STRICT output FROM document_finalization_outputs WHERE preparation_id=finalization.id AND kind=NEW.member_kind AND page=NEW.page;
   expected_retained:=output.bytes+4096+octet_length(output.storage_key)+octet_length(output.content_type);expected_identity:=output.sha256;
  ELSIF NEW.kind='audit_input' THEN expected_retained:=octet_length(finalization.audit_snapshot_payload)+4096;expected_identity:=finalization.audit_snapshot_sha256;
  ELSE expected_retained:=octet_length(finalization.certificate_input_payload)+4096;expected_identity:=finalization.certificate_input_sha256;
  END IF;
 ELSE RAISE EXCEPTION 'signing resource inventory kind is invalid' USING ERRCODE='23514'; END IF;
 IF expected_identity IS NULL OR ROW(NEW.ceremony_epoch,NEW.identity_sha256,NEW.db_capacity_bytes,NEW.db_retained_bytes,NEW.provider_reserved_bytes,NEW.provider_reserved_objects)
   IS DISTINCT FROM ROW(epoch,expected_identity,expected_capacity,expected_retained,expected_provider,expected_objects) THEN
  RAISE EXCEPTION 'signing resource debit differs from derived inventory' USING ERRCODE='23514';
 END IF;
 -- Account application is deferred until the complete same-transaction tuple exists.
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_record_v1(org UUID,doc UUID,admission UUID,resource_kind TEXT,operation UUID,member TEXT,member_page INTEGER) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE a document_signing_admissions%ROWTYPE; p signature_fit_preparations%ROWTYPE; b document_signing_admission_bodies%ROWTYPE;
 orig signature_fit_original_payloads%ROWTYPE; au signature_fit_original_authorities%ROWTYPE; fp document_finalization_preparations%ROWTYPE; outrow document_finalization_outputs%ROWTYPE; request_binding signature_fit_request_bindings%ROWTYPE;
 capacity BIGINT:=0; retained BIGINT:=0; provider BIGINT:=0; objects BIGINT:=0; identity BYTEA; fit_capacity NUMERIC; fit_provider NUMERIC; fit_objects NUMERIC; slot_retained NUMERIC;
BEGIN
 SELECT * INTO STRICT a FROM document_signing_admissions WHERE id=admission AND org_id=org AND document_id=doc;
 IF resource_kind='candidate' THEN
  SELECT COALESCE(sum(hash_signing_resource_fit_db_v1(sl.fit_bytes_limit,sl.expected_objects)::numeric),0),COALESCE(sum(sl.fit_bytes_limit::numeric),0),COALESCE(sum(sl.expected_objects::numeric),0),COALESCE(sum((4096+16*sl.target_count+4*sl.page_count)::numeric),0) INTO fit_capacity,fit_provider,fit_objects,slot_retained FROM document_signing_admission_slots sl WHERE sl.admission_id=a.id;
  IF fit_capacity>1152921504606846976 OR fit_provider>1152921504606846976 OR fit_objects>1000000000 THEN RAISE EXCEPTION 'signing resource entitlement overflow' USING ERRCODE='23514'; END IF;
  retained:=hash_signing_resource_candidate_db_v1(a)+slot_retained::bigint;
  capacity:=retained+a.base_bytes_limit+LEAST(8388608::bigint,cardinality(a.expected_ordinary_pages)::bigint*1048576)+8192*cardinality(a.expected_ordinary_pages)::bigint+hash_signing_resource_common_db_v1(a)+fit_capacity::bigint;
  provider:=hash_signing_resource_common_provider_v1(a)+fit_provider::bigint;objects:=cardinality(a.expected_ordinary_pages)+5+fit_objects::bigint;identity:=a.static_basis_body_sha256;
 ELSIF resource_kind='ordinary' THEN SELECT * INTO STRICT b FROM document_signing_admission_bodies WHERE admission_id=a.id AND kind=member AND page=member_page;retained:=b.bytes+octet_length(b.plan_payload)+4096;identity:=digest(b.sha256||b.plan_sha256||b.package_sha256||b.report_sha256||b.inspection_sha256,'sha256');
 ELSIF resource_kind='fit' THEN
  SELECT * INTO STRICT p FROM signature_fit_preparations WHERE id=operation AND org_id=org AND document_id=doc;
  IF NOT EXISTS(SELECT 1 FROM signing_resource_fit_transfers tr WHERE tr.admission_id=a.id AND tr.recipient_id=p.recipient_id AND tr.preparation_id=p.id) THEN capacity:=hash_signing_resource_fit_db_v1(p.reserved_bytes,p.expected_objects);provider:=p.reserved_bytes;objects:=p.expected_objects;END IF;
  retained:=4096+octet_length(p.source_storage_key)+octet_length(p.source_version_id);identity:=p.authority_sha256;
 ELSIF resource_kind='authority' THEN SELECT * INTO STRICT au FROM signature_fit_original_authorities WHERE preparation_id=operation AND org_id=org AND document_id=doc;retained:=au.authority_bytes+4096+4*cardinality(au.occupied_pages);identity:=au.authority_sha256;
 ELSIF resource_kind='payload' THEN SELECT * INTO STRICT orig FROM signature_fit_original_payloads WHERE preparation_id=operation AND org_id=org AND document_id=doc AND kind=member AND page=member_page;retained:=orig.bytes+4096+octet_length(orig.storage_key)+octet_length(orig.content_type);identity:=orig.sha256;
 ELSIF resource_kind='request_binding' THEN
  SELECT * INTO STRICT request_binding FROM signature_fit_request_bindings WHERE preparation_id=operation AND org_id=org AND document_id=doc AND admission_id=a.id;
  capacity:=hash_signing_resource_request_db_v1(request_binding);retained:=capacity;identity:=request_binding.binding_sha256;
 ELSE
  SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=operation AND org_id=org AND document_id=doc;
  IF resource_kind='finalization' THEN
   IF NOT EXISTS(SELECT 1 FROM signing_resource_finalization_transfers tr WHERE tr.admission_id=a.id AND tr.preparation_id=fp.id) THEN capacity:=hash_signing_resource_common_db_v1(a);provider:=hash_signing_resource_common_provider_v1(a);objects:=cardinality(a.expected_ordinary_pages)+5;END IF;
   retained:=4096+octet_length(fp.geometry_pages_payload)+octet_length(fp.field_snapshot_payload)+octet_length(fp.original_document_name)+octet_length(fp.source_storage_key)+octet_length(fp.source_version_id);identity:=fp.field_snapshot_sha256;
  ELSIF resource_kind='output' THEN SELECT * INTO STRICT outrow FROM document_finalization_outputs WHERE preparation_id=operation AND kind=member AND page=member_page;retained:=outrow.bytes+4096+octet_length(outrow.storage_key)+octet_length(outrow.content_type);identity:=outrow.sha256;
  ELSIF resource_kind='audit_input' THEN retained:=octet_length(fp.audit_snapshot_payload)+4096;identity:=fp.audit_snapshot_sha256;
  ELSIF resource_kind='certificate_input' THEN retained:=octet_length(fp.certificate_input_payload)+4096;identity:=fp.certificate_input_sha256;
  ELSE RAISE EXCEPTION 'signing resource kind unavailable' USING ERRCODE='23514';END IF;
 END IF;
 INSERT INTO signing_resource_debts(org_id,document_id,ceremony_epoch,admission_id,kind,operation_id,member_kind,page,identity_sha256,db_capacity_bytes,db_retained_bytes,provider_reserved_bytes,provider_reserved_objects)
 VALUES(org,doc,a.ceremony_epoch,a.id,resource_kind,operation,member,member_page,identity,capacity,retained,provider,objects);
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_after_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE org_value UUID;doc_value UUID;admission UUID; policy_value TEXT; source_preparation UUID; p signature_fit_preparations%ROWTYPE; fp document_finalization_preparations%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='signature_fit_objects' THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='document_finalization_outputs' THEN SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=NEW.preparation_id;org_value:=fp.org_id;doc_value:=fp.document_id;
 ELSE org_value:=NEW.org_id;doc_value:=NEW.document_id; END IF;
 SELECT signing_admission_policy INTO STRICT policy_value FROM documents WHERE id=doc_value AND org_id=org_value;
 IF policy_value='historical' THEN RETURN NEW; END IF;
 admission:=hash_signing_resource_entities_v1(org_value,doc_value);
 IF TG_TABLE_NAME='document_signing_admissions' THEN admission:=NEW.id;PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'candidate',NEW.id,'',0);
 ELSIF TG_TABLE_NAME='document_signing_admission_bodies' THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,NEW.admission_id,'ordinary',NEW.admission_id,NEW.kind,NEW.page);
 ELSIF TG_TABLE_NAME='signature_fit_preparations' THEN
  IF admission IS NULL THEN RAISE EXCEPTION 'signing resource preparation requires current static admission' USING ERRCODE='23514';END IF;
  -- The first logical prep conserves the ENTIRE unknown-name slot ceiling.
  -- Later preparations add their own immutable ceiling; old debt is not freed.
  INSERT INTO signing_resource_fit_transfers(admission_id,org_id,document_id,recipient_id,preparation_id)
   SELECT admission,org_value,doc_value,NEW.recipient_id,NEW.id WHERE NOT EXISTS(SELECT 1 FROM signing_resource_fit_transfers tr WHERE tr.admission_id=admission AND tr.recipient_id=NEW.recipient_id);
  PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'fit',NEW.id,'',0);
 ELSIF TG_TABLE_NAME IN('signature_fit_original_authorities','signature_fit_original_payloads') THEN
  SELECT debt.admission_id INTO STRICT admission FROM signing_resource_debts debt WHERE debt.org_id=org_value AND debt.document_id=doc_value AND debt.kind='fit' AND debt.operation_id=NEW.preparation_id;
  IF TG_TABLE_NAME='signature_fit_original_authorities' THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'authority',NEW.preparation_id,'',0);
  ELSE PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'payload',NEW.preparation_id,NEW.kind,NEW.page);END IF;
 ELSIF TG_TABLE_NAME='signature_fit_request_bindings' THEN
  PERFORM hash_signing_resource_record_v1(org_value,doc_value,NEW.admission_id,'request_binding',NEW.preparation_id,'',0);
 ELSIF TG_TABLE_NAME='document_finalization_preparations' THEN
  IF TG_OP='INSERT' THEN
   INSERT INTO signing_resource_finalization_transfers(admission_id,org_id,document_id,preparation_id)
    SELECT admission,org_value,doc_value,NEW.id WHERE NOT EXISTS(SELECT 1 FROM signing_resource_finalization_transfers tr WHERE tr.admission_id=admission);
   PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'finalization',NEW.id,'',0);
  ELSE SELECT debt.admission_id INTO STRICT admission FROM signing_resource_debts debt WHERE debt.org_id=org_value AND debt.document_id=doc_value AND debt.kind='finalization' AND debt.operation_id=NEW.id;END IF;
  IF NEW.audit_snapshot_payload IS NOT NULL AND (TG_OP='INSERT' OR OLD.audit_snapshot_payload IS NULL) THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'audit_input',NEW.id,'',0);END IF;
  IF NEW.certificate_input_payload IS NOT NULL AND (TG_OP='INSERT' OR OLD.certificate_input_payload IS NULL) THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'certificate_input',NEW.id,'',0);END IF;
 ELSIF TG_TABLE_NAME='document_finalization_outputs' THEN
  SELECT debt.admission_id INTO STRICT admission FROM signing_resource_debts debt WHERE debt.org_id=org_value AND debt.document_id=doc_value AND debt.kind='finalization' AND debt.operation_id=NEW.preparation_id;
  PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'output',NEW.preparation_id,NEW.kind,NEW.page);
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_pair_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE org_value UUID;doc_value UUID;operation UUID;member TEXT:='';member_page INTEGER:=0;resource_kind TEXT;admission UUID;
 p signature_fit_preparations%ROWTYPE;fp document_finalization_preparations%ROWTYPE;debt signing_resource_debts%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='signing_resource_fit_transfers' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='fit';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='signing_resource_finalization_transfers' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='finalization';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='signing_resource_debts' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.operation_id;member:=NEW.member_kind;member_page:=NEW.page;resource_kind:=NEW.kind;admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='document_signing_admissions' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.id;resource_kind:='candidate';admission:=NEW.id;
 ELSIF TG_TABLE_NAME='document_signing_admission_bodies' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.admission_id;member:=NEW.kind;member_page:=NEW.page;resource_kind:='ordinary';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='signature_fit_preparations' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.id;resource_kind:='fit';
 ELSIF TG_TABLE_NAME='signature_fit_original_authorities' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='authority';
 ELSIF TG_TABLE_NAME='signature_fit_original_payloads' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;member:=NEW.kind;member_page:=NEW.page;resource_kind:='payload';
 ELSIF TG_TABLE_NAME='signature_fit_request_bindings' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='request_binding';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='document_finalization_preparations' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.id;resource_kind:='finalization';
 ELSIF TG_TABLE_NAME='document_finalization_outputs' THEN SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=NEW.preparation_id;org_value:=fp.org_id;doc_value:=fp.document_id;operation:=fp.id;member:=NEW.kind;member_page:=NEW.page;resource_kind:='output';
 ELSE RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM documents WHERE id=doc_value AND org_id=org_value AND signing_admission_policy='pdf-static-v1') THEN RETURN NULL;END IF;
 SELECT * INTO STRICT debt FROM signing_resource_debts WHERE org_id=org_value AND document_id=doc_value AND kind=resource_kind AND operation_id=operation AND member_kind=member AND page=member_page;
 IF admission IS NOT NULL AND debt.admission_id<>admission THEN RAISE EXCEPTION 'signing resource source/receipt admission differs' USING ERRCODE='23514';END IF;
 IF resource_kind IN('fit','authority','payload','request_binding') THEN
  SELECT * INTO STRICT p FROM signature_fit_preparations WHERE id=operation AND org_id=org_value AND document_id=doc_value;
  IF NOT EXISTS(SELECT 1 FROM signature_fit_original_authorities oa WHERE oa.preparation_id=p.id AND oa.org_id=p.org_id AND oa.document_id=p.document_id AND oa.authority_sha256=p.authority_sha256)
   OR NOT EXISTS(SELECT 1 FROM signature_fit_original_payloads os WHERE os.preparation_id=p.id AND os.kind='span' AND os.page=0 AND os.sha256=p.span_sha256)
   OR NOT EXISTS(SELECT 1 FROM document_signing_admission_slots sl WHERE sl.admission_id=debt.admission_id AND sl.org_id=p.org_id AND sl.document_id=p.document_id AND sl.recipient_id=p.recipient_id AND sl.designated_preparation_id=p.id AND sl.designated_owner_id=p.owner_id) THEN
   RAISE EXCEPTION 'signing resource fit reservation requires atomic85/87/88 tuple' USING ERRCODE='23514';
  END IF;
  IF p.request_binding_creation_xid IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signature_fit_request_bindings rb
   WHERE rb.preparation_id=p.id AND rb.org_id=p.org_id AND rb.document_id=p.document_id AND rb.recipient_id=p.recipient_id AND rb.ceremony_epoch=p.ceremony_epoch
    AND rb.admission_id=debt.admission_id AND rb.authority_sha256=p.authority_sha256 AND rb.captured_transaction_id=p.request_binding_creation_xid
    AND rb.binding_sha256=hash_signature_fit_request_identity_v1(rb)
    AND EXISTS(SELECT 1 FROM signing_resource_debts rd WHERE rd.org_id=rb.org_id AND rd.document_id=rb.document_id AND rd.kind='request_binding' AND rd.operation_id=rb.preparation_id AND rd.member_kind='' AND rd.page=0
     AND rd.admission_id=rb.admission_id AND rd.captured_transaction_id=rb.captured_transaction_id AND rd.identity_sha256=rb.binding_sha256)) THEN
   RAISE EXCEPTION 'signing resources require immutable atomic85/87/88/90 request binding' USING ERRCODE='23514';END IF;
 END IF;
 IF resource_kind='finalization' THEN
  SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=operation;
  IF fp.audit_snapshot_payload IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signing_resource_debts WHERE org_id=org_value AND document_id=doc_value AND kind='audit_input' AND operation_id=operation AND member_kind='' AND page=0)
   OR fp.certificate_input_payload IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signing_resource_debts WHERE org_id=org_value AND document_id=doc_value AND kind='certificate_input' AND operation_id=operation AND member_kind='' AND page=0) THEN
   RAISE EXCEPTION 'signing resource final input lacks retained debt' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NULL;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION 'signing resource inventory lacks exact debt receipt' USING ERRCODE='23514';
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_snapshot_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE rows_count BIGINT; docs_count BIGINT; db_total NUMERIC; provider_total NUMERIC; objects_total NUMERIC; fingerprint BYTEA;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NEW.verification_state<>'pending' OR NOT NEW.unknown_provider_debt THEN
  RAISE EXCEPTION 'signing resource staged snapshot is not verification' USING ERRCODE='23514';
 END IF;
 -- Take the serialized metadata snapshot ourselves, including direct SQL.
 -- Admission/collector resources MUST be held before dispatch. No provider I/O
 -- occurs under locks; active writers make staging refuse rather than wait.
 LOCK TABLE documents,document_signing_admissions,document_signing_admission_bodies,document_signing_admission_slots,signature_signing_admission_bindings,signature_fit_preparations,signature_fit_objects,signature_fit_selections,signature_fit_companions,signature_fit_original_authorities,signature_fit_original_payloads,signature_fit_request_bindings,document_finalization_preparations,document_finalization_outputs,document_finalization_references IN SHARE MODE NOWAIT;
 PERFORM 1 FROM signing_resource_control WHERE singleton FOR UPDATE NOWAIT;
  IF (SELECT count(*) FROM signing_resource_inventory_snapshots)>=8 THEN
  RAISE EXCEPTION 'signing resource staged snapshot inventory full' USING ERRCODE='23514';
 END IF;

 IF NEW.captured_transaction_id IS DISTINCT FROM pg_current_xact_id() THEN RAISE EXCEPTION 'signing resource snapshot transaction differs' USING ERRCODE='23514'; END IF;
 SELECT count(*),count(DISTINCT document_id) INTO rows_count,docs_count FROM signing_resource_current_inventory_v1;
 IF rows_count>65536 OR docs_count>4096 THEN RAISE EXCEPTION 'signing resource inventory exceeds staged profile' USING ERRCODE='23514'; END IF;
 SELECT COALESCE(sum(db_bytes::numeric),0),COALESCE(sum(provider_bytes::numeric),0),COALESCE(sum(provider_objects::numeric),0),
  digest(convert_to(COALESCE(string_agg(org_id::text||'/'||document_id::text||'/'||kind||'/'||operation_id::text||'/'||member_kind||'/'||page::text||'/'||encode(identity_sha256,'hex')||'/'||db_bytes::text||'/'||provider_bytes::text||'/'||provider_objects::text,E'\n' ORDER BY org_id,document_id,kind,operation_id,member_kind,page),''),'UTF8'),'sha256')
 INTO db_total,provider_total,objects_total,fingerprint FROM signing_resource_current_inventory_v1;
 IF db_total>1152921504606846976 OR provider_total>1152921504606846976 OR objects_total>1000000000 OR
  ROW(NEW.entry_count,NEW.document_count,NEW.known_db_bytes,NEW.known_provider_bytes,NEW.known_provider_objects,NEW.inventory_sha256)
  IS DISTINCT FROM ROW(rows_count,docs_count,db_total::bigint,provider_total::bigint,objects_total::bigint,fingerprint) THEN
  RAISE EXCEPTION 'signing resource snapshot differs from exact scoped inventory' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_stage_inventory_v1(snapshot_id UUID,receipt_id UUID,receipt_key TEXT,receipt_version TEXT,receipt_sha BYTEA,receipt_size BIGINT)
RETURNS signing_resource_inventory_snapshots LANGUAGE plpgsql AS $$
DECLARE n BIGINT; docs BIGINT; db_amount NUMERIC; provider_amount NUMERIC; object_amount NUMERIC; sha BYTEA; result signing_resource_inventory_snapshots%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'signing resource staging requires read committed' USING ERRCODE='23514';END IF;
 LOCK TABLE documents,document_signing_admissions,document_signing_admission_bodies,document_signing_admission_slots,signature_signing_admission_bindings,signature_fit_preparations,signature_fit_objects,signature_fit_selections,signature_fit_companions,signature_fit_original_authorities,signature_fit_original_payloads,signature_fit_request_bindings,document_finalization_preparations,document_finalization_outputs,document_finalization_references IN SHARE MODE NOWAIT;
 SELECT count(*),count(DISTINCT document_id) INTO n,docs FROM signing_resource_current_inventory_v1;
 IF n>65536 OR docs>4096 THEN RAISE EXCEPTION 'signing resource inventory exceeds staged profile' USING ERRCODE='23514';END IF;
 SELECT COALESCE(sum(db_bytes::numeric),0),COALESCE(sum(provider_bytes::numeric),0),COALESCE(sum(provider_objects::numeric),0),
 digest(convert_to(COALESCE(string_agg(org_id::text||'/'||document_id::text||'/'||kind||'/'||operation_id::text||'/'||member_kind||'/'||page::text||'/'||encode(identity_sha256,'hex')||'/'||db_bytes::text||'/'||provider_bytes::text||'/'||provider_objects::text,E'\n' ORDER BY org_id,document_id,kind,operation_id,member_kind,page),''),'UTF8'),'sha256')
 INTO db_amount,provider_amount,object_amount,sha FROM signing_resource_current_inventory_v1;
 IF db_amount>1152921504606846976 OR provider_amount>1152921504606846976 OR object_amount>1000000000 THEN RAISE EXCEPTION 'signing resource inventory overflow' USING ERRCODE='23514';END IF;
 INSERT INTO signing_resource_inventory_snapshots(id,inventory_sha256,entry_count,document_count,known_db_bytes,known_provider_bytes,known_provider_objects,controller_receipt_id,receipt_storage_key,receipt_version_id,receipt_sha256,receipt_bytes)
 VALUES(snapshot_id,sha,n,docs,db_amount::bigint,provider_amount::bigint,object_amount::bigint,receipt_id,receipt_key,receipt_version,receipt_sha,receipt_size) RETURNING * INTO result;
 INSERT INTO signing_resource_inventory_entries(snapshot_id,org_id,document_id,ceremony_epoch,kind,operation_id,member_kind,page,identity_sha256,db_bytes,provider_bytes,provider_objects)
 SELECT result.id,inv.org_id,inv.document_id,inv.ceremony_epoch,inv.kind,inv.operation_id,inv.member_kind,inv.page,inv.identity_sha256,inv.db_bytes,inv.provider_bytes,inv.provider_objects FROM signing_resource_current_inventory_v1 inv;
 RETURN result;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'signing resource inventory is busy' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE OR REPLACE VIEW signing_resource_current_inventory_v1 AS
SELECT d.org_id,d.id AS document_id,d.sent_at AS ceremony_epoch,'document'::text AS kind,d.id AS operation_id,''::text AS member_kind,0::integer AS page,
 digest(convert_to(jsonb_build_array(d.id,d.org_id,d.status,d.signing_admission_policy,d.signing_admission_active_id,d.signing_admission_sealed_id,d.pdf_storage_key,d.pdf_storage_version_id,encode(d.pdf_sha256,'hex'),hash_article13_canonical_sent_at(d.sent_at),d.deleted_at IS NOT NULL)::text,'UTF8'),'sha256') AS identity_sha256,
 (4096+octet_length(d.name)+COALESCE(octet_length(d.pdf_storage_key),0)+COALESCE(octet_length(d.pdf_storage_version_id),0))::bigint AS db_bytes,0::bigint AS provider_bytes,0::bigint AS provider_objects
FROM documents d WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT a.org_id,a.document_id,a.ceremony_epoch,'candidate',a.id,'',0,
 digest(convert_to(jsonb_build_array(a.id,encode(a.static_basis_sha256,'hex'),encode(a.static_basis_body_sha256,'hex'),encode(a.geometry_sha256,'hex'),encode(a.fields_sha256,'hex'),encode(a.parties_sha256,'hex'),encode(a.render_recipe_sha256,'hex'),a.status,a.owner_id,hash_article13_canonical_sent_at(a.lease_until),a.attempts)::text,'UTF8'),'sha256'),
 (octet_length(a.static_basis_payload)::bigint+octet_length(a.geometry_payload)+octet_length(a.geometry_pages_payload)+octet_length(a.fields_payload)+octet_length(a.parties_payload)+octet_length(a.render_recipe_payload)+octet_length(a.ordinary_recipe_payload)+octet_length(a.original_document_name)+octet_length(a.source_storage_key)+octet_length(a.source_version_id)+4096),(a.base_bytes_limit+a.final_pdf_bytes_limit+a.fits_index_bytes_limit+a.certificate_pdf_bytes_limit+a.certificate_payload_bytes_limit+a.certificate_signature_bytes_limit)::bigint,(cardinality(a.expected_ordinary_pages)+5)::bigint
FROM document_signing_admissions a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT b.org_id,b.document_id,a.ceremony_epoch,'ordinary',b.admission_id,b.kind,b.page,
 digest(convert_to(jsonb_build_array(b.page,encode(b.sha256,'hex'),b.bytes,encode(b.plan_sha256,'hex'),octet_length(b.plan_payload),encode(b.package_sha256,'hex'),encode(b.report_sha256,'hex'),encode(b.inspection_sha256,'hex'),b.captured_owner_id)::text,'UTF8'),'sha256'),
 (b.bytes+octet_length(b.plan_payload)+4096)::bigint,0::bigint,0::bigint
FROM document_signing_admission_bodies b JOIN document_signing_admissions a ON a.id=b.admission_id JOIN documents d ON d.id=b.document_id AND d.org_id=b.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'fit',p.id,'',0,
 digest(convert_to(jsonb_build_array(p.id,p.recipient_id,p.request_binding_creation_xid::text,encode(p.authority_sha256,'hex'),p.source_storage_key,p.source_version_id,encode(p.source_sha256,'hex'),p.source_bytes,encode(p.geometry_sha256,'hex'),encode(p.span_sha256,'hex'),p.reserved_bytes,p.expected_objects,p.status,p.owner_id,hash_article13_canonical_sent_at(p.lease_until),p.attempts,p.selection_commit_attempted_at IS NOT NULL,p.selection_not_committed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(p.source_storage_key)+octet_length(p.source_version_id))::bigint,p.reserved_bytes,p.expected_objects::bigint
FROM signature_fit_preparations p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'fit_object',p.id,o.kind,o.page,
 digest(convert_to(jsonb_build_array(o.kind,o.page,o.storage_key,encode(o.sha256,'hex'),o.bytes,o.content_type,o.version_id,o.upload_attempted_at IS NOT NULL,o.readback_verified_at IS NOT NULL,o.cleanup_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(o.storage_key)+octet_length(o.content_type)+COALESCE(octet_length(o.version_id),0))::bigint,0::bigint,0::bigint
FROM signature_fit_objects o JOIN signature_fit_preparations p ON p.id=o.preparation_id JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT a.org_id,a.document_id,a.ceremony_epoch,'authority',a.preparation_id,'',0,a.authority_sha256,(a.authority_bytes+4096+4*cardinality(a.occupied_pages))::bigint,0::bigint,0::bigint
FROM signature_fit_original_authorities a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT b.org_id,b.document_id,a.ceremony_epoch,'payload',b.preparation_id,b.kind,b.page,
 digest(convert_to(jsonb_build_array(b.kind,b.page,b.storage_key,encode(b.sha256,'hex'),b.bytes,b.content_type,b.captured_owner_id)::text,'UTF8'),'sha256'),(b.bytes+4096+octet_length(b.storage_key)+octet_length(b.content_type))::bigint,0::bigint,0::bigint
FROM signature_fit_original_payloads b JOIN signature_fit_original_authorities a ON a.preparation_id=b.preparation_id JOIN documents d ON d.id=b.document_id AND d.org_id=b.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'finalization',p.id,'',0,
 digest(convert_to(jsonb_build_array(p.id,encode(p.source_sha256,'hex'),p.source_version_id,encode(p.geometry_sha256,'hex'),encode(p.field_snapshot_sha256,'hex'),hash_article13_canonical_sent_at(p.completion_effective_at),p.status,p.expected_outputs,p.expected_references,encode(p.audit_snapshot_sha256,'hex'),encode(p.certificate_input_sha256,'hex'),p.publication_commit_attempted_at IS NOT NULL,p.published_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(p.geometry_pages_payload)+octet_length(p.field_snapshot_payload)+octet_length(p.original_document_name)+octet_length(p.source_storage_key)+octet_length(p.source_version_id)+COALESCE(octet_length(p.audit_snapshot_payload),0)+COALESCE(octet_length(p.certificate_input_payload),0))::bigint,
 (p.base_bytes_limit+p.final_pdf_bytes_limit+p.fits_index_bytes_limit+p.certificate_pdf_bytes_limit+p.certificate_payload_bytes_limit+p.certificate_signature_bytes_limit)::bigint,p.expected_outputs::bigint
FROM document_finalization_preparations p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'output',p.id,o.kind,o.page,
 digest(convert_to(jsonb_build_array(o.kind,o.page,o.storage_key,encode(o.sha256,'hex'),o.bytes,o.content_type,o.version_id,o.upload_attempted_at IS NOT NULL,o.readback_verified_at IS NOT NULL,o.retention_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (o.bytes+4096+octet_length(o.storage_key)+octet_length(o.content_type)+COALESCE(octet_length(o.version_id),0))::bigint,0::bigint,0::bigint
FROM document_finalization_outputs o JOIN document_finalization_preparations p ON p.id=o.preparation_id JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT sl.org_id,sl.document_id,a.ceremony_epoch,'slot',sl.admission_id,sl.recipient_id::text,0,
 digest(convert_to(jsonb_build_array(sl.recipient_id,sl.target_ids,sl.occupied_pages,sl.expected_objects,sl.fit_bytes_limit,sl.pdf_bytes_limit,sl.designated_preparation_id,sl.designated_owner_id)::text,'UTF8'),'sha256'),
 (4096+16*sl.target_count+4*sl.page_count)::bigint,sl.fit_bytes_limit,sl.expected_objects::bigint
FROM document_signing_admission_slots sl JOIN document_signing_admissions a ON a.id=sl.admission_id JOIN documents d ON d.id=sl.document_id AND d.org_id=sl.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT se.org_id,se.document_id,se.ceremony_epoch,'selection',se.id,'',0,
 digest(convert_to(jsonb_build_array(se.id,se.preparation_id,se.recipient_id,encode(se.authority_sha256,'hex'),se.span_storage_key,se.span_version_id,encode(se.span_sha256,'hex'),se.span_bytes,se.manifest_storage_key,se.manifest_version_id,encode(se.manifest_sha256,'hex'),se.manifest_bytes,hash_article13_canonical_sent_at(se.retain_until),se.retention_started_at IS NOT NULL,se.retention_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(se.source_storage_key)+octet_length(se.source_version_id)+octet_length(se.span_storage_key)+octet_length(se.span_version_id)+octet_length(se.manifest_storage_key)+octet_length(se.manifest_version_id))::bigint,0::bigint,0::bigint
FROM signature_fit_selections se JOIN documents d ON d.id=se.document_id AND d.org_id=se.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT co.org_id,co.document_id,d.sent_at,'companion',co.signature_id,'',0,
 digest(convert_to(jsonb_build_array(co.signature_id,co.recipient_id,co.field_id,co.selection_id,encode(co.span_sha256,'hex'))::text,'UTF8'),'sha256'),4096::bigint,0::bigint,0::bigint
FROM signature_fit_companions co JOIN documents d ON d.id=co.document_id AND d.org_id=co.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT bi.org_id,bi.document_id,a.ceremony_epoch,'binding',bi.signature_id,'',0,
 digest(convert_to(jsonb_build_array(bi.signature_id,bi.admission_id,bi.recipient_id,bi.field_id,bi.selection_id,bi.signed_event_id,encode(bi.static_basis_sha256,'hex'),encode(bi.reviewed_basis_sha256,'hex'))::text,'UTF8'),'sha256'),4096::bigint,0::bigint,0::bigint
FROM signature_signing_admission_bindings bi JOIN document_signing_admissions a ON a.id=bi.admission_id JOIN documents d ON d.id=bi.document_id AND d.org_id=bi.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'reference',p.id,r.kind||'/'||r.owner_key::text,r.page,
 digest(convert_to(jsonb_build_array(r.kind,r.owner_key,r.signature_id,r.selection_id,r.page,r.storage_key,r.version_id,encode(r.sha256,'hex'),r.bytes,r.content_type,r.retention_started_at IS NOT NULL,r.retention_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(r.storage_key)+octet_length(r.version_id)+octet_length(r.content_type))::bigint,0::bigint,0::bigint
FROM document_finalization_references r JOIN document_finalization_preparations p ON p.id=r.preparation_id JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT rb.org_id,rb.document_id,rb.ceremony_epoch,'request_binding',rb.preparation_id,'',0,rb.binding_sha256,
 (rb.original_request_bytes+rb.accepted_intent_bytes+8192)::bigint,0::bigint,0::bigint
FROM signature_fit_request_bindings rb;
CREATE TRIGGER zz_signing_resource_request_binding AFTER INSERT ON signature_fit_request_bindings FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_after_v1();
CREATE CONSTRAINT TRIGGER signing_resource_request_binding_pair AFTER INSERT ON signature_fit_request_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();

-- +goose StatementBegin
CREATE FUNCTION hash_signature_fit_request_selection_gate_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE doc documents%ROWTYPE;preparation UUID;
BEGIN
 SELECT * INTO STRICT doc FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF doc.signing_admission_policy='historical' THEN RETURN NEW;END IF;
 IF doc.signing_admission_policy<>'pdf-static-v1' THEN RAISE EXCEPTION 'request selection policy unavailable' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='signature_fit_selections' THEN preparation:=NEW.preparation_id;
 ELSE SELECT preparation_id INTO STRICT preparation FROM signature_fit_selections WHERE id=NEW.selection_id AND org_id=doc.org_id AND document_id=doc.id AND recipient_id=NEW.recipient_id;END IF;
 IF NOT EXISTS(SELECT 1 FROM signature_fit_preparations p JOIN signature_fit_request_bindings rb ON rb.preparation_id=p.id AND rb.org_id=p.org_id AND rb.document_id=p.document_id AND rb.recipient_id=p.recipient_id AND rb.ceremony_epoch=p.ceremony_epoch
  WHERE p.id=preparation AND p.org_id=doc.org_id AND p.document_id=doc.id AND p.recipient_id=NEW.recipient_id AND p.request_binding_creation_xid IS NOT NULL AND rb.captured_transaction_id=p.request_binding_creation_xid
   AND rb.authority_sha256=p.authority_sha256 AND rb.binding_sha256=hash_signature_fit_request_identity_v1(rb)) THEN
  RAISE EXCEPTION 'fitted selection requires captured original request; old preparations cannot be backfilled' USING ERRCODE='23514';END IF;
 -- Presence/identity is still not permission. Existing85/88/current credential,
 -- notice, retained-version, final publication and actual retirement gates remain.
 RETURN NEW;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION 'request selection scoped parent missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER ab_signature_fit_request_selection BEFORE INSERT ON signature_fit_selections FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_request_selection_gate_v1();
CREATE TRIGGER ab_signature_fit_request_companion BEFORE INSERT ON signature_fit_companions FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_request_selection_gate_v1();
CREATE TRIGGER ab_signature_fit_request_admission_binding BEFORE INSERT ON signature_signing_admission_bindings FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_request_selection_gate_v1();

-- +goose StatementBegin
CREATE FUNCTION hash_signature_fit_reserve_bound_request_v1(
 target_org UUID,target_document UUID,target_recipient UUID,target_admission UUID,reviewed_basis BYTEA,
 lease_owner UUID,lease_end TIMESTAMPTZ,origin_payload BYTEA,intent_payload BYTEA,authority_payload BYTEA,span_payload BYTEA
) RETURNS signature_fit_request_bindings LANGUAGE plpgsql AS $$
DECLARE doc documents%ROWTYPE;recipient_row recipients%ROWTYPE;admission document_signing_admissions%ROWTYPE;slot document_signing_admission_slots%ROWTYPE;
 existing signature_fit_request_bindings%ROWTYPE;result signature_fit_request_bindings%ROWTYPE;prep signature_fit_preparations%ROWTYPE;old_original signature_fit_original_authorities%ROWTYPE;
 original_json JSONB;intent_json JSONB;original_doc_expiry TIMESTAMPTZ;source_sha BYTEA;intent_sha BYTEA;preparation UUID;
BEGIN
 -- Not authorization. The application supplies only privately issued and fully
 -- decoded receipt/intent/authority under real before-dispatch resource admission.
 -- No prep UUID, quota amount, activation, retired/settled bool, COMMIT or provider
 -- operation is accepted. The SQL transaction's ack/unknown/retirement is owned by
 -- ApplicationSessionV1; callers never create a new UUID after unknown outcomes.
 IF current_setting('transaction_isolation')<>'read committed' OR NOT EXISTS(SELECT 1 FROM signing_resource_control WHERE singleton AND state='ready') THEN
  RAISE EXCEPTION 'bound request reservation requires verified resources' USING ERRCODE='23514';END IF;
 IF octet_length(origin_payload) NOT BETWEEN 1 AND 1048576 OR octet_length(intent_payload) NOT BETWEEN 1 AND 1048576
  OR octet_length(authority_payload) NOT BETWEEN 1 AND 1048576 OR octet_length(span_payload) NOT BETWEEN 1 AND 1048576 THEN RAISE EXCEPTION 'bound request body exceeds profile' USING ERRCODE='23514';END IF;
 PERFORM hash_signing_resource_entities_v1(target_org,target_document);
 SELECT * INTO STRICT doc FROM documents WHERE id=target_document AND org_id=target_org FOR UPDATE;
 SELECT * INTO STRICT recipient_row FROM recipients WHERE id=target_recipient AND document_id=doc.id FOR UPDATE;
 SELECT * INTO STRICT admission FROM document_signing_admissions WHERE id=target_admission AND org_id=doc.org_id AND document_id=doc.id FOR UPDATE;
 SELECT * INTO STRICT slot FROM document_signing_admission_slots WHERE admission_id=admission.id AND recipient_id=recipient_row.id FOR UPDATE;
 IF doc.signing_admission_policy<>'pdf-static-v1' OR doc.signing_admission_active_id IS DISTINCT FROM admission.id OR admission.static_basis_sha256 IS DISTINCT FROM reviewed_basis
  OR admission.status NOT IN('staging','ready','sealed') OR NOT hash_pdf_admission_current_matches_v1(admission.id,doc.org_id,doc.id)
  OR doc.status NOT IN('sent','in_progress') OR recipient_row.status NOT IN('pending','sent','viewed') OR recipient_row.role IN('cc','viewer')
  OR NOT hash_signature_fit_request_finite_v1(recipient_row.magic_token_expires_at) OR recipient_row.magic_token_expires_at<=clock_timestamp()
  OR (doc.expires_at IS NOT NULL AND (NOT hash_signature_fit_request_finite_v1(doc.expires_at) OR doc.expires_at<=clock_timestamp()))
  OR NOT doc.requires_signature OR doc.source_kind<>'pdf' OR doc.routing_tier<>'SES' OR doc.is_envelope OR doc.parent_envelope_id IS NOT NULL OR doc.deleted_at IS NOT NULL THEN
  RAISE EXCEPTION 'bound request current scope differs' USING ERRCODE='23514';END IF;
 source_sha:=digest(authority_payload,'sha256');intent_sha:=digest(intent_payload,'sha256');
 SELECT * INTO existing FROM signature_fit_request_bindings WHERE org_id=doc.org_id AND document_id=doc.id AND recipient_id=recipient_row.id AND ceremony_epoch=admission.ceremony_epoch
  AND admission_id=admission.id AND static_basis_sha256=admission.static_basis_sha256 AND authority_sha256=source_sha AND accepted_intent_semantic_sha256=intent_sha FOR UPDATE;
 IF FOUND THEN
  -- A semantic hit is byte-for-byte reconciliation, never new admission or lease
  -- takeover. A rotated token/deadline origin mismatch does not choose another ID.
  SELECT * INTO STRICT old_original FROM signature_fit_original_authorities WHERE preparation_id=existing.preparation_id AND org_id=doc.org_id AND document_id=doc.id;
  IF existing.original_request_payload IS DISTINCT FROM origin_payload OR existing.accepted_intent_payload IS DISTINCT FROM intent_payload OR old_original.authority_payload IS DISTINCT FROM authority_payload
   OR slot.designated_preparation_id IS DISTINCT FROM existing.preparation_id
   OR NOT EXISTS(SELECT 1 FROM signature_fit_original_payloads WHERE preparation_id=existing.preparation_id AND kind='span' AND page=0 AND payload=span_payload) THEN
   RAISE EXCEPTION 'bound request semantic conflict requires original reconciliation' USING ERRCODE='23514';END IF;
  original_json:=convert_from(existing.original_request_payload,'UTF8')::jsonb;
  IF original_json->>'token_sha256' IS DISTINCT FROM encode(recipient_row.magic_token_hash,'hex') OR original_json->>'role' IS DISTINCT FROM recipient_row.role
   OR NOT hash_signature_fit_request_finite_v1((original_json->'recipient_expiry'->>'value')::timestamptz)
   OR (original_json->'recipient_expiry'->>'value')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'bound request original credential expired or changed' USING ERRCODE='23514';END IF;
  IF (original_json->'document_expiry'->>'valid')::boolean THEN
   original_doc_expiry:=(original_json->'document_expiry'->>'value')::timestamptz;
   IF NOT hash_signature_fit_request_finite_v1(original_doc_expiry) OR original_doc_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'bound request original document deadline expired' USING ERRCODE='23514';END IF;
  END IF;
  RETURN existing;
 END IF;
 IF slot.designated_preparation_id IS NOT NULL THEN RAISE EXCEPTION 'bound request cannot replace unresolved original designation' USING ERRCODE='23514';END IF;
 IF lease_owner IS NULL OR lease_owner='00000000-0000-0000-0000-000000000000' OR NOT hash_signature_fit_request_finite_v1(lease_end) OR lease_end<=clock_timestamp() THEN RAISE EXCEPTION 'bound request requires a current preparation lease' USING ERRCODE='23514';END IF;
 preparation:=gen_random_uuid();
 INSERT INTO signature_fit_preparations(id,org_id,document_id,recipient_id,ceremony_epoch,authority_sha256,source_storage_key,source_version_id,source_sha256,source_bytes,geometry_sha256,span_sha256,reserved_bytes,expected_objects,owner_id,lease_until)
 VALUES(preparation,doc.org_id,doc.id,recipient_row.id,admission.ceremony_epoch,source_sha,admission.source_storage_key,admission.source_version_id,admission.source_sha256,admission.source_bytes,admission.geometry_sha256,digest(span_payload,'sha256'),slot.fit_bytes_limit,slot.expected_objects,lease_owner,lease_end) RETURNING * INTO prep;
 INSERT INTO signature_fit_original_authorities(preparation_id,org_id,document_id,recipient_id,ceremony_epoch,authority_payload,authority_sha256,authority_bytes,occupied_pages,captured_owner_id)
 VALUES(prep.id,prep.org_id,prep.document_id,prep.recipient_id,prep.ceremony_epoch,authority_payload,prep.authority_sha256,octet_length(authority_payload),slot.occupied_pages,prep.owner_id);
 INSERT INTO signature_fit_original_payloads(preparation_id,org_id,document_id,kind,page,storage_key,sha256,bytes,content_type,payload,captured_owner_id)
 VALUES(prep.id,prep.org_id,prep.document_id,'span',0,'org/'||prep.org_id::text||'/documents/'||prep.document_id::text||'/signatures/fit/'||prep.id::text||'/span.html',prep.span_sha256,octet_length(span_payload),'text/html',span_payload,prep.owner_id);
 INSERT INTO signature_fit_request_bindings(preparation_id,org_id,document_id,recipient_id,ceremony_epoch,admission_id,static_basis_sha256,authority_sha256,
  original_request_payload,original_request_sha256,original_request_bytes,accepted_intent_payload,accepted_intent_sha256,accepted_intent_semantic_sha256,accepted_intent_bytes)
 VALUES(prep.id,prep.org_id,prep.document_id,prep.recipient_id,prep.ceremony_epoch,admission.id,admission.static_basis_sha256,prep.authority_sha256,
  origin_payload,digest(origin_payload,'sha256'),octet_length(origin_payload),intent_payload,intent_sha,intent_sha,octet_length(intent_payload)) RETURNING * INTO result;
 UPDATE document_signing_admission_slots SET designated_preparation_id=prep.id,designated_owner_id=prep.owner_id WHERE admission_id=admission.id AND recipient_id=recipient_row.id AND designated_preparation_id IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'bound request designation changed' USING ERRCODE='23514';END IF;
 RETURN result;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION 'bound request scoped immutable parent missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd

-- +goose Down
-- Used requests and staged inventory require explicit managed disposition.
-- No row deletion, refund, baseline replacement or deinitialization is inferred.
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'request binding rollback requires read committed' USING ERRCODE='23514';END IF;
 LOCK TABLE documents,document_signing_admissions,document_signing_admission_bodies,document_signing_admission_slots,signature_signing_admission_bindings,signature_fit_preparations,signature_fit_objects,signature_fit_selections,signature_fit_companions,signature_fit_original_authorities,signature_fit_original_payloads,signature_fit_request_bindings,document_finalization_preparations,document_finalization_outputs,document_finalization_references,signing_resource_inventory_snapshots,signing_resource_inventory_entries,signing_resource_control,signing_resource_accounts,signing_resource_debts,signing_resource_debit_batches,signing_resource_fit_transfers,signing_resource_finalization_transfers IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM signature_fit_request_bindings) OR EXISTS(SELECT 1 FROM signing_resource_debts WHERE kind='request_binding')
  OR EXISTS(SELECT 1 FROM signing_resource_inventory_entries WHERE kind='request_binding') OR EXISTS(SELECT 1 FROM signing_resource_inventory_snapshots)
  OR EXISTS(SELECT 1 FROM signature_fit_preparations WHERE request_binding_creation_xid IS NOT NULL)
  OR EXISTS(SELECT 1 FROM documents WHERE signature_fit_request_binding_bytes<>0 OR signature_fit_request_binding_count<>0) THEN
  RAISE EXCEPTION 'request binding rollback refuses retained or staged inventory' USING ERRCODE='23514';END IF;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'request binding rollback refuses active inventory' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
DROP TRIGGER ab_signature_fit_request_admission_binding ON signature_signing_admission_bindings;
DROP TRIGGER ab_signature_fit_request_companion ON signature_fit_companions;
DROP TRIGGER ab_signature_fit_request_selection ON signature_fit_selections;
DROP TRIGGER signing_resource_request_binding_pair ON signature_fit_request_bindings;
DROP TRIGGER zz_signing_resource_request_binding ON signature_fit_request_bindings;
DROP TRIGGER aa_signing_resource_request_binding ON signature_fit_request_bindings;
DROP TRIGGER signature_fit_request_binding_guard ON signature_fit_request_bindings;
DROP TRIGGER signature_fit_request_budget_body ON signature_fit_request_bindings;
DROP TRIGGER signature_fit_request_budget_document ON documents;
DROP TRIGGER ab_signature_fit_request_slot_guard ON document_signing_admission_slots;
DROP TRIGGER ab_signature_fit_request_birth ON signature_fit_preparations;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION hash_signing_resource_entities_v1(org UUID,doc UUID) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE document_row documents%ROWTYPE; admission_id_value UUID;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'signing resource scope requires read committed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT document_row FROM documents WHERE id=doc AND org_id=org FOR UPDATE;
 IF document_row.signing_admission_policy='historical' THEN RETURN NULL; END IF;
 IF document_row.signing_admission_policy<>'pdf-static-v1' THEN RAISE EXCEPTION 'signing resource policy unavailable' USING ERRCODE='23514'; END IF;
 -- Parent serialization also fences all guarded child writers. No body decoding
 -- or provider I/O, and no account is locked until these entity locks are owned.
 IF (SELECT count(*) FROM recipients WHERE document_id=doc)>100 OR (SELECT count(*) FROM signature_fit_preparations WHERE document_id=doc)>1024 OR (SELECT count(*) FROM document_signing_admissions WHERE document_id=doc)>8 THEN
  RAISE EXCEPTION 'signing resource entity inventory exceeds profile' USING ERRCODE='23514';
 END IF;
 PERFORM 1 FROM recipients WHERE document_id=doc ORDER BY id FOR UPDATE;
 PERFORM 1 FROM document_signing_admissions WHERE document_id=doc AND org_id=org ORDER BY id FOR UPDATE;
 PERFORM 1 FROM document_signing_admission_slots WHERE document_id=doc AND org_id=org ORDER BY admission_id,recipient_id FOR UPDATE;
 PERFORM 1 FROM signature_fit_preparations WHERE document_id=doc AND org_id=org ORDER BY id FOR UPDATE;
 PERFORM 1 FROM signature_fit_original_authorities WHERE document_id=doc AND org_id=org ORDER BY preparation_id FOR UPDATE;
 PERFORM 1 FROM document_finalization_preparations WHERE document_id=doc AND org_id=org ORDER BY id FOR UPDATE;
 admission_id_value:=COALESCE(document_row.signing_admission_sealed_id,document_row.signing_admission_active_id);
 RETURN admission_id_value;
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_debt_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE a document_signing_admissions%ROWTYPE; prep signature_fit_preparations%ROWTYPE;
 ordinary document_signing_admission_bodies%ROWTYPE; original signature_fit_original_payloads%ROWTYPE; authority signature_fit_original_authorities%ROWTYPE;
 finalization document_finalization_preparations%ROWTYPE; output document_finalization_outputs%ROWTYPE;
 expected_capacity BIGINT:=0; expected_retained BIGINT:=0; expected_provider BIGINT:=0; expected_objects BIGINT:=0; expected_identity BYTEA;
 fit_bytes NUMERIC; fit_db NUMERIC; fit_objects NUMERIC; slots_db NUMERIC; epoch TIMESTAMPTZ;
 account_global signing_resource_accounts%ROWTYPE; account_tenant signing_resource_accounts%ROWTYPE; account_key_value UUID;
BEGIN
 IF NEW.org_id='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'signing resource tenant is invalid' USING ERRCODE='23514'; END IF;
 IF NEW.captured_transaction_id IS DISTINCT FROM pg_current_xact_id() OR EXISTS(SELECT 1 FROM signing_resource_debit_batches WHERE captured_transaction_id=pg_current_xact_id()) THEN RAISE EXCEPTION 'signing resource transaction is already account-sealed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT a FROM document_signing_admissions WHERE id=NEW.admission_id AND org_id=NEW.org_id AND document_id=NEW.document_id;
 epoch:=a.ceremony_epoch;
 IF NEW.kind='candidate' THEN
  IF NEW.operation_id<>a.id OR NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'signing resource candidate identity differs' USING ERRCODE='23514'; END IF;
  SELECT COALESCE(sum(sl.fit_bytes_limit::numeric),0),COALESCE(sum(hash_signing_resource_fit_db_v1(sl.fit_bytes_limit,sl.expected_objects)::numeric),0),COALESCE(sum(sl.expected_objects::numeric),0),COALESCE(sum((4096+16*sl.target_count+4*sl.page_count)::numeric),0)
   INTO fit_bytes,fit_db,fit_objects,slots_db FROM document_signing_admission_slots sl WHERE sl.admission_id=a.id;
  IF fit_bytes>1152921504606846976 OR fit_db>1152921504606846976 OR fit_objects>1000000000 THEN RAISE EXCEPTION 'signing resource entitlement overflow' USING ERRCODE='23514'; END IF;
  expected_retained:=hash_signing_resource_candidate_db_v1(a)+slots_db::bigint;
  expected_capacity:=expected_retained+a.base_bytes_limit+LEAST(8388608::bigint,cardinality(a.expected_ordinary_pages)::bigint*1048576)+8192*cardinality(a.expected_ordinary_pages)::bigint+hash_signing_resource_common_db_v1(a)+fit_db::bigint;
  expected_provider:=hash_signing_resource_common_provider_v1(a)+fit_bytes::bigint;
  expected_objects:=cardinality(a.expected_ordinary_pages)+5+fit_objects::bigint;expected_identity:=a.static_basis_body_sha256;
 ELSIF NEW.kind='ordinary' THEN
  SELECT * INTO STRICT ordinary FROM document_signing_admission_bodies WHERE admission_id=a.id AND org_id=a.org_id AND document_id=a.document_id AND kind=NEW.member_kind AND page=NEW.page;
  IF NEW.operation_id<>a.id THEN RAISE EXCEPTION 'signing resource ordinary identity differs' USING ERRCODE='23514'; END IF;
  expected_retained:=ordinary.bytes+octet_length(ordinary.plan_payload)+4096;expected_identity:=digest(ordinary.sha256||ordinary.plan_sha256||ordinary.package_sha256||ordinary.report_sha256||ordinary.inspection_sha256,'sha256');
 ELSIF NEW.kind='fit' THEN
  SELECT * INTO STRICT prep FROM signature_fit_preparations WHERE id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND ceremony_epoch=a.ceremony_epoch;
  IF NEW.member_kind<>'' OR NEW.page<>0 OR NOT EXISTS(SELECT 1 FROM document_signing_admission_slots sl WHERE sl.admission_id=a.id AND sl.recipient_id=prep.recipient_id AND prep.expected_objects=sl.expected_objects AND prep.reserved_bytes<=sl.fit_bytes_limit) THEN RAISE EXCEPTION 'signing resource preparation differs from slot' USING ERRCODE='23514'; END IF;
  IF NOT EXISTS(SELECT 1 FROM signing_resource_fit_transfers tr WHERE tr.admission_id=a.id AND tr.recipient_id=prep.recipient_id AND tr.preparation_id=prep.id) THEN
   expected_capacity:=hash_signing_resource_fit_db_v1(prep.reserved_bytes,prep.expected_objects);expected_provider:=prep.reserved_bytes;expected_objects:=prep.expected_objects;
  END IF;
  expected_retained:=4096+octet_length(prep.source_storage_key)+octet_length(prep.source_version_id);expected_identity:=prep.authority_sha256;
 ELSIF NEW.kind='authority' THEN
  IF NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'signing resource authority member differs' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT authority FROM signature_fit_original_authorities WHERE preparation_id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND ceremony_epoch=a.ceremony_epoch;
  expected_retained:=authority.authority_bytes+4096+4*cardinality(authority.occupied_pages);expected_identity:=authority.authority_sha256;
 ELSIF NEW.kind='payload' THEN
  SELECT * INTO STRICT original FROM signature_fit_original_payloads WHERE preparation_id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND kind=NEW.member_kind AND page=NEW.page;
  expected_retained:=original.bytes+4096+octet_length(original.storage_key)+octet_length(original.content_type);expected_identity:=original.sha256;
 ELSIF NEW.kind IN('finalization','output','audit_input','certificate_input') THEN
  IF NEW.kind IN('audit_input','certificate_input') AND (NEW.member_kind<>'' OR NEW.page<>0) THEN RAISE EXCEPTION 'signing resource input member differs' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT finalization FROM document_finalization_preparations WHERE id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND ceremony_epoch=a.ceremony_epoch;
  IF NEW.kind='finalization' THEN
   IF NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'signing resource finalization identity differs' USING ERRCODE='23514'; END IF;
   IF NOT EXISTS(SELECT 1 FROM signing_resource_finalization_transfers tr WHERE tr.admission_id=a.id AND tr.preparation_id=finalization.id) THEN
    expected_capacity:=hash_signing_resource_common_db_v1(a);expected_provider:=hash_signing_resource_common_provider_v1(a);expected_objects:=cardinality(a.expected_ordinary_pages)+5;
   END IF;
   expected_retained:=4096+octet_length(finalization.geometry_pages_payload)+octet_length(finalization.field_snapshot_payload)+octet_length(finalization.original_document_name)+octet_length(finalization.source_storage_key)+octet_length(finalization.source_version_id);expected_identity:=finalization.field_snapshot_sha256;
  ELSIF NEW.kind='output' THEN
   SELECT * INTO STRICT output FROM document_finalization_outputs WHERE preparation_id=finalization.id AND kind=NEW.member_kind AND page=NEW.page;
   expected_retained:=output.bytes+4096+octet_length(output.storage_key)+octet_length(output.content_type);expected_identity:=output.sha256;
  ELSIF NEW.kind='audit_input' THEN expected_retained:=octet_length(finalization.audit_snapshot_payload)+4096;expected_identity:=finalization.audit_snapshot_sha256;
  ELSE expected_retained:=octet_length(finalization.certificate_input_payload)+4096;expected_identity:=finalization.certificate_input_sha256;
  END IF;
 ELSE RAISE EXCEPTION 'signing resource inventory kind is invalid' USING ERRCODE='23514'; END IF;
 IF expected_identity IS NULL OR ROW(NEW.ceremony_epoch,NEW.identity_sha256,NEW.db_capacity_bytes,NEW.db_retained_bytes,NEW.provider_reserved_bytes,NEW.provider_reserved_objects)
   IS DISTINCT FROM ROW(epoch,expected_identity,expected_capacity,expected_retained,expected_provider,expected_objects) THEN
  RAISE EXCEPTION 'signing resource debit differs from derived inventory' USING ERRCODE='23514';
 END IF;
 -- Account application is deferred until the complete same-transaction tuple exists.
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_record_v1(org UUID,doc UUID,admission UUID,resource_kind TEXT,operation UUID,member TEXT,member_page INTEGER) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE a document_signing_admissions%ROWTYPE; p signature_fit_preparations%ROWTYPE; b document_signing_admission_bodies%ROWTYPE;
 orig signature_fit_original_payloads%ROWTYPE; au signature_fit_original_authorities%ROWTYPE; fp document_finalization_preparations%ROWTYPE; outrow document_finalization_outputs%ROWTYPE;
 capacity BIGINT:=0; retained BIGINT:=0; provider BIGINT:=0; objects BIGINT:=0; identity BYTEA; fit_capacity NUMERIC; fit_provider NUMERIC; fit_objects NUMERIC; slot_retained NUMERIC;
BEGIN
 SELECT * INTO STRICT a FROM document_signing_admissions WHERE id=admission AND org_id=org AND document_id=doc;
 IF resource_kind='candidate' THEN
  SELECT COALESCE(sum(hash_signing_resource_fit_db_v1(sl.fit_bytes_limit,sl.expected_objects)::numeric),0),COALESCE(sum(sl.fit_bytes_limit::numeric),0),COALESCE(sum(sl.expected_objects::numeric),0),COALESCE(sum((4096+16*sl.target_count+4*sl.page_count)::numeric),0) INTO fit_capacity,fit_provider,fit_objects,slot_retained FROM document_signing_admission_slots sl WHERE sl.admission_id=a.id;
  IF fit_capacity>1152921504606846976 OR fit_provider>1152921504606846976 OR fit_objects>1000000000 THEN RAISE EXCEPTION 'signing resource entitlement overflow' USING ERRCODE='23514'; END IF;
  retained:=hash_signing_resource_candidate_db_v1(a)+slot_retained::bigint;
  capacity:=retained+a.base_bytes_limit+LEAST(8388608::bigint,cardinality(a.expected_ordinary_pages)::bigint*1048576)+8192*cardinality(a.expected_ordinary_pages)::bigint+hash_signing_resource_common_db_v1(a)+fit_capacity::bigint;
  provider:=hash_signing_resource_common_provider_v1(a)+fit_provider::bigint;objects:=cardinality(a.expected_ordinary_pages)+5+fit_objects::bigint;identity:=a.static_basis_body_sha256;
 ELSIF resource_kind='ordinary' THEN SELECT * INTO STRICT b FROM document_signing_admission_bodies WHERE admission_id=a.id AND kind=member AND page=member_page;retained:=b.bytes+octet_length(b.plan_payload)+4096;identity:=digest(b.sha256||b.plan_sha256||b.package_sha256||b.report_sha256||b.inspection_sha256,'sha256');
 ELSIF resource_kind='fit' THEN
  SELECT * INTO STRICT p FROM signature_fit_preparations WHERE id=operation AND org_id=org AND document_id=doc;
  IF NOT EXISTS(SELECT 1 FROM signing_resource_fit_transfers tr WHERE tr.admission_id=a.id AND tr.recipient_id=p.recipient_id AND tr.preparation_id=p.id) THEN capacity:=hash_signing_resource_fit_db_v1(p.reserved_bytes,p.expected_objects);provider:=p.reserved_bytes;objects:=p.expected_objects;END IF;
  retained:=4096+octet_length(p.source_storage_key)+octet_length(p.source_version_id);identity:=p.authority_sha256;
 ELSIF resource_kind='authority' THEN SELECT * INTO STRICT au FROM signature_fit_original_authorities WHERE preparation_id=operation AND org_id=org AND document_id=doc;retained:=au.authority_bytes+4096+4*cardinality(au.occupied_pages);identity:=au.authority_sha256;
 ELSIF resource_kind='payload' THEN SELECT * INTO STRICT orig FROM signature_fit_original_payloads WHERE preparation_id=operation AND org_id=org AND document_id=doc AND kind=member AND page=member_page;retained:=orig.bytes+4096+octet_length(orig.storage_key)+octet_length(orig.content_type);identity:=orig.sha256;
 ELSE
  SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=operation AND org_id=org AND document_id=doc;
  IF resource_kind='finalization' THEN
   IF NOT EXISTS(SELECT 1 FROM signing_resource_finalization_transfers tr WHERE tr.admission_id=a.id AND tr.preparation_id=fp.id) THEN capacity:=hash_signing_resource_common_db_v1(a);provider:=hash_signing_resource_common_provider_v1(a);objects:=cardinality(a.expected_ordinary_pages)+5;END IF;
   retained:=4096+octet_length(fp.geometry_pages_payload)+octet_length(fp.field_snapshot_payload)+octet_length(fp.original_document_name)+octet_length(fp.source_storage_key)+octet_length(fp.source_version_id);identity:=fp.field_snapshot_sha256;
  ELSIF resource_kind='output' THEN SELECT * INTO STRICT outrow FROM document_finalization_outputs WHERE preparation_id=operation AND kind=member AND page=member_page;retained:=outrow.bytes+4096+octet_length(outrow.storage_key)+octet_length(outrow.content_type);identity:=outrow.sha256;
  ELSIF resource_kind='audit_input' THEN retained:=octet_length(fp.audit_snapshot_payload)+4096;identity:=fp.audit_snapshot_sha256;
  ELSIF resource_kind='certificate_input' THEN retained:=octet_length(fp.certificate_input_payload)+4096;identity:=fp.certificate_input_sha256;
  ELSE RAISE EXCEPTION 'signing resource kind unavailable' USING ERRCODE='23514';END IF;
 END IF;
 INSERT INTO signing_resource_debts(org_id,document_id,ceremony_epoch,admission_id,kind,operation_id,member_kind,page,identity_sha256,db_capacity_bytes,db_retained_bytes,provider_reserved_bytes,provider_reserved_objects)
 VALUES(org,doc,a.ceremony_epoch,a.id,resource_kind,operation,member,member_page,identity,capacity,retained,provider,objects);
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_after_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE org_value UUID;doc_value UUID;admission UUID; policy_value TEXT; source_preparation UUID; p signature_fit_preparations%ROWTYPE; fp document_finalization_preparations%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='signature_fit_objects' THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='document_finalization_outputs' THEN SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=NEW.preparation_id;org_value:=fp.org_id;doc_value:=fp.document_id;
 ELSE org_value:=NEW.org_id;doc_value:=NEW.document_id; END IF;
 SELECT signing_admission_policy INTO STRICT policy_value FROM documents WHERE id=doc_value AND org_id=org_value;
 IF policy_value='historical' THEN RETURN NEW; END IF;
 admission:=hash_signing_resource_entities_v1(org_value,doc_value);
 IF TG_TABLE_NAME='document_signing_admissions' THEN admission:=NEW.id;PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'candidate',NEW.id,'',0);
 ELSIF TG_TABLE_NAME='document_signing_admission_bodies' THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,NEW.admission_id,'ordinary',NEW.admission_id,NEW.kind,NEW.page);
 ELSIF TG_TABLE_NAME='signature_fit_preparations' THEN
  IF admission IS NULL THEN RAISE EXCEPTION 'signing resource preparation requires current static admission' USING ERRCODE='23514';END IF;
  -- The first logical prep conserves the ENTIRE unknown-name slot ceiling.
  -- Later preparations add their own immutable ceiling; old debt is not freed.
  INSERT INTO signing_resource_fit_transfers(admission_id,org_id,document_id,recipient_id,preparation_id)
   SELECT admission,org_value,doc_value,NEW.recipient_id,NEW.id WHERE NOT EXISTS(SELECT 1 FROM signing_resource_fit_transfers tr WHERE tr.admission_id=admission AND tr.recipient_id=NEW.recipient_id);
  PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'fit',NEW.id,'',0);
 ELSIF TG_TABLE_NAME IN('signature_fit_original_authorities','signature_fit_original_payloads') THEN
  SELECT debt.admission_id INTO STRICT admission FROM signing_resource_debts debt WHERE debt.org_id=org_value AND debt.document_id=doc_value AND debt.kind='fit' AND debt.operation_id=NEW.preparation_id;
  IF TG_TABLE_NAME='signature_fit_original_authorities' THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'authority',NEW.preparation_id,'',0);
  ELSE PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'payload',NEW.preparation_id,NEW.kind,NEW.page);END IF;
 ELSIF TG_TABLE_NAME='document_finalization_preparations' THEN
  IF TG_OP='INSERT' THEN
   INSERT INTO signing_resource_finalization_transfers(admission_id,org_id,document_id,preparation_id)
    SELECT admission,org_value,doc_value,NEW.id WHERE NOT EXISTS(SELECT 1 FROM signing_resource_finalization_transfers tr WHERE tr.admission_id=admission);
   PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'finalization',NEW.id,'',0);
  ELSE SELECT debt.admission_id INTO STRICT admission FROM signing_resource_debts debt WHERE debt.org_id=org_value AND debt.document_id=doc_value AND debt.kind='finalization' AND debt.operation_id=NEW.id;END IF;
  IF NEW.audit_snapshot_payload IS NOT NULL AND (TG_OP='INSERT' OR OLD.audit_snapshot_payload IS NULL) THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'audit_input',NEW.id,'',0);END IF;
  IF NEW.certificate_input_payload IS NOT NULL AND (TG_OP='INSERT' OR OLD.certificate_input_payload IS NULL) THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'certificate_input',NEW.id,'',0);END IF;
 ELSIF TG_TABLE_NAME='document_finalization_outputs' THEN
  SELECT debt.admission_id INTO STRICT admission FROM signing_resource_debts debt WHERE debt.org_id=org_value AND debt.document_id=doc_value AND debt.kind='finalization' AND debt.operation_id=NEW.preparation_id;
  PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'output',NEW.preparation_id,NEW.kind,NEW.page);
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_pair_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE org_value UUID;doc_value UUID;operation UUID;member TEXT:='';member_page INTEGER:=0;resource_kind TEXT;admission UUID;
 p signature_fit_preparations%ROWTYPE;fp document_finalization_preparations%ROWTYPE;debt signing_resource_debts%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='signing_resource_fit_transfers' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='fit';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='signing_resource_finalization_transfers' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='finalization';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='signing_resource_debts' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.operation_id;member:=NEW.member_kind;member_page:=NEW.page;resource_kind:=NEW.kind;admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='document_signing_admissions' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.id;resource_kind:='candidate';admission:=NEW.id;
 ELSIF TG_TABLE_NAME='document_signing_admission_bodies' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.admission_id;member:=NEW.kind;member_page:=NEW.page;resource_kind:='ordinary';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='signature_fit_preparations' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.id;resource_kind:='fit';
 ELSIF TG_TABLE_NAME='signature_fit_original_authorities' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='authority';
 ELSIF TG_TABLE_NAME='signature_fit_original_payloads' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;member:=NEW.kind;member_page:=NEW.page;resource_kind:='payload';
 ELSIF TG_TABLE_NAME='document_finalization_preparations' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.id;resource_kind:='finalization';
 ELSIF TG_TABLE_NAME='document_finalization_outputs' THEN SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=NEW.preparation_id;org_value:=fp.org_id;doc_value:=fp.document_id;operation:=fp.id;member:=NEW.kind;member_page:=NEW.page;resource_kind:='output';
 ELSE RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM documents WHERE id=doc_value AND org_id=org_value AND signing_admission_policy='pdf-static-v1') THEN RETURN NULL;END IF;
 SELECT * INTO STRICT debt FROM signing_resource_debts WHERE org_id=org_value AND document_id=doc_value AND kind=resource_kind AND operation_id=operation AND member_kind=member AND page=member_page;
 IF admission IS NOT NULL AND debt.admission_id<>admission THEN RAISE EXCEPTION 'signing resource source/receipt admission differs' USING ERRCODE='23514';END IF;
 IF resource_kind IN('fit','authority','payload') THEN
  SELECT * INTO STRICT p FROM signature_fit_preparations WHERE id=operation AND org_id=org_value AND document_id=doc_value;
  IF NOT EXISTS(SELECT 1 FROM signature_fit_original_authorities oa WHERE oa.preparation_id=p.id AND oa.org_id=p.org_id AND oa.document_id=p.document_id AND oa.authority_sha256=p.authority_sha256)
   OR NOT EXISTS(SELECT 1 FROM signature_fit_original_payloads os WHERE os.preparation_id=p.id AND os.kind='span' AND os.page=0 AND os.sha256=p.span_sha256)
   OR NOT EXISTS(SELECT 1 FROM document_signing_admission_slots sl WHERE sl.admission_id=debt.admission_id AND sl.org_id=p.org_id AND sl.document_id=p.document_id AND sl.recipient_id=p.recipient_id AND sl.designated_preparation_id=p.id AND sl.designated_owner_id=p.owner_id) THEN
   RAISE EXCEPTION 'signing resource fit reservation requires atomic85/87/88 tuple' USING ERRCODE='23514';
  END IF;
 END IF;
 IF resource_kind='finalization' THEN
  SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=operation;
  IF fp.audit_snapshot_payload IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signing_resource_debts WHERE org_id=org_value AND document_id=doc_value AND kind='audit_input' AND operation_id=operation AND member_kind='' AND page=0)
   OR fp.certificate_input_payload IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signing_resource_debts WHERE org_id=org_value AND document_id=doc_value AND kind='certificate_input' AND operation_id=operation AND member_kind='' AND page=0) THEN
   RAISE EXCEPTION 'signing resource final input lacks retained debt' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NULL;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION 'signing resource inventory lacks exact debt receipt' USING ERRCODE='23514';
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_snapshot_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE rows_count BIGINT; docs_count BIGINT; db_total NUMERIC; provider_total NUMERIC; objects_total NUMERIC; fingerprint BYTEA;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NEW.verification_state<>'pending' OR NOT NEW.unknown_provider_debt THEN
  RAISE EXCEPTION 'signing resource staged snapshot is not verification' USING ERRCODE='23514';
 END IF;
 -- Take the serialized metadata snapshot ourselves, including direct SQL.
 -- Admission/collector resources MUST be held before dispatch. No provider I/O
 -- occurs under locks; active writers make staging refuse rather than wait.
 LOCK TABLE documents,document_signing_admissions,document_signing_admission_bodies,document_signing_admission_slots,signature_signing_admission_bindings,signature_fit_preparations,signature_fit_objects,signature_fit_selections,signature_fit_companions,signature_fit_original_authorities,signature_fit_original_payloads,document_finalization_preparations,document_finalization_outputs,document_finalization_references IN SHARE MODE NOWAIT;
 PERFORM 1 FROM signing_resource_control WHERE singleton FOR UPDATE NOWAIT;
  IF (SELECT count(*) FROM signing_resource_inventory_snapshots)>=8 THEN
  RAISE EXCEPTION 'signing resource staged snapshot inventory full' USING ERRCODE='23514';
 END IF;

 IF NEW.captured_transaction_id IS DISTINCT FROM pg_current_xact_id() THEN RAISE EXCEPTION 'signing resource snapshot transaction differs' USING ERRCODE='23514'; END IF;
 SELECT count(*),count(DISTINCT document_id) INTO rows_count,docs_count FROM signing_resource_current_inventory_v1;
 IF rows_count>65536 OR docs_count>4096 THEN RAISE EXCEPTION 'signing resource inventory exceeds staged profile' USING ERRCODE='23514'; END IF;
 SELECT COALESCE(sum(db_bytes::numeric),0),COALESCE(sum(provider_bytes::numeric),0),COALESCE(sum(provider_objects::numeric),0),
  digest(convert_to(COALESCE(string_agg(org_id::text||'/'||document_id::text||'/'||kind||'/'||operation_id::text||'/'||member_kind||'/'||page::text||'/'||encode(identity_sha256,'hex')||'/'||db_bytes::text||'/'||provider_bytes::text||'/'||provider_objects::text,E'\n' ORDER BY org_id,document_id,kind,operation_id,member_kind,page),''),'UTF8'),'sha256')
 INTO db_total,provider_total,objects_total,fingerprint FROM signing_resource_current_inventory_v1;
 IF db_total>1152921504606846976 OR provider_total>1152921504606846976 OR objects_total>1000000000 OR
  ROW(NEW.entry_count,NEW.document_count,NEW.known_db_bytes,NEW.known_provider_bytes,NEW.known_provider_objects,NEW.inventory_sha256)
  IS DISTINCT FROM ROW(rows_count,docs_count,db_total::bigint,provider_total::bigint,objects_total::bigint,fingerprint) THEN
  RAISE EXCEPTION 'signing resource snapshot differs from exact scoped inventory' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION hash_signing_resource_stage_inventory_v1(snapshot_id UUID,receipt_id UUID,receipt_key TEXT,receipt_version TEXT,receipt_sha BYTEA,receipt_size BIGINT)
RETURNS signing_resource_inventory_snapshots LANGUAGE plpgsql AS $$
DECLARE n BIGINT; docs BIGINT; db_amount NUMERIC; provider_amount NUMERIC; object_amount NUMERIC; sha BYTEA; result signing_resource_inventory_snapshots%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'signing resource staging requires read committed' USING ERRCODE='23514';END IF;
 LOCK TABLE documents,document_signing_admissions,document_signing_admission_bodies,document_signing_admission_slots,signature_signing_admission_bindings,signature_fit_preparations,signature_fit_objects,signature_fit_selections,signature_fit_companions,signature_fit_original_authorities,signature_fit_original_payloads,document_finalization_preparations,document_finalization_outputs,document_finalization_references IN SHARE MODE NOWAIT;
 SELECT count(*),count(DISTINCT document_id) INTO n,docs FROM signing_resource_current_inventory_v1;
 IF n>65536 OR docs>4096 THEN RAISE EXCEPTION 'signing resource inventory exceeds staged profile' USING ERRCODE='23514';END IF;
 SELECT COALESCE(sum(db_bytes::numeric),0),COALESCE(sum(provider_bytes::numeric),0),COALESCE(sum(provider_objects::numeric),0),
 digest(convert_to(COALESCE(string_agg(org_id::text||'/'||document_id::text||'/'||kind||'/'||operation_id::text||'/'||member_kind||'/'||page::text||'/'||encode(identity_sha256,'hex')||'/'||db_bytes::text||'/'||provider_bytes::text||'/'||provider_objects::text,E'\n' ORDER BY org_id,document_id,kind,operation_id,member_kind,page),''),'UTF8'),'sha256')
 INTO db_amount,provider_amount,object_amount,sha FROM signing_resource_current_inventory_v1;
 IF db_amount>1152921504606846976 OR provider_amount>1152921504606846976 OR object_amount>1000000000 THEN RAISE EXCEPTION 'signing resource inventory overflow' USING ERRCODE='23514';END IF;
 INSERT INTO signing_resource_inventory_snapshots(id,inventory_sha256,entry_count,document_count,known_db_bytes,known_provider_bytes,known_provider_objects,controller_receipt_id,receipt_storage_key,receipt_version_id,receipt_sha256,receipt_bytes)
 VALUES(snapshot_id,sha,n,docs,db_amount::bigint,provider_amount::bigint,object_amount::bigint,receipt_id,receipt_key,receipt_version,receipt_sha,receipt_size) RETURNING * INTO result;
 INSERT INTO signing_resource_inventory_entries(snapshot_id,org_id,document_id,ceremony_epoch,kind,operation_id,member_kind,page,identity_sha256,db_bytes,provider_bytes,provider_objects)
 SELECT result.id,inv.org_id,inv.document_id,inv.ceremony_epoch,inv.kind,inv.operation_id,inv.member_kind,inv.page,inv.identity_sha256,inv.db_bytes,inv.provider_bytes,inv.provider_objects FROM signing_resource_current_inventory_v1 inv;
 RETURN result;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'signing resource inventory is busy' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE OR REPLACE VIEW signing_resource_current_inventory_v1 AS
SELECT d.org_id,d.id AS document_id,d.sent_at AS ceremony_epoch,'document'::text AS kind,d.id AS operation_id,''::text AS member_kind,0::integer AS page,
 digest(convert_to(jsonb_build_array(d.id,d.org_id,d.status,d.signing_admission_policy,d.signing_admission_active_id,d.signing_admission_sealed_id,d.pdf_storage_key,d.pdf_storage_version_id,encode(d.pdf_sha256,'hex'),hash_article13_canonical_sent_at(d.sent_at),d.deleted_at IS NOT NULL)::text,'UTF8'),'sha256') AS identity_sha256,
 (4096+octet_length(d.name)+COALESCE(octet_length(d.pdf_storage_key),0)+COALESCE(octet_length(d.pdf_storage_version_id),0))::bigint AS db_bytes,0::bigint AS provider_bytes,0::bigint AS provider_objects
FROM documents d WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT a.org_id,a.document_id,a.ceremony_epoch,'candidate',a.id,'',0,
 digest(convert_to(jsonb_build_array(a.id,encode(a.static_basis_sha256,'hex'),encode(a.static_basis_body_sha256,'hex'),encode(a.geometry_sha256,'hex'),encode(a.fields_sha256,'hex'),encode(a.parties_sha256,'hex'),encode(a.render_recipe_sha256,'hex'),a.status,a.owner_id,hash_article13_canonical_sent_at(a.lease_until),a.attempts)::text,'UTF8'),'sha256'),
 (octet_length(a.static_basis_payload)::bigint+octet_length(a.geometry_payload)+octet_length(a.geometry_pages_payload)+octet_length(a.fields_payload)+octet_length(a.parties_payload)+octet_length(a.render_recipe_payload)+octet_length(a.ordinary_recipe_payload)+octet_length(a.original_document_name)+octet_length(a.source_storage_key)+octet_length(a.source_version_id)+4096),(a.base_bytes_limit+a.final_pdf_bytes_limit+a.fits_index_bytes_limit+a.certificate_pdf_bytes_limit+a.certificate_payload_bytes_limit+a.certificate_signature_bytes_limit)::bigint,(cardinality(a.expected_ordinary_pages)+5)::bigint
FROM document_signing_admissions a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT b.org_id,b.document_id,a.ceremony_epoch,'ordinary',b.admission_id,b.kind,b.page,
 digest(convert_to(jsonb_build_array(b.page,encode(b.sha256,'hex'),b.bytes,encode(b.plan_sha256,'hex'),octet_length(b.plan_payload),encode(b.package_sha256,'hex'),encode(b.report_sha256,'hex'),encode(b.inspection_sha256,'hex'),b.captured_owner_id)::text,'UTF8'),'sha256'),
 (b.bytes+octet_length(b.plan_payload)+4096)::bigint,0::bigint,0::bigint
FROM document_signing_admission_bodies b JOIN document_signing_admissions a ON a.id=b.admission_id JOIN documents d ON d.id=b.document_id AND d.org_id=b.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'fit',p.id,'',0,
 digest(convert_to(jsonb_build_array(p.id,p.recipient_id,encode(p.authority_sha256,'hex'),p.source_storage_key,p.source_version_id,encode(p.source_sha256,'hex'),p.source_bytes,encode(p.geometry_sha256,'hex'),encode(p.span_sha256,'hex'),p.reserved_bytes,p.expected_objects,p.status,p.owner_id,hash_article13_canonical_sent_at(p.lease_until),p.attempts,p.selection_commit_attempted_at IS NOT NULL,p.selection_not_committed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(p.source_storage_key)+octet_length(p.source_version_id))::bigint,p.reserved_bytes,p.expected_objects::bigint
FROM signature_fit_preparations p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'fit_object',p.id,o.kind,o.page,
 digest(convert_to(jsonb_build_array(o.kind,o.page,o.storage_key,encode(o.sha256,'hex'),o.bytes,o.content_type,o.version_id,o.upload_attempted_at IS NOT NULL,o.readback_verified_at IS NOT NULL,o.cleanup_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(o.storage_key)+octet_length(o.content_type)+COALESCE(octet_length(o.version_id),0))::bigint,0::bigint,0::bigint
FROM signature_fit_objects o JOIN signature_fit_preparations p ON p.id=o.preparation_id JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT a.org_id,a.document_id,a.ceremony_epoch,'authority',a.preparation_id,'',0,a.authority_sha256,(a.authority_bytes+4096+4*cardinality(a.occupied_pages))::bigint,0::bigint,0::bigint
FROM signature_fit_original_authorities a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT b.org_id,b.document_id,a.ceremony_epoch,'payload',b.preparation_id,b.kind,b.page,
 digest(convert_to(jsonb_build_array(b.kind,b.page,b.storage_key,encode(b.sha256,'hex'),b.bytes,b.content_type,b.captured_owner_id)::text,'UTF8'),'sha256'),(b.bytes+4096+octet_length(b.storage_key)+octet_length(b.content_type))::bigint,0::bigint,0::bigint
FROM signature_fit_original_payloads b JOIN signature_fit_original_authorities a ON a.preparation_id=b.preparation_id JOIN documents d ON d.id=b.document_id AND d.org_id=b.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'finalization',p.id,'',0,
 digest(convert_to(jsonb_build_array(p.id,encode(p.source_sha256,'hex'),p.source_version_id,encode(p.geometry_sha256,'hex'),encode(p.field_snapshot_sha256,'hex'),hash_article13_canonical_sent_at(p.completion_effective_at),p.status,p.expected_outputs,p.expected_references,encode(p.audit_snapshot_sha256,'hex'),encode(p.certificate_input_sha256,'hex'),p.publication_commit_attempted_at IS NOT NULL,p.published_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(p.geometry_pages_payload)+octet_length(p.field_snapshot_payload)+octet_length(p.original_document_name)+octet_length(p.source_storage_key)+octet_length(p.source_version_id)+COALESCE(octet_length(p.audit_snapshot_payload),0)+COALESCE(octet_length(p.certificate_input_payload),0))::bigint,
 (p.base_bytes_limit+p.final_pdf_bytes_limit+p.fits_index_bytes_limit+p.certificate_pdf_bytes_limit+p.certificate_payload_bytes_limit+p.certificate_signature_bytes_limit)::bigint,p.expected_outputs::bigint
FROM document_finalization_preparations p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'output',p.id,o.kind,o.page,
 digest(convert_to(jsonb_build_array(o.kind,o.page,o.storage_key,encode(o.sha256,'hex'),o.bytes,o.content_type,o.version_id,o.upload_attempted_at IS NOT NULL,o.readback_verified_at IS NOT NULL,o.retention_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (o.bytes+4096+octet_length(o.storage_key)+octet_length(o.content_type)+COALESCE(octet_length(o.version_id),0))::bigint,0::bigint,0::bigint
FROM document_finalization_outputs o JOIN document_finalization_preparations p ON p.id=o.preparation_id JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT sl.org_id,sl.document_id,a.ceremony_epoch,'slot',sl.admission_id,sl.recipient_id::text,0,
 digest(convert_to(jsonb_build_array(sl.recipient_id,sl.target_ids,sl.occupied_pages,sl.expected_objects,sl.fit_bytes_limit,sl.pdf_bytes_limit,sl.designated_preparation_id,sl.designated_owner_id)::text,'UTF8'),'sha256'),
 (4096+16*sl.target_count+4*sl.page_count)::bigint,sl.fit_bytes_limit,sl.expected_objects::bigint
FROM document_signing_admission_slots sl JOIN document_signing_admissions a ON a.id=sl.admission_id JOIN documents d ON d.id=sl.document_id AND d.org_id=sl.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT se.org_id,se.document_id,se.ceremony_epoch,'selection',se.id,'',0,
 digest(convert_to(jsonb_build_array(se.id,se.preparation_id,se.recipient_id,encode(se.authority_sha256,'hex'),se.span_storage_key,se.span_version_id,encode(se.span_sha256,'hex'),se.span_bytes,se.manifest_storage_key,se.manifest_version_id,encode(se.manifest_sha256,'hex'),se.manifest_bytes,hash_article13_canonical_sent_at(se.retain_until),se.retention_started_at IS NOT NULL,se.retention_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(se.source_storage_key)+octet_length(se.source_version_id)+octet_length(se.span_storage_key)+octet_length(se.span_version_id)+octet_length(se.manifest_storage_key)+octet_length(se.manifest_version_id))::bigint,0::bigint,0::bigint
FROM signature_fit_selections se JOIN documents d ON d.id=se.document_id AND d.org_id=se.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT co.org_id,co.document_id,d.sent_at,'companion',co.signature_id,'',0,
 digest(convert_to(jsonb_build_array(co.signature_id,co.recipient_id,co.field_id,co.selection_id,encode(co.span_sha256,'hex'))::text,'UTF8'),'sha256'),4096::bigint,0::bigint,0::bigint
FROM signature_fit_companions co JOIN documents d ON d.id=co.document_id AND d.org_id=co.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT bi.org_id,bi.document_id,a.ceremony_epoch,'binding',bi.signature_id,'',0,
 digest(convert_to(jsonb_build_array(bi.signature_id,bi.admission_id,bi.recipient_id,bi.field_id,bi.selection_id,bi.signed_event_id,encode(bi.static_basis_sha256,'hex'),encode(bi.reviewed_basis_sha256,'hex'))::text,'UTF8'),'sha256'),4096::bigint,0::bigint,0::bigint
FROM signature_signing_admission_bindings bi JOIN document_signing_admissions a ON a.id=bi.admission_id JOIN documents d ON d.id=bi.document_id AND d.org_id=bi.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'reference',p.id,r.kind||'/'||r.owner_key::text,r.page,
 digest(convert_to(jsonb_build_array(r.kind,r.owner_key,r.signature_id,r.selection_id,r.page,r.storage_key,r.version_id,encode(r.sha256,'hex'),r.bytes,r.content_type,r.retention_started_at IS NOT NULL,r.retention_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(r.storage_key)+octet_length(r.version_id)+octet_length(r.content_type))::bigint,0::bigint,0::bigint
FROM document_finalization_references r JOIN document_finalization_preparations p ON p.id=r.preparation_id JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1';
ALTER TABLE signing_resource_debts DROP CONSTRAINT signing_resource_debts_kind_check;
ALTER TABLE signing_resource_debts ADD CONSTRAINT signing_resource_debts_kind_check CHECK(kind IN('candidate','ordinary','fit','authority','payload','finalization','output','audit_input','certificate_input'));
DROP FUNCTION hash_signature_fit_reserve_bound_request_v1(UUID,UUID,UUID,UUID,BYTEA,UUID,TIMESTAMPTZ,BYTEA,BYTEA,BYTEA,BYTEA);
DROP FUNCTION hash_signing_resource_request_db_v1(signature_fit_request_bindings);
DROP FUNCTION hash_signature_fit_request_selection_gate_v1();
DROP FUNCTION hash_signature_fit_request_slot_guard_v1();
DROP FUNCTION hash_signature_fit_request_budget_v1();
DROP FUNCTION hash_signature_fit_request_binding_guard_v1();
DROP FUNCTION hash_signature_fit_request_payloads_match_v1(signature_fit_request_bindings,documents,recipients,document_lawful_basis_confirmations,orgs,signature_fit_original_authorities);
DROP FUNCTION hash_signature_fit_request_identity_v1(signature_fit_request_bindings);
DROP FUNCTION hash_signature_fit_request_birth_v1();
DROP FUNCTION hash_signature_fit_request_json_unique_v1(BYTEA);
DROP FUNCTION hash_signature_fit_request_finite_v1(TIMESTAMPTZ);
DROP FUNCTION hash_signature_fit_request_trim_v1(TEXT);
DROP FUNCTION hash_signature_fit_request_text_commitment_v1(TEXT);
DROP FUNCTION hash_signature_fit_request_uuid_v1(UUID);
DROP FUNCTION hash_signature_fit_request_stamp_v1(TIMESTAMPTZ);
DROP TABLE signature_fit_request_bindings;
ALTER TABLE signature_fit_preparations DROP COLUMN request_binding_creation_xid;
ALTER TABLE documents DROP COLUMN signature_fit_request_binding_bytes,DROP COLUMN signature_fit_request_binding_count;
