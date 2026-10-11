-- +goose Up
-- Atomic delegated execution persistence only; no route/dispatch is enabled.
-- Manual signatures and source1/2/3 canonical evidence are not rewritten.
ALTER TABLE signatures ADD COLUMN signature_kind TEXT NOT NULL DEFAULT 'manual'
 CHECK (signature_kind IN ('manual','delegated_grant_v1'));
ALTER TABLE signatures ADD COLUMN presign_execution_id UUID;
ALTER TABLE signatures ADD CONSTRAINT signatures_presign_kind_pair CHECK (
 (signature_kind='manual' AND presign_execution_id IS NULL)
 OR (signature_kind='delegated_grant_v1' AND presign_execution_id IS NOT NULL
     AND signer_ip IS NULL AND signer_ua IS NULL AND image_version_pin_required
     AND image_version_id IS NOT NULL));
ALTER TABLE signatures ADD CONSTRAINT signatures_presign_identity UNIQUE(id,document_id,recipient_id,field_id);
ALTER TABLE send_sealing_intents ADD COLUMN presign_execution_id UUID;

CREATE TABLE presign_executions (
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 id UUID NOT NULL CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 document_id UUID NOT NULL UNIQUE,
 grant_id UUID NOT NULL, grant_revision BIGINT NOT NULL,
 grant_sha256 BYTEA NOT NULL CHECK(octet_length(grant_sha256)=32),
 policy_id UUID NOT NULL, policy_revision BIGINT NOT NULL,
 policy_sha256 BYTEA NOT NULL CHECK(octet_length(policy_sha256)=32),
 executor_kind TEXT NOT NULL CHECK(executor_kind IN ('member','api_key')),
 executor_user_id UUID NOT NULL CHECK(executor_user_id<>'00000000-0000-0000-0000-000000000000'),
 executor_credential_id UUID NOT NULL,
 request_id UUID NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
 command_canonical BYTEA NOT NULL CHECK(octet_length(command_canonical) BETWEEN 1 AND 65536),
 command_sha256 BYTEA NOT NULL CHECK(octet_length(command_sha256)=32),
 original_credential_sha256 BYTEA NOT NULL CHECK(octet_length(original_credential_sha256)=32),
 canonical_execution BYTEA NOT NULL CHECK(octet_length(canonical_execution) BETWEEN 1 AND 65536),
 execution_sha256 BYTEA NOT NULL CHECK(octet_length(execution_sha256)=32),
 admission_canonical BYTEA NOT NULL CHECK(octet_length(admission_canonical) BETWEEN 1 AND 262144),
 admission_sha256 BYTEA NOT NULL CHECK(octet_length(admission_sha256)=32),
 audit_event_id UUID NOT NULL UNIQUE REFERENCES events(id) ON DELETE RESTRICT,
 signature_id UUID NOT NULL UNIQUE,
 provider_recipient_id UUID NOT NULL, provider_field_id UUID NOT NULL,
 materialization_id UUID NOT NULL,
 source_commitment BYTEA NOT NULL CHECK(octet_length(source_commitment)=32),
 ceremony_epoch TIMESTAMPTZ NOT NULL CHECK(isfinite(ceremony_epoch)),
 executed_at TIMESTAMPTZ NOT NULL CHECK(isfinite(executed_at)),
 use_number BIGINT NOT NULL CHECK(use_number BETWEEN 1 AND 1000000),
 PRIMARY KEY(org_id,id), UNIQUE(id),
 UNIQUE(org_id,id,document_id),
 UNIQUE(id,document_id,signature_id),
 UNIQUE(org_id,id,grant_id,grant_revision,use_number,execution_sha256),
 UNIQUE(org_id,executor_kind,executor_user_id,executor_credential_id,request_id,id,execution_sha256),
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(org_id,grant_id,grant_revision) REFERENCES presign_grant_revisions(org_id,grant_id,revision) ON DELETE RESTRICT,
 FOREIGN KEY(org_id,policy_id,policy_revision) REFERENCES presign_workflow_revisions(org_id,policy_id,revision) ON DELETE RESTRICT,
 FOREIGN KEY(materialization_id,document_id,org_id,source_commitment)
  REFERENCES html_document_materializations(id,document_id,org_id,source_commitment) ON DELETE RESTRICT,
 FOREIGN KEY(signature_id,document_id,provider_recipient_id,provider_field_id)
  REFERENCES signatures(id,document_id,recipient_id,field_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK((executor_kind='member' AND executor_credential_id='00000000-0000-0000-0000-000000000000')
  OR (executor_kind='api_key' AND executor_credential_id<>'00000000-0000-0000-0000-000000000000'))
);
CREATE TABLE presign_execution_uses (
 org_id UUID NOT NULL, grant_id UUID NOT NULL, grant_revision BIGINT NOT NULL,
 use_number BIGINT NOT NULL CHECK(use_number BETWEEN 1 AND 1000000),
 execution_id UUID NOT NULL UNIQUE,
 execution_sha256 BYTEA NOT NULL CHECK(octet_length(execution_sha256)=32),
 PRIMARY KEY(org_id,grant_id,grant_revision,use_number),
 UNIQUE(org_id,execution_id,grant_id,grant_revision,use_number,execution_sha256),
 FOREIGN KEY(org_id,execution_id,grant_id,grant_revision,use_number,execution_sha256)
  REFERENCES presign_executions(org_id,id,grant_id,grant_revision,use_number,execution_sha256) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE presign_executions ADD CONSTRAINT presign_execution_exact_use
 FOREIGN KEY(org_id,id,grant_id,grant_revision,use_number,execution_sha256)
 REFERENCES presign_execution_uses(org_id,execution_id,grant_id,grant_revision,use_number,execution_sha256) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE presign_execution_requests (
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 executor_kind TEXT NOT NULL CHECK(executor_kind IN ('member','api_key')),
 executor_user_id UUID NOT NULL CHECK(executor_user_id<>'00000000-0000-0000-0000-000000000000'),
 executor_credential_id UUID NOT NULL,
 request_id UUID NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
 state TEXT NOT NULL CHECK(state IN ('committed','closed')),
 execution_id UUID, execution_sha256 BYTEA,
 command_canonical BYTEA, command_sha256 BYTEA,
 original_credential_sha256 BYTEA NOT NULL CHECK(octet_length(original_credential_sha256)=32),
 audit_event_id UUID NOT NULL UNIQUE REFERENCES events(id) ON DELETE RESTRICT,
 occurred_at TIMESTAMPTZ NOT NULL CHECK(isfinite(occurred_at)),
 PRIMARY KEY(org_id,executor_kind,executor_user_id,executor_credential_id,request_id),
 UNIQUE(org_id,executor_kind,executor_user_id,executor_credential_id,request_id,execution_id,execution_sha256),
 FOREIGN KEY(org_id,execution_id) REFERENCES presign_executions(org_id,id) DEFERRABLE INITIALLY DEFERRED,
 CHECK((executor_kind='member' AND executor_credential_id='00000000-0000-0000-0000-000000000000')
  OR (executor_kind='api_key' AND executor_credential_id<>'00000000-0000-0000-0000-000000000000')),
 CHECK((state='closed' AND execution_id IS NULL AND execution_sha256 IS NULL AND command_canonical IS NULL AND command_sha256 IS NULL)
  OR (state='committed' AND execution_id IS NOT NULL AND execution_sha256 IS NOT NULL AND octet_length(execution_sha256)=32
      AND command_canonical IS NOT NULL AND octet_length(command_canonical) BETWEEN 1 AND 65536
      AND command_sha256 IS NOT NULL AND octet_length(command_sha256)=32))
);
ALTER TABLE presign_executions ADD CONSTRAINT presign_execution_exact_request
 FOREIGN KEY(org_id,executor_kind,executor_user_id,executor_credential_id,request_id,id,execution_sha256)
 REFERENCES presign_execution_requests(org_id,executor_kind,executor_user_id,executor_credential_id,request_id,execution_id,execution_sha256) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE signatures ADD CONSTRAINT signature_presign_execution
 FOREIGN KEY(presign_execution_id,document_id,id) REFERENCES presign_executions(id,document_id,signature_id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE send_sealing_intents ADD CONSTRAINT sealing_presign_execution
 FOREIGN KEY(org_id,presign_execution_id,document_id) REFERENCES presign_executions(org_id,id,document_id) DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX presign_execution_actor_requests ON presign_executions(org_id,executor_user_id,request_id);

CREATE TRIGGER presign_executions_immutable BEFORE UPDATE OR DELETE ON presign_executions FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();
CREATE TRIGGER presign_execution_uses_immutable BEFORE UPDATE OR DELETE ON presign_execution_uses FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();
CREATE TRIGGER presign_execution_requests_immutable BEFORE UPDATE OR DELETE ON presign_execution_requests FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_execution_insert() RETURNS trigger AS $$
DECLARE g presign_grants%ROWTYPE; gr presign_grant_revisions%ROWTYPE;
        p presign_workflow_revisions%ROWTYPE; d documents%ROWTYPE; x JSONB; c JSONB;
        grantor UUID; principal RECORD; a JSONB;
BEGIN
 x:=convert_from(NEW.canonical_execution,'UTF8')::jsonb;
 c:=convert_from(NEW.command_canonical,'UTF8')::jsonb;
 a:=convert_from(NEW.admission_canonical,'UTF8')::jsonb;
 IF sha256(convert_to('hash:presign-execution:v1','UTF8')||decode('00','hex')||NEW.canonical_execution) IS DISTINCT FROM NEW.execution_sha256
    OR sha256(convert_to('hash:presign-execution-command:v1','UTF8')||decode('00','hex')||NEW.command_canonical) IS DISTINCT FROM NEW.command_sha256
    OR sha256(convert_to('hash:presign-data-admission:v1','UTF8')||decode('00','hex')||NEW.admission_canonical) IS DISTINCT FROM NEW.admission_sha256
    OR x->>'schema_version' IS DISTINCT FROM '1'
    OR x->>'id' IS DISTINCT FROM NEW.id::text OR x->>'org_id' IS DISTINCT FROM NEW.org_id::text
    OR x->'document'->>'id' IS DISTINCT FROM NEW.document_id::text
    OR x->'document'->>'org_id' IS DISTINCT FROM NEW.org_id::text
    OR x->'grant'->>'id' IS DISTINCT FROM NEW.grant_id::text
    OR x->'grant'->>'revision' IS DISTINCT FROM NEW.grant_revision::text
    OR x->'grant'->>'sha256' IS DISTINCT FROM encode(NEW.grant_sha256,'hex')
    OR x->'policy'->>'id' IS DISTINCT FROM NEW.policy_id::text
    OR x->'policy'->>'revision' IS DISTINCT FROM NEW.policy_revision::text
    OR x->'policy'->>'sha256' IS DISTINCT FROM encode(NEW.policy_sha256,'hex')
    OR x->'executor' IS DISTINCT FROM jsonb_build_object('kind',NEW.executor_kind,'user_id',NEW.executor_user_id,'credential_id',NEW.executor_credential_id)
    OR x->'signature'->>'id' IS DISTINCT FROM NEW.signature_id::text
    OR x->'signature'->>'recipient_id' IS DISTINCT FROM NEW.provider_recipient_id::text
    OR x->'signature'->>'field_id' IS DISTINCT FROM NEW.provider_field_id::text
    OR x->'document'->'materialization'->>'id' IS DISTINCT FROM NEW.materialization_id::text
    OR x->'document'->'materialization'->>'source_commitment' IS DISTINCT FROM encode(NEW.source_commitment,'hex')
    OR x->'document'->>'data_evidence_sha256' IS DISTINCT FROM encode(NEW.admission_sha256,'hex')
    OR a->>'version' IS DISTINCT FROM '1' OR a->>'org_id' IS DISTINCT FROM NEW.org_id::text
    OR a->>'document_id' IS DISTINCT FROM NEW.document_id::text
    OR a->>'sender_id' IS DISTINCT FROM x->'document'->>'sender_id'
    OR a->>'policy_id' IS DISTINCT FROM NEW.policy_id::text
    OR a->>'source_commitment' IS DISTINCT FROM encode(NEW.source_commitment,'hex')
    OR a->'template' IS DISTINCT FROM x->'document'->'template'
    OR a->>'values_sha256' IS DISTINCT FROM x->'document'->>'values_sha256'
    OR a->>'sections_sha256' IS DISTINCT FROM x->'document'->>'sections_sha256'
    OR a->>'review_evidence_sha256' IS DISTINCT FROM x->'document'->>'review_evidence_sha256'
    OR jsonb_typeof(a->'valid_until') IS DISTINCT FROM 'string'
    OR NOT isfinite((a->>'valid_until')::timestamptz)
    OR (x->>'ceremony_epoch')::timestamptz IS DISTINCT FROM NEW.ceremony_epoch
    OR (x->>'executed_at')::timestamptz IS DISTINCT FROM NEW.executed_at
    OR x->>'use_number' IS DISTINCT FROM NEW.use_number::text
    OR c->>'schema_version' IS DISTINCT FROM '1' OR c->>'org_id' IS DISTINCT FROM NEW.org_id::text
    OR c->>'request_id' IS DISTINCT FROM NEW.request_id::text
    OR c->>'document_id' IS DISTINCT FROM NEW.document_id::text OR c->'executor' IS DISTINCT FROM x->'executor'
    OR c->'document' IS DISTINCT FROM x->'document'
    OR c->'grant' IS DISTINCT FROM x->'grant' OR c->'policy' IS DISTINCT FROM x->'policy'
    OR c->>'source_commitment' IS DISTINCT FROM encode(NEW.source_commitment,'hex')
    OR c->>'admission_sha256' IS DISTINCT FROM encode(NEW.admission_sha256,'hex')
    OR c->>'original_credential_sha256' IS DISTINCT FROM encode(NEW.original_credential_sha256,'hex') THEN
  RAISE EXCEPTION 'delegated execution canonical tuple is inconsistent' USING ERRCODE='23514';
 END IF;
 SELECT grantor_user_id INTO STRICT grantor FROM presign_grants WHERE org_id=NEW.org_id AND id=NEW.grant_id;
 -- Users before grant-head matches the sticky user-transition trigger's order.
 FOR principal IN SELECT * FROM users WHERE org_id=NEW.org_id AND id IN(grantor,NEW.executor_user_id) ORDER BY id FOR SHARE LOOP
  IF principal.role NOT IN('owner','sender') THEN RAISE EXCEPTION 'delegated principal is ineligible' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM users WHERE org_id=NEW.org_id AND id=grantor)
    OR NOT EXISTS(SELECT 1 FROM users WHERE org_id=NEW.org_id AND id=NEW.executor_user_id) THEN
  RAISE EXCEPTION 'delegated principal is missing' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT g FROM presign_grants WHERE org_id=NEW.org_id AND id=NEW.grant_id FOR UPDATE;
 SELECT * INTO STRICT gr FROM presign_grant_revisions WHERE org_id=g.org_id AND grant_id=g.id AND revision=NEW.grant_revision;
 SELECT * INTO STRICT p FROM presign_workflow_revisions WHERE org_id=NEW.org_id AND policy_id=NEW.policy_id AND revision=NEW.policy_revision;
 IF g.revoked_at IS NOT NULL OR g.current_revision<>NEW.grant_revision
    OR gr.grant_sha256 IS DISTINCT FROM NEW.grant_sha256 OR gr.policy_id<>NEW.policy_id OR gr.policy_revision<>NEW.policy_revision
    OR gr.policy_sha256 IS DISTINCT FROM NEW.policy_sha256 OR p.policy_sha256 IS DISTINCT FROM NEW.policy_sha256
    OR a->>'workflow_id' IS DISTINCT FROM p.workflow_id::text
    OR a->>'workflow_revision' IS DISTINCT FROM p.revision::text
    OR a->>'definition_sha256' IS DISTINCT FROM encode(p.definition_sha256,'hex')
    OR a->>'input_mode' IS DISTINCT FROM convert_from(p.canonical_policy,'UTF8')::jsonb->'rules'->>'input_mode'
    OR NOT EXISTS(SELECT 1 FROM presign_workflows WHERE org_id=p.org_id AND id=p.workflow_id AND archived_at IS NULL)
    OR EXISTS(SELECT 1 FROM presign_workflow_retirements WHERE org_id=p.org_id AND workflow_id=p.workflow_id AND revision=p.revision)
    OR NEW.executed_at<gr.not_before OR NEW.executed_at>=gr.expires_at OR clock_timestamp()>=gr.expires_at
    OR NEW.executed_at>clock_timestamp() OR NEW.ceremony_epoch<gr.not_before
    OR NEW.use_number>gr.max_uses THEN
  RAISE EXCEPTION 'delegated grant or policy is not current' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM users u WHERE u.org_id=g.org_id AND u.id=g.grantor_user_id
   AND u.name=convert_from(gr.canonical_grant,'UTF8')::jsonb->'grantor'->>'name'
   AND u.email=convert_from(gr.canonical_grant,'UTF8')::jsonb->'grantor'->>'email') THEN
  RAISE EXCEPTION 'delegated named grantor changed' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF d.status<>'draft' OR d.deleted_at IS NOT NULL OR d.sender_id<>grantor OR d.source_kind<>'pdf'
    OR NOT d.requires_signature OR d.is_envelope OR d.parent_envelope_id IS NOT NULL
    OR d.routing_mode<>'parallel' OR COALESCE(COALESCE(d.html_current_source_json,d.html_source_json)->>'schema_version','')<>'3'
    OR EXISTS(SELECT 1 FROM signatures WHERE document_id=d.id)
    OR NOT EXISTS(SELECT 1 FROM send_sealing_intents i WHERE i.document_id=d.id AND i.org_id=d.org_id
       AND i.presign_execution_id IS NULL AND i.actor_user_id=NEW.executor_user_id
       AND i.article13_notice_epoch_at=NEW.ceremony_epoch
       AND i.retention_started_at IS NULL AND i.retention_completed_at IS NULL) THEN
  RAISE EXCEPTION 'delegated execution requires its untouched source3 draft' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
 RAISE EXCEPTION 'delegated execution authority is missing' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER presign_execution_insert BEFORE INSERT ON presign_executions FOR EACH ROW EXECUTE FUNCTION hash_presign_execution_insert();

CREATE FUNCTION hash_presign_use_insert() RETURNS trigger AS $$
DECLARE g presign_grants%ROWTYPE; limit_uses BIGINT; next_use BIGINT;
BEGIN
 SELECT * INTO STRICT g FROM presign_grants WHERE org_id=NEW.org_id AND id=NEW.grant_id FOR UPDATE;
 SELECT max_uses INTO STRICT limit_uses FROM presign_grant_revisions WHERE org_id=NEW.org_id AND grant_id=NEW.grant_id AND revision=NEW.grant_revision;
 SELECT COALESCE(max(use_number),0)+1 INTO next_use FROM presign_execution_uses WHERE org_id=NEW.org_id AND grant_id=NEW.grant_id AND grant_revision=NEW.grant_revision;
 IF g.revoked_at IS NOT NULL OR g.current_revision<>NEW.grant_revision OR NEW.use_number<>next_use OR NEW.use_number>limit_uses THEN
  RAISE EXCEPTION 'delegated use must be the exact remaining allowance' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'delegated grant is missing' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER presign_execution_use_insert BEFORE INSERT ON presign_execution_uses FOR EACH ROW EXECUTE FUNCTION hash_presign_use_insert();

CREATE FUNCTION hash_presign_request_complete() RETURNS trigger AS $$
DECLARE e presign_executions%ROWTYPE; ev events%ROWTYPE;
BEGIN
 IF NEW.state='committed' THEN
  SELECT * INTO STRICT e FROM presign_executions WHERE org_id=NEW.org_id AND id=NEW.execution_id;
  IF ROW(NEW.executor_kind,NEW.executor_user_id,NEW.executor_credential_id,NEW.request_id,NEW.execution_sha256,
     NEW.command_canonical,NEW.command_sha256,NEW.original_credential_sha256,NEW.audit_event_id,NEW.occurred_at)
     IS DISTINCT FROM ROW(e.executor_kind,e.executor_user_id,e.executor_credential_id,e.request_id,e.execution_sha256,
     e.command_canonical,e.command_sha256,e.original_credential_sha256,e.audit_event_id,e.executed_at) THEN
   RAISE EXCEPTION 'execution request does not match its committed use' USING ERRCODE='23514';
  END IF;
 ELSE
  SELECT * INTO STRICT ev FROM events WHERE id=NEW.audit_event_id;
  IF ev.org_id<>NEW.org_id OR ev.actor_user_id IS DISTINCT FROM NEW.executor_user_id
     OR ev.kind<>'presign.execution.request.closed' OR ev.document_id IS NOT NULL OR ev.recipient_id IS NOT NULL
     OR ev.row_hash IS NULL OR ev.payload_hashed IS NULL
     OR convert_from(ev.payload_hashed,'UTF8')::jsonb IS DISTINCT FROM ev.payload_json
     OR NOT (ev.payload_json @> jsonb_build_object('request_id',NEW.request_id,'executor_kind',NEW.executor_kind,
       'executor_user_id',NEW.executor_user_id,'executor_credential_id',NEW.executor_credential_id)) THEN
   RAISE EXCEPTION 'closed execution request requires exact audit lineage' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NULL;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'execution request lineage is missing' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER presign_execution_request_complete AFTER INSERT ON presign_execution_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_presign_request_complete();

CREATE FUNCTION hash_check_presign_execution(target UUID, fresh BOOLEAN DEFAULT FALSE) RETURNS void AS $$
DECLARE e presign_executions%ROWTYPE; d documents%ROWTYPE; s signatures%ROWTYPE;
        i send_sealing_intents%ROWTYPE; r recipients%ROWTYPE; f RECORD;
        p presign_workflow_revisions%ROWTYPE; g presign_grant_revisions%ROWTYPE;
        req presign_execution_requests%ROWTYPE; ev events%ROWTYPE; x JSONB; src JSONB; gp JSONB; pp JSONB;
        slot TEXT; rid UUID; declaration JSONB; party JSONB; field_pin JSONB; index_number INTEGER; options_hash TEXT;
BEGIN
 -- Legacy/manual paths return before acquiring any new parent lock.
 SELECT * INTO e FROM presign_executions WHERE document_id=target;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=e.document_id AND org_id=e.org_id FOR UPDATE;
 x:=convert_from(e.canonical_execution,'UTF8')::jsonb;
 src:=COALESCE(d.html_current_source_json,d.html_source_json);
 SELECT * INTO STRICT p FROM presign_workflow_revisions WHERE org_id=e.org_id AND policy_id=e.policy_id AND revision=e.policy_revision;
 SELECT * INTO STRICT g FROM presign_grant_revisions WHERE org_id=e.org_id AND grant_id=e.grant_id AND revision=e.grant_revision;
 pp:=convert_from(p.canonical_policy,'UTF8')::jsonb;
 gp:=convert_from(g.canonical_grant,'UTF8')::jsonb;
 IF d.status NOT IN('sealing','sent','in_progress','finalizing','completed','declined','voided','expired')
    OR d.deleted_at IS NOT NULL OR d.source_kind<>'pdf' OR NOT d.requires_signature
    OR d.is_envelope OR d.parent_envelope_id IS NOT NULL OR d.routing_mode<>'parallel'
    OR src->>'schema_version' IS DISTINCT FROM '3'
    OR x->'document'->>'signing_plan_sha256' IS DISTINCT FROM src->'signing_artifact'->>'plan_sha256'
    OR d.sender_id IS DISTINCT FROM (gp->'grantor'->>'user_id')::uuid
    OR d.html_current_materialization_id IS DISTINCT FROM e.materialization_id
    OR src->>'commitment' IS DISTINCT FROM encode(e.source_commitment,'hex')
    OR src->>'template_id' IS DISTINCT FROM p.template_id::text
    OR src->>'template_version' IS DISTINCT FROM p.template_version::text
    OR src->>'template_content_sha256' IS DISTINCT FROM encode(p.template_content_sha256,'hex')
    OR x->'executor' IS DISTINCT FROM pp->'executor'
    OR x->'document'->'template' IS DISTINCT FROM pp->'template'
    OR x->'document'->'materialization'->>'revision' IS DISTINCT FROM d.html_current_materialization_sequence::text
    OR x->'document'->'base_pdf'->'artifact'->>'storage_key' IS DISTINCT FROM d.pdf_storage_key
    OR x->'document'->'base_pdf'->'artifact'->>'sha256' IS DISTINCT FROM encode(d.pdf_sha256,'hex')
    OR x->'document'->'base_pdf'->'artifact'->>'version_id' IS DISTINCT FROM d.pdf_storage_version_id
    OR x->'document'->'base_pdf'->>'pages' IS DISTINCT FROM d.html_current_page_count::text
    OR x->'visible_pdf'->>'pages' IS DISTINCT FROM d.html_current_page_count::text
    OR x->'signature'->>'typed_name' IS DISTINCT FROM gp->'grantor'->>'name'
    OR x->'signature'->'style' IS DISTINCT FROM gp->'signature'
    OR x->'document'->'parties'->1->>'name' IS DISTINCT FROM gp->'grantor'->>'name'
    OR x->'document'->'parties'->1->>'email' IS DISTINCT FROM gp->'grantor'->>'email'
    OR x->'document'->'parties'->1->>'company_name' IS DISTINCT FROM gp->'grantor'->>'company_name'
    OR x->'document'->'parties'->1->>'company_id' IS DISTINCT FROM gp->'grantor'->>'company_id'
    OR x->'document'->'parties'->1->>'authority_basis' IS DISTINCT FROM gp->'grantor'->>'authority_basis' THEN
  RAISE EXCEPTION 'delegated execution source or policy drifted' USING ERRCODE='23514';
 END IF;
 -- Existing complete source3 party/geometry/branding guard remains mandatory.
 PERFORM hash_check_branded_signing_page(d.id);
 -- The actual source plan and its row pair must equal both captured tuples.
 -- DB76 establishes printed-source consistency; these checks also bind the
 -- immutable execution descriptor rather than merely validating current rows.
 FOREACH slot IN ARRAY ARRAY['customer','provider'] LOOP
  index_number:=CASE WHEN slot='customer' THEN 0 ELSE 1 END;
  SELECT (v->>'recipient_id')::uuid INTO STRICT rid FROM jsonb_array_elements(src->'party_bindings') v WHERE v->>'slot'=slot;
  SELECT v INTO STRICT declaration FROM jsonb_array_elements(src->'master'->'contract_profile'->'parties') v WHERE v->>'slot'=slot;
  SELECT * INTO STRICT r FROM recipients WHERE id=rid AND document_id=d.id AND role=slot;
  SELECT * INTO STRICT f FROM document_fields WHERE document_id=d.id AND recipient_id=rid;
  party:=jsonb_build_object('id',r.id,'slot',slot,'role',r.role,'name',r.name,'email',r.email,
    'company_name',src->'values'->>(declaration->>'company_name'),
    'company_id',src->'values'->>(declaration->>'company_id'),
    'authority_basis',src->'values'->>(declaration->>'representative_authority'));
  -- SigningFieldOptions has exactly these three ASCII fields, in this order.
  -- Hash its existing compact struct encoding, never PostgreSQL jsonb::text.
  options_hash:=encode(sha256(convert_to('{"policy":'||to_json(src->'signing_artifact'->>'policy')::text
    ||',"slot":'||to_json(slot)::text||',"source_commitment":'||to_json(src->>'commitment')::text||'}','UTF8')),'hex');
  field_pin:=jsonb_build_object('id',f.id,'recipient_id',rid,'slot',slot,'type',f.type,'required',f.required,
    'page',f.page,'x',f.x_pct*10000,'y',f.y_pct*10000,'w',f.w_pct*10000,'h',f.h_pct*10000,
    'source_commitment',src->>'commitment','options_sha256',options_hash);
  IF x->'document'->'parties'->index_number IS DISTINCT FROM party
     OR x->'document'->'fields'->index_number IS DISTINCT FROM field_pin
     OR f.value IS NOT NULL OR f.completed_at IS NOT NULL
     OR (fresh AND slot='customer' AND (r.status<>'pending' OR r.signed_at IS NOT NULL
         OR r.sent_at IS NOT NULL OR r.first_viewed_at IS NOT NULL)) THEN
   RAISE EXCEPTION 'delegated captured party or field differs from the exact source plan' USING ERRCODE='23514';
  END IF;
 END LOOP;
 IF pp->'rules'->>'input_mode'='reviewed_document' AND
   (d.html_reviewed_materialization_id IS DISTINCT FROM e.materialization_id
    OR d.html_reviewed_pdf_sha256 IS DISTINCT FROM d.pdf_sha256
    OR d.html_reviewed_by IS NULL OR d.html_reviewed_at IS NULL) THEN
  RAISE EXCEPTION 'delegated reviewed-document mode needs exact human review' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT s FROM signatures WHERE id=e.signature_id AND document_id=d.id;
 SELECT * INTO STRICT r FROM recipients WHERE id=e.provider_recipient_id AND document_id=d.id;
 SELECT * INTO STRICT f FROM document_fields WHERE id=e.provider_field_id AND document_id=d.id;
 IF s.signature_kind<>'delegated_grant_v1' OR s.presign_execution_id IS DISTINCT FROM e.id
    OR s.recipient_id<>e.provider_recipient_id OR s.field_id<>e.provider_field_id
    OR s.signer_ip IS NOT NULL OR s.signer_ua IS NOT NULL
    OR s.signed_at IS DISTINCT FROM e.executed_at
    OR s.font IS DISTINCT FROM x->'signature'->'style'->>'font'
    OR s.typed_name IS DISTINCT FROM x->'signature'->>'typed_name'
    OR s.image_storage_key IS DISTINCT FROM x->'signature'->'image'->>'storage_key'
    OR encode(s.image_sha256,'hex') IS DISTINCT FROM x->'signature'->'image'->>'sha256'
    OR s.image_version_id IS DISTINCT FROM x->'signature'->'image'->>'version_id'
    OR NOT s.image_version_pin_required OR r.role<>'provider' OR r.status<>'signed'
    OR r.signed_at IS DISTINCT FROM e.executed_at OR r.sent_at IS NOT NULL OR r.first_viewed_at IS NOT NULL
    OR octet_length(r.magic_token_hash)<>0 OR NOT isfinite(r.magic_token_expires_at)
    OR r.magic_token_expires_at IS DISTINCT FROM TIMESTAMPTZ '1970-01-01 00:00:00+00'
    OR r.name IS DISTINCT FROM gp->'grantor'->>'name' OR r.email IS DISTINCT FROM gp->'grantor'->>'email'
    OR x->'document'->'parties'->1->>'id' IS DISTINCT FROM r.id::text
    OR f.recipient_id IS DISTINCT FROM r.id OR f.type<>'signature' OR NOT f.required
    OR x->'document'->'fields'->1->>'id' IS DISTINCT FROM f.id::text
    OR x->'document'->'fields'->1->>'recipient_id' IS DISTINCT FROM r.id::text
    OR x->'document'->'fields'->1->>'page' IS DISTINCT FROM f.page::text
    OR (x->'document'->'fields'->1->>'x')::numeric IS DISTINCT FROM f.x_pct*10000
    OR (x->'document'->'fields'->1->>'y')::numeric IS DISTINCT FROM f.y_pct*10000
    OR (x->'document'->'fields'->1->>'w')::numeric IS DISTINCT FROM f.w_pct*10000
    OR (x->'document'->'fields'->1->>'h')::numeric IS DISTINCT FROM f.h_pct*10000 THEN
  RAISE EXCEPTION 'delegated signature or named provider drifted' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT i FROM send_sealing_intents WHERE document_id=d.id AND org_id=d.org_id;
 IF i.presign_execution_id IS DISTINCT FROM e.id OR i.actor_user_id IS DISTINCT FROM e.executor_user_id
    OR i.article13_notice_epoch_at IS DISTINCT FROM e.ceremony_epoch
    OR i.retain_until IS DISTINCT FROM hash_evidence_retain_until(e.ceremony_epoch,7)
    OR (d.sent_at IS NOT NULL AND d.sent_at IS DISTINCT FROM e.ceremony_epoch)
    -- BeginDocumentSendSealing preserves an earlier document epoch. The
    -- newly committed intent is authoritative until exact publication.
    OR (d.status='sealing' AND d.article13_notice_epoch_at IS NOT NULL
        AND (NOT isfinite(d.article13_notice_epoch_at) OR d.article13_notice_epoch_at>e.ceremony_epoch))
    OR (d.status<>'sealing' AND d.article13_notice_epoch_at IS DISTINCT FROM e.ceremony_epoch) THEN
  RAISE EXCEPTION 'delegated sealing ceremony drifted' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT req FROM presign_execution_requests WHERE org_id=e.org_id AND executor_kind=e.executor_kind
   AND executor_user_id=e.executor_user_id AND executor_credential_id=e.executor_credential_id AND request_id=e.request_id;
 IF req.state<>'committed' OR req.execution_id IS DISTINCT FROM e.id
    OR req.execution_sha256 IS DISTINCT FROM e.execution_sha256
    OR req.command_canonical IS DISTINCT FROM e.command_canonical OR req.command_sha256 IS DISTINCT FROM e.command_sha256
    OR req.original_credential_sha256 IS DISTINCT FROM e.original_credential_sha256
    OR req.audit_event_id IS DISTINCT FROM e.audit_event_id OR req.occurred_at IS DISTINCT FROM e.executed_at THEN
  RAISE EXCEPTION 'delegated original request outcome drifted' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT ev FROM events WHERE id=e.audit_event_id;
 IF ev.org_id<>e.org_id OR ev.document_id IS DISTINCT FROM e.document_id
    OR ev.recipient_id IS DISTINCT FROM e.provider_recipient_id OR ev.actor_user_id IS DISTINCT FROM e.executor_user_id
    OR ev.kind<>'presign.execution.committed' OR ev.row_hash IS NULL OR ev.payload_hashed IS NULL
    OR convert_from(ev.payload_hashed,'UTF8')::jsonb IS DISTINCT FROM ev.payload_json
    OR NOT (ev.payload_json @> jsonb_build_object(
       'execution_id',e.id,'execution_sha256',encode(e.execution_sha256,'hex'),
       'grant_id',e.grant_id,'grant_revision',e.grant_revision,'use_number',e.use_number,
       'request_id',e.request_id,'command_sha256',encode(e.command_sha256,'hex'),
       'executor_kind',e.executor_kind,'executor_user_id',e.executor_user_id,'executor_credential_id',e.executor_credential_id)) THEN
  RAISE EXCEPTION 'delegated execution requires exact audit lineage' USING ERRCODE='23514';
 END IF;
 IF fresh THEN
  IF clock_timestamp()>=g.expires_at
     OR (jsonb_array_length(convert_from(e.admission_canonical,'UTF8')::jsonb->'crm_values')>0
         AND clock_timestamp()>=(convert_from(e.admission_canonical,'UTF8')::jsonb->>'valid_until')::timestamptz)
     OR NOT EXISTS(SELECT 1 FROM presign_grants h WHERE h.org_id=e.org_id AND h.id=e.grant_id AND h.current_revision=e.grant_revision AND h.revoked_at IS NULL)
     OR NOT EXISTS(SELECT 1 FROM presign_workflows h WHERE h.org_id=p.org_id AND h.id=p.workflow_id AND h.archived_at IS NULL)
     OR EXISTS(SELECT 1 FROM presign_workflow_retirements WHERE org_id=p.org_id AND workflow_id=p.workflow_id AND revision=p.revision)
     OR NOT EXISTS(SELECT 1 FROM templates t JOIN html_template_revisions tr ON tr.template_id=t.id AND tr.org_id=t.org_id
       WHERE t.id=p.template_id AND t.org_id=p.org_id AND t.archived_at IS NULL
       AND tr.version=p.template_version AND tr.content_sha256=p.template_content_sha256 AND tr.approved_by IS NOT NULL AND tr.approved_at IS NOT NULL)
     OR (e.executor_kind='api_key' AND NOT EXISTS(SELECT 1 FROM api_keys a WHERE a.org_id=e.org_id AND a.user_id=e.executor_user_id
       AND a.id=e.executor_credential_id AND a.expires_at IS NOT NULL AND a.expires_at>clock_timestamp()
       AND (a.scopes && ARRAY['admin','write']::text[]
            OR a.scopes @> ARRAY['write:authoring','write:workflow']::text[]))) THEN
   RAISE EXCEPTION 'delegated fresh execution authority expired or retired' USING ERRCODE='23514';
  END IF;
 END IF;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
 RAISE EXCEPTION 'delegated execution atomic pairing is incomplete' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION hash_guard_presign_pair() RETURNS trigger AS $$
DECLARE target UUID;
BEGIN
 IF TG_TABLE_NAME='documents' THEN target:=NEW.id;
 ELSE target:=NEW.document_id;
 END IF;
 PERFORM hash_check_presign_execution(target,TG_TABLE_NAME='presign_executions');
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER presign_execution_complete AFTER INSERT ON presign_executions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_pair();
CREATE CONSTRAINT TRIGGER presign_execution_document AFTER UPDATE ON documents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_pair();
CREATE CONSTRAINT TRIGGER presign_execution_signature AFTER INSERT OR UPDATE ON signatures DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_pair();
CREATE CONSTRAINT TRIGGER presign_execution_recipient AFTER UPDATE ON recipients DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_pair();
CREATE CONSTRAINT TRIGGER presign_execution_field AFTER UPDATE ON document_fields DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_pair();
CREATE CONSTRAINT TRIGGER presign_execution_sealing AFTER INSERT OR UPDATE ON send_sealing_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_pair();

CREATE FUNCTION hash_guard_presign_retained_pair() RETURNS trigger AS $$
DECLARE target UUID; eid UUID;
BEGIN
 IF TG_TABLE_NAME='documents' THEN target:=OLD.id; ELSE target:=OLD.document_id; END IF;
 SELECT id INTO eid FROM presign_executions WHERE document_id=target;
 IF NOT FOUND THEN
  -- Adding a delegation to an ordinary row is checked by its deferred FK/pair.
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'delegated execution evidence is retained' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='signatures' THEN
  -- Resolve table-specific record fields only inside the selected branch;
  -- SQL boolean short-circuit does not defer OLD field parameter lookup.
  IF OLD.presign_execution_id IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
   RAISE EXCEPTION 'delegated signature is immutable' USING ERRCODE='23514';
  END IF;
 ELSIF TG_TABLE_NAME='send_sealing_intents' THEN
  IF OLD.presign_execution_id IS NULL AND NEW.presign_execution_id=eid
     AND (to_jsonb(NEW)-'presign_execution_id') IS NOT DISTINCT FROM (to_jsonb(OLD)-'presign_execution_id') THEN
   RETURN NEW;
  END IF;
  IF (to_jsonb(NEW)-ARRAY['retention_started_at','retention_completed_at','attempts','last_error','updated_at'])
     IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['retention_started_at','retention_completed_at','attempts','last_error','updated_at'])
     OR NEW.attempts<OLD.attempts
     OR (OLD.retention_started_at IS NOT NULL AND NEW.retention_started_at IS DISTINCT FROM OLD.retention_started_at)
     OR (OLD.retention_completed_at IS NOT NULL AND NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at)
     OR (NEW.retention_completed_at IS NOT NULL AND NEW.retention_started_at IS NULL) THEN
   RAISE EXCEPTION 'delegated sealing core is immutable' USING ERRCODE='23514';
  END IF;
 ELSIF TG_TABLE_NAME='recipients' THEN
  IF OLD.id=(SELECT provider_recipient_id FROM presign_executions WHERE id=eid)
     AND OLD.status='signed'
     AND (NEW.magic_token_hash IS DISTINCT FROM OLD.magic_token_hash
          OR NEW.magic_token_expires_at IS DISTINCT FROM OLD.magic_token_expires_at) THEN
   RAISE EXCEPTION 'delegated provider public token is permanently disabled' USING ERRCODE='23514';
  END IF;
 ELSIF TG_TABLE_NAME='documents' THEN
  IF NEW.status='draft' OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
    OR ROW(NEW.org_id,NEW.sender_id,NEW.template_id,NEW.source_kind,NEW.requires_signature,NEW.routing_mode,NEW.is_envelope,NEW.parent_envelope_id,
       NEW.pdf_storage_key,NEW.pdf_sha256,NEW.pdf_storage_version_id,NEW.variables_json,NEW.html_source_json,NEW.html_current_source_json,
       NEW.html_current_materialization_id,NEW.html_current_materialization_sequence,NEW.html_current_page_count,NEW.expires_at,
       NEW.html_reviewed_pdf_sha256,NEW.html_reviewed_materialization_id,NEW.html_reviewed_by,NEW.html_reviewed_at)
      IS DISTINCT FROM ROW(OLD.org_id,OLD.sender_id,OLD.template_id,OLD.source_kind,OLD.requires_signature,OLD.routing_mode,OLD.is_envelope,OLD.parent_envelope_id,
       OLD.pdf_storage_key,OLD.pdf_sha256,OLD.pdf_storage_version_id,OLD.variables_json,OLD.html_source_json,OLD.html_current_source_json,
       OLD.html_current_materialization_id,OLD.html_current_materialization_sequence,OLD.html_current_page_count,OLD.expires_at,
       OLD.html_reviewed_pdf_sha256,OLD.html_reviewed_materialization_id,OLD.html_reviewed_by,OLD.html_reviewed_at) THEN
   RAISE EXCEPTION 'delegated document cannot reopen or replace its source' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER presign_retained_document BEFORE UPDATE OR DELETE ON documents FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_retained_pair();
CREATE TRIGGER presign_retained_signature BEFORE UPDATE OR DELETE ON signatures FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_retained_pair();
CREATE TRIGGER presign_retained_recipient BEFORE UPDATE OR DELETE ON recipients FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_retained_pair();
CREATE TRIGGER presign_retained_field BEFORE DELETE ON document_fields FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_retained_pair();
CREATE TRIGGER presign_retained_sealing BEFORE UPDATE OR DELETE ON send_sealing_intents FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_retained_pair();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM presign_executions) OR EXISTS(SELECT 1 FROM presign_execution_uses)
    OR EXISTS(SELECT 1 FROM presign_execution_requests) THEN
  RAISE EXCEPTION 'cannot discard retained delegated execution evidence';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER presign_retained_document ON documents;
DROP TRIGGER presign_retained_signature ON signatures;
DROP TRIGGER presign_retained_recipient ON recipients;
DROP TRIGGER presign_retained_field ON document_fields;
DROP TRIGGER presign_retained_sealing ON send_sealing_intents;
DROP TRIGGER presign_execution_document ON documents;
DROP TRIGGER presign_execution_signature ON signatures;
DROP TRIGGER presign_execution_recipient ON recipients;
DROP TRIGGER presign_execution_field ON document_fields;
DROP TRIGGER presign_execution_sealing ON send_sealing_intents;
ALTER TABLE signatures DROP CONSTRAINT signature_presign_execution;
ALTER TABLE send_sealing_intents DROP CONSTRAINT sealing_presign_execution;
ALTER TABLE presign_executions DROP CONSTRAINT presign_execution_exact_use;
ALTER TABLE presign_executions DROP CONSTRAINT presign_execution_exact_request;
DROP TABLE presign_execution_requests,presign_execution_uses,presign_executions;
DROP FUNCTION hash_guard_presign_retained_pair();
DROP FUNCTION hash_guard_presign_pair();
DROP FUNCTION hash_check_presign_execution(UUID,BOOLEAN);
DROP FUNCTION hash_presign_request_complete();
DROP FUNCTION hash_presign_use_insert();
DROP FUNCTION hash_presign_execution_insert();
ALTER TABLE send_sealing_intents DROP COLUMN presign_execution_id;
ALTER TABLE signatures DROP CONSTRAINT signatures_presign_identity;
ALTER TABLE signatures DROP CONSTRAINT signatures_presign_kind_pair;
ALTER TABLE signatures DROP COLUMN presign_execution_id;
ALTER TABLE signatures DROP COLUMN signature_kind;
