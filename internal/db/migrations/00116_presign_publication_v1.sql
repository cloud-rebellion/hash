-- +goose Up
-- M82 deliberately stores only the immutable execution and its base/visible
-- PDF and span pins. It has no relation for the archived font/recipe/worker
-- proof, an owned in-flight upload, publication, or a superseding ceremony.
-- Keep every M82 canonical byte/domain intact and append these exact relations.

CREATE TABLE presign_preparations_v1 (
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 id UUID NOT NULL CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 executor_kind TEXT NOT NULL CHECK(executor_kind IN ('member','api_key')),
 executor_user_id UUID NOT NULL CHECK(executor_user_id<>'00000000-0000-0000-0000-000000000000'),
 executor_credential_id UUID NOT NULL,
 request_id UUID NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
 document_id UUID NOT NULL,
 intent_canonical BYTEA NOT NULL CHECK(octet_length(intent_canonical) BETWEEN 1 AND 8192),
 intent_sha256 BYTEA NOT NULL CHECK(octet_length(intent_sha256)=32),
 original_credential_sha256 BYTEA NOT NULL CHECK(octet_length(original_credential_sha256)=32),
 state TEXT NOT NULL DEFAULT 'preparing' CHECK(state IN ('preparing','committed','closed')),
 execution_id UUID,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 expires_at TIMESTAMPTZ NOT NULL CHECK(isfinite(expires_at)),
 PRIMARY KEY(org_id,id),
 UNIQUE(org_id,executor_kind,executor_user_id,executor_credential_id,request_id),
 -- Original closed request identity survives deletion after every real
 -- transient version is cleaned. The insertion/deletion guards below own
 -- that lifecycle; a generic FK would strand clean nonlegal drafts forever.
 FOREIGN KEY(org_id,execution_id,document_id) REFERENCES presign_executions(org_id,id,document_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK((executor_kind='member' AND executor_credential_id='00000000-0000-0000-0000-000000000000') OR
       (executor_kind='api_key' AND executor_credential_id<>'00000000-0000-0000-0000-000000000000')),
 CHECK((state='committed')=(execution_id IS NOT NULL)),
 CHECK(expires_at>created_at)
);
CREATE UNIQUE INDEX presign_one_preparing_document116 ON presign_preparations_v1(document_id) WHERE state='preparing';

CREATE TABLE presign_preparation_objects_v1 (
 org_id UUID NOT NULL,
 preparation_id UUID NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('signature_span','signature_font','inter_font','overlay_recipe',
   'signature_fragment','disclosure_fragment','overlay_proof','visible_pdf')),
 object_key TEXT NOT NULL CHECK(length(object_key) BETWEEN 1 AND 1024 AND
   object_key ~ '^org/[a-f0-9-]{36}/documents/[a-f0-9-]{36}/presign/[a-f0-9-]{36}/[a-z_]+$'),
 content_type TEXT NOT NULL CHECK(content_type IN ('text/html; charset=utf-8','font/woff2','application/json','application/pdf')),
 object_sha256 BYTEA NOT NULL CHECK(octet_length(object_sha256)=32),
 object_bytes BIGINT NOT NULL CHECK(object_bytes BETWEEN 1 AND 52428800),
 upload_attempted BOOLEAN NOT NULL DEFAULT FALSE,
 version_id TEXT CHECK(length(version_id) BETWEEN 1 AND 1024 AND version_id !~ '[^!-~]'),
 resolved_at TIMESTAMPTZ CHECK(resolved_at IS NULL OR isfinite(resolved_at)),
 cleanup_started_at TIMESTAMPTZ CHECK(cleanup_started_at IS NULL OR isfinite(cleanup_started_at)),
 deleted_at TIMESTAMPTZ CHECK(deleted_at IS NULL OR isfinite(deleted_at)),
 PRIMARY KEY(org_id,preparation_id,role), UNIQUE(object_key),
 FOREIGN KEY(org_id,preparation_id) REFERENCES presign_preparations_v1(org_id,id) ON DELETE RESTRICT,
 CHECK((version_id IS NULL)=(resolved_at IS NULL)),
 CHECK(version_id IS NULL OR upload_attempted),
 CHECK(deleted_at IS NULL OR (cleanup_started_at IS NOT NULL AND version_id IS NOT NULL))
);

CREATE TABLE presign_execution_assets_v1 (
 org_id UUID NOT NULL,
 execution_id UUID NOT NULL,
 document_id UUID NOT NULL,
 preparation_id UUID NOT NULL,
 canonical_assets BYTEA NOT NULL CHECK(octet_length(canonical_assets) BETWEEN 1 AND 65536),
 assets_sha256 BYTEA NOT NULL CHECK(octet_length(assets_sha256)=32),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 PRIMARY KEY(org_id,execution_id), UNIQUE(document_id),
 FOREIGN KEY(org_id,execution_id,document_id) REFERENCES presign_executions(org_id,id,document_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(org_id,preparation_id) REFERENCES presign_preparations_v1(org_id,id) ON DELETE RESTRICT
);

CREATE TABLE presign_execution_publications_v1 (
 org_id UUID NOT NULL,
 execution_id UUID NOT NULL,
 document_id UUID NOT NULL,
 customer_recipient_id UUID NOT NULL,
 state TEXT NOT NULL DEFAULT 'retaining' CHECK(state IN ('retaining','published','expired')),
 retain_until TIMESTAMPTZ NOT NULL CHECK(isfinite(retain_until)),
 retention_started_at TIMESTAMPTZ CHECK(retention_started_at IS NULL OR isfinite(retention_started_at)),
 retention_completed_at TIMESTAMPTZ CHECK(retention_completed_at IS NULL OR isfinite(retention_completed_at)),
 published_at TIMESTAMPTZ CHECK(published_at IS NULL OR isfinite(published_at)),
 publication_event_id UUID REFERENCES events(id) ON DELETE RESTRICT,
 PRIMARY KEY(org_id,execution_id), UNIQUE(document_id),
 FOREIGN KEY(org_id,execution_id) REFERENCES presign_execution_assets_v1(org_id,execution_id) ON DELETE RESTRICT,
 FOREIGN KEY(org_id,execution_id,document_id) REFERENCES presign_executions(org_id,id,document_id) ON DELETE RESTRICT,
 CHECK(retention_completed_at IS NULL OR retention_started_at IS NOT NULL),
 CHECK((state='published')=(published_at IS NOT NULL)),
 CHECK((state='published')=(publication_event_id IS NOT NULL)),
 CHECK(state='retaining' OR retention_completed_at IS NOT NULL)
);

CREATE TABLE presign_supersessions_v1 (
 org_id UUID NOT NULL,
 prior_execution_id UUID NOT NULL,
 prior_document_id UUID NOT NULL,
 document_id UUID NOT NULL,
 request_id UUID NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
 actor_user_id UUID NOT NULL,
 audit_event_id UUID NOT NULL UNIQUE REFERENCES events(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 PRIMARY KEY(org_id,prior_execution_id), UNIQUE(document_id),
 FOREIGN KEY(org_id,prior_execution_id,prior_document_id) REFERENCES presign_executions(org_id,id,document_id) ON DELETE RESTRICT,
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(org_id,actor_user_id,request_id) REFERENCES html_document_creation_requests(org_id,actor_user_id,request_id) ON DELETE RESTRICT,
 CHECK(document_id<>prior_document_id)
);

-- +goose StatementBegin
CREATE FUNCTION hash_presign_assets116() RETURNS trigger AS $$
DECLARE e presign_executions%ROWTYPE; p presign_preparations_v1%ROWTYPE;
 x JSONB; a JSONB; o JSONB; i INTEGER; reserved presign_preparation_objects_v1%ROWTYPE;
 roles TEXT[]:=ARRAY['signature_span','signature_font','inter_font','overlay_recipe',
   'signature_fragment','disclosure_fragment','overlay_proof','visible_pdf'];
BEGIN
 SELECT * INTO STRICT e FROM presign_executions WHERE org_id=NEW.org_id AND id=NEW.execution_id;
 SELECT * INTO STRICT p FROM presign_preparations_v1 WHERE org_id=NEW.org_id AND id=NEW.preparation_id;
 x:=convert_from(e.canonical_execution,'UTF8')::jsonb;
 a:=convert_from(NEW.canonical_assets,'UTF8')::jsonb;
 IF NEW.document_id<>e.document_id OR p.document_id<>e.document_id OR p.state<>'committed' OR p.execution_id<>e.id
   OR EXISTS(SELECT 1 FROM document_packages_v1 pkg JOIN document_attachment_drafts_v1 attachment ON attachment.package_id=pkg.id AND attachment.org_id=pkg.org_id WHERE pkg.org_id=e.org_id AND pkg.document_id=e.document_id)
   OR EXISTS(SELECT 1 FROM document_package_captures_v1 WHERE org_id=e.org_id AND document_id=e.document_id)
   OR EXISTS(SELECT 1 FROM document_package_send_attempts_v1 WHERE org_id=e.org_id AND document_id=e.document_id)
   OR EXISTS(SELECT 1 FROM document_attachment_drafts_v1 WHERE org_id=e.org_id AND member_document_id=e.document_id)
   OR EXISTS(SELECT 1 FROM document_package_capture_members_v1 WHERE org_id=e.org_id AND member_document_id=e.document_id)
   OR ROW(p.executor_kind,p.executor_user_id,p.executor_credential_id,p.request_id,p.original_credential_sha256)
     IS DISTINCT FROM ROW(e.executor_kind,e.executor_user_id,e.executor_credential_id,e.request_id,e.original_credential_sha256)
   OR a->>'schema_version' IS DISTINCT FROM '1' OR a->>'org_id' IS DISTINCT FROM e.org_id::text
   OR a->>'document_id' IS DISTINCT FROM e.document_id::text OR a->>'execution_id' IS DISTINCT FROM e.id::text
   OR a->>'execution_sha256' IS DISTINCT FROM encode(e.execution_sha256,'hex')
   OR jsonb_typeof(a) IS DISTINCT FROM 'object'
   OR a-ARRAY['schema_version','org_id','document_id','execution_id','execution_sha256','objects','bindings','overlay'] <> '{}'::jsonb
   OR (SELECT count(*) FROM jsonb_object_keys(a))<>8
   OR jsonb_typeof(a->'objects') IS DISTINCT FROM 'array' OR jsonb_array_length(a->'objects') IS DISTINCT FROM 8
   OR (SELECT count(*) FROM presign_preparation_objects_v1 WHERE org_id=p.org_id AND preparation_id=p.id)<>8
   OR jsonb_typeof(a->'bindings') IS DISTINCT FROM 'object'
   OR (a->'bindings')-ARRAY['source_commitment','signing_plan_sha256','branding_sha256','policy_sha256','grant_sha256','font','span_sha256','signature_font_sha256','inter_font_sha256','disclosure_sha256','recipe_sha256'] <> '{}'::jsonb
   OR (SELECT count(*) FROM jsonb_object_keys(a->'bindings'))<>11
   OR jsonb_typeof(a->'overlay') IS DISTINCT FROM 'object'
   OR (a->'overlay')-ARRAY['schema_version','policy','bindings_sha256','base_sha256','base_bytes','signature_sha256','disclosure_sha256','processing_sha256','processing_bytes','output_sha256','output_bytes','pages','geometry_sha256','original_content_sha256','forms'] <> '{}'::jsonb
   OR (SELECT count(*) FROM jsonb_object_keys(a->'overlay'))<>15
   OR sha256(convert_to('hash:presign-execution-assets:v1','UTF8')||decode('00','hex')||NEW.canonical_assets)<>NEW.assets_sha256 THEN
  RAISE EXCEPTION 'presign asset set differs from committed original execution' USING ERRCODE='23514';
 END IF;
 FOR i IN 0..7 LOOP
  o:=a->'objects'->i;
  SELECT * INTO STRICT reserved FROM presign_preparation_objects_v1
   WHERE org_id=e.org_id AND preparation_id=p.id AND role=roles[i+1];
  IF o->>'role' IS DISTINCT FROM roles[i+1] OR o->>'content_type' IS DISTINCT FROM reserved.content_type
    OR jsonb_typeof(o) IS DISTINCT FROM 'object' OR o-ARRAY['role','content_type','object'] <> '{}'::jsonb
    OR (SELECT count(*) FROM jsonb_object_keys(o))<>3
    OR jsonb_typeof(o->'object') IS DISTINCT FROM 'object' OR (o->'object')-ARRAY['storage_key','version_id','sha256','bytes'] <> '{}'::jsonb
    OR (SELECT count(*) FROM jsonb_object_keys(o->'object'))<>4
    OR o->'object'->>'storage_key' IS DISTINCT FROM reserved.object_key
    OR o->'object'->>'version_id' IS DISTINCT FROM reserved.version_id
    OR o->'object'->>'sha256' IS DISTINCT FROM encode(reserved.object_sha256,'hex')
    OR o->'object'->>'bytes' IS DISTINCT FROM reserved.object_bytes::text
    OR NOT reserved.upload_attempted OR reserved.resolved_at IS NULL OR reserved.cleanup_started_at IS NOT NULL OR reserved.deleted_at IS NOT NULL THEN
   RAISE EXCEPTION 'presign archive differs from exact resolved upload' USING ERRCODE='23514';
  END IF;
 END LOOP;
 IF a->'objects'->0->'object' IS DISTINCT FROM x->'signature'->'image'
   OR a->'objects'->7->'object' IS DISTINCT FROM x->'visible_pdf'->'artifact'
   OR a->'objects'->6->'object'->>'sha256' IS DISTINCT FROM x->>'visible_stamp_proof_sha256'
   OR a->'overlay'->>'base_sha256' IS DISTINCT FROM x->'document'->'base_pdf'->'artifact'->>'sha256'
   OR a->'overlay'->>'output_sha256' IS DISTINCT FROM x->'visible_pdf'->'artifact'->>'sha256'
   OR a->'overlay'->>'pages' IS DISTINCT FROM x->'visible_pdf'->>'pages'
   OR a->'bindings'->>'source_commitment' IS DISTINCT FROM x->'document'->'materialization'->>'source_commitment'
   OR a->'bindings'->>'signing_plan_sha256' IS DISTINCT FROM x->'document'->>'signing_plan_sha256'
   OR a->'bindings'->>'branding_sha256' IS DISTINCT FROM x->'document'->>'branding_sha256'
   OR a->'bindings'->>'policy_sha256' IS DISTINCT FROM x->'policy'->>'sha256'
   OR a->'bindings'->>'grant_sha256' IS DISTINCT FROM x->'grant'->>'sha256'
   OR a->'bindings'->>'font' IS DISTINCT FROM x->'signature'->'style'->>'font'
   OR a->'bindings'->>'span_sha256' IS DISTINCT FROM x->'signature'->'image'->>'sha256'
   OR a->'bindings'->>'signature_font_sha256' IS DISTINCT FROM x->'signature'->'style'->>'font_sha256'
   OR a->'bindings'->>'inter_font_sha256' IS DISTINCT FROM a->'objects'->2->'object'->>'sha256'
   OR a->'bindings'->>'recipe_sha256' IS DISTINCT FROM a->'objects'->3->'object'->>'sha256'
   OR a->'overlay'->>'signature_sha256' IS DISTINCT FROM a->'objects'->4->'object'->>'sha256'
   OR a->'overlay'->>'disclosure_sha256' IS DISTINCT FROM a->'objects'->5->'object'->>'sha256' THEN
  RAISE EXCEPTION 'presign archive substitutes original or visible artifact' USING ERRCODE='23514';
 END IF;
 PERFORM hash_check_presign_execution(e.document_id,FALSE);
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
 RAISE EXCEPTION 'presign archive pairing is incomplete' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER presign_assets_complete116 AFTER INSERT ON presign_execution_assets_v1
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_presign_assets116();
CREATE TRIGGER presign_assets_immutable116 BEFORE UPDATE OR DELETE ON presign_execution_assets_v1
 FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();
CREATE TRIGGER presign_supersession_immutable116 BEFORE UPDATE OR DELETE ON presign_supersessions_v1
 FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_preparation116() RETURNS trigger AS $$
DECLARE p presign_preparations_v1%ROWTYPE; expected_type TEXT; x JSONB;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'presign preparation requires retained recovery' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='presign_preparations_v1' THEN
  IF TG_OP='INSERT' THEN
   x:=convert_from(NEW.intent_canonical,'UTF8')::jsonb;
   IF NEW.state<>'preparing' OR NEW.execution_id IS NOT NULL OR NEW.expires_at>NEW.created_at+interval '45 seconds'
    OR sha256(convert_to('hash:presign-execution-intent:v1','UTF8')||decode('00','hex')||NEW.intent_canonical) IS DISTINCT FROM NEW.intent_sha256
    OR jsonb_typeof(x) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(x))<>11
    OR x-ARRAY['request_id','expected_org_id','expected_user_id','document_id','document_updated_at','materialization_id','materialization_revision','source_commitment','policy','grant','lawful_basis']<>'{}'::jsonb
    OR x->>'request_id' IS DISTINCT FROM NEW.request_id::text OR x->>'expected_org_id' IS DISTINCT FROM NEW.org_id::text
    OR x->>'expected_user_id' IS DISTINCT FROM NEW.executor_user_id::text OR x->>'document_id' IS DISTINCT FROM NEW.document_id::text
    OR x->>'lawful_basis' IS DISTINCT FROM 'contract' OR x->>'source_commitment' !~ '^[a-f0-9]{64}$'
    OR EXISTS(SELECT 1 FROM document_packages_v1 pkg JOIN document_attachment_drafts_v1 attachment ON attachment.package_id=pkg.id AND attachment.org_id=pkg.org_id WHERE pkg.org_id=NEW.org_id AND pkg.document_id=NEW.document_id)
    OR EXISTS(SELECT 1 FROM document_package_captures_v1 WHERE org_id=NEW.org_id AND document_id=NEW.document_id)
    OR EXISTS(SELECT 1 FROM document_package_send_attempts_v1 WHERE org_id=NEW.org_id AND document_id=NEW.document_id)
    OR EXISTS(SELECT 1 FROM document_attachment_drafts_v1 WHERE org_id=NEW.org_id AND member_document_id=NEW.document_id)
    OR EXISTS(SELECT 1 FROM document_package_capture_members_v1 WHERE org_id=NEW.org_id AND member_document_id=NEW.document_id)
    OR NOT EXISTS(SELECT 1 FROM documents d WHERE d.id=NEW.document_id AND d.org_id=NEW.org_id AND d.status='draft' AND d.deleted_at IS NULL
     AND d.updated_at=(x->>'document_updated_at')::timestamptz AND d.html_current_materialization_id=(x->>'materialization_id')::uuid
     AND d.html_current_materialization_sequence=(x->>'materialization_revision')::bigint
     AND COALESCE(d.html_current_source_json,d.html_source_json)->>'commitment'=x->>'source_commitment') THEN
    RAISE EXCEPTION 'pre-sign preparation requires the exact original actor request and source' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
  END IF;
  IF (to_jsonb(NEW)-ARRAY['state','execution_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','execution_id'])
    OR OLD.state<>'preparing' OR NEW.state NOT IN('preparing','committed','closed') THEN
   RAISE EXCEPTION 'presign original preparation is immutable' USING ERRCODE='23514';
  END IF;
 ELSE
  SELECT * INTO STRICT p FROM presign_preparations_v1 WHERE org_id=NEW.org_id AND id=NEW.preparation_id FOR UPDATE;
  expected_type:=CASE WHEN NEW.role='signature_span' THEN 'text/html; charset=utf-8'
   WHEN NEW.role IN('signature_font','inter_font') THEN 'font/woff2'
   WHEN NEW.role IN('overlay_recipe','overlay_proof') THEN 'application/json' ELSE 'application/pdf' END;
  IF NEW.object_key IS DISTINCT FROM 'org/'||p.org_id::text||'/documents/'||p.document_id::text||'/presign/'||p.id::text||'/'||NEW.role
    OR NEW.content_type<>expected_type OR (NEW.role NOT IN('signature_fragment','disclosure_fragment','visible_pdf') AND NEW.object_bytes>1048576) THEN
   RAISE EXCEPTION 'presign upload is not its exact owned role' USING ERRCODE='23514';
  END IF;
  IF TG_OP='INSERT' THEN
   IF p.state<>'preparing' OR NEW.upload_attempted OR NEW.version_id IS NOT NULL OR NEW.resolved_at IS NOT NULL
     OR NEW.cleanup_started_at IS NOT NULL OR NEW.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'presign upload must start as an unattempted reservation' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
  END IF;
  IF (to_jsonb(NEW)-ARRAY['upload_attempted','version_id','resolved_at','cleanup_started_at','deleted_at']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['upload_attempted','version_id','resolved_at','cleanup_started_at','deleted_at'])
    OR (OLD.upload_attempted AND NOT NEW.upload_attempted)
    OR (OLD.version_id IS NOT NULL AND ROW(NEW.version_id,NEW.resolved_at) IS DISTINCT FROM ROW(OLD.version_id,OLD.resolved_at))
    OR (OLD.cleanup_started_at IS NOT NULL AND NEW.cleanup_started_at IS DISTINCT FROM OLD.cleanup_started_at)
    OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at)
    OR (p.state='committed' AND NEW IS DISTINCT FROM OLD)
    OR (NEW.cleanup_started_at IS NOT NULL AND p.state<>'closed')
    OR (p.state='closed' AND ROW(NEW.upload_attempted) IS DISTINCT FROM ROW(OLD.upload_attempted)) THEN
   RAISE EXCEPTION 'presign upload reservation is immutable' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER presign_preparation_retained116 BEFORE INSERT OR UPDATE OR DELETE ON presign_preparations_v1
 FOR EACH ROW EXECUTE FUNCTION hash_presign_preparation116();
CREATE TRIGGER presign_preparation_object_retained116 BEFORE INSERT OR UPDATE OR DELETE ON presign_preparation_objects_v1
 FOR EACH ROW EXECUTE FUNCTION hash_presign_preparation116();

-- Every writer must preserve the source while an admitted producer or an
-- uncertain upload can still own it. Closed fully cleaned requests retain only
-- their immutable tombstone and do not prevent normal draft retirement.
-- +goose StatementBegin
CREATE FUNCTION hash_presign_draft_lifecycle116() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP='DELETE' OR (NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL) THEN
  IF EXISTS(SELECT 1 FROM presign_preparations_v1 p WHERE p.org_id=OLD.org_id AND p.document_id=OLD.id
    AND (p.state='preparing' OR EXISTS(SELECT 1 FROM presign_preparation_objects_v1 o WHERE o.org_id=p.org_id AND o.preparation_id=p.id AND o.upload_attempted AND o.deleted_at IS NULL))) THEN
   RAISE EXCEPTION 'pre-sign producer or unresolved transient evidence requires original-request cleanup before draft retirement' USING ERRCODE='23514';
  END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER presign_draft_lifecycle116 BEFORE UPDATE OR DELETE ON documents FOR EACH ROW EXECUTE FUNCTION hash_presign_draft_lifecycle116();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_publication116() RETURNS trigger AS $$
DECLARE e presign_executions%ROWTYPE; i send_sealing_intents%ROWTYPE; r recipients%ROWTYPE; ev events%ROWTYPE; d documents%ROWTYPE; x JSONB;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'presign publication is retained' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.org_id,NEW.execution_id,NEW.document_id,NEW.customer_recipient_id,NEW.retain_until)
    IS DISTINCT FROM ROW(OLD.org_id,OLD.execution_id,OLD.document_id,OLD.customer_recipient_id,OLD.retain_until)
    OR (OLD.state<>'retaining' AND NEW IS DISTINCT FROM OLD)
    OR (OLD.retention_started_at IS NOT NULL AND NEW.retention_started_at IS DISTINCT FROM OLD.retention_started_at)
    OR (OLD.retention_completed_at IS NOT NULL AND NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at) THEN
   RAISE EXCEPTION 'presign publication cannot reopen or replace evidence' USING ERRCODE='23514';
  END IF;
 END IF;
 SELECT * INTO STRICT e FROM presign_executions WHERE org_id=NEW.org_id AND id=NEW.execution_id;
 SELECT * INTO STRICT i FROM send_sealing_intents WHERE org_id=NEW.org_id AND document_id=e.document_id;
 SELECT * INTO STRICT d FROM documents WHERE org_id=NEW.org_id AND id=e.document_id;
 x:=convert_from(e.canonical_execution,'UTF8')::jsonb;
 SELECT * INTO STRICT r FROM recipients WHERE id=NEW.customer_recipient_id AND document_id=e.document_id;
 IF NEW.document_id<>e.document_id OR r.id::text IS DISTINCT FROM x->'document'->'parties'->0->>'id'
   OR r.role<>'customer' OR NEW.retain_until IS DISTINCT FROM i.retain_until OR i.presign_execution_id IS DISTINCT FROM e.id
   OR NEW.retention_started_at IS DISTINCT FROM i.retention_started_at
   OR NEW.retention_completed_at IS DISTINCT FROM i.retention_completed_at
   OR (NEW.retention_completed_at IS NOT NULL AND NEW.retention_completed_at<NEW.retention_started_at)
   OR (TG_OP='INSERT' AND NEW.state<>'retaining') THEN
  RAISE EXCEPTION 'presign publication differs from exact intent and customer' USING ERRCODE='23514';
 END IF;
 IF NEW.state='published' THEN
  SELECT * INTO STRICT ev FROM events WHERE id=NEW.publication_event_id;
  IF ev.org_id<>e.org_id OR ev.document_id IS DISTINCT FROM e.document_id OR ev.recipient_id IS DISTINCT FROM r.id
    OR ev.actor_user_id IS DISTINCT FROM e.executor_user_id OR ev.kind<>'presign.execution.published' OR octet_length(ev.row_hash) IS DISTINCT FROM 32
    OR convert_from(ev.payload_hashed,'UTF8')::jsonb IS DISTINCT FROM ev.payload_json
    OR jsonb_typeof(ev.payload_json) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(ev.payload_json))<>6
    OR ev.payload_json-ARRAY['execution_id','execution_sha256','visible_pdf_sha256','assets_sha256','customer_recipient_id','retain_until']<>'{}'::jsonb
    OR ev.payload_json->>'execution_sha256' IS DISTINCT FROM encode(e.execution_sha256,'hex')
    OR ev.payload_json->>'assets_sha256' IS DISTINCT FROM (SELECT encode(a.assets_sha256,'hex') FROM presign_execution_assets_v1 a WHERE a.org_id=e.org_id AND a.execution_id=e.id)
    OR ev.payload_json->>'customer_recipient_id' IS DISTINCT FROM r.id::text
    OR (ev.payload_json->>'retain_until')::timestamptz IS DISTINCT FROM NEW.retain_until
    OR ev.payload_json->>'execution_id' IS DISTINCT FROM e.id::text
    OR ev.payload_json->>'visible_pdf_sha256' IS DISTINCT FROM x->'visible_pdf'->'artifact'->>'sha256'
    OR r.sent_at IS NULL OR r.status NOT IN('sent','viewed','signed') OR d.status NOT IN('sent','in_progress','finalizing','completed','declined','voided','expired')
    OR NEW.published_at<NEW.retention_completed_at THEN
   RAISE EXCEPTION 'presign customer publication lacks actual audit and invitation' USING ERRCODE='23514';
  END IF;
 END IF;
 IF NEW.state='expired' AND (d.status<>'expired' OR r.sent_at IS NOT NULL OR r.first_viewed_at IS NOT NULL
   OR r.signed_at IS NOT NULL OR octet_length(r.magic_token_hash)<>0) THEN
  RAISE EXCEPTION 'expired pre-sign publication must never invite a customer' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
 RAISE EXCEPTION 'presign publication pairing is incomplete' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER presign_publication_guard116 BEFORE INSERT OR UPDATE OR DELETE ON presign_execution_publications_v1
 FOR EACH ROW EXECUTE FUNCTION hash_presign_publication116();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_supersession116() RETURNS trigger AS $$
DECLARE old_execution presign_executions%ROWTYPE; prior documents%ROWTYPE; fresh documents%ROWTYPE; ev events%ROWTYPE; birth html_document_creation_requests%ROWTYPE;
BEGIN
 SELECT * INTO STRICT old_execution FROM presign_executions WHERE org_id=NEW.org_id AND id=NEW.prior_execution_id;
 SELECT * INTO STRICT prior FROM documents WHERE org_id=NEW.org_id AND id=NEW.prior_document_id FOR UPDATE;
 SELECT * INTO STRICT fresh FROM documents WHERE org_id=NEW.org_id AND id=NEW.document_id FOR UPDATE;
 SELECT * INTO STRICT ev FROM events WHERE id=NEW.audit_event_id;
 SELECT * INTO STRICT birth FROM html_document_creation_requests WHERE org_id=NEW.org_id AND actor_user_id=NEW.actor_user_id AND request_id=NEW.request_id;
 IF old_execution.document_id<>prior.id OR prior.status NOT IN('declined','voided','expired','completed')
   OR fresh.status<>'draft' OR fresh.deleted_at IS NOT NULL OR fresh.parent_envelope_id IS NOT NULL OR fresh.is_envelope
   OR fresh.sender_id<>NEW.actor_user_id OR fresh.source_kind<>'pdf' OR NOT fresh.requires_signature OR fresh.routing_mode<>'parallel'
   OR fresh.signing_admission_policy<>'historical' OR fresh.template_id IS DISTINCT FROM prior.template_id
   OR fresh.html_current_materialization_id IS NULL OR fresh.html_current_materialization_id=prior.html_current_materialization_id
   OR fresh.html_current_materialization_sequence<>1 OR fresh.html_reviewed_at IS NOT NULL OR fresh.html_reviewed_by IS NOT NULL
   OR fresh.html_effective_source_commitment IS NULL OR fresh.html_effective_source_commitment=prior.html_effective_source_commitment
   OR NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.actor_user_id AND org_id=NEW.org_id AND (role='owner' OR (role='sender' AND prior.sender_id=NEW.actor_user_id)))
   OR birth.original_document_id<>fresh.id OR birth.current_document_id IS DISTINCT FROM fresh.id
   OR birth.template_id IS DISTINCT FROM fresh.template_id OR birth.html_materialization_id IS DISTINCT FROM fresh.html_current_materialization_id
   OR birth.html_source_commitment IS DISTINCT FROM fresh.html_effective_source_commitment OR birth.pdf_sha256 IS DISTINCT FROM fresh.pdf_sha256
   OR EXISTS(SELECT 1 FROM document_packages_v1 pkg JOIN document_attachment_drafts_v1 attachment ON attachment.package_id=pkg.id AND attachment.org_id=pkg.org_id WHERE pkg.org_id=NEW.org_id AND pkg.document_id=fresh.id)
   OR EXISTS(SELECT 1 FROM document_package_captures_v1 WHERE org_id=NEW.org_id AND document_id=fresh.id)
   OR EXISTS(SELECT 1 FROM document_package_send_attempts_v1 WHERE org_id=NEW.org_id AND document_id=fresh.id)
   OR EXISTS(SELECT 1 FROM document_attachment_drafts_v1 WHERE org_id=NEW.org_id AND member_document_id=fresh.id)
   OR EXISTS(SELECT 1 FROM document_package_capture_members_v1 WHERE org_id=NEW.org_id AND member_document_id=fresh.id)
   OR EXISTS(SELECT 1 FROM signatures WHERE document_id=fresh.id)
   OR EXISTS(SELECT 1 FROM recipients WHERE document_id=fresh.id AND (status<>'pending' OR sent_at IS NOT NULL OR first_viewed_at IS NOT NULL OR signed_at IS NOT NULL))
   OR (SELECT count(*) FROM recipients WHERE document_id=fresh.id)<>2
   OR (SELECT count(*) FROM document_fields WHERE document_id=fresh.id)<>2
   OR ev.org_id<>NEW.org_id OR ev.document_id IS DISTINCT FROM fresh.id OR ev.actor_user_id IS DISTINCT FROM NEW.actor_user_id
   OR ev.recipient_id IS NOT NULL OR ev.kind<>'presign.execution.superseded' OR octet_length(ev.row_hash) IS DISTINCT FROM 32
   OR convert_from(ev.payload_hashed,'UTF8')::jsonb IS DISTINCT FROM ev.payload_json
   OR jsonb_typeof(ev.payload_json) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(ev.payload_json))<>6
   OR ev.payload_json-ARRAY['prior_execution_id','prior_execution_sha256','prior_document_id','document_id','request_id','source_commitment']<>'{}'::jsonb
   OR ev.payload_json->>'prior_execution_id' IS DISTINCT FROM old_execution.id::text
   OR ev.payload_json->>'prior_execution_sha256' IS DISTINCT FROM encode(old_execution.execution_sha256,'hex')
   OR ev.payload_json->>'prior_document_id' IS DISTINCT FROM prior.id::text
   OR ev.payload_json->>'document_id' IS DISTINCT FROM fresh.id::text
   OR ev.payload_json->>'request_id' IS DISTINCT FROM NEW.request_id::text
   OR ev.payload_json->>'source_commitment' IS DISTINCT FROM fresh.html_effective_source_commitment THEN
  RAISE EXCEPTION 'pre-sign supersession requires fresh unreviewed ceremony and retained terminal original' USING ERRCODE='23514';
 END IF;
 PERFORM hash_check_presign_execution(prior.id,FALSE);
 PERFORM hash_check_branded_signing_page(fresh.id);
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
 RAISE EXCEPTION 'pre-sign supersession lineage is incomplete' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER presign_supersession_complete116 AFTER INSERT ON presign_supersessions_v1
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_presign_supersession116();



-- M79 remains the actual HTML birth/replay owner. This small relation binds
-- that real receipt to the original API credential and approved source command.
CREATE TABLE presign_source_requests_v1 (
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 executor_credential_id UUID NOT NULL CHECK(executor_credential_id<>'00000000-0000-0000-0000-000000000000'),
 request_id UUID NOT NULL CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
 executor_user_id UUID NOT NULL CHECK(executor_user_id<>'00000000-0000-0000-0000-000000000000'),
 original_credential_sha256 BYTEA NOT NULL CHECK(octet_length(original_credential_sha256)=32),
 state TEXT NOT NULL CHECK(state IN('committed','closed')),
 input_sha256 BYTEA CHECK(octet_length(input_sha256)=32),
 policy_id UUID, policy_revision BIGINT CHECK(policy_revision BETWEEN 1 AND 2147483647), policy_sha256 BYTEA CHECK(octet_length(policy_sha256)=32),
 grant_id UUID, grant_revision BIGINT CHECK(grant_revision BETWEEN 1 AND 2147483647), grant_sha256 BYTEA CHECK(octet_length(grant_sha256)=32),
 template_id UUID, template_version BIGINT CHECK(template_version BETWEEN 1 AND 2147483647), template_content_sha256 BYTEA CHECK(octet_length(template_content_sha256)=32),
 creation_request_id UUID, document_id UUID, original_document_updated_at TIMESTAMPTZ CHECK(original_document_updated_at IS NULL OR isfinite(original_document_updated_at)),
 materialization_id UUID, materialization_revision BIGINT CHECK(materialization_revision=1),
 source_commitment TEXT CHECK((source_commitment COLLATE "C") ~ '^[0-9a-f]{64}$'),
 base_pdf_key TEXT CHECK(hash_package_opaque_v1(base_pdf_key)), base_pdf_version_id TEXT CHECK(hash_package_opaque_v1(base_pdf_version_id)),
 base_pdf_sha256 BYTEA CHECK(octet_length(base_pdf_sha256)=32), page_count INTEGER CHECK(page_count BETWEEN 1 AND 500),
 close_event_id UUID REFERENCES events(id) DEFERRABLE INITIALLY DEFERRED,
 crm_bindings_sha256 BYTEA CHECK(crm_bindings_sha256 IS NULL OR octet_length(crm_bindings_sha256)=32),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 PRIMARY KEY(org_id,executor_credential_id,request_id),
 UNIQUE(document_id),
 FOREIGN KEY(org_id,executor_user_id,creation_request_id) REFERENCES html_document_creation_requests(org_id,actor_user_id,request_id) ON DELETE CASCADE,
 CHECK((state='closed' AND close_event_id IS NOT NULL AND
   ROW(input_sha256,policy_id,policy_revision,policy_sha256,grant_id,grant_revision,grant_sha256,template_id,template_version,template_content_sha256,
    creation_request_id,document_id,original_document_updated_at,materialization_id,materialization_revision,source_commitment,base_pdf_key,base_pdf_version_id,base_pdf_sha256,page_count,crm_bindings_sha256) IS NULL)
  OR (state='committed' AND close_event_id IS NULL AND creation_request_id=request_id AND
   ROW(input_sha256,policy_id,policy_revision,policy_sha256,grant_id,grant_revision,grant_sha256,template_id,template_version,template_content_sha256,
    creation_request_id,document_id,original_document_updated_at,materialization_id,materialization_revision,source_commitment,base_pdf_key,base_pdf_version_id,base_pdf_sha256,page_count) IS NOT NULL))
);
-- +goose StatementBegin
CREATE FUNCTION hash_presign_source_request116() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE h html_document_creation_requests%ROWTYPE;d documents%ROWTYPE;m html_document_materializations%ROWTYPE;ev events%ROWTYPE;
BEGIN
 IF NEW.state='closed' THEN
  SELECT * INTO STRICT ev FROM events WHERE id=NEW.close_event_id;
  IF ev.org_id<>NEW.org_id OR ev.actor_user_id IS DISTINCT FROM NEW.executor_user_id OR ev.document_id IS NOT NULL OR ev.recipient_id IS NOT NULL
   OR ev.kind<>'presign.source.request.closed' OR octet_length(ev.row_hash) IS DISTINCT FROM 32
   OR convert_from(ev.payload_hashed,'UTF8')::jsonb IS DISTINCT FROM ev.payload_json
   OR ev.payload_json IS DISTINCT FROM jsonb_build_object('request_id',NEW.request_id,'executor_credential_id',NEW.executor_credential_id) THEN
   RAISE EXCEPTION 'API source closure requires exact actual original request audit' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT h FROM html_document_creation_requests WHERE org_id=NEW.org_id AND actor_user_id=NEW.executor_user_id AND request_id=NEW.creation_request_id;
 SELECT * INTO STRICT d FROM documents WHERE id=h.original_document_id AND org_id=NEW.org_id;
 SELECT * INTO STRICT m FROM html_document_materializations WHERE id=h.html_materialization_id AND document_id=d.id AND org_id=d.org_id;
 IF h.input_digest IS DISTINCT FROM NEW.input_sha256 OR h.original_document_id<>NEW.document_id OR h.current_document_id IS DISTINCT FROM d.id
  OR h.template_id<>NEW.template_id OR h.html_materialization_id<>NEW.materialization_id OR h.html_source_commitment<>NEW.source_commitment
  OR h.pdf_sha256 IS DISTINCT FROM NEW.base_pdf_sha256 OR h.page_count<>NEW.page_count
  OR d.status<>'draft' OR d.deleted_at IS NOT NULL OR d.source_kind<>'pdf' OR NOT d.requires_signature OR d.is_envelope OR d.parent_envelope_id IS NOT NULL
  OR d.routing_mode<>'parallel' OR d.signing_admission_policy<>'historical' OR d.sender_id<>NEW.executor_user_id OR d.updated_at IS DISTINCT FROM NEW.original_document_updated_at
  OR d.html_current_materialization_id IS DISTINCT FROM m.id OR m.sequence<>1 OR m.sequence<>NEW.materialization_revision
  OR m.pdf_key<>NEW.base_pdf_key OR m.pdf_version_id<>NEW.base_pdf_version_id OR m.pdf_sha256 IS DISTINCT FROM NEW.base_pdf_sha256
  OR encode(m.source_commitment,'hex')<>NEW.source_commitment OR m.page_count<>NEW.page_count
  OR NOT EXISTS(SELECT 1 FROM presign_workflow_revisions p JOIN presign_grant_revisions g
   ON g.org_id=p.org_id AND g.policy_id=p.policy_id AND g.policy_revision=p.revision AND g.policy_sha256=p.policy_sha256
   WHERE p.org_id=NEW.org_id AND p.policy_id=NEW.policy_id AND p.revision=NEW.policy_revision AND p.policy_sha256=NEW.policy_sha256
    AND g.grant_id=NEW.grant_id AND g.revision=NEW.grant_revision AND g.grant_sha256=NEW.grant_sha256
    AND p.template_id=NEW.template_id AND p.template_version=NEW.template_version AND p.template_content_sha256=NEW.template_content_sha256
    AND convert_from(p.canonical_policy,'UTF8')::jsonb->'executor'=jsonb_build_object('kind','api_key','user_id',NEW.executor_user_id,'credential_id',NEW.executor_credential_id)
    AND convert_from(p.canonical_policy,'UTF8')::jsonb#>>'{rules,input_mode}'='approved_data'
    AND ((convert_from(p.canonical_definition,'UTF8')::jsonb#>'{data_rules,crm}' IS NULL
      OR convert_from(p.canonical_definition,'UTF8')::jsonb#>'{data_rules,crm}'='null'::jsonb)=(NEW.crm_bindings_sha256 IS NULL))) THEN
  RAISE EXCEPTION 'API source receipt differs from exact owned approved schema3 birth' USING ERRCODE='23514';
 END IF;
 PERFORM hash_check_branded_signing_page(d.id);
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN RAISE EXCEPTION 'API source receipt is incomplete' USING ERRCODE='23514';
END $$;
CREATE FUNCTION hash_presign_source_immutable116() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP='DELETE' AND NOT EXISTS(SELECT 1 FROM orgs WHERE id=OLD.org_id) THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'API source request is immutable' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER presign_source_complete116 AFTER INSERT ON presign_source_requests_v1 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_presign_source_request116();
CREATE TRIGGER presign_source_immutable116 BEFORE UPDATE OR DELETE ON presign_source_requests_v1 FOR EACH ROW EXECUTE FUNCTION hash_presign_source_immutable116();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION hash_guard_amendment_policy_insert_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE d documents%ROWTYPE;b JSONB;source JSONB;
BEGIN

 -- An explicitly committed pre-sign execution owns its own immutable source
 -- and approved-data/review evidence. This branch does not relabel it human.
 IF EXISTS(SELECT 1 FROM presign_executions WHERE org_id=NEW.org_id AND document_id=NEW.document_id) THEN
  SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE NOWAIT;
  PERFORM hash_check_presign_execution(d.id,FALSE);
  source:=COALESCE(d.html_current_source_json,d.html_source_json);b:=convert_from(NEW.basis,'UTF8')::jsonb;
  IF d.status<>'sealing' OR d.source_kind<>'pdf' OR d.is_envelope OR d.parent_envelope_id IS NOT NULL OR d.deleted_at IS NOT NULL
   OR source IS NULL OR source->>'schema_version' IS DISTINCT FROM '3'
   OR NEW.presented_pdf_sha256 IS DISTINCT FROM d.pdf_sha256 OR NEW.presented_pdf_version_id IS DISTINCT FROM d.pdf_storage_version_id
   OR NEW.presented_source_sha256 IS DISTINCT FROM decode(source->>'commitment','hex')
   OR b->>'kind' IS DISTINCT FROM 'frozen_agreement_policy' OR b->>'frozen_policy_id' IS DISTINCT FROM NEW.id::text
   OR hash_amendment_policy_source_matches_v1(source,b) IS DISTINCT FROM TRUE
   OR NOT EXISTS(SELECT 1 FROM presign_executions e JOIN presign_execution_assets_v1 a ON a.org_id=e.org_id AND a.execution_id=e.id AND a.document_id=e.document_id
     JOIN presign_execution_publications_v1 p ON p.org_id=e.org_id AND p.execution_id=e.id AND p.document_id=e.document_id
     JOIN send_sealing_intents i ON i.org_id=e.org_id AND i.document_id=e.document_id AND i.presign_execution_id=e.id
     WHERE e.org_id=d.org_id AND e.document_id=d.id AND e.executor_user_id=NEW.frozen_by
      AND p.state='retaining' AND p.retention_started_at IS NOT NULL AND p.retention_completed_at IS NOT NULL
      AND p.retention_started_at=i.retention_started_at AND p.retention_completed_at=i.retention_completed_at AND p.retain_until=i.retain_until) THEN
   RAISE EXCEPTION 'pre-sign policy freeze requires exact retained committed source and execution' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
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
-- +goose StatementEnd


-- Extend only the native fresh finalization selection. Old V1/V2 bytes,
-- defaults and retained clocks remain immutable. A delegated document cannot
-- silently enter V2 if its explicit publication relation is incomplete.
ALTER TABLE public.documents DROP CONSTRAINT documents_participant_report_schema_check;
ALTER TABLE public.documents ADD CONSTRAINT documents_participant_report_schema_check CHECK(participant_report_schema IN ('hash-participant-report-v1','hash-participant-report-v2','hash-participant-report-v3'));
ALTER TABLE public.document_ordinary_finalization_preparations_v1 DROP CONSTRAINT ordinary_finalization_report_schema_check;
ALTER TABLE public.document_ordinary_finalization_preparations_v1 ADD CONSTRAINT ordinary_finalization_report_schema_check CHECK(report_schema IN ('hash-participant-report-v1','hash-participant-report-v2','hash-participant-report-v3'));
ALTER TABLE public.document_participant_reports_v1 DROP CONSTRAINT document_participant_reports_v1_schema_version_check;
ALTER TABLE public.document_participant_reports_v1 ADD CONSTRAINT document_participant_reports_v1_schema_version_check CHECK(schema_version IN ('hash-participant-report-v1','hash-participant-report-v2','hash-participant-report-v3'));
-- +goose StatementBegin
CREATE FUNCTION public.hash_presign_report_schema116(target_org UUID,target_document UUID) RETURNS TEXT
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE e public.presign_executions%ROWTYPE;
BEGIN
 SELECT * INTO e FROM public.presign_executions WHERE org_id=target_org AND document_id=target_document;
 IF NOT FOUND THEN RETURN 'hash-participant-report-v2'; END IF;
 PERFORM public.hash_check_presign_execution(target_document,FALSE);
 IF NOT EXISTS(SELECT 1 FROM public.presign_execution_publications_v1 p
   JOIN public.presign_execution_assets_v1 a ON a.org_id=p.org_id AND a.execution_id=p.execution_id AND a.document_id=p.document_id
   JOIN public.send_sealing_intents i ON i.org_id=p.org_id AND i.document_id=p.document_id AND i.presign_execution_id=p.execution_id
   WHERE p.org_id=target_org AND p.document_id=target_document AND p.execution_id=e.id AND p.state='published'
    AND p.publication_event_id IS NOT NULL AND p.published_at IS NOT NULL
    AND p.retention_started_at IS NOT NULL AND p.retention_completed_at IS NOT NULL
    AND p.retain_until=i.retain_until AND p.retention_started_at=i.retention_started_at AND p.retention_completed_at=i.retention_completed_at) THEN
  RAISE EXCEPTION 'delegated finalization requires exact committed published retained execution' USING ERRCODE='23514';
 END IF;
 RETURN 'hash-participant-report-v3';
END $$;
CREATE OR REPLACE FUNCTION public.hash_guard_document_report_schema_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE parent_schema TEXT;parent_is_envelope BOOLEAN;parent_root UUID;parent_deleted TIMESTAMPTZ;
 parent_status TEXT;parent_bound BOOLEAN;parent_clock TIMESTAMPTZ;parent_retain TIMESTAMPTZ;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.parent_envelope_id IS NULL THEN
   IF NEW.participant_report_schema IS DISTINCT FROM 'hash-participant-report-v2' THEN
    RAISE EXCEPTION 'new root requires current participant report selection' USING ERRCODE='23514';
   END IF;
  ELSE
   -- Normal native envelope creation owns root first. TRY locking also makes
   -- a caller holding only a child refuse a busy root instead of inverting it.
   SELECT d.participant_report_schema,d.is_envelope,d.parent_envelope_id,d.deleted_at,d.status,
    d.completion_effective_at_bound,d.completion_effective_at,d.finalization_retain_until
    INTO STRICT parent_schema,parent_is_envelope,parent_root,parent_deleted,parent_status,parent_bound,parent_clock,parent_retain
    FROM public.documents d WHERE d.id=NEW.parent_envelope_id AND d.org_id=NEW.org_id FOR SHARE OF d NOWAIT;
   IF NOT parent_is_envelope OR parent_root IS NOT NULL OR parent_deleted IS NOT NULL THEN
    RAISE EXCEPTION 'participant report child root differs' USING ERRCODE='23514';
   END IF;
   NEW.participant_report_schema:=parent_schema;
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.status IN ('finalizing','completed') OR OLD.completion_effective_at IS NOT NULL THEN
  IF NEW.participant_report_schema IS DISTINCT FROM OLD.participant_report_schema THEN
   RAISE EXCEPTION 'retained participant report selection is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ((NEW.parent_envelope_id IS NULL AND OLD.status='in_progress')
  OR (NEW.parent_envelope_id IS NOT NULL AND OLD.status IN ('sent','in_progress'))) AND NEW.status='finalizing'
  AND OLD.completion_effective_at IS NULL AND OLD.completion_effective_at_bound
  AND NEW.completion_effective_at_bound AND NEW.completion_effective_at IS NOT NULL
  AND isfinite(NEW.completion_effective_at) THEN
  IF NEW.parent_envelope_id IS NULL THEN
   IF NEW.participant_report_schema IS DISTINCT FROM public.hash_presign_report_schema116(NEW.org_id,NEW.id) THEN
    RAISE EXCEPTION 'fresh finalization requires exact ordinary or delegated report selection' USING ERRCODE='23514';
   END IF;
  ELSE
   SELECT d.participant_report_schema,d.is_envelope,d.parent_envelope_id,d.deleted_at,d.status,
    d.completion_effective_at_bound,d.completion_effective_at,d.finalization_retain_until
    INTO STRICT parent_schema,parent_is_envelope,parent_root,parent_deleted,parent_status,parent_bound,parent_clock,parent_retain
    FROM public.documents d WHERE d.id=NEW.parent_envelope_id AND d.org_id=NEW.org_id FOR SHARE OF d NOWAIT;
   IF NOT parent_is_envelope OR parent_root IS NOT NULL OR parent_deleted IS NOT NULL
    OR parent_status<>'finalizing' OR NOT parent_bound
    OR parent_clock IS DISTINCT FROM NEW.completion_effective_at
    OR parent_retain IS DISTINCT FROM NEW.finalization_retain_until
    OR NEW.participant_report_schema IS DISTINCT FROM parent_schema THEN
    RAISE EXCEPTION 'child participant report selection differs from frozen root' USING ERRCODE='23514';
   END IF;
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.status='finalizing' AND OLD.status<>'finalizing' THEN
  RAISE EXCEPTION 'participant report selection requires supported fresh native transition' USING ERRCODE='23514';
 END IF;
 IF NEW.participant_report_schema IS DISTINCT FROM OLD.participant_report_schema THEN
  RAISE EXCEPTION 'participant report selection changes only at fresh native finalization' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM presign_source_requests_v1) OR EXISTS(SELECT 1 FROM presign_preparations_v1) OR EXISTS(SELECT 1 FROM presign_execution_assets_v1)
   OR EXISTS(SELECT 1 FROM presign_execution_publications_v1) OR EXISTS(SELECT 1 FROM presign_supersessions_v1) THEN
  RAISE EXCEPTION 'presign integration records forbid rollback; use qualified paired restoration' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION hash_guard_amendment_policy_insert_v1() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
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
-- +goose StatementEnd

-- Restore the original M113 guard bytes only after the no-history fence.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.hash_guard_document_report_schema_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE parent_schema TEXT;parent_is_envelope BOOLEAN;parent_root UUID;parent_deleted TIMESTAMPTZ;
 parent_status TEXT;parent_bound BOOLEAN;parent_clock TIMESTAMPTZ;parent_retain TIMESTAMPTZ;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.parent_envelope_id IS NULL THEN
   IF NEW.participant_report_schema IS DISTINCT FROM 'hash-participant-report-v2' THEN
    RAISE EXCEPTION 'new root requires current participant report selection' USING ERRCODE='23514';
   END IF;
  ELSE
   -- Normal native envelope creation owns root first. TRY locking also makes
   -- a caller holding only a child refuse a busy root instead of inverting it.
   SELECT d.participant_report_schema,d.is_envelope,d.parent_envelope_id,d.deleted_at,d.status,
    d.completion_effective_at_bound,d.completion_effective_at,d.finalization_retain_until
    INTO STRICT parent_schema,parent_is_envelope,parent_root,parent_deleted,parent_status,parent_bound,parent_clock,parent_retain
    FROM public.documents d WHERE d.id=NEW.parent_envelope_id AND d.org_id=NEW.org_id FOR SHARE OF d NOWAIT;
   IF NOT parent_is_envelope OR parent_root IS NOT NULL OR parent_deleted IS NOT NULL THEN
    RAISE EXCEPTION 'participant report child root differs' USING ERRCODE='23514';
   END IF;
   NEW.participant_report_schema:=parent_schema;
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.status IN ('finalizing','completed') OR OLD.completion_effective_at IS NOT NULL THEN
  IF NEW.participant_report_schema IS DISTINCT FROM OLD.participant_report_schema THEN
   RAISE EXCEPTION 'retained participant report selection is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ((NEW.parent_envelope_id IS NULL AND OLD.status='in_progress')
  OR (NEW.parent_envelope_id IS NOT NULL AND OLD.status IN ('sent','in_progress'))) AND NEW.status='finalizing'
  AND OLD.completion_effective_at IS NULL AND OLD.completion_effective_at_bound
  AND NEW.completion_effective_at_bound AND NEW.completion_effective_at IS NOT NULL
  AND isfinite(NEW.completion_effective_at) THEN
  IF NEW.parent_envelope_id IS NULL THEN
   IF NEW.participant_report_schema IS DISTINCT FROM 'hash-participant-report-v2' THEN
    RAISE EXCEPTION 'fresh finalization requires current participant report selection' USING ERRCODE='23514';
   END IF;
  ELSE
   SELECT d.participant_report_schema,d.is_envelope,d.parent_envelope_id,d.deleted_at,d.status,
    d.completion_effective_at_bound,d.completion_effective_at,d.finalization_retain_until
    INTO STRICT parent_schema,parent_is_envelope,parent_root,parent_deleted,parent_status,parent_bound,parent_clock,parent_retain
    FROM public.documents d WHERE d.id=NEW.parent_envelope_id AND d.org_id=NEW.org_id FOR SHARE OF d NOWAIT;
   IF NOT parent_is_envelope OR parent_root IS NOT NULL OR parent_deleted IS NOT NULL
    OR parent_status<>'finalizing' OR NOT parent_bound
    OR parent_clock IS DISTINCT FROM NEW.completion_effective_at
    OR parent_retain IS DISTINCT FROM NEW.finalization_retain_until
    OR NEW.participant_report_schema IS DISTINCT FROM parent_schema THEN
    RAISE EXCEPTION 'child participant report selection differs from frozen root' USING ERRCODE='23514';
   END IF;
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.status='finalizing' AND OLD.status<>'finalizing' THEN
  RAISE EXCEPTION 'participant report selection requires supported fresh native transition' USING ERRCODE='23514';
 END IF;
 IF NEW.participant_report_schema IS DISTINCT FROM OLD.participant_report_schema THEN
  RAISE EXCEPTION 'participant report selection changes only at fresh native finalization' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
ALTER TABLE public.documents DROP CONSTRAINT documents_participant_report_schema_check;
ALTER TABLE public.documents ADD CONSTRAINT documents_participant_report_schema_check CHECK(participant_report_schema IN ('hash-participant-report-v1','hash-participant-report-v2'));
ALTER TABLE public.document_ordinary_finalization_preparations_v1 DROP CONSTRAINT ordinary_finalization_report_schema_check;
ALTER TABLE public.document_ordinary_finalization_preparations_v1 ADD CONSTRAINT ordinary_finalization_report_schema_check CHECK(report_schema IN ('hash-participant-report-v1','hash-participant-report-v2'));
ALTER TABLE public.document_participant_reports_v1 DROP CONSTRAINT document_participant_reports_v1_schema_version_check;
ALTER TABLE public.document_participant_reports_v1 ADD CONSTRAINT document_participant_reports_v1_schema_version_check CHECK(schema_version IN ('hash-participant-report-v1','hash-participant-report-v2'));
DROP FUNCTION public.hash_presign_report_schema116(UUID,UUID);

DROP TABLE presign_source_requests_v1;
DROP FUNCTION hash_presign_source_request116(),hash_presign_source_immutable116();
DROP TRIGGER presign_draft_lifecycle116 ON documents;
DROP FUNCTION hash_presign_draft_lifecycle116();
DROP TABLE presign_supersessions_v1,presign_execution_publications_v1,presign_execution_assets_v1,
 presign_preparation_objects_v1,presign_preparations_v1;
DROP FUNCTION hash_presign_publication116();
DROP FUNCTION hash_presign_preparation116();
DROP FUNCTION hash_presign_assets116();
DROP FUNCTION hash_presign_supersession116();
