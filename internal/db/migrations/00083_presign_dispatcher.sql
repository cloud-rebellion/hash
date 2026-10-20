-- +goose Up
-- Actual dispatch has a distinct immutable intent/artifact companion. Old
-- migration82 supporting records are not backfilled with fabricated archives.
CREATE TABLE presign_dispatcher_executions (
 org_id UUID NOT NULL,
 execution_id UUID NOT NULL,
 execution_sha256 BYTEA NOT NULL CHECK(octet_length(execution_sha256)=32),
 executor_kind TEXT NOT NULL CHECK(executor_kind IN ('member','api_key')),
 executor_user_id UUID NOT NULL,
 executor_credential_id UUID NOT NULL,
 request_id UUID NOT NULL,
 command_sha256 BYTEA NOT NULL CHECK(octet_length(command_sha256)=32),
 intent_canonical BYTEA NOT NULL CHECK(octet_length(intent_canonical) BETWEEN 1 AND 16384),
 intent_sha256 BYTEA NOT NULL CHECK(octet_length(intent_sha256)=32),
 manifest_canonical BYTEA NOT NULL CHECK(octet_length(manifest_canonical) BETWEEN 1 AND 32768),
 manifest_sha256 BYTEA NOT NULL CHECK(octet_length(manifest_sha256)=32),
 manifest_object_key TEXT NOT NULL CHECK(octet_length(manifest_object_key) BETWEEN 1 AND 1024),
 manifest_object_version_id TEXT NOT NULL CHECK(octet_length(manifest_object_version_id) BETWEEN 1 AND 1024 AND manifest_object_version_id<>'null'),
 manifest_object_sha256 BYTEA NOT NULL CHECK(octet_length(manifest_object_sha256)=32),
 manifest_object_bytes BIGINT NOT NULL CHECK(manifest_object_bytes=octet_length(manifest_canonical)),
 document_name TEXT NOT NULL CHECK(btrim(document_name)<>''),
 controller_name TEXT NOT NULL CHECK(btrim(controller_name)<>''),
 controller_contact TEXT NOT NULL CHECK(btrim(controller_contact)<>''),
 confirmed_at TIMESTAMPTZ NOT NULL CHECK(isfinite(confirmed_at)),
 PRIMARY KEY(org_id,execution_id),
 UNIQUE(org_id,executor_kind,executor_user_id,executor_credential_id,request_id),
 FOREIGN KEY(org_id,executor_kind,executor_user_id,executor_credential_id,request_id,execution_id,execution_sha256)
  REFERENCES presign_executions(org_id,executor_kind,executor_user_id,executor_credential_id,request_id,id,execution_sha256) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER presign_dispatcher_immutable BEFORE UPDATE OR DELETE ON presign_dispatcher_executions FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_dispatcher_keys(v JSONB, required TEXT[]) RETURNS BOOLEAN AS $$
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'object' THEN RETURN FALSE; END IF;
 RETURN (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(v) key)
        IS NOT DISTINCT FROM (SELECT array_agg(key ORDER BY key) FROM unnest(required) key);
END;
$$ LANGUAGE plpgsql IMMUTABLE;
CREATE FUNCTION hash_presign_dispatcher_sha(v JSONB) RETURNS BOOLEAN AS $$
BEGIN
 RETURN jsonb_typeof(v)='string' AND (v#>>'{}') COLLATE "C" ~ '^[0-9a-f]{64}$';
END;
$$ LANGUAGE plpgsql IMMUTABLE;
CREATE FUNCTION hash_presign_dispatcher_integer(v JSONB,lo BIGINT,hi BIGINT) RETURNS BOOLEAN AS $$
DECLARE text_value TEXT;
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'number' THEN RETURN FALSE; END IF;
 text_value:=v#>>'{}';
 IF octet_length(text_value)>19 OR text_value COLLATE "C" !~ '^(0|[1-9][0-9]*)$' THEN RETURN FALSE; END IF;
 RETURN text_value::numeric BETWEEN lo AND hi;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
CREATE FUNCTION hash_presign_dispatcher_unique_json(v JSON) RETURNS BOOLEAN AS $$
DECLARE item JSON;
BEGIN
 IF json_typeof(v)='object' THEN
  IF (SELECT count(*)<>count(DISTINCT key) FROM json_each(v)) THEN RETURN FALSE; END IF;
  FOR item IN SELECT value FROM json_each(v) LOOP IF NOT hash_presign_dispatcher_unique_json(item) THEN RETURN FALSE; END IF; END LOOP;
 ELSIF json_typeof(v)='array' THEN
  FOR item IN SELECT value FROM json_array_elements(v) LOOP IF NOT hash_presign_dispatcher_unique_json(item) THEN RETURN FALSE; END IF; END LOOP;
 END IF;
 RETURN TRUE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
CREATE FUNCTION hash_presign_dispatcher_pin(v JSONB,max_bytes BIGINT) RETURNS BOOLEAN AS $$
DECLARE part TEXT;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['storage_key','version_id','sha256','bytes']) THEN RETURN FALSE; END IF;
 IF jsonb_typeof(v->'storage_key') IS DISTINCT FROM 'string' OR jsonb_typeof(v->'version_id') IS DISTINCT FROM 'string'
    OR octet_length(v->>'storage_key') NOT BETWEEN 1 AND 1024 OR octet_length(v->>'version_id') NOT BETWEEN 1 AND 1024
    OR v->>'version_id'='null' OR (v->>'version_id') COLLATE "C" !~ '^[!-~]+$'
    OR NOT COALESCE(hash_presign_dispatcher_sha(v->'sha256'),FALSE)
    OR NOT COALESCE(hash_presign_dispatcher_integer(v->'bytes',1,max_bytes),FALSE) THEN RETURN FALSE; END IF;
 FOREACH part IN ARRAY string_to_array(v->>'storage_key','/') LOOP
  IF part IN ('','.','..') OR part COLLATE "C" !~ '^[A-Za-z0-9_.-]+$' THEN RETURN FALSE; END IF;
 END LOOP;
 RETURN TRUE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Validate the full new archive protocol, including required observations.
-- These checks establish immutable descriptor integrity, not a PDF reparse,
-- storage readback, fresh grant permission or proof of a human privacy action.
CREATE FUNCTION hash_validate_presign_dispatcher_manifest(m JSONB) RETURNS VOID AS $$
DECLARE key TEXT; pin JSONB; proof JSONB; report JSONB; pdf JSONB; properties JSONB;
        form JSONB; coordinate JSONB; position INTEGER; expected_rect JSONB; keys TEXT[]:=ARRAY[]::TEXT[];
        property_keys TEXT[]:=ARRAY['info_dictionary','xmp_metadata','object_streams','linearization','embedded_files','acroform','annotations'];
        property_names TEXT[]:=ARRAY['source_info_dictionary','xmp_metadata','object_streams','linearization','embedded_files','acroform','annotations'];
        removed JSONB:='[]'::jsonb; absent JSONB:='[]'::jsonb; generated JSONB:='[]'::jsonb;
        binding_bytes BYTEA; prefix TEXT; suffix TEXT;
BEGIN
 IF NOT hash_presign_dispatcher_keys(m,ARRAY['schema_version','org_id','document_id','materialization','signing_plan_sha256','branding_sha256','policy','grant','style','base_pdf','span','signature_font','inter_font','disclosure_text','disclosure_version','disclosure_sha256','render_recipe','signature_fragment_pdf','disclosure_fragment_pdf','visible_pdf','worker_proof','metadata_report']) THEN
  RAISE EXCEPTION 'delegated artifact manifest keys are invalid' USING ERRCODE='23514';
 END IF;
 IF NOT COALESCE(hash_presign_dispatcher_integer(m->'schema_version',1,1),FALSE) OR NOT COALESCE(hash_presign_dispatcher_integer(m->'disclosure_version',1,1),FALSE) THEN
  RAISE EXCEPTION 'delegated manifest version type is invalid' USING ERRCODE='23514';
 END IF;
 FOREACH key IN ARRAY ARRAY['signing_plan_sha256','branding_sha256','disclosure_sha256'] LOOP
  IF NOT COALESCE(hash_presign_dispatcher_sha(m->key),FALSE) THEN RAISE EXCEPTION 'delegated manifest hash is invalid' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF NOT hash_presign_dispatcher_keys(m->'materialization',ARRAY['id','revision','source_commitment']) OR NOT COALESCE(hash_presign_dispatcher_integer(m->'materialization'->'revision',1,1000000),FALSE)
    OR NOT COALESCE(hash_presign_dispatcher_sha(m->'materialization'->'source_commitment'),FALSE) THEN
  RAISE EXCEPTION 'delegated materialization pin is invalid' USING ERRCODE='23514';
 END IF;
 FOREACH key IN ARRAY ARRAY['policy','grant'] LOOP
  IF NOT hash_presign_dispatcher_keys(m->key,ARRAY['id','revision','sha256']) OR NOT COALESCE(hash_presign_dispatcher_integer(m->key->'revision',1,1000000),FALSE) OR NOT COALESCE(hash_presign_dispatcher_sha(m->key->'sha256'),FALSE) THEN
   RAISE EXCEPTION 'delegated authority pin is invalid' USING ERRCODE='23514';
  END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['base_pdf','visible_pdf'] LOOP
  IF NOT hash_presign_dispatcher_keys(m->key,ARRAY['artifact','pages']) OR NOT COALESCE(hash_presign_dispatcher_integer(m->key->'pages',1,500),FALSE) THEN
   RAISE EXCEPTION 'delegated PDF pin shape is invalid' USING ERRCODE='23514';
  END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['base_pdf','span','signature_font','inter_font','disclosure_text','render_recipe','signature_fragment_pdf','disclosure_fragment_pdf','visible_pdf'] LOOP
  pin:=m->key;
  IF key IN ('base_pdf','visible_pdf') THEN pin:=pin->'artifact'; END IF;
  IF NOT hash_presign_dispatcher_pin(pin,CASE WHEN key IN ('span','signature_font','inter_font','disclosure_text','render_recipe') THEN 1048576 ELSE 52428800 END) THEN
   RAISE EXCEPTION 'delegated archive pin is invalid' USING ERRCODE='23514';
  END IF;
  IF pin->>'storage_key'=ANY(keys) THEN RAISE EXCEPTION 'delegated archive keys alias' USING ERRCODE='23514'; END IF;
  keys:=array_append(keys,pin->>'storage_key');
 END LOOP;
 IF (m->'span'->>'storage_key') COLLATE "C" !~ ('^org/'||(m->>'org_id')||'/documents/'||(m->>'document_id')||'/presign-prepared/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/signature[.]html$') THEN
  RAISE EXCEPTION 'delegated archive ownership prefix is invalid' USING ERRCODE='23514';
 END IF;
 prefix:=left(m->'span'->>'storage_key',length(m->'span'->>'storage_key')-length('signature.html'));
 FOREACH key IN ARRAY ARRAY['signature_font','inter_font','disclosure_text','render_recipe','signature_fragment_pdf','disclosure_fragment_pdf','visible_pdf'] LOOP
  suffix:=CASE key WHEN 'signature_font' THEN 'signature.woff2' WHEN 'inter_font' THEN 'inter.woff2' WHEN 'disclosure_text' THEN 'disclosure.txt' WHEN 'render_recipe' THEN 'recipe.json' WHEN 'signature_fragment_pdf' THEN 'signature-fragment.pdf' WHEN 'disclosure_fragment_pdf' THEN 'disclosure-fragment.pdf' ELSE 'provider-visible.pdf' END;
  pin:=m->key; IF key='visible_pdf' THEN pin:=pin->'artifact'; END IF;
  IF pin->>'storage_key' IS DISTINCT FROM prefix||suffix THEN RAISE EXCEPTION 'delegated archive ownership paths are inconsistent' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF NOT hash_presign_dispatcher_keys(m->'style',ARRAY['font','font_sha256']) OR jsonb_typeof(m->'style'->'font') IS DISTINCT FROM 'string'
    OR COALESCE(m->'style'->>'font','') NOT IN ('Caveat','Dancing Script','Great Vibes','Sacramento','Homemade Apple')
    OR NOT COALESCE(hash_presign_dispatcher_sha(m->'style'->'font_sha256'),FALSE) OR m->'style'->>'font_sha256' IS DISTINCT FROM m->'signature_font'->>'sha256'
    OR m->'base_pdf'->>'pages' IS DISTINCT FROM m->'visible_pdf'->>'pages'
    OR m->'base_pdf'->'artifact'->>'sha256'=m->'visible_pdf'->'artifact'->>'sha256' THEN
  RAISE EXCEPTION 'delegated manifest style or PDF tuple is invalid' USING ERRCODE='23514';
 END IF;
 proof:=m->'worker_proof';
 IF NOT hash_presign_dispatcher_keys(proof,ARRAY['schema_version','policy','bindings_sha256','base_sha256','base_bytes','signature_sha256','disclosure_sha256','processing_sha256','processing_bytes','output_sha256','output_bytes','pages','geometry_sha256','original_content_sha256','forms'])
    OR NOT COALESCE(hash_presign_dispatcher_integer(proof->'schema_version',1,1),FALSE) OR NOT COALESCE(hash_presign_dispatcher_integer(proof->'pages',1,500),FALSE) OR proof->>'policy' IS DISTINCT FROM 'hash-provider-confined-overlay-v1' THEN
  RAISE EXCEPTION 'delegated worker proof shape is invalid' USING ERRCODE='23514';
 END IF;
 FOREACH key IN ARRAY ARRAY['bindings_sha256','base_sha256','signature_sha256','disclosure_sha256','processing_sha256','output_sha256','geometry_sha256','original_content_sha256'] LOOP
  IF NOT COALESCE(hash_presign_dispatcher_sha(proof->key),FALSE) THEN RAISE EXCEPTION 'delegated worker proof hash is invalid' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['base_bytes','processing_bytes','output_bytes'] LOOP
  IF NOT COALESCE(hash_presign_dispatcher_integer(proof->key,1,52428800),FALSE) THEN RAISE EXCEPTION 'delegated worker proof bound is invalid' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF proof->>'base_sha256' IS DISTINCT FROM m->'base_pdf'->'artifact'->>'sha256' OR proof->>'base_bytes' IS DISTINCT FROM m->'base_pdf'->'artifact'->>'bytes'
    OR proof->>'output_sha256' IS DISTINCT FROM m->'visible_pdf'->'artifact'->>'sha256' OR proof->>'output_bytes' IS DISTINCT FROM m->'visible_pdf'->'artifact'->>'bytes'
    OR proof->>'pages' IS DISTINCT FROM m->'base_pdf'->>'pages' OR proof->>'signature_sha256' IS DISTINCT FROM m->'signature_fragment_pdf'->>'sha256'
    OR proof->>'disclosure_sha256' IS DISTINCT FROM m->'disclosure_fragment_pdf'->>'sha256' THEN
  RAISE EXCEPTION 'delegated worker proof pins are inconsistent' USING ERRCODE='23514';
 END IF;
 -- Known strings are validated hex or the fixed font allowlist, so this is the
 -- exact Go struct-order encoding; jsonb::text would introduce another domain.
 binding_bytes:=convert_to(format('{"source_commitment":"%s","signing_plan_sha256":"%s","branding_sha256":"%s","policy_sha256":"%s","grant_sha256":"%s","font":"%s","span_sha256":"%s","signature_font_sha256":"%s","inter_font_sha256":"%s","disclosure_sha256":"%s","recipe_sha256":"%s"}',
  m->'materialization'->>'source_commitment',m->>'signing_plan_sha256',m->>'branding_sha256',m->'policy'->>'sha256',m->'grant'->>'sha256',m->'style'->>'font',m->'span'->>'sha256',m->'signature_font'->>'sha256',m->'inter_font'->>'sha256',m->>'disclosure_sha256',m->'render_recipe'->>'sha256'),'UTF8');
 IF proof->>'bindings_sha256' IS DISTINCT FROM encode(digest(convert_to('hash:presign-provider-worker-bindings:v1','UTF8')||decode('00','hex')||binding_bytes,'sha256'),'hex') THEN
  RAISE EXCEPTION 'delegated worker bindings are inconsistent' USING ERRCODE='23514';
 END IF;
 IF jsonb_typeof(proof->'forms') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'delegated forms are missing' USING ERRCODE='23514'; END IF;
 IF jsonb_array_length(proof->'forms')<>2 THEN RAISE EXCEPTION 'delegated form count is invalid' USING ERRCODE='23514'; END IF;
 FOR position IN 0..1 LOOP
  form:=proof->'forms'->position;
  expected_rect:=CASE WHEN position=0 THEN '[61495996,119868797,471967968,54934399]'::jsonb ELSE '[59495996,71563198,475967968,25257599]'::jsonb END;
  IF NOT hash_presign_dispatcher_keys(form,ARRAY['slot','rectangle_micro_points','content_sha256','resources_sha256','fragment_geometry_sha256'])
    OR form->>'slot' IS DISTINCT FROM (CASE WHEN position=0 THEN 'provider_signature' ELSE 'provider_disclosure' END)
    OR form->'rectangle_micro_points' IS DISTINCT FROM expected_rect
    OR NOT COALESCE(hash_presign_dispatcher_sha(form->'content_sha256'),FALSE) OR NOT COALESCE(hash_presign_dispatcher_sha(form->'resources_sha256'),FALSE)
    OR NOT COALESCE(hash_presign_dispatcher_sha(form->'fragment_geometry_sha256'),FALSE) THEN
   RAISE EXCEPTION 'delegated confined form proof is invalid' USING ERRCODE='23514';
  END IF;
  FOR coordinate IN SELECT value FROM jsonb_array_elements(form->'rectangle_micro_points') LOOP
   IF NOT COALESCE(hash_presign_dispatcher_integer(coordinate,0,9007199254740991),FALSE) THEN
    RAISE EXCEPTION 'delegated form coordinate type is invalid' USING ERRCODE='23514';
   END IF;
  END LOOP;
 END LOOP;
 report:=m->'metadata_report';
 IF NOT hash_presign_dispatcher_keys(report,ARRAY['asset','content_type','method','stripped','bytes_before','bytes_after','provenance','pdf'])
    OR jsonb_typeof(report->'asset') IS DISTINCT FROM 'string' OR octet_length(report->>'asset')>128
    OR report->>'content_type' IS DISTINCT FROM 'application/pdf' OR report->>'method' IS DISTINCT FROM 'pdfcpu' OR report->>'provenance' IS DISTINCT FROM 'observed'
    OR NOT COALESCE(hash_presign_dispatcher_integer(report->'bytes_before',1,52428800),FALSE) OR NOT COALESCE(hash_presign_dispatcher_integer(report->'bytes_after',1,52428800),FALSE)
    OR report->>'bytes_before' IS DISTINCT FROM proof->>'processing_bytes' OR report->>'bytes_after' IS DISTINCT FROM proof->>'output_bytes' THEN
  RAISE EXCEPTION 'delegated metadata report is invalid' USING ERRCODE='23514';
 END IF;
 pdf:=report->'pdf';
 IF NOT hash_presign_dispatcher_keys(pdf,ARRAY['schema_version','policy','source_sha256','output_sha256','pages_before','pages_after','geometry_sha256_before','geometry_sha256_after','before','after','removed','absent','generated'])
    OR NOT COALESCE(hash_presign_dispatcher_integer(pdf->'schema_version',1,1),FALSE) OR NOT COALESCE(hash_presign_dispatcher_integer(pdf->'pages_before',1,500),FALSE) OR NOT COALESCE(hash_presign_dispatcher_integer(pdf->'pages_after',1,500),FALSE) OR pdf->>'policy' IS DISTINCT FROM 'hash-pdf-intake-v1'
    OR pdf->>'source_sha256' IS DISTINCT FROM proof->>'processing_sha256' OR pdf->>'output_sha256' IS DISTINCT FROM proof->>'output_sha256'
    OR pdf->>'pages_before' IS DISTINCT FROM proof->>'pages' OR pdf->>'pages_after' IS DISTINCT FROM proof->>'pages'
    OR pdf->>'geometry_sha256_before' IS DISTINCT FROM proof->>'geometry_sha256' OR pdf->>'geometry_sha256_after' IS DISTINCT FROM proof->>'geometry_sha256' THEN
  RAISE EXCEPTION 'delegated metadata proof pairing is invalid' USING ERRCODE='23514';
 END IF;
 FOREACH key IN ARRAY ARRAY['before','after'] LOOP
  properties:=pdf->key;
  IF NOT hash_presign_dispatcher_keys(properties,property_keys) THEN RAISE EXCEPTION 'delegated metadata observations are missing' USING ERRCODE='23514'; END IF;
  FOR position IN 1..7 LOOP
   IF jsonb_typeof(properties->property_keys[position]) IS DISTINCT FROM 'boolean' THEN RAISE EXCEPTION 'delegated metadata observation type is invalid' USING ERRCODE='23514'; END IF;
  END LOOP;
 END LOOP;
 FOR position IN 1..7 LOOP
  IF pdf->'before'->property_keys[position]='true'::jsonb THEN removed:=removed||jsonb_build_array(property_names[position]); ELSE absent:=absent||jsonb_build_array(property_names[position]); END IF;
  IF position>1 AND pdf->'after'->property_keys[position] IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION 'delegated output metadata remains' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF pdf->'after'->'info_dictionary'='true'::jsonb THEN generated:=jsonb_build_array('info_dictionary'); END IF;
 IF pdf->'removed' IS DISTINCT FROM removed OR report->'stripped' IS DISTINCT FROM removed OR pdf->'absent' IS DISTINCT FROM absent OR pdf->'generated' IS DISTINCT FROM generated THEN
  RAISE EXCEPTION 'delegated metadata categories are inconsistent' USING ERRCODE='23514';
 END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION hash_check_presign_dispatcher(target_org UUID,target_execution UUID) RETURNS VOID AS $$
DECLARE c presign_dispatcher_executions%ROWTYPE; e presign_executions%ROWTYPE;
        ev events%ROWTYPE; d documents%ROWTYPE; lb document_lawful_basis_confirmations%ROWTYPE;
        i JSONB; m JSONB; x JSONB; g JSONB;
BEGIN
 SELECT * INTO STRICT c FROM presign_dispatcher_executions WHERE org_id=target_org AND execution_id=target_execution;
 SELECT * INTO STRICT e FROM presign_executions WHERE org_id=target_org AND id=target_execution;
 SELECT * INTO STRICT ev FROM events WHERE id=e.audit_event_id;
 SELECT * INTO STRICT d FROM documents WHERE id=e.document_id AND org_id=e.org_id;
 SELECT * INTO STRICT lb FROM document_lawful_basis_confirmations WHERE document_id=d.id AND org_id=d.org_id FOR SHARE;
 i:=convert_from(c.intent_canonical,'UTF8')::jsonb;
 m:=convert_from(c.manifest_canonical,'UTF8')::jsonb;
 x:=convert_from(e.canonical_execution,'UTF8')::jsonb;
 SELECT convert_from(canonical_grant,'UTF8')::jsonb INTO STRICT g FROM presign_grant_revisions WHERE org_id=e.org_id AND grant_id=e.grant_id AND revision=e.grant_revision;
 IF jsonb_typeof(i) IS DISTINCT FROM 'object' OR jsonb_typeof(m) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'delegated dispatcher JSON shape is invalid' USING ERRCODE='23514';
 END IF;
 IF NOT hash_presign_dispatcher_unique_json(convert_from(c.intent_canonical,'UTF8')::json) OR NOT hash_presign_dispatcher_unique_json(convert_from(c.manifest_canonical,'UTF8')::json)
    OR NOT hash_presign_dispatcher_keys(i,ARRAY['schema_version','org_id','executor','request_id','document_id','policy','grant','materialization_id','materialization_revision','source_commitment','pdf_sha256','lawful_basis']) THEN
  RAISE EXCEPTION 'delegated dispatcher JSON keys are invalid' USING ERRCODE='23514';
 END IF;
 PERFORM hash_validate_presign_dispatcher_manifest(m);
 IF c.execution_sha256 IS DISTINCT FROM e.execution_sha256 OR c.command_sha256 IS DISTINCT FROM e.command_sha256
    OR c.intent_sha256 IS DISTINCT FROM digest(convert_to('hash:presign-dispatcher-intent:v1','UTF8')||decode('00','hex')||c.intent_canonical,'sha256')
    OR c.manifest_sha256 IS DISTINCT FROM digest(convert_to('hash:presign-provider-artifacts:v1','UTF8')||decode('00','hex')||c.manifest_canonical,'sha256')
    OR c.manifest_object_sha256 IS DISTINCT FROM digest(c.manifest_canonical,'sha256')
    OR c.manifest_object_key IS DISTINCT FROM left(m->'span'->>'storage_key',length(m->'span'->>'storage_key')-length('signature.html'))||'manifest.json'
    OR NOT hash_presign_dispatcher_pin(jsonb_build_object('storage_key',c.manifest_object_key,'version_id',c.manifest_object_version_id,'sha256',encode(c.manifest_object_sha256,'hex'),'bytes',c.manifest_object_bytes),32768)
    OR NOT COALESCE(hash_presign_dispatcher_integer(i->'schema_version',1,1),FALSE)
    OR NOT COALESCE(hash_presign_dispatcher_integer(i->'materialization_revision',1,1000000),FALSE)
    OR i->>'org_id' IS DISTINCT FROM e.org_id::text
    OR i->'executor' IS DISTINCT FROM x->'executor' OR i->>'request_id' IS DISTINCT FROM e.request_id::text
    OR i->>'document_id' IS DISTINCT FROM e.document_id::text OR i->'policy' IS DISTINCT FROM x->'policy' OR i->'grant' IS DISTINCT FROM x->'grant'
    OR i->>'materialization_id' IS DISTINCT FROM e.materialization_id::text
    OR i->>'materialization_revision' IS DISTINCT FROM x->'document'->'materialization'->>'revision'
    OR i->>'source_commitment' IS DISTINCT FROM encode(e.source_commitment,'hex')
    OR i->>'pdf_sha256' IS DISTINCT FROM x->'document'->'base_pdf'->'artifact'->>'sha256'
    OR i->>'lawful_basis' IS DISTINCT FROM 'contract'
    OR jsonb_typeof(m) IS DISTINCT FROM 'object' OR m->>'schema_version' IS DISTINCT FROM '1'
    OR m->>'org_id' IS DISTINCT FROM e.org_id::text OR m->>'document_id' IS DISTINCT FROM e.document_id::text
    OR m->'materialization' IS DISTINCT FROM x->'document'->'materialization'
    OR m->>'signing_plan_sha256' IS DISTINCT FROM x->'document'->>'signing_plan_sha256'
    OR m->>'branding_sha256' IS DISTINCT FROM x->'document'->>'branding_sha256'
    OR m->'policy' IS DISTINCT FROM x->'policy' OR m->'grant' IS DISTINCT FROM x->'grant'
    OR m->'style' IS DISTINCT FROM x->'signature'->'style' OR m->'base_pdf' IS DISTINCT FROM x->'document'->'base_pdf'
    OR m->'span' IS DISTINCT FROM x->'signature'->'image' OR m->'visible_pdf' IS DISTINCT FROM x->'visible_pdf'
    OR encode(c.manifest_sha256,'hex') IS DISTINCT FROM x->>'visible_stamp_proof_sha256'
    OR m->'signature_font'->>'sha256' IS DISTINCT FROM g->'signature'->>'font_sha256'
    OR m->>'disclosure_version' IS DISTINCT FROM g->'disclosure'->>'version'
    OR m->>'disclosure_sha256' IS DISTINCT FROM g->'disclosure'->>'sha256'
    OR ev.payload_json->>'dispatcher_schema_version' IS DISTINCT FROM '1'
    OR ev.payload_json->>'dispatcher_intent_sha256' IS DISTINCT FROM encode(c.intent_sha256,'hex')
    OR ev.payload_json->>'provider_artifact_sha256' IS DISTINCT FROM encode(c.manifest_sha256,'hex')
    OR d.name IS DISTINCT FROM c.document_name OR d.lawful_basis IS DISTINCT FROM 'contract'
    OR lb.lawful_basis IS DISTINCT FROM 'contract' OR lb.confirmed_by IS DISTINCT FROM e.executor_user_id OR lb.via IS DISTINCT FROM 'automation'
    OR lb.controller_name IS DISTINCT FROM c.controller_name OR lb.controller_contact IS DISTINCT FROM c.controller_contact
    OR lb.confirmed_at IS DISTINCT FROM c.confirmed_at THEN
  RAISE EXCEPTION 'delegated dispatcher intent or artifact pairing is inconsistent' USING ERRCODE='23514';
 END IF;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
 RAISE EXCEPTION 'delegated dispatcher companion is incomplete' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION hash_guard_presign_dispatcher_pair() RETURNS trigger AS $$
DECLARE target_org UUID; target_id UUID; marked BOOLEAN;
BEGIN
 IF TG_TABLE_NAME='presign_dispatcher_executions' THEN
  target_org:=NEW.org_id; target_id:=NEW.execution_id;
 ELSE
  target_org:=NEW.org_id; target_id:=NEW.id;
  SELECT ev.payload_json ? 'dispatcher_schema_version' OR ev.payload_json ? 'dispatcher_intent_sha256' OR ev.payload_json ? 'provider_artifact_sha256'
   INTO marked FROM events ev WHERE ev.id=NEW.audit_event_id;
  IF NOT COALESCE(marked,FALSE) AND NOT EXISTS(SELECT 1 FROM presign_dispatcher_executions WHERE org_id=target_org AND execution_id=target_id) THEN RETURN NULL; END IF;
 END IF;
 PERFORM hash_check_presign_dispatcher(target_org,target_id);
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER presign_dispatcher_execution_pair AFTER INSERT ON presign_executions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_dispatcher_pair();
CREATE CONSTRAINT TRIGGER presign_dispatcher_companion_pair AFTER INSERT ON presign_dispatcher_executions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_dispatcher_pair();

-- +goose StatementBegin
CREATE FUNCTION hash_guard_presign_dispatcher_disclosure() RETURNS trigger AS $$
DECLARE target UUID; source_version INTEGER;
BEGIN
 IF TG_TABLE_NAME='documents' THEN target:=OLD.id; ELSE
  target:=OLD.document_id;
  SELECT COALESCE((COALESCE(html_current_source_json,html_source_json)->>'schema_version')::integer,0) INTO source_version FROM documents WHERE id=target;
  IF source_version=3 THEN
   -- Normal callers hold parent first. Direct child-first mutations fail on
   -- contention rather than hiding an uncommitted companion or deadlocking it.
   PERFORM id FROM documents WHERE id=target FOR UPDATE NOWAIT;
  END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM presign_dispatcher_executions c JOIN presign_executions e ON e.id=c.execution_id AND e.org_id=c.org_id WHERE e.document_id=target) THEN
  IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='document_lawful_basis_confirmations' THEN
  RAISE EXCEPTION 'delegated controller instruction is immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'delegated dispatcher evidence is retained' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.name,NEW.lawful_basis) IS DISTINCT FROM ROW(OLD.name,OLD.lawful_basis) THEN
  RAISE EXCEPTION 'delegated dispatcher disclosure is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER presign_dispatcher_document_disclosure BEFORE UPDATE OR DELETE ON documents FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_dispatcher_disclosure();
CREATE TRIGGER presign_dispatcher_controller_instruction BEFORE UPDATE OR DELETE ON document_lawful_basis_confirmations FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_dispatcher_disclosure();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM presign_dispatcher_executions) THEN RAISE EXCEPTION 'retained delegated dispatcher evidence prevents rollback' USING ERRCODE='23514'; END IF; END $$;
-- +goose StatementEnd
DROP TRIGGER presign_dispatcher_controller_instruction ON document_lawful_basis_confirmations;
DROP TRIGGER presign_dispatcher_document_disclosure ON documents;
DROP FUNCTION hash_guard_presign_dispatcher_disclosure();
DROP TRIGGER presign_dispatcher_companion_pair ON presign_dispatcher_executions;
DROP TRIGGER presign_dispatcher_execution_pair ON presign_executions;
DROP FUNCTION hash_guard_presign_dispatcher_pair();
DROP FUNCTION hash_check_presign_dispatcher(UUID,UUID);
DROP FUNCTION hash_validate_presign_dispatcher_manifest(JSONB);
DROP FUNCTION hash_presign_dispatcher_pin(JSONB,BIGINT);
DROP FUNCTION hash_presign_dispatcher_unique_json(JSON);
DROP FUNCTION hash_presign_dispatcher_integer(JSONB,BIGINT,BIGINT);
DROP FUNCTION hash_presign_dispatcher_sha(JSONB);
DROP FUNCTION hash_presign_dispatcher_keys(JSONB,TEXT[]);
DROP TABLE presign_dispatcher_executions;
