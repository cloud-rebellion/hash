-- +goose Up
-- SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
-- Copyright (c) Bright Interaction
-- External additive84 proposal only. The complete verified patch below is
-- included byte-for-byte; neither83 nor retained evidence is rewritten.
-- Goose owns the transaction and version row; do not add BEGIN/COMMIT or
-- NO TRANSACTION. Refuse inherited incompatible isolation before any DDL.
-- +goose StatementBegin
DO $$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'presign canonical installation requires read committed' USING ERRCODE='23514';
 END IF;
END;
$$;
-- +goose StatementEnd
-- External prospective patch; source-only and not an applied migration.
-- Root decides integration into provisional83 versus a later additive migration.
-- No retained canonical byte, purpose domain, migration82 or existing guard is rewritten.
-- The only supported schemas here are timestamp-free dispatcher intent v1 and manifest v1.
-- +goose StatementBegin
CREATE FUNCTION hash_presign_canonical_quote_v1(v JSONB,max_utf8_bytes INTEGER) RETURNS BYTEA AS $$
DECLARE raw BYTEA; emitted BYTEA:=decode('22','hex'); cursor_index INTEGER:=0; current_byte INTEGER;
BEGIN
 IF max_utf8_bytes IS NULL OR max_utf8_bytes NOT BETWEEN 0 AND 1024 OR jsonb_typeof(v) IS DISTINCT FROM 'string' THEN
  RAISE EXCEPTION 'presign canonical string type or bound is invalid' USING ERRCODE='23514';
 END IF;
 raw:=convert_to(v#>>'{}','UTF8');
 IF octet_length(raw)>max_utf8_bytes THEN RAISE EXCEPTION 'presign canonical string bound exceeded' USING ERRCODE='23514'; END IF;
 WHILE cursor_index<octet_length(raw) LOOP
  current_byte:=get_byte(raw,cursor_index);
  IF current_byte=34 THEN emitted:=emitted||decode('5c22','hex');
  ELSIF current_byte=92 THEN emitted:=emitted||decode('5c5c','hex');
  ELSIF current_byte=8 THEN emitted:=emitted||decode('5c62','hex');
  ELSIF current_byte=9 THEN emitted:=emitted||decode('5c74','hex');
  ELSIF current_byte=10 THEN emitted:=emitted||decode('5c6e','hex');
  ELSIF current_byte=12 THEN emitted:=emitted||decode('5c66','hex');
  ELSIF current_byte=13 THEN emitted:=emitted||decode('5c72','hex');
  ELSIF current_byte<32 THEN emitted:=emitted||convert_to(chr(92)||'u00'||lpad(to_hex(current_byte),2,'0'),'UTF8');
  ELSIF current_byte=226 THEN
   -- Parsed UTF8 cannot end midway through this three-byte sequence. Keep
   -- bounded reads structurally separate from boolean evaluation ordering.
   IF cursor_index+2>=octet_length(raw) THEN RAISE EXCEPTION 'presign canonical UTF8 is invalid' USING ERRCODE='23514'; END IF;
   IF get_byte(raw,cursor_index+1)=128 AND get_byte(raw,cursor_index+2) IN (168,169) THEN
    emitted:=emitted||convert_to(chr(92)||(CASE WHEN get_byte(raw,cursor_index+2)=168 THEN 'u2028' ELSE 'u2029' END),'UTF8');
    cursor_index:=cursor_index+2;
   ELSE emitted:=emitted||substring(raw FROM cursor_index+1 FOR 1);
   END IF;
  ELSE emitted:=emitted||substring(raw FROM cursor_index+1 FOR 1);
  END IF;
  cursor_index:=cursor_index+1;
 END LOOP;
 RETURN emitted||decode('22','hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_integer_v1(v JSONB,low_bound BIGINT,high_bound BIGINT) RETURNS BYTEA AS $$
BEGIN
 IF NOT COALESCE(hash_presign_dispatcher_integer(v,low_bound,high_bound),FALSE) THEN
  RAISE EXCEPTION 'presign canonical integer is invalid' USING ERRCODE='23514';
 END IF;
 RETURN convert_to((v#>>'{}')::BIGINT::TEXT,'UTF8');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_boolean_v1(v JSONB) RETURNS BYTEA AS $$
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'boolean' THEN RAISE EXCEPTION 'presign canonical boolean is invalid' USING ERRCODE='23514'; END IF;
 RETURN convert_to(CASE WHEN v='true'::jsonb THEN 'true' ELSE 'false' END,'UTF8');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_uuid_v1(v JSONB,allow_nil BOOLEAN) RETURNS BYTEA AS $$
BEGIN
 IF allow_nil IS NULL OR jsonb_typeof(v) IS DISTINCT FROM 'string'
    OR (v#>>'{}') COLLATE "C" !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    OR (NOT allow_nil AND v#>>'{}'='00000000-0000-0000-0000-000000000000') THEN
  RAISE EXCEPTION 'presign canonical UUID is invalid' USING ERRCODE='23514';
 END IF;
 RETURN hash_presign_canonical_quote_v1(v,36);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_sha_v1(v JSONB) RETURNS BYTEA AS $$
BEGIN
 IF NOT COALESCE(hash_presign_dispatcher_sha(v),FALSE) THEN RAISE EXCEPTION 'presign canonical SHA is invalid' USING ERRCODE='23514'; END IF;
 RETURN hash_presign_canonical_quote_v1(v,64);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_strings_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA:=convert_to('[','UTF8'); item JSONB; ordinal BIGINT;
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'presign canonical string array is invalid' USING ERRCODE='23514'; END IF;
 IF jsonb_array_length(v)>7 THEN RAISE EXCEPTION 'presign canonical category count exceeded' USING ERRCODE='23514'; END IF;
 FOR item,ordinal IN SELECT value,position FROM jsonb_array_elements(v) WITH ORDINALITY AS parts(value,position) ORDER BY position LOOP
  IF ordinal>1 THEN emitted:=emitted||convert_to(',','UTF8'); END IF;
  emitted:=emitted||hash_presign_canonical_quote_v1(item,128);
 END LOOP;
 RETURN emitted||convert_to(']','UTF8');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_rectangle_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA:=convert_to('[','UTF8'); item JSONB; ordinal BIGINT;
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'presign canonical rectangle type is invalid' USING ERRCODE='23514'; END IF;
 IF jsonb_array_length(v)<>4 THEN RAISE EXCEPTION 'presign canonical rectangle count is invalid' USING ERRCODE='23514'; END IF;
 FOR item,ordinal IN SELECT value,position FROM jsonb_array_elements(v) WITH ORDINALITY AS parts(value,position) ORDER BY position LOOP
  IF ordinal>1 THEN emitted:=emitted||convert_to(',','UTF8'); END IF;
  emitted:=emitted||hash_presign_canonical_integer_v1(item,0,9007199254740991);
 END LOOP;
 RETURN emitted||convert_to(']','UTF8');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_reference_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['id','revision','sha256']) THEN
  RAISE EXCEPTION 'presign canonical reference keys are invalid' USING ERRCODE='23514';
 END IF;
 emitted:=convert_to('{"id":','UTF8')||hash_presign_canonical_uuid_v1(v->'id',FALSE)
  ||convert_to(',"revision":','UTF8')||hash_presign_canonical_integer_v1(v->'revision',1,1000000)
  ||convert_to(',"sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'sha256')||convert_to('}','UTF8');
 IF octet_length(emitted)>1024 THEN RAISE EXCEPTION 'presign canonical reference output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_materialization_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['id','revision','source_commitment']) THEN
  RAISE EXCEPTION 'presign canonical materialization keys are invalid' USING ERRCODE='23514';
 END IF;
 emitted:=convert_to('{"id":','UTF8')||hash_presign_canonical_uuid_v1(v->'id',FALSE)
  ||convert_to(',"revision":','UTF8')||hash_presign_canonical_integer_v1(v->'revision',1,1000000)
  ||convert_to(',"source_commitment":','UTF8')||hash_presign_canonical_sha_v1(v->'source_commitment')||convert_to('}','UTF8');
 IF octet_length(emitted)>1024 THEN RAISE EXCEPTION 'presign canonical materialization output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_executor_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['kind','user_id','credential_id']) THEN
  RAISE EXCEPTION 'presign canonical executor keys are invalid' USING ERRCODE='23514';
 END IF;
 IF v->>'kind' NOT IN ('member','api_key') OR (v->>'kind'='member' AND v->>'credential_id'<>'00000000-0000-0000-0000-000000000000') OR (v->>'kind'='api_key' AND v->>'credential_id'='00000000-0000-0000-0000-000000000000') THEN RAISE EXCEPTION 'presign canonical executor is invalid' USING ERRCODE='23514'; END IF;
 emitted:=convert_to('{"kind":','UTF8')||hash_presign_canonical_quote_v1(v->'kind',7)
  ||convert_to(',"user_id":','UTF8')||hash_presign_canonical_uuid_v1(v->'user_id',FALSE)
  ||convert_to(',"credential_id":','UTF8')||hash_presign_canonical_uuid_v1(v->'credential_id',TRUE)||convert_to('}','UTF8');
 IF octet_length(emitted)>1024 THEN RAISE EXCEPTION 'presign canonical executor output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_style_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['font','font_sha256']) THEN
  RAISE EXCEPTION 'presign canonical style keys are invalid' USING ERRCODE='23514';
 END IF;
 IF COALESCE(v->>'font','') NOT IN ('Caveat','Dancing Script','Great Vibes','Sacramento','Homemade Apple') THEN RAISE EXCEPTION 'presign canonical font is invalid' USING ERRCODE='23514'; END IF;
 emitted:=convert_to('{"font":','UTF8')||hash_presign_canonical_quote_v1(v->'font',14)
  ||convert_to(',"font_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'font_sha256')||convert_to('}','UTF8');
 IF octet_length(emitted)>1024 THEN RAISE EXCEPTION 'presign canonical style output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_artifact_v1(v JSONB,max_bytes BIGINT) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['storage_key','version_id','sha256','bytes']) THEN
  RAISE EXCEPTION 'presign canonical artifact keys are invalid' USING ERRCODE='23514';
 END IF;
 IF NOT COALESCE(hash_presign_dispatcher_pin(v,max_bytes),FALSE) THEN RAISE EXCEPTION 'presign canonical artifact pin is invalid' USING ERRCODE='23514'; END IF;
 emitted:=convert_to('{"storage_key":','UTF8')||hash_presign_canonical_quote_v1(v->'storage_key',1024)
  ||convert_to(',"version_id":','UTF8')||hash_presign_canonical_quote_v1(v->'version_id',1024)
  ||convert_to(',"sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'sha256')
  ||convert_to(',"bytes":','UTF8')||hash_presign_canonical_integer_v1(v->'bytes',1,max_bytes)||convert_to('}','UTF8');
 IF octet_length(emitted)>16384 THEN RAISE EXCEPTION 'presign canonical artifact output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_pdf_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['artifact','pages']) THEN
  RAISE EXCEPTION 'presign canonical pdf keys are invalid' USING ERRCODE='23514';
 END IF;
 emitted:=convert_to('{"artifact":','UTF8')||hash_presign_canonical_artifact_v1(v->'artifact',52428800)
  ||convert_to(',"pages":','UTF8')||hash_presign_canonical_integer_v1(v->'pages',1,500)||convert_to('}','UTF8');
 IF octet_length(emitted)>32768 THEN RAISE EXCEPTION 'presign canonical pdf output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_properties_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['info_dictionary','xmp_metadata','object_streams','linearization','embedded_files','acroform','annotations']) THEN
  RAISE EXCEPTION 'presign canonical properties keys are invalid' USING ERRCODE='23514';
 END IF;
 emitted:=convert_to('{"info_dictionary":','UTF8')||hash_presign_canonical_boolean_v1(v->'info_dictionary')
  ||convert_to(',"xmp_metadata":','UTF8')||hash_presign_canonical_boolean_v1(v->'xmp_metadata')
  ||convert_to(',"object_streams":','UTF8')||hash_presign_canonical_boolean_v1(v->'object_streams')
  ||convert_to(',"linearization":','UTF8')||hash_presign_canonical_boolean_v1(v->'linearization')
  ||convert_to(',"embedded_files":','UTF8')||hash_presign_canonical_boolean_v1(v->'embedded_files')
  ||convert_to(',"acroform":','UTF8')||hash_presign_canonical_boolean_v1(v->'acroform')
  ||convert_to(',"annotations":','UTF8')||hash_presign_canonical_boolean_v1(v->'annotations')||convert_to('}','UTF8');
 IF octet_length(emitted)>2048 THEN RAISE EXCEPTION 'presign canonical properties output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_form_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['slot','rectangle_micro_points','content_sha256','resources_sha256','fragment_geometry_sha256']) THEN
  RAISE EXCEPTION 'presign canonical form keys are invalid' USING ERRCODE='23514';
 END IF;
 emitted:=convert_to('{"slot":','UTF8')||hash_presign_canonical_quote_v1(v->'slot',64)
  ||convert_to(',"rectangle_micro_points":','UTF8')||hash_presign_canonical_rectangle_v1(v->'rectangle_micro_points')
  ||convert_to(',"content_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'content_sha256')
  ||convert_to(',"resources_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'resources_sha256')
  ||convert_to(',"fragment_geometry_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'fragment_geometry_sha256')||convert_to('}','UTF8');
 IF octet_length(emitted)>2048 THEN RAISE EXCEPTION 'presign canonical form output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_forms_v1(v JSONB) RETURNS BYTEA AS $$
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'presign canonical forms type is invalid' USING ERRCODE='23514'; END IF;
 IF jsonb_array_length(v)<>2 THEN RAISE EXCEPTION 'presign canonical forms count is invalid' USING ERRCODE='23514'; END IF;
 RETURN convert_to('[','UTF8')||hash_presign_canonical_form_v1(v->0)||convert_to(',','UTF8')||hash_presign_canonical_form_v1(v->1)||convert_to(']','UTF8');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_worker_proof_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['schema_version','policy','bindings_sha256','base_sha256','base_bytes','signature_sha256','disclosure_sha256','processing_sha256','processing_bytes','output_sha256','output_bytes','pages','geometry_sha256','original_content_sha256','forms']) THEN
  RAISE EXCEPTION 'presign canonical worker_proof keys are invalid' USING ERRCODE='23514';
 END IF;
 emitted:=convert_to('{"schema_version":','UTF8')||hash_presign_canonical_integer_v1(v->'schema_version',1,1)
  ||convert_to(',"policy":','UTF8')||hash_presign_canonical_quote_v1(v->'policy',64)
  ||convert_to(',"bindings_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'bindings_sha256')
  ||convert_to(',"base_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'base_sha256')
  ||convert_to(',"base_bytes":','UTF8')||hash_presign_canonical_integer_v1(v->'base_bytes',1,52428800)
  ||convert_to(',"signature_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'signature_sha256')
  ||convert_to(',"disclosure_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'disclosure_sha256')
  ||convert_to(',"processing_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'processing_sha256')
  ||convert_to(',"processing_bytes":','UTF8')||hash_presign_canonical_integer_v1(v->'processing_bytes',1,52428800)
  ||convert_to(',"output_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'output_sha256')
  ||convert_to(',"output_bytes":','UTF8')||hash_presign_canonical_integer_v1(v->'output_bytes',1,52428800)
  ||convert_to(',"pages":','UTF8')||hash_presign_canonical_integer_v1(v->'pages',1,500)
  ||convert_to(',"geometry_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'geometry_sha256')
  ||convert_to(',"original_content_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'original_content_sha256')
  ||convert_to(',"forms":','UTF8')||hash_presign_canonical_forms_v1(v->'forms')||convert_to('}','UTF8');
 IF octet_length(emitted)>8192 THEN RAISE EXCEPTION 'presign canonical worker_proof output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_pdf_proof_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['schema_version','policy','source_sha256','output_sha256','pages_before','pages_after','geometry_sha256_before','geometry_sha256_after','before','after','removed','absent','generated']) THEN
  RAISE EXCEPTION 'presign canonical pdf_proof keys are invalid' USING ERRCODE='23514';
 END IF;
 emitted:=convert_to('{"schema_version":','UTF8')||hash_presign_canonical_integer_v1(v->'schema_version',1,1)
  ||convert_to(',"policy":','UTF8')||hash_presign_canonical_quote_v1(v->'policy',64)
  ||convert_to(',"source_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'source_sha256')
  ||convert_to(',"output_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'output_sha256')
  ||convert_to(',"pages_before":','UTF8')||hash_presign_canonical_integer_v1(v->'pages_before',1,500)
  ||convert_to(',"pages_after":','UTF8')||hash_presign_canonical_integer_v1(v->'pages_after',1,500)
  ||convert_to(',"geometry_sha256_before":','UTF8')||hash_presign_canonical_sha_v1(v->'geometry_sha256_before')
  ||convert_to(',"geometry_sha256_after":','UTF8')||hash_presign_canonical_sha_v1(v->'geometry_sha256_after')
  ||convert_to(',"before":','UTF8')||hash_presign_canonical_properties_v1(v->'before')
  ||convert_to(',"after":','UTF8')||hash_presign_canonical_properties_v1(v->'after')
  ||convert_to(',"removed":','UTF8')||hash_presign_canonical_strings_v1(v->'removed')
  ||convert_to(',"absent":','UTF8')||hash_presign_canonical_strings_v1(v->'absent')
  ||convert_to(',"generated":','UTF8')||hash_presign_canonical_strings_v1(v->'generated')||convert_to('}','UTF8');
 IF octet_length(emitted)>8192 THEN RAISE EXCEPTION 'presign canonical pdf_proof output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_report_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['asset','content_type','method','stripped','bytes_before','bytes_after','provenance','pdf']) THEN
  RAISE EXCEPTION 'presign canonical report keys are invalid' USING ERRCODE='23514';
 END IF;
 emitted:=convert_to('{"asset":','UTF8')||hash_presign_canonical_quote_v1(v->'asset',128)
  ||convert_to(',"content_type":','UTF8')||hash_presign_canonical_quote_v1(v->'content_type',128)
  ||convert_to(',"method":','UTF8')||hash_presign_canonical_quote_v1(v->'method',128)
  ||convert_to(',"stripped":','UTF8')||hash_presign_canonical_strings_v1(v->'stripped')
  ||convert_to(',"bytes_before":','UTF8')||hash_presign_canonical_integer_v1(v->'bytes_before',1,52428800)
  ||convert_to(',"bytes_after":','UTF8')||hash_presign_canonical_integer_v1(v->'bytes_after',1,52428800)
  ||convert_to(',"provenance":','UTF8')||hash_presign_canonical_quote_v1(v->'provenance',128)
  ||convert_to(',"pdf":','UTF8')||hash_presign_canonical_pdf_proof_v1(v->'pdf')||convert_to('}','UTF8');
 IF octet_length(emitted)>12288 THEN RAISE EXCEPTION 'presign canonical report output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_intent_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['schema_version','org_id','executor','request_id','document_id','policy','grant','materialization_id','materialization_revision','source_commitment','pdf_sha256','lawful_basis']) THEN
  RAISE EXCEPTION 'presign canonical intent keys are invalid' USING ERRCODE='23514';
 END IF;
 IF v->>'lawful_basis' IS DISTINCT FROM 'contract' THEN RAISE EXCEPTION 'presign canonical lawful basis is invalid' USING ERRCODE='23514'; END IF;
 emitted:=convert_to('{"schema_version":','UTF8')||hash_presign_canonical_integer_v1(v->'schema_version',1,1)
  ||convert_to(',"org_id":','UTF8')||hash_presign_canonical_uuid_v1(v->'org_id',FALSE)
  ||convert_to(',"executor":','UTF8')||hash_presign_canonical_executor_v1(v->'executor')
  ||convert_to(',"request_id":','UTF8')||hash_presign_canonical_uuid_v1(v->'request_id',FALSE)
  ||convert_to(',"document_id":','UTF8')||hash_presign_canonical_uuid_v1(v->'document_id',FALSE)
  ||convert_to(',"policy":','UTF8')||hash_presign_canonical_reference_v1(v->'policy')
  ||convert_to(',"grant":','UTF8')||hash_presign_canonical_reference_v1(v->'grant')
  ||convert_to(',"materialization_id":','UTF8')||hash_presign_canonical_uuid_v1(v->'materialization_id',FALSE)
  ||convert_to(',"materialization_revision":','UTF8')||hash_presign_canonical_integer_v1(v->'materialization_revision',1,1000000)
  ||convert_to(',"source_commitment":','UTF8')||hash_presign_canonical_sha_v1(v->'source_commitment')
  ||convert_to(',"pdf_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'pdf_sha256')
  ||convert_to(',"lawful_basis":','UTF8')||hash_presign_canonical_quote_v1(v->'lawful_basis',8)||convert_to('}','UTF8');
 IF octet_length(emitted)>16384 THEN RAISE EXCEPTION 'presign canonical intent output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_presign_canonical_manifest_v1(v JSONB) RETURNS BYTEA AS $$
DECLARE emitted BYTEA;
BEGIN
 IF NOT hash_presign_dispatcher_keys(v,ARRAY['schema_version','org_id','document_id','materialization','signing_plan_sha256','branding_sha256','policy','grant','style','base_pdf','span','signature_font','inter_font','disclosure_text','disclosure_version','disclosure_sha256','render_recipe','signature_fragment_pdf','disclosure_fragment_pdf','visible_pdf','worker_proof','metadata_report']) THEN
  RAISE EXCEPTION 'presign canonical manifest keys are invalid' USING ERRCODE='23514';
 END IF;
 PERFORM hash_validate_presign_dispatcher_manifest(v);
 emitted:=convert_to('{"schema_version":','UTF8')||hash_presign_canonical_integer_v1(v->'schema_version',1,1)
  ||convert_to(',"org_id":','UTF8')||hash_presign_canonical_uuid_v1(v->'org_id',FALSE)
  ||convert_to(',"document_id":','UTF8')||hash_presign_canonical_uuid_v1(v->'document_id',FALSE)
  ||convert_to(',"materialization":','UTF8')||hash_presign_canonical_materialization_v1(v->'materialization')
  ||convert_to(',"signing_plan_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'signing_plan_sha256')
  ||convert_to(',"branding_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'branding_sha256')
  ||convert_to(',"policy":','UTF8')||hash_presign_canonical_reference_v1(v->'policy')
  ||convert_to(',"grant":','UTF8')||hash_presign_canonical_reference_v1(v->'grant')
  ||convert_to(',"style":','UTF8')||hash_presign_canonical_style_v1(v->'style')
  ||convert_to(',"base_pdf":','UTF8')||hash_presign_canonical_pdf_v1(v->'base_pdf')
  ||convert_to(',"span":','UTF8')||hash_presign_canonical_artifact_v1(v->'span',1048576)
  ||convert_to(',"signature_font":','UTF8')||hash_presign_canonical_artifact_v1(v->'signature_font',1048576)
  ||convert_to(',"inter_font":','UTF8')||hash_presign_canonical_artifact_v1(v->'inter_font',1048576)
  ||convert_to(',"disclosure_text":','UTF8')||hash_presign_canonical_artifact_v1(v->'disclosure_text',1048576)
  ||convert_to(',"disclosure_version":','UTF8')||hash_presign_canonical_integer_v1(v->'disclosure_version',1,1)
  ||convert_to(',"disclosure_sha256":','UTF8')||hash_presign_canonical_sha_v1(v->'disclosure_sha256')
  ||convert_to(',"render_recipe":','UTF8')||hash_presign_canonical_artifact_v1(v->'render_recipe',1048576)
  ||convert_to(',"signature_fragment_pdf":','UTF8')||hash_presign_canonical_artifact_v1(v->'signature_fragment_pdf',52428800)
  ||convert_to(',"disclosure_fragment_pdf":','UTF8')||hash_presign_canonical_artifact_v1(v->'disclosure_fragment_pdf',52428800)
  ||convert_to(',"visible_pdf":','UTF8')||hash_presign_canonical_pdf_v1(v->'visible_pdf')
  ||convert_to(',"worker_proof":','UTF8')||hash_presign_canonical_worker_proof_v1(v->'worker_proof')
  ||convert_to(',"metadata_report":','UTF8')||hash_presign_canonical_report_v1(v->'metadata_report')||convert_to('}','UTF8');
 IF octet_length(emitted)>32768 THEN RAISE EXCEPTION 'presign canonical manifest output bound exceeded' USING ERRCODE='23514'; END IF;
 RETURN emitted;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE FUNCTION hash_check_presign_dispatcher_canonical_v1(target_org UUID,target_execution UUID) RETURNS VOID AS $$
DECLARE companion presign_dispatcher_executions%ROWTYPE; intent_json JSONB; manifest_json JSONB;
BEGIN
 SELECT * INTO STRICT companion FROM presign_dispatcher_executions WHERE org_id=target_org AND execution_id=target_execution;
 IF NOT hash_presign_dispatcher_unique_json(convert_from(companion.intent_canonical,'UTF8')::json)
    OR NOT hash_presign_dispatcher_unique_json(convert_from(companion.manifest_canonical,'UTF8')::json) THEN
  RAISE EXCEPTION 'presign canonical JSON keys are duplicated' USING ERRCODE='23514';
 END IF;
 intent_json:=convert_from(companion.intent_canonical,'UTF8')::jsonb;
 manifest_json:=convert_from(companion.manifest_canonical,'UTF8')::jsonb;
 IF companion.intent_canonical IS DISTINCT FROM hash_presign_canonical_intent_v1(intent_json)
    OR companion.manifest_canonical IS DISTINCT FROM hash_presign_canonical_manifest_v1(manifest_json) THEN
  RAISE EXCEPTION 'presign dispatcher canonical bytes are invalid' USING ERRCODE='23514';
 END IF;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
 RAISE EXCEPTION 'presign canonical companion is incomplete' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION hash_guard_presign_dispatcher_canonical_v1() RETURNS trigger AS $$
BEGIN
 PERFORM hash_check_presign_dispatcher_canonical_v1(NEW.org_id,NEW.execution_id);
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Validate any retained companions first. Never grandfather or rewrite bytes.
-- Legacy82 supporting rows have no83 companion and remain outside this guard.
-- Serialize installation with inserts, then inspect the fresh committed set.
-- This patch is installed atomically in a READ COMMITTED migration transaction.
LOCK TABLE presign_dispatcher_executions IN SHARE ROW EXCLUSIVE MODE;
DO $$
DECLARE existing presign_dispatcher_executions%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'presign canonical installation requires read committed' USING ERRCODE='23514';
 END IF;
 FOR existing IN SELECT * FROM presign_dispatcher_executions LOOP
  PERFORM hash_check_presign_dispatcher_canonical_v1(existing.org_id,existing.execution_id);
 END LOOP;
END;
$$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER presign_dispatcher_companion_canonical_v1
 AFTER INSERT ON presign_dispatcher_executions DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION hash_guard_presign_dispatcher_canonical_v1();

-- +goose Down
-- Removing this integrity guard would reopen the known privileged SQL gap.
-- Refuse even on an empty database. Goose must retain version84 on failure.
-- +goose StatementBegin
DO $$
BEGIN
 RAISE EXCEPTION 'presign dispatcher canonical guard cannot be downgraded' USING ERRCODE='23514';
END;
$$;
-- +goose StatementEnd
