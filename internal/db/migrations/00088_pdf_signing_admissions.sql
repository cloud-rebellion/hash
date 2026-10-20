-- +goose Up
-- Explicit opt-in immutable pre-Sign PDF foundation; historical85/86/87 paths
-- stay default. No route or policy activated. Worker/producer/credential,
-- tenant/global memory/disk, actualZIP and audit/version/index admission are
-- mandatory caller gates. Stale/unknown originals remain retained and charged.
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'PDF admission installation requires read committed' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
LOCK TABLE documents,recipients,document_fields,signatures IN ACCESS EXCLUSIVE MODE;
ALTER TABLE documents
 ADD COLUMN signing_admission_policy TEXT NOT NULL DEFAULT 'historical' CHECK(signing_admission_policy IN('historical','pdf-static-v1')),
 ADD COLUMN signing_admission_active_id UUID,
 ADD COLUMN signing_admission_sealed_id UUID,
 ADD COLUMN signing_admission_count INTEGER NOT NULL DEFAULT 0 CHECK(signing_admission_count BETWEEN 0 AND 8),
 ADD COLUMN signing_admission_static_bytes BIGINT NOT NULL DEFAULT 0 CHECK(signing_admission_static_bytes BETWEEN 0 AND 83886080),
 ADD COLUMN signing_admission_ordinary_bytes BIGINT NOT NULL DEFAULT 0 CHECK(signing_admission_ordinary_bytes BETWEEN 0 AND 52428800),
 ADD COLUMN signing_admission_plan_bytes BIGINT NOT NULL DEFAULT 0 CHECK(signing_admission_plan_bytes BETWEEN 0 AND 8388608);
ALTER TABLE signatures ADD CONSTRAINT signatures_admission_document_identity UNIQUE(id,document_id);
CREATE TABLE document_signing_admissions (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 org_id UUID NOT NULL,document_id UUID NOT NULL,
 ceremony_epoch TIMESTAMPTZ NOT NULL CHECK(isfinite(ceremony_epoch)),
 original_document_name TEXT NOT NULL CHECK(octet_length(original_document_name) BETWEEN 1 AND 65536 AND btrim(original_document_name)<>''),
 source_storage_key TEXT NOT NULL CHECK(octet_length(source_storage_key) BETWEEN 1 AND 1024 AND source_storage_key=btrim(source_storage_key) AND source_storage_key !~ '[[:cntrl:]]'),
 source_version_id TEXT NOT NULL CHECK(hash_signature_fit_version_valid(source_version_id)),
 source_sha256 BYTEA NOT NULL CHECK(octet_length(source_sha256)=32),
 source_bytes BIGINT NOT NULL CHECK(source_bytes BETWEEN 1 AND 52428800),
 source_pages INTEGER NOT NULL CHECK(source_pages BETWEEN 1 AND 500),
 static_basis_payload BYTEA NOT NULL CHECK(octet_length(static_basis_payload) BETWEEN 1 AND 4194304),
 static_basis_sha256 BYTEA NOT NULL CHECK(octet_length(static_basis_sha256)=32 AND digest(convert_to('hash:pdf-signing-static-basis:v1:','UTF8')||static_basis_payload,'sha256')=static_basis_sha256),
 static_basis_body_sha256 BYTEA NOT NULL CHECK(octet_length(static_basis_body_sha256)=32 AND digest(static_basis_payload,'sha256')=static_basis_body_sha256),
 geometry_payload BYTEA NOT NULL CHECK(octet_length(geometry_payload) BETWEEN 1 AND 1048576),
 geometry_payload_sha256 BYTEA NOT NULL CHECK(octet_length(geometry_payload_sha256)=32 AND digest(geometry_payload,'sha256')=geometry_payload_sha256),
 geometry_pages_payload BYTEA NOT NULL CHECK(octet_length(geometry_pages_payload) BETWEEN 1 AND 1048576),
 geometry_sha256 BYTEA NOT NULL CHECK(octet_length(geometry_sha256)=32 AND digest(geometry_pages_payload,'sha256')=geometry_sha256),
 fields_payload BYTEA NOT NULL CHECK(octet_length(fields_payload) BETWEEN 1 AND 1048576),
 fields_sha256 BYTEA NOT NULL CHECK(octet_length(fields_sha256)=32 AND digest(fields_payload,'sha256')=fields_sha256),
 parties_payload BYTEA NOT NULL CHECK(octet_length(parties_payload) BETWEEN 1 AND 1048576),
 parties_sha256 BYTEA NOT NULL CHECK(octet_length(parties_sha256)=32 AND digest(parties_payload,'sha256')=parties_sha256),
 render_recipe_payload BYTEA NOT NULL CHECK(octet_length(render_recipe_payload) BETWEEN 1 AND 262144),
 render_recipe_sha256 BYTEA NOT NULL CHECK(octet_length(render_recipe_sha256)=32 AND digest(render_recipe_payload,'sha256')=render_recipe_sha256),
 ordinary_recipe_payload BYTEA NOT NULL CHECK(octet_length(ordinary_recipe_payload) BETWEEN 1 AND 16384),
 ordinary_recipe_sha256 BYTEA NOT NULL CHECK(ordinary_recipe_sha256=decode('499169106f632bd576a93b8e45daf6d4c2272cdbd93363c5d75b30883134fdcf','hex') AND digest(ordinary_recipe_payload,'sha256')=ordinary_recipe_sha256),
 branding_context_sha256 BYTEA NOT NULL CHECK(octet_length(branding_context_sha256)=32),
 expected_ordinary_pages INTEGER[] NOT NULL CHECK(cardinality(expected_ordinary_pages) BETWEEN 0 AND 500),
 required_parties INTEGER NOT NULL CHECK(required_parties BETWEEN 1 AND 100),
 field_count INTEGER NOT NULL CHECK(field_count BETWEEN 1 AND 1000),
 base_bytes_limit BIGINT NOT NULL CHECK(base_bytes_limit BETWEEN 0 AND 52428800),
 descriptor_bytes_limit BIGINT NOT NULL CHECK(descriptor_bytes_limit BETWEEN 1 AND 1048576),
 final_pdf_bytes_limit BIGINT NOT NULL CHECK(final_pdf_bytes_limit BETWEEN 1 AND 52428800),
 fits_index_bytes_limit BIGINT NOT NULL CHECK(fits_index_bytes_limit BETWEEN 1 AND 8388608),
 certificate_pdf_bytes_limit BIGINT NOT NULL CHECK(certificate_pdf_bytes_limit BETWEEN 1 AND 8388608),
 certificate_payload_bytes_limit BIGINT NOT NULL CHECK(certificate_payload_bytes_limit BETWEEN 1 AND 4194304),
 certificate_signature_bytes_limit BIGINT NOT NULL CHECK(certificate_signature_bytes_limit BETWEEN 1 AND 256),
 events_bytes_limit BIGINT NOT NULL CHECK(events_bytes_limit BETWEEN 1 AND 4194304),
 versions_bytes_limit BIGINT NOT NULL CHECK(versions_bytes_limit BETWEEN 1 AND 4194304),
 archive_manifest_bytes_limit BIGINT NOT NULL CHECK(archive_manifest_bytes_limit BETWEEN 1 AND 1048576),
 archive_budget_bytes BIGINT NOT NULL CHECK(archive_budget_bytes BETWEEN 1 AND 167772160),
 processing_budget_bytes BIGINT NOT NULL CHECK(processing_budget_bytes BETWEEN 1 AND 52428800),
 source_inspection_sha256 BYTEA CHECK(source_inspection_sha256 IS NULL OR octet_length(source_inspection_sha256)=32),
 ready_at TIMESTAMPTZ CHECK(ready_at IS NULL OR isfinite(ready_at)),
 sealed_at TIMESTAMPTZ CHECK(sealed_at IS NULL OR isfinite(sealed_at)),
 stale_at TIMESTAMPTZ CHECK(stale_at IS NULL OR isfinite(stale_at)),
 first_signature_id UUID,
 owner_id UUID NOT NULL CHECK(owner_id<>'00000000-0000-0000-0000-000000000000'),
 lease_until TIMESTAMPTZ NOT NULL CHECK(isfinite(lease_until)),
 attempts INTEGER NOT NULL DEFAULT 1 CHECK(attempts BETWEEN 1 AND 8),
 status TEXT NOT NULL DEFAULT 'staging' CHECK(status IN('staging','ready','sealed','stale')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(updated_at)),
 UNIQUE(id,org_id,document_id),
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(first_signature_id,document_id) REFERENCES signatures(id,document_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK((status IN('ready','sealed'))=(ready_at IS NOT NULL) OR status='stale'),
 CHECK((ready_at IS NULL)=(source_inspection_sha256 IS NULL)),
 CHECK((status='sealed')=(sealed_at IS NOT NULL AND first_signature_id IS NOT NULL)),
 CHECK((status='stale')=(stale_at IS NOT NULL)),
 CHECK((cardinality(expected_ordinary_pages)=0 AND base_bytes_limit=0) OR (cardinality(expected_ordinary_pages)>0 AND base_bytes_limit>=cardinality(expected_ordinary_pages)))
);
-- A→B→A may capture a NEW logical ID; stale originals never reactivate or
-- stop consuming retained quotas. Read/retry stale work by exact old ID only.
CREATE UNIQUE INDEX document_signing_admissions_current_basis ON document_signing_admissions(document_id,ceremony_epoch,static_basis_sha256) WHERE status<>'stale';
CREATE UNIQUE INDEX document_signing_admissions_one_sealed ON document_signing_admissions(document_id,ceremony_epoch) WHERE status='sealed';
CREATE INDEX document_signing_admissions_inventory ON document_signing_admissions(org_id,document_id,id);
CREATE INDEX document_signing_admissions_recovery ON document_signing_admissions(status,lease_until,id);
ALTER TABLE documents
 ADD CONSTRAINT documents_signing_admission_active_identity FOREIGN KEY(signing_admission_active_id,org_id,id) REFERENCES document_signing_admissions(id,org_id,document_id) DEFERRABLE INITIALLY DEFERRED,
 ADD CONSTRAINT documents_signing_admission_sealed_identity FOREIGN KEY(signing_admission_sealed_id,org_id,id) REFERENCES document_signing_admissions(id,org_id,document_id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE document_signing_admission_bodies (
 admission_id UUID NOT NULL,org_id UUID NOT NULL,document_id UUID NOT NULL,
 kind TEXT NOT NULL DEFAULT 'ordinary_page' CHECK(kind='ordinary_page'),page INTEGER NOT NULL CHECK(page BETWEEN 1 AND 500),
 payload BYTEA NOT NULL,sha256 BYTEA NOT NULL CHECK(octet_length(sha256)=32),
 bytes BIGINT NOT NULL CHECK(bytes BETWEEN 1 AND 8388608 AND octet_length(payload)=bytes AND digest(payload,'sha256')=sha256),
 content_type TEXT NOT NULL CHECK(content_type='application/pdf'),
 static_basis_sha256 BYTEA NOT NULL CHECK(octet_length(static_basis_sha256)=32),
 plan_payload BYTEA NOT NULL CHECK(octet_length(plan_payload) BETWEEN 1 AND 1048576),
 plan_sha256 BYTEA NOT NULL CHECK(octet_length(plan_sha256)=32 AND digest(plan_payload,'sha256')=plan_sha256),package_sha256 BYTEA NOT NULL CHECK(octet_length(package_sha256)=32),
 report_sha256 BYTEA NOT NULL CHECK(octet_length(report_sha256)=32),inspection_sha256 BYTEA NOT NULL CHECK(octet_length(inspection_sha256)=32),
 captured_owner_id UUID NOT NULL CHECK(captured_owner_id<>'00000000-0000-0000-0000-000000000000'),
 captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(captured_at)),
 PRIMARY KEY(admission_id,kind,page),
 FOREIGN KEY(admission_id,org_id,document_id) REFERENCES document_signing_admissions(id,org_id,document_id) ON DELETE RESTRICT
);
CREATE INDEX document_signing_admission_bodies_inventory ON document_signing_admission_bodies(org_id,document_id,admission_id,page);
ALTER TABLE signature_fit_preparations ADD CONSTRAINT signature_fit_preparations_admission_identity UNIQUE(id,org_id,document_id,recipient_id);
CREATE TABLE document_signing_admission_slots (
 admission_id UUID NOT NULL,org_id UUID NOT NULL,document_id UUID NOT NULL,recipient_id UUID NOT NULL,
 target_ids UUID[] NOT NULL CHECK(cardinality(target_ids) BETWEEN 1 AND 1000),
 occupied_pages INTEGER[] NOT NULL CHECK(cardinality(occupied_pages) BETWEEN 1 AND 500),
 target_count INTEGER NOT NULL CHECK(target_count=cardinality(target_ids)),
 page_count INTEGER NOT NULL CHECK(page_count=cardinality(occupied_pages)),
 expected_objects INTEGER NOT NULL CHECK(expected_objects=page_count+2),
 fit_bytes_limit BIGINT NOT NULL CHECK(fit_bytes_limit=3145728::bigint+page_count::bigint*16777276),
 pdf_bytes_limit BIGINT NOT NULL CHECK(pdf_bytes_limit=page_count::bigint*8388608),
 designated_preparation_id UUID,designated_owner_id UUID,
 CHECK((designated_preparation_id IS NULL)=(designated_owner_id IS NULL)),
 PRIMARY KEY(admission_id,recipient_id),
 FOREIGN KEY(admission_id,org_id,document_id) REFERENCES document_signing_admissions(id,org_id,document_id) ON DELETE RESTRICT,
 FOREIGN KEY(recipient_id,document_id) REFERENCES recipients(id,document_id) ON DELETE RESTRICT,
 FOREIGN KEY(designated_preparation_id,org_id,document_id,recipient_id) REFERENCES signature_fit_preparations(id,org_id,document_id,recipient_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE signature_signing_admission_bindings (
 signature_id UUID PRIMARY KEY,admission_id UUID NOT NULL,org_id UUID NOT NULL,document_id UUID NOT NULL,recipient_id UUID NOT NULL,field_id UUID NOT NULL,
 static_basis_sha256 BYTEA NOT NULL CHECK(octet_length(static_basis_sha256)=32),
 reviewed_basis_sha256 BYTEA NOT NULL CHECK(octet_length(reviewed_basis_sha256)=32 AND reviewed_basis_sha256=static_basis_sha256),
 selection_id UUID NOT NULL UNIQUE,signed_event_id UUID NOT NULL REFERENCES events(id) DEFERRABLE INITIALLY DEFERRED,bound_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(bound_at)),
 FOREIGN KEY(admission_id,org_id,document_id) REFERENCES document_signing_admissions(id,org_id,document_id) ON DELETE RESTRICT,
 FOREIGN KEY(signature_id,document_id,recipient_id,field_id) REFERENCES signatures(id,document_id,recipient_id,field_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(selection_id,org_id,document_id,recipient_id) REFERENCES signature_fit_selections(id,org_id,document_id,recipient_id) ON DELETE RESTRICT
);

-- +goose StatementBegin
CREATE FUNCTION hash_pdf_admission_basis_matches_v1(admission document_signing_admissions,doc documents)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE basis_json JSONB; geometry_json JSONB; fields_json JSONB; parties_json JSONB; recipe_json JSONB; ordinary_json JSONB;
 expected_fields JSONB; expected_parties JSONB; expected_roles JSONB; expected_pages INTEGER[]; member JSONB; box_member JSONB; coordinate JSONB;
 party_count BIGINT; fields_count BIGINT; visible_x0 NUMERIC;visible_y0 NUMERIC;visible_x1 NUMERIC;visible_y1 NUMERIC;
BEGIN
 basis_json:=convert_from(admission.static_basis_payload,'UTF8')::jsonb;
 geometry_json:=convert_from(admission.geometry_payload,'UTF8')::jsonb;
 fields_json:=convert_from(admission.fields_payload,'UTF8')::jsonb;
 parties_json:=convert_from(admission.parties_payload,'UTF8')::jsonb;
 recipe_json:=convert_from(admission.render_recipe_payload,'UTF8')::jsonb;
 ordinary_json:=convert_from(admission.ordinary_recipe_payload,'UTF8')::jsonb;
 IF doc.deleted_at IS NOT NULL OR doc.source_kind<>'pdf' OR NOT doc.requires_signature OR doc.is_envelope OR doc.parent_envelope_id IS NOT NULL
  OR NOT doc.evidence_version_pins_required OR NOT doc.article13_notice_epoch_v61_committed
  OR ROW(doc.sent_at,doc.article13_notice_epoch_at,doc.pdf_storage_key,doc.pdf_storage_version_id,doc.pdf_sha256,doc.name)
   IS DISTINCT FROM ROW(admission.ceremony_epoch,admission.ceremony_epoch,admission.source_storage_key,admission.source_version_id,admission.source_sha256,admission.original_document_name)
  OR jsonb_typeof(basis_json) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(basis_json))<>14
  OR jsonb_typeof(fields_json) IS DISTINCT FROM 'array' OR jsonb_array_length(fields_json) NOT BETWEEN 1 AND 1000
  OR jsonb_typeof(geometry_json) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(geometry_json))<>5
  OR jsonb_typeof(geometry_json->'pages') IS DISTINCT FROM 'array' OR jsonb_array_length(geometry_json->'pages') IS DISTINCT FROM admission.source_pages
  OR geometry_json->'pages' IS DISTINCT FROM convert_from(admission.geometry_pages_payload,'UTF8')::jsonb
  OR geometry_json->'schema_version' IS DISTINCT FROM '1'::jsonb
  OR geometry_json->>'source_sha256' IS DISTINCT FROM encode(admission.source_sha256,'hex')
  OR (geometry_json->>'source_bytes')::bigint IS DISTINCT FROM admission.source_bytes
  OR geometry_json->>'geometry_sha256' IS DISTINCT FROM encode(admission.geometry_sha256,'hex') THEN RETURN FALSE; END IF;
 SELECT count(*) INTO party_count FROM recipients WHERE document_id=doc.id;
 SELECT count(*) INTO fields_count FROM document_fields WHERE document_id=doc.id;
 IF party_count NOT BETWEEN 1 AND 100 OR party_count<>admission.required_parties OR fields_count NOT BETWEEN 1 AND 1000
  OR fields_count<>admission.field_count OR fields_count<>jsonb_array_length(fields_json)
  OR EXISTS(SELECT 1 FROM recipients rp WHERE rp.document_id=doc.id AND
   (rp.role IN('cc','viewer') OR rp.role !~ '^[a-z][a-z0-9_-]{0,63}$' OR octet_length(rp.name) NOT BETWEEN 1 AND 800
    OR char_length(rp.name)>200 OR rp.name<>hash_fitted_trim_v1(rp.name) OR rp.name=''
    OR octet_length(rp.email) NOT BETWEEN 1 AND 254 OR rp.email<>hash_fitted_trim_v1(rp.email)
    OR rp.order_index NOT BETWEEN 0 AND 1000 OR octet_length(rp.locale) NOT BETWEEN 1 AND 32))
  OR EXISTS(SELECT 1 FROM recipients rp WHERE rp.document_id=doc.id GROUP BY rp.role HAVING count(*)>1)
  OR EXISTS(SELECT 1 FROM document_fields fp LEFT JOIN recipients rp ON rp.id=fp.recipient_id AND rp.document_id=doc.id
   WHERE fp.document_id=doc.id AND (rp.id IS NULL OR fp.type NOT IN('signature','text','date','checkbox','dropdown','initial')
    OR fp.page NOT BETWEEN 1 AND admission.source_pages OR fp.x_pct<0 OR fp.y_pct<0 OR fp.w_pct<=0 OR fp.h_pct<=0
    OR fp.x_pct+fp.w_pct>100 OR fp.y_pct+fp.h_pct>100
    OR (fp.type='signature' AND (NOT fp.required OR COALESCE(hash_fitted_trim_v1(fp.value),'')<>''))
    OR (fp.type<>'signature' AND (party_count<>1 OR rp.role<>'signer' OR octet_length(COALESCE(fp.value,''))>4096
       OR COALESCE(fp.value,'') ~ U&'[\0001-\0009\000B\000C\000E-\001F\007F-\009F]'))))
  OR EXISTS(SELECT 1 FROM recipients rp WHERE rp.document_id=doc.id AND NOT EXISTS(
   SELECT 1 FROM document_fields fp WHERE fp.document_id=doc.id AND fp.recipient_id=rp.id AND fp.type='signature' AND fp.required))
  OR EXISTS(SELECT 1 FROM document_fields fp WHERE fp.document_id=doc.id AND fp.type='signature'
   GROUP BY fp.recipient_id,fp.page HAVING count(*)>128) THEN RETURN FALSE; END IF;
 SELECT jsonb_agg(jsonb_build_object('ID',fp.id,'RecipientID',fp.recipient_id,'RecipientValid',TRUE,'Type',fp.type,
  'Page',fp.page,'Required',fp.required,'X',fp.x_pct::text,'Y',fp.y_pct::text,'W',fp.w_pct::text,'H',fp.h_pct::text,
  'ValueValid',fp.value IS NOT NULL,'Value',COALESCE(fp.value,'')) ORDER BY fp.id) INTO expected_fields FROM document_fields fp WHERE fp.document_id=doc.id;
 SELECT jsonb_agg(jsonb_build_object('id',rp.id,'role',rp.role,'email',rp.email,'name',rp.name,'order_index',rp.order_index,'locale',rp.locale) ORDER BY rp.id),
  jsonb_agg(to_jsonb(rp.role) ORDER BY rp.role) INTO expected_parties,expected_roles FROM recipients rp WHERE rp.document_id=doc.id;
 IF fields_json IS DISTINCT FROM expected_fields OR parties_json IS DISTINCT FROM jsonb_build_object(
  'required_roles',expected_roles,'routing_mode',doc.routing_mode,'parties',expected_parties) THEN RETURN FALSE; END IF;
 SELECT COALESCE(array_agg(page ORDER BY page),ARRAY[]::INTEGER[]) INTO expected_pages FROM (
  SELECT DISTINCT fp.page FROM document_fields fp WHERE fp.document_id=doc.id AND fp.type<>'signature' AND fp.value IS NOT NULL
   AND hash_fitted_trim_v1(fp.value)<>'' AND (fp.type<>'checkbox' OR lower(hash_fitted_trim_v1(fp.value)) IN('true','1','yes','on','checked','x'))
 ) actual_ordinary;
 IF admission.expected_ordinary_pages IS DISTINCT FROM expected_pages THEN RETURN FALSE; END IF;
 FOR member IN SELECT value FROM jsonb_array_elements(geometry_json->'pages') LOOP
  IF jsonb_typeof(member) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(member))<>3
   OR jsonb_typeof(member->'boxes') IS DISTINCT FROM 'array' OR jsonb_array_length(member->'boxes')<>5
   OR jsonb_typeof(member->'rotation') IS DISTINCT FROM 'number' OR (member->>'rotation')::integer%90<>0
   OR jsonb_typeof(member->'user_unit') IS DISTINCT FROM 'number' OR (member->>'user_unit')::numeric<=0 OR (member->>'user_unit')::numeric>75000 THEN RETURN FALSE; END IF;
  FOR box_member IN SELECT value FROM jsonb_array_elements(member->'boxes') LOOP
   IF jsonb_typeof(box_member) IS DISTINCT FROM 'array' OR jsonb_array_length(box_member)<>4 THEN RETURN FALSE; END IF;
   FOR coordinate IN SELECT value FROM jsonb_array_elements(box_member) LOOP
    IF jsonb_typeof(coordinate) IS DISTINCT FROM 'number' OR abs(coordinate::text::numeric)>1000000000 THEN RETURN FALSE; END IF;
   END LOOP;
   IF (box_member->>2)::numeric<=(box_member->>0)::numeric OR (box_member->>3)::numeric<=(box_member->>1)::numeric THEN RETURN FALSE; END IF;
  END LOOP;
  visible_x0:=greatest((member#>>'{boxes,0,0}')::numeric,(member#>>'{boxes,1,0}')::numeric);
  visible_y0:=greatest((member#>>'{boxes,0,1}')::numeric,(member#>>'{boxes,1,1}')::numeric);
  visible_x1:=least((member#>>'{boxes,0,2}')::numeric,(member#>>'{boxes,1,2}')::numeric);
  visible_y1:=least((member#>>'{boxes,0,3}')::numeric,(member#>>'{boxes,1,3}')::numeric);
  IF visible_x1<=visible_x0 OR visible_y1<=visible_y0 THEN
   visible_x0:=(member#>>'{boxes,0,0}')::numeric;visible_y0:=(member#>>'{boxes,0,1}')::numeric;
   visible_x1:=(member#>>'{boxes,0,2}')::numeric;visible_y1:=(member#>>'{boxes,0,3}')::numeric;
  END IF;
  IF (visible_x1-visible_x0)*(member->>'user_unit')::numeric>14400 OR (visible_y1-visible_y0)*(member->>'user_unit')::numeric>14400 THEN RETURN FALSE; END IF;
 END LOOP;
 IF ordinary_json IS DISTINCT FROM jsonb_build_object(
  'schema','hash-ordinary-page-recipe-v1','recipe_id','hash-ordinary-page-inter-11px-v1',
  'html_template_sha256','720927e59ff7a41b620f75370b21ed47257673aac7175ad408a1652392d8ed4c',
  'core_css_sha256','d398eb66d5b09f31cf39abe581f25276fc43f32a9278e611e2a185d3b2e9680e',
  'measurement_sha256','ca1800d540df736a3af8383d79c17e5a31423861ed3448ebb082628cf9108786',
  'snapshot_sha256','3a8f95ecd3438e40f1ba080f9e7a133ff8bc21cae42a4ff713507490ca5c3047',
  'print_recipe_sha256','472c32c79de2e6f4094a2c2729323c4d12d432c64334f765421048df8cddfa73',
  'fonts',jsonb_build_array(jsonb_build_object('file','Inter.woff2','family','Inter',
   'sha256','3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62','bytes',48256)))
  OR jsonb_typeof(recipe_json) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(recipe_json))<>2
  OR recipe_json->'ordinary' IS DISTINCT FROM ordinary_json
  OR jsonb_typeof(recipe_json->'original_branding_context') IS DISTINCT FROM 'object'
  OR (SELECT count(*) FROM jsonb_object_keys(recipe_json->'original_branding_context'))<>2
  OR jsonb_typeof(recipe_json->'original_branding_context'->'css') IS DISTINCT FROM 'string'
  OR octet_length(recipe_json->'original_branding_context'->>'css')>65536
  OR encode(digest(convert_to(recipe_json->'original_branding_context'->>'css','UTF8'),'sha256'),'hex') IS DISTINCT FROM encode(admission.branding_context_sha256,'hex')
  OR recipe_json->'original_branding_context'->>'sha256' IS DISTINCT FROM encode(admission.branding_context_sha256,'hex') THEN RETURN FALSE; END IF;
 RETURN basis_json IS NOT DISTINCT FROM jsonb_build_object('schema','hash-pdf-signing-static-basis-v1','org_id',doc.org_id,'document_id',doc.id,
  'original_document_name',admission.original_document_name,'ceremony_epoch',hash_article13_canonical_sent_at(admission.ceremony_epoch),
  'source_kind','pdf','requires_signature',TRUE,'is_envelope',FALSE,'parent_envelope_id','00000000-0000-0000-0000-000000000000'::uuid,
  'source',jsonb_build_object('key',admission.source_storage_key,'version_id',admission.source_version_id,'sha256',encode(admission.source_sha256,'hex'),'bytes',admission.source_bytes),
  'geometry',geometry_json,'fields',fields_json,'party_plan',parties_json,'render_recipe',recipe_json);
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Conservative prospective capacity floor, not the authoritative actual ZIP
-- ledger. Actual per-member/name/10k-entry accounting, known PDF section sizes,
-- producer ceilings and critical audit/version/index growth MUST be admitted
-- by the application before every irreversible signature. No debt disappears.
CREATE FUNCTION hash_pdf_admission_capacity_valid_v1(admission document_signing_admissions,doc documents)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE fit_future NUMERIC;pdf_future NUMERIC;ordinary_total NUMERIC;framing NUMERIC:=22;members BIGINT:=12;
 prep_row signature_fit_preparations%ROWTYPE;slot_row document_signing_admission_slots%ROWTYPE;pages INTEGER[];page_value INTEGER;
 name_value TEXT;live_count BIGINT;reserved_total NUMERIC;
BEGIN
 SELECT count(*),COALESCE(sum(reserved_bytes),0) INTO live_count,reserved_total FROM signature_fit_preparations
  WHERE document_id=doc.id AND org_id=doc.org_id AND status<>'cleaned';
 IF live_count>800 OR reserved_total IS DISTINCT FROM doc.signature_fit_reserved_bytes::numeric THEN RETURN FALSE; END IF;
 SELECT COALESCE(sum(bytes),0) INTO ordinary_total FROM document_signing_admission_bodies
  WHERE admission_id=admission.id AND org_id=doc.org_id AND document_id=doc.id;
 IF ordinary_total>admission.base_bytes_limit THEN RETURN FALSE; END IF;
 SELECT COALESCE(sum(sl.fit_bytes_limit) FILTER(WHERE sl.designated_preparation_id IS NULL),0),
  COALESCE(sum(sl.pdf_bytes_limit),0) INTO fit_future,pdf_future FROM document_signing_admission_slots sl WHERE sl.admission_id=admission.id;
 IF admission.source_bytes+admission.base_bytes_limit+pdf_future+admission.descriptor_bytes_limit>admission.processing_budget_bytes THEN RETURN FALSE; END IF;
 FOREACH name_value IN ARRAY ARRAY['source-'||doc.id::text||'.pdf','final-pdf.pdf','audit-cert.pdf','audit-cert-payload.txt',
  'audit-cert-signature.txt','signature-fit-index.json','events.json','versions.json','manifest.json','manifest-public-key.pem','certificate-public-key.pem'] LOOP
  framing:=framing+92+2*octet_length(name_value);
 END LOOP;
 members:=11;
 FOREACH page_value IN ARRAY admission.expected_ordinary_pages LOOP
  framing:=framing+92+2*octet_length('base-'||doc.id::text||'-page-'||page_value::text||'.pdf');members:=members+1;
 END LOOP;
 FOR slot_row IN SELECT * FROM document_signing_admission_slots WHERE admission_id=admission.id AND designated_preparation_id IS NULL LOOP
  framing:=framing+92+2*octet_length('fit-'||slot_row.recipient_id::text||'-manifest.json')+92+2*octet_length('fit-'||slot_row.recipient_id::text||'-span.html');
  members:=members+2;
  FOREACH page_value IN ARRAY slot_row.occupied_pages LOOP
   framing:=framing+92+2*octet_length('fit-'||slot_row.recipient_id::text||'-page-'||page_value::text||'.fit');members:=members+1;
  END LOOP;
 END LOOP;
 FOR prep_row IN SELECT * FROM signature_fit_preparations WHERE document_id=doc.id AND org_id=doc.org_id AND status<>'cleaned' LOOP
  SELECT oa.occupied_pages INTO pages FROM signature_fit_original_authorities oa WHERE oa.preparation_id=prep_row.id AND oa.org_id=doc.org_id AND oa.document_id=doc.id;
  IF NOT FOUND OR cardinality(pages)+2<>prep_row.expected_objects THEN
   -- Historical unknown inventory is still charged, with a bounded conservative
   -- name allowance; its emptiness is not cleanup/retry/signing permission.
   framing:=framing+prep_row.expected_objects::numeric*(92+2*128);members:=members+prep_row.expected_objects;
  ELSE
   framing:=framing+92+2*octet_length('fit-'||prep_row.id::text||'-manifest.json')+92+2*octet_length('fit-'||prep_row.id::text||'-span.html');
   members:=members+2;
   FOREACH page_value IN ARRAY pages LOOP
    framing:=framing+92+2*octet_length('fit-'||prep_row.id::text||'-page-'||page_value::text||'.fit');members:=members+1;
   END LOOP;
  END IF;
 END LOOP;
 RETURN members<=10000 AND admission.archive_budget_bytes>=reserved_total+fit_future+admission.source_bytes+admission.base_bytes_limit+
  admission.final_pdf_bytes_limit+admission.fits_index_bytes_limit+admission.certificate_pdf_bytes_limit+
  admission.certificate_payload_bytes_limit+admission.certificate_signature_bytes_limit+admission.events_bytes_limit+
  admission.versions_bytes_limit+admission.archive_manifest_bytes_limit+32768+framing;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END $$;

CREATE FUNCTION hash_pdf_admission_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE doc_row documents%ROWTYPE;stored_bytes BIGINT;body_pages INTEGER[];body_total BIGINT;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PDF admission originals are retained' USING ERRCODE='23514'; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'PDF admission requires read committed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT doc_row FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  IF doc_row.signing_admission_policy<>'pdf-static-v1' OR doc_row.signing_admission_sealed_id IS NOT NULL
   OR doc_row.status NOT IN('sent','in_progress') OR NEW.status<>'staging' OR NEW.attempts<>1 OR NEW.lease_until<=clock_timestamp()
   OR NEW.created_at<NEW.ceremony_epoch OR NEW.created_at>clock_timestamp() OR NEW.updated_at>clock_timestamp()
   OR NEW.ready_at IS NOT NULL OR NEW.sealed_at IS NOT NULL OR NEW.stale_at IS NOT NULL OR NEW.first_signature_id IS NOT NULL
   OR EXISTS(SELECT 1 FROM signatures WHERE document_id=doc_row.id)
   OR EXISTS(SELECT 1 FROM recipients WHERE document_id=doc_row.id AND status NOT IN('pending','sent','viewed'))
   OR NOT hash_pdf_admission_basis_matches_v1(NEW,doc_row) THEN
   RAISE EXCEPTION 'PDF admission capture differs from current unsigned ceremony' USING ERRCODE='23514'; END IF;
  stored_bytes:=octet_length(NEW.static_basis_payload)::bigint+octet_length(NEW.geometry_payload)+octet_length(NEW.geometry_pages_payload)+
   octet_length(NEW.fields_payload)+octet_length(NEW.parties_payload)+octet_length(NEW.render_recipe_payload)+octet_length(NEW.ordinary_recipe_payload)+
   octet_length(NEW.original_document_name)+octet_length(NEW.source_storage_key)+octet_length(NEW.source_version_id);
  UPDATE documents SET signing_admission_count=signing_admission_count+1,signing_admission_static_bytes=signing_admission_static_bytes+stored_bytes
   WHERE id=doc_row.id AND org_id=doc_row.org_id AND signing_admission_count<8 AND signing_admission_static_bytes+stored_bytes<=83886080;
  IF NOT FOUND THEN RAISE EXCEPTION 'retained PDF candidate quota exhausted' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['owner_id','lease_until','attempts','status','source_inspection_sha256','ready_at','sealed_at','stale_at','first_signature_id','updated_at'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['owner_id','lease_until','attempts','status','source_inspection_sha256','ready_at','sealed_at','stale_at','first_signature_id','updated_at'])
  OR (OLD.source_inspection_sha256 IS NOT NULL AND NEW.source_inspection_sha256 IS DISTINCT FROM OLD.source_inspection_sha256)
  OR (OLD.ready_at IS NOT NULL AND NEW.ready_at IS DISTINCT FROM OLD.ready_at)
  OR (OLD.sealed_at IS NOT NULL AND NEW.sealed_at IS DISTINCT FROM OLD.sealed_at)
  OR (OLD.stale_at IS NOT NULL AND NEW.stale_at IS DISTINCT FROM OLD.stale_at)
  OR (OLD.first_signature_id IS NOT NULL AND NEW.first_signature_id IS DISTINCT FROM OLD.first_signature_id) THEN
  RAISE EXCEPTION 'PDF admission identity and checkpoints are immutable' USING ERRCODE='23514'; END IF;
 IF NEW.status=OLD.status AND ROW(NEW.source_inspection_sha256,NEW.ready_at,NEW.sealed_at,NEW.stale_at,NEW.first_signature_id)
  IS DISTINCT FROM ROW(OLD.source_inspection_sha256,OLD.ready_at,OLD.sealed_at,OLD.stale_at,OLD.first_signature_id) THEN
  RAISE EXCEPTION 'PDF phase checkpoints require their exact state transition' USING ERRCODE='23514'; END IF;
 IF OLD.status IN('sealed','stale') AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'terminal PDF admission is immutable' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.owner_id,NEW.lease_until) IS DISTINCT FROM ROW(OLD.owner_id,OLD.lease_until) THEN
  IF OLD.lease_until>clock_timestamp() OR NEW.lease_until<=clock_timestamp() OR NEW.attempts<>OLD.attempts+1
   OR NEW.status<>OLD.status OR NEW.attempts>8 THEN RAISE EXCEPTION 'PDF admission takeover requires expiry' USING ERRCODE='23514'; END IF;
 ELSIF NEW.attempts<>OLD.attempts THEN RAISE EXCEPTION 'PDF admission attempt changes require takeover' USING ERRCODE='23514'; END IF;
 IF NEW.status IS DISTINCT FROM OLD.status AND NOT(
  (OLD.status='staging' AND NEW.status IN('ready','stale')) OR (OLD.status='ready' AND NEW.status IN('sealed','stale'))) THEN
  RAISE EXCEPTION 'PDF admission state cannot move backwards' USING ERRCODE='23514'; END IF;
 IF NEW.status='stale' THEN
  IF doc_row.signing_admission_sealed_id IS NOT NULL OR EXISTS(SELECT 1 FROM signatures WHERE document_id=doc_row.id)
   OR (doc_row.status IN('sent','in_progress') AND hash_pdf_admission_basis_matches_v1(NEW,doc_row)) THEN RAISE EXCEPTION 'current or signed PDF admission cannot be invalidated' USING ERRCODE='23514'; END IF;
  IF NEW.stale_at IS NULL OR NEW.stale_at>clock_timestamp() THEN RAISE EXCEPTION 'PDF stale checkpoint missing' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW IS DISTINCT FROM OLD AND NEW.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'PDF checkpoint requires current lease' USING ERRCODE='23514'; END IF;
 IF NOT hash_pdf_admission_basis_matches_v1(NEW,doc_row) OR doc_row.signing_admission_active_id IS DISTINCT FROM NEW.id
  OR doc_row.status NOT IN('sent','in_progress') THEN RAISE EXCEPTION 'PDF ready or seal basis is stale' USING ERRCODE='23514'; END IF;
 IF NEW.status='ready' AND OLD.status='staging' THEN
  SELECT COALESCE(array_agg(bd.page ORDER BY bd.page),ARRAY[]::INTEGER[]),COALESCE(sum(bd.bytes),0) INTO body_pages,body_total
   FROM document_signing_admission_bodies bd WHERE bd.admission_id=NEW.id;
  IF body_pages IS DISTINCT FROM NEW.expected_ordinary_pages OR body_total>NEW.base_bytes_limit OR NEW.source_inspection_sha256 IS NULL
   OR NEW.ready_at IS NULL OR NEW.ready_at>clock_timestamp()
   OR (SELECT count(*) FROM document_signing_admission_slots WHERE admission_id=NEW.id)<>NEW.required_parties
   OR NOT hash_pdf_admission_capacity_valid_v1(NEW,doc_row) THEN RAISE EXCEPTION 'PDF readiness requires complete admitted originals and capacity' USING ERRCODE='23514'; END IF;
 END IF;
 IF NEW.status='sealed' AND OLD.status='ready' THEN
  IF NEW.first_signature_id IS NULL OR NEW.sealed_at IS NULL OR NEW.sealed_at<NEW.ready_at OR NEW.sealed_at>clock_timestamp()
   OR NOT hash_pdf_admission_capacity_valid_v1(NEW,doc_row) THEN RAISE EXCEPTION 'PDF seal requires admitted real signature transaction' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'PDF admission parent missing' USING ERRCODE='23514';
END $$;
CREATE TRIGGER pdf_signing_admission_guard BEFORE INSERT OR UPDATE OR DELETE ON document_signing_admissions FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_guard_v1();

CREATE FUNCTION hash_pdf_admission_init_slots_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE party_row recipients%ROWTYPE;ids UUID[];pages INTEGER[];
BEGIN
 FOR party_row IN SELECT * FROM recipients WHERE document_id=NEW.document_id ORDER BY id FOR UPDATE LOOP
  SELECT array_agg(fp.id ORDER BY fp.id),array_agg(DISTINCT fp.page ORDER BY fp.page) INTO ids,pages
   FROM document_fields fp WHERE fp.document_id=NEW.document_id AND fp.recipient_id=party_row.id AND fp.type='signature' AND fp.required;
  INSERT INTO document_signing_admission_slots(admission_id,org_id,document_id,recipient_id,target_ids,occupied_pages,target_count,page_count,expected_objects,fit_bytes_limit,pdf_bytes_limit)
   VALUES(NEW.id,NEW.org_id,NEW.document_id,party_row.id,ids,pages,cardinality(ids),cardinality(pages),cardinality(pages)+2,
    3145728::bigint+cardinality(pages)::bigint*16777276,cardinality(pages)::bigint*8388608);
 END LOOP;
 RETURN NULL;
END $$;
CREATE TRIGGER pdf_signing_admission_init_slots AFTER INSERT ON document_signing_admissions FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_init_slots_v1();

CREATE FUNCTION hash_pdf_admission_body_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE doc_row documents%ROWTYPE;admission_row document_signing_admissions%ROWTYPE;total BIGINT;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'original ordinary PDFs are immutable and retained' USING ERRCODE='23514'; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'ordinary capture requires read committed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT doc_row FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 PERFORM 1 FROM recipients WHERE document_id=doc_row.id ORDER BY id FOR UPDATE;
 SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=NEW.admission_id AND org_id=doc_row.org_id AND document_id=doc_row.id FOR UPDATE;
 IF doc_row.signing_admission_policy<>'pdf-static-v1' OR doc_row.signing_admission_active_id IS DISTINCT FROM admission_row.id
  OR admission_row.status<>'staging' OR admission_row.owner_id<>NEW.captured_owner_id OR admission_row.lease_until<=clock_timestamp()
  OR admission_row.static_basis_sha256 IS DISTINCT FROM NEW.static_basis_sha256 OR NOT NEW.page=ANY(admission_row.expected_ordinary_pages)
  OR doc_row.status NOT IN('sent','in_progress') OR EXISTS(SELECT 1 FROM signatures WHERE document_id=doc_row.id)
  OR NOT hash_pdf_admission_basis_matches_v1(admission_row,doc_row) OR NOT hash_pdf_admission_plan_matches_v1(NEW,admission_row) OR substring(NEW.payload FROM 1 FOR 5)<>convert_to('%PDF-','UTF8') THEN
  RAISE EXCEPTION 'ordinary PDF capture differs from current frozen candidate' USING ERRCODE='23514'; END IF;
 SELECT COALESCE(sum(bytes),0) INTO total FROM document_signing_admission_bodies WHERE admission_id=admission_row.id;
 IF total+NEW.bytes>admission_row.base_bytes_limit THEN RAISE EXCEPTION 'ordinary PDF candidate body quota exhausted' USING ERRCODE='23514'; END IF;
 UPDATE documents SET signing_admission_ordinary_bytes=signing_admission_ordinary_bytes+NEW.bytes,
  signing_admission_plan_bytes=signing_admission_plan_bytes+octet_length(NEW.plan_payload)
  WHERE id=doc_row.id AND org_id=doc_row.org_id AND signing_admission_ordinary_bytes+NEW.bytes<=52428800
   AND signing_admission_plan_bytes+octet_length(NEW.plan_payload)<=8388608;
 IF NOT FOUND THEN RAISE EXCEPTION 'retained ordinary PDF document quota exhausted' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'ordinary PDF scoped parent missing' USING ERRCODE='23514';
END $$;
CREATE TRIGGER pdf_signing_admission_body_guard BEFORE INSERT OR UPDATE OR DELETE ON document_signing_admission_bodies FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_body_guard_v1();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION hash_pdf_admission_slot_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE doc_row documents%ROWTYPE;admission_row document_signing_admissions%ROWTYPE;prep_row signature_fit_preparations%ROWTYPE;
 original_row signature_fit_original_authorities%ROWTYPE;recipient_row recipients%ROWTYPE;ids UUID[];pages INTEGER[];
 original_json JSONB;expected_targets JSONB;fields_json JSONB;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PDF capacity slots are retained' USING ERRCODE='23514'; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'PDF slots require read committed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT doc_row FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO STRICT recipient_row FROM recipients WHERE id=NEW.recipient_id AND document_id=doc_row.id FOR UPDATE;
 SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=NEW.admission_id AND org_id=doc_row.org_id AND document_id=doc_row.id FOR UPDATE;
 fields_json:=convert_from(admission_row.fields_payload,'UTF8')::jsonb;
 SELECT array_agg((e->>'ID')::uuid ORDER BY (e->>'ID')::uuid),array_agg(DISTINCT (e->>'Page')::integer ORDER BY (e->>'Page')::integer)
  INTO ids,pages FROM jsonb_array_elements(fields_json) e WHERE e->>'Type'='signature' AND e->>'RecipientID'=recipient_row.id::text;
 IF NEW.target_ids IS DISTINCT FROM ids OR NEW.occupied_pages IS DISTINCT FROM pages OR admission_row.status='stale' THEN
  RAISE EXCEPTION 'PDF slot differs from complete frozen target set' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF admission_row.status<>'staging' OR NEW.designated_preparation_id IS NOT NULL OR NEW.designated_owner_id IS NOT NULL THEN
   RAISE EXCEPTION 'PDF slot must start as unsigned capacity' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['designated_preparation_id','designated_owner_id'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['designated_preparation_id','designated_owner_id']) THEN
  RAISE EXCEPTION 'PDF slot static identity is immutable' USING ERRCODE='23514'; END IF;
 IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF NEW.designated_preparation_id IS NULL OR NEW.designated_owner_id IS NULL OR doc_row.signing_admission_active_id IS DISTINCT FROM admission_row.id
  OR doc_row.status NOT IN('sent','in_progress') OR recipient_row.status NOT IN('pending','sent','viewed')
  OR NOT hash_pdf_admission_basis_matches_v1(admission_row,doc_row)
  OR EXISTS(SELECT 1 FROM signatures WHERE document_id=doc_row.id AND recipient_id=recipient_row.id)
  OR (OLD.designated_preparation_id IS NOT NULL AND EXISTS(SELECT 1 FROM signature_fit_selections WHERE preparation_id=OLD.designated_preparation_id)) THEN
  RAISE EXCEPTION 'PDF slot designation cannot replace a signed or selected choice' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT prep_row FROM signature_fit_preparations WHERE id=NEW.designated_preparation_id
  AND org_id=doc_row.org_id AND document_id=doc_row.id AND recipient_id=recipient_row.id FOR UPDATE;
 SELECT * INTO STRICT original_row FROM signature_fit_original_authorities WHERE preparation_id=prep_row.id
  AND org_id=doc_row.org_id AND document_id=doc_row.id AND recipient_id=recipient_row.id;
 original_json:=convert_from(original_row.authority_payload,'UTF8')::jsonb;
 SELECT jsonb_agg(jsonb_build_object('id',(e->>'ID')::uuid,'org_id',doc_row.org_id,'document_id',doc_row.id,'recipient_id',recipient_row.id,
  'page',(e->>'Page')::integer,'required',TRUE,'x_pct',e->>'X','y_pct',e->>'Y','w_pct',e->>'W','h_pct',e->>'H') ORDER BY (e->>'ID')::uuid)
  INTO expected_targets FROM jsonb_array_elements(fields_json) e WHERE e->>'Type'='signature' AND e->>'RecipientID'=recipient_row.id::text;
 IF ROW(prep_row.ceremony_epoch,prep_row.source_storage_key,prep_row.source_version_id,prep_row.source_sha256,prep_row.source_bytes,prep_row.geometry_sha256)
  IS DISTINCT FROM ROW(admission_row.ceremony_epoch,admission_row.source_storage_key,admission_row.source_version_id,admission_row.source_sha256,admission_row.source_bytes,admission_row.geometry_sha256)
  OR prep_row.owner_id IS DISTINCT FROM NEW.designated_owner_id OR prep_row.status NOT IN('staging','prepared')
  OR prep_row.reserved_bytes>NEW.fit_bytes_limit OR prep_row.expected_objects<>NEW.expected_objects
  OR original_row.occupied_pages IS DISTINCT FROM NEW.occupied_pages OR original_json->'targets' IS DISTINCT FROM expected_targets
  OR original_json->'geometry' IS DISTINCT FROM convert_from(admission_row.geometry_payload,'UTF8')::jsonb
  OR original_row.authority_sha256 IS DISTINCT FROM prep_row.authority_sha256
  OR (prep_row.lease_until<=clock_timestamp() AND NOT EXISTS(SELECT 1 FROM signature_fit_selections xs WHERE xs.preparation_id=prep_row.id AND xs.retention_completed_at IS NOT NULL))
  OR NOT EXISTS(SELECT 1 FROM signature_fit_original_payloads os WHERE os.preparation_id=prep_row.id AND os.kind='span' AND os.page=0 AND os.sha256=prep_row.span_sha256) THEN
  RAISE EXCEPTION 'PDF designated preparation lacks exact captured85/87 authority' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'PDF slot original scoped lineage missing' USING ERRCODE='23514';
END $$;
CREATE TRIGGER pdf_signing_admission_slot_guard BEFORE INSERT OR UPDATE OR DELETE ON document_signing_admission_slots FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_slot_guard_v1();

CREATE FUNCTION hash_pdf_admission_document_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admission_row document_signing_admissions%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.signing_admission_policy<>'historical' OR NEW.signing_admission_active_id IS NOT NULL OR NEW.signing_admission_sealed_id IS NOT NULL
   OR NEW.signing_admission_count<>0 OR NEW.signing_admission_static_bytes<>0 OR NEW.signing_admission_ordinary_bytes<>0 OR NEW.signing_admission_plan_bytes<>0 THEN
   RAISE EXCEPTION 'document must start with historical PDF policy' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.signing_admission_policy IS DISTINCT FROM OLD.signing_admission_policy THEN
  IF OLD.signing_admission_policy<>'historical' OR NEW.signing_admission_policy<>'pdf-static-v1'
   OR current_setting('transaction_isolation')<>'read committed' OR NEW.deleted_at IS NOT NULL OR NEW.status NOT IN('sent','in_progress')
   OR NEW.source_kind<>'pdf' OR NOT NEW.requires_signature OR NEW.is_envelope OR NEW.parent_envelope_id IS NOT NULL
   OR NOT NEW.evidence_version_pins_required OR NOT NEW.article13_notice_epoch_v61_committed OR NEW.sent_at IS DISTINCT FROM NEW.article13_notice_epoch_at
   OR NEW.signing_admission_active_id IS NOT NULL OR NEW.signing_admission_sealed_id IS NOT NULL
   OR EXISTS(SELECT 1 FROM signatures WHERE document_id=NEW.id) THEN
   RAISE EXCEPTION 'PDF admission policy cannot downgrade or upgrade a signed ceremony' USING ERRCODE='23514'; END IF;
 END IF;
 IF OLD.signing_admission_sealed_id IS NOT NULL AND ROW(NEW.signing_admission_sealed_id,NEW.signing_admission_active_id)
  IS DISTINCT FROM ROW(OLD.signing_admission_sealed_id,OLD.signing_admission_active_id) THEN
  RAISE EXCEPTION 'document sealed PDF admission is immutable' USING ERRCODE='23514'; END IF;
 IF NEW.signing_admission_active_id IS DISTINCT FROM OLD.signing_admission_active_id AND NEW.signing_admission_active_id IS NOT NULL THEN
  SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=NEW.signing_admission_active_id AND org_id=NEW.org_id AND document_id=NEW.id;
  IF NEW.signing_admission_policy<>'pdf-static-v1' OR admission_row.status NOT IN('staging','ready')
   OR EXISTS(SELECT 1 FROM signatures WHERE document_id=NEW.id) OR NOT hash_pdf_admission_basis_matches_v1(admission_row,NEW) THEN
   RAISE EXCEPTION 'document active PDF candidate is stale or signed' USING ERRCODE='23514'; END IF;
 END IF;
 IF OLD.signing_admission_active_id IS NOT NULL AND NEW.signing_admission_active_id IS NULL AND EXISTS(
  SELECT 1 FROM document_signing_admissions WHERE id=OLD.signing_admission_active_id AND status<>'stale') THEN
  RAISE EXCEPTION 'active PDF candidate must be positively invalidated before detaching' USING ERRCODE='23514'; END IF;
 IF NEW.signing_admission_sealed_id IS DISTINCT FROM OLD.signing_admission_sealed_id THEN
  SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=NEW.signing_admission_sealed_id AND org_id=NEW.org_id AND document_id=NEW.id;
  IF admission_row.status<>'sealed' OR NEW.signing_admission_active_id IS DISTINCT FROM admission_row.id THEN
   RAISE EXCEPTION 'document seal must name its exact active candidate' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'document PDF pointer lineage missing' USING ERRCODE='23514';
END $$;
CREATE TRIGGER pdf_signing_admission_document_guard BEFORE INSERT OR UPDATE ON documents FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_document_guard_v1();

-- Edits keep their existing pre-first-Sign behavior. A losing ready candidate
-- becomes stale under the parent fence; no quota is released or body discarded.
-- Once sealed, the captured source, field geometry/values and party identities
-- stay immutable. Status and signing progress are deliberately not basis data.
CREATE FUNCTION hash_pdf_admission_invalidate_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE affected_documents UUID[];target_document UUID;doc_row documents%ROWTYPE;admission_row document_signing_admissions%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='documents' THEN affected_documents:=ARRAY[OLD.id,NEW.id];
 ELSIF TG_OP='INSERT' THEN affected_documents:=ARRAY[NEW.document_id];
 ELSIF TG_OP='DELETE' THEN affected_documents:=ARRAY[OLD.document_id];
 ELSE affected_documents:=ARRAY[OLD.document_id,NEW.document_id];END IF;
 -- A move changes both parents. Acquire the entire parent set in UUID order
 -- before any admission lock, then reread each parent under those fences.
 PERFORM 1 FROM documents WHERE id=ANY(affected_documents) ORDER BY id FOR UPDATE;
 FOR target_document IN SELECT DISTINCT parent_id FROM unnest(affected_documents) AS parents(parent_id) WHERE parent_id IS NOT NULL ORDER BY parent_id LOOP
  SELECT * INTO doc_row FROM documents WHERE id=target_document FOR UPDATE;
  IF NOT FOUND OR doc_row.signing_admission_policy<>'pdf-static-v1' THEN CONTINUE;END IF;
  IF doc_row.signing_admission_sealed_id IS NOT NULL THEN
   SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=doc_row.signing_admission_sealed_id AND org_id=doc_row.org_id AND document_id=doc_row.id FOR UPDATE;
   IF admission_row.status<>'sealed' OR doc_row.signing_admission_active_id IS DISTINCT FROM admission_row.id
    OR NOT hash_pdf_admission_basis_matches_v1(admission_row,doc_row) THEN
    RAISE EXCEPTION 'signed PDF basis cannot be revised' USING ERRCODE='23514';
   END IF;
   CONTINUE;
  END IF;
  IF doc_row.signing_admission_active_id IS NULL THEN CONTINUE;END IF;
  SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=doc_row.signing_admission_active_id AND org_id=doc_row.org_id AND document_id=doc_row.id FOR UPDATE;
  IF admission_row.status IN('staging','ready') AND (doc_row.status NOT IN('sent','in_progress') OR NOT hash_pdf_admission_basis_matches_v1(admission_row,doc_row)) THEN
   -- A real signature must never race an edit into silently invalidating its
   -- basis. The transaction rolls back; first Sign and edit share the doc lock.
   IF EXISTS(SELECT 1 FROM signatures WHERE document_id=doc_row.id) THEN RAISE EXCEPTION 'signed PDF basis cannot be revised' USING ERRCODE='23514'; END IF;
   UPDATE document_signing_admissions SET status='stale',stale_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=admission_row.id;
   UPDATE documents SET signing_admission_active_id=NULL WHERE id=doc_row.id AND org_id=doc_row.org_id;
  END IF;
 END LOOP;
 RETURN NULL;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'document PDF admission lineage missing' USING ERRCODE='23514';
END $$;
CREATE TRIGGER pdf_admission_invalidate_fields AFTER INSERT OR UPDATE OR DELETE ON document_fields FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_invalidate_v1();
CREATE TRIGGER pdf_admission_invalidate_parties AFTER INSERT OR UPDATE OR DELETE ON recipients FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_invalidate_v1();
CREATE TRIGGER pdf_admission_invalidate_document AFTER UPDATE OF name,status,routing_mode,source_kind,requires_signature,is_envelope,parent_envelope_id,sent_at,article13_notice_epoch_at,article13_notice_epoch_v61_committed,evidence_version_pins_required,pdf_storage_key,pdf_storage_version_id,pdf_sha256,deleted_at ON documents FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_invalidate_v1();

CREATE FUNCTION hash_pdf_admission_signature_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE doc_row documents%ROWTYPE;admission_row document_signing_admissions%ROWTYPE;
BEGIN
 SELECT * INTO STRICT doc_row FROM documents WHERE id=NEW.document_id FOR UPDATE;
 IF doc_row.signing_admission_policy='historical' THEN RETURN NEW; END IF;
 IF current_setting('transaction_isolation')<>'read committed' OR doc_row.status NOT IN('sent','in_progress')
  OR NEW.signature_kind<>'manual_pdf_fit_v1' OR doc_row.signing_admission_active_id IS NULL THEN
  RAISE EXCEPTION 'new PDF policy requires actual fitted signature admission' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM recipients WHERE id=NEW.recipient_id AND document_id=doc_row.id AND status IN('pending','sent','viewed') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'new PDF signature recipient is not eligible' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=doc_row.signing_admission_active_id AND org_id=doc_row.org_id AND document_id=doc_row.id FOR UPDATE;
 IF admission_row.status NOT IN('ready','sealed') OR NOT hash_pdf_admission_basis_matches_v1(admission_row,doc_row)
  OR NOT hash_pdf_admission_capacity_valid_v1(admission_row,doc_row)
  OR (doc_row.signing_admission_sealed_id IS NOT NULL AND doc_row.signing_admission_sealed_id IS DISTINCT FROM admission_row.id) THEN
  RAISE EXCEPTION 'new PDF signature basis or capacity is stale' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'new PDF signature scoped basis missing' USING ERRCODE='23514';
END $$;
CREATE TRIGGER pdf_admission_signature_guard BEFORE INSERT ON signatures FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_signature_guard_v1();

CREATE FUNCTION hash_pdf_admission_binding_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE doc_row documents%ROWTYPE;admission_row document_signing_admissions%ROWTYPE;signature_row signatures%ROWTYPE;
 companion_row signature_fit_companions%ROWTYPE;selection_row signature_fit_selections%ROWTYPE;slot_row document_signing_admission_slots%ROWTYPE;
 original_json JSONB;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'actual PDF signature binding is immutable' USING ERRCODE='23514'; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'PDF binding requires read committed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT doc_row FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 PERFORM 1 FROM recipients WHERE id=NEW.recipient_id AND document_id=doc_row.id FOR UPDATE;
 SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=NEW.admission_id AND org_id=doc_row.org_id AND document_id=doc_row.id FOR UPDATE;
 SELECT * INTO STRICT signature_row FROM signatures WHERE id=NEW.signature_id AND document_id=doc_row.id AND recipient_id=NEW.recipient_id AND field_id=NEW.field_id;
 SELECT * INTO STRICT companion_row FROM signature_fit_companions WHERE signature_id=signature_row.id;
 SELECT * INTO STRICT selection_row FROM signature_fit_selections WHERE id=NEW.selection_id FOR UPDATE;
 SELECT * INTO STRICT slot_row FROM document_signing_admission_slots WHERE admission_id=admission_row.id AND recipient_id=signature_row.recipient_id FOR UPDATE;
 SELECT convert_from(oa.authority_payload,'UTF8')::jsonb INTO STRICT original_json FROM signature_fit_original_authorities oa WHERE oa.preparation_id=selection_row.preparation_id AND oa.org_id=doc_row.org_id AND oa.document_id=doc_row.id;
 IF doc_row.signing_admission_policy<>'pdf-static-v1' OR doc_row.signing_admission_active_id IS DISTINCT FROM admission_row.id
  OR admission_row.status<>'sealed' OR doc_row.signing_admission_sealed_id IS DISTINCT FROM admission_row.id
  OR NEW.static_basis_sha256 IS DISTINCT FROM admission_row.static_basis_sha256 OR NEW.reviewed_basis_sha256 IS DISTINCT FROM admission_row.static_basis_sha256
  OR signature_row.signature_kind<>'manual_pdf_fit_v1' OR NOT signature_row.field_id=ANY(slot_row.target_ids)
  OR companion_row.selection_id IS DISTINCT FROM selection_row.id
  OR ROW(companion_row.org_id,companion_row.document_id,companion_row.recipient_id,companion_row.field_id,companion_row.span_sha256)
     IS DISTINCT FROM ROW(doc_row.org_id,doc_row.id,signature_row.recipient_id,signature_row.field_id,signature_row.image_sha256)
  OR slot_row.designated_preparation_id IS DISTINCT FROM selection_row.preparation_id
  OR ROW(selection_row.org_id,selection_row.document_id,selection_row.recipient_id,selection_row.ceremony_epoch,selection_row.source_storage_key,selection_row.source_version_id,selection_row.source_sha256,selection_row.source_bytes,selection_row.geometry_sha256)
     IS DISTINCT FROM ROW(doc_row.org_id,doc_row.id,signature_row.recipient_id,admission_row.ceremony_epoch,admission_row.source_storage_key,admission_row.source_version_id,admission_row.source_sha256,admission_row.source_bytes,admission_row.geometry_sha256)
  OR ROW(selection_row.span_storage_key,selection_row.span_version_id,selection_row.span_sha256)
     IS DISTINCT FROM ROW(signature_row.image_storage_key,signature_row.image_version_id,signature_row.image_sha256)
  OR selection_row.retention_completed_at IS NULL OR selection_row.retention_completed_at>signature_row.signed_at
  OR original_json->>'typed_name' IS DISTINCT FROM signature_row.typed_name OR original_json->>'font' IS DISTINCT FROM signature_row.font
  OR original_json->>'span_sha256' IS DISTINCT FROM encode(signature_row.image_sha256,'hex')
  OR NOT hash_pdf_admission_basis_matches_v1(admission_row,doc_row) OR NOT hash_pdf_admission_capacity_valid_v1(admission_row,doc_row) THEN
  RAISE EXCEPTION 'actual PDF binding differs from sealed review and retained selection' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'actual PDF signature original lineage missing' USING ERRCODE='23514';
END $$;
CREATE TRIGGER pdf_admission_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON signature_signing_admission_bindings FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_binding_guard_v1();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION hash_pdf_admission_plan_matches_v1(body_row document_signing_admission_bodies,admission document_signing_admissions)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE plan_json JSONB;geometry_json JSONB;page_json JSONB;expected_fields JSONB;width_points DOUBLE PRECISION;height_points DOUBLE PRECISION;
 x0 DOUBLE PRECISION;y0 DOUBLE PRECISION;x1 DOUBLE PRECISION;y1 DOUBLE PRECISION;
BEGIN
 plan_json:=convert_from(body_row.plan_payload,'UTF8')::jsonb;
 geometry_json:=convert_from(admission.geometry_payload,'UTF8')::jsonb;page_json:=geometry_json->'pages'->(body_row.page-1);
 SELECT jsonb_agg(jsonb_build_object('id',e->>'ID','recipient_id',e->>'RecipientID','type',e->>'Type','required',e->'Required',
  'x_pct',e->>'X','y_pct',e->>'Y','w_pct',e->>'W','h_pct',e->>'H','value_valid',e->'ValueValid','value',e->>'Value') ORDER BY (e->>'ID')::uuid)
  INTO expected_fields FROM jsonb_array_elements(convert_from(admission.fields_payload,'UTF8')::jsonb) e
  WHERE (e->>'Page')::integer=body_row.page AND e->>'Type'<>'signature';
 IF expected_fields IS NULL OR jsonb_typeof(plan_json) IS DISTINCT FROM 'object'
  OR jsonb_typeof(plan_json->'width_points') IS DISTINCT FROM 'string' OR jsonb_typeof(plan_json->'height_points') IS DISTINCT FROM 'string'
  OR octet_length(plan_json->>'width_points') NOT BETWEEN 1 AND 128 OR octet_length(plan_json->>'height_points') NOT BETWEEN 1 AND 128
  OR plan_json->>'width_points' !~ '^[0-9]+([.][0-9]+)?$' OR plan_json->>'height_points' !~ '^[0-9]+([.][0-9]+)?$' THEN RETURN FALSE;END IF;
 x0:=greatest((page_json#>>'{boxes,0,0}')::double precision,(page_json#>>'{boxes,1,0}')::double precision);
 y0:=greatest((page_json#>>'{boxes,0,1}')::double precision,(page_json#>>'{boxes,1,1}')::double precision);
 x1:=least((page_json#>>'{boxes,0,2}')::double precision,(page_json#>>'{boxes,1,2}')::double precision);
 y1:=least((page_json#>>'{boxes,0,3}')::double precision,(page_json#>>'{boxes,1,3}')::double precision);
 IF x1<=x0 OR y1<=y0 THEN
  x0:=(page_json#>>'{boxes,0,0}')::double precision;y0:=(page_json#>>'{boxes,0,1}')::double precision;
  x1:=(page_json#>>'{boxes,0,2}')::double precision;y1:=(page_json#>>'{boxes,0,3}')::double precision;
 END IF;
 IF (page_json->>'rotation')::integer%180<>0 THEN
  width_points:=(y1-y0)*(page_json->>'user_unit')::double precision;height_points:=(x1-x0)*(page_json->>'user_unit')::double precision;
 ELSE
  width_points:=(x1-x0)*(page_json->>'user_unit')::double precision;height_points:=(y1-y0)*(page_json->>'user_unit')::double precision;
 END IF;
 IF (plan_json->>'width_points')::double precision IS DISTINCT FROM width_points OR (plan_json->>'height_points')::double precision IS DISTINCT FROM height_points THEN RETURN FALSE; END IF;
 RETURN plan_json IS NOT DISTINCT FROM jsonb_build_object('schema',1,'org_id',admission.org_id,'document_id',admission.document_id,
  'ceremony_epoch',hash_article13_canonical_sent_at(admission.ceremony_epoch),'source_key',admission.source_storage_key,'source_version_id',admission.source_version_id,
  'source_sha256',encode(admission.source_sha256,'hex'),'source_bytes',admission.source_bytes,'source_pages',admission.source_pages,'geometry_sha256',encode(admission.geometry_sha256,'hex'),
  'page',body_row.page,'geometry',page_json,'width_points',plan_json->>'width_points','height_points',plan_json->>'height_points',
  'static_basis_sha256',encode(admission.static_basis_sha256,'hex'),'fields_sha256',encode(admission.fields_sha256,'hex'),
  'branding_context_sha256',encode(admission.branding_context_sha256,'hex'),'render_recipe_sha256',encode(admission.ordinary_recipe_sha256,'hex'),'fields',expected_fields);
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END $$;

-- This deferred pair includes statuses/audit, not merely a companion. The
-- original request's final credential recheck remains a caller obligation.
CREATE FUNCTION hash_pdf_admission_actual_pair_check_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE signature_uuid UUID;signature_row signatures%ROWTYPE;doc_row documents%ROWTYPE;
 admission_row document_signing_admissions%ROWTYPE;binding_row signature_signing_admission_bindings%ROWTYPE;event_row events%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='signatures' THEN signature_uuid:=NEW.id;
 ELSIF TG_TABLE_NAME='signature_signing_admission_bindings' THEN signature_uuid:=NEW.signature_id;
 ELSIF TG_TABLE_NAME='documents' THEN
  IF NEW.signing_admission_sealed_id IS NULL OR NEW.signing_admission_sealed_id IS NOT DISTINCT FROM OLD.signing_admission_sealed_id THEN RETURN NULL;END IF;
  SELECT first_signature_id INTO STRICT signature_uuid FROM document_signing_admissions WHERE id=NEW.signing_admission_sealed_id;
 ELSE
  IF NEW.status<>'sealed' THEN RETURN NULL;END IF;signature_uuid:=NEW.first_signature_id;
 END IF;
 SELECT * INTO STRICT signature_row FROM signatures WHERE id=signature_uuid;
 SELECT * INTO STRICT doc_row FROM documents WHERE id=signature_row.document_id FOR UPDATE;
 IF doc_row.signing_admission_policy='historical' THEN RETURN NULL;END IF;
 SELECT * INTO STRICT binding_row FROM signature_signing_admission_bindings WHERE signature_id=signature_row.id;
 SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=binding_row.admission_id AND org_id=doc_row.org_id AND document_id=doc_row.id;
 SELECT * INTO STRICT event_row FROM events WHERE id=binding_row.signed_event_id;
 IF admission_row.status<>'sealed' OR doc_row.signing_admission_active_id IS DISTINCT FROM admission_row.id
  OR doc_row.signing_admission_sealed_id IS DISTINCT FROM admission_row.id OR NOT doc_row.fits_index_required
  OR signature_row.signature_kind<>'manual_pdf_fit_v1' OR doc_row.status NOT IN('in_progress','finalizing','completed')
  OR signature_row.signed_at<admission_row.ceremony_epoch
  OR NOT EXISTS(SELECT 1 FROM recipients rp WHERE rp.id=signature_row.recipient_id AND rp.document_id=doc_row.id AND rp.status='signed' AND rp.signed_at IS NOT NULL)
  OR ROW(binding_row.org_id,binding_row.document_id,binding_row.recipient_id,binding_row.field_id,binding_row.static_basis_sha256)
    IS DISTINCT FROM ROW(doc_row.org_id,doc_row.id,signature_row.recipient_id,signature_row.field_id,admission_row.static_basis_sha256)
  OR ROW(event_row.org_id,event_row.document_id,event_row.recipient_id,event_row.kind)
    IS DISTINCT FROM ROW(doc_row.org_id,doc_row.id,signature_row.recipient_id,'document.signed'::text)
  OR event_row.payload_hashed IS NULL OR (convert_from(event_row.payload_hashed,'UTF8')::jsonb)->>'signature_id' IS DISTINCT FROM signature_row.id::text
  OR event_row.payload_json IS DISTINCT FROM convert_from(event_row.payload_hashed,'UTF8')::jsonb THEN
  RAISE EXCEPTION 'PDF signature seal/status/original audit pair is incomplete' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM signature_signing_admission_bindings WHERE signature_id=admission_row.first_signature_id AND admission_id=admission_row.id) THEN
  RAISE EXCEPTION 'PDF first seal lacks its exact real signature binding' USING ERRCODE='23514'; END IF;
 RETURN NULL;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'PDF actual signature/audit pair missing' USING ERRCODE='23514';
END $$;
CREATE CONSTRAINT TRIGGER pdf_admission_pair_signature AFTER INSERT ON signatures DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_actual_pair_check_v1();
CREATE CONSTRAINT TRIGGER pdf_admission_pair_binding AFTER INSERT ON signature_signing_admission_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_actual_pair_check_v1();
CREATE CONSTRAINT TRIGGER pdf_admission_pair_seal AFTER UPDATE ON document_signing_admissions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_actual_pair_check_v1();
CREATE CONSTRAINT TRIGGER pdf_admission_pair_document AFTER UPDATE ON documents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_actual_pair_check_v1();

CREATE FUNCTION hash_pdf_admission_fit_reservation_check_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE doc_row documents%ROWTYPE;admission_row document_signing_admissions%ROWTYPE;
BEGIN
 SELECT * INTO STRICT doc_row FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF doc_row.signing_admission_policy='historical' THEN RETURN NULL;END IF;
 SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=doc_row.signing_admission_active_id AND org_id=doc_row.org_id AND document_id=doc_row.id;
 IF doc_row.status NOT IN('sent','in_progress') OR admission_row.status NOT IN('staging','ready','sealed')
  OR EXISTS(SELECT 1 FROM signatures WHERE document_id=doc_row.id AND recipient_id=NEW.recipient_id)
  OR NOT EXISTS(SELECT 1 FROM document_signing_admission_slots sl WHERE sl.admission_id=admission_row.id AND sl.recipient_id=NEW.recipient_id AND sl.designated_preparation_id=NEW.id)
  OR NOT hash_pdf_admission_basis_matches_v1(admission_row,doc_row) OR NOT hash_pdf_admission_capacity_valid_v1(admission_row,doc_row) THEN
  RAISE EXCEPTION 'new PDF fit reservation requires atomic exact future-slot designation and capacity' USING ERRCODE='23514'; END IF;
 RETURN NULL;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'new PDF fit reservation admission missing' USING ERRCODE='23514';
END $$;
CREATE CONSTRAINT TRIGGER pdf_admission_fit_reservation_pair AFTER INSERT ON signature_fit_preparations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_fit_reservation_check_v1();

CREATE FUNCTION hash_pdf_admission_retained_counter_check_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_uuid UUID;doc_row documents%ROWTYPE;candidate_count BIGINT;static_total NUMERIC;ordinary_total NUMERIC;plan_total NUMERIC;
BEGIN
 IF TG_TABLE_NAME='documents' THEN target_uuid:=NEW.id;ELSE target_uuid:=NEW.document_id;END IF;
 SELECT * INTO doc_row FROM documents WHERE id=target_uuid FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT count(*),COALESCE(sum(octet_length(ad.static_basis_payload)::bigint+octet_length(ad.geometry_payload)+octet_length(ad.geometry_pages_payload)+
  octet_length(ad.fields_payload)+octet_length(ad.parties_payload)+octet_length(ad.render_recipe_payload)+octet_length(ad.ordinary_recipe_payload)+
  octet_length(ad.original_document_name)+octet_length(ad.source_storage_key)+octet_length(ad.source_version_id)),0)
  INTO candidate_count,static_total FROM document_signing_admissions ad WHERE ad.document_id=doc_row.id AND ad.org_id=doc_row.org_id;
 SELECT COALESCE(sum(bd.bytes),0),COALESCE(sum(octet_length(bd.plan_payload)),0) INTO ordinary_total,plan_total
  FROM document_signing_admission_bodies bd WHERE bd.document_id=doc_row.id AND bd.org_id=doc_row.org_id;
 IF ROW(doc_row.signing_admission_count::bigint,doc_row.signing_admission_static_bytes::numeric,doc_row.signing_admission_ordinary_bytes::numeric,doc_row.signing_admission_plan_bytes::numeric)
  IS DISTINCT FROM ROW(candidate_count,static_total,ordinary_total,plan_total) THEN
  RAISE EXCEPTION 'retained PDF admission counters differ from immutable inventory' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER pdf_admission_retained_header AFTER INSERT ON document_signing_admissions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_retained_counter_check_v1();
CREATE CONSTRAINT TRIGGER pdf_admission_retained_body AFTER INSERT ON document_signing_admission_bodies DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_retained_counter_check_v1();
CREATE CONSTRAINT TRIGGER pdf_admission_retained_document AFTER INSERT OR UPDATE ON documents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_pdf_admission_retained_counter_check_v1();
-- +goose StatementEnd

-- +goose StatementBegin
-- Fresh locked SQL consistency check only. Returned metadata never contains
-- original bodies; SQL's own bounded validation is not genuine worker proof.
CREATE FUNCTION hash_pdf_admission_current_matches_v1(target_id UUID,target_org UUID,target_document UUID)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE doc_row documents%ROWTYPE;admission_row document_signing_admissions%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RETURN FALSE;END IF;
 SELECT * INTO STRICT doc_row FROM documents WHERE id=target_document AND org_id=target_org FOR UPDATE;
 PERFORM 1 FROM recipients WHERE document_id=doc_row.id ORDER BY id FOR UPDATE;
 SELECT * INTO STRICT admission_row FROM document_signing_admissions WHERE id=target_id AND org_id=target_org AND document_id=target_document FOR UPDATE;
 RETURN doc_row.signing_admission_policy='pdf-static-v1' AND doc_row.signing_admission_active_id=admission_row.id
  AND admission_row.status<>'stale' AND hash_pdf_admission_basis_matches_v1(admission_row,doc_row);
EXCEPTION WHEN NO_DATA_FOUND THEN RETURN FALSE;
END $$;
-- +goose StatementEnd

-- +goose Down
-- A stale transaction snapshot must not infer an empty retained inventory.
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'PDF admission rollback requires read committed' USING ERRCODE='23514';END IF;
END $$;
-- +goose StatementEnd
LOCK TABLE documents,document_signing_admissions,document_signing_admission_bodies,document_signing_admission_slots,signature_signing_admission_bindings IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM document_signing_admissions) OR EXISTS(SELECT 1 FROM document_signing_admission_bodies)
  OR EXISTS(SELECT 1 FROM document_signing_admission_slots) OR EXISTS(SELECT 1 FROM signature_signing_admission_bindings)
  OR EXISTS(SELECT 1 FROM documents WHERE signing_admission_policy<>'historical' OR signing_admission_active_id IS NOT NULL OR signing_admission_sealed_id IS NOT NULL
   OR signing_admission_count<>0 OR signing_admission_static_bytes<>0 OR signing_admission_ordinary_bytes<>0 OR signing_admission_plan_bytes<>0) THEN
  RAISE EXCEPTION 'cannot discard used PDF admissions, originals or policy' USING ERRCODE='23514';END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER pdf_admission_retained_document ON documents;
DROP TRIGGER pdf_admission_retained_body ON document_signing_admission_bodies;
DROP TRIGGER pdf_admission_retained_header ON document_signing_admissions;
DROP TRIGGER pdf_admission_fit_reservation_pair ON signature_fit_preparations;
DROP TRIGGER pdf_admission_pair_document ON documents;
DROP TRIGGER pdf_admission_pair_seal ON document_signing_admissions;
DROP TRIGGER pdf_admission_pair_binding ON signature_signing_admission_bindings;
DROP TRIGGER pdf_admission_pair_signature ON signatures;
DROP TRIGGER pdf_admission_binding_guard ON signature_signing_admission_bindings;
DROP TRIGGER pdf_admission_signature_guard ON signatures;
DROP TRIGGER pdf_admission_invalidate_document ON documents;
DROP TRIGGER pdf_admission_invalidate_parties ON recipients;
DROP TRIGGER pdf_admission_invalidate_fields ON document_fields;
DROP TRIGGER pdf_signing_admission_document_guard ON documents;
DROP TRIGGER pdf_signing_admission_slot_guard ON document_signing_admission_slots;
DROP TRIGGER pdf_signing_admission_body_guard ON document_signing_admission_bodies;
DROP TRIGGER pdf_signing_admission_init_slots ON document_signing_admissions;
DROP TRIGGER pdf_signing_admission_guard ON document_signing_admissions;
DROP FUNCTION hash_pdf_admission_current_matches_v1(UUID,UUID,UUID);
DROP FUNCTION hash_pdf_admission_retained_counter_check_v1();
DROP FUNCTION hash_pdf_admission_fit_reservation_check_v1();
DROP FUNCTION hash_pdf_admission_actual_pair_check_v1();
DROP FUNCTION hash_pdf_admission_binding_guard_v1();
DROP FUNCTION hash_pdf_admission_signature_guard_v1();
DROP FUNCTION hash_pdf_admission_invalidate_v1();
DROP FUNCTION hash_pdf_admission_document_guard_v1();
DROP FUNCTION hash_pdf_admission_slot_guard_v1();
DROP FUNCTION hash_pdf_admission_body_guard_v1();
DROP FUNCTION hash_pdf_admission_init_slots_v1();
DROP FUNCTION hash_pdf_admission_guard_v1();
DROP FUNCTION hash_pdf_admission_plan_matches_v1(document_signing_admission_bodies,document_signing_admissions);
DROP FUNCTION hash_pdf_admission_capacity_valid_v1(document_signing_admissions,documents);
DROP FUNCTION hash_pdf_admission_basis_matches_v1(document_signing_admissions,documents);
ALTER TABLE documents DROP CONSTRAINT documents_signing_admission_active_identity,DROP CONSTRAINT documents_signing_admission_sealed_identity;
DROP TABLE signature_signing_admission_bindings,document_signing_admission_slots,document_signing_admission_bodies,document_signing_admissions;
ALTER TABLE signatures DROP CONSTRAINT signatures_admission_document_identity;
ALTER TABLE signature_fit_preparations DROP CONSTRAINT signature_fit_preparations_admission_identity;
ALTER TABLE documents DROP COLUMN signing_admission_policy,DROP COLUMN signing_admission_active_id,DROP COLUMN signing_admission_sealed_id,
 DROP COLUMN signing_admission_count,DROP COLUMN signing_admission_static_bytes,DROP COLUMN signing_admission_ordinary_bytes,DROP COLUMN signing_admission_plan_bytes;
