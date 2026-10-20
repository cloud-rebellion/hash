-- +goose Up
-- Opt-in immutable originals for newly captured fit preparations. Historical
-- migration85 preparations without an authority sidecar retain their existing
-- protocol. This migration grants no signing, upload retry, cleanup or DSR
-- permission. Production must admit global DB staging resources before capture;
-- these retained per-document ceilings are not a tenant/global storage quota.
-- +goose StatementBegin
DO $$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'fit original installation requires read committed' USING ERRCODE='23514';
 END IF;
END;
$$;
-- +goose StatementEnd

ALTER TABLE documents
 ADD COLUMN signature_fit_original_payload_bytes BIGINT NOT NULL DEFAULT 0
  CHECK(signature_fit_original_payload_bytes BETWEEN 0 AND 167772160),
 ADD COLUMN signature_fit_original_authority_bytes BIGINT NOT NULL DEFAULT 0
  CHECK(signature_fit_original_authority_bytes BETWEEN 0 AND 134217728),
 ADD COLUMN signature_fit_original_authority_count INTEGER NOT NULL DEFAULT 0
  CHECK(signature_fit_original_authority_count BETWEEN 0 AND 128);

CREATE TABLE signature_fit_original_authorities (
 preparation_id UUID PRIMARY KEY,
 org_id UUID NOT NULL, document_id UUID NOT NULL, recipient_id UUID NOT NULL,
 ceremony_epoch TIMESTAMPTZ NOT NULL CHECK(isfinite(ceremony_epoch)),
 authority_payload BYTEA NOT NULL,
 authority_sha256 BYTEA NOT NULL CHECK(octet_length(authority_sha256)=32),
 authority_bytes BIGINT NOT NULL CHECK(authority_bytes BETWEEN 1 AND 1048576),
 occupied_pages INTEGER[] NOT NULL CHECK(cardinality(occupied_pages) BETWEEN 1 AND 500),
 captured_owner_id UUID NOT NULL CHECK(captured_owner_id<>'00000000-0000-0000-0000-000000000000'),
 captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(captured_at)),
 CHECK(octet_length(authority_payload)=authority_bytes AND digest(authority_payload,'sha256')=authority_sha256),
 UNIQUE(preparation_id,org_id,document_id),
 FOREIGN KEY(preparation_id,org_id,document_id,recipient_id,ceremony_epoch)
  REFERENCES signature_fit_preparations(id,org_id,document_id,recipient_id,ceremony_epoch) ON DELETE RESTRICT
);
CREATE INDEX signature_fit_original_authority_inventory ON signature_fit_original_authorities(document_id,org_id,preparation_id);

CREATE TABLE signature_fit_original_payloads (
 preparation_id UUID NOT NULL, org_id UUID NOT NULL, document_id UUID NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('span','page','manifest')),
 page INTEGER NOT NULL CHECK((kind='page' AND page BETWEEN 1 AND 500) OR (kind IN('span','manifest') AND page=0)),
 storage_key TEXT NOT NULL UNIQUE CHECK(octet_length(storage_key) BETWEEN 1 AND 2048),
 sha256 BYTEA NOT NULL CHECK(octet_length(sha256)=32),
 bytes BIGINT NOT NULL CHECK(bytes>0 AND
  ((kind='span' AND bytes<=1048576) OR (kind='manifest' AND bytes<=2097152) OR (kind='page' AND bytes<=16777276))),
 content_type TEXT NOT NULL CHECK(
  (kind='span' AND content_type='text/html') OR
  (kind='manifest' AND content_type='application/json') OR
  (kind='page' AND content_type='application/vnd.hash.signature-fit.v1')),
 payload BYTEA NOT NULL,
 captured_owner_id UUID NOT NULL CHECK(captured_owner_id<>'00000000-0000-0000-0000-000000000000'),
 captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(captured_at)),
 PRIMARY KEY(preparation_id,kind,page),
 CHECK(octet_length(payload)=bytes AND digest(payload,'sha256')=sha256),
 FOREIGN KEY(preparation_id,org_id,document_id)
  REFERENCES signature_fit_original_authorities(preparation_id,org_id,document_id) ON DELETE RESTRICT
);
CREATE INDEX signature_fit_original_payload_inventory ON signature_fit_original_payloads(document_id,org_id,preparation_id);

-- Literal canonical JSON is produced/decoded by manualfit's frozen V1 reader,
-- including duplicate-key closure, font/geometry/plan validation and canonical
-- byte equality, BEFORE this query. SQL additionally binds the exact raw SHA,
-- scalar source/geometry identities, complete current assigned target set and
-- occupied page membership. This is not a replacement signing credential or
-- an isolated-worker geometry/package admission.
-- +goose StatementBegin
CREATE FUNCTION hash_signature_fit_original_authority_matches_v1(
 original signature_fit_original_authorities, prep signature_fit_preparations
) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE a JSONB; geometry JSONB; member JSONB; target JSONB; actual_targets JSONB;
 page_numbers INTEGER[]:=ARRAY[]::integer[]; target_ids JSONB; page_targets JSONB;
 page_number INTEGER; source_pages INTEGER; field_count BIGINT;
BEGIN
 a:=convert_from(original.authority_payload,'UTF8')::jsonb;
 IF jsonb_typeof(a) IS DISTINCT FROM 'object'
  OR a->>'schema' IS DISTINCT FROM 'manual_pdf_fit_v1'
  OR a->>'org_id' IS DISTINCT FROM prep.org_id::text
  OR a->>'document_id' IS DISTINCT FROM prep.document_id::text
  OR a->>'recipient_id' IS DISTINCT FROM prep.recipient_id::text
  OR a->>'ceremony_epoch' IS DISTINCT FROM hash_article13_canonical_sent_at(prep.ceremony_epoch)
  OR a->'source' IS DISTINCT FROM jsonb_build_object('key',prep.source_storage_key,
   'version_id',prep.source_version_id,'sha256',encode(prep.source_sha256,'hex'),'bytes',prep.source_bytes)
  OR a->>'span_sha256' IS DISTINCT FROM encode(prep.span_sha256,'hex')
  OR jsonb_typeof(a->'typed_name') IS DISTINCT FROM 'string'
  OR octet_length(a->>'typed_name') NOT BETWEEN 1 AND 800
  OR jsonb_typeof(a->'font') IS DISTINCT FROM 'string'
  OR jsonb_typeof(a->'font_info') IS DISTINCT FROM 'object'
  OR jsonb_typeof(a->'targets') IS DISTINCT FROM 'array'
  OR jsonb_typeof(a->'expected_target_ids') IS DISTINCT FROM 'array'
  OR jsonb_typeof(a->'pages') IS DISTINCT FROM 'array' THEN RETURN FALSE; END IF;
 geometry:=a->'geometry';
 IF jsonb_typeof(geometry) IS DISTINCT FROM 'object'
  OR geometry->'schema_version' IS DISTINCT FROM '1'::jsonb
  OR geometry->>'source_sha256' IS DISTINCT FROM encode(prep.source_sha256,'hex')
  OR (geometry->>'source_bytes')::bigint IS DISTINCT FROM prep.source_bytes
  OR geometry->>'geometry_sha256' IS DISTINCT FROM encode(prep.geometry_sha256,'hex')
  OR jsonb_typeof(geometry->'pages') IS DISTINCT FROM 'array' THEN RETURN FALSE; END IF;
 source_pages:=jsonb_array_length(geometry->'pages');
 IF source_pages NOT BETWEEN 1 AND 500 OR jsonb_array_length(a->'targets') NOT BETWEEN 1 AND 1000
  OR jsonb_array_length(a->'pages') NOT BETWEEN 1 AND source_pages
  OR prep.expected_objects<>jsonb_array_length(a->'pages')+2 THEN RETURN FALSE; END IF;
 SELECT count(*),COALESCE(jsonb_agg(jsonb_build_object('id',f.id,'org_id',prep.org_id,
  'document_id',f.document_id,'recipient_id',f.recipient_id,'page',f.page,'required',f.required,
  'x_pct',f.x_pct::text,'y_pct',f.y_pct::text,'w_pct',f.w_pct::text,'h_pct',f.h_pct::text) ORDER BY f.id),'[]'::jsonb),
  COALESCE(jsonb_agg(to_jsonb(f.id) ORDER BY f.id),'[]'::jsonb)
  INTO field_count,actual_targets,target_ids
 FROM document_fields f WHERE f.document_id=prep.document_id AND f.recipient_id=prep.recipient_id AND f.type='signature';
 IF field_count NOT BETWEEN 1 AND 1000 OR a->'targets' IS DISTINCT FROM actual_targets
  OR a->'expected_target_ids' IS DISTINCT FROM target_ids THEN RETURN FALSE; END IF;
 FOR target IN SELECT item.value FROM jsonb_array_elements(a->'targets') item(value) LOOP
  IF target->'required' IS DISTINCT FROM 'true'::jsonb OR (target->>'page')::integer NOT BETWEEN 1 AND source_pages
   OR (target->>'x_pct')::numeric<0 OR (target->>'y_pct')::numeric<0
   OR (target->>'w_pct')::numeric<=0 OR (target->>'h_pct')::numeric<=0
   OR (target->>'x_pct')::numeric+(target->>'w_pct')::numeric>100
   OR (target->>'y_pct')::numeric+(target->>'h_pct')::numeric>100 THEN RETURN FALSE; END IF;
 END LOOP;
 FOR member IN SELECT item.value FROM jsonb_array_elements(a->'pages') item(value) LOOP
  page_number:=(member->'plan'->>'page')::integer;
  IF page_number IS NULL OR page_number NOT BETWEEN 1 AND source_pages
   OR (cardinality(page_numbers)>0 AND page_number<=page_numbers[cardinality(page_numbers)])
   OR member->'plan'->>'text' IS DISTINCT FROM a->>'typed_name'
   OR member->'plan'->>'font' IS DISTINCT FROM a->>'font'
   OR member->'plan'->>'sourceSha256' IS DISTINCT FROM encode(prep.source_sha256,'hex')
   OR member->'plan'->>'geometrySha256' IS DISTINCT FROM encode(prep.geometry_sha256,'hex')
   OR member->'plan'->>'spanSha256' IS DISTINCT FROM encode(prep.span_sha256,'hex')
   OR NOT COALESCE(member->>'input_sha256' ~ '^[0-9a-f]{64}$',FALSE)
   OR jsonb_typeof(member->'plan'->'targets') IS DISTINCT FROM 'array' THEN RETURN FALSE; END IF;
  SELECT COALESCE(jsonb_agg(t.value->'id' ORDER BY t.value->>'id'),'[]'::jsonb) INTO page_targets
   FROM jsonb_array_elements(member->'plan'->'targets') t(value);
  SELECT COALESCE(jsonb_agg(t.value->'id' ORDER BY t.value->>'id'),'[]'::jsonb) INTO target_ids
   FROM jsonb_array_elements(a->'targets') t(value) WHERE (t.value->>'page')::integer=page_number;
  IF page_targets IS DISTINCT FROM target_ids OR jsonb_array_length(page_targets) NOT BETWEEN 1 AND 128 THEN RETURN FALSE; END IF;
  page_numbers:=array_append(page_numbers,page_number);
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(a->'targets') t(value) WHERE NOT (t.value->>'page')::integer=ANY(page_numbers))
  OR page_numbers IS DISTINCT FROM original.occupied_pages THEN RETURN FALSE; END IF;
 RETURN TRUE;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END;
$$;

CREATE FUNCTION hash_signature_fit_original_authority_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE doc documents%ROWTYPE; recipient_row recipients%ROWTYPE; prep signature_fit_preparations%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'fit original authority is immutable and retained' USING ERRCODE='23514'; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'fit original capture requires read committed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT doc FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT * INTO STRICT recipient_row FROM recipients WHERE id=NEW.recipient_id AND document_id=doc.id FOR UPDATE;
 SELECT * INTO STRICT prep FROM signature_fit_preparations WHERE id=NEW.preparation_id
  AND org_id=NEW.org_id AND document_id=NEW.document_id AND recipient_id=NEW.recipient_id FOR UPDATE;
 IF doc.deleted_at IS NOT NULL OR doc.status NOT IN('sent','in_progress') OR doc.source_kind<>'pdf'
  OR NOT doc.requires_signature OR NOT doc.evidence_version_pins_required OR doc.is_envelope OR doc.parent_envelope_id IS NOT NULL
  OR NOT doc.article13_notice_epoch_v61_committed
  OR ROW(doc.sent_at,doc.article13_notice_epoch_at,doc.pdf_storage_key,doc.pdf_storage_version_id,doc.pdf_sha256)
     IS DISTINCT FROM ROW(prep.ceremony_epoch,prep.ceremony_epoch,prep.source_storage_key,prep.source_version_id,prep.source_sha256)
  OR recipient_row.status NOT IN('pending','sent','viewed') OR recipient_row.role IN('cc','viewer')
  OR prep.status<>'staging' OR prep.owner_id<>NEW.captured_owner_id OR prep.lease_until<=clock_timestamp()
  OR prep.selection_commit_attempted_at IS NOT NULL
  OR NEW.ceremony_epoch IS DISTINCT FROM prep.ceremony_epoch OR NEW.authority_sha256 IS DISTINCT FROM prep.authority_sha256
  OR EXISTS(SELECT 1 FROM signature_fit_selections s WHERE s.preparation_id=prep.id)
  OR EXISTS(SELECT 1 FROM signature_fit_objects o WHERE o.preparation_id=prep.id)
  OR NOT hash_signature_fit_original_authority_matches_v1(NEW,prep) THEN
  RAISE EXCEPTION 'fit original authority differs from current staging ceremony' USING ERRCODE='23514'; END IF;
 -- Retained accounting never follows85 cleaned/debt release. Unknown/selected
 -- operations continue to count; there is intentionally no discard mutation.
 UPDATE documents SET signature_fit_original_authority_bytes=signature_fit_original_authority_bytes+NEW.authority_bytes,
  signature_fit_original_authority_count=signature_fit_original_authority_count+1
 WHERE id=doc.id AND org_id=doc.org_id AND signature_fit_original_authority_count<128
  AND signature_fit_original_authority_bytes+NEW.authority_bytes<=134217728;
 IF NOT FOUND THEN RAISE EXCEPTION 'fit original authority staging quota exhausted' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'fit original authority scoped parent missing' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER signature_fit_original_authority_guard BEFORE INSERT OR UPDATE OR DELETE ON signature_fit_original_authorities
 FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_original_authority_guard();

CREATE FUNCTION hash_signature_fit_original_payload_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE doc documents%ROWTYPE; prep signature_fit_preparations%ROWTYPE; recipient_id UUID; authority_sha BYTEA;
 occupied INTEGER[]; canonical_key TEXT; member_count BIGINT; member_bytes BIGINT; manifest JSONB; authority_json JSONB;
 manifest_member JSONB; object_row signature_fit_objects%ROWTYPE; manifest_pages INTEGER[]:=ARRAY[]::integer[];
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'fit original payload is immutable and retained' USING ERRCODE='23514'; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'fit original capture requires read committed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT doc FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 SELECT a.recipient_id,a.authority_sha256,a.occupied_pages INTO STRICT recipient_id,authority_sha,occupied
  FROM signature_fit_original_authorities a WHERE a.preparation_id=NEW.preparation_id AND a.org_id=NEW.org_id AND a.document_id=doc.id;
 PERFORM 1 FROM recipients r WHERE r.id=recipient_id AND r.document_id=doc.id AND r.status IN('pending','sent','viewed') AND r.role NOT IN('cc','viewer') FOR UPDATE OF r;
 IF NOT FOUND THEN RAISE EXCEPTION 'fit original recipient is no longer eligible' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT prep FROM signature_fit_preparations WHERE id=NEW.preparation_id AND org_id=NEW.org_id AND document_id=doc.id FOR UPDATE;
 IF doc.deleted_at IS NOT NULL OR doc.status NOT IN('sent','in_progress') OR doc.source_kind<>'pdf'
  OR NOT doc.requires_signature OR NOT doc.evidence_version_pins_required OR doc.is_envelope OR doc.parent_envelope_id IS NOT NULL
  OR NOT doc.article13_notice_epoch_v61_committed
  OR ROW(doc.sent_at,doc.article13_notice_epoch_at,doc.pdf_storage_key,doc.pdf_storage_version_id,doc.pdf_sha256)
     IS DISTINCT FROM ROW(prep.ceremony_epoch,prep.ceremony_epoch,prep.source_storage_key,prep.source_version_id,prep.source_sha256)
  OR prep.status<>'staging' OR prep.owner_id<>NEW.captured_owner_id OR prep.lease_until<=clock_timestamp()
  OR prep.selection_commit_attempted_at IS NOT NULL OR prep.recipient_id IS DISTINCT FROM recipient_id
  OR prep.authority_sha256 IS DISTINCT FROM authority_sha
  OR EXISTS(SELECT 1 FROM signature_fit_selections s WHERE s.preparation_id=prep.id)
  OR EXISTS(SELECT 1 FROM signature_fit_objects o WHERE o.preparation_id=prep.id AND o.kind=NEW.kind AND o.page=NEW.page) THEN
  RAISE EXCEPTION 'fit original payload requires current uncaptured object reservation' USING ERRCODE='23514'; END IF;
 canonical_key:='org/'||prep.org_id::text||'/documents/'||prep.document_id::text||'/signatures/fit/'||prep.id::text||'/'||
  CASE NEW.kind WHEN 'span' THEN 'span.html' WHEN 'manifest' THEN 'manifest.json' ELSE 'page-'||NEW.page::text||'.fit' END;
 IF NEW.storage_key IS DISTINCT FROM canonical_key OR (NEW.kind='page' AND NOT NEW.page=ANY(occupied))
  OR (NEW.kind='span' AND NEW.sha256 IS DISTINCT FROM prep.span_sha256) THEN
  RAISE EXCEPTION 'fit original object differs from authority member identity' USING ERRCODE='23514'; END IF;
 SELECT count(*),COALESCE(sum(a.bytes),0) INTO member_count,member_bytes FROM signature_fit_original_payloads a WHERE a.preparation_id=prep.id;
 IF member_count>=prep.expected_objects OR member_bytes+NEW.bytes>prep.reserved_bytes THEN
  RAISE EXCEPTION 'fit original payload exceeds operation ceiling' USING ERRCODE='23514'; END IF;
 IF NEW.kind='manifest' THEN
  manifest:=convert_from(NEW.payload,'UTF8')::jsonb;
  SELECT convert_from(a.authority_payload,'UTF8')::jsonb INTO STRICT authority_json FROM signature_fit_original_authorities a WHERE a.preparation_id=prep.id;
  IF manifest->>'schema' IS DISTINCT FROM 'hash-manual-signature-fit-manifest-v1'
   OR manifest->>'operation_id' IS DISTINCT FROM prep.id::text OR manifest->>'org_id' IS DISTINCT FROM prep.org_id::text
   OR manifest->>'document_id' IS DISTINCT FROM prep.document_id::text OR manifest->>'recipient_id' IS DISTINCT FROM prep.recipient_id::text
   OR manifest->>'ceremony_epoch' IS DISTINCT FROM hash_article13_canonical_sent_at(prep.ceremony_epoch)
   OR manifest->>'authority_sha256' IS DISTINCT FROM encode(prep.authority_sha256,'hex')
   OR manifest->>'recipe_sha256' IS DISTINCT FROM 'ed5a53b65dfe42099002721a6453fe2a2b9aef26fd97a8ae0dcc7fd6cad2c6da'
   OR manifest->'authority' IS DISTINCT FROM authority_json OR jsonb_typeof(manifest->'pages') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'fit original manifest authority differs' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT object_row FROM signature_fit_objects o WHERE o.preparation_id=prep.id AND o.kind='span' AND o.page=0;
  IF object_row.version_id IS NULL OR object_row.readback_verified_at IS NULL OR object_row.cleanup_completed_at IS NOT NULL
   OR manifest->'span' IS DISTINCT FROM jsonb_build_object('key',object_row.storage_key,'version_id',object_row.version_id,
    'sha256',encode(object_row.sha256,'hex'),'bytes',object_row.bytes,'content_type',object_row.content_type) THEN
   RAISE EXCEPTION 'fit original manifest span differs from exact readback' USING ERRCODE='23514'; END IF;
  IF jsonb_array_length(manifest->'pages')<>cardinality(occupied) THEN
   RAISE EXCEPTION 'fit original manifest page set differs' USING ERRCODE='23514'; END IF;
  FOR manifest_member IN SELECT item.value FROM jsonb_array_elements(manifest->'pages') item(value) LOOP
   IF (manifest_member->>'page')::integer IS DISTINCT FROM occupied[cardinality(manifest_pages)+1] THEN
    RAISE EXCEPTION 'fit original manifest page order differs' USING ERRCODE='23514'; END IF;
   SELECT * INTO STRICT object_row FROM signature_fit_objects o WHERE o.preparation_id=prep.id AND o.kind='page' AND o.page=(manifest_member->>'page')::integer;
   IF object_row.version_id IS NULL OR object_row.readback_verified_at IS NULL OR object_row.cleanup_completed_at IS NOT NULL
    OR manifest_member->'package' IS DISTINCT FROM jsonb_build_object('key',object_row.storage_key,'version_id',object_row.version_id,
     'sha256',encode(object_row.sha256,'hex'),'bytes',object_row.bytes,'content_type',object_row.content_type) THEN
    RAISE EXCEPTION 'fit original manifest package differs from exact readback' USING ERRCODE='23514'; END IF;
   manifest_pages:=array_append(manifest_pages,object_row.page);
  END LOOP;
 END IF;
 UPDATE documents SET signature_fit_original_payload_bytes=signature_fit_original_payload_bytes+NEW.bytes
 WHERE id=doc.id AND org_id=doc.org_id AND signature_fit_original_payload_bytes+NEW.bytes<=167772160;
 IF NOT FOUND THEN RAISE EXCEPTION 'fit original payload staging quota exhausted' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'fit original payload scoped lineage missing' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER signature_fit_original_payload_guard BEFORE INSERT OR UPDATE OR DELETE ON signature_fit_original_payloads
 FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_original_payload_guard();

CREATE FUNCTION hash_signature_fit_original_budget_check() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE document_id_to_check UUID; actual_authority BIGINT; actual_count INTEGER; actual_payload BIGINT;
 expected_authority BIGINT; expected_count BIGINT; expected_payload BIGINT;
BEGIN
 IF TG_TABLE_NAME='documents' THEN document_id_to_check:=NEW.id; ELSE document_id_to_check:=NEW.document_id; END IF;
 SELECT d.signature_fit_original_authority_bytes,d.signature_fit_original_authority_count,d.signature_fit_original_payload_bytes
  INTO STRICT actual_authority,actual_count,actual_payload FROM documents d WHERE d.id=document_id_to_check;
 SELECT COALESCE(sum(a.authority_bytes),0),count(*) INTO expected_authority,expected_count
  FROM signature_fit_original_authorities a WHERE a.document_id=document_id_to_check;
 SELECT COALESCE(sum(a.bytes),0) INTO expected_payload FROM signature_fit_original_payloads a WHERE a.document_id=document_id_to_check;
 IF ROW(actual_authority,actual_count::bigint,actual_payload) IS DISTINCT FROM ROW(expected_authority,expected_count,expected_payload) THEN
  RAISE EXCEPTION 'fit original retained inventory differs from document counters' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER signature_fit_original_budget_document AFTER INSERT OR UPDATE ON documents
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_original_budget_check();
CREATE CONSTRAINT TRIGGER signature_fit_original_budget_authority AFTER INSERT ON signature_fit_original_authorities
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_original_budget_check();
CREATE CONSTRAINT TRIGGER signature_fit_original_budget_payload AFTER INSERT ON signature_fit_original_payloads
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_original_budget_check();

CREATE FUNCTION hash_signature_fit_original_object_pair_check() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE original_key TEXT; original_sha BYTEA; original_bytes BIGINT; original_type TEXT; has_authority BOOLEAN;
BEGIN
 SELECT EXISTS(SELECT 1 FROM signature_fit_original_authorities a WHERE a.preparation_id=NEW.preparation_id) INTO has_authority;
 IF NOT has_authority THEN RETURN NEW; END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'fit original reservation requires read committed' USING ERRCODE='23514'; END IF;
 SELECT a.storage_key,a.sha256,a.bytes,a.content_type INTO STRICT original_key,original_sha,original_bytes,original_type
  FROM signature_fit_original_payloads a WHERE a.preparation_id=NEW.preparation_id AND a.kind=NEW.kind AND a.page=NEW.page;
 IF ROW(NEW.storage_key,NEW.sha256,NEW.bytes,NEW.content_type)
  IS DISTINCT FROM ROW(original_key,original_sha,original_bytes,original_type) THEN
  RAISE EXCEPTION 'fit reservation differs from earlier captured original' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'fit reservation requires earlier captured original body' USING ERRCODE='23514';
END;
$$;
-- Immediate guard enforces statement order; deferred guard also checks the
-- committed exact pair. Capturing a header after any85 object is forbidden.
CREATE TRIGGER signature_fit_original_object_before_reservation BEFORE INSERT ON signature_fit_objects
 FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_original_object_pair_check();
CREATE CONSTRAINT TRIGGER signature_fit_original_object_pair AFTER INSERT ON signature_fit_objects
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_original_object_pair_check();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'fit original rollback requires read committed' USING ERRCODE='23514';
 END IF;
END;
$$;
LOCK TABLE documents,signature_fit_objects,signature_fit_original_authorities,signature_fit_original_payloads IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM signature_fit_original_authorities) OR EXISTS(SELECT 1 FROM signature_fit_original_payloads)
  OR EXISTS(SELECT 1 FROM documents WHERE signature_fit_original_authority_bytes<>0
   OR signature_fit_original_authority_count<>0 OR signature_fit_original_payload_bytes<>0) THEN
  RAISE EXCEPTION 'cannot discard captured original fit inventory' USING ERRCODE='23514';
 END IF;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER signature_fit_original_object_pair ON signature_fit_objects;
DROP TRIGGER signature_fit_original_object_before_reservation ON signature_fit_objects;
DROP TRIGGER signature_fit_original_budget_payload ON signature_fit_original_payloads;
DROP TRIGGER signature_fit_original_budget_authority ON signature_fit_original_authorities;
DROP TRIGGER signature_fit_original_budget_document ON documents;
DROP TRIGGER signature_fit_original_payload_guard ON signature_fit_original_payloads;
DROP TRIGGER signature_fit_original_authority_guard ON signature_fit_original_authorities;
DROP FUNCTION hash_signature_fit_original_object_pair_check();
DROP FUNCTION hash_signature_fit_original_budget_check();
DROP FUNCTION hash_signature_fit_original_payload_guard();
DROP FUNCTION hash_signature_fit_original_authority_guard();
DROP FUNCTION hash_signature_fit_original_authority_matches_v1(signature_fit_original_authorities,signature_fit_preparations);
DROP TABLE signature_fit_original_payloads,signature_fit_original_authorities;
ALTER TABLE documents DROP COLUMN signature_fit_original_payload_bytes,
 DROP COLUMN signature_fit_original_authority_bytes,DROP COLUMN signature_fit_original_authority_count;
