-- +goose Up
-- Append-only draft captures. They are not Send freezes or signing evidence.
CREATE UNIQUE INDEX document_package_identity_v1 ON document_packages_v1(id,org_id,document_id);

-- +goose StatementBegin
CREATE FUNCTION hash_package_json_keys_v1(value JSONB,keys TEXT[]) RETURNS BOOLEAN AS $$
 SELECT CASE WHEN jsonb_typeof(value)='object' THEN COALESCE(value ?& keys
   AND (SELECT count(*) FROM jsonb_object_keys(value))=cardinality(keys),false) ELSE false END;
$$ LANGUAGE sql IMMUTABLE;
CREATE FUNCTION hash_package_manifest_projection_v1(raw BYTEA) RETURNS JSONB AS $$
DECLARE j JSONB; m JSONB; p JSONB; s JSONB; mat JSONB;
BEGIN
 IF raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 65536 THEN
  RAISE EXCEPTION 'package manifest byte bound' USING ERRCODE='23514'; END IF;
 -- This is a semantic inventory projection, never a canonical reserialization.
 -- The application must still use DecodeManifestV1 on the original bytes.
 j:=convert_from(raw,'UTF8')::jsonb;
 IF NOT hash_package_json_keys_v1(j,ARRAY['schema','binding','main','annexes'])
  OR j->>'schema' IS DISTINCT FROM 'hash-legal-package-manifest-v1'
  OR NOT hash_package_json_keys_v1(j->'binding',ARRAY['org_id','document_id','package_id','revision'])
  OR jsonb_typeof(j->'annexes') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'package manifest shape' USING ERRCODE='23514'; END IF;
 IF jsonb_array_length(j->'annexes')>16 THEN RAISE EXCEPTION 'package annex bound' USING ERRCODE='23514'; END IF;
 FOREACH s IN ARRAY ARRAY[j->'binding'] LOOP
  IF jsonb_typeof(s->'org_id') IS DISTINCT FROM 'string' OR jsonb_typeof(s->'document_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(s->'package_id') IS DISTINCT FROM 'string' OR jsonb_typeof(s->'revision') IS DISTINCT FROM 'string'
   OR (s->>'revision') !~ '^[1-9][0-9]{0,18}$' THEN
   RAISE EXCEPTION 'package binding shape' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOR m IN SELECT value FROM jsonb_array_elements(jsonb_build_array(j->'main')||(j->'annexes')) LOOP
  IF NOT hash_package_json_keys_v1(m,ARRAY['document_id','title','category','pdf','source'])
   OR jsonb_typeof(m->'document_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(m->'title') IS DISTINCT FROM 'string' OR jsonb_typeof(m->'category') IS DISTINCT FROM 'string'
   OR NOT hash_package_label_v1(m->>'title',512,false) OR NOT hash_package_label_v1(m->>'category',128,true) THEN
   RAISE EXCEPTION 'package member shape' USING ERRCODE='23514'; END IF;
  p:=m->'pdf'; s:=m->'source';
  IF NOT hash_package_json_keys_v1(p,ARRAY['key','version_id','sha256','bytes','pages'])
   OR jsonb_typeof(p->'key') IS DISTINCT FROM 'string' OR jsonb_typeof(p->'version_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(p->'sha256') IS DISTINCT FROM 'string' OR (p->>'sha256') !~ '^[0-9a-f]{64}$'
   OR jsonb_typeof(p->'bytes') IS DISTINCT FROM 'number' OR (p->>'bytes') !~ '^[1-9][0-9]{0,7}$'
   OR jsonb_typeof(p->'pages') IS DISTINCT FROM 'number' OR (p->>'pages') !~ '^[1-9][0-9]{0,2}$'
   OR NOT hash_package_json_keys_v1(s,ARRAY['kind','commitment_sha256','origin_commitment_sha256','materialization'])
   OR jsonb_typeof(s->'kind') IS DISTINCT FROM 'string'
   OR jsonb_typeof(s->'commitment_sha256') IS DISTINCT FROM 'string'
   OR jsonb_typeof(s->'origin_commitment_sha256') IS DISTINCT FROM 'string' THEN
   RAISE EXCEPTION 'package PDF/source shape' USING ERRCODE='23514'; END IF;
  IF (s->>'kind'='pdf-import' AND (s->>'commitment_sha256'<>'' OR s->>'origin_commitment_sha256'<>'' OR s->'materialization'<>'null'::jsonb))
   OR (s->>'kind'<>'pdf-import' AND ((s->>'commitment_sha256') !~ '^[0-9a-f]{64}$' OR (s->>'origin_commitment_sha256') !~ '^[0-9a-f]{64}$')) THEN
   RAISE EXCEPTION 'package source commitments' USING ERRCODE='23514'; END IF;
  mat:=s->'materialization';
  IF mat<>'null'::jsonb AND (NOT hash_package_json_keys_v1(mat,ARRAY['id','sequence'])
   OR jsonb_typeof(mat->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(mat->'sequence') IS DISTINCT FROM 'number'
   OR (mat->>'sequence') !~ '^[1-9][0-9]{0,9}$') THEN
   RAISE EXCEPTION 'package materialization shape' USING ERRCODE='23514'; END IF;
 END LOOP;
 RETURN j;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
CREATE FUNCTION hash_package_manifest_members_v1(raw BYTEA)
RETURNS TABLE(member_position SMALLINT,member_document_id UUID,title TEXT,category TEXT,pdf_key TEXT,pdf_version_id TEXT,
 pdf_sha256 BYTEA,pdf_bytes BIGINT,pdf_pages INTEGER,source_kind TEXT,source_commitment BYTEA,origin_commitment BYTEA,
 materialization_id UUID,materialization_sequence INTEGER) AS $$
 SELECT (e.n-1)::smallint,(e.m->>'document_id')::uuid,e.m->>'title',e.m->>'category',
  e.m->'pdf'->>'key',e.m->'pdf'->>'version_id',decode(e.m->'pdf'->>'sha256','hex'),
  (e.m->'pdf'->>'bytes')::bigint,(e.m->'pdf'->>'pages')::integer,e.m->'source'->>'kind',
  CASE WHEN e.m->'source'->>'commitment_sha256'<>'' THEN decode(e.m->'source'->>'commitment_sha256','hex') END,
  CASE WHEN e.m->'source'->>'origin_commitment_sha256'<>'' THEN decode(e.m->'source'->>'origin_commitment_sha256','hex') END,
  (e.m->'source'->'materialization'->>'id')::uuid,(e.m->'source'->'materialization'->>'sequence')::integer
 FROM (SELECT hash_package_manifest_projection_v1(raw) AS j) v
 CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(v.j->'main')||(v.j->'annexes')) WITH ORDINALITY e(m,n);
$$ LANGUAGE sql IMMUTABLE;
-- +goose StatementEnd

CREATE TABLE document_package_captures_v1 (
 package_id UUID NOT NULL,org_id UUID NOT NULL,document_id UUID NOT NULL,
 revision BIGINT NOT NULL CHECK (revision>0),
 previous_revision BIGINT NOT NULL CHECK(previous_revision>=0 AND revision>previous_revision),
 captured_root_updated_at TIMESTAMPTZ NOT NULL CHECK (isfinite(captured_root_updated_at)),
 captured_draft_generation BIGINT NOT NULL CHECK (captured_draft_generation>0),
 manifest BYTEA NOT NULL CHECK (octet_length(manifest) BETWEEN 1 AND 65536),
 manifest_sha256 BYTEA NOT NULL CHECK (octet_length(manifest_sha256)=32 AND manifest_sha256=sha256(manifest)),
 legal_commitment_sha256 BYTEA NOT NULL CHECK (octet_length(legal_commitment_sha256)=32
  AND legal_commitment_sha256=sha256(convert_to('hash:legal-package-manifest:v1','UTF8')||decode('00','hex')||manifest)),
 member_count SMALLINT NOT NULL CHECK (member_count BETWEEN 1 AND 17),
 pdf_bytes BIGINT NOT NULL CHECK (pdf_bytes BETWEEN 1 AND 52428800),
 pdf_pages INTEGER NOT NULL CHECK (pdf_pages BETWEEN 1 AND 500),
 created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(created_at)),
 PRIMARY KEY(package_id,revision),UNIQUE(package_id,previous_revision),UNIQUE(package_id,revision,org_id),
 FOREIGN KEY(package_id,org_id,document_id) REFERENCES document_packages_v1(id,org_id,document_id) ON DELETE RESTRICT
);
CREATE TABLE document_package_capture_members_v1 (
 package_id UUID NOT NULL,revision BIGINT NOT NULL,org_id UUID NOT NULL,
 member_position SMALLINT NOT NULL CHECK(member_position BETWEEN 0 AND 16),
 member_document_id UUID NOT NULL CHECK(member_document_id<>'00000000-0000-0000-0000-000000000000'),
 title TEXT NOT NULL CHECK(hash_package_label_v1(title,512,false)),
 category TEXT NOT NULL CHECK(hash_package_label_v1(category,128,true)),
 pdf_key TEXT NOT NULL CHECK(hash_package_key_v1(pdf_key,org_id)),
 pdf_version_id TEXT NOT NULL CHECK(hash_package_opaque_v1(pdf_version_id) AND hash_package_trim_v1(pdf_version_id) NOT IN ('null','hash:unversioned-development')),
 pdf_sha256 BYTEA NOT NULL CHECK(octet_length(pdf_sha256)=32 AND pdf_sha256<>decode(repeat('00',32),'hex')),
 pdf_bytes BIGINT NOT NULL CHECK(pdf_bytes BETWEEN 1 AND 52428800),
 pdf_pages INTEGER NOT NULL CHECK(pdf_pages BETWEEN 1 AND 500),
 source_kind TEXT NOT NULL CHECK(source_kind IN ('pdf-import','html-origin','html-materialization')),
 source_commitment BYTEA,origin_commitment BYTEA,materialization_id UUID,materialization_sequence INTEGER,
 PRIMARY KEY(package_id,revision,member_position),UNIQUE(package_id,revision,member_document_id),UNIQUE(package_id,revision,pdf_key,pdf_version_id),
 FOREIGN KEY(package_id,revision,org_id) REFERENCES document_package_captures_v1(package_id,revision,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(materialization_id,member_document_id,org_id,source_commitment)
  REFERENCES html_document_materializations(id,document_id,org_id,source_commitment) ON DELETE RESTRICT,
 CHECK(source_commitment IS NULL OR source_commitment<>decode(repeat('00',32),'hex')),
 CHECK(origin_commitment IS NULL OR origin_commitment<>decode(repeat('00',32),'hex')),
 CHECK(materialization_id IS NULL OR materialization_id<>'00000000-0000-0000-0000-000000000000'),
 CHECK((source_kind='pdf-import' AND source_commitment IS NULL AND origin_commitment IS NULL AND materialization_id IS NULL AND materialization_sequence IS NULL)
  OR (source_kind='html-origin' AND source_commitment IS NOT NULL AND octet_length(source_commitment)=32 AND origin_commitment IS NOT NULL
   AND source_commitment=origin_commitment AND materialization_id IS NULL AND materialization_sequence IS NULL)
  OR (source_kind='html-materialization' AND source_commitment IS NOT NULL AND octet_length(source_commitment)=32
   AND origin_commitment IS NOT NULL AND octet_length(origin_commitment)=32 AND materialization_id IS NOT NULL AND materialization_sequence>0
   AND materialization_sequence IS NOT NULL AND (materialization_sequence<>1 OR source_commitment=origin_commitment)))
);
CREATE INDEX document_package_capture_subject_v1 ON document_package_capture_members_v1(org_id,member_document_id);
CREATE INDEX document_package_capture_object_v1 ON document_package_capture_members_v1(pdf_key);

-- +goose StatementBegin
CREATE FUNCTION hash_guard_document_package_capture_v1() RETURNS trigger AS $$
DECLARE root documents%ROWTYPE; p document_packages_v1%ROWTYPE; j JSONB; b JSONB; main RECORD; previous BIGINT; draft_count BIGINT;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'package captures are append only' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT root FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE NOWAIT;
 SELECT * INTO STRICT p FROM document_packages_v1 WHERE id=NEW.package_id AND org_id=NEW.org_id AND document_id=root.id FOR UPDATE NOWAIT;
 IF root.status<>'draft' OR root.deleted_at IS NOT NULL OR root.source_kind<>'pdf' OR root.is_envelope OR root.parent_envelope_id IS NOT NULL
  OR root.updated_at IS DISTINCT FROM NEW.captured_root_updated_at OR p.draft_generation<>NEW.captured_draft_generation
  OR hash_package_has_signing_evidence_v1(root.id,root.org_id)
  OR NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.created_by AND org_id=NEW.org_id) THEN
  RAISE EXCEPTION 'package capture root, generation or actor differs' USING ERRCODE='23514'; END IF;
 SELECT coalesce(max(revision),0) INTO previous FROM document_package_captures_v1 WHERE package_id=p.id;
 IF NEW.previous_revision<>previous OR NEW.revision<=previous THEN RAISE EXCEPTION 'package revision head differs' USING ERRCODE='23514'; END IF;
 j:=hash_package_manifest_projection_v1(NEW.manifest); b:=j->'binding';
 IF b->>'org_id' IS DISTINCT FROM NEW.org_id::text OR b->>'document_id' IS DISTINCT FROM NEW.document_id::text
  OR b->>'package_id' IS DISTINCT FROM NEW.package_id::text OR b->>'revision' IS DISTINCT FROM NEW.revision::text THEN
  RAISE EXCEPTION 'package manifest binding differs' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT main FROM hash_package_manifest_members_v1(NEW.manifest) WHERE member_position=0;
 IF main.member_document_id<>root.id OR main.title IS DISTINCT FROM root.name
  OR main.pdf_key IS DISTINCT FROM root.pdf_storage_key OR main.pdf_version_id IS DISTINCT FROM root.pdf_storage_version_id
  OR main.pdf_sha256 IS DISTINCT FROM root.pdf_sha256 THEN
  RAISE EXCEPTION 'package main PDF differs' USING ERRCODE='23514'; END IF;
 IF root.html_source_json IS NULL THEN
  IF main.source_kind<>'pdf-import' THEN RAISE EXCEPTION 'package main source differs' USING ERRCODE='23514'; END IF;
 ELSE
  IF main.source_commitment IS DISTINCT FROM decode(COALESCE(root.html_current_source_json,root.html_source_json)->>'commitment','hex')
   OR main.origin_commitment IS DISTINCT FROM decode(root.html_source_json->>'commitment','hex')
   OR root.html_reviewed_pdf_sha256 IS DISTINCT FROM main.pdf_sha256 OR root.html_reviewed_by IS NULL OR root.html_reviewed_at IS NULL
   OR root.html_reviewed_materialization_id IS DISTINCT FROM root.html_current_materialization_id
   OR main.materialization_id IS DISTINCT FROM root.html_current_materialization_id
   OR main.materialization_sequence IS DISTINCT FROM root.html_current_materialization_sequence
   OR (root.html_current_page_count IS NOT NULL AND main.pdf_pages<>root.html_current_page_count)
   OR main.source_kind IS DISTINCT FROM (CASE WHEN root.html_current_materialization_id IS NULL THEN 'html-origin' ELSE 'html-materialization' END) THEN
   RAISE EXCEPTION 'package main reviewed HTML differs' USING ERRCODE='23514'; END IF;
 END IF;
 SELECT count(*) INTO draft_count FROM document_attachment_drafts_v1 WHERE package_id=p.id;
 IF draft_count>16 OR draft_count<>jsonb_array_length(j->'annexes')
  OR EXISTS(SELECT ordinal FROM document_attachment_drafts_v1 WHERE package_id=p.id GROUP BY ordinal HAVING count(*)<>1) THEN
  RAISE EXCEPTION 'package attachment cardinality or order differs' USING ERRCODE='23514'; END IF;
 IF EXISTS(
  SELECT 1 FROM (SELECT row_number() OVER(ORDER BY ordinal)::smallint AS member_position,a.* FROM document_attachment_drafts_v1 a WHERE package_id=p.id) a
  FULL JOIN (SELECT * FROM hash_package_manifest_members_v1(NEW.manifest) WHERE member_position>0) m USING(member_position)
  WHERE ROW(a.member_document_id,a.title,a.category,a.pdf_key,a.pdf_version_id,a.pdf_sha256,a.pdf_bytes,a.pdf_pages,
    a.source_kind,a.source_commitment,a.origin_commitment,a.materialization_id,a.materialization_sequence)
   IS DISTINCT FROM ROW(m.member_document_id,m.title,m.category,m.pdf_key,m.pdf_version_id,m.pdf_sha256,m.pdf_bytes,m.pdf_pages,
    m.source_kind,m.source_commitment,m.origin_commitment,m.materialization_id,m.materialization_sequence)
 ) THEN RAISE EXCEPTION 'package selected annex tuple differs' USING ERRCODE='23514'; END IF;
 SELECT count(*)::smallint,sum(pdf_bytes),sum(pdf_pages)::integer INTO NEW.member_count,NEW.pdf_bytes,NEW.pdf_pages
  FROM hash_package_manifest_members_v1(NEW.manifest);
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_package_capture_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_package_captures_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_document_package_capture_v1();

CREATE FUNCTION hash_guard_document_package_capture_member_v1() RETURNS trigger AS $$
DECLARE raw BYTEA;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'package captured members are append only' USING ERRCODE='23514'; END IF;
 SELECT manifest INTO STRICT raw FROM document_package_captures_v1 WHERE package_id=NEW.package_id AND revision=NEW.revision AND org_id=NEW.org_id;
 IF NOT EXISTS(SELECT 1 FROM hash_package_manifest_members_v1(raw) m WHERE m.member_position=NEW.member_position
  AND ROW(m.member_document_id,m.title,m.category,m.pdf_key,m.pdf_version_id,m.pdf_sha256,m.pdf_bytes,m.pdf_pages,
   m.source_kind,m.source_commitment,m.origin_commitment,m.materialization_id,m.materialization_sequence)
  IS NOT DISTINCT FROM ROW(NEW.member_document_id,NEW.title,NEW.category,NEW.pdf_key,NEW.pdf_version_id,NEW.pdf_sha256,NEW.pdf_bytes,NEW.pdf_pages,
   NEW.source_kind,NEW.source_commitment,NEW.origin_commitment,NEW.materialization_id,NEW.materialization_sequence)) THEN
  RAISE EXCEPTION 'captured member differs from stored manifest' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_package_capture_member_guard_v1 BEFORE INSERT OR UPDATE OR DELETE ON document_package_capture_members_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_document_package_capture_member_v1();
CREATE FUNCTION hash_derive_document_package_capture_members_v1() RETURNS trigger AS $$
BEGIN
 INSERT INTO document_package_capture_members_v1 SELECT NEW.package_id,NEW.revision,NEW.org_id,m.* FROM hash_package_manifest_members_v1(NEW.manifest) m;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER document_package_capture_derive_members_v1 AFTER INSERT ON document_package_captures_v1
 FOR EACH ROW EXECUTE FUNCTION hash_derive_document_package_capture_members_v1();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE documents,document_packages_v1,document_attachment_drafts_v1,document_package_captures_v1,document_package_capture_members_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM document_package_captures_v1) OR EXISTS(SELECT 1 FROM document_package_capture_members_v1) THEN
  RAISE EXCEPTION 'package capture history prevents rollback' USING ERRCODE='23514'; END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER document_package_capture_derive_members_v1 ON document_package_captures_v1;
DROP FUNCTION hash_derive_document_package_capture_members_v1();
DROP TRIGGER document_package_capture_member_guard_v1 ON document_package_capture_members_v1;
DROP FUNCTION hash_guard_document_package_capture_member_v1();
DROP TRIGGER document_package_capture_guard_v1 ON document_package_captures_v1;
DROP FUNCTION hash_guard_document_package_capture_v1();
DROP TABLE document_package_capture_members_v1;
DROP TABLE document_package_captures_v1;
DROP FUNCTION hash_package_manifest_members_v1(BYTEA);
DROP FUNCTION hash_package_manifest_projection_v1(BYTEA);
DROP FUNCTION hash_package_json_keys_v1(JSONB,TEXT[]);
DROP INDEX document_package_identity_v1;
