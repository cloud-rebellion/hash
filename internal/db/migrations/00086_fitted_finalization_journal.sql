-- +goose Up
-- New fitted finalizations have one recoverable, tenant-scoped cross-store
-- journal. Provider bytes are durably stored BEFORE the original upload marker.
-- This migration does not enable a signing policy, worker, export callback or
-- destructive privacy/cleanup workflow. Historical migrations remain unchanged.
-- +goose StatementBegin
DO $$
BEGIN
 IF current_setting('transaction_isolation') <> 'read committed' THEN
  RAISE EXCEPTION 'fitted finalization installation requires read committed' USING ERRCODE='23514';
 END IF;
END;
$$;
-- +goose StatementEnd
LOCK TABLE documents, signatures, signature_fit_companions IN ACCESS EXCLUSIVE MODE;
-- No old completed/in-flight signature can be retroactively called schema4.
-- Migration85 has not activated fitted Sign. A used inventory requires explicit
-- reconciliation rather than backfilling invented index/name/payload authority.
-- +goose StatementBegin
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM signatures WHERE signature_kind='manual_pdf_fit_v1') THEN
  RAISE EXCEPTION 'fitted finalization cutover requires no unjournaled fitted signatures' USING ERRCODE='23514';
 END IF;
END;
$$;
-- +goose StatementEnd

ALTER TABLE documents
 ADD COLUMN fits_index_required BOOLEAN NOT NULL DEFAULT FALSE,
 ADD COLUMN fits_index_preparation_id UUID,
 ADD COLUMN fits_index_storage_key TEXT,
 ADD COLUMN fits_index_version_id TEXT,
 ADD COLUMN fits_index_sha256 BYTEA,
 ADD COLUMN fits_index_bytes BIGINT,
 ADD CONSTRAINT documents_fits_index_pin_pair CHECK (
  (fits_index_preparation_id IS NULL AND fits_index_storage_key IS NULL AND fits_index_version_id IS NULL
   AND fits_index_sha256 IS NULL AND fits_index_bytes IS NULL AND NOT(status='completed' AND fits_index_required))
  OR
  (fits_index_required AND status='completed' AND fits_index_preparation_id IS NOT NULL
   AND fits_index_storage_key IS NOT NULL AND fits_index_version_id IS NOT NULL
   AND fits_index_sha256 IS NOT NULL AND octet_length(fits_index_sha256)=32
   AND fits_index_bytes IS NOT NULL AND fits_index_bytes BETWEEN 1 AND 8388608
   AND hash_signature_fit_version_valid(fits_index_version_id)
   AND fits_index_storage_key='org/'||org_id::text||'/documents/'||id::text||'/finalization/index/'||
       fits_index_preparation_id::text||'/signature-fit-index.json')
 );

CREATE TABLE document_finalization_preparations (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 org_id UUID NOT NULL, document_id UUID NOT NULL,
 ceremony_epoch TIMESTAMPTZ NOT NULL CHECK(isfinite(ceremony_epoch)),
 completion_effective_at TIMESTAMPTZ NOT NULL CHECK(isfinite(completion_effective_at) AND completion_effective_at>ceremony_epoch),
 retain_until TIMESTAMPTZ NOT NULL CHECK(isfinite(retain_until) AND retain_until=date_trunc('second',retain_until)
                                      AND retain_until=hash_evidence_retain_until(completion_effective_at,7)),
 original_document_name TEXT NOT NULL CHECK(octet_length(original_document_name) BETWEEN 1 AND 65536 AND btrim(original_document_name)<>''),
 source_storage_key TEXT NOT NULL CHECK(octet_length(source_storage_key) BETWEEN 1 AND 1024 AND source_storage_key=btrim(source_storage_key) AND source_storage_key !~ '[[:cntrl:]]'),
 source_version_id TEXT NOT NULL CHECK(hash_signature_fit_version_valid(source_version_id)),
 source_sha256 BYTEA NOT NULL CHECK(octet_length(source_sha256)=32),
 source_bytes BIGINT NOT NULL CHECK(source_bytes BETWEEN 1 AND 52428800),
 source_pages INTEGER NOT NULL CHECK(source_pages BETWEEN 1 AND 500),
 geometry_pages_payload BYTEA NOT NULL CHECK(octet_length(geometry_pages_payload) BETWEEN 1 AND 1048576),
 geometry_sha256 BYTEA NOT NULL CHECK(octet_length(geometry_sha256)=32 AND digest(geometry_pages_payload,'sha256')=geometry_sha256),
 field_snapshot_payload BYTEA NOT NULL CHECK(octet_length(field_snapshot_payload) BETWEEN 1 AND 1048576),
 field_snapshot_sha256 BYTEA NOT NULL CHECK(octet_length(field_snapshot_sha256)=32 AND digest(field_snapshot_payload,'sha256')=field_snapshot_sha256),
 required_base_pages INTEGER[] NOT NULL,
 expected_outputs INTEGER NOT NULL CHECK(expected_outputs BETWEEN 5 AND 505),
 expected_references INTEGER NOT NULL CHECK(expected_references BETWEEN 4 AND 9990),
 fit_reserved_bytes BIGINT NOT NULL CHECK(fit_reserved_bytes BETWEEN 0 AND 167772160),
 base_bytes_limit BIGINT NOT NULL CHECK(base_bytes_limit BETWEEN 0 AND 52428800),
 final_pdf_bytes_limit BIGINT NOT NULL CHECK(final_pdf_bytes_limit BETWEEN 1 AND 52428800),
 fits_index_bytes_limit BIGINT NOT NULL CHECK(fits_index_bytes_limit BETWEEN 1 AND 8388608),
 certificate_pdf_bytes_limit BIGINT NOT NULL CHECK(certificate_pdf_bytes_limit BETWEEN 1 AND 8388608),
 certificate_payload_bytes_limit BIGINT NOT NULL CHECK(certificate_payload_bytes_limit BETWEEN 1 AND 4194304),
 certificate_signature_bytes_limit BIGINT NOT NULL CHECK(certificate_signature_bytes_limit BETWEEN 1 AND 256),
 archive_budget_bytes BIGINT NOT NULL CHECK(archive_budget_bytes BETWEEN 1 AND 167772160),
 -- Capture the actual event/chain/issuer/branding context before output work;
 -- a later retry must not sample another document's newer org chain head.
 audit_snapshot_payload BYTEA,
 audit_snapshot_sha256 BYTEA,
 certificate_input_payload BYTEA,
 certificate_input_sha256 BYTEA,
 owner_id UUID NOT NULL CHECK(owner_id<>'00000000-0000-0000-0000-000000000000'),
 lease_until TIMESTAMPTZ NOT NULL CHECK(isfinite(lease_until)),
 attempts INTEGER NOT NULL DEFAULT 1 CHECK(attempts BETWEEN 1 AND 8),
 status TEXT NOT NULL DEFAULT 'staging' CHECK(status IN('staging','prepared','published')),
 retention_started_at TIMESTAMPTZ CHECK(retention_started_at IS NULL OR isfinite(retention_started_at)),
 retention_completed_at TIMESTAMPTZ CHECK(retention_completed_at IS NULL OR
  (isfinite(retention_completed_at) AND retention_started_at IS NOT NULL AND retention_completed_at>=retention_started_at)),
 publication_commit_attempted_at TIMESTAMPTZ CHECK(publication_commit_attempted_at IS NULL OR isfinite(publication_commit_attempted_at)),
 published_at TIMESTAMPTZ CHECK(published_at IS NULL OR
  (isfinite(published_at) AND publication_commit_attempted_at IS NOT NULL AND published_at>=publication_commit_attempted_at)),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(updated_at)),
 CHECK((status='published')=(published_at IS NOT NULL)),
 UNIQUE(org_id,document_id,ceremony_epoch,completion_effective_at),
 UNIQUE(id,org_id,document_id),
 FOREIGN KEY(document_id,org_id,retain_until) REFERENCES documents(id,org_id,finalization_retain_until) ON DELETE RESTRICT,
 CHECK(expected_outputs=cardinality(required_base_pages)+5),
 CHECK((cardinality(required_base_pages)=0 AND base_bytes_limit=0) OR (cardinality(required_base_pages)>0 AND base_bytes_limit>=cardinality(required_base_pages))),
 CHECK((audit_snapshot_payload IS NULL AND audit_snapshot_sha256 IS NULL) OR
  (audit_snapshot_payload IS NOT NULL AND audit_snapshot_sha256 IS NOT NULL AND octet_length(audit_snapshot_payload) BETWEEN 1 AND 4194304
   AND octet_length(audit_snapshot_sha256)=32 AND digest(audit_snapshot_payload,'sha256')=audit_snapshot_sha256)),
 CHECK((certificate_input_payload IS NULL AND certificate_input_sha256 IS NULL) OR
  (certificate_input_payload IS NOT NULL AND certificate_input_sha256 IS NOT NULL AND octet_length(certificate_input_payload) BETWEEN 1 AND 4194304
   AND octet_length(certificate_input_sha256)=32 AND digest(certificate_input_payload,'sha256')=certificate_input_sha256))
);
CREATE INDEX document_finalization_preparations_recovery ON document_finalization_preparations(status,lease_until,id);
CREATE INDEX document_finalization_preparations_privacy ON document_finalization_preparations(org_id,document_id,id);
ALTER TABLE documents ADD CONSTRAINT documents_fits_index_preparation_identity
 FOREIGN KEY(fits_index_preparation_id,org_id,id) REFERENCES document_finalization_preparations(id,org_id,document_id)
 DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE document_finalization_outputs (
 preparation_id UUID NOT NULL REFERENCES document_finalization_preparations(id) ON DELETE RESTRICT,
 kind TEXT NOT NULL CHECK(kind IN('base_pdf','final_pdf','fits_index','certificate_pdf','certificate_payload','certificate_signature')),
 page INTEGER NOT NULL CHECK((kind='base_pdf' AND page BETWEEN 1 AND 500) OR (kind<>'base_pdf' AND page=0)),
 storage_key TEXT NOT NULL UNIQUE CHECK(octet_length(storage_key) BETWEEN 1 AND 1024),
 sha256 BYTEA NOT NULL CHECK(octet_length(sha256)=32),
 bytes BIGINT NOT NULL CHECK(bytes>0),
 content_type TEXT NOT NULL,
 -- No discard mutation is provided until a real durable controller/hold
 -- disposition exists. Clearing pending bytes destroys exact crash recovery.
 payload BYTEA NOT NULL CHECK(octet_length(payload)=bytes),
 upload_attempted_at TIMESTAMPTZ CHECK(upload_attempted_at IS NULL OR isfinite(upload_attempted_at)),
 upload_owner_id UUID CHECK(upload_owner_id IS NULL OR upload_owner_id<>'00000000-0000-0000-0000-000000000000'),
 version_id TEXT CHECK(version_id IS NULL OR hash_signature_fit_version_valid(version_id)),
 readback_verified_at TIMESTAMPTZ CHECK(readback_verified_at IS NULL OR
  (isfinite(readback_verified_at) AND version_id IS NOT NULL AND upload_attempted_at IS NOT NULL AND readback_verified_at>=upload_attempted_at)),
 retention_started_at TIMESTAMPTZ CHECK(retention_started_at IS NULL OR isfinite(retention_started_at)),
 retention_completed_at TIMESTAMPTZ CHECK(retention_completed_at IS NULL OR
  (isfinite(retention_completed_at) AND retention_started_at IS NOT NULL AND readback_verified_at IS NOT NULL AND retention_completed_at>=retention_started_at)),
 PRIMARY KEY(preparation_id,kind,page),
 CHECK((upload_attempted_at IS NULL AND upload_owner_id IS NULL) OR (upload_attempted_at IS NOT NULL AND upload_owner_id IS NOT NULL)),
 CHECK(version_id IS NULL OR upload_attempted_at IS NOT NULL),
 CHECK(upload_attempted_at IS NULL OR retention_started_at IS NOT NULL),
 CHECK((kind IN('base_pdf','final_pdf') AND bytes<=52428800 AND content_type='application/pdf')
 OR (kind='fits_index' AND bytes<=8388608 AND content_type='application/json')
 OR (kind='certificate_pdf' AND bytes<=8388608 AND content_type='application/pdf')
 OR (kind='certificate_payload' AND bytes<=4194304 AND content_type='text/plain')
 OR (kind='certificate_signature' AND bytes<=256 AND content_type='text/plain'))
);

CREATE TABLE document_finalization_references (
 preparation_id UUID NOT NULL REFERENCES document_finalization_preparations(id) ON DELETE RESTRICT,
 kind TEXT NOT NULL CHECK(kind IN('source','fit_span','fit_page','fit_manifest','legacy_span')),
 signature_id UUID REFERENCES signatures(id) ON DELETE RESTRICT,
 selection_id UUID REFERENCES signature_fit_selections(id) ON DELETE RESTRICT,
 page INTEGER NOT NULL CHECK((kind='fit_page' AND page BETWEEN 1 AND 500) OR (kind<>'fit_page' AND page=0)),
 storage_key TEXT NOT NULL CHECK(octet_length(storage_key) BETWEEN 1 AND 1024),
 version_id TEXT NOT NULL CHECK(hash_signature_fit_version_valid(version_id)),
 sha256 BYTEA NOT NULL CHECK(octet_length(sha256)=32),
 bytes BIGINT NOT NULL CHECK(bytes>0),
 content_type TEXT NOT NULL,
 retention_started_at TIMESTAMPTZ CHECK(retention_started_at IS NULL OR isfinite(retention_started_at)),
 retention_completed_at TIMESTAMPTZ CHECK(retention_completed_at IS NULL OR
  (isfinite(retention_completed_at) AND retention_started_at IS NOT NULL AND retention_completed_at>=retention_started_at)),
 -- A fixed owner key makes the source row unique without NULL uniqueness gaps.
 owner_key UUID NOT NULL,
 PRIMARY KEY(preparation_id,kind,owner_key,page),
 CHECK((kind='source' AND signature_id IS NULL AND selection_id IS NULL)
 OR (kind IN('fit_span','fit_page','fit_manifest') AND signature_id IS NOT NULL AND selection_id IS NOT NULL AND owner_key=signature_id)
 OR (kind='legacy_span' AND signature_id IS NOT NULL AND selection_id IS NULL AND owner_key=signature_id)),
 CHECK((kind='source' AND bytes<=52428800 AND content_type='application/pdf')
 OR (kind='fit_span' AND bytes<=1048576 AND content_type='text/html')
 OR (kind='fit_page' AND bytes<=16777276 AND content_type='application/vnd.hash.signature-fit.v1')
 OR (kind='fit_manifest' AND bytes<=2097152 AND content_type='application/json')
 OR (kind='legacy_span' AND bytes<=5056 AND content_type='text/html'))
);

ALTER TABLE document_finalization_intents
 ADD COLUMN fitted_preparation_id UUID,
 ADD COLUMN fits_index_storage_key TEXT,
 ADD COLUMN fits_index_version_id TEXT,
 ADD COLUMN fits_index_sha256 BYTEA,
 ADD COLUMN fits_index_bytes BIGINT,
 ADD CONSTRAINT finalization_intent_fitted_pin_pair CHECK(
  (fitted_preparation_id IS NULL AND fits_index_storage_key IS NULL AND fits_index_version_id IS NULL AND fits_index_sha256 IS NULL AND fits_index_bytes IS NULL)
  OR
  (fitted_preparation_id IS NOT NULL AND fits_index_storage_key IS NOT NULL AND fits_index_version_id IS NOT NULL
   AND fits_index_sha256 IS NOT NULL AND octet_length(fits_index_sha256)=32 AND fits_index_bytes IS NOT NULL AND fits_index_bytes BETWEEN 1 AND 8388608
   AND hash_signature_fit_version_valid(fits_index_version_id)
   AND fits_index_storage_key='org/'||org_id::text||'/documents/'||document_id::text||'/finalization/index/'||fitted_preparation_id::text||'/signature-fit-index.json')
 ),
 ADD CONSTRAINT finalization_intent_fitted_preparation_identity FOREIGN KEY(fitted_preparation_id,org_id,document_id)
 REFERENCES document_finalization_preparations(id,org_id,document_id) ON DELETE RESTRICT;

-- +goose StatementBegin
CREATE FUNCTION hash_fitted_trim_v1(value TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT btrim(value,U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000');
$$;

CREATE FUNCTION hash_fitted_basis_matches_v1(p document_finalization_preparations,d documents)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE b JSONB; g JSONB; e JSONB; box JSONB; coordinate JSONB; expected JSONB; field_record document_fields%ROWTYPE; signature_record signatures%ROWTYPE;
 ids UUID[]:=ARRAY[]::UUID[]; legacy_ids UUID[]:=ARRAY[]::UUID[]; bases INTEGER[]; party_count INTEGER; n BIGINT; legacy_bytes BIGINT:=0; fit_objects BIGINT; minimum_archive NUMERIC;
BEGIN
 b:=convert_from(p.field_snapshot_payload,'UTF8')::jsonb;
 g:=convert_from(p.geometry_pages_payload,'UTF8')::jsonb;
 SELECT count(*) INTO party_count FROM recipients WHERE document_id=d.id;
 IF party_count NOT BETWEEN 1 AND 100 OR EXISTS(SELECT 1 FROM recipients WHERE document_id=d.id GROUP BY role HAVING count(*)>1) THEN RETURN FALSE; END IF;
 IF jsonb_typeof(b) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(b))<>4
 OR b->>'Schema' IS DISTINCT FROM 'hash-manual-finalization-field-basis-v1' OR b->>'DocumentID' IS DISTINCT FROM d.id::text
 OR jsonb_typeof(b->'Fields') IS DISTINCT FROM 'array' OR jsonb_typeof(b->'Legacy') IS DISTINCT FROM 'array'
 OR jsonb_array_length(b->'Fields') NOT BETWEEN 1 AND 1000
 OR jsonb_typeof(g) IS DISTINCT FROM 'array' OR jsonb_array_length(g)<>p.source_pages THEN RETURN FALSE; END IF;
 FOR e IN SELECT value FROM jsonb_array_elements(g) LOOP
  IF jsonb_typeof(e) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(e))<>3
   OR jsonb_typeof(e->'boxes') IS DISTINCT FROM 'array' OR jsonb_array_length(e->'boxes')<>5
   OR jsonb_typeof(e->'rotation') IS DISTINCT FROM 'number' OR (e->>'rotation')::integer%90<>0
   OR jsonb_typeof(e->'user_unit') IS DISTINCT FROM 'number' OR (e->>'user_unit')::numeric<=0 OR (e->>'user_unit')::numeric>75000 THEN RETURN FALSE; END IF;
  FOR box IN SELECT value FROM jsonb_array_elements(e->'boxes') LOOP
   IF jsonb_typeof(box) IS DISTINCT FROM 'array' OR jsonb_array_length(box)<>4 THEN RETURN FALSE; END IF;
   FOR coordinate IN SELECT value FROM jsonb_array_elements(box) LOOP
    IF jsonb_typeof(coordinate) IS DISTINCT FROM 'number' OR abs(coordinate::text::numeric)>1000000000 THEN RETURN FALSE; END IF;
   END LOOP;
   IF (box->>2)::numeric<=(box->>0)::numeric OR (box->>3)::numeric<=(box->>1)::numeric THEN RETURN FALSE; END IF;
  END LOOP;
 END LOOP;
 FOR e IN SELECT value FROM jsonb_array_elements(b->'Fields') LOOP
  SELECT * INTO field_record FROM document_fields WHERE id=(e->>'ID')::uuid AND document_id=d.id;
  IF NOT FOUND OR field_record.id=ANY(ids) OR (cardinality(ids)>0 AND field_record.id<=ids[cardinality(ids)]) OR field_record.recipient_id IS NULL
   OR NOT EXISTS(SELECT 1 FROM recipients WHERE id=field_record.recipient_id AND document_id=d.id)
   OR field_record.type NOT IN('signature','text','date','checkbox','dropdown','initial')
   OR (field_record.type='signature' AND NOT field_record.required)
   OR (field_record.type<>'signature' AND (party_count<>1 OR NOT EXISTS(SELECT 1 FROM recipients WHERE id=field_record.recipient_id AND document_id=d.id AND role='signer'))) THEN RETURN FALSE; END IF;
  expected:=jsonb_build_object('ID',field_record.id,'RecipientID',COALESCE(field_record.recipient_id,'00000000-0000-0000-0000-000000000000'::uuid),
   'RecipientValid',field_record.recipient_id IS NOT NULL,'Type',field_record.type,'Page',field_record.page,'Required',field_record.required,
   'X',field_record.x_pct::text,'Y',field_record.y_pct::text,'W',field_record.w_pct::text,'H',field_record.h_pct::text,'ValueValid',field_record.value IS NOT NULL,'Value',COALESCE(field_record.value,''));
  IF e IS DISTINCT FROM expected OR field_record.page NOT BETWEEN 1 AND p.source_pages
   OR field_record.x_pct<0 OR field_record.y_pct<0 OR field_record.w_pct<=0 OR field_record.h_pct<=0 OR field_record.x_pct+field_record.w_pct>100 OR field_record.y_pct+field_record.h_pct>100 THEN RETURN FALSE; END IF;
  ids:=array_append(ids,field_record.id);
 END LOOP;
 IF cardinality(ids)<>(SELECT count(*) FROM document_fields WHERE document_id=d.id) THEN RETURN FALSE; END IF;
 FOR e IN SELECT value FROM jsonb_array_elements(b->'Legacy') LOOP
  SELECT * INTO signature_record FROM signatures WHERE id=(e->>'ID')::uuid AND document_id=d.id;
  IF NOT FOUND OR signature_record.id=ANY(legacy_ids) OR (cardinality(legacy_ids)>0 AND signature_record.id<=legacy_ids[cardinality(legacy_ids)])
   OR signature_record.signature_kind NOT IN('manual','delegated_grant_v1') OR signature_record.signed_at IS NULL OR signature_record.typed_name IS NULL OR signature_record.font IS NULL
   OR jsonb_typeof(e->'Object'->'bytes') IS DISTINCT FROM 'number' OR (e->'Object'->>'bytes')::bigint NOT BETWEEN 1 AND 5056
   OR NOT signature_record.image_version_pin_required OR signature_record.image_version_id IS NULL OR NOT hash_signature_fit_version_valid(signature_record.image_version_id)
   OR octet_length(signature_record.typed_name) NOT BETWEEN 1 AND 800 OR char_length(signature_record.typed_name)>200 OR hash_fitted_trim_v1(signature_record.typed_name)=''
   OR octet_length(signature_record.font)>128 THEN RETURN FALSE; END IF;
  expected:=jsonb_build_object('DocumentID',d.id,'ID',signature_record.id,'RecipientID',signature_record.recipient_id,'FieldID',signature_record.field_id,'Kind',signature_record.signature_kind,
   'SignedAt',e->'SignedAt','Object',jsonb_build_object('key',signature_record.image_storage_key,'version_id',signature_record.image_version_id,
    'sha256',encode(signature_record.image_sha256,'hex'),'bytes',(e->'Object'->>'bytes')::bigint,'content_type','text/html'),
   'Name',signature_record.typed_name,'Font',signature_record.font,'SpanSHA256',encode(signature_record.image_sha256,'hex'));
  IF e IS DISTINCT FROM expected OR jsonb_typeof(e->'SignedAt') IS DISTINCT FROM 'string'
   OR (e->>'SignedAt')::timestamptz IS DISTINCT FROM signature_record.signed_at THEN RETURN FALSE; END IF;
  legacy_ids:=array_append(legacy_ids,signature_record.id);legacy_bytes:=legacy_bytes+(e->'Object'->>'bytes')::bigint;
 END LOOP;
 IF cardinality(legacy_ids)<>(SELECT count(*) FROM signatures WHERE document_id=d.id AND signature_kind<>'manual_pdf_fit_v1')
 OR (SELECT count(*) FROM signatures WHERE document_id=d.id) NOT BETWEEN 1 AND 100
 OR party_count NOT BETWEEN 1 AND 100 THEN RETURN FALSE; END IF;
 IF EXISTS(SELECT 1 FROM recipients r WHERE r.document_id=d.id AND (r.status<>'signed' OR r.role IN('cc','viewer') OR r.role !~ '^[a-z][a-z0-9_-]{0,63}$'
  OR r.signed_at IS NULL OR r.signed_at<p.ceremony_epoch OR r.signed_at>=p.completion_effective_at
  OR NOT EXISTS(SELECT 1 FROM signatures s WHERE s.document_id=d.id AND s.recipient_id=r.id)))
 OR EXISTS(SELECT 1 FROM signatures s WHERE s.document_id=d.id AND (s.signed_at IS NULL OR s.signed_at>=p.completion_effective_at
  OR s.signed_at<p.ceremony_epoch OR NOT EXISTS(SELECT 1 FROM document_fields f WHERE f.id=s.field_id AND f.document_id=d.id
   AND f.recipient_id=s.recipient_id AND f.type='signature' AND f.required))) THEN RETURN FALSE; END IF;
 -- Every fitted signature binds its actual85 companion and retained selection.
 -- Geometry bytes are digest-checked above and equal every selected full-page
 -- geometry hash, while source versions remain opaque and byte-for-byte exact.
 IF NOT EXISTS(SELECT 1 FROM signatures WHERE document_id=d.id AND signature_kind='manual_pdf_fit_v1')
 OR EXISTS(SELECT 1 FROM signatures s LEFT JOIN signature_fit_companions c ON c.signature_id=s.id
  LEFT JOIN signature_fit_selections x ON x.id=c.selection_id LEFT JOIN signature_fit_preparations a ON a.id=x.preparation_id
  WHERE s.document_id=d.id AND s.signature_kind='manual_pdf_fit_v1' AND
  (c.signature_id IS NULL OR x.id IS NULL OR a.id IS NULL
   OR ROW(c.org_id,c.document_id,c.recipient_id,c.field_id,c.span_sha256) IS DISTINCT FROM ROW(d.org_id,d.id,s.recipient_id,s.field_id,s.image_sha256)
   OR ROW(x.org_id,x.document_id,x.recipient_id,x.ceremony_epoch,x.source_storage_key,x.source_version_id,x.source_sha256,x.source_bytes,x.geometry_sha256)
      IS DISTINCT FROM ROW(d.org_id,d.id,s.recipient_id,p.ceremony_epoch,p.source_storage_key,p.source_version_id,p.source_sha256,p.source_bytes,p.geometry_sha256)
   OR ROW(x.span_storage_key,x.span_version_id,x.span_sha256) IS DISTINCT FROM ROW(s.image_storage_key,s.image_version_id,s.image_sha256)
   OR x.retention_started_at IS NULL OR x.retention_completed_at IS NULL OR x.retention_completed_at>s.signed_at OR a.status<>'prepared'
   OR x.authority_sha256 IS DISTINCT FROM a.authority_sha256)) THEN RETURN FALSE; END IF;
 SELECT COALESCE(array_agg(page ORDER BY page),ARRAY[]::INTEGER[]) INTO bases FROM (
  SELECT DISTINCT f.page FROM document_fields f WHERE f.document_id=d.id AND
   ((f.type='signature' AND f.recipient_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signatures s
      WHERE s.document_id=d.id AND s.recipient_id=f.recipient_id AND s.signature_kind='manual_pdf_fit_v1'))
    OR (f.type<>'signature' AND f.value IS NOT NULL AND hash_fitted_trim_v1(f.value)<>''
     AND (f.type<>'checkbox' OR lower(hash_fitted_trim_v1(f.value)) IN('true','1','yes','on','checked','x'))))
 ) q;
 IF p.required_base_pages IS DISTINCT FROM bases THEN RETURN FALSE; END IF;
 SELECT count(*) INTO fit_objects FROM signature_fit_objects o JOIN signature_fit_selections x ON x.preparation_id=o.preparation_id
  JOIN signature_fit_companions c ON c.selection_id=x.id WHERE c.document_id=d.id AND c.org_id=d.org_id;
 IF p.expected_references<>1+fit_objects+cardinality(legacy_ids) THEN RETURN FALSE; END IF;
 SELECT count(*) INTO n FROM signature_fit_preparations WHERE document_id=d.id AND status<>'cleaned';
 minimum_archive:=p.fit_reserved_bytes+p.source_bytes+legacy_bytes+p.base_bytes_limit+p.final_pdf_bytes_limit+
  p.fits_index_bytes_limit+p.certificate_pdf_bytes_limit+p.certificate_payload_bytes_limit+p.certificate_signature_bytes_limit+
  4194304+4194304+1048576+2*16384+22+
  (n*502+p.expected_outputs+p.expected_references+5)*(92+2*128);
 RETURN p.archive_budget_bytes>=minimum_archive;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END;
$$;

CREATE FUNCTION hash_fitted_pin_matches_v1(pin JSONB,key TEXT,version TEXT,sha BYTEA,byte_count BIGINT,media TEXT)
RETURNS BOOLEAN LANGUAGE sql IMMUTABLE AS $$
 SELECT pin IS NOT DISTINCT FROM jsonb_build_object('key',key,'version_id',version,'sha256',encode(sha,'hex'),'bytes',byte_count,'content_type',media)
  AND version IS NOT NULL AND sha IS NOT NULL AND byte_count IS NOT NULL;
$$;

-- Structural SQL linkage is independent of the app's mandatory frozen decoder,
-- actual package/processing-byte checks and trusted Ed25519 verification. SQL
-- cannot turn a self-asserted public key, provider pin or timestamp into proof.
CREATE FUNCTION hash_fitted_index_matches_v1(raw BYTEA,p document_finalization_preparations)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE w JSONB; b JSONB; doc JSONB; e JSONB; m JSONB; a JSONB; v JSONB; expected JSONB;
 basis JSONB; geom JSONB; selected signature_fit_selections%ROWTYPE; sig signatures%ROWTYPE;
 output document_finalization_outputs%ROWTYPE; object signature_fit_objects%ROWTYPE;
 ids UUID[]:=ARRAY[]::UUID[]; pages INTEGER[]:=ARRAY[]::INTEGER[]; member JSONB;
 previous_at TIMESTAMPTZ; previous_id UUID; at TIMESTAMPTZ; pdf_bytes BIGINT:=0; layer_count BIGINT:=0; base_bytes BIGINT:=0;
BEGIN
 w:=convert_from(raw,'UTF8')::jsonb;b:=w->'payload';basis:=convert_from(p.field_snapshot_payload,'UTF8')::jsonb;
 geom:=jsonb_build_object('schema_version',1,'source_sha256',encode(p.source_sha256,'hex'),'source_bytes',p.source_bytes,
                        'geometry_sha256',encode(p.geometry_sha256,'hex'),'pages',convert_from(p.geometry_pages_payload,'UTF8')::jsonb);
 IF jsonb_typeof(w) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(w))<>6
 OR w->>'schema' IS DISTINCT FROM 'hash-manual-fit-index-v1' OR w->>'signature_domain' IS DISTINCT FROM 'hash:manual-fit-index:v1'
 OR octet_length(decode(w->>'public_key_b64','base64')) IS DISTINCT FROM 32 OR octet_length(decode(w->>'signature_b64','base64')) IS DISTINCT FROM 64
 OR w->>'signing_key_sha256' IS DISTINCT FROM encode(digest(decode(w->>'public_key_b64','base64'),'sha256'),'hex')
 OR jsonb_typeof(b) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(b))<>11
 OR b->>'schema' IS DISTINCT FROM 'hash-manual-fit-index-v1' OR b->>'org_id' IS DISTINCT FROM p.org_id::text
 OR b->>'document_id' IS DISTINCT FROM p.document_id::text OR b->>'original_document_name' IS DISTINCT FROM p.original_document_name
 OR (b->>'ceremony_epoch')::timestamptz IS DISTINCT FROM p.ceremony_epoch
 OR (b->>'completion_effective_at')::timestamptz IS DISTINCT FROM p.completion_effective_at OR (b->>'retain_until')::timestamptz IS DISTINCT FROM p.retain_until
 OR jsonb_typeof(b->'documents') IS DISTINCT FROM 'array' OR jsonb_array_length(b->'documents')<>1
 OR jsonb_typeof(b->'entries') IS DISTINCT FROM 'array' OR jsonb_typeof(b->'legacy_signatures') IS DISTINCT FROM 'array' THEN RETURN FALSE; END IF;
 doc:=b->'documents'->0;
 IF jsonb_typeof(doc) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(doc))<>9
 OR doc->>'document_id' IS DISTINCT FROM p.document_id::text OR doc->'position' IS DISTINCT FROM '0'::jsonb
 OR (doc->>'ceremony_epoch')::timestamptz IS DISTINCT FROM p.ceremony_epoch
 OR doc->'source' IS DISTINCT FROM jsonb_build_object('key',p.source_storage_key,'version_id',p.source_version_id,'sha256',encode(p.source_sha256,'hex'),'bytes',p.source_bytes)
 OR doc->'field_snapshot_json' IS DISTINCT FROM basis OR doc->>'field_snapshot_sha256' IS DISTINCT FROM encode(p.field_snapshot_sha256,'hex')
 OR doc->'geometry' IS DISTINCT FROM geom OR jsonb_typeof(doc->'base_pages') IS DISTINCT FROM 'array'
 OR jsonb_array_length(doc->'base_pages')<>cardinality(p.required_base_pages) THEN RETURN FALSE; END IF;
 SELECT * INTO output FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='final_pdf' AND readback_verified_at IS NOT NULL;
 IF NOT FOUND OR NOT hash_fitted_pin_matches_v1(b->'final_pdf',output.storage_key,output.version_id,output.sha256,output.bytes,output.content_type) THEN RETURN FALSE; END IF;
 FOR e IN SELECT value FROM jsonb_array_elements(doc->'base_pages') LOOP
  SELECT * INTO output FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='base_pdf' AND page=(e->>'page')::integer AND readback_verified_at IS NOT NULL;
  IF NOT FOUND OR output.page=ANY(pages) OR (cardinality(pages)>0 AND output.page<=pages[cardinality(pages)])
   OR NOT hash_fitted_pin_matches_v1(e->'object',output.storage_key,output.version_id,output.sha256,output.bytes,output.content_type)
   OR e->>'source_sha256' IS DISTINCT FROM encode(p.source_sha256,'hex') OR e->>'geometry_sha256' IS DISTINCT FROM encode(p.geometry_sha256,'hex')
   OR e->>'field_snapshot_sha256' IS DISTINCT FROM encode(p.field_snapshot_sha256,'hex') THEN RETURN FALSE; END IF;
  pages:=array_append(pages,output.page);base_bytes:=base_bytes+output.bytes;layer_count:=layer_count+1;
 END LOOP;
 IF pages IS DISTINCT FROM p.required_base_pages THEN RETURN FALSE; END IF;
 pages:=ARRAY[]::INTEGER[];
 FOR e IN SELECT value FROM jsonb_array_elements(b->'entries') LOOP
  SELECT * INTO sig FROM signatures WHERE document_id=p.document_id AND id=(e->>'signature_id')::uuid AND signature_kind='manual_pdf_fit_v1';
  IF NOT FOUND OR sig.id=ANY(ids) THEN RETURN FALSE; END IF;
  at:=(e->>'signed_at')::timestamptz;
  IF at IS DISTINCT FROM sig.signed_at OR (previous_at IS NOT NULL AND (at<previous_at OR (at=previous_at AND sig.id<=previous_id))) THEN RETURN FALSE; END IF;
  SELECT x.* INTO selected FROM signature_fit_companions c JOIN signature_fit_selections x ON x.id=c.selection_id
   WHERE c.signature_id=sig.id AND c.org_id=p.org_id AND c.document_id=p.document_id;
  IF NOT FOUND OR e->>'selection_id' IS DISTINCT FROM selected.id::text OR e->>'recipient_id' IS DISTINCT FROM sig.recipient_id::text
   OR e->>'field_id' IS DISTINCT FROM sig.field_id::text OR (e->>'retention_floor')::timestamptz IS DISTINCT FROM selected.retain_until
   OR NOT hash_fitted_pin_matches_v1(e->'manifest_object',selected.manifest_storage_key,selected.manifest_version_id,selected.manifest_sha256,selected.manifest_bytes,'application/json') THEN RETURN FALSE; END IF;
  m:=e->'manifest';a:=m->'authority';
  SELECT jsonb_build_object('expected_target_ids',COALESCE(jsonb_agg(f->'ID' ORDER BY f->>'ID'),'[]'::jsonb),
   'targets',COALESCE(jsonb_agg(jsonb_build_object('id',f->'ID','org_id',p.org_id,'document_id',p.document_id,'recipient_id',sig.recipient_id,
    'page',f->'Page','required',f->'Required','x_pct',f->'X','y_pct',f->'Y','w_pct',f->'W','h_pct',f->'H') ORDER BY f->>'ID'),'[]'::jsonb))
   INTO expected FROM jsonb_array_elements(basis->'Fields') f WHERE f->>'Type'='signature' AND f->>'RecipientID'=sig.recipient_id::text;
  IF m->>'schema' IS DISTINCT FROM 'hash-manual-signature-fit-manifest-v1' OR m->>'operation_id' IS DISTINCT FROM selected.preparation_id::text
   OR m->>'org_id' IS DISTINCT FROM p.org_id::text OR m->>'document_id' IS DISTINCT FROM p.document_id::text OR m->>'recipient_id' IS DISTINCT FROM sig.recipient_id::text
   OR (m->>'ceremony_epoch')::timestamptz IS DISTINCT FROM p.ceremony_epoch OR m->>'authority_sha256' IS DISTINCT FROM encode(selected.authority_sha256,'hex')
   OR NOT hash_fitted_pin_matches_v1(m->'span',selected.span_storage_key,selected.span_version_id,selected.span_sha256,selected.span_bytes,'text/html')
   OR a->>'schema' IS DISTINCT FROM 'manual_pdf_fit_v1' OR a->>'org_id' IS DISTINCT FROM p.org_id::text OR a->>'document_id' IS DISTINCT FROM p.document_id::text
   OR a->>'recipient_id' IS DISTINCT FROM sig.recipient_id::text OR (a->>'ceremony_epoch')::timestamptz IS DISTINCT FROM p.ceremony_epoch
   OR a->>'span_sha256' IS DISTINCT FROM encode(selected.span_sha256,'hex') OR a->>'typed_name' IS DISTINCT FROM sig.typed_name OR a->>'font' IS DISTINCT FROM sig.font
   OR a->'source' IS DISTINCT FROM doc->'source' OR a->'geometry' IS DISTINCT FROM geom
   OR a->'expected_target_ids' IS DISTINCT FROM expected->'expected_target_ids' OR a->'targets' IS DISTINCT FROM expected->'targets'
   OR jsonb_typeof(m->'pages') IS DISTINCT FROM 'array' OR jsonb_typeof(e->'pdf_sections') IS DISTINCT FROM 'array'
   OR jsonb_array_length(m->'pages')<>(SELECT count(*) FROM signature_fit_objects WHERE preparation_id=selected.preparation_id AND kind='page')
   OR jsonb_array_length(e->'pdf_sections')<>jsonb_array_length(m->'pages') THEN RETURN FALSE; END IF;
  pages:=ARRAY[]::INTEGER[];
  FOR member IN SELECT value FROM jsonb_array_elements(m->'pages') LOOP
   SELECT * INTO object FROM signature_fit_objects WHERE preparation_id=selected.preparation_id AND kind='page' AND page=(member->>'page')::integer AND readback_verified_at IS NOT NULL AND cleanup_completed_at IS NULL;
   IF NOT FOUND OR object.page=ANY(pages) OR (cardinality(pages)>0 AND object.page<=pages[cardinality(pages)])
    OR NOT hash_fitted_pin_matches_v1(member->'package',object.storage_key,object.version_id,object.sha256,object.bytes,object.content_type) THEN RETURN FALSE; END IF;
   v:=e->'pdf_sections'->cardinality(pages);
   IF (v->>'page')::integer IS DISTINCT FROM object.page OR jsonb_typeof(v->'pdf_bytes') IS DISTINCT FROM 'number'
    OR (v->>'pdf_bytes')::bigint NOT BETWEEN 1 AND object.bytes THEN RETURN FALSE; END IF;
   pages:=array_append(pages,object.page);pdf_bytes:=pdf_bytes+(v->>'pdf_bytes')::bigint;layer_count:=layer_count+1;
  END LOOP;
  ids:=array_append(ids,sig.id);previous_at:=at;previous_id:=sig.id;
 END LOOP;
 IF cardinality(ids)<>(SELECT count(*) FROM signature_fit_companions WHERE document_id=p.document_id AND org_id=p.org_id) THEN RETURN FALSE; END IF;
 ids:=ARRAY[]::UUID[];previous_at:=NULL;previous_id:=NULL;
 FOR e IN SELECT value FROM jsonb_array_elements(b->'legacy_signatures') LOOP
  SELECT value INTO member FROM jsonb_array_elements(basis->'Legacy') WHERE value->>'ID'=e->>'signature_id';
  IF NOT FOUND OR (e->>'signature_id')::uuid=ANY(ids) THEN RETURN FALSE; END IF;
  at:=(e->>'signed_at')::timestamptz;
  IF at IS DISTINCT FROM (member->>'SignedAt')::timestamptz OR (previous_at IS NOT NULL AND (at<previous_at OR (at=previous_at AND (e->>'signature_id')::uuid<=previous_id))) THEN RETURN FALSE; END IF;
  expected:=jsonb_build_object('document_id',member->'DocumentID','signature_id',member->'ID','recipient_id',member->'RecipientID','field_id',member->'FieldID',
   'kind',member->'Kind','signed_at',e->'signed_at','object',member->'Object','original_name',member->'Name','font',member->'Font','span_sha256',member->'SpanSHA256');
  IF e IS DISTINCT FROM expected THEN RETURN FALSE; END IF;
  ids:=array_append(ids,(e->>'signature_id')::uuid);previous_at:=at;previous_id:=(e->>'signature_id')::uuid;
 END LOOP;
 IF cardinality(ids)<>jsonb_array_length(basis->'Legacy') THEN RETURN FALSE; END IF;
 SELECT * INTO STRICT output FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='final_pdf';
 v:=doc->'composition';
 IF v->'schema_version' IS DISTINCT FROM '1'::jsonb OR v->>'policy' IS DISTINCT FROM 'hash-pdf-manual-ordered-layers-v1'
  OR v->>'source_sha256' IS DISTINCT FROM encode(p.source_sha256,'hex') OR (v->>'source_bytes')::bigint IS DISTINCT FROM p.source_bytes
  OR v->>'geometry_sha256' IS DISTINCT FROM encode(p.geometry_sha256,'hex') OR (v->>'pages')::integer IS DISTINCT FROM p.source_pages
  OR (v->>'layers')::bigint IS DISTINCT FROM layer_count OR layer_count NOT BETWEEN 1 AND 1500
  OR (v->>'processing_bytes')::bigint IS NULL OR (v->>'processing_bytes')::bigint<=p.source_bytes+base_bytes+pdf_bytes
  OR (v->>'processing_bytes')::bigint>52428800 OR v->>'output_sha256' IS DISTINCT FROM encode(output.sha256,'hex')
  OR (v->>'output_bytes')::bigint IS DISTINCT FROM output.bytes
  OR COALESCE(v->>'descriptor_sha256','') !~ '^[0-9a-f]{64}$' OR COALESCE(v->>'original_content_sha256','') !~ '^[0-9a-f]{64}$'
  OR COALESCE(v->>'ordered_painting_sha256','') !~ '^[0-9a-f]{64}$' OR COALESCE(v->>'processing_sha256','') !~ '^[0-9a-f]{64}$' THEN RETURN FALSE; END IF;
 RETURN TRUE;
EXCEPTION WHEN OTHERS THEN RETURN FALSE;
END;
$$;

CREATE FUNCTION hash_fitted_preparation_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d documents%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'finalization inventory cannot be discarded' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  IF NEW.status<>'staging' OR NEW.attempts<>1 OR NEW.lease_until<=clock_timestamp() OR NEW.lease_until>clock_timestamp()+interval '15 minutes'
   OR NEW.retention_started_at IS NOT NULL OR NEW.retention_completed_at IS NOT NULL OR NEW.publication_commit_attempted_at IS NOT NULL OR NEW.published_at IS NOT NULL
   OR NEW.audit_snapshot_payload IS NOT NULL OR NEW.certificate_input_payload IS NOT NULL
   OR d.status<>'finalizing' OR d.source_kind<>'pdf' OR NOT d.requires_signature OR NOT d.evidence_version_pins_required OR d.is_envelope OR d.parent_envelope_id IS NOT NULL OR d.deleted_at IS NOT NULL
   OR NOT d.fits_index_required OR NOT d.completion_effective_at_bound OR NOT d.article13_notice_epoch_v61_committed
   OR ROW(NEW.ceremony_epoch,NEW.completion_effective_at,NEW.retain_until,NEW.original_document_name,NEW.source_storage_key,NEW.source_version_id,NEW.source_sha256,NEW.fit_reserved_bytes)
      IS DISTINCT FROM ROW(d.article13_notice_epoch_at,d.completion_effective_at,d.finalization_retain_until,d.name,d.pdf_storage_key,d.pdf_storage_version_id,d.pdf_sha256,d.signature_fit_reserved_bytes)
   OR NOT hash_fitted_basis_matches_v1(NEW,d) THEN
    RAISE EXCEPTION 'finalization capture differs from actual frozen ceremony' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.id,NEW.org_id,NEW.document_id,NEW.ceremony_epoch,NEW.completion_effective_at,NEW.retain_until,NEW.original_document_name,
  NEW.source_storage_key,NEW.source_version_id,NEW.source_sha256,NEW.source_bytes,NEW.source_pages,NEW.geometry_pages_payload,NEW.geometry_sha256,
  NEW.field_snapshot_payload,NEW.field_snapshot_sha256,NEW.required_base_pages,NEW.expected_outputs,NEW.expected_references,NEW.fit_reserved_bytes,
  NEW.base_bytes_limit,NEW.final_pdf_bytes_limit,NEW.fits_index_bytes_limit,NEW.certificate_pdf_bytes_limit,NEW.certificate_payload_bytes_limit,
  NEW.certificate_signature_bytes_limit,NEW.archive_budget_bytes,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.id,OLD.org_id,OLD.document_id,OLD.ceremony_epoch,OLD.completion_effective_at,OLD.retain_until,OLD.original_document_name,
  OLD.source_storage_key,OLD.source_version_id,OLD.source_sha256,OLD.source_bytes,OLD.source_pages,OLD.geometry_pages_payload,OLD.geometry_sha256,
  OLD.field_snapshot_payload,OLD.field_snapshot_sha256,OLD.required_base_pages,OLD.expected_outputs,OLD.expected_references,OLD.fit_reserved_bytes,
  OLD.base_bytes_limit,OLD.final_pdf_bytes_limit,OLD.fits_index_bytes_limit,OLD.certificate_pdf_bytes_limit,OLD.certificate_payload_bytes_limit,
  OLD.certificate_signature_bytes_limit,OLD.archive_budget_bytes,OLD.created_at)
 OR OLD.status='published' AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'finalization captured identity is immutable' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.owner_id,NEW.lease_until) IS DISTINCT FROM ROW(OLD.owner_id,OLD.lease_until) THEN
  IF NEW.lease_until<=clock_timestamp() OR NEW.lease_until>clock_timestamp()+interval '15 minutes'
   OR (NEW.owner_id=OLD.owner_id AND (OLD.lease_until<=clock_timestamp() OR NEW.attempts<>OLD.attempts OR NEW.lease_until<OLD.lease_until))
   OR (NEW.owner_id<>OLD.owner_id AND (OLD.lease_until>clock_timestamp() OR NEW.attempts<>OLD.attempts+1)) THEN
   RAISE EXCEPTION 'finalization lease transition is invalid' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.attempts<>OLD.attempts THEN RAISE EXCEPTION 'finalization attempts require bounded takeover' USING ERRCODE='23514'; END IF;
 IF NEW IS DISTINCT FROM OLD AND NEW.lease_until<=clock_timestamp() THEN
  RAISE EXCEPTION 'finalization checkpoint requires current lease' USING ERRCODE='23514';
 END IF;
 IF (OLD.audit_snapshot_payload IS NOT NULL AND ROW(NEW.audit_snapshot_payload,NEW.audit_snapshot_sha256) IS DISTINCT FROM ROW(OLD.audit_snapshot_payload,OLD.audit_snapshot_sha256))
 OR (OLD.certificate_input_payload IS NOT NULL AND ROW(NEW.certificate_input_payload,NEW.certificate_input_sha256) IS DISTINCT FROM ROW(OLD.certificate_input_payload,OLD.certificate_input_sha256))
 OR (OLD.retention_started_at IS NOT NULL AND NEW.retention_started_at IS DISTINCT FROM OLD.retention_started_at)
 OR (OLD.retention_completed_at IS NOT NULL AND NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at)
 OR (OLD.publication_commit_attempted_at IS NOT NULL AND NEW.publication_commit_attempted_at IS DISTINCT FROM OLD.publication_commit_attempted_at)
 OR (OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at) THEN
  RAISE EXCEPTION 'finalization original checkpoint cannot be rewritten' USING ERRCODE='23514';
 END IF;
 IF OLD.audit_snapshot_payload IS NULL AND NEW.audit_snapshot_payload IS NOT NULL AND
  (OLD.status<>'staging' OR EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=OLD.id)) THEN
  RAISE EXCEPTION 'audit context must precede original output work' USING ERRCODE='23514'; END IF;
 IF OLD.certificate_input_payload IS NULL AND NEW.certificate_input_payload IS NOT NULL AND
  (OLD.status<>'staging' OR NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=OLD.id AND kind='final_pdf' AND readback_verified_at IS NOT NULL)
   OR NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=OLD.id AND kind='fits_index' AND readback_verified_at IS NOT NULL)
   OR EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=OLD.id AND kind IN('certificate_pdf','certificate_payload','certificate_signature'))) THEN
  RAISE EXCEPTION 'certificate input requires exact final/index pins before render' USING ERRCODE='23514'; END IF;
 IF NEW.status IS DISTINCT FROM OLD.status AND NOT((OLD.status='staging' AND NEW.status='prepared') OR (OLD.status='prepared' AND NEW.status='published')) THEN
  RAISE EXCEPTION 'finalization state cannot move backwards' USING ERRCODE='23514'; END IF;
 IF NEW.status='prepared' AND OLD.status='staging' THEN
  IF NEW.audit_snapshot_payload IS NULL OR NEW.certificate_input_payload IS NULL
   OR (SELECT count(*) FROM document_finalization_outputs WHERE preparation_id=NEW.id)<>NEW.expected_outputs
   OR EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=NEW.id AND (version_id IS NULL OR readback_verified_at IS NULL))
   OR (SELECT count(*) FROM document_finalization_references WHERE preparation_id=NEW.id)<>NEW.expected_references THEN
   RAISE EXCEPTION 'prepared finalization requires complete exact durable inventory' USING ERRCODE='23514'; END IF;
 END IF;
 IF OLD.retention_completed_at IS NULL AND NEW.retention_completed_at IS NOT NULL AND
  (OLD.status<>'prepared' OR OLD.retention_started_at IS NULL OR NEW.status<>'prepared' OR EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=NEW.id AND retention_completed_at IS NULL)
   OR EXISTS(SELECT 1 FROM document_finalization_references WHERE preparation_id=NEW.id AND retention_completed_at IS NULL)
   OR NOT EXISTS(SELECT 1 FROM document_finalization_intents WHERE fitted_preparation_id=NEW.id AND retention_completed_at IS NOT NULL)) THEN
  RAISE EXCEPTION 'finalization retention requires all exact outputs/references and intent checkpoint' USING ERRCODE='23514'; END IF;
 IF OLD.publication_commit_attempted_at IS NULL AND NEW.publication_commit_attempted_at IS NOT NULL AND
  (OLD.status<>'prepared' OR OLD.retention_completed_at IS NULL OR NEW.status<>'prepared' OR NEW.retention_completed_at IS NULL) THEN
  RAISE EXCEPTION 'publication attempt requires verified final retention' USING ERRCODE='23514'; END IF;
 IF OLD.published_at IS NULL AND NEW.published_at IS NOT NULL AND
  (OLD.status<>'prepared' OR OLD.retention_completed_at IS NULL OR OLD.publication_commit_attempted_at IS NULL OR NEW.status<>'published') THEN
  RAISE EXCEPTION 'published checkpoint requires earlier retained publication attempt' USING ERRCODE='23514'; END IF;
 IF NEW.status='published' AND (d.status<>'completed' OR d.fits_index_preparation_id IS DISTINCT FROM NEW.id OR NEW.retention_completed_at IS NULL OR NEW.published_at IS NULL) THEN
  RAISE EXCEPTION 'published finalization requires paired completed row' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'finalization parent is missing' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER fitted_preparation_guard BEFORE INSERT OR UPDATE OR DELETE ON document_finalization_preparations
 FOR EACH ROW EXECUTE FUNCTION hash_fitted_preparation_guard_v1();

CREATE FUNCTION hash_fitted_output_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p document_finalization_preparations%ROWTYPE; d UUID; key TEXT; used NUMERIC; lim BIGINT; index_json JSONB;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'original finalization output cannot be discarded' USING ERRCODE='23514'; END IF;
 SELECT document_id INTO STRICT d FROM document_finalization_preparations WHERE id=NEW.preparation_id;
 PERFORM 1 FROM documents WHERE id=d FOR UPDATE;
 SELECT * INTO STRICT p FROM document_finalization_preparations WHERE id=NEW.preparation_id FOR UPDATE;
 key:='org/'||p.org_id::text||'/documents/'||p.document_id::text||'/';
 CASE NEW.kind
 WHEN 'base_pdf' THEN key:=key||'finalization/base/'||p.id::text||'/page-'||NEW.page::text||'.pdf';lim:=p.base_bytes_limit;
 WHEN 'final_pdf' THEN key:=key||'final-'||encode(NEW.sha256,'hex')||'.pdf';lim:=p.final_pdf_bytes_limit;
 WHEN 'fits_index' THEN key:=key||'finalization/index/'||p.id::text||'/signature-fit-index.json';lim:=p.fits_index_bytes_limit;
 WHEN 'certificate_pdf' THEN key:=key||'audit-'||encode(NEW.sha256,'hex')||'.pdf';lim:=p.certificate_pdf_bytes_limit;
 WHEN 'certificate_payload' THEN key:=key||'audit-payload-'||encode(NEW.sha256,'hex')||'.txt';lim:=p.certificate_payload_bytes_limit;
 WHEN 'certificate_signature' THEN key:=key||'audit-signature-'||encode(NEW.sha256,'hex')||'.txt';lim:=p.certificate_signature_bytes_limit;
 ELSE RAISE EXCEPTION 'unsupported finalization output' USING ERRCODE='23514';
 END CASE;
 IF NEW.storage_key<>key OR NEW.bytes>lim OR (NEW.kind='base_pdf' AND NOT NEW.page=ANY(p.required_base_pages)) THEN
  RAISE EXCEPTION 'output differs from reserved owned identity/limit' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF p.status<>'staging' OR p.lease_until<=clock_timestamp() OR p.audit_snapshot_payload IS NULL
   OR NEW.upload_attempted_at IS NOT NULL OR NEW.upload_owner_id IS NOT NULL OR NEW.version_id IS NOT NULL
   OR NEW.readback_verified_at IS NOT NULL OR NEW.retention_started_at IS NOT NULL OR NEW.retention_completed_at IS NOT NULL
   OR (NEW.kind IN('certificate_pdf','certificate_payload','certificate_signature') AND p.certificate_input_payload IS NULL)
   OR (SELECT count(*) FROM document_finalization_outputs WHERE preparation_id=p.id)>=p.expected_outputs THEN
   RAISE EXCEPTION 'output must reserve original bytes before its attempt' USING ERRCODE='23514'; END IF;
  -- Hash the original body once at reservation. Later checkpoints compare the
  -- immutable native bytea and do not hex-expand or rehash a 50MiB PDF in JSON.
  IF digest(NEW.payload,'sha256') IS DISTINCT FROM NEW.sha256 THEN
   RAISE EXCEPTION 'original output body differs from committed SHA' USING ERRCODE='23514'; END IF;
  SELECT COALESCE(sum(bytes),0) INTO used FROM document_finalization_outputs WHERE preparation_id=p.id AND kind=NEW.kind;
  IF used+NEW.bytes>lim THEN RAISE EXCEPTION 'aggregate output kind reservation exceeded' USING ERRCODE='23514'; END IF;
  IF NEW.kind='certificate_payload' AND NEW.payload IS DISTINCT FROM p.certificate_input_payload THEN
   RAISE EXCEPTION 'certificate payload must preserve exact original frozen signed HTML' USING ERRCODE='23514'; END IF;
  IF NEW.kind='fits_index' AND NOT hash_fitted_index_matches_v1(NEW.payload,p) THEN
   RAISE EXCEPTION 'signed index differs from guarded frozen journal' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.preparation_id,NEW.kind,NEW.page,NEW.storage_key,NEW.sha256,NEW.bytes,NEW.content_type,NEW.payload)
 IS DISTINCT FROM ROW(OLD.preparation_id,OLD.kind,OLD.page,OLD.storage_key,OLD.sha256,OLD.bytes,OLD.content_type,OLD.payload)
 OR p.status='published' AND NEW IS DISTINCT FROM OLD
 OR (OLD.upload_attempted_at IS NOT NULL AND ROW(NEW.upload_attempted_at,NEW.upload_owner_id) IS DISTINCT FROM ROW(OLD.upload_attempted_at,OLD.upload_owner_id))
 OR (OLD.version_id IS NOT NULL AND NEW.version_id IS DISTINCT FROM OLD.version_id)
 OR (OLD.readback_verified_at IS NOT NULL AND NEW.readback_verified_at IS DISTINCT FROM OLD.readback_verified_at)
 OR (OLD.retention_started_at IS NOT NULL AND NEW.retention_started_at IS DISTINCT FROM OLD.retention_started_at)
 OR (OLD.retention_completed_at IS NOT NULL AND NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at) THEN
  RAISE EXCEPTION 'original output bytes/pins/checkpoints are immutable' USING ERRCODE='23514'; END IF;
 IF NEW IS DISTINCT FROM OLD AND p.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'output checkpoint requires current lease' USING ERRCODE='23514'; END IF;
 IF OLD.retention_started_at IS NULL AND NEW.retention_started_at IS NOT NULL AND p.retention_started_at IS NULL THEN
  RAISE EXCEPTION 'output retention must follow earlier parent start' USING ERRCODE='23514'; END IF;
 IF OLD.upload_attempted_at IS NULL AND NEW.upload_attempted_at IS NOT NULL AND
  (p.status<>'staging' OR NEW.upload_owner_id IS DISTINCT FROM p.owner_id OR OLD.retention_started_at IS NULL
   OR p.retention_started_at IS NULL OR NEW.version_id IS NOT NULL OR NEW.readback_verified_at IS NOT NULL) THEN
  RAISE EXCEPTION 'original upload requires earlier durable final retention start' USING ERRCODE='23514'; END IF;
 IF OLD.version_id IS NULL AND NEW.version_id IS NOT NULL AND OLD.upload_attempted_at IS NULL THEN
  RAISE EXCEPTION 'positive output pin requires earlier original attempt' USING ERRCODE='23514'; END IF;
 IF OLD.readback_verified_at IS NULL AND NEW.readback_verified_at IS NOT NULL AND OLD.version_id IS NULL THEN
  RAISE EXCEPTION 'readback requires earlier exact positive pin' USING ERRCODE='23514'; END IF;
 IF OLD.retention_completed_at IS NULL AND NEW.retention_completed_at IS NOT NULL AND
  (OLD.retention_started_at IS NULL OR OLD.readback_verified_at IS NULL) THEN
  RAISE EXCEPTION 'retention completion requires earlier exact readback/start' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'output operation is missing' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER fitted_output_guard BEFORE INSERT OR UPDATE OR DELETE ON document_finalization_outputs FOR EACH ROW EXECUTE FUNCTION hash_fitted_output_guard_v1();

CREATE FUNCTION hash_fitted_reference_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p document_finalization_preparations%ROWTYPE; d UUID; e JSONB; matched BOOLEAN:=FALSE;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'retained finalization reference cannot be discarded' USING ERRCODE='23514'; END IF;
 SELECT document_id INTO STRICT d FROM document_finalization_preparations WHERE id=NEW.preparation_id;
 PERFORM 1 FROM documents WHERE id=d FOR UPDATE;
 SELECT * INTO STRICT p FROM document_finalization_preparations WHERE id=NEW.preparation_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  IF p.status<>'staging' OR p.lease_until<=clock_timestamp() OR NEW.retention_started_at IS NOT NULL OR NEW.retention_completed_at IS NOT NULL
   OR (SELECT count(*) FROM document_finalization_references WHERE preparation_id=p.id)>=p.expected_references THEN
   RAISE EXCEPTION 'reference must be captured before retention' USING ERRCODE='23514'; END IF;
  IF NEW.kind='source' THEN
   matched:=NEW.owner_key=p.document_id AND ROW(NEW.storage_key,NEW.version_id,NEW.sha256,NEW.bytes)
       IS NOT DISTINCT FROM ROW(p.source_storage_key,p.source_version_id,p.source_sha256,p.source_bytes);
  ELSIF NEW.kind='legacy_span' THEN
   FOR e IN SELECT value FROM jsonb_array_elements(convert_from(p.field_snapshot_payload,'UTF8')::jsonb->'Legacy') LOOP
    IF e->>'ID'=NEW.signature_id::text AND e->'Object'->>'key'=NEW.storage_key AND e->'Object'->>'version_id'=NEW.version_id
     AND e->'Object'->>'sha256'=encode(NEW.sha256,'hex') AND (e->'Object'->>'bytes')::bigint=NEW.bytes THEN matched:=TRUE; END IF;
   END LOOP;
  ELSE
   SELECT EXISTS(SELECT 1 FROM signature_fit_companions c JOIN signature_fit_selections x ON x.id=c.selection_id
    JOIN signature_fit_objects o ON o.preparation_id=x.preparation_id
    WHERE c.org_id=p.org_id AND c.document_id=p.document_id AND c.signature_id=NEW.signature_id AND c.selection_id=NEW.selection_id
     AND o.kind=CASE NEW.kind WHEN 'fit_span' THEN 'span' WHEN 'fit_page' THEN 'page' WHEN 'fit_manifest' THEN 'manifest' END
     AND o.page=NEW.page AND o.storage_key=NEW.storage_key AND o.version_id=NEW.version_id AND o.sha256=NEW.sha256 AND o.bytes=NEW.bytes
     AND o.content_type=NEW.content_type AND o.readback_verified_at IS NOT NULL AND o.cleanup_completed_at IS NULL) INTO matched;
  END IF;
  IF NOT matched THEN RAISE EXCEPTION 'reference differs from actual frozen source/85/legacy pins' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['retention_started_at','retention_completed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['retention_started_at','retention_completed_at'])
 OR (OLD.retention_started_at IS NOT NULL AND NEW.retention_started_at IS DISTINCT FROM OLD.retention_started_at)
 OR (OLD.retention_completed_at IS NOT NULL AND NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at)
 OR p.status='published' AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'reference identity/checkpoints are immutable' USING ERRCODE='23514'; END IF;
 IF NEW IS DISTINCT FROM OLD AND (p.lease_until<=clock_timestamp() OR p.status<>'prepared'
  OR NOT EXISTS(SELECT 1 FROM document_finalization_intents WHERE fitted_preparation_id=p.id AND retention_started_at IS NOT NULL)) THEN
  RAISE EXCEPTION 'reference retention requires current lease and durable intent start' USING ERRCODE='23514'; END IF;
 IF OLD.retention_completed_at IS NULL AND NEW.retention_completed_at IS NOT NULL AND OLD.retention_started_at IS NULL THEN
  RAISE EXCEPTION 'reference completion requires earlier durable start' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'reference operation is missing' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER fitted_reference_guard BEFORE INSERT OR UPDATE OR DELETE ON document_finalization_references FOR EACH ROW EXECUTE FUNCTION hash_fitted_reference_guard_v1();

CREATE FUNCTION hash_fitted_intent_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d documents%ROWTYPE; p document_finalization_preparations%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT d FROM documents WHERE id=OLD.document_id AND org_id=OLD.org_id FOR UPDATE;
  IF OLD.fitted_preparation_id IS NULL THEN RETURN OLD; END IF;
  SELECT * INTO STRICT p FROM document_finalization_preparations WHERE id=OLD.fitted_preparation_id AND document_id=d.id AND org_id=d.org_id;
  IF d.status<>'completed' OR d.fits_index_preparation_id IS DISTINCT FROM p.id OR p.status<>'published'
   OR p.published_at IS NULL OR p.retention_completed_at IS NULL OR OLD.retention_completed_at IS NULL THEN
   RAISE EXCEPTION 'fitted intent may only leave inventory after paired retained publication' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF NOT d.fits_index_required THEN
  IF NEW.fitted_preparation_id IS NOT NULL THEN RAISE EXCEPTION 'legacy intent cannot claim fitted index' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT p FROM document_finalization_preparations WHERE id=NEW.fitted_preparation_id AND document_id=d.id AND org_id=d.org_id;
 IF d.status<>'finalizing' OR p.status<>'prepared' OR NEW.mode<>'signature' OR NOT NEW.evidence_version_pins_required OR ROW(NEW.completion_effective_at,NEW.retain_until) IS DISTINCT FROM ROW(p.completion_effective_at,p.retain_until)
 OR NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='fits_index'
  AND ROW(storage_key,version_id,sha256,bytes) IS NOT DISTINCT FROM ROW(NEW.fits_index_storage_key,NEW.fits_index_version_id,NEW.fits_index_sha256,NEW.fits_index_bytes) AND readback_verified_at IS NOT NULL)
 OR NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='final_pdf'
  AND ROW(storage_key,version_id,sha256) IS NOT DISTINCT FROM ROW(NEW.final_pdf_key,NEW.final_pdf_version_id,NEW.final_pdf_sha256) AND readback_verified_at IS NOT NULL)
 OR NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='certificate_pdf'
  AND ROW(storage_key,version_id,sha256) IS NOT DISTINCT FROM ROW(NEW.audit_cert_key,NEW.audit_cert_version_id,NEW.audit_cert_sha256) AND readback_verified_at IS NOT NULL)
 OR NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='certificate_payload'
  AND ROW(storage_key,version_id,sha256) IS NOT DISTINCT FROM ROW(NEW.audit_payload_key,NEW.audit_payload_version_id,NEW.audit_payload_sha256) AND readback_verified_at IS NOT NULL)
 OR NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND kind='certificate_signature'
  AND ROW(storage_key,version_id,sha256) IS NOT DISTINCT FROM ROW(NEW.audit_signature_key,NEW.audit_signature_version_id,NEW.audit_signature_sha256) AND readback_verified_at IS NOT NULL) THEN
  RAISE EXCEPTION 'fitted intent differs from prepared exact output journal' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW IS DISTINCT FROM OLD AND p.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'fitted intent checkpoint requires current lease' USING ERRCODE='23514'; END IF;
  IF OLD.retention_started_at IS NOT NULL AND NEW.retention_started_at IS DISTINCT FROM OLD.retention_started_at
   OR OLD.retention_completed_at IS NOT NULL AND NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at THEN
   RAISE EXCEPTION 'fitted intent retention checkpoints are immutable' USING ERRCODE='23514'; END IF;
  IF OLD.retention_started_at IS NULL AND NEW.retention_started_at IS NOT NULL AND p.retention_started_at IS NULL THEN
   RAISE EXCEPTION 'fitted intent retention must follow durable parent start' USING ERRCODE='23514'; END IF;
  IF OLD.retention_completed_at IS NULL AND NEW.retention_completed_at IS NOT NULL AND
   (OLD.retention_started_at IS NULL OR NOT EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id)
    OR EXISTS(SELECT 1 FROM document_finalization_outputs WHERE preparation_id=p.id AND retention_completed_at IS NULL)
    OR EXISTS(SELECT 1 FROM document_finalization_references WHERE preparation_id=p.id AND retention_completed_at IS NULL)) THEN
   RAISE EXCEPTION 'fitted intent retention requires every exact journal pin' USING ERRCODE='23514'; END IF;
 END IF;
 IF TG_OP='INSERT' AND (NEW.retention_started_at IS NOT NULL OR NEW.retention_completed_at IS NOT NULL OR p.lease_until<=clock_timestamp()) THEN
  RAISE EXCEPTION 'fitted intent cannot invent retention checkpoints' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' AND ROW(NEW.fitted_preparation_id,NEW.fits_index_storage_key,NEW.fits_index_version_id,NEW.fits_index_sha256,NEW.fits_index_bytes)
 IS DISTINCT FROM ROW(OLD.fitted_preparation_id,OLD.fits_index_storage_key,OLD.fits_index_version_id,OLD.fits_index_sha256,OLD.fits_index_bytes) THEN
  RAISE EXCEPTION 'intent fitted pin is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'fitted intent lineage is missing' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER fitted_intent_guard BEFORE INSERT OR UPDATE OR DELETE ON document_finalization_intents FOR EACH ROW EXECUTE FUNCTION hash_fitted_intent_guard_v1();

CREATE FUNCTION hash_fitted_document_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p document_finalization_preparations%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.fits_index_required OR NEW.fits_index_preparation_id IS NOT NULL THEN RAISE EXCEPTION 'new document cannot invent fitted provenance' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF OLD.fits_index_required AND NOT NEW.fits_index_required THEN RAISE EXCEPTION 'fitted evidence cannot be downgraded' USING ERRCODE='23514'; END IF;
 IF NOT OLD.fits_index_required AND NEW.fits_index_required AND
  (OLD.status NOT IN('sent','in_progress') OR OLD.source_kind<>'pdf' OR NOT OLD.requires_signature OR NOT OLD.evidence_version_pins_required OR OLD.is_envelope OR OLD.parent_envelope_id IS NOT NULL OR OLD.deleted_at IS NOT NULL
   OR NOT OLD.article13_notice_epoch_v61_committed) THEN RAISE EXCEPTION 'first fitted flag requires actual standalone active ceremony' USING ERRCODE='23514'; END IF;
 IF OLD.fits_index_storage_key IS NOT NULL AND ROW(NEW.fits_index_preparation_id,NEW.fits_index_storage_key,NEW.fits_index_version_id,NEW.fits_index_sha256,NEW.fits_index_bytes)
 IS DISTINCT FROM ROW(OLD.fits_index_preparation_id,OLD.fits_index_storage_key,OLD.fits_index_version_id,OLD.fits_index_sha256,OLD.fits_index_bytes) THEN
  RAISE EXCEPTION 'completed fitted index pin is immutable' USING ERRCODE='23514'; END IF;
 IF OLD.fits_index_storage_key IS NOT NULL AND ROW(NEW.final_pdf_key,NEW.final_pdf_sha,NEW.final_pdf_version_id,
  NEW.audit_cert_key,NEW.audit_cert_sha256,NEW.audit_cert_version_id,NEW.audit_payload_key,NEW.audit_payload_sha256,NEW.audit_payload_version_id,
  NEW.audit_signature_key,NEW.audit_signature_sha256,NEW.audit_signature_version_id,NEW.evidence_version_pins_required)
 IS DISTINCT FROM ROW(OLD.final_pdf_key,OLD.final_pdf_sha,OLD.final_pdf_version_id,
  OLD.audit_cert_key,OLD.audit_cert_sha256,OLD.audit_cert_version_id,OLD.audit_payload_key,OLD.audit_payload_sha256,OLD.audit_payload_version_id,
  OLD.audit_signature_key,OLD.audit_signature_sha256,OLD.audit_signature_version_id,OLD.evidence_version_pins_required) THEN
  RAISE EXCEPTION 'completed fitted output/certificate pair is immutable' USING ERRCODE='23514'; END IF;
 IF NEW.fits_index_required AND OLD.status<>'completed' AND NEW.status='completed' THEN
  SELECT * INTO STRICT p FROM document_finalization_preparations WHERE id=NEW.fits_index_preparation_id AND org_id=NEW.org_id AND document_id=NEW.id;
  IF p.status<>'prepared' OR p.retention_completed_at IS NULL OR p.publication_commit_attempted_at IS NULL
   OR NOT EXISTS(SELECT 1 FROM document_finalization_intents i WHERE i.fitted_preparation_id=p.id AND i.retention_completed_at IS NOT NULL
    AND ROW(i.fits_index_storage_key,i.fits_index_version_id,i.fits_index_sha256,i.fits_index_bytes) IS NOT DISTINCT FROM ROW(NEW.fits_index_storage_key,NEW.fits_index_version_id,NEW.fits_index_sha256,NEW.fits_index_bytes)
    AND ROW(i.final_pdf_key,i.final_pdf_sha256,i.final_pdf_version_id) IS NOT DISTINCT FROM ROW(NEW.final_pdf_key,NEW.final_pdf_sha,NEW.final_pdf_version_id)
    AND ROW(i.audit_cert_key,i.audit_cert_sha256,i.audit_cert_version_id) IS NOT DISTINCT FROM ROW(NEW.audit_cert_key,NEW.audit_cert_sha256,NEW.audit_cert_version_id)
    AND ROW(i.audit_payload_key,i.audit_payload_sha256,i.audit_payload_version_id) IS NOT DISTINCT FROM ROW(NEW.audit_payload_key,NEW.audit_payload_sha256,NEW.audit_payload_version_id)
    AND ROW(i.audit_signature_key,i.audit_signature_sha256,i.audit_signature_version_id) IS NOT DISTINCT FROM ROW(NEW.audit_signature_key,NEW.audit_signature_sha256,NEW.audit_signature_version_id)) THEN
   RAISE EXCEPTION 'completed fitted publication lacks exact retained intent/journal pair' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'completed fitted publication lineage is missing' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER fitted_document_guard BEFORE INSERT OR UPDATE ON documents FOR EACH ROW EXECUTE FUNCTION hash_fitted_document_guard_v1();

CREATE FUNCTION hash_fitted_document_pair_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target UUID; d documents%ROWTYPE; has_fit BOOLEAN; p document_finalization_preparations%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='documents' THEN target:=NEW.id; ELSE target:=NEW.document_id; END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=target;
 SELECT EXISTS(SELECT 1 FROM signatures WHERE document_id=target AND signature_kind='manual_pdf_fit_v1') INTO has_fit;
 IF d.fits_index_required IS DISTINCT FROM has_fit THEN RAISE EXCEPTION 'fitted signature and document requirement must commit together' USING ERRCODE='23514'; END IF;
 IF d.status='completed' AND d.fits_index_required THEN
  SELECT * INTO STRICT p FROM document_finalization_preparations WHERE id=d.fits_index_preparation_id AND document_id=d.id AND org_id=d.org_id;
  IF p.status<>'published' OR p.published_at IS NULL OR p.retention_completed_at IS NULL THEN
   RAISE EXCEPTION 'completed fitted document requires published durable journal' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'fitted document pair lineage is missing' USING ERRCODE='23514';
END;
$$;
CREATE CONSTRAINT TRIGGER fitted_document_pair_document AFTER INSERT OR UPDATE ON documents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_fitted_document_pair_v1();
CREATE CONSTRAINT TRIGGER fitted_document_pair_signature AFTER INSERT OR UPDATE ON signatures DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_fitted_document_pair_v1();

CREATE FUNCTION hash_fitted_closed_preparation_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM 1 FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id AND fits_index_required AND status IN('finalizing','completed')) THEN
  RAISE EXCEPTION 'frozen fitted finalization cannot admit new fit preparations' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER fitted_closed_preparation_guard BEFORE INSERT ON signature_fit_preparations FOR EACH ROW EXECUTE FUNCTION hash_fitted_closed_preparation_guard_v1();
-- +goose StatementEnd

-- +goose Down
LOCK TABLE documents, signatures, document_finalization_intents, document_finalization_preparations IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM documents WHERE fits_index_required)
 OR EXISTS(SELECT 1 FROM document_finalization_preparations)
 OR EXISTS(SELECT 1 FROM document_finalization_outputs)
 OR EXISTS(SELECT 1 FROM document_finalization_references)
 OR EXISTS(SELECT 1 FROM document_finalization_intents WHERE fitted_preparation_id IS NOT NULL) THEN
  RAISE EXCEPTION 'cannot roll back used fitted finalization inventory' USING ERRCODE='23514';
 END IF;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER fitted_closed_preparation_guard ON signature_fit_preparations;
DROP TRIGGER fitted_document_pair_signature ON signatures;
DROP TRIGGER fitted_document_pair_document ON documents;
DROP TRIGGER fitted_document_guard ON documents;
DROP TRIGGER fitted_intent_guard ON document_finalization_intents;
DROP TRIGGER fitted_reference_guard ON document_finalization_references;
DROP TRIGGER fitted_output_guard ON document_finalization_outputs;
DROP TRIGGER fitted_preparation_guard ON document_finalization_preparations;
DROP FUNCTION hash_fitted_closed_preparation_guard_v1();
DROP FUNCTION hash_fitted_document_pair_v1();
DROP FUNCTION hash_fitted_document_guard_v1();
DROP FUNCTION hash_fitted_intent_guard_v1();
DROP FUNCTION hash_fitted_reference_guard_v1();
DROP FUNCTION hash_fitted_output_guard_v1();
DROP FUNCTION hash_fitted_preparation_guard_v1();
DROP FUNCTION hash_fitted_index_matches_v1(BYTEA,document_finalization_preparations);
DROP FUNCTION hash_fitted_pin_matches_v1(JSONB,TEXT,TEXT,BYTEA,BIGINT,TEXT);
DROP FUNCTION hash_fitted_basis_matches_v1(document_finalization_preparations,documents);
DROP FUNCTION hash_fitted_trim_v1(TEXT);
ALTER TABLE documents DROP CONSTRAINT documents_fits_index_preparation_identity;
ALTER TABLE document_finalization_intents DROP CONSTRAINT finalization_intent_fitted_preparation_identity, DROP CONSTRAINT finalization_intent_fitted_pin_pair,
 DROP COLUMN fitted_preparation_id, DROP COLUMN fits_index_storage_key, DROP COLUMN fits_index_version_id, DROP COLUMN fits_index_sha256, DROP COLUMN fits_index_bytes;
DROP TABLE document_finalization_references,document_finalization_outputs,document_finalization_preparations;
ALTER TABLE documents DROP CONSTRAINT documents_fits_index_pin_pair,
 DROP COLUMN fits_index_required,DROP COLUMN fits_index_preparation_id,DROP COLUMN fits_index_storage_key,DROP COLUMN fits_index_version_id,DROP COLUMN fits_index_sha256,DROP COLUMN fits_index_bytes;
