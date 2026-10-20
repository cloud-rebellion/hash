-- +goose Up
-- Durable manual fit staging and exact selected pins. This migration does not
-- activate signing, finalization or cleanup workers. It stores no typed name,
-- font bytes, authority JSON or contract prose in transient database rows.
-- Standalone 84 -> 85 installation preserves the inherited-isolation contract.
-- Refuse before any DDL; Goose owns the transaction and version history.
-- +goose StatementBegin
DO $$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'signature fit installation requires read committed' USING ERRCODE='23514';
 END IF;
END;
$$;
-- +goose StatementEnd
-- Exact object versions are opaque identities. Trim only for invalid aliases;
-- retain the original bytes on every INSERT, comparison and readback. The
-- whitespace list matches Go strings.TrimSpace after control rejection.
-- +goose StatementBegin
CREATE FUNCTION hash_signature_fit_version_valid(value TEXT) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT octet_length(value) BETWEEN 1 AND 1024
 AND value !~ U&'[\0001-\001F\007F-\009F]'
 AND btrim(value,U&'\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')
  NOT IN ('','null','hash:unversioned-development');
$$;
-- +goose StatementEnd

ALTER TABLE signatures DROP CONSTRAINT signatures_signature_kind_check;
ALTER TABLE signatures ADD CONSTRAINT signatures_signature_kind_check
 CHECK (signature_kind IN ('manual','delegated_grant_v1','manual_pdf_fit_v1'));
ALTER TABLE signatures DROP CONSTRAINT signatures_presign_kind_pair;
ALTER TABLE signatures ADD CONSTRAINT signatures_presign_kind_pair CHECK (
 (signature_kind='manual' AND presign_execution_id IS NULL)
 OR (signature_kind='manual_pdf_fit_v1' AND presign_execution_id IS NULL
     AND image_version_pin_required AND image_version_id IS NOT NULL)
 OR (signature_kind='delegated_grant_v1' AND presign_execution_id IS NOT NULL
     AND signer_ip IS NULL AND signer_ua IS NULL AND image_version_pin_required
     AND image_version_id IS NOT NULL));
ALTER TABLE recipients ADD CONSTRAINT recipients_fit_document_identity UNIQUE(id,document_id);
-- This counter reserves FIT ARTIFACT bytes only. Source/final/certificate/index
-- and legacy evidence still require complete before-Sign/finalization admission.
-- Updating the parent counter is the serialization point. A stale repeatable-
-- read transaction must fail its parent UPDATE rather than sum a stale snapshot.
ALTER TABLE documents ADD COLUMN signature_fit_reserved_bytes BIGINT NOT NULL DEFAULT 0
 CHECK(signature_fit_reserved_bytes BETWEEN 0 AND 167772160);

CREATE TABLE signature_fit_preparations (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 org_id UUID NOT NULL, document_id UUID NOT NULL, recipient_id UUID NOT NULL,
 ceremony_epoch TIMESTAMPTZ NOT NULL CHECK(isfinite(ceremony_epoch)),
 authority_sha256 BYTEA NOT NULL CHECK(octet_length(authority_sha256)=32),
 source_storage_key TEXT NOT NULL CHECK(octet_length(source_storage_key) BETWEEN 1 AND 2048 AND source_storage_key=btrim(source_storage_key) AND source_storage_key !~ '[[:cntrl:]]'),
 source_version_id TEXT NOT NULL CHECK(hash_signature_fit_version_valid(source_version_id)),
 source_sha256 BYTEA NOT NULL CHECK(octet_length(source_sha256)=32),
 source_bytes BIGINT NOT NULL CHECK(source_bytes BETWEEN 1 AND 104857600),
 geometry_sha256 BYTEA NOT NULL CHECK(octet_length(geometry_sha256)=32),
 span_sha256 BYTEA NOT NULL CHECK(octet_length(span_sha256)=32),
 reserved_bytes BIGINT NOT NULL CHECK(reserved_bytes BETWEEN 3 AND 167772160),
 expected_objects INTEGER NOT NULL CHECK(expected_objects BETWEEN 3 AND 502),
 owner_id UUID NOT NULL CHECK(owner_id<>'00000000-0000-0000-0000-000000000000'),
 lease_until TIMESTAMPTZ NOT NULL CHECK(isfinite(lease_until)),
 attempts INTEGER NOT NULL DEFAULT 1 CHECK(attempts BETWEEN 1 AND 8),
 status TEXT NOT NULL DEFAULT 'staging' CHECK(status IN('staging','prepared','abandoned','cleaning','cleaned')),
 selection_commit_attempted_at TIMESTAMPTZ CHECK(selection_commit_attempted_at IS NULL OR isfinite(selection_commit_attempted_at)),
 selection_not_committed_at TIMESTAMPTZ CHECK(selection_not_committed_at IS NULL OR (isfinite(selection_not_committed_at) AND selection_commit_attempted_at IS NOT NULL AND selection_not_committed_at>=selection_commit_attempted_at)),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(updated_at)),
 UNIQUE(id,org_id,document_id,recipient_id,ceremony_epoch),
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(recipient_id,document_id) REFERENCES recipients(id,document_id) ON DELETE RESTRICT
);
CREATE INDEX signature_fit_preparations_recovery ON signature_fit_preparations(status,lease_until,id);
CREATE INDEX signature_fit_preparations_inventory ON signature_fit_preparations(org_id,document_id,recipient_id,id);

CREATE TABLE signature_fit_objects (
 preparation_id UUID NOT NULL REFERENCES signature_fit_preparations(id) ON DELETE RESTRICT,
 kind TEXT NOT NULL CHECK(kind IN('span','page','manifest')),
 page INTEGER NOT NULL CHECK((kind='page' AND page BETWEEN 1 AND 500) OR (kind IN('span','manifest') AND page=0)),
 storage_key TEXT NOT NULL UNIQUE CHECK(octet_length(storage_key) BETWEEN 1 AND 2048),
 sha256 BYTEA NOT NULL CHECK(octet_length(sha256)=32),
 bytes BIGINT NOT NULL CHECK(bytes>0 AND ((kind='span' AND bytes<=1048576) OR (kind='manifest' AND bytes<=2097152) OR (kind='page' AND bytes<=16777276))),
 content_type TEXT NOT NULL CHECK((kind='span' AND content_type='text/html') OR (kind='manifest' AND content_type='application/json') OR (kind='page' AND content_type='application/vnd.hash.signature-fit.v1')),
 upload_attempted_at TIMESTAMPTZ CHECK(upload_attempted_at IS NULL OR isfinite(upload_attempted_at)),
 upload_owner_id UUID CHECK(upload_owner_id IS NULL OR upload_owner_id<>'00000000-0000-0000-0000-000000000000'),
 version_id TEXT CHECK(version_id IS NULL OR hash_signature_fit_version_valid(version_id)),
 readback_verified_at TIMESTAMPTZ CHECK(readback_verified_at IS NULL OR isfinite(readback_verified_at)),
 cleanup_completed_at TIMESTAMPTZ CHECK(cleanup_completed_at IS NULL OR isfinite(cleanup_completed_at)),
 PRIMARY KEY(preparation_id,kind,page),
 CHECK((upload_attempted_at IS NULL AND upload_owner_id IS NULL) OR (upload_attempted_at IS NOT NULL AND upload_owner_id IS NOT NULL)),
 CHECK(version_id IS NULL OR upload_attempted_at IS NOT NULL),
 CHECK(readback_verified_at IS NULL OR (version_id IS NOT NULL AND readback_verified_at>=upload_attempted_at)),
 CHECK(cleanup_completed_at IS NULL OR upload_attempted_at IS NULL OR version_id IS NOT NULL)
);

CREATE TABLE signature_fit_selections (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 preparation_id UUID NOT NULL UNIQUE,
 org_id UUID NOT NULL, document_id UUID NOT NULL, recipient_id UUID NOT NULL,
 ceremony_epoch TIMESTAMPTZ NOT NULL CHECK(isfinite(ceremony_epoch)),
 authority_sha256 BYTEA NOT NULL CHECK(octet_length(authority_sha256)=32),
 source_storage_key TEXT NOT NULL, source_version_id TEXT NOT NULL,
 source_sha256 BYTEA NOT NULL CHECK(octet_length(source_sha256)=32), source_bytes BIGINT NOT NULL,
 geometry_sha256 BYTEA NOT NULL CHECK(octet_length(geometry_sha256)=32),
 span_storage_key TEXT NOT NULL, span_version_id TEXT NOT NULL,
 span_sha256 BYTEA NOT NULL CHECK(octet_length(span_sha256)=32), span_bytes BIGINT NOT NULL,
 manifest_storage_key TEXT NOT NULL, manifest_version_id TEXT NOT NULL,
 manifest_sha256 BYTEA NOT NULL CHECK(octet_length(manifest_sha256)=32), manifest_bytes BIGINT NOT NULL,
 retain_until TIMESTAMPTZ NOT NULL CHECK(isfinite(retain_until) AND retain_until=date_trunc('second',retain_until) AND retain_until=hash_evidence_retain_until(ceremony_epoch,7)),
 retention_started_at TIMESTAMPTZ CHECK(retention_started_at IS NULL OR isfinite(retention_started_at)),
 retention_completed_at TIMESTAMPTZ CHECK(retention_completed_at IS NULL OR (isfinite(retention_completed_at) AND retention_started_at IS NOT NULL AND retention_completed_at>=retention_started_at)),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
 UNIQUE(document_id,recipient_id,ceremony_epoch),
 UNIQUE(id,org_id,document_id,recipient_id),
 FOREIGN KEY(preparation_id,org_id,document_id,recipient_id,ceremony_epoch)
  REFERENCES signature_fit_preparations(id,org_id,document_id,recipient_id,ceremony_epoch) ON DELETE RESTRICT
);
CREATE INDEX signature_fit_selections_pending_retention ON signature_fit_selections(created_at,id) WHERE retention_completed_at IS NULL;

CREATE TABLE signature_fit_companions (
 signature_id UUID PRIMARY KEY,
 org_id UUID NOT NULL, document_id UUID NOT NULL, recipient_id UUID NOT NULL,
 field_id UUID NOT NULL, selection_id UUID NOT NULL UNIQUE,
 span_sha256 BYTEA NOT NULL CHECK(octet_length(span_sha256)=32),
 FOREIGN KEY(signature_id,document_id,recipient_id,field_id)
  REFERENCES signatures(id,document_id,recipient_id,field_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(selection_id,org_id,document_id,recipient_id)
  REFERENCES signature_fit_selections(id,org_id,document_id,recipient_id) ON DELETE RESTRICT
);

-- +goose StatementBegin
CREATE FUNCTION hash_signature_fit_preparation_guard() RETURNS trigger AS $$
DECLARE d documents%ROWTYPE; n BIGINT; count_objects BIGINT; total_objects BIGINT;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'fit inventory cannot be silently discarded' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT d FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  IF NEW.status<>'staging' OR NEW.attempts<>1 OR NEW.selection_commit_attempted_at IS NOT NULL OR NEW.selection_not_committed_at IS NOT NULL
     OR NEW.lease_until<=clock_timestamp() THEN
   RAISE EXCEPTION 'fit preparation must start with a current staging lease' USING ERRCODE='23514';
  END IF;
  -- Original source/field/notice/credential authority is rechecked by the
  -- caller under these locks. This row cannot be treated as an authorization.
  IF d.deleted_at IS NOT NULL THEN RAISE EXCEPTION 'fit document is deleted' USING ERRCODE='23514'; END IF;
  IF (SELECT count(*) FROM signature_fit_preparations WHERE document_id=NEW.document_id AND recipient_id=NEW.recipient_id AND ceremony_epoch=NEW.ceremony_epoch)>=8 THEN
   RAISE EXCEPTION 'fit ceremony operation attempts exhausted' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM recipients WHERE id=NEW.recipient_id AND document_id=NEW.document_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'fit recipient is foreign' USING ERRCODE='23514'; END IF;
  UPDATE documents SET signature_fit_reserved_bytes=signature_fit_reserved_bytes+NEW.reserved_bytes
   WHERE id=NEW.document_id AND org_id=NEW.org_id AND signature_fit_reserved_bytes+NEW.reserved_bytes<=167772160
   RETURNING signature_fit_reserved_bytes INTO n;
  IF NOT FOUND THEN RAISE EXCEPTION 'fit document reservation budget exhausted' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['owner_id','lease_until','attempts','status','selection_commit_attempted_at','selection_not_committed_at','updated_at'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['owner_id','lease_until','attempts','status','selection_commit_attempted_at','selection_not_committed_at','updated_at'])
    OR NEW.attempts<OLD.attempts OR NEW.attempts>OLD.attempts+1
    OR (OLD.selection_commit_attempted_at IS NOT NULL AND NEW.selection_commit_attempted_at IS DISTINCT FROM OLD.selection_commit_attempted_at)
    OR (OLD.selection_not_committed_at IS NOT NULL AND NEW.selection_not_committed_at IS DISTINCT FROM OLD.selection_not_committed_at) THEN
  RAISE EXCEPTION 'fit preparation identity or checkpoint is immutable' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.owner_id,NEW.lease_until) IS DISTINCT FROM ROW(OLD.owner_id,OLD.lease_until) THEN
  IF OLD.lease_until>clock_timestamp() OR NEW.lease_until<=clock_timestamp() OR NEW.attempts<>OLD.attempts+1 THEN
   RAISE EXCEPTION 'fit lease takeover requires expiry and one bounded attempt' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.attempts IS DISTINCT FROM OLD.attempts THEN
  RAISE EXCEPTION 'fit attempt counter only advances with lease takeover' USING ERRCODE='23514';
 END IF;
 IF NEW IS DISTINCT FROM OLD AND NEW.lease_until<=clock_timestamp() THEN
  RAISE EXCEPTION 'fit operation checkpoint requires a current lease' USING ERRCODE='23514';
 END IF;
 IF EXISTS(SELECT 1 FROM signature_fit_selections WHERE preparation_id=OLD.id) AND NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'selected fit preparation is immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
  (OLD.status='staging' AND NEW.status IN('prepared','abandoned')) OR
  (OLD.status='prepared' AND NEW.status='abandoned') OR
  (OLD.status='abandoned' AND NEW.status='cleaning') OR
  (OLD.status='cleaning' AND NEW.status='cleaned')) THEN
  RAISE EXCEPTION 'fit preparation state cannot move backwards' USING ERRCODE='23514';
 END IF;
 IF NEW.selection_commit_attempted_at IS DISTINCT FROM OLD.selection_commit_attempted_at
    AND (OLD.status<>'prepared' OR NEW.status<>'prepared' OR OLD.selection_not_committed_at IS NOT NULL) THEN
  RAISE EXCEPTION 'fit selection attempt requires prepared pins' USING ERRCODE='23514';
 END IF;
 IF NEW.selection_not_committed_at IS DISTINCT FROM OLD.selection_not_committed_at
    AND (OLD.status<>'prepared' OR NEW.status<>'prepared') THEN
  RAISE EXCEPTION 'fit selection reconciliation requires prepared inventory' USING ERRCODE='23514';
 END IF;
 IF NEW.status IN('abandoned','cleaning','cleaned')
    AND NEW.selection_commit_attempted_at IS NOT NULL AND NEW.selection_not_committed_at IS NULL THEN
  RAISE EXCEPTION 'unknown fit selection commit must be reconciled before cleanup' USING ERRCODE='23514';
 END IF;
 IF NEW.status='prepared' AND OLD.status='staging' THEN
  SELECT count(*),COALESCE(sum(bytes),0) INTO count_objects,total_objects FROM signature_fit_objects WHERE preparation_id=NEW.id;
  -- Reserve a bounded ceiling before nondeterministic renderer/provider IO.
  -- Unused capacity stays reserved; every exact object pin/readback is required.
  IF count_objects<>NEW.expected_objects OR total_objects>NEW.reserved_bytes
     OR (SELECT count(*) FROM signature_fit_objects WHERE preparation_id=NEW.id AND kind='span')<>1
     OR (SELECT count(*) FROM signature_fit_objects WHERE preparation_id=NEW.id AND kind='manifest')<>1
     OR (SELECT count(*) FROM signature_fit_objects WHERE preparation_id=NEW.id AND kind='page') NOT BETWEEN 1 AND 500
     OR EXISTS(SELECT 1 FROM signature_fit_objects WHERE preparation_id=NEW.id AND (version_id IS NULL OR readback_verified_at IS NULL OR cleanup_completed_at IS NOT NULL))
     OR NOT EXISTS(SELECT 1 FROM signature_fit_objects WHERE preparation_id=NEW.id AND kind='span' AND sha256=NEW.span_sha256) THEN
   RAISE EXCEPTION 'fit prepared state requires every exact readback pin' USING ERRCODE='23514';
  END IF;
 END IF;
 IF NEW.status='cleaning' AND EXISTS(SELECT 1 FROM signature_fit_objects WHERE preparation_id=NEW.id AND upload_attempted_at IS NOT NULL AND version_id IS NULL) THEN
  RAISE EXCEPTION 'unknown fit upload outcome must be reconciled before cleanup' USING ERRCODE='23514';
 END IF;
 IF NEW.status='cleaned' AND OLD.status='cleaning' THEN
  IF EXISTS(SELECT 1 FROM signature_fit_objects WHERE preparation_id=NEW.id AND cleanup_completed_at IS NULL) THEN
   RAISE EXCEPTION 'fit cleanup requires every owned object checkpoint' USING ERRCODE='23514';
  END IF;
  UPDATE documents SET signature_fit_reserved_bytes=signature_fit_reserved_bytes-NEW.reserved_bytes
   WHERE id=NEW.document_id AND org_id=NEW.org_id AND signature_fit_reserved_bytes>=NEW.reserved_bytes;
  IF NOT FOUND THEN RAISE EXCEPTION 'fit document reservation counter is inconsistent' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'fit preparation parent is missing' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER signature_fit_preparation_guard BEFORE INSERT OR UPDATE OR DELETE ON signature_fit_preparations FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_preparation_guard();

CREATE FUNCTION hash_signature_fit_budget_check() RETURNS trigger AS $$
DECLARE target UUID; actual BIGINT; expected BIGINT;
BEGIN
 IF TG_TABLE_NAME='documents' THEN target:=NEW.id; ELSE target:=NEW.document_id; END IF;
 SELECT signature_fit_reserved_bytes INTO actual FROM documents WHERE id=target;
 SELECT COALESCE(sum(reserved_bytes),0) INTO expected FROM signature_fit_preparations WHERE document_id=target AND status<>'cleaned';
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'fit document reservation inventory does not match counter' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER signature_fit_budget_document AFTER INSERT OR UPDATE ON documents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_budget_check();
CREATE CONSTRAINT TRIGGER signature_fit_budget_preparation AFTER INSERT OR UPDATE ON signature_fit_preparations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_budget_check();

CREATE FUNCTION hash_signature_fit_object_guard() RETURNS trigger AS $$
DECLARE p signature_fit_preparations%ROWTYPE; d UUID; canonical_key TEXT; n BIGINT; total BIGINT;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'fit object inventory cannot be silently discarded' USING ERRCODE='23514'; END IF;
 SELECT document_id INTO STRICT d FROM signature_fit_preparations WHERE id=NEW.preparation_id;
 PERFORM 1 FROM documents WHERE id=d FOR UPDATE;
 SELECT * INTO STRICT p FROM signature_fit_preparations WHERE id=NEW.preparation_id FOR UPDATE;
 canonical_key:='org/'||p.org_id::text||'/documents/'||p.document_id::text||'/signatures/fit/'||p.id::text||'/'||
  CASE NEW.kind WHEN 'span' THEN 'span.html' WHEN 'manifest' THEN 'manifest.json' ELSE 'page-'||NEW.page::text||'.fit' END;
 IF NEW.storage_key IS DISTINCT FROM canonical_key THEN RAISE EXCEPTION 'fit object key is outside its owned namespace' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM signature_fit_selections WHERE preparation_id=p.id) THEN
  RAISE EXCEPTION 'selected fit object inventory is immutable' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
  IF p.status<>'staging' OR p.lease_until<=clock_timestamp() OR NEW.upload_attempted_at IS NOT NULL OR NEW.version_id IS NOT NULL
     OR NEW.upload_owner_id IS NOT NULL OR NEW.readback_verified_at IS NOT NULL OR NEW.cleanup_completed_at IS NOT NULL THEN
   RAISE EXCEPTION 'fit object must be reserved before upload' USING ERRCODE='23514';
  END IF;
  SELECT count(*),COALESCE(sum(bytes),0) INTO n,total FROM signature_fit_objects WHERE preparation_id=p.id;
  IF n>=p.expected_objects OR total+NEW.bytes>p.reserved_bytes THEN
   RAISE EXCEPTION 'fit object reservation exceeds operation budget' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['upload_attempted_at','upload_owner_id','version_id','readback_verified_at','cleanup_completed_at'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['upload_attempted_at','upload_owner_id','version_id','readback_verified_at','cleanup_completed_at'])
    OR (OLD.upload_attempted_at IS NOT NULL AND NEW.upload_attempted_at IS DISTINCT FROM OLD.upload_attempted_at)
    OR (OLD.upload_owner_id IS NOT NULL AND NEW.upload_owner_id IS DISTINCT FROM OLD.upload_owner_id)
    OR (OLD.version_id IS NOT NULL AND NEW.version_id IS DISTINCT FROM OLD.version_id)
    OR (OLD.readback_verified_at IS NOT NULL AND NEW.readback_verified_at IS DISTINCT FROM OLD.readback_verified_at)
    OR (OLD.cleanup_completed_at IS NOT NULL AND NEW.cleanup_completed_at IS DISTINCT FROM OLD.cleanup_completed_at) THEN
  RAISE EXCEPTION 'fit object identity or checkpoint is immutable' USING ERRCODE='23514';
 END IF;
 IF NEW.version_id IS DISTINCT FROM OLD.version_id AND OLD.upload_attempted_at IS NULL THEN
  RAISE EXCEPTION 'fit version pin requires an earlier durable upload attempt' USING ERRCODE='23514';
 END IF;
 IF NEW.readback_verified_at IS DISTINCT FROM OLD.readback_verified_at AND OLD.version_id IS NULL THEN
  RAISE EXCEPTION 'fit readback requires an earlier durable exact version pin' USING ERRCODE='23514';
 END IF;
 IF NEW.upload_attempted_at IS DISTINCT FROM OLD.upload_attempted_at AND NEW.upload_owner_id IS DISTINCT FROM p.owner_id THEN
  RAISE EXCEPTION 'fit upload attempt must record its original operation owner' USING ERRCODE='23514';
 END IF;
 IF NEW.cleanup_completed_at IS DISTINCT FROM OLD.cleanup_completed_at THEN
  IF p.status<>'cleaning' OR (to_jsonb(NEW)-'cleanup_completed_at') IS DISTINCT FROM (to_jsonb(OLD)-'cleanup_completed_at') THEN
   RAISE EXCEPTION 'fit object cleanup requires reconciled cleaning operation' USING ERRCODE='23514';
  END IF;
 ELSE
  IF p.status NOT IN('staging','abandoned') OR p.lease_until<=clock_timestamp() OR OLD.cleanup_completed_at IS NOT NULL
     OR (p.status='abandoned' AND NEW.upload_attempted_at IS DISTINCT FROM OLD.upload_attempted_at) THEN
   RAISE EXCEPTION 'fit upload checkpoint requires current staging lease' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'fit object operation is missing' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER signature_fit_object_guard BEFORE INSERT OR UPDATE OR DELETE ON signature_fit_objects FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_object_guard();

CREATE FUNCTION hash_signature_fit_selection_guard() RETURNS trigger AS $$
DECLARE p signature_fit_preparations%ROWTYPE; sp signature_fit_objects%ROWTYPE; mf signature_fit_objects%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'selected fit evidence cannot be discarded' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['retention_started_at','retention_completed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['retention_started_at','retention_completed_at'])
     OR (OLD.retention_started_at IS NOT NULL AND NEW.retention_started_at IS DISTINCT FROM OLD.retention_started_at)
     OR (OLD.retention_completed_at IS NOT NULL AND NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at) THEN
   RAISE EXCEPTION 'selected fit pins or retention checkpoints are immutable' USING ERRCODE='23514';
  END IF;
  IF NEW.retention_completed_at IS DISTINCT FROM OLD.retention_completed_at AND OLD.retention_started_at IS NULL THEN
   RAISE EXCEPTION 'fit retention completion requires an earlier durable start' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 -- Every selecting/reconciling query acquires document -> recipient -> prep.
 PERFORM 1 FROM documents WHERE id=NEW.document_id AND org_id=NEW.org_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'fit selection document is foreign' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM recipients WHERE id=NEW.recipient_id AND document_id=NEW.document_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'fit selection recipient is foreign' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT p FROM signature_fit_preparations WHERE id=NEW.preparation_id FOR UPDATE;
 SELECT * INTO STRICT sp FROM signature_fit_objects WHERE preparation_id=p.id AND kind='span' AND page=0;
 SELECT * INTO STRICT mf FROM signature_fit_objects WHERE preparation_id=p.id AND kind='manifest' AND page=0;
 IF p.status<>'prepared' OR p.selection_commit_attempted_at IS NULL OR p.selection_not_committed_at IS NOT NULL
    OR ROW(NEW.org_id,NEW.document_id,NEW.recipient_id,NEW.ceremony_epoch,NEW.authority_sha256,NEW.source_storage_key,NEW.source_version_id,NEW.source_sha256,NEW.source_bytes,NEW.geometry_sha256,NEW.span_sha256)
       IS DISTINCT FROM ROW(p.org_id,p.document_id,p.recipient_id,p.ceremony_epoch,p.authority_sha256,p.source_storage_key,p.source_version_id,p.source_sha256,p.source_bytes,p.geometry_sha256,p.span_sha256)
    OR ROW(NEW.span_storage_key,NEW.span_version_id,NEW.span_sha256,NEW.span_bytes)
       IS DISTINCT FROM ROW(sp.storage_key,sp.version_id,sp.sha256,sp.bytes)
    OR ROW(NEW.manifest_storage_key,NEW.manifest_version_id,NEW.manifest_sha256,NEW.manifest_bytes)
       IS DISTINCT FROM ROW(mf.storage_key,mf.version_id,mf.sha256,mf.bytes)
    OR sp.readback_verified_at IS NULL OR mf.readback_verified_at IS NULL
    OR NEW.retention_started_at IS NOT NULL OR NEW.retention_completed_at IS NOT NULL THEN
  RAISE EXCEPTION 'fit selection does not bind exact prepared pins' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'fit selection exact preparation is missing' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER signature_fit_selection_guard BEFORE INSERT OR UPDATE OR DELETE ON signature_fit_selections FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_selection_guard();

CREATE FUNCTION hash_signature_fit_companion_immutable() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'fit signature companion is immutable' USING ERRCODE='23514'; END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER signature_fit_companion_immutable BEFORE UPDATE OR DELETE ON signature_fit_companions FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_companion_immutable();

CREATE FUNCTION hash_signature_fit_signature_immutable() RETURNS trigger AS $$
BEGIN
 IF OLD.signature_kind='manual_pdf_fit_v1' THEN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'fitted signature is retained' USING ERRCODE='23514'; END IF;
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'fitted signature is immutable' USING ERRCODE='23514'; END IF;
 ELSIF TG_OP='UPDATE' AND NEW.signature_kind='manual_pdf_fit_v1' THEN
  RAISE EXCEPTION 'legacy signatures cannot be retrofitted' USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER signature_fit_signature_immutable BEFORE UPDATE OR DELETE ON signatures FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_signature_immutable();

CREATE FUNCTION hash_signature_fit_pair_check() RETURNS trigger AS $$
DECLARE sid UUID; s signatures%ROWTYPE; c signature_fit_companions%ROWTYPE; x signature_fit_selections%ROWTYPE; org UUID;
BEGIN
 IF TG_TABLE_NAME='signatures' THEN sid:=NEW.id; ELSE sid:=NEW.signature_id; END IF;
 SELECT * INTO STRICT s FROM signatures WHERE id=sid;
 SELECT * INTO c FROM signature_fit_companions WHERE signature_id=sid;
 IF s.signature_kind<>'manual_pdf_fit_v1' THEN
  IF FOUND THEN RAISE EXCEPTION 'only fitted signatures may have a fit companion' USING ERRCODE='23514'; END IF;
  RETURN NULL;
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'fitted signature requires its exact retained companion' USING ERRCODE='23514'; END IF;
 SELECT org_id INTO STRICT org FROM documents WHERE id=s.document_id;
 SELECT * INTO STRICT x FROM signature_fit_selections WHERE id=c.selection_id;
 IF ROW(c.org_id,c.document_id,c.recipient_id,c.field_id,c.span_sha256)
       IS DISTINCT FROM ROW(org,s.document_id,s.recipient_id,s.field_id,s.image_sha256)
    OR ROW(x.org_id,x.document_id,x.recipient_id,x.span_storage_key,x.span_version_id,x.span_sha256)
       IS DISTINCT FROM ROW(org,s.document_id,s.recipient_id,s.image_storage_key,s.image_version_id,s.image_sha256)
    OR x.retention_started_at IS NULL OR x.retention_completed_at IS NULL OR NOT s.image_version_pin_required
    OR s.presign_execution_id IS NOT NULL
    OR NOT EXISTS(SELECT 1 FROM document_fields f WHERE f.id=s.field_id AND f.document_id=s.document_id AND f.recipient_id=s.recipient_id AND f.type='signature' AND f.required) THEN
  RAISE EXCEPTION 'fitted signature companion or original retained span differs' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
EXCEPTION WHEN NO_DATA_FOUND THEN RAISE EXCEPTION 'fitted signature retained lineage is missing' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER signature_fit_pair_signature AFTER INSERT OR UPDATE ON signatures DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_pair_check();
CREATE CONSTRAINT TRIGGER signature_fit_pair_companion AFTER INSERT ON signature_fit_companions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signature_fit_pair_check();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM signature_fit_preparations) OR EXISTS(SELECT 1 FROM signature_fit_objects)
    OR EXISTS(SELECT 1 FROM signature_fit_selections) OR EXISTS(SELECT 1 FROM signature_fit_companions)
    OR EXISTS(SELECT 1 FROM signatures WHERE signature_kind='manual_pdf_fit_v1') THEN
  RAISE EXCEPTION 'cannot discard fit inventory or retained signature evidence';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER signature_fit_pair_companion ON signature_fit_companions;
DROP TRIGGER signature_fit_pair_signature ON signatures;
DROP TRIGGER signature_fit_signature_immutable ON signatures;
DROP TRIGGER signature_fit_companion_immutable ON signature_fit_companions;
DROP TRIGGER signature_fit_selection_guard ON signature_fit_selections;
DROP TRIGGER signature_fit_object_guard ON signature_fit_objects;
DROP TRIGGER signature_fit_budget_preparation ON signature_fit_preparations;
DROP TRIGGER signature_fit_budget_document ON documents;
DROP TRIGGER signature_fit_preparation_guard ON signature_fit_preparations;
DROP FUNCTION hash_signature_fit_pair_check();
DROP FUNCTION hash_signature_fit_signature_immutable();
DROP FUNCTION hash_signature_fit_companion_immutable();
DROP FUNCTION hash_signature_fit_selection_guard();
DROP FUNCTION hash_signature_fit_object_guard();
DROP FUNCTION hash_signature_fit_budget_check();
DROP FUNCTION hash_signature_fit_preparation_guard();
DROP TABLE signature_fit_companions,signature_fit_selections,signature_fit_objects,signature_fit_preparations;
DROP FUNCTION hash_signature_fit_version_valid(TEXT);
ALTER TABLE documents DROP COLUMN signature_fit_reserved_bytes;
ALTER TABLE recipients DROP CONSTRAINT recipients_fit_document_identity;
ALTER TABLE signatures DROP CONSTRAINT signatures_presign_kind_pair;
ALTER TABLE signatures ADD CONSTRAINT signatures_presign_kind_pair CHECK (
 (signature_kind='manual' AND presign_execution_id IS NULL)
 OR (signature_kind='delegated_grant_v1' AND presign_execution_id IS NOT NULL
     AND signer_ip IS NULL AND signer_ua IS NULL AND image_version_pin_required
     AND image_version_id IS NOT NULL));
ALTER TABLE signatures DROP CONSTRAINT signatures_signature_kind_check;
ALTER TABLE signatures ADD CONSTRAINT signatures_signature_kind_check CHECK(signature_kind IN('manual','delegated_grant_v1'));
