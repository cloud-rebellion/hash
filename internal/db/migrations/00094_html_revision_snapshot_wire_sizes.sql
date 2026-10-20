-- SOURCE-ONLY FOUNDATION; no historical measurement/backfill or activation.
-- Actual owned producers must acquire their work loan BEFORE these measurements.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('server_encoding') <> 'UTF8' THEN
  RAISE EXCEPTION 'HTML snapshot sizing requires UTF8' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
-- Refuse a concurrent old writer instead of waiting through a DDL/source lock inversion.
LOCK TABLE documents,events IN EXCLUSIVE MODE NOWAIT;
CREATE TABLE html_snapshot_event_payload_sizes_v1 (
 event_id UUID PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
 document_id UUID NOT NULL,
 org_id UUID NOT NULL,
 payload_wire_bytes BIGINT NOT NULL CHECK(payload_wire_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at))
);
CREATE TABLE html_revision_snapshot_sizes_v1 (
 snapshot_id UUID PRIMARY KEY REFERENCES html_document_materialization_snapshots(id) ON DELETE CASCADE,
 document_id UUID NOT NULL,
 org_id UUID NOT NULL,
 source_wire_bytes BIGINT NOT NULL CHECK(source_wire_bytes>=0),
 fields_wire_bytes BIGINT NOT NULL CHECK(fields_wire_bytes>=0),
 recipients_wire_bytes BIGINT NOT NULL CHECK(recipients_wire_bytes>=0),
 notice_wire_bytes BIGINT NOT NULL CHECK(notice_wire_bytes>=0),
 ceremony_events_wire_bytes BIGINT NOT NULL CHECK(ceremony_events_wire_bytes>=0),
 report_wire_bytes BIGINT NOT NULL CHECK(report_wire_bytes>=0),
 raw_text_bytes BIGINT NOT NULL CHECK(raw_text_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at))
);
CREATE INDEX html_snapshot_event_sizes_scope_v1 ON html_snapshot_event_payload_sizes_v1(document_id,org_id,event_id);
CREATE INDEX html_revision_snapshot_sizes_scope_v1 ON html_revision_snapshot_sizes_v1(document_id,org_id,snapshot_id);
-- A fixed UUID subject fence covers the COMPLETE M74 event set, which is
-- keyed by document_id alone (M43 retains subject UUIDs without document FK).
-- Every reverse-order caller uses TRY, never waits chain -> subject -> parent.
-- Hash collisions conservatively refuse/serialize; no source/tenant authority
-- is derived from the hash. The prefix separates the semantic key domain.
-- +goose StatementBegin
CREATE FUNCTION hash_lock_html_snapshot_subject_v1(target_document_id UUID) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
BEGIN
 IF target_document_id IS NULL THEN RETURN;END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('hash-html-snapshot-subject-v1:'||target_document_id::text,0)) THEN
  RAISE EXCEPTION 'HTML snapshot subject is busy' USING ERRCODE='55P03';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION hash_fence_html_snapshot_document_identity_v1() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE target_document UUID;subjects UUID[];
BEGIN
 IF TG_OP='DELETE' THEN subjects:=ARRAY[OLD.id];
 ELSIF TG_OP='UPDATE' THEN subjects:=ARRAY[OLD.id,NEW.id];
 ELSE subjects:=ARRAY[NEW.id];END IF;
 FOR target_document IN SELECT DISTINCT v FROM unnest(subjects)v WHERE v IS NOT NULL ORDER BY v LOOP
  PERFORM hash_lock_html_snapshot_subject_v1(target_document);
 END LOOP;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- Birth/reuse/move/delete of a UUID cannot race an orphan-subject event into
-- a newly active collection. This does not forbid existing identity changes
-- or remove/retarget retained audit subjects; contention is visible 55P03.
CREATE TRIGGER aa_html_snapshot_document_identity_fence_v1 BEFORE INSERT OR UPDATE OF id,org_id OR DELETE
 ON documents FOR EACH ROW EXECUTE FUNCTION hash_fence_html_snapshot_document_identity_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_fence_html_snapshot_event_set_v1() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE target_org UUID;targets UUID[];target_document UUID;subjects UUID[];
BEGIN
 -- The existing audit appender already holds this SAME advisory lock. Never
 -- acquire a document parent here: normal order is document -> org chain.
 -- A genuine org CASCADE reaches this BEFORE DELETE after the org is absent
 -- to its own transaction. It must not retain chain -> later document edges.
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM orgs WHERE id=OLD.org_id) THEN targets:=ARRAY[OLD.org_id];
  ELSE targets:=ARRAY[]::UUID[];END IF;
  subjects:=ARRAY[OLD.document_id];
 ELSIF TG_OP='UPDATE' THEN
  targets:=ARRAY[OLD.org_id,NEW.org_id];subjects:=ARRAY[OLD.document_id,NEW.document_id];
 ELSE targets:=ARRAY[NEW.org_id];subjects:=ARRAY[NEW.document_id];END IF;
 FOR target_org IN SELECT DISTINCT v FROM unnest(targets) v WHERE v IS NOT NULL ORDER BY v LOOP
  PERFORM pg_advisory_xact_lock(hashtextextended(target_org::text,0));
 END LOOP;
 -- Even the genuine org-cascade exception retains the UUID TRY fence.
 -- No parent row is acquired and reverse ordering can only refuse.
 FOR target_document IN SELECT DISTINCT v FROM unnest(subjects)v WHERE v IS NOT NULL ORDER BY v LOOP
  PERFORM hash_lock_html_snapshot_subject_v1(target_document);
 END LOOP;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- Alphabetical BEFORE-trigger ordering puts the chain fence before cache
-- invalidation; no source JSON or row body is expanded by either cheap hook.
CREATE TRIGGER aa_html_snapshot_event_set_fence_v1 BEFORE INSERT OR UPDATE OR DELETE
 ON events FOR EACH ROW EXECUTE FUNCTION hash_fence_html_snapshot_event_set_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_invalidate_html_snapshot_event_size_v1() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 DELETE FROM html_snapshot_event_payload_sizes_v1 WHERE event_id=OLD.id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_html_snapshot_event_size_v1 BEFORE UPDATE OF id,org_id,document_id,payload_json
 ON events FOR EACH ROW EXECUTE FUNCTION hash_invalidate_html_snapshot_event_size_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_derive_html_snapshot_event_size_v1() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_org UUID;actual_document UUID;payload JSONB;
BEGIN
 IF NEW.event_id IS NULL OR NEW.document_id IS NULL OR NEW.org_id IS NULL THEN
  RAISE EXCEPTION 'HTML event size scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.event_id IS DISTINCT FROM OLD.event_id THEN
  RAISE EXCEPTION 'HTML event size identity is immutable' USING ERRCODE='23514';
 END IF;
 -- No parent document is acquired after this chain lock. Actual producer
 -- owns its fresh event and original context; caller sizes are never trusted.
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.org_id::text,0));
 SELECT e.org_id,e.document_id INTO STRICT actual_org,actual_document
  FROM events e WHERE e.id=NEW.event_id FOR SHARE OF e NOWAIT;
 IF actual_org IS DISTINCT FROM NEW.org_id OR actual_document IS DISTINCT FROM NEW.document_id THEN
  RAISE EXCEPTION 'HTML event size scope differs' USING ERRCODE='23514';
 END IF;
 SELECT e.payload_json INTO STRICT payload FROM events e WHERE e.id=NEW.event_id;
 -- This is a real expanded measurement, only after a genuine producer loan.
 NEW.payload_wire_bytes:=COALESCE(octet_length(payload::text)::bigint,0);
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'HTML event size source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_html_snapshot_event_size_v1 BEFORE INSERT OR UPDATE
 ON html_snapshot_event_payload_sizes_v1 FOR EACH ROW EXECUTE FUNCTION hash_derive_html_snapshot_event_size_v1();
-- +goose StatementBegin
CREATE FUNCTION hash_derive_html_revision_snapshot_size_v1() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_org UUID;actual_document UUID;s html_document_materialization_snapshots%ROWTYPE;
BEGIN
 IF NEW.snapshot_id IS NULL OR NEW.document_id IS NULL OR NEW.org_id IS NULL THEN
  RAISE EXCEPTION 'HTML snapshot size scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.snapshot_id IS DISTINCT FROM OLD.snapshot_id THEN
  RAISE EXCEPTION 'HTML snapshot size identity is immutable' USING ERRCODE='23514';
 END IF;
 -- Same immutable parent order as the genuine capture/append producer.
 PERFORM 1 FROM documents d WHERE d.id=NEW.document_id AND d.org_id=NEW.org_id FOR UPDATE OF d NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'HTML snapshot size parent missing' USING ERRCODE='23514';END IF;
 SELECT h.org_id,h.document_id INTO STRICT actual_org,actual_document
  FROM html_document_materialization_snapshots h WHERE h.id=NEW.snapshot_id FOR SHARE OF h NOWAIT;
 IF actual_org IS DISTINCT FROM NEW.org_id OR actual_document IS DISTINCT FROM NEW.document_id THEN
  RAISE EXCEPTION 'HTML snapshot size scope differs' USING ERRCODE='23514';
 END IF;
 -- Immutable source. The owned capture work allowance precedes this expanded
 -- six-JSON measurement. No source update can refresh it automatically.
 SELECT * INTO STRICT s FROM html_document_materialization_snapshots WHERE id=NEW.snapshot_id;
 NEW.source_wire_bytes:=COALESCE(octet_length(s.source_json::text)::bigint,0);
 NEW.fields_wire_bytes:=COALESCE(octet_length(s.fields_json::text)::bigint,0);
 NEW.recipients_wire_bytes:=COALESCE(octet_length(s.recipients_json::text)::bigint,0);
 NEW.notice_wire_bytes:=COALESCE(octet_length(s.notice_context_json::text)::bigint,0);
 NEW.ceremony_events_wire_bytes:=COALESCE(octet_length(s.ceremony_events_json::text)::bigint,0);
 NEW.report_wire_bytes:=COALESCE(octet_length(s.metadata_redaction_report::text)::bigint,0);
 NEW.raw_text_bytes:=(octet_length(s.kind)::numeric+octet_length(s.source_commitment)
  +octet_length(s.pdf_key)+octet_length(s.pdf_sha256)+octet_length(s.pdf_version_id)
  +COALESCE(octet_length(s.rendered_pdf_key),0)+COALESCE(octet_length(s.rendered_pdf_sha256),0)
  +COALESCE(octet_length(s.rendered_pdf_version_id),0)+COALESCE(octet_length(s.reviewed_pdf_sha256),0))::bigint;
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'HTML snapshot size source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_html_revision_snapshot_size_v1 BEFORE INSERT OR UPDATE
 ON html_revision_snapshot_sizes_v1 FOR EACH ROW EXECUTE FUNCTION hash_derive_html_revision_snapshot_size_v1();
-- +goose Down
-- Empty-only foundation rollback never silently discards admitted cache debt.
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE documents,events,html_document_materialization_snapshots,html_snapshot_event_payload_sizes_v1,html_revision_snapshot_sizes_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM html_snapshot_event_payload_sizes_v1) OR EXISTS(SELECT 1 FROM html_revision_snapshot_sizes_v1) THEN
  RAISE EXCEPTION 'HTML snapshot sizes require reviewed disposition before rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER derive_html_revision_snapshot_size_v1 ON html_revision_snapshot_sizes_v1;
DROP TRIGGER derive_html_snapshot_event_size_v1 ON html_snapshot_event_payload_sizes_v1;
DROP TRIGGER invalidate_html_snapshot_event_size_v1 ON events;
DROP TRIGGER aa_html_snapshot_event_set_fence_v1 ON events;
DROP TRIGGER aa_html_snapshot_document_identity_fence_v1 ON documents;
DROP FUNCTION hash_derive_html_revision_snapshot_size_v1();
DROP FUNCTION hash_derive_html_snapshot_event_size_v1();
DROP FUNCTION hash_invalidate_html_snapshot_event_size_v1();
DROP FUNCTION hash_fence_html_snapshot_event_set_v1();
DROP FUNCTION hash_fence_html_snapshot_document_identity_v1();
DROP FUNCTION hash_lock_html_snapshot_subject_v1(UUID);
DROP TABLE html_revision_snapshot_sizes_v1;
DROP TABLE html_snapshot_event_payload_sizes_v1;
