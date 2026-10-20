-- +goose Up
-- Internal retained intake reports accompany exact selected PDF/source pins.
-- These bytes are PostgreSQL's UTF8 JSONB serialization, not original parser
-- formatting, malware verdicts, signed contractual terms or admission credit.
-- No historical row is expanded/backfilled. Missing legacy proof requires
-- explicit reselection before the owned package workflow can use that row.
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE documents,document_packages_v1,document_attachment_drafts_v1,
  document_package_captures_v1,document_package_capture_members_v1
  IN ACCESS EXCLUSIVE MODE NOWAIT;
END $$;
-- +goose StatementEnd
ALTER TABLE document_attachment_drafts_v1
 ADD COLUMN pdf_intake_report BYTEA,
 ADD COLUMN pdf_intake_report_sha256 BYTEA,
 ADD CONSTRAINT document_attachment_intake_report_v1 CHECK (
  (pdf_intake_report IS NULL AND pdf_intake_report_sha256 IS NULL) OR
  (pdf_intake_report IS NOT NULL AND pdf_intake_report_sha256 IS NOT NULL
   AND octet_length(pdf_intake_report) BETWEEN 1 AND 65536
   AND octet_length(pdf_intake_report_sha256)=32
   AND pdf_intake_report_sha256=sha256(pdf_intake_report)));
ALTER TABLE document_package_capture_members_v1
 ADD COLUMN pdf_intake_report BYTEA,
 ADD COLUMN pdf_intake_report_sha256 BYTEA,
 ADD CONSTRAINT document_package_member_intake_report_v1 CHECK (
  (pdf_intake_report IS NULL AND pdf_intake_report_sha256 IS NULL) OR
  (pdf_intake_report IS NOT NULL AND pdf_intake_report_sha256 IS NOT NULL
   AND octet_length(pdf_intake_report) BETWEEN 1 AND 65536
   AND octet_length(pdf_intake_report_sha256)=32
   AND pdf_intake_report_sha256=sha256(pdf_intake_report)));

-- +goose StatementBegin
CREATE FUNCTION hash_document_package_source_report_v1(target UUID,tenant UUID)
RETURNS BYTEA LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE report JSONB; measured BIGINT; raw BYTEA;
BEGIN
 -- Actual callers already hold sorted source/root locks. Read the report and
 -- its genuine, invalidated-on-change M93 scalar in one MVCC statement, before
 -- text serialization. No missing-cache refresh or historical expansion.
 SELECT d.metadata_redaction_report,r.report_wire_bytes INTO report,measured
 FROM documents d JOIN document_read_report_sizes_v1 r
  ON r.document_id=d.id AND r.org_id=d.org_id
 WHERE d.id=target AND d.org_id=tenant AND d.deleted_at IS NULL
  AND r.measurement_server_version_num=current_setting('server_version_num')::integer
  AND r.report_wire_bytes BETWEEN 1 AND 65536;
 IF NOT FOUND OR jsonb_typeof(report) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'package source intake report is not bounded and measured' USING ERRCODE='23514';
 END IF;
 raw:=convert_to(report::text,'UTF8');
 IF octet_length(raw) IS DISTINCT FROM measured THEN
  RAISE EXCEPTION 'package source intake report size changed' USING ERRCODE='23514';
 END IF;
 RETURN raw;
END $$;

CREATE FUNCTION hash_guard_document_attachment_intake_report_v1()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE raw BYTEA;
BEGIN
 IF TG_OP='UPDATE' THEN
  -- Compare with OLD only: live source changes must not replace old proof,
  -- invalidate a relabel, or backfill a legacy NULL pair.
  IF ROW(NEW.pdf_intake_report,NEW.pdf_intake_report_sha256)
   IS DISTINCT FROM ROW(OLD.pdf_intake_report,OLD.pdf_intake_report_sha256) THEN
   RAISE EXCEPTION 'selected intake report requires explicit replacement' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 raw:=hash_document_package_source_report_v1(NEW.member_document_id,NEW.org_id);
 IF NEW.pdf_intake_report IS NULL AND NEW.pdf_intake_report_sha256 IS NULL THEN
  NEW.pdf_intake_report:=raw;NEW.pdf_intake_report_sha256:=sha256(raw);
 ELSIF NEW.pdf_intake_report IS DISTINCT FROM raw
  OR NEW.pdf_intake_report_sha256 IS DISTINCT FROM sha256(raw) THEN
  RAISE EXCEPTION 'selected intake report differs from actual source' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- Same-kind PostgreSQL triggers run by name: M99 obtains the globally sorted
-- source/root locks first; this guard adds no document lock or source refresh.
CREATE TRIGGER zz_document_attachment_intake_report_guard_v1
 BEFORE INSERT OR UPDATE ON document_attachment_drafts_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_document_attachment_intake_report_v1();

CREATE FUNCTION hash_guard_document_package_member_intake_report_v1()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE expected BYTEA;root UUID;
BEGIN
 IF NEW.member_position=0 THEN
  SELECT document_id INTO STRICT root FROM document_package_captures_v1
   WHERE package_id=NEW.package_id AND revision=NEW.revision AND org_id=NEW.org_id;
  expected:=hash_document_package_source_report_v1(root,NEW.org_id);
 ELSE
  SELECT a.pdf_intake_report INTO expected FROM (
   SELECT row_number() OVER(ORDER BY ordinal)::smallint AS member_position,d.*
   FROM document_attachment_drafts_v1 d WHERE package_id=NEW.package_id AND org_id=NEW.org_id
  ) a WHERE a.member_position=NEW.member_position AND a.member_document_id=NEW.member_document_id;
 END IF;
 IF expected IS NULL OR NEW.pdf_intake_report IS DISTINCT FROM expected
  OR NEW.pdf_intake_report_sha256 IS DISTINCT FROM sha256(expected) THEN
  RAISE EXCEPTION 'captured intake report is missing or differs from frozen selection' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER zz_document_package_member_intake_report_guard_v1
 BEFORE INSERT ON document_package_capture_members_v1
 FOR EACH ROW EXECUTE FUNCTION hash_guard_document_package_member_intake_report_v1();

CREATE OR REPLACE FUNCTION hash_derive_document_package_capture_members_v1()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE main_report BYTEA;
BEGIN
 main_report:=hash_document_package_source_report_v1(NEW.document_id,NEW.org_id);
 -- Explicit targets preserve the M100 legal manifest and its ordered members.
 -- Sparse draft ordinals map to contiguous manifest positions, never live
 -- annex documents or their later metadata reports.
 INSERT INTO document_package_capture_members_v1(
  package_id,revision,org_id,member_position,member_document_id,title,category,
  pdf_key,pdf_version_id,pdf_sha256,pdf_bytes,pdf_pages,source_kind,
  source_commitment,origin_commitment,materialization_id,materialization_sequence,
  pdf_intake_report,pdf_intake_report_sha256)
 SELECT NEW.package_id,NEW.revision,NEW.org_id,
  m.member_position,m.member_document_id,m.title,m.category,m.pdf_key,m.pdf_version_id,m.pdf_sha256,
  m.pdf_bytes,m.pdf_pages,m.source_kind,m.source_commitment,m.origin_commitment,
  m.materialization_id,m.materialization_sequence,
  CASE WHEN m.member_position=0 THEN main_report ELSE a.pdf_intake_report END,
  CASE WHEN m.member_position=0 THEN sha256(main_report) ELSE a.pdf_intake_report_sha256 END
 FROM hash_package_manifest_members_v1(NEW.manifest) m
 LEFT JOIN (
  SELECT row_number() OVER(ORDER BY ordinal)::smallint AS member_position,d.*
  FROM document_attachment_drafts_v1 d WHERE package_id=NEW.package_id AND org_id=NEW.org_id
 ) a ON a.member_position=m.member_position AND a.member_document_id=m.member_document_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Refuse data loss, including proof retained by unsigned captures. Existing
-- legacy NULL rows can roll back without inventing or discarding report bytes.
-- This does not certify old generated wildcard binaries against the new schema.
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE documents,document_packages_v1,document_attachment_drafts_v1,
  document_package_captures_v1,document_package_capture_members_v1
  IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM document_attachment_drafts_v1
    WHERE pdf_intake_report IS NOT NULL OR pdf_intake_report_sha256 IS NOT NULL)
  OR EXISTS(SELECT 1 FROM document_package_capture_members_v1
    WHERE pdf_intake_report IS NOT NULL OR pdf_intake_report_sha256 IS NOT NULL) THEN
  RAISE EXCEPTION 'retained package intake reports prevent rollback' USING ERRCODE='23514';
 END IF;
END $$;
DROP TRIGGER zz_document_package_member_intake_report_guard_v1 ON document_package_capture_members_v1;
DROP FUNCTION hash_guard_document_package_member_intake_report_v1();
DROP TRIGGER zz_document_attachment_intake_report_guard_v1 ON document_attachment_drafts_v1;
DROP FUNCTION hash_guard_document_attachment_intake_report_v1();
-- Restore the original M100 projection before removing the additive columns.
CREATE OR REPLACE FUNCTION hash_derive_document_package_capture_members_v1() RETURNS trigger AS $$
BEGIN
 INSERT INTO document_package_capture_members_v1 SELECT NEW.package_id,NEW.revision,NEW.org_id,m.* FROM hash_package_manifest_members_v1(NEW.manifest) m;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP FUNCTION hash_document_package_source_report_v1(UUID,UUID);
ALTER TABLE document_attachment_drafts_v1
 DROP CONSTRAINT document_attachment_intake_report_v1,
 DROP COLUMN pdf_intake_report,DROP COLUMN pdf_intake_report_sha256;
ALTER TABLE document_package_capture_members_v1
 DROP CONSTRAINT document_package_member_intake_report_v1,
 DROP COLUMN pdf_intake_report,DROP COLUMN pdf_intake_report_sha256;
-- +goose StatementEnd
