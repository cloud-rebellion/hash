-- +goose Up
-- Select a report variant at the genuine native finalization freeze. Metadata
-- defaults label old rows V1 without UPDATE or M111 clock movement. Existing
-- finalizing even without ordinary preparation retains its original V1 pin.
LOCK TABLE public.documents,public.document_ordinary_finalization_preparations_v1,public.document_participant_reports_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
ALTER TABLE public.documents ADD COLUMN participant_report_schema TEXT NOT NULL DEFAULT 'hash-participant-report-v1'
 CONSTRAINT documents_participant_report_schema_check CHECK(participant_report_schema IN ('hash-participant-report-v1','hash-participant-report-v2'));
ALTER TABLE public.documents ALTER COLUMN participant_report_schema SET DEFAULT 'hash-participant-report-v2';
ALTER TABLE public.document_ordinary_finalization_preparations_v1 ADD COLUMN report_schema TEXT NOT NULL DEFAULT 'hash-participant-report-v1'
 CONSTRAINT ordinary_finalization_report_schema_check CHECK(report_schema IN ('hash-participant-report-v1','hash-participant-report-v2'));
-- A fresh capture must explicitly copy the locked document pin. An old worker
-- omitting this field cannot accidentally freeze a V1 certificate for V2.
ALTER TABLE public.document_ordinary_finalization_preparations_v1 ALTER COLUMN report_schema DROP DEFAULT;
ALTER TABLE public.document_participant_reports_v1 DROP CONSTRAINT document_participant_reports_v1_schema_version_check;
ALTER TABLE public.document_participant_reports_v1 ADD CONSTRAINT document_participant_reports_v1_schema_version_check
 CHECK(schema_version IN ('hash-participant-report-v1','hash-participant-report-v2'));

-- Only new schema guards are added. All M108/M109 receipt/intent/completion/
-- delivery/immutability/retention checks and the M111 clock remain installed.
-- +goose StatementBegin
CREATE FUNCTION public.hash_guard_document_report_schema_v2() RETURNS trigger
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
CREATE TRIGGER participant_report_schema_document_v2 BEFORE INSERT OR UPDATE ON public.documents
 FOR EACH ROW EXECUTE FUNCTION public.hash_guard_document_report_schema_v2();

CREATE FUNCTION public.hash_guard_ordinary_report_schema_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_schema TEXT;
BEGIN
 SELECT d.participant_report_schema INTO STRICT actual_schema FROM public.documents d
  WHERE d.id=NEW.document_id AND d.org_id=NEW.org_id FOR UPDATE OF d;
 IF NEW.report_schema IS DISTINCT FROM actual_schema THEN
  RAISE EXCEPTION 'ordinary participant report selection differs from document' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.report_schema IS DISTINCT FROM OLD.report_schema THEN
   RAISE EXCEPTION 'ordinary participant report selection is immutable' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER ordinary_report_schema_v2 BEFORE INSERT OR UPDATE ON public.document_ordinary_finalization_preparations_v1
 FOR EACH ROW EXECUTE FUNCTION public.hash_guard_ordinary_report_schema_v2();

CREATE FUNCTION public.hash_guard_participant_receipt_schema_v2() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_schema TEXT;preparation_schema TEXT;
BEGIN
 SELECT d.participant_report_schema INTO STRICT actual_schema FROM public.documents d
  WHERE d.id=NEW.document_id AND d.org_id=NEW.org_id FOR UPDATE OF d;
 IF NEW.schema_version IS DISTINCT FROM actual_schema THEN
  RAISE EXCEPTION 'participant report receipt selection differs from frozen document' USING ERRCODE='23514';
 END IF;
 SELECT p.report_schema INTO preparation_schema FROM public.document_ordinary_finalization_preparations_v1 p
  WHERE p.document_id=NEW.document_id AND p.org_id=NEW.org_id;
 IF FOUND AND NEW.schema_version IS DISTINCT FROM preparation_schema THEN
  RAISE EXCEPTION 'participant report receipt selection differs from retained preparation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER participant_report_receipt_schema_v2 BEFORE INSERT ON public.document_participant_reports_v1
 FOR EACH ROW EXECUTE FUNCTION public.hash_guard_participant_receipt_schema_v2();
-- +goose StatementEnd

-- +goose Down
-- Draft-only default metadata is not a report commitment. Refuse every retained
-- V2 preparation/receipt and any V2 legal completion clock, including voided
-- ceremonies. No signed artifact, row or clock is rewritten/relabelled.
LOCK TABLE public.documents,public.document_ordinary_finalization_preparations_v1,public.document_participant_reports_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.document_ordinary_finalization_preparations_v1 WHERE report_schema='hash-participant-report-v2')
 OR EXISTS(SELECT 1 FROM public.document_participant_reports_v1 WHERE schema_version='hash-participant-report-v2')
 OR EXISTS(SELECT 1 FROM public.documents WHERE participant_report_schema='hash-participant-report-v2'
  AND (completion_effective_at IS NOT NULL OR completed_at IS NOT NULL OR finalization_retain_until IS NOT NULL OR status IN ('finalizing','completed'))) THEN
  RAISE EXCEPTION 'retained participant report V2 commitments prevent rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER participant_report_receipt_schema_v2 ON public.document_participant_reports_v1;
DROP TRIGGER ordinary_report_schema_v2 ON public.document_ordinary_finalization_preparations_v1;
DROP TRIGGER participant_report_schema_document_v2 ON public.documents;
DROP FUNCTION public.hash_guard_participant_receipt_schema_v2(),public.hash_guard_ordinary_report_schema_v2(),public.hash_guard_document_report_schema_v2();
ALTER TABLE public.document_participant_reports_v1 DROP CONSTRAINT document_participant_reports_v1_schema_version_check;
ALTER TABLE public.document_participant_reports_v1 ADD CONSTRAINT document_participant_reports_v1_schema_version_check CHECK(schema_version='hash-participant-report-v1');
ALTER TABLE public.document_ordinary_finalization_preparations_v1 DROP COLUMN report_schema;
ALTER TABLE public.documents DROP COLUMN participant_report_schema;
