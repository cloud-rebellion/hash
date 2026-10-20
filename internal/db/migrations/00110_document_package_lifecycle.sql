-- +goose Up
-- Forward replacement of the temporary M99 dispatch gate. No historical Send,
-- consent or report is backfilled; M103/M105/M106 and M107/M108 remain owners
-- of their respective atomic transitions and immutable evidence.
-- +goose StatementBegin
CREATE FUNCTION hash_package_lifecycle_version_v1() RETURNS INTEGER LANGUAGE sql IMMUTABLE AS $$ SELECT 1; $$;

-- This is a lifetime association, not a replay of initial invitation effects.
-- Recipient status/tokens and mutable mail/display projections legitimately
-- change after Send. M106 already proved those effects at its original commit.
CREATE FUNCTION hash_package_lifecycle_receipt_matches_v1(target UUID,tenant UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 SELECT count(*)=1
 FROM documents d JOIN document_packages_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
 JOIN document_package_send_attempts_v1 a ON a.document_id=d.id AND a.org_id=d.org_id AND a.package_id=p.id
 JOIN document_package_send_completions_v1 c ON c.attempt_id=a.attempt_id AND c.document_id=a.document_id AND c.org_id=a.org_id
 WHERE d.id=target AND d.org_id=tenant AND d.deleted_at IS NULL
  AND a.terminal_outcome='completed' AND a.retention_started_at IS NOT NULL AND a.retention_completed_at IS NOT NULL
  AND a.captured_draft_generation=p.draft_generation AND a.member_count>1
  AND c.manifest_sha256=a.manifest_sha256 AND c.legal_commitment_sha256=a.legal_commitment_sha256
  AND c.article13_notice_epoch_at=a.article13_notice_epoch_at AND c.retain_until=a.retain_until
  AND c.outcome IN ('sent','expired') AND octet_length(c.effect_sha256)=32
  AND d.sent_at=a.article13_notice_epoch_at AND d.article13_notice_epoch_at=a.article13_notice_epoch_at
  AND d.article13_notice_schema='hash-a13-2026-08-31' AND d.article13_notice_epoch_v61_committed
  AND d.evidence_version_pins_required
  AND hash_package_send_main_matches_v1(d.id,d.org_id,a.package_id,a.capture_revision)
  AND hash_package_send_members_retained_v1(a.attempt_id)
  AND NOT EXISTS(SELECT 1 FROM document_package_send_attempts_v1 pending WHERE pending.document_id=d.id AND pending.org_id=d.org_id AND pending.terminal_outcome IS NULL)
  AND NOT EXISTS(SELECT 1 FROM send_sealing_intents i WHERE i.document_id=d.id AND i.org_id=d.org_id);
$$;

CREATE OR REPLACE FUNCTION hash_guard_unhandled_document_package_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE a document_package_send_attempts_v1%ROWTYPE;has_active BOOLEAN;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM document_packages_v1 p JOIN document_attachment_drafts_v1 m ON m.package_id=p.id AND m.org_id=p.org_id
  WHERE p.document_id=OLD.id AND p.org_id=OLD.org_id) THEN RETURN NEW;END IF;
 -- Keep the original topology/source/deletion restrictions at every stage.
 IF NEW.id IS DISTINCT FROM OLD.id OR NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.is_envelope
  OR NEW.parent_envelope_id IS NOT NULL OR NEW.source_kind<>'pdf' OR NEW.deleted_at IS NOT NULL THEN
  RAISE EXCEPTION 'attachment package topology or source is unsupported' USING ERRCODE='23514';END IF;
 IF OLD.status='draft' AND NEW.status='draft' THEN RETURN NEW;END IF;
 -- Captured originals and response rules cannot be edited while changing a
 -- lifecycle state, or by an unrelated UPDATE after dispatch.
 IF ROW(NEW.name,NEW.pdf_storage_key,NEW.pdf_storage_version_id,NEW.pdf_sha256,NEW.html_source_json,
  NEW.html_current_source_json,NEW.html_current_materialization_id,NEW.html_current_materialization_sequence,
  NEW.html_reviewed_pdf_sha256,NEW.html_reviewed_by,NEW.html_reviewed_at,NEW.html_reviewed_materialization_id,
  NEW.requires_signature,NEW.routing_mode,NEW.variables_json,NEW.blocks_json)
 IS DISTINCT FROM ROW(OLD.name,OLD.pdf_storage_key,OLD.pdf_storage_version_id,OLD.pdf_sha256,OLD.html_source_json,
  OLD.html_current_source_json,OLD.html_current_materialization_id,OLD.html_current_materialization_sequence,
  OLD.html_reviewed_pdf_sha256,OLD.html_reviewed_by,OLD.html_reviewed_at,OLD.html_reviewed_materialization_id,
  OLD.requires_signature,OLD.routing_mode,OLD.variables_json,OLD.blocks_json) THEN
  RAISE EXCEPTION 'dispatched package originals or response rules are immutable' USING ERRCODE='23514';END IF;
 SELECT candidate.* INTO a FROM document_package_send_attempts_v1 candidate
 JOIN document_packages_v1 p ON p.id=candidate.package_id AND p.org_id=candidate.org_id AND p.document_id=candidate.document_id
 JOIN send_sealing_intents intent ON intent.package_send_attempt_id=candidate.attempt_id AND intent.org_id=candidate.org_id AND intent.document_id=candidate.document_id
 WHERE candidate.document_id=OLD.id AND candidate.org_id=OLD.org_id AND candidate.terminal_outcome IS NULL
  AND p.draft_generation=candidate.captured_draft_generation AND candidate.member_count>1
  AND ROW(intent.actor_user_id,intent.article13_notice_epoch_at,intent.retain_until,intent.retention_started_at,intent.retention_completed_at)
   IS NOT DISTINCT FROM ROW(candidate.actor_user_id,candidate.article13_notice_epoch_at,candidate.retain_until,candidate.retention_started_at,candidate.retention_completed_at)
  AND intent.presign_execution_id IS NULL
  AND NOT EXISTS(SELECT 1 FROM document_package_captures_v1 newer WHERE newer.package_id=p.id AND newer.revision>candidate.capture_revision)
  AND hash_package_send_main_matches_v1(OLD.id,OLD.org_id,p.id,candidate.capture_revision);
 has_active:=FOUND;
 IF NEW.status='sealing' THEN
  IF OLD.status NOT IN ('draft','sealing') OR NOT has_active
   OR (OLD.status='draft' AND a.captured_root_updated_at IS DISTINCT FROM OLD.updated_at)
   OR ROW(NEW.sent_at,NEW.article13_notice_epoch_at,NEW.article13_notice_schema,NEW.article13_notice_epoch_v61_committed)
    IS DISTINCT FROM ROW(OLD.sent_at,OLD.article13_notice_epoch_at,OLD.article13_notice_schema,OLD.article13_notice_epoch_v61_committed) THEN
   RAISE EXCEPTION 'package sealing requires its current exact capture and intent' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF NEW.status='draft' THEN
  IF OLD.status='sealing' THEN
   IF NOT has_active OR a.retention_started_at IS NOT NULL OR a.retention_completed_at IS NOT NULL THEN
    RAISE EXCEPTION 'retained package cannot return to draft' USING ERRCODE='23514';END IF;
  ELSIF OLD.status='changes_requested' THEN
   IF NOT hash_package_lifecycle_receipt_matches_v1(OLD.id,OLD.org_id)
    OR hash_package_has_signing_evidence_v1(OLD.id,OLD.org_id)
    OR EXISTS(SELECT 1 FROM document_package_responses_v1 r WHERE r.document_id=OLD.id AND r.org_id=OLD.org_id)
    OR EXISTS(SELECT 1 FROM document_participant_reports_v1 r WHERE r.document_id=OLD.id AND r.org_id=OLD.org_id) THEN
    RAISE EXCEPTION 'responded package cannot return to draft' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'package cannot return to draft from this state' USING ERRCODE='23514';END IF;
  IF NEW.sent_at IS NOT NULL OR ROW(NEW.article13_notice_epoch_at,NEW.article13_notice_schema,NEW.article13_notice_epoch_v61_committed)
   IS DISTINCT FROM ROW(OLD.article13_notice_epoch_at,OLD.article13_notice_schema,OLD.article13_notice_epoch_v61_committed) THEN
   RAISE EXCEPTION 'package draft reset must preserve the prior notice epoch' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 -- Native late expiry first allocates sent, then expires it, then records the
 -- M106 receipt in one transaction. The deferred gate sees only that result.
 IF has_active AND ((OLD.status='sealing' AND NEW.status IN ('sent','expired')) OR (OLD.status='sent' AND NEW.status='expired')) THEN
  IF a.retention_started_at IS NULL OR a.retention_completed_at IS NULL OR NOT NEW.evidence_version_pins_required
   OR NEW.sent_at IS DISTINCT FROM a.article13_notice_epoch_at OR NEW.article13_notice_epoch_at IS DISTINCT FROM a.article13_notice_epoch_at
   OR NEW.article13_notice_schema<>'hash-a13-2026-08-31' OR NOT NEW.article13_notice_epoch_v61_committed THEN
   RAISE EXCEPTION 'package Send transition differs from retained exact attempt' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF NOT hash_package_lifecycle_receipt_matches_v1(OLD.id,OLD.org_id)
  OR ROW(NEW.sent_at,NEW.article13_notice_epoch_at,NEW.article13_notice_schema,NEW.article13_notice_epoch_v61_committed,NEW.evidence_version_pins_required)
   IS DISTINCT FROM ROW(OLD.sent_at,OLD.article13_notice_epoch_at,OLD.article13_notice_schema,OLD.article13_notice_epoch_v61_committed,OLD.evidence_version_pins_required)
  OR NOT ((OLD.status IN ('sent','in_progress') AND NEW.status IN ('sent','in_progress','changes_requested','finalizing','declined','voided','expired'))
   OR (OLD.status='changes_requested' AND NEW.status='changes_requested')
   OR (OLD.status='finalizing' AND NEW.status IN ('finalizing','completed'))
   OR (OLD.status IN ('completed','declined','voided','expired') AND NEW.status=OLD.status)) THEN
  RAISE EXCEPTION 'package lifecycle requires its immutable Send receipt and current epoch' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER unhandled_document_package_guard_v1 ON documents;
CREATE TRIGGER unhandled_document_package_guard_v1 BEFORE UPDATE ON documents
 FOR EACH ROW EXECUTE FUNCTION hash_guard_unhandled_document_package_v1();

CREATE FUNCTION hash_require_package_lifecycle_receipt_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE state TEXT;
BEGIN
 SELECT d.status INTO state FROM documents d WHERE d.id=NEW.id AND d.org_id=NEW.org_id
  AND EXISTS(SELECT 1 FROM document_packages_v1 p JOIN document_attachment_drafts_v1 m ON m.package_id=p.id AND m.org_id=p.org_id
   WHERE p.document_id=d.id AND p.org_id=d.org_id);
 IF NOT FOUND OR state IN ('draft','sealing') THEN RETURN NULL;END IF;
 IF NOT hash_package_lifecycle_receipt_matches_v1(NEW.id,NEW.org_id) THEN
  RAISE EXCEPTION 'package lifecycle commit requires an exact completed Send receipt' USING ERRCODE='23514';END IF;
 RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER document_package_lifecycle_receipt_v1 AFTER UPDATE ON documents
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_require_package_lifecycle_receipt_v1();
-- +goose StatementEnd

-- +goose Down
-- A return to the temporary closed gate must not strand a real ceremony or
-- erase the meaning of an already admitted nonempty package Send history.
-- +goose StatementBegin
LOCK TABLE documents,document_packages_v1,document_attachment_drafts_v1,document_package_send_attempts_v1,send_sealing_intents
 IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM document_package_send_attempts_v1 WHERE member_count>1)
  OR EXISTS(SELECT 1 FROM documents d JOIN document_packages_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
   JOIN document_attachment_drafts_v1 m ON m.package_id=p.id AND m.org_id=p.org_id WHERE d.status<>'draft') THEN
  RAISE EXCEPTION 'admitted attachment package history prevents lifecycle rollback' USING ERRCODE='23514';END IF;
END $$;
DROP TRIGGER document_package_lifecycle_receipt_v1 ON documents;
DROP FUNCTION hash_require_package_lifecycle_receipt_v1();
DROP TRIGGER unhandled_document_package_guard_v1 ON documents;
CREATE OR REPLACE FUNCTION hash_guard_unhandled_document_package_v1() RETURNS trigger AS $$
BEGIN
 IF EXISTS (SELECT 1 FROM document_packages_v1 p JOIN document_attachment_drafts_v1 a ON a.package_id=p.id WHERE p.document_id=OLD.id)
  AND (NEW.status <> 'draft' OR NEW.is_envelope OR NEW.parent_envelope_id IS NOT NULL OR NEW.source_kind <> 'pdf' OR NEW.deleted_at IS NOT NULL) THEN
  RAISE EXCEPTION 'attachment package requires package-aware workflow' USING ERRCODE='23514';END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER unhandled_document_package_guard_v1 BEFORE UPDATE OF status,is_envelope,parent_envelope_id,source_kind,deleted_at ON documents
 FOR EACH ROW EXECUTE FUNCTION hash_guard_unhandled_document_package_v1();
DROP FUNCTION hash_package_lifecycle_receipt_matches_v1(UUID,UUID);
DROP FUNCTION hash_package_lifecycle_version_v1();
-- +goose StatementEnd
