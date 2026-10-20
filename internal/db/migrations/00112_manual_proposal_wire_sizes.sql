-- Fresh native writer measurements only; no historical expansion or backfill.
-- A native producer must own the real body loan BEFORE measuring JSONB text.
-- +goose Up
LOCK TABLE public.document_proposals IN EXCLUSIVE MODE NOWAIT;
CREATE TABLE public.manual_proposal_wire_sizes_v1 (
 proposal_id UUID PRIMARY KEY REFERENCES public.document_proposals(id) ON DELETE CASCADE,
 document_id UUID NOT NULL,
 org_id UUID NOT NULL,
 proposal_created_at TIMESTAMPTZ NOT NULL CHECK(isfinite(proposal_created_at)),
 proposal_updated_at TIMESTAMPTZ NOT NULL CHECK(isfinite(proposal_updated_at)),
 diff_wire_bytes BIGINT NOT NULL CHECK(diff_wire_bytes>=0),
 measurement_server_version_num INTEGER NOT NULL CHECK(measurement_server_version_num>0),
 measured_at TIMESTAMPTZ NOT NULL CHECK(isfinite(measured_at))
);
CREATE INDEX manual_proposal_wire_scope_v1 ON public.manual_proposal_wire_sizes_v1(document_id,org_id,proposal_id);
-- Invalidation is scalar and never compares/expands old JSONB. Even an UPDATE
-- that writes the same values invalidates rather than guessing content identity.
-- +goose StatementBegin
CREATE FUNCTION public.hash_invalidate_manual_proposal_wire_v1() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 DELETE FROM public.manual_proposal_wire_sizes_v1 WHERE proposal_id=OLD.id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER invalidate_manual_proposal_wire_v1 BEFORE UPDATE
 ON public.document_proposals FOR EACH ROW EXECUTE FUNCTION public.hash_invalidate_manual_proposal_wire_v1();
-- The table never accepts caller-supplied sizes/stamps as proof. Same-row TRY
-- locking refuses cache->source inversion; normal native writers already hold
-- physical root -> target -> actor -> proposal before this fresh measurement.
-- +goose StatementBegin
CREATE FUNCTION public.hash_derive_manual_proposal_wire_v1() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE actual_document UUID;actual_org UUID;actual_created TIMESTAMPTZ;actual_updated TIMESTAMPTZ;
BEGIN
 IF NEW.proposal_id IS NULL OR NEW.document_id IS NULL OR NEW.org_id IS NULL THEN
  RAISE EXCEPTION 'manual proposal wire scope required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.proposal_id IS DISTINCT FROM OLD.proposal_id THEN
  RAISE EXCEPTION 'manual proposal wire identity is immutable' USING ERRCODE='23514';
 END IF;
 SELECT p.document_id,p.org_id,p.created_at,p.updated_at INTO STRICT actual_document,actual_org,actual_created,actual_updated
 FROM public.document_proposals p WHERE p.id=NEW.proposal_id FOR SHARE OF p NOWAIT;
 IF actual_document IS DISTINCT FROM NEW.document_id OR actual_org IS DISTINCT FROM NEW.org_id THEN
  RAISE EXCEPTION 'manual proposal wire source scope differs' USING ERRCODE='23514';
 END IF;
 IF NOT isfinite(actual_created) OR NOT isfinite(actual_updated) OR current_setting('server_encoding')<>'UTF8' THEN
  RAISE EXCEPTION 'manual proposal wire source format differs' USING ERRCODE='23514';
 END IF;
 -- Actual owned source expansion, never a physical-storage compression ratio.
 SELECT octet_length(p.diff_json::text)::bigint INTO STRICT NEW.diff_wire_bytes
 FROM public.document_proposals p WHERE p.id=NEW.proposal_id;
 NEW.proposal_created_at:=actual_created;NEW.proposal_updated_at:=actual_updated;
 NEW.measurement_server_version_num:=current_setting('server_version_num')::integer;
 NEW.measured_at:=clock_timestamp();
 RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND THEN
 RAISE EXCEPTION 'manual proposal wire source missing' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER derive_manual_proposal_wire_v1 BEFORE INSERT OR UPDATE
 ON public.manual_proposal_wire_sizes_v1 FOR EACH ROW EXECUTE FUNCTION public.hash_derive_manual_proposal_wire_v1();

-- +goose Down
LOCK TABLE public.document_proposals,public.manual_proposal_wire_sizes_v1 IN ACCESS EXCLUSIVE MODE NOWAIT;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.manual_proposal_wire_sizes_v1) THEN
  RAISE EXCEPTION 'retained native proposal measurements require reviewed disposition before rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER derive_manual_proposal_wire_v1 ON public.manual_proposal_wire_sizes_v1;
DROP TRIGGER invalidate_manual_proposal_wire_v1 ON public.document_proposals;
DROP FUNCTION public.hash_derive_manual_proposal_wire_v1();
DROP FUNCTION public.hash_invalidate_manual_proposal_wire_v1();
DROP TABLE public.manual_proposal_wire_sizes_v1;
