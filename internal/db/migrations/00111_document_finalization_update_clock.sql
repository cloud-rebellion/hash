-- +goose Up
-- M67 deliberately ignores a requested updated_at. Preserve that rule, while
-- the first actual finalization freeze must reach its separately bound legal
-- completion clock. That clock may be ahead of wall time because it follows
-- retained participant-history highwaters. Root and sent envelope children
-- use the same legal commitment; this function supplies no readiness authority.
-- No historical document, archive or evidence row is rewritten.
LOCK TABLE public.documents IN ACCESS EXCLUSIVE MODE NOWAIT;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION hash_advance_document_update_clock() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := GREATEST(clock_timestamp(), OLD.updated_at + interval '1 microsecond');
    IF OLD.status IN ('sent', 'in_progress')
       AND NEW.status = 'finalizing'
       AND OLD.completion_effective_at IS NULL
       AND OLD.completion_effective_at_bound
       AND NEW.completion_effective_at_bound
       AND NEW.completion_effective_at IS NOT NULL
       AND isfinite(NEW.completion_effective_at) THEN
        NEW.updated_at := GREATEST(NEW.updated_at, NEW.completion_effective_at);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- Rollback never deletes state or rewrites legal clocks. An admitted/pending
-- ceremony can still need its first coherent freeze, so require an explicitly
-- reviewed disposition before restoring the earlier clock policy. NOWAIT also
-- refuses overlapping document activity rather than reversing lock order.
LOCK TABLE public.documents IN ACCESS EXCLUSIVE MODE NOWAIT;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.documents
        WHERE deleted_at IS NULL
          AND status IN ('sealing', 'sent', 'in_progress', 'changes_requested', 'finalizing')
    ) THEN
        RAISE EXCEPTION 'active document ceremonies require reviewed disposition before document clock rollback'
            USING ERRCODE = '23514';
    END IF;
END;
$$;
-- +goose StatementEnd
-- Exact M67 function body and invoker/default-path semantics. The existing
-- hash_document_update_clock trigger remains installed throughout Up/Down.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION hash_advance_document_update_clock() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := GREATEST(clock_timestamp(), OLD.updated_at + interval '1 microsecond');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
