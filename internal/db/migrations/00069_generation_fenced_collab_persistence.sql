-- +goose Up
-- Existing logs intentionally remain unassociated until their canonical
-- generation can be established. Do not infer an association from timestamps.
CREATE TABLE collab_state_generations (
    document_id uuid PRIMARY KEY REFERENCES collab_doc_states(document_id) ON DELETE CASCADE,
    generation bigint NOT NULL CHECK (generation > 0)
);

-- +goose StatementBegin
CREATE FUNCTION hash_persist_collab_generation(
    p_document_id uuid, p_org_id uuid, p_generation bigint,
    p_state bytea, p_state_size integer, p_update_count integer, p_last_user_id uuid
) RETURNS boolean AS $$
DECLARE
    current_generation bigint;
BEGIN
    IF p_state IS NULL OR p_state_size IS DISTINCT FROM octet_length(p_state)
       OR p_state_size > 8388608 OR p_update_count IS NULL
       OR p_update_count < 0 OR p_update_count > 65536 THEN
        RAISE EXCEPTION 'invalid collaboration persistence bounds';
    END IF;
    -- Acquire the parent first. The following statement gets a fresh snapshot
    -- after a concurrent canonical writer commits, rather than trusting a
    -- generation observed before waiting on this lock.
    PERFORM id FROM documents
    WHERE id = p_document_id AND org_id = p_org_id
      AND status = 'draft' AND source_kind = 'blocks' AND deleted_at IS NULL
    FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT generation INTO current_generation FROM collab_document_generations
    WHERE document_id = p_document_id;
    IF current_generation IS NULL OR p_generation IS DISTINCT FROM current_generation THEN
        RETURN false;
    END IF;
    IF p_last_user_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM users WHERE id = p_last_user_id AND org_id = p_org_id
    ) THEN RETURN false; END IF;

    INSERT INTO collab_doc_states(document_id, ydoc_state, state_size, update_count, last_user_id)
    VALUES(p_document_id, p_state, p_state_size, p_update_count, p_last_user_id)
    ON CONFLICT(document_id) DO UPDATE SET
        ydoc_state = EXCLUDED.ydoc_state,
        state_size = EXCLUDED.state_size,
        update_count = collab_doc_states.update_count + EXCLUDED.update_count,
        last_user_id = COALESCE(EXCLUDED.last_user_id, collab_doc_states.last_user_id),
        updated_at = now();
    INSERT INTO collab_state_generations(document_id, generation)
    VALUES(p_document_id, p_generation)
    ON CONFLICT(document_id) DO UPDATE SET generation = EXCLUDED.generation;
    RETURN true;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM collab_state_generations) THEN
        RAISE EXCEPTION 'preserve collaboration generation associations before rollback';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP FUNCTION hash_persist_collab_generation(uuid, uuid, bigint, bytea, integer, integer, uuid);
DROP TABLE collab_state_generations;
