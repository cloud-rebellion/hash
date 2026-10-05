-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION hash_save_canonical_collab(
    p_document_id uuid, p_org_id uuid, p_generation bigint,
    p_expected_updated_at timestamptz, p_blocks jsonb, p_variables jsonb,
    p_state bytea, p_update_count integer, p_user_id uuid
) RETURNS boolean AS $$
DECLARE
    observed_updated_at timestamptz;
    current_generation bigint;
BEGIN
    IF p_blocks IS NULL OR jsonb_typeof(p_blocks) <> 'object'
       OR p_generation IS NULL OR p_generation < 1
       OR p_generation = 9223372036854775807
       OR p_expected_updated_at IS NULL OR p_user_id IS NULL THEN
        RAISE EXCEPTION 'invalid canonical collaboration save';
    END IF;
    SELECT updated_at INTO observed_updated_at FROM documents
    WHERE id = p_document_id AND org_id = p_org_id
      AND status = 'draft' AND source_kind = 'blocks' AND deleted_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT generation INTO current_generation FROM collab_document_generations
    WHERE document_id = p_document_id;
    IF current_generation IS DISTINCT FROM p_generation
       OR observed_updated_at IS DISTINCT FROM p_expected_updated_at
       OR NOT EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND org_id = p_org_id) THEN
        RETURN false;
    END IF;

    UPDATE documents SET blocks_json = p_blocks,
        variables_json = COALESCE(p_variables, variables_json), updated_at = clock_timestamp()
    WHERE id = p_document_id;
    -- The canonical trigger advances changed trees. Equal trees must also
    -- advance here, preventing a queued old flush from replacing this history.
    UPDATE collab_document_generations SET generation = generation + 1
    WHERE document_id = p_document_id AND generation = p_generation;
    SELECT generation INTO current_generation FROM collab_document_generations
    WHERE document_id = p_document_id;
    IF current_generation IS DISTINCT FROM p_generation + 1 THEN
        RAISE EXCEPTION 'canonical collaboration generation transition failed';
    END IF;
    IF NOT hash_persist_collab_generation(p_document_id, p_org_id,
        current_generation, p_state, octet_length(p_state), p_update_count, p_user_id) THEN
        -- Raise so even a caller that commits after this error cannot retain
        -- only the canonical half of the operation.
        RAISE EXCEPTION 'canonical collaboration history association failed';
    END IF;
    RETURN true;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION hash_save_canonical_collab(uuid, uuid, bigint, timestamptz, jsonb, jsonb, bytea, integer, uuid);
