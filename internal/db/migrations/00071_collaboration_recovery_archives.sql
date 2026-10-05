-- +goose Up
-- These archives are document-scoped recovery data, never signing evidence.
-- Unknown legacy associations remain NULL; do not invent a generation.
CREATE TABLE collab_recovery_archives (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    observed_canonical_generation bigint NOT NULL CHECK (observed_canonical_generation > 0),
    history_generation bigint CHECK (history_generation > 0),
    origin text NOT NULL CHECK (origin IN ('persisted', 'active_room')),
    ydoc_state bytea NOT NULL CHECK (octet_length(ydoc_state) <= 8388608),
    recovered_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '90 days',
    CHECK (expires_at > created_at)
);
CREATE INDEX collab_recovery_archives_document ON collab_recovery_archives(document_id, created_at);

-- +goose StatementBegin
CREATE FUNCTION hash_recover_canonical_collab(
    p_document_id uuid, p_org_id uuid, p_generation bigint,
    p_expected_updated_at timestamptz, p_user_id uuid, p_acknowledged boolean,
    p_room_state bytea, p_room_generation bigint
) RETURNS bigint AS $$
DECLARE
    current_generation bigint;
    observed_updated_at timestamptz;
    archive_count bigint;
    archive_bytes bigint;
    additional_count bigint;
    additional_bytes bigint;
BEGIN
    IF p_acknowledged IS DISTINCT FROM true OR p_generation IS NULL
       OR p_generation < 1 OR p_generation = 9223372036854775807
       OR p_expected_updated_at IS NULL OR p_user_id IS NULL
       OR (p_room_state IS NOT NULL AND
           (p_room_generation IS NULL OR p_room_generation < 1
            OR p_room_generation > p_generation OR octet_length(p_room_state) > 8388608)) THEN
        RAISE EXCEPTION 'invalid acknowledged collaboration recovery';
    END IF;
    SELECT updated_at INTO observed_updated_at FROM documents
    WHERE id = p_document_id AND org_id = p_org_id
      AND status = 'draft' AND source_kind = 'blocks' AND deleted_at IS NULL
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 0; END IF;

    IF EXISTS(SELECT 1 FROM data_subject_requests WHERE org_id = p_org_id
       AND (document_id = p_document_id OR document_id IS NULL)
       AND kind = 'erasure' AND status = 'fulfilled') THEN
        RAISE EXCEPTION 'collaboration recovery requires privacy review after erasure' USING ERRCODE = '55000';
    END IF;

    -- Never discard earlier archives to make room for another recovery.
    SELECT count(*), COALESCE(sum(octet_length(ydoc_state)),0)
      INTO archive_count, archive_bytes FROM collab_recovery_archives
      WHERE document_id = p_document_id;
    SELECT count(*), COALESCE(sum(octet_length(ydoc_state)),0)
      INTO additional_count, additional_bytes FROM collab_doc_states
      WHERE document_id = p_document_id AND octet_length(ydoc_state) > 0;
    IF p_room_state IS NOT NULL AND octet_length(p_room_state) > 0 THEN
        additional_count := additional_count + 1;
        additional_bytes := additional_bytes + octet_length(p_room_state);
    END IF;
    IF archive_count + additional_count > 16 OR archive_bytes + additional_bytes > 67108864 THEN
        RAISE EXCEPTION 'collaboration recovery archive budget reached' USING ERRCODE = '54000';
    END IF;
    SELECT generation INTO current_generation FROM collab_document_generations
    WHERE document_id = p_document_id;
    IF current_generation IS DISTINCT FROM p_generation
       OR observed_updated_at IS DISTINCT FROM p_expected_updated_at THEN RETURN 0; END IF;
    -- Recovery is an explicit owner operation, not automatic import cleanup.
    PERFORM id FROM users WHERE id = p_user_id AND org_id = p_org_id AND role = 'owner' FOR SHARE;
    IF NOT FOUND THEN RETURN 0; END IF;

    INSERT INTO collab_recovery_archives(document_id, observed_canonical_generation,
        history_generation, origin, ydoc_state, recovered_by)
    SELECT p_document_id, current_generation, g.generation, 'persisted', s.ydoc_state, p_user_id
    FROM collab_doc_states s LEFT JOIN collab_state_generations g USING(document_id)
    WHERE s.document_id = p_document_id AND octet_length(s.ydoc_state) > 0;
    IF p_room_state IS NOT NULL AND octet_length(p_room_state) > 0 THEN
        INSERT INTO collab_recovery_archives(document_id, observed_canonical_generation,
            history_generation, origin, ydoc_state, recovered_by)
        VALUES(p_document_id, current_generation, p_room_generation, 'active_room', p_room_state, p_user_id);
    END IF;
    UPDATE collab_document_generations SET generation = generation + 1 WHERE document_id = p_document_id;
    UPDATE documents SET updated_at = clock_timestamp() WHERE id = p_document_id;
    INSERT INTO collab_doc_states(document_id, ydoc_state, state_size, update_count, last_user_id)
    VALUES(p_document_id, '\x'::bytea, 0, 0, p_user_id)
    ON CONFLICT(document_id) DO UPDATE SET ydoc_state = EXCLUDED.ydoc_state,
        state_size = 0, update_count = 0, last_user_id = p_user_id, updated_at = clock_timestamp();
    INSERT INTO collab_state_generations(document_id, generation) VALUES(p_document_id, current_generation + 1)
    ON CONFLICT(document_id) DO UPDATE SET generation = EXCLUDED.generation;
    RETURN current_generation + 1;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM collab_recovery_archives) THEN
        RAISE EXCEPTION 'preserve collaboration recovery archives before rollback';
    END IF;
END $$;
-- +goose StatementEnd
DROP FUNCTION hash_recover_canonical_collab(uuid, uuid, bigint, timestamptz, uuid, boolean, bytea, bigint);
DROP TABLE collab_recovery_archives;
