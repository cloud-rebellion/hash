-- +goose Up
ALTER TABLE users ADD COLUMN session_generation BIGINT NOT NULL DEFAULT 0
    CHECK (session_generation >= 0);

-- +goose Down
-- Dropping recorded revocations could make previously logged-out cookies valid.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE session_generation <> 0) THEN
        RAISE EXCEPTION 'cannot remove sender session revocation after generations have advanced';
    END IF;
END;
$$;
-- +goose StatementEnd
ALTER TABLE users DROP COLUMN session_generation;
