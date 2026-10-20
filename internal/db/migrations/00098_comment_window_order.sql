-- +goose Up
-- The UUID tie-breaker makes both seek directions bounded even when many
-- comments share a PostgreSQL microsecond. Retain the historical index.
CREATE INDEX idx_document_comments_window
    ON document_comments(document_id, created_at, id);

-- +goose Down
DROP INDEX idx_document_comments_window;
