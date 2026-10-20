-- +goose Up
-- Match the bounded pending-attempt keyset scan without changing which durable
-- jobs are visible. Queue coordinates are selectors, never recovery authority.
CREATE INDEX document_package_send_recovery_queue_v1 ON document_package_send_attempts_v1(created_at,attempt_id)
 WHERE terminal_outcome IS NULL;

-- The new reader requires this schema marker even when the queue is empty.
-- +goose StatementBegin
CREATE FUNCTION hash_package_send_recovery_queue_version_v1() RETURNS INTEGER AS $$
 SELECT 1;
$$ LANGUAGE sql STABLE;
-- +goose StatementEnd

-- +goose Down
-- Removing the marker invalidates dependent query plans; the new reader fails
-- closed on the missing function rather than running without the scan index.
DROP FUNCTION hash_package_send_recovery_queue_version_v1();
DROP INDEX document_package_send_recovery_queue_v1;
