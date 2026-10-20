-- +goose Up
-- Support the capped, metadata-only failed-mail observation in id order.
-- This transactional build scans existing rows and blocks table writes.
-- Keep the active pending/retrying queue index and every row unchanged.
CREATE INDEX email_deliveries_failed_observation_v1
    ON public.email_deliveries (id) INCLUDE (created_at)
    WHERE status = 'failed';

-- +goose Down
-- Remove only the index owned by this migration; preserve queue data/indexes.
DROP INDEX public.email_deliveries_failed_observation_v1;
