-- +goose Up
-- Backfill the payload-size measurement (00094) for events that were written
-- before every writer measured its own event: CRM template population, pre-sign
-- source and supersession births, and the legacy revise path logged through the
-- plain audit appender and left no row. An HTML document with an unmeasured
-- event cannot be revised or have a ceremony retired (503 "retry later").
-- The derive trigger measures the real payload and takes the org chain lock; this
-- statement supplies only the scope. Events that already have a row (including
-- one from another server version) are left alone, and so are non-HTML documents.
INSERT INTO html_snapshot_event_payload_sizes_v1 (event_id, document_id, org_id, payload_wire_bytes, measurement_server_version_num, measured_at)
SELECT e.id, e.document_id, e.org_id, 0, current_setting('server_version_num')::integer, clock_timestamp()
FROM events e
JOIN documents d ON d.id = e.document_id AND d.org_id = e.org_id
WHERE d.html_source_json IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM html_snapshot_event_payload_sizes_v1 m WHERE m.event_id = e.id)
ORDER BY e.org_id, e.id
ON CONFLICT (event_id) DO NOTHING;

-- +goose Down
-- The rows are a derived cache; a rollback leaves them in place.
SELECT 1;
