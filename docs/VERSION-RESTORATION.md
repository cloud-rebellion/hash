# Restoring block document versions

REST and MCP restore a historical block version through the same native draft
transaction used by block editing. Organization/document scope, the original
credential, live author role, draft/evidence/privacy guards and
`expected_updated_at` still apply. Restore replaces only blocks and variables;
the current document name remains unchanged. It creates one `restore` snapshot
and one `document.updated` audit event, preserving the selected version number,
snapshot name, parent history and transport-specific audit fields.

The native writer owns the historical read and the new source measurements
before commit. A failed read, capacity admission, validation or audit write rolls
back the source, snapshot and measurements. It never repairs old caches after a
generic document update. Subsequent native edits use the restored document's
genuine fresh measurements.

Historical version bodies have no persisted sizing cache. The current bounded
reader therefore supports schema-1 block targets without HTML provenance on
PostgreSQL 16.15/UTF8 only when both stored JSONB values are uncompressed. It
locks metadata first, derives the existing conservative PostgreSQL storage-size
upper bound, acquires actual work capacity, then reads the exact historical body.
Compressed values, unknown schema/storage/encoding and capacity refusals fail
before restoring content. Large valid uncompressed versions can also exceed
capacity because the bound must cover PostgreSQL's worst-case numeric expansion.
This is a known limitation; this change does not qualify every historical target
as restorable. No migration, historical cache backfill or work-limit increase is
introduced.
