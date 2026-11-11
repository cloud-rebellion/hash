-- +goose Up
-- M127: a durable record of stored object versions that a committed privacy
-- erasure still owes the object store. A DSR PDF-history erasure erases the
-- revision rows, which were the only pointer to the replaced objects, and then
-- deletes the objects after the transaction commits. Without a record written
-- in that same transaction, a storage fault leaves the request fulfilled and the
-- subject's PDF stored with nothing left to find it. The row is the obligation:
-- the request handler attempts it right after commit and the worker sweep retries
-- it with backoff until the exact version is gone (an absent version counts as
-- done). A row is deleted only after the object store confirmed the deletion.
--
-- document_id has no foreign key on purpose: the worker may hard-delete the
-- parent draft while an obligation is still pending, and the obligation must
-- outlive it. org_id is mandatory and every index starts with it. storage_key
-- names an org and a document id, never a subject; last_error carries a bounded
-- storage error and no request data.
CREATE TABLE pending_object_deletions_v1 (
 id UUID PRIMARY KEY,
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 document_id UUID NOT NULL,
 dsr_id UUID REFERENCES data_subject_requests(id) ON DELETE SET NULL,
 storage_key TEXT NOT NULL CHECK (storage_key <> '' AND octet_length(storage_key) <= 1024),
 version_id TEXT NOT NULL CHECK (version_id <> '' AND octet_length(version_id) <= 1024),
 sha256 BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 -- Doubles as the retry backoff and the sweep lease: a claimed row is pushed
 -- into the future, so a crashed sweep leaves it eligible again later.
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
 last_error TEXT NOT NULL DEFAULT '' CHECK (octet_length(last_error) <= 512),
 UNIQUE (org_id, storage_key, version_id)
);
CREATE INDEX pending_object_deletions_due_v1 ON pending_object_deletions_v1 (org_id, next_attempt_at);
CREATE INDEX pending_object_deletions_document_v1 ON pending_object_deletions_v1 (org_id, document_id);

-- +goose Down
LOCK TABLE pending_object_deletions_v1 IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM pending_object_deletions_v1) THEN
  RAISE EXCEPTION 'pending object deletions forbid migration rollback until the object store has drained them' USING ERRCODE = '23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE pending_object_deletions_v1;
