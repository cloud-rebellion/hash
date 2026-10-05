-- +goose Up
-- Recovery records have a separate grace period from signing evidence.
-- Pending document-linked or organization-wide privacy requests defer expiry. This is not a
-- general legal-hold control; additional preservation requires the approved
-- operator procedure, including suspending expiry processing when necessary.
CREATE INDEX collab_recovery_archives_expiry
    ON collab_recovery_archives(expires_at, document_id, id);

-- A separate namespace prevents collision with unrelated application locks.
-- Hash collisions between organizations only cause conservative serialization.
-- +goose StatementBegin
CREATE FUNCTION hash_collab_archive_dsr_lock_key(p_org_id uuid) RETURNS bigint AS $$
    SELECT hashtextextended('hash:collab-archive:dsr:' || p_org_id::text, 0);
$$ LANGUAGE sql IMMUTABLE STRICT;
-- +goose StatementEnd

-- Global requests have no document FK to serialize their creation or reopen.
-- Their writers take the exclusive organization fence; expiry takes a shared
-- fence after the document lock and rechecks the committed request state.
-- +goose StatementBegin
CREATE FUNCTION hash_lock_global_dsr_for_collab_archives() RETURNS trigger AS $$
BEGIN
    -- Closed linked requests can become global when a parent is purged via
    -- ON DELETE SET NULL. They create no preservation obligation, so taking
    -- the exclusive fence here would upgrade the purger's shared fence and
    -- deadlock concurrent same-organization purges after object deletion.
    -- Inserts/reopens of pending global requests still serialize with purge.
    IF NEW.document_id IS NULL AND NEW.status IN ('open', 'in_progress') THEN
        PERFORM pg_advisory_xact_lock(hash_collab_archive_dsr_lock_key(NEW.org_id));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER collab_archives_global_dsr_fence
BEFORE INSERT OR UPDATE ON data_subject_requests
FOR EACH ROW EXECUTE FUNCTION hash_lock_global_dsr_for_collab_archives();

-- +goose StatementBegin
CREATE FUNCTION hash_purge_expired_collab_archives() RETURNS bigint AS $$
DECLARE
    cutoff timestamptz := statement_timestamp();
    candidate record;
    purged bigint := 0;
    removed bigint;
BEGIN
    -- Global requests do not update the document row. Higher isolation would
    -- keep an older request snapshot after acquiring the organization fence.
    IF current_setting('transaction_isolation') NOT IN ('read committed', 'read uncommitted') THEN
        RAISE EXCEPTION 'collaboration archive expiry requires READ COMMITTED isolation'
            USING ERRCODE = '25000';
    END IF;
    -- Bound both selected parents and the total archive deletions. The first
    -- request predicate avoids repeatedly selecting already-protected parents;
    -- it is not the final authorization to discard their history.
    FOR candidate IN
        SELECT d.id, d.org_id FROM documents d
        WHERE EXISTS (
            SELECT 1 FROM collab_recovery_archives a
            WHERE a.document_id = d.id AND a.expires_at <= cutoff
        )
          AND NOT EXISTS (
            SELECT 1 FROM data_subject_requests r
            WHERE r.org_id = d.org_id AND (r.document_id = d.id OR r.document_id IS NULL)
              AND r.status IN ('open', 'in_progress')
        )
        ORDER BY d.id
        FOR UPDATE OF d SKIP LOCKED
        LIMIT 100
    LOOP
        -- Do not wait on global writers after acquiring a parent. A multi-step
        -- writer could take an organization fence before a later document
        -- operation; skipping contention prevents the inverse lock order.
        IF NOT pg_try_advisory_xact_lock_shared(hash_collab_archive_dsr_lock_key(candidate.org_id)) THEN
            CONTINUE;
        END IF;

        -- The parent lock must precede this fresh statement snapshot and all
        -- archive locks. Linked request creation takes this document lock (or
        -- the FK's conflicting KEY SHARE lock), and recovery does likewise.
        -- A request committed after the candidate snapshot is visible here.
        IF EXISTS (
            SELECT 1 FROM data_subject_requests r
            WHERE r.org_id = candidate.org_id
              AND (r.document_id = candidate.id OR r.document_id IS NULL)
              AND r.status IN ('open', 'in_progress')
        ) THEN
            CONTINUE;
        END IF;

        WITH expired AS (
            SELECT a.id FROM collab_recovery_archives a
            WHERE a.document_id = candidate.id AND a.expires_at <= cutoff
            ORDER BY a.expires_at, a.id
            FOR UPDATE OF a SKIP LOCKED
            LIMIT (100 - purged)
        )
        DELETE FROM collab_recovery_archives a USING expired
        WHERE a.id = expired.id;
        GET DIAGNOSTICS removed = ROW_COUNT;
        purged := purged + removed;
        EXIT WHEN purged >= 100;
    END LOOP;
    RETURN purged;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION hash_purge_expired_collab_archives();
DROP TRIGGER collab_archives_global_dsr_fence ON data_subject_requests;
DROP FUNCTION hash_lock_global_dsr_for_collab_archives();
DROP FUNCTION hash_collab_archive_dsr_lock_key(uuid);
DROP INDEX collab_recovery_archives_expiry;
