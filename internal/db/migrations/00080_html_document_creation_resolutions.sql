-- +goose Up
-- One terminal outcome retires an actor-scoped request even if its HTTP
-- response is lost. The unique key, rather than an absent-row observation,
-- excludes a later commit under every transaction isolation level.
LOCK TABLE html_document_creation_requests IN ACCESS EXCLUSIVE MODE;

CREATE TABLE html_document_creation_resolutions (
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Retain the original actor after member removal, as in migration79.
    actor_user_id UUID NOT NULL,
    request_id UUID NOT NULL,
    template_id UUID NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('committed', 'closed')),
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, actor_user_id, request_id),
    CHECK (org_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (actor_user_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (request_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (template_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

-- Existing committed receipts retain their original identity and timestamp.
-- Install runtime locking triggers after this backfill; migration79 bytes and
-- its immutable initial artifact pins are deliberately unchanged.
INSERT INTO html_document_creation_resolutions (
    org_id, actor_user_id, request_id, template_id, state, resolved_at
)
SELECT org_id, actor_user_id, request_id, template_id, 'committed', created_at
FROM html_document_creation_requests;

-- +goose StatementBegin
CREATE FUNCTION hash_guard_html_creation_resolution() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM orgs WHERE id = OLD.org_id) THEN
            RAISE EXCEPTION 'HTML creation outcomes cannot be deleted' USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW IS DISTINCT FROM OLD THEN
            RAISE EXCEPTION 'HTML creation outcomes are immutable' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    -- This is the same unconditional lock as LockBillingUsageForOrg. A nil
    -- billing engine must never weaken request retirement serialization.
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.org_id::text, 63001));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER html_creation_resolutions_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON html_document_creation_resolutions
    FOR EACH ROW EXECUTE FUNCTION hash_guard_html_creation_resolution();

-- +goose StatementBegin
CREATE FUNCTION hash_claim_html_creation_resolution() RETURNS trigger AS $$
DECLARE
    resolution html_document_creation_resolutions%ROWTYPE;
BEGIN
    -- Acquire quota before migration79's document lock, including for direct
    -- SQL callers. The unique registry key is the isolation-independent gate.
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.org_id::text, 63001));
    INSERT INTO html_document_creation_resolutions (
        org_id, actor_user_id, request_id, template_id, state, resolved_at
    ) VALUES (
        NEW.org_id, NEW.actor_user_id, NEW.request_id, NEW.template_id,
        'committed', NEW.created_at
    ) ON CONFLICT (org_id, actor_user_id, request_id) DO NOTHING;
    SELECT * INTO STRICT resolution FROM html_document_creation_resolutions
        WHERE org_id = NEW.org_id AND actor_user_id = NEW.actor_user_id
          AND request_id = NEW.request_id FOR SHARE;
    IF resolution.state <> 'committed' OR resolution.template_id IS DISTINCT FROM NEW.template_id THEN
        RAISE EXCEPTION 'HTML creation request is already retired' USING ERRCODE = '23514';
    END IF;
    -- An existing committed receipt may make the outer INSERT a no-op. Its
    -- original timestamp, not this discarded attempt's default, is retained.
    RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
    -- ON CONFLICT can see a winning row that an old REPEATABLE READ snapshot
    -- cannot read. Refuse; never reinterpret that conflict as an unused UUID.
    RAISE EXCEPTION 'HTML creation outcome must be visible and exact' USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER html_creation_requests_00_resolution
    BEFORE INSERT ON html_document_creation_requests
    FOR EACH ROW EXECUTE FUNCTION hash_claim_html_creation_resolution();

-- +goose StatementBegin
CREATE FUNCTION hash_check_html_creation_resolution() RETURNS trigger AS $$
DECLARE
    resolution html_document_creation_resolutions%ROWTYPE;
    receipt html_document_creation_requests%ROWTYPE;
    scope_org UUID;
    scope_actor UUID;
    scope_request UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        scope_org := OLD.org_id;
        scope_actor := OLD.actor_user_id;
        scope_request := OLD.request_id;
    ELSE
        scope_org := NEW.org_id;
        scope_actor := NEW.actor_user_id;
        scope_request := NEW.request_id;
    END IF;
    -- Full tenant erasure may cascade both retained metadata tables. A user
    -- or document deletion alone never retires or removes an outcome.
    IF NOT EXISTS (SELECT 1 FROM orgs WHERE id = scope_org) THEN
        RETURN NULL;
    END IF;
    SELECT * INTO STRICT resolution FROM html_document_creation_resolutions
        WHERE org_id = scope_org AND actor_user_id = scope_actor
          AND request_id = scope_request;
    IF resolution.state = 'closed' THEN
        IF EXISTS (SELECT 1 FROM html_document_creation_requests
            WHERE org_id = scope_org AND actor_user_id = scope_actor AND request_id = scope_request) THEN
            RAISE EXCEPTION 'closed HTML creation request cannot have a receipt' USING ERRCODE = '23514';
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO STRICT receipt FROM html_document_creation_requests
        WHERE org_id = scope_org AND actor_user_id = scope_actor
          AND request_id = scope_request;
    IF receipt.template_id IS DISTINCT FROM resolution.template_id
        OR receipt.created_at IS DISTINCT FROM resolution.resolved_at THEN
        RAISE EXCEPTION 'HTML creation outcome must match its original receipt' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
    RAISE EXCEPTION 'committed HTML creation outcome requires its exact receipt' USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- The claim is inserted before its receipt exists. Defer the complete
-- invariant until commit, and also check direct registry inserts.
CREATE CONSTRAINT TRIGGER html_creation_resolutions_receipt
    AFTER INSERT OR UPDATE OR DELETE ON html_document_creation_resolutions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION hash_check_html_creation_resolution();

CREATE CONSTRAINT TRIGGER html_creation_requests_resolution_receipt
    AFTER INSERT ON html_document_creation_requests
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION hash_check_html_creation_resolution();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    LOCK TABLE html_document_creation_requests, html_document_creation_resolutions IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM html_document_creation_resolutions WHERE state = 'closed') THEN
        RAISE EXCEPTION 'cannot discard closed HTML creation requests';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER html_creation_requests_resolution_receipt ON html_document_creation_requests;
DROP TRIGGER html_creation_requests_00_resolution ON html_document_creation_requests;
DROP TABLE html_document_creation_resolutions;
DROP FUNCTION hash_check_html_creation_resolution();
DROP FUNCTION hash_claim_html_creation_resolution();
DROP FUNCTION hash_guard_html_creation_resolution();
