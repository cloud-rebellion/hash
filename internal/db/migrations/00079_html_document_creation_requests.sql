-- +goose Up
-- Browser creation can commit even when its response is lost. Retain only a
-- domain-separated command digest and immutable creation pins, not entered
-- contract text, CRM payloads, session cookies or review tokens. A missing
-- current document is a tombstone, never permission to reuse this request.
CREATE TABLE html_document_creation_requests (
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Retain the original actor identifier after member removal. A user FK
    -- would either erase replay protection or obstruct the member lifecycle.
    actor_user_id UUID NOT NULL,
    request_id UUID NOT NULL,
    input_digest BYTEA NOT NULL CHECK (octet_length(input_digest) = 32),
    template_id UUID NOT NULL,
    original_document_id UUID NOT NULL,
    current_document_id UUID REFERENCES documents(id) ON DELETE SET NULL,
    html_materialization_id UUID NOT NULL,
    html_source_commitment TEXT NOT NULL
        CHECK ((html_source_commitment COLLATE "C") ~ '^[0-9a-f]{64}$'),
    pdf_sha256 BYTEA NOT NULL CHECK (octet_length(pdf_sha256) = 32),
    page_count INTEGER NOT NULL CHECK (page_count BETWEEN 1 AND 500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, actor_user_id, request_id),
    CHECK (actor_user_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (request_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (current_document_id IS NULL OR current_document_id = original_document_id)
);

CREATE INDEX idx_html_document_creation_requests_document
    ON html_document_creation_requests(current_document_id)
    WHERE current_document_id IS NOT NULL;

-- Enforce durable replay pins even if a future writer forgets the current
-- handler checks. Deletion can only detach the live pointer; it never changes
-- the original identity or authorizes another creation for the same request.
-- +goose StatementBegin
CREATE FUNCTION hash_guard_html_creation_request() RETURNS trigger AS $$
DECLARE
    d documents%ROWTYPE;
    m html_document_materializations%ROWTYPE;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM orgs WHERE id = OLD.org_id) THEN
            RAISE EXCEPTION 'HTML creation replay protection cannot be deleted' USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
        IF (to_jsonb(NEW) - 'current_document_id') IS DISTINCT FROM (to_jsonb(OLD) - 'current_document_id')
            OR OLD.current_document_id IS NULL OR NEW.current_document_id IS NOT NULL
            OR EXISTS (SELECT 1 FROM documents WHERE id = OLD.current_document_id) THEN
            RAISE EXCEPTION 'HTML creation pins are immutable' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO STRICT d FROM documents WHERE id = NEW.current_document_id AND org_id = NEW.org_id FOR SHARE;
    SELECT * INTO STRICT m FROM html_document_materializations
        WHERE id = d.html_current_materialization_id AND document_id = d.id AND org_id = d.org_id;
    IF d.id IS DISTINCT FROM NEW.original_document_id OR d.sender_id IS DISTINCT FROM NEW.actor_user_id
        OR d.template_id IS DISTINCT FROM NEW.template_id OR d.status <> 'draft' OR d.deleted_at IS NOT NULL
        OR m.sequence <> 1 OR m.id IS DISTINCT FROM NEW.html_materialization_id
        OR encode(m.source_commitment, 'hex') IS DISTINCT FROM NEW.html_source_commitment
        OR m.pdf_sha256 IS DISTINCT FROM NEW.pdf_sha256 OR m.page_count IS DISTINCT FROM NEW.page_count
        OR m.pdf_key IS DISTINCT FROM d.pdf_storage_key OR m.pdf_version_id IS DISTINCT FROM d.pdf_storage_version_id
        OR m.pdf_sha256 IS DISTINCT FROM d.pdf_sha256
        OR NOT EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_user_id AND org_id = NEW.org_id AND role IN ('owner','sender')) THEN
        RAISE EXCEPTION 'HTML creation request must bind the exact initial materialization' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER html_creation_requests_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON html_document_creation_requests
    FOR EACH ROW EXECUTE FUNCTION hash_guard_html_creation_request();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    LOCK TABLE html_document_creation_requests IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM html_document_creation_requests LIMIT 1) THEN
        RAISE EXCEPTION 'cannot discard durable HTML document creation replay protection';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE html_document_creation_requests;
DROP FUNCTION hash_guard_html_creation_request();
