-- +goose Up
-- Per-Hash-organization credentials replace the process-global CRM bearer.
-- Opaque remote account IDs are not local UUIDs or company registration IDs.
CREATE TABLE crm_connections (
    org_id UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    id UUID NOT NULL UNIQUE,
    generation BIGINT NOT NULL CHECK (generation > 0),
    status TEXT NOT NULL CHECK (status IN ('candidate', 'active', 'revoked')),
    origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
    -- PostgreSQL bounded regex repetitions stop at 255; enforce length separately.
    crm_team_id TEXT NOT NULL CHECK (length(crm_team_id) BETWEEN 1 AND 256 AND (crm_team_id COLLATE "C") ~ '^[A-Za-z0-9_-]+$'),
    crm_user_id TEXT NOT NULL CHECK (length(crm_user_id) BETWEEN 1 AND 256 AND (crm_user_id COLLATE "C") ~ '^[A-Za-z0-9_-]+$'),
    credential_ciphertext BYTEA,
    verified_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (status = 'revoked' OR generation < 9223372036854775807),
    CHECK ((status = 'revoked' AND credential_ciphertext IS NULL) OR
           (status IN ('candidate', 'active') AND credential_ciphertext IS NOT NULL AND octet_length(credential_ciphertext) BETWEEN 32 AND 512))
);

-- +goose StatementBegin
CREATE FUNCTION guard_crm_connection_generation() RETURNS trigger AS $$
BEGIN
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id OR
       OLD.generation = 9223372036854775807 OR NEW.generation <> OLD.generation + 1 THEN
        RAISE EXCEPTION 'CRM connection revision must advance exactly once';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER crm_connection_generation BEFORE UPDATE ON crm_connections
FOR EACH ROW EXECUTE FUNCTION guard_crm_connection_generation();

ALTER TABLE document_variable_bindings DROP CONSTRAINT document_variable_bindings_source_kind_check;
ALTER TABLE document_variable_bindings ADD CONSTRAINT document_variable_bindings_source_kind_check
CHECK (source_kind IN ('static','crm.deal','crm.contact','crm.company','scanner.finding','org.setting','agent.computed'));

-- +goose Down
-- Refuse erasing retained encrypted account configuration or new bindings.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM crm_connections) OR
       EXISTS (SELECT 1 FROM document_variable_bindings WHERE source_kind = 'crm.company') THEN
        RAISE EXCEPTION 'CRM configuration or company bindings must be reconciled before rollback';
    END IF;
END $$;
-- +goose StatementEnd
ALTER TABLE document_variable_bindings DROP CONSTRAINT document_variable_bindings_source_kind_check;
ALTER TABLE document_variable_bindings ADD CONSTRAINT document_variable_bindings_source_kind_check
CHECK (source_kind IN ('static','crm.deal','crm.contact','scanner.finding','org.setting','agent.computed'));
DROP TABLE crm_connections;
DROP FUNCTION guard_crm_connection_generation();
