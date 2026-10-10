-- +goose Up
-- Current mapping review is mutable authoring state; immutable audit records
-- retain the exact applied mapping/observations for historical materializations.
CREATE TABLE document_crm_mapping_reviews (
    document_id UUID PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    has_mappings BOOLEAN NOT NULL,
    binding_digest TEXT NOT NULL CHECK ((binding_digest COLLATE "C") ~ '^[0-9a-f]{64}$'),
    content_commitment TEXT NOT NULL CHECK ((content_commitment COLLATE "C") ~ '^[0-9a-f]{64}$'),
    connection_id UUID,
    connection_generation BIGINT,
    origin TEXT NOT NULL DEFAULT '',
    crm_team_id TEXT NOT NULL DEFAULT '',
    crm_user_id TEXT NOT NULL DEFAULT '',
    -- Keep a reviewer while its review remains. Deferred NO ACTION permits an
    -- organization deletion to cascade through both documents/reviews and users.
    reviewed_by UUID NOT NULL REFERENCES users(id) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((has_mappings AND connection_id IS NOT NULL
            AND connection_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND connection_generation IS NOT NULL AND connection_generation > 0
            AND length(origin) BETWEEN 1 AND 2048
            AND length(crm_team_id) BETWEEN 1 AND 256 AND (crm_team_id COLLATE "C") ~ '^[A-Za-z0-9_-]+$'
            AND length(crm_user_id) BETWEEN 1 AND 256 AND (crm_user_id COLLATE "C") ~ '^[A-Za-z0-9_-]+$')
        OR (NOT has_mappings AND connection_id IS NULL AND connection_generation IS NULL
            AND origin = '' AND crm_team_id = '' AND crm_user_id = ''))
);

-- +goose Down
-- Never silently discard a previously reviewed mapping or an explicit unlink.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM document_crm_mapping_reviews) THEN
        RAISE EXCEPTION 'CRM mapping reviews must be reconciled before rollback';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE document_crm_mapping_reviews;
