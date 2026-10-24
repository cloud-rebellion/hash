-- +goose Up
-- Native staff credentials remain separate from signer credentials and from
-- organization roles. Only mailbox proof can install an initial credential.
CREATE TABLE staff_password_credentials (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 80 AND 512),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE staff_auth_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
    purpose TEXT NOT NULL CHECK (purpose IN ('register', 'setup', 'reset')),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_generation BIGINT,
    name TEXT NOT NULL DEFAULT '' CHECK (length(name) <= 200),
    company_name TEXT NOT NULL DEFAULT '' CHECK (length(company_name) <= 200),
    password_hash TEXT CHECK (length(password_hash) BETWEEN 80 AND 512),
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours'),
    CHECK ((purpose = 'register' AND password_hash IS NOT NULL)
        OR (purpose IN ('setup', 'reset') AND password_hash IS NULL AND user_id IS NOT NULL)),
    CHECK ((user_id IS NULL AND session_generation IS NULL)
        OR (user_id IS NOT NULL AND session_generation IS NOT NULL AND session_generation >= 0))
);

CREATE INDEX staff_auth_requests_email ON staff_auth_requests (email, created_at DESC);
CREATE INDEX staff_auth_requests_expiry ON staff_auth_requests (expires_at);

-- Only auth mail uses this envelope. Plaintext HTML/text stay empty and the
-- existing lease/backoff worker opens the body only while delivering SMTP.
ALTER TABLE email_deliveries ADD COLUMN staff_auth_ciphertext BYTEA;
ALTER TABLE email_deliveries ADD CONSTRAINT staff_auth_email_sealed_body CHECK (
    staff_auth_ciphertext IS NULL OR
    (octet_length(staff_auth_ciphertext) BETWEEN 30 AND 32768 AND html_body = '' AND text_body = '')
);

-- +goose Down
-- Credential or recovery data must never disappear during rollback. Hold the
-- tables against concurrent writers before inspecting their complete state.
LOCK TABLE staff_password_credentials, staff_auth_requests, email_deliveries
    IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM staff_password_credentials)
        OR EXISTS (SELECT 1 FROM staff_auth_requests)
        OR EXISTS (SELECT 1 FROM email_deliveries WHERE staff_auth_ciphertext IS NOT NULL)
    THEN
        RAISE EXCEPTION 'staff authentication records forbid rollback; use qualified restoration'
            USING ERRCODE = '23514';
    END IF;
END;
$$;
-- +goose StatementEnd
ALTER TABLE email_deliveries DROP CONSTRAINT staff_auth_email_sealed_body;
ALTER TABLE email_deliveries DROP COLUMN staff_auth_ciphertext;
DROP TABLE staff_auth_requests;
DROP TABLE staff_password_credentials;
