-- +goose Up
-- Preserve only mail already retained at this migration as installation mail.
-- New workspace mail must carry its native organization identity; neither
-- recipient addresses nor mutable display/header text confer tenant authority.
ALTER TABLE email_deliveries ADD COLUMN smtp_org_id UUID;
ALTER TABLE email_deliveries ADD COLUMN smtp_purpose TEXT NOT NULL DEFAULT 'workspace';
ALTER TABLE email_deliveries ADD COLUMN smtp_claim_nonce UUID;
UPDATE email_deliveries SET smtp_purpose='installation_legacy';
ALTER TABLE email_deliveries ADD CONSTRAINT email_delivery_smtp_scope_v1 CHECK (
 (smtp_purpose IN ('workspace','workspace_test') AND smtp_org_id IS NOT NULL AND smtp_org_id<>'00000000-0000-0000-0000-000000000000'::uuid)
 OR (smtp_purpose IN ('installation_auth','installation_legacy') AND smtp_org_id IS NULL)
);
-- +goose StatementBegin
CREATE FUNCTION hash_email_smtp_route_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.smtp_purpose='installation_legacy' THEN
  RAISE EXCEPTION 'legacy SMTP routing is migration-only' USING ERRCODE='23514';
 END IF;
 -- A surviving pre-M120 worker must not claim tenant mail and then send it
 -- through its installation sender. Fresh native lease/retry SQL advances a
 -- database nonce on every attempt; old generated statements cannot do so.
 IF TG_OP='UPDATE' AND OLD.smtp_purpose IN ('workspace','workspace_test')
  AND NEW.status='retrying'
  AND (NEW.next_attempt_at IS DISTINCT FROM OLD.next_attempt_at OR NEW.status IS DISTINCT FROM OLD.status)
  AND (NEW.smtp_claim_nonce IS NULL OR NEW.smtp_claim_nonce IS NOT DISTINCT FROM OLD.smtp_claim_nonce) THEN
  RAISE EXCEPTION 'workspace SMTP-aware claim required' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND (NEW.smtp_org_id IS DISTINCT FROM OLD.smtp_org_id OR NEW.smtp_purpose IS DISTINCT FROM OLD.smtp_purpose) THEN
  RAISE EXCEPTION 'retained SMTP routing is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER email_smtp_route_guard_v1 BEFORE INSERT OR UPDATE ON email_deliveries
FOR EACH ROW EXECUTE FUNCTION hash_email_smtp_route_guard_v1();

CREATE TABLE org_smtp_settings_v1 (
 org_id UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
 revision BIGINT NOT NULL CHECK(revision>=0),
 mode TEXT NOT NULL CHECK(mode IN ('installation_legacy','configured','disabled')),
 config_ciphertext BYTEA CHECK(octet_length(config_ciphertext) BETWEEN 30 AND 12288),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 last_test_at TIMESTAMPTZ,
 CHECK((mode='configured' AND revision>0 AND config_ciphertext IS NOT NULL)
   OR (mode='installation_legacy' AND revision=0 AND config_ciphertext IS NULL)
   OR (mode='disabled' AND revision>0 AND config_ciphertext IS NULL))
);
-- Explicit compatibility applies only to organizations existing at Up. New
-- organizations have no row and cannot silently use the installation sender.
INSERT INTO org_smtp_settings_v1(org_id,revision,mode)
SELECT id,0,'installation_legacy' FROM orgs;
-- +goose StatementBegin
CREATE FUNCTION hash_workspace_smtp_legacy_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.mode='installation_legacy' THEN
  RAISE EXCEPTION 'legacy workspace SMTP mode is migration-only' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER workspace_smtp_legacy_guard_v1 BEFORE INSERT OR UPDATE ON org_smtp_settings_v1
FOR EACH ROW EXECUTE FUNCTION hash_workspace_smtp_legacy_guard_v1();

CREATE TABLE org_smtp_test_requests_v1 (
 email_delivery_id UUID PRIMARY KEY REFERENCES email_deliveries(id) ON DELETE RESTRICT,
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 settings_revision BIGINT NOT NULL CHECK(settings_revision>0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX org_smtp_test_owner_v1 ON org_smtp_test_requests_v1(org_id,owner_id,created_at DESC);

-- +goose Down
LOCK TABLE org_smtp_settings_v1,org_smtp_test_requests_v1,email_deliveries IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM org_smtp_settings_v1 WHERE revision>0 OR config_ciphertext IS NOT NULL)
  OR EXISTS(SELECT 1 FROM org_smtp_test_requests_v1)
  OR EXISTS(SELECT 1 FROM email_deliveries WHERE smtp_purpose IN ('workspace','workspace_test')) THEN
  RAISE EXCEPTION 'retained workspace SMTP settings or delivery routing forbid rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE org_smtp_test_requests_v1;
DROP TABLE org_smtp_settings_v1;
DROP FUNCTION hash_workspace_smtp_legacy_guard_v1();
DROP TRIGGER email_smtp_route_guard_v1 ON email_deliveries;
DROP FUNCTION hash_email_smtp_route_guard_v1();
ALTER TABLE email_deliveries DROP CONSTRAINT email_delivery_smtp_scope_v1;
ALTER TABLE email_deliveries DROP COLUMN smtp_claim_nonce;
ALTER TABLE email_deliveries DROP COLUMN smtp_purpose;
ALTER TABLE email_deliveries DROP COLUMN smtp_org_id;
