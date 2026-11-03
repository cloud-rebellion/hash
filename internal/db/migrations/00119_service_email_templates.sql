-- +goose Up
-- Owner-authored email introductions are revisioned separately from documents,
-- sender credentials and transport. Rendered messages remain frozen in the
-- original durable outbox; workers never re-read mutable template settings.
CREATE TABLE org_email_template_revisions_v1 (
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('email.invite','email.reminder','email.completed_signer','email.completed_sender','email.changes_requested','email.new_comment')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    subject_template TEXT NOT NULL CHECK (octet_length(subject_template) <= 256),
    html_template TEXT NOT NULL CHECK (octet_length(html_template) <= 16384),
    text_template TEXT NOT NULL CHECK (octet_length(text_template) <= 8192),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id,kind,revision)
);
CREATE TABLE org_email_template_heads_v1 (
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    revision BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id,kind),
    FOREIGN KEY (org_id,kind,revision) REFERENCES org_email_template_revisions_v1(org_id,kind,revision)
);
-- +goose StatementBegin
CREATE FUNCTION hash_email_template_revision_immutable_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'email template revisions are immutable' USING ERRCODE='23514';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER email_template_revision_immutable_v1 BEFORE UPDATE ON org_email_template_revisions_v1
FOR EACH ROW EXECUTE FUNCTION hash_email_template_revision_immutable_v1();

-- +goose Down
LOCK TABLE org_email_template_heads_v1,org_email_template_revisions_v1 IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM org_email_template_revisions_v1) OR EXISTS(SELECT 1 FROM org_email_template_heads_v1) THEN
        RAISE EXCEPTION 'retained email template revisions forbid rollback' USING ERRCODE='23514';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE org_email_template_heads_v1;
DROP TABLE org_email_template_revisions_v1;
DROP FUNCTION hash_email_template_revision_immutable_v1();
