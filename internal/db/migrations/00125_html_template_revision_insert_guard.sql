-- +goose Up
-- M073 guards UPDATE and DELETE only. A revision must be born unapproved and
-- become approved through the one completed-approval UPDATE, so no INSERT path
-- (future code, SQL injection) can fabricate an already-approved design.
-- +goose StatementBegin
CREATE FUNCTION hash_guard_html_template_revision_insert() RETURNS trigger AS $$
BEGIN
    IF NEW.approved_by IS NOT NULL OR NEW.approved_at IS NOT NULL THEN
        RAISE EXCEPTION 'HTML template revision must be inserted unapproved; approval is a separate completed step'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER html_template_revision_insert_unapproved
BEFORE INSERT ON html_template_revisions
FOR EACH ROW EXECUTE FUNCTION hash_guard_html_template_revision_insert();

-- +goose Down
DROP TRIGGER html_template_revision_insert_unapproved ON html_template_revisions;
DROP FUNCTION hash_guard_html_template_revision_insert();
