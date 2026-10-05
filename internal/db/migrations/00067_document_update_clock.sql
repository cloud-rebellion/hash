-- +goose Up
-- A transaction may begin before a competing writer commits. now() alone can
-- therefore move updated_at backwards or repeat it. Every writer advances the
-- row clock after acquiring the update lock, including machine/lifecycle writes.
-- +goose StatementBegin
CREATE FUNCTION hash_advance_document_update_clock() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := GREATEST(clock_timestamp(), OLD.updated_at + interval '1 microsecond');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER hash_document_update_clock BEFORE UPDATE ON documents
FOR EACH ROW EXECUTE FUNCTION hash_advance_document_update_clock();

-- +goose Down
DROP TRIGGER hash_document_update_clock ON documents;
DROP FUNCTION hash_advance_document_update_clock();
