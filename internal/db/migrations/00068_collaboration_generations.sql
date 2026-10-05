-- +goose Up
-- Reconciliation foundation: this ledger tracks canonical tree generations.
-- It does not itself fence CRDT writes; matching server/client wiring is required.
CREATE TABLE collab_document_generations (
    document_id uuid PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0)
);
INSERT INTO collab_document_generations (document_id) SELECT id FROM documents;

-- +goose StatementBegin
CREATE FUNCTION hash_track_canonical_collab_generation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO collab_document_generations (document_id) VALUES (NEW.id);
    ELSIF NEW.blocks_json IS DISTINCT FROM OLD.blocks_json THEN
        INSERT INTO collab_document_generations (document_id, generation)
        VALUES (NEW.id, 2)
        ON CONFLICT (document_id) DO UPDATE
        SET generation = collab_document_generations.generation + 1;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER hash_canonical_collab_generation
AFTER INSERT OR UPDATE OF blocks_json ON documents
FOR EACH ROW EXECUTE FUNCTION hash_track_canonical_collab_generation();

-- +goose Down
-- Reusing old generation numbers after a rollback could admit stale clients.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM collab_document_generations WHERE generation > 1) THEN
        RAISE EXCEPTION 'preserve advanced collaboration generations before rollback';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER hash_canonical_collab_generation ON documents;
DROP FUNCTION hash_track_canonical_collab_generation();
DROP TABLE collab_document_generations;
