-- +goose Up
-- Workspace organization only: folder membership never changes a document,
-- its signing source, updated_at, evidence, or native measurement caches.
CREATE TABLE document_folders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80 AND name = btrim(name)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (id, org_id)
);
CREATE UNIQUE INDEX document_folders_org_name_unique ON document_folders(org_id, lower(name));
CREATE INDEX document_folders_org_order ON document_folders(org_id, lower(name), id);

CREATE TABLE document_folder_memberships (
    document_id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    folder_id UUID NOT NULL,
    FOREIGN KEY (document_id, org_id) REFERENCES documents(id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id, org_id) REFERENCES document_folders(id, org_id) ON DELETE NO ACTION DEFERRABLE INITIALLY IMMEDIATE
);
CREATE INDEX document_folder_memberships_org_folder ON document_folder_memberships(org_id, folder_id, document_id);

-- +goose Down
-- Removing this optional organization feature unfiles documents; no document
-- content, signature, evidence, or source measurement is deleted or rewritten.
DROP TABLE document_folder_memberships;
DROP TABLE document_folders;
