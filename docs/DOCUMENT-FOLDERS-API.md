# Document folders

Migration 118 adds a single level of organization-scoped folders. Filing is
workspace metadata: it does not edit the contract, change `documents.updated_at`,
invalidate source measurements, alter signing evidence, or require another
signature. Completed documents can be moved just like drafts.

These staff endpoints use the existing signed session, CSRF and tenant boundary.
Viewers can list. Senders and owners can create, rename, move and delete empty
folders; their live membership and original credential are retained through
each write transaction. Folder names contain 1–80 characters without control
characters; surrounding whitespace is removed. Names are unique within the
organization ignoring database case. Folder names and movement IDs are recorded
in their own organization audit events, not `document.updated` events.

| Request | Body or query | Result |
| --- | --- | --- |
| `GET /api/v1/document-folders` | Optional `limit` (default100, max500), `offset` | `{folders:[{id,name,document_count,created_at,updated_at}],total,limit,offset}` |
| `POST /api/v1/document-folders` | `{ "name": "Customers" }` | 201 `{folder:{...}}` |
| `PATCH /api/v1/document-folders/{folderId}` | `{ "name": "Partners" }` | 200 `{folder:{...}}` |
| `DELETE /api/v1/document-folders/{folderId}` | None | 204, or409 when active documents remain |
| `PUT /api/v1/documents/{id}/folder` | `{ "folder_id": "folder UUID" }` or `{ "folder_id": null }` | 200 `{document_id,folder_id}` |
| `GET /api/v1/documents` | Omit `folder_id` for All; use `folder_id=unfiled` or one folder UUID | Existing list plus `folder_id:null\|UUID` for each document |

The document list combines its existing repeated `status` filter with the folder
filter before SQL pagination. Count and rows use the same predicate in one
read-only repeatable-read snapshot. Duplicate `folder_id` parameters are refused.
Missing or foreign folders/documents return404. Duplicate folder names and
nonempty deletion return409. Invalid input returns400. Folder deletion never
deletes documents. When a folder contains only already-deleted documents, it can
be deleted after removing only those documents' invisible filing metadata.

This API does not add nested folders, public signer access, API-key write routes,
or changes to organization/document visibility. Database composite foreign keys
also enforce both tenant boundaries. Moving a document to another organization's
folder is refused even if its UUID is known.

Apply the bundled database migrations before using these endpoints.
