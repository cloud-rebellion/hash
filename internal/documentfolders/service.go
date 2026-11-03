// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package documentfolders

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInput        = errors.New("invalid folder input")
	ErrNotFound     = errors.New("folder or document not found")
	ErrNameConflict = errors.New("a folder with this name already exists")
	ErrNotEmpty     = errors.New("move the documents before deleting this folder")
)

type Service struct {
	Pool  *pgxpool.Pool
	Audit *audit.Logger
}
type Folder struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	DocumentCount int64     `json:"document_count"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
type FolderPage struct {
	Folders []Folder `json:"folders"`
	Total   int64    `json:"total"`
	Limit   int32    `json:"limit"`
	Offset  int32    `json:"offset"`
}
type Document struct {
	Metadata generated.ListDocumentMetadataForRESTRow
	FolderID *uuid.UUID
}
type DocumentPage struct {
	Documents     []Document
	Total         int64
	Limit, Offset int32
}
type Filter struct {
	Kind string
	ID   uuid.UUID
}

func ParseFilter(values []string) (Filter, error) {
	if len(values) == 0 {
		return Filter{Kind: "all"}, nil
	}
	if len(values) != 1 {
		return Filter{}, ErrInput
	}
	if values[0] == "unfiled" {
		return Filter{Kind: "unfiled"}, nil
	}
	id, err := uuid.Parse(values[0])
	if err != nil || id == uuid.Nil {
		return Filter{}, ErrInput
	}
	return Filter{Kind: "folder", ID: id}, nil
}
func NormalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 80 {
		return "", ErrInput
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", ErrInput
		}
	}
	return name, nil
}
func validPage(limit, offset int32) bool { return limit >= 1 && limit <= 500 && offset >= 0 }
func validFilter(filter Filter) bool {
	return ((filter.Kind == "all" || filter.Kind == "unfiled") && filter.ID == uuid.Nil) || (filter.Kind == "folder" && filter.ID != uuid.Nil)
}
func classify(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == "document_folders_org_name_unique" {
		return ErrNameConflict
	}
	return err
}

func (s Service) List(ctx context.Context, org uuid.UUID, limit, offset int32) (FolderPage, error) {
	out := FolderPage{Folders: []Folder{}, Limit: limit, Offset: offset}
	if s.Pool == nil || org == uuid.Nil || !validPage(limit, offset) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM document_folders WHERE org_id=$1`, org).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT `+folderColumns+` FROM document_folders f WHERE f.org_id=$1 ORDER BY lower(f.name),f.id LIMIT $2 OFFSET $3`, org, limit, offset)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		folder, e := scanFolder(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Folders = append(out.Folders, folder)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func (s Service) ListDocuments(ctx context.Context, org uuid.UUID, status []string, filter Filter, limit, offset int32) (DocumentPage, error) {
	out := DocumentPage{Documents: []Document{}, Limit: limit, Offset: offset}
	if s.Pool == nil || org == uuid.Nil || !validPage(limit, offset) || !validFilter(filter) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	if filter.Kind == "folder" {
		var id uuid.UUID
		if err = tx.QueryRow(ctx, `SELECT id FROM document_folders WHERE id=$1 AND org_id=$2`, filter.ID, org).Scan(&id); err != nil {
			return out, classify(err)
		}
	}
	args := []any{org, status, filter.Kind, filter.ID}
	if err = tx.QueryRow(ctx, `SELECT count(*) `+documentScope, args...).Scan(&out.Total); err != nil {
		return out, err
	}
	args = append(args, limit, offset)
	rows, err := tx.Query(ctx, `SELECT `+documentProjection+` `+documentScope+` ORDER BY d.updated_at DESC,d.id DESC LIMIT $5 OFFSET $6`, args...)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		document, e := scanDocument(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Documents = append(out.Documents, document)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func mutate[T any](ctx context.Context, s Service, actor authoring.Actor, kind string, fn func(context.Context, pgx.Tx) (T, map[string]any, error)) (T, error) {
	var zero T
	if s.Pool == nil || s.Audit == nil || fn == nil {
		return zero, errors.New("folder storage unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return zero, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockAuthor(ctx, tx, actor)
	if err != nil {
		return zero, err
	}
	out, payload, err := fn(ctx, tx)
	if err != nil {
		return zero, classify(err)
	}
	// Sidecar operations have their own organization audit kind. They never
	// append document.updated or alter a completed document's event set.
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, Kind: kind, Payload: payload})
	if err != nil {
		return zero, err
	}
	if err = guard.Recheck(ctx); err != nil {
		return zero, err
	}
	if err = tx.Commit(ctx); err != nil {
		return zero, err
	}
	s.Audit.Publish(pending)
	return out, nil
}

func (s Service) Create(ctx context.Context, actor authoring.Actor, name string) (Folder, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return Folder{}, err
	}
	return mutate(ctx, s, actor, "document_folder.created", func(ctx context.Context, tx pgx.Tx) (Folder, map[string]any, error) {
		var id uuid.UUID
		err := tx.QueryRow(ctx, `INSERT INTO document_folders(org_id,name) VALUES($1,$2) RETURNING id`, actor.OrgID, name).Scan(&id)
		if err != nil {
			return Folder{}, nil, err
		}
		folder, err := getFolder(ctx, tx, actor.OrgID, id)
		return folder, map[string]any{"folder_id": id, "name": name}, err
	})
}
func (s Service) Rename(ctx context.Context, actor authoring.Actor, id uuid.UUID, name string) (Folder, error) {
	name, err := NormalizeName(name)
	if err != nil || id == uuid.Nil {
		return Folder{}, ErrInput
	}
	return mutate(ctx, s, actor, "document_folder.renamed", func(ctx context.Context, tx pgx.Tx) (Folder, map[string]any, error) {
		var found uuid.UUID
		err := tx.QueryRow(ctx, `UPDATE document_folders SET name=$3,updated_at=clock_timestamp() WHERE org_id=$1 AND id=$2 RETURNING id`, actor.OrgID, id, name).Scan(&found)
		if err != nil {
			return Folder{}, nil, err
		}
		folder, err := getFolder(ctx, tx, actor.OrgID, id)
		return folder, map[string]any{"folder_id": id, "name": name}, err
	})
}
func (s Service) Delete(ctx context.Context, actor authoring.Actor, id uuid.UUID) error {
	if id == uuid.Nil {
		return ErrInput
	}
	_, err := mutate(ctx, s, actor, "document_folder.deleted", func(ctx context.Context, tx pgx.Tx) (bool, map[string]any, error) {
		var found uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM document_folders WHERE org_id=$1 AND id=$2 FOR UPDATE`, actor.OrgID, id).Scan(&found); err != nil {
			return false, nil, err
		}
		var populated bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM document_folder_memberships m JOIN documents d ON d.id=m.document_id AND d.org_id=m.org_id WHERE m.org_id=$1 AND m.folder_id=$2 AND d.deleted_at IS NULL)`, actor.OrgID, id).Scan(&populated); err != nil {
			return false, nil, err
		}
		if populated {
			return false, nil, ErrNotEmpty
		}
		// Deleted documents remain retained. Only their now-invisible filing
		// metadata is removed so an apparently empty folder can be deleted.
		if _, err := tx.Exec(ctx, `DELETE FROM document_folder_memberships m USING documents d WHERE m.org_id=$1 AND m.folder_id=$2 AND d.id=m.document_id AND d.org_id=m.org_id AND d.deleted_at IS NOT NULL`, actor.OrgID, id); err != nil {
			return false, nil, err
		}
		_, err := tx.Exec(ctx, `DELETE FROM document_folders WHERE org_id=$1 AND id=$2`, actor.OrgID, id)
		return true, map[string]any{"folder_id": id}, err
	})
	return err
}
func (s Service) Move(ctx context.Context, actor authoring.Actor, document uuid.UUID, folder *uuid.UUID) error {
	if document == uuid.Nil || (folder != nil && *folder == uuid.Nil) {
		return ErrInput
	}
	_, err := mutate(ctx, s, actor, "document_folder.document_moved", func(ctx context.Context, tx pgx.Tx) (bool, map[string]any, error) {
		var found uuid.UUID
		// Identity-only KEY SHARE permits contract edits/signing to proceed. It
		// never reads or rewrites a signed body or its timestamps/caches.
		if err := tx.QueryRow(ctx, `SELECT id FROM documents WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL FOR KEY SHARE`, document, actor.OrgID).Scan(&found); err != nil {
			return false, nil, err
		}
		if folder == nil {
			_, err := tx.Exec(ctx, `DELETE FROM document_folder_memberships WHERE org_id=$1 AND document_id=$2`, actor.OrgID, document)
			return true, map[string]any{"document_id": document, "folder_id": nil}, err
		}
		if err := tx.QueryRow(ctx, `SELECT id FROM document_folders WHERE id=$1 AND org_id=$2 FOR KEY SHARE`, *folder, actor.OrgID).Scan(&found); err != nil {
			return false, nil, err
		}
		_, err := tx.Exec(ctx, `INSERT INTO document_folder_memberships(document_id,org_id,folder_id) VALUES($1,$2,$3) ON CONFLICT(document_id) DO UPDATE SET folder_id=EXCLUDED.folder_id WHERE document_folder_memberships.org_id=EXCLUDED.org_id`, document, actor.OrgID, *folder)
		return true, map[string]any{"document_id": document, "folder_id": *folder}, err
	})
	return err
}
