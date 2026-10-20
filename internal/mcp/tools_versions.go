// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/versions"
)

// registerVersionTools mounts the Phase 8.1 history surface for agents.
// list_document_versions, diff_document_versions, and restore_document_version
// give agents the same insight into change history that the timeline UI gives
// humans, which is the substrate the negotiation copilot (Phase 11.2) will
// drive into in Phase 11.
func registerVersionTools(s *Server, d Deps) {
	if d.Versions == nil {
		// Versions engine is optional during early bring-up; emit no tools
		// rather than error here so a stack without the migration applied
		// still serves the rest of the API.
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "list_document_versions",
		Description: "List the document's version history newest-first. Each version captures the full block tree, variables, and authorship metadata at the moment of the edit.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"limit":       intSchema("max versions to return (default 50, max 200)", 1, 200, 50),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				Limit      int    `json:"limit"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			if _, err := d.Queries.GetActiveDocumentIdentity(r.Context(), generated.GetActiveDocumentIdentityParams{ID: id, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			limit := p.Limit
			if limit <= 0 {
				limit = 50
			}
			if limit > 200 {
				limit = 200
			}
			rows, err := d.Versions.History(r.Context(), id, int32(limit))
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, v := range rows {
				out = append(out, versionToMap(v))
			}
			return map[string]any{"versions": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "diff_document_versions",
		Description: "Block-level diff between two versions. HTML-derived PDFs use declared-source and exact-PDF history instead and are refused. 'to' defaults to the latest, 'from' to to-1. Returns Added/Removed/Modified/Moved entries keyed by stable block_id, plus aggregate counts.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"from":        intSchema("source version_no (defaults to to-1)", 1, 100000, 0),
			"to":          intSchema("target version_no (defaults to latest)", 1, 100000, 0),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, retErr error) {
			defer func() {
				if cancelErr := blocks.TreeContextError(r.Context()); cancelErr != nil {
					result = nil
					retErr = cancelErr
				}
			}()
			if cancelErr := blocks.TreeContextError(r.Context()); cancelErr != nil {
				return nil, cancelErr
			}
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				From       int    `json:"from"`
				To         int    `json:"to"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			doc, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			if err := requireDocumentBlockDiff(doc); err != nil {
				return nil, err
			}
			maxNo, err := d.Queries.GetLatestDocumentVersionNo(r.Context(), id)
			if err != nil {
				return nil, err
			}
			if maxNo <= 0 {
				return map[string]any{
					"from": nil, "to": nil, "changes": []any{}, "counts": versions.DiffCounts{},
				}, nil
			}
			to := int32(p.To)
			if to <= 0 {
				to = maxNo
			}
			from := int32(p.From)
			if from <= 0 {
				from = to - 1
			}
			if from < 1 {
				from = 1
			}
			if from > to {
				return nil, errors.New("from must be <= to")
			}
			if from == to {
				v, err := d.Versions.GetByNo(r.Context(), id, to)
				if err != nil {
					return nil, err
				}
				if v.OrgID != u.OrgID {
					return nil, errors.New("version not found")
				}
				fromSide := versionSideContext(r.Context(), v)
				toSide := versionSideContext(r.Context(), v)
				if cancelErr := blocks.TreeContextError(r.Context()); cancelErr != nil {
					return nil, cancelErr
				}
				return map[string]any{
					"from":    fromSide,
					"to":      toSide,
					"changes": []any{},
					"counts":  versions.DiffCounts{},
				}, nil
			}
			fromV, err := d.Versions.GetByNo(r.Context(), id, from)
			if err != nil {
				return nil, fmt.Errorf("from v%d: %w", from, err)
			}
			toV, err := d.Versions.GetByNo(r.Context(), id, to)
			if err != nil {
				return nil, fmt.Errorf("to v%d: %w", to, err)
			}
			if fromV.OrgID != u.OrgID || toV.OrgID != u.OrgID {
				return nil, errors.New("version not found")
			}
			changes, err := versions.DiffContext(r.Context(), fromV.BlockTreeJson, toV.BlockTreeJson)
			if err != nil {
				return nil, err
			}
			fromSide := versionSideContext(r.Context(), fromV)
			toSide := versionSideContext(r.Context(), toV)
			if cancelErr := blocks.TreeContextError(r.Context()); cancelErr != nil {
				return nil, cancelErr
			}
			return map[string]any{
				"from":    fromSide,
				"to":      toSide,
				"changes": changes,
				"counts":  versions.SummarizeCounts(changes),
			}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "restore_document_version",
		Write:       true,
		Description: "Materialize a historical version onto the live draft document. Logs a 'restore' event and snapshots a new version capturing the action. Refuses on non-draft documents.",
		InputSchema: schemaObject(map[string]any{
			"expected_updated_at": stringSchema("updated_at from the observed live document"),
			"document_id":         stringSchema("document uuid (must be in draft state, source_kind=blocks)"),
			"target_version":      intSchema("version_no to restore (must already exist)", 1, 100000, 0),
		}, []string{"document_id", "target_version", "expected_updated_at"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				ExpectedUpdatedAt string `json:"expected_updated_at"`
				DocumentID        string `json:"document_id"`
				TargetVersion     int    `json:"target_version"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			if p.TargetVersion <= 0 {
				return nil, errors.New("target_version must be >= 1")
			}
			if d.Pool == nil || d.Audit == nil {
				return nil, errors.New("atomic audit dependencies unavailable")
			}
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), id, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
			defer cancel()
			tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				return nil, err
			}
			defer func() { _ = authoring.Rollback(ctx, tx) }()
			guard, err := authoring.LockDraft(ctx, tx, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
			if err != nil {
				return nil, err
			}
			q := d.Queries.WithTx(tx)
			locked := guard.Document
			if locked.SourceKind != "blocks" {
				return nil, errors.New("restore only supported on block-source documents")
			}
			actorID := guard.UserID()
			if err := checkDocumentObservation(locked, p.ExpectedUpdatedAt); err != nil {
				return nil, err
			}
			target, err := q.GetDocumentVersionByNo(ctx, generated.GetDocumentVersionByNoParams{DocumentID: id, VersionNo: int32(p.TargetVersion)})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("version not found")
			}
			if err != nil {
				return nil, err
			}
			if target.OrgID != u.OrgID {
				return nil, errors.New("version not found")
			}
			if target.SourceKind != "blocks" {
				return nil, errors.New("target version is not block-source")
			}
			if _, _, err := versions.New(q).Restore(ctx, versions.RestoreInput{
				DocumentID: id, TargetVersion: int32(p.TargetVersion), OrgID: u.OrgID, CreatedBy: &actorID,
			}); err != nil {
				return nil, err
			}
			updated, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{
				ID:            id,
				OrgID:         u.OrgID,
				BlocksJson:    target.BlockTreeJson,
				VariablesJson: target.VariablesJson,
			})
			if err != nil {
				return nil, err
			}
			pending, err := d.Audit.LogTx(ctx, tx, audit.Entry{
				OrgID:       u.OrgID,
				ActorUserID: &actorID,
				DocumentID:  &id,
				Kind:        audit.KindDocumentUpdated,
				Payload: map[string]any{
					"via":             "mcp",
					"tool":            "restore_document_version",
					"restored_from_v": target.VersionNo,
				},
			})
			if err != nil {
				return nil, err
			}
			if err := guard.Recheck(ctx); err != nil {
				return nil, err
			}
			if err := tx.Commit(ctx); err != nil {
				return nil, err
			}
			d.Audit.Publish(pending)
			return map[string]any{
				"document_id":     updated.ID.String(),
				"name":            updated.Name,
				"status":          updated.Status,
				"restored_from_v": target.VersionNo,
			}, nil
		},
	})
}

// HTML text/PDF changes cannot be represented by an empty block tree. Refuse
// before choosing latest/self/no-history shortcuts that could claim zero
// changes for different immutable materializations.
func requireDocumentBlockDiff(doc *generated.Document) error {
	if doc == nil {
		return errors.New("document not found")
	}
	if len(doc.HtmlSourceJson) != 0 || len(doc.HtmlCurrentSourceJson) != 0 || doc.HtmlCurrentMaterializationID.Valid {
		return errors.New("HTML revisions use declared-source and exact-PDF history; block-tree diff is unavailable")
	}
	return nil
}

// versionToMap shapes a generated.DocumentVersion for the MCP wire. Block tree
// and variables JSON are returned as-is so agents can pass them straight back
// to set_document_blocks for restore-without-restore patterns.
func versionToMap(v *generated.DocumentVersion) map[string]any {
	out := map[string]any{
		"id":             v.ID.String(),
		"document_id":    v.DocumentID.String(),
		"version_no":     v.VersionNo,
		"name":           v.Name,
		"source_kind":    v.SourceKind,
		"summary":        v.Summary,
		"created_via":    v.CreatedVia,
		"created_at":     v.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"schema_version": v.SchemaVersion,
		"blocks_json":    json.RawMessage(v.BlockTreeJson),
		"variables_json": json.RawMessage(v.VariablesJson),
	}
	if v.CreatedBy.Valid {
		out["created_by"] = uuid.UUID(v.CreatedBy.Bytes).String()
	}
	if v.ParentID.Valid {
		out["parent_id"] = uuid.UUID(v.ParentID.Bytes).String()
	}
	return out
}

func versionSide(v *generated.DocumentVersion) versions.DiffSide {
	return versionSideContext(context.Background(), v)
}

func versionSideContext(ctx context.Context, v *generated.DocumentVersion) versions.DiffSide {
	count, _ := mcpBlockCountContext(ctx, v.BlockTreeJson)
	return versions.DiffSide{
		VersionID:  v.ID.String(),
		VersionNo:  v.VersionNo,
		DocumentID: v.DocumentID.String(),
		BlockCount: count,
		NameAtRev:  v.Name,
	}
}

func mcpBlockCount(raw json.RawMessage) (int, error) {
	return mcpBlockCountContext(context.Background(), raw)
}

func mcpBlockCountContext(ctx context.Context, raw json.RawMessage) (int, error) {
	return blocks.CountTopLevelTreeBlocksContext(ctx, raw)
}
