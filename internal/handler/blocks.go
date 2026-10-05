// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/versions"
)

// Block CRUD endpoints. Same shape the MCP authoring tools call into;
// shared via mutateTree below so REST + MCP stay consistent.

type appendBlockInput struct {
	ExpectedUpdatedAt string       `json:"expected_updated_at"`
	Block             blocks.Block `json:"block"`
}

func (s *Server) handleAppendBlock(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in appendBlockInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:append_block", func(t *blocks.Tree) error {
		t.Blocks = append(t.Blocks, in.Block)
		return blocks.Validate(t)
	}, in.ExpectedUpdatedAt)
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type updateBlockInput struct {
	ExpectedUpdatedAt string       `json:"expected_updated_at"`
	Block             blocks.Block `json:"block"`
}

func (s *Server) handleUpdateBlock(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	bid := chiURLParam(r, "bid")
	if bid == "" {
		writeError(w, http.StatusBadRequest, "block id required")
		return
	}
	var in updateBlockInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:update_block", func(t *blocks.Tree) error {
		for i := range t.Blocks {
			if t.Blocks[i].ID == bid {
				in.Block.ID = bid
				t.Blocks[i] = in.Block
				return blocks.Validate(t)
			}
		}
		return errors.New("block not found")
	}, in.ExpectedUpdatedAt)
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

func (s *Server) handleDeleteBlock(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	bid := chiURLParam(r, "bid")
	if bid == "" {
		writeError(w, http.StatusBadRequest, "block id required")
		return
	}
	var in struct {
		ExpectedUpdatedAt string `json:"expected_updated_at"`
	}
	if err := decodeJSON(r, &in); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:delete_block", func(t *blocks.Tree) error {
		filtered := make([]blocks.Block, 0, len(t.Blocks))
		removed := false
		for _, b := range t.Blocks {
			if b.ID == bid {
				removed = true
				continue
			}
			filtered = append(filtered, b)
		}
		if !removed {
			return errors.New("block not found")
		}
		t.Blocks = filtered
		return nil
	}, in.ExpectedUpdatedAt)
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type reorderBlocksInput struct {
	BlockIDs          []string `json:"block_ids"`
	ExpectedUpdatedAt string   `json:"expected_updated_at"`
}

func (s *Server) handleReorderBlocks(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in reorderBlocksInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:reorder_blocks", func(t *blocks.Tree) error {
		if len(in.BlockIDs) != len(t.Blocks) {
			return errors.New("block_ids length must equal top-level block count")
		}
		byID := map[string]blocks.Block{}
		for _, b := range t.Blocks {
			byID[b.ID] = b
		}
		seen := map[string]bool{}
		out := make([]blocks.Block, 0, len(in.BlockIDs))
		for _, id := range in.BlockIDs {
			b, ok := byID[id]
			if !ok || seen[id] {
				return fmt.Errorf("unknown or duplicate block id: %s", id)
			}
			seen[id] = true
			out = append(out, b)
		}
		t.Blocks = out
		return nil
	}, in.ExpectedUpdatedAt)
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type importHTMLInput struct {
	HTML              string `json:"html"`
	ExpectedUpdatedAt string `json:"expected_updated_at"`
}

func (s *Server) handleImportHTML(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusTooManyRequests, "import capacity busy; retry later")
		return
	}
	defer release()
	var in importHTMLInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := malwarescan.ScanActive(r.Context(), []byte(in.HTML)); err != nil {
		writeScanError(w, err)
		return
	}
	tree, err := blocks.ParseHTMLChecked(in.HTML)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.replaceTree(r, u.OrgID, u.UserID, docID, "rest:import_html", tree, in.ExpectedUpdatedAt)
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type importMarkdownInput struct {
	Markdown          string `json:"markdown"`
	ExpectedUpdatedAt string `json:"expected_updated_at"`
}

func (s *Server) handleImportMarkdown(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusTooManyRequests, "import capacity busy; retry later")
		return
	}
	defer release()
	var in importMarkdownInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := malwarescan.ScanActive(r.Context(), []byte(in.Markdown)); err != nil {
		writeScanError(w, err)
		return
	}
	tree, err := blocks.ParseMarkdownChecked(in.Markdown)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.replaceTree(r, u.OrgID, u.UserID, docID, "rest:import_markdown", tree, in.ExpectedUpdatedAt)
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

func (s *Server) handlePreviewHTML(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if doc.SourceKind != "blocks" {
		writeError(w, http.StatusBadRequest, "preview is only for blocks-source documents")
		return
	}
	tree, err := blocks.ParseTree(doc.BlocksJson)
	if err != nil {
		writeInternalErrorMsg(w, "stored blocks invalid", err)
		return
	}
	vars, _, err := s.resolveVariables(r.Context(), doc)
	if err != nil {
		writeInternalErrorMsg(w, "resolve vars", err)
		return
	}
	body := blocks.RenderHTML(tree, vars)
	brand, err := s.resolveBrandingForDoc(r.Context(), doc)
	if err != nil {
		writeInternalErrorMsg(w, "resolve branding", err)
		return
	}
	html := brand.CSSVariables() + body
	setDocumentPreviewHeaders(w, true)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// mutateTree loads the doc, applies fn to its block tree, persists, and
// audits. Every REST caller supplies the reviewed document timestamp; MCP
// enforces the same invariant in its own transactional helper.
func (s *Server) mutateTree(r *http.Request, orgID, userID uuid.UUID, docID uuid.UUID, toolName string, fn func(*blocks.Tree) error, expected string) (*generated.Document, error) {
	return s.mutateTreeVia(r, orgID, userID, docID, versions.ViaHuman, toolName, fn, expected)
}

func (s *Server) mutateTreeVia(r *http.Request, orgID, userID uuid.UUID, docID uuid.UUID, via versions.Via, toolName string, fn func(*blocks.Tree) error, expected string) (*generated.Document, error) {
	authorize, err := s.sessionDraftAuthorization(r, orgID, userID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockDraft(ctx, tx, authoring.Actor{OrgID: orgID, UserID: userID, Authorize: authorize}, docID)
	if err != nil {
		return nil, err
	}
	q := s.Queries.WithTx(tx)
	existing := guard.Document
	if existing.SourceKind != "blocks" {
		return nil, authoring.ErrDocumentNotDraft
	}
	actorID := guard.UserID()
	if expected == "" {
		return nil, errBlockObservationMissing
	}
	stamp, err := time.Parse(time.RFC3339Nano, expected)
	if err != nil {
		return nil, errBlockObservationMalformed
	}
	if !existing.UpdatedAt.Valid || !existing.UpdatedAt.Time.Equal(stamp) {
		return nil, errBlockObservationStale
	}

	tree, err := blocks.ParseTree(existing.BlocksJson)
	if err != nil {
		return nil, fmt.Errorf("existing blocks_json invalid: %w", err)
	}
	if err := fn(tree); err != nil {
		return nil, err
	}
	if err := blocks.Validate(tree); err != nil {
		return nil, fmt.Errorf("post-edit validation: %w", err)
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	doc, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{
		ID: docID, OrgID: orgID, BlocksJson: raw, VariablesJson: existing.VariablesJson,
	})
	if err != nil {
		return nil, err
	}
	if s.Versions != nil {
		if _, err := versions.New(q).Snapshot(ctx, versions.SnapshotInput{
			DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind,
			BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &actorID,
			Via: via, Summary: toolName,
		}); err != nil {
			return nil, err
		}
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: orgID, ActorUserID: &actorID, DocumentID: &docID,
		Kind:      audit.KindDocumentUpdated,
		IP:        firstIPFromHeader(r),
		UserAgent: r.UserAgent(),
		Payload:   map[string]any{"via": "rest", "tool": toolName, "blocks": len(tree.Blocks)},
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
	s.Audit.Publish(pending)
	return doc, nil
}

// replaceTree replaces the entire block tree in one shot. Used by import
// endpoints.
func (s *Server) replaceTree(r *http.Request, orgID, userID uuid.UUID, docID uuid.UUID, toolName string, tree *blocks.Tree, expected string) (*generated.Document, error) {
	if err := blocks.Validate(tree); err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}
	return s.mutateTreeVia(r, orgID, userID, docID, versions.ViaImport, toolName, func(current *blocks.Tree) error {
		*current = *tree
		return nil
	}, expected)
}

// mapMutationStatus turns errors back into HTTP statuses.
var errBlockObservationMissing = errors.New("expected_updated_at is required")
var errBlockObservationMalformed = errors.New("expected_updated_at must be RFC3339")
var errBlockObservationStale = errors.New("Document changed since observation. Fetch and review before replacing the block.")

func mapMutationStatus(err error) int {
	var postgresError *pgconn.PgError
	var connectionError *pgconn.ConnectError
	if errors.Is(err, pgx.ErrNoRows) || errors.As(err, &postgresError) || errors.As(err, &connectionError) {
		return http.StatusInternalServerError
	}
	if status, ok := draftAuthoringErrorStatus(err); ok {
		return status
	}
	for _, invalid := range []error{blocks.ErrInvalidBlock, blocks.ErrUnknownType, blocks.ErrSchemaVersion, blocks.ErrMissingID, blocks.ErrDuplicateID} {
		if errors.Is(err, invalid) {
			return http.StatusBadRequest
		}
	}
	if errors.Is(err, errBlockObservationMissing) {
		return http.StatusPreconditionRequired
	}
	if errors.Is(err, errBlockObservationMalformed) {
		return http.StatusBadRequest
	}
	if errors.Is(err, errBlockObservationStale) {
		return http.StatusPreconditionFailed
	}
	if errors.Is(err, errNotFound) {
		return http.StatusNotFound
	}
	msg := err.Error()
	switch {
	case msgContains(msg, "block not found"), msgContains(msg, "unknown or duplicate"), msgContains(msg, "block_ids length"):
		return http.StatusBadRequest
	case msgContains(msg, "not editable"), msgContains(msg, "not in draft"):
		return http.StatusConflict
	case msgContains(msg, "validation"):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func (s *Server) writeBlockMutationError(w http.ResponseWriter, err error) {
	status := mapMutationStatus(err)
	if status == http.StatusInternalServerError {
		s.writeDraftAuthoringError(w, "mutate blocks", err)
		return
	}
	writeError(w, status, err.Error())
}

func msgContains(s, substr string) bool {
	return len(s) >= len(substr) && (indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func chiURLParam(r *http.Request, name string) string {
	return chi.URLParam(r, name)
}

func firstIPFromHeader(r *http.Request) string {
	// The outermost production middleware has already resolved Caddy's
	// authenticated single client address into RemoteAddr and stripped all
	// forwarding headers. Re-reading a raw header here would undo that boundary.
	return clientIP(r)
}
