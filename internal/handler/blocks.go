// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/resolver"
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
	input, inputOK := s.newBlocksHTTPInputV1(w, r, u.OrgID)
	if !inputOK {
		return
	}
	defer input.CloseConsumerV1()
	if err := decodeBlocksStreamingInputV1(input, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:append_block", func(t *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
		t.Blocks = append(t.Blocks, in.Block)
		return blocks.ValidateForSendV1(t, admission)
	}, in.ExpectedUpdatedAt)
	if doc != nil {
		defer doc.CloseConsumerV1()
	}
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc.Document))
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
	input, inputOK := s.newBlocksHTTPInputV1(w, r, u.OrgID)
	if !inputOK {
		return
	}
	defer input.CloseConsumerV1()
	if err := decodeBlocksStreamingInputV1(input, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:update_block", func(t *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
		for i := range t.Blocks {
			if t.Blocks[i].ID == bid {
				in.Block.ID = bid
				t.Blocks[i] = in.Block
				return blocks.ValidateForSendV1(t, admission)
			}
		}
		return errors.New("block not found")
	}, in.ExpectedUpdatedAt)
	if doc != nil {
		defer doc.CloseConsumerV1()
	}
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc.Document))
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
	input, inputOK := s.newBlocksHTTPInputV1(w, r, u.OrgID)
	if !inputOK {
		return
	}
	defer input.CloseConsumerV1()
	if err := decodeBlocksStreamingInputV1(input, r, &in); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:delete_block", func(t *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
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
	if doc != nil {
		defer doc.CloseConsumerV1()
	}
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc.Document))
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
	input, inputOK := s.newBlocksHTTPInputV1(w, r, u.OrgID)
	if !inputOK {
		return
	}
	defer input.CloseConsumerV1()
	if err := decodeBlocksStreamingInputV1(input, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	doc, err := s.mutateTree(r, u.OrgID, u.UserID, docID, "rest:reorder_blocks", func(t *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
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
	if doc != nil {
		defer doc.CloseConsumerV1()
	}
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc.Document))
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
	input, inputOK := s.newBlocksHTTPInputV1(w, r, u.OrgID)
	if !inputOK {
		return
	}
	defer input.CloseConsumerV1()
	if err := decodeBlocksStreamingInputV1(input, r, &in); err != nil {
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
	if doc != nil {
		defer doc.CloseConsumerV1()
	}
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc.Document))
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
	input, inputOK := s.newBlocksHTTPInputV1(w, r, u.OrgID)
	if !inputOK {
		return
	}
	defer input.CloseConsumerV1()
	if err := decodeBlocksStreamingInputV1(input, r, &in); err != nil {
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
	if doc != nil {
		defer doc.CloseConsumerV1()
	}
	if err != nil {
		s.writeBlockMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc.Document))
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
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writePreviewError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), resolver.PreviewTimeout)
	defer cancel()
	doc, err := s.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
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
	vars, report, err := s.resolveVariables(ctx, doc)
	if err != nil {
		writeInternalErrorMsg(w, "resolve vars", err)
		return
	}
	// Discovery has its own explicit observation endpoint. A contract preview
	// must not silently depict fresh CRM text that has not been applied yet.
	if doc.Status == "draft" {
		if err := resolver.CheckReviewedCRMValues(doc, report); err != nil {
			s.writePreviewError(w, err)
			return
		}
	}
	body := blocks.RenderHTML(tree, vars)
	brand, err := s.resolveBrandingForDoc(ctx, doc)
	if err != nil {
		writeInternalErrorMsg(w, "resolve branding", err)
		return
	}
	if err := resolver.CheckPreview(ctx, s.Pool, doc, report, u.UserID, authorize); err != nil {
		s.writePreviewError(w, err)
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
func (s *Server) mutateTree(r *http.Request, orgID, userID uuid.UUID, docID uuid.UUID, toolName string, fn pdfadmission.BlocksEditV1, expected string) (*blockauthoring.ResultV1, error) {
	return s.mutateTreeVia(r, orgID, userID, docID, versions.ViaHuman, toolName, fn, expected)
}
func (s *Server) mutateTreeVia(r *http.Request, orgID, userID uuid.UUID, docID uuid.UUID, via versions.Via, toolName string, fn pdfadmission.BlocksEditV1, expected string) (*blockauthoring.ResultV1, error) {
	authorize, err := s.sessionDraftAuthorization(r, orgID, userID)
	if err != nil {
		return nil, err
	}
	return blockauthoring.MutateTreeV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit, SnapshotMutation: s.Versions != nil}, blockauthoring.ActorV1{OrgID: orgID, UserID: userID, Authorize: authorize, Via: "rest", Tool: toolName, IP: firstIPFromHeader(r), UserAgent: r.UserAgent()}, docID, via, expected, checkRESTBlockObservationV1, fn)
}
func checkRESTBlockObservationV1(existing *generated.Document, expected string) error {
	if expected == "" {
		return errBlockObservationMissing
	}
	stamp, err := time.Parse(time.RFC3339Nano, expected)
	if err != nil {
		return errBlockObservationMalformed
	}
	if existing == nil || !existing.UpdatedAt.Valid || !existing.UpdatedAt.Time.Equal(stamp) {
		return errBlockObservationStale
	}
	return nil
}

// replaceTree replaces the entire block tree in one shot. Used by import
// endpoints.
func (s *Server) replaceTree(r *http.Request, orgID, userID uuid.UUID, docID uuid.UUID, toolName string, tree *blocks.Tree, expected string) (*blockauthoring.ResultV1, error) {
	if err := blocks.Validate(tree); err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}
	return s.mutateTreeVia(r, orgID, userID, docID, versions.ViaImport, toolName, func(current *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
		*current = *tree
		return nil
	}, expected)
}

// mapMutationStatus turns errors back into HTTP statuses.
var errBlockObservationMissing = errors.New("expected_updated_at is required")
var errBlockObservationMalformed = errors.New("expected_updated_at must be RFC3339")
var errBlockObservationStale = errors.New("Document changed since observation. Fetch and review before replacing the block.")

func mapMutationStatus(err error) int {
	if pdfadmission.IsInternalApplicationWriteFailureV1(err) {
		return http.StatusInternalServerError
	}
	if errors.Is(err, pdfadmission.ErrBlocksInputV1) || errors.Is(err, pdfadmission.ErrBlocksWriterV1) || errors.Is(err, pdfadmission.ErrHTMLRevisionReadV1) || errors.Is(err, pdfadmission.ErrApplicationAdmissionV1) || errors.Is(err, pdfadmission.ErrApplicationSessionV1) {
		return http.StatusServiceUnavailable
	}
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
	if status == http.StatusServiceUnavailable {
		writeError(w, status, "block editing capacity unavailable; retry later")
		return
	}
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
