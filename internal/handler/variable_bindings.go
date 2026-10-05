// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
)

// resolveVariables is the single render-time path: every preview, signer
// view, and final-PDF render goes through here so resolution rules stay in
// one place. When the document is non-draft (sent / in_progress / completed
// / etc), we run in FreezeMode so live binding fetches never alter what a
// signed document renders.
func (s *Server) resolveVariables(ctx context.Context, doc *generated.Document) (map[string]string, []resolver.ResolveReport, error) {
	if s.Resolver == nil {
		// fall back to the static-only behaviour from week 2
		out := map[string]string{}
		if len(doc.VariablesJson) > 0 {
			var raw map[string]any
			if err := json.Unmarshal(doc.VariablesJson, &raw); err == nil {
				for k, v := range raw {
					if str, ok := v.(string); ok {
						out[k] = str
					}
				}
			}
		}
		return out, nil, nil
	}
	opts := resolver.ResolveOptions{}
	if doc.Status != "draft" {
		opts.FreezeMode = true
	}
	return s.Resolver.Resolve(ctx, doc, opts)
}

// bindingDTO is the wire shape returned by both REST and MCP for a single
// binding row.
type bindingDTO struct {
	Variable     string `json:"variable"`
	SourceKind   string `json:"source_kind"`
	SourceRef    string `json:"source_ref,omitempty"`
	SourcePath   string `json:"source_path,omitempty"`
	Fallback     string `json:"fallback,omitempty"`
	LastValue    string `json:"last_value,omitempty"`
	LastResolved string `json:"last_resolved,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	UpdatedAt    string `json:"updated_at"`
}

func bindingToDTO(b *generated.DocumentVariableBinding) bindingDTO {
	out := bindingDTO{
		Variable:   b.VariableName,
		SourceKind: b.SourceKind,
		SourceRef:  b.SourceRef,
		SourcePath: b.SourcePath,
		Fallback:   b.Fallback,
		LastValue:  b.LastValue,
		LastError:  b.LastError,
		UpdatedAt:  b.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if b.LastResolved.Valid {
		out.LastResolved = b.LastResolved.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return out
}

// GET /api/v1/documents/{id}/variable-bindings
func (s *Server) handleListVariableBindings(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	rows, err := s.Queries.ListVariableBindings(r.Context(), docID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]bindingDTO, 0, len(rows))
	for _, b := range rows {
		out = append(out, bindingToDTO(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": out, "count": len(out)})
}

// PUT /api/v1/documents/{id}/variable-bindings/{name}
//
// Body: { "source_kind": "...", "source_ref": "...", "source_path": "...", "fallback": "..." }
func (s *Server) handleUpsertVariableBinding(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "variable name required")
		return
	}
	var in struct {
		SourceKind string `json:"source_kind"`
		SourceRef  string `json:"source_ref"`
		SourcePath string `json:"source_path"`
		Fallback   string `json:"fallback"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := resolver.ValidateBinding(name, resolver.SourceKind(in.SourceKind), in.SourceRef, in.SourcePath, in.Fallback); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	authorize, ok := s.sessionMutationAuthorization(w, r, sess)
	if !ok {
		return
	}
	row, err := s.mutateVariableBinding(r, sess, authorize, docID, name, "upsert_variable_binding", in.SourceKind, func(ctx context.Context, q *generated.Queries) (*generated.DocumentVariableBinding, error) {
		return q.UpsertVariableBinding(ctx, generated.UpsertVariableBindingParams{
			DocumentID: docID, VariableName: name, SourceKind: in.SourceKind,
			SourceRef: in.SourceRef, SourcePath: in.SourcePath, Fallback: in.Fallback,
		})
	})
	if err != nil {
		s.writeDraftAuthoringError(w, "mutate variable binding", err)
		return
	}
	writeJSON(w, http.StatusOK, bindingToDTO(row))
}

// DELETE /api/v1/documents/{id}/variable-bindings/{name}
func (s *Server) handleDeleteVariableBinding(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "variable name required")
		return
	}
	if err := resolver.ValidateBindingName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	authorize, ok := s.sessionMutationAuthorization(w, r, sess)
	if !ok {
		return
	}
	if _, err := s.mutateVariableBinding(r, sess, authorize, docID, name, "delete_variable_binding", "", func(ctx context.Context, q *generated.Queries) (*generated.DocumentVariableBinding, error) {
		return nil, q.DeleteVariableBinding(ctx, generated.DeleteVariableBindingParams{DocumentID: docID, VariableName: name})
	}); err != nil {
		s.writeDraftAuthoringError(w, "mutate variable binding", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) mutateVariableBinding(r *http.Request, sess auth.SessionUser, authorize auth.TransactionAuthorization,
	docID uuid.UUID, name, tool, sourceKind string, mutation func(context.Context, *generated.Queries) (*generated.DocumentVariableBinding, error),
) (*generated.DocumentVariableBinding, error) {
	if s.Pool == nil || s.Audit == nil {
		return nil, errors.New("atomic variable binding dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin variable binding mutation: %w", err)
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockDraft(ctx, tx, authoring.Actor{OrgID: sess.OrgID, UserID: sess.UserID, Authorize: authorize}, docID)
	if err != nil {
		return nil, err
	}
	row, err := mutation(ctx, generated.New(tx))
	if err != nil {
		return nil, fmt.Errorf("mutate variable binding: %w", err)
	}
	actorID := guard.UserID()
	payload := map[string]any{"via": "rest", "tool": tool, "variable": name}
	if sourceKind != "" {
		payload["source_kind"] = sourceKind
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &actorID, DocumentID: &docID, Kind: audit.KindDocumentUpdated,
		IP: firstIPFromHeader(r), UserAgent: r.UserAgent(), Payload: payload,
	})
	if err != nil {
		return nil, fmt.Errorf("audit variable binding mutation: %w", err)
	}
	if err := guard.Recheck(ctx); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit variable binding mutation: %w", err)
	}
	s.Audit.Publish(pending)
	return row, nil
}

// GET /api/v1/documents/{id}/resolve-preview
//
// Returns the resolved variable map plus a per-binding ResolveReport so the
// editor can display "var X resolved from CRM, var Y from fallback" without
// running its own resolver client-side.
func (s *Server) handleResolvePreview(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	resolved, report, err := s.resolveVariables(r.Context(), doc)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"variables": resolved,
		"report":    report,
		"frozen":    doc.Status != "draft",
	})
}
