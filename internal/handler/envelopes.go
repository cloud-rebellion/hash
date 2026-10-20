// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Phase 8.6 envelope REST surface. Envelopes ARE documents (with
// is_envelope=true), so the existing /documents endpoints handle GET /
// PATCH / DELETE; these handlers add the envelope-specific ops.

// POST /api/v1/documents/{id}/promote-to-envelope
func (s *Server) handlePromoteToEnvelope(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if s.Envelopes == nil {
		writeError(w, http.StatusServiceUnavailable, "envelopes engine not configured")
		return
	}
	result, err := s.mutateEnvelopeOwnedV1(r, sess.OrgID, sess.UserID, "promote_to_envelope", blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopePromoteV1, Root: id})
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		s.writeEnvelopeOwnedErrorV1(w, "promote_to_envelope", err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(result.Document))
}

// Original small single Decode caps/unknown-field/trailing behavior are kept.
func (s *Server) handleAttachToEnvelope(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	root, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		ChildID  string `json:"child_id"`
		Position int32  `json:"position"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	input, inputOK := s.newBlocksHTTPInputV1(w, r, sess.OrgID)
	if !inputOK {
		return
	}
	defer input.CloseConsumerV1()
	if err := decodeEnvelopeStreamingInputV1(input, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	child, err := uuid.Parse(in.ChildID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "child_id must be a uuid")
		return
	}
	result, err := s.mutateEnvelopeOwnedV1(r, sess.OrgID, sess.UserID, "attach_to_envelope", blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopeAttachV1, Root: root, Children: []uuid.UUID{child}, Position: in.Position})
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		s.writeEnvelopeOwnedErrorV1(w, "attach_to_envelope", err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(result.Document))
}
func (s *Server) handleDetachFromEnvelope(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	root, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		ChildID string `json:"child_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	input, inputOK := s.newBlocksHTTPInputV1(w, r, sess.OrgID)
	if !inputOK {
		return
	}
	defer input.CloseConsumerV1()
	if err := decodeEnvelopeStreamingInputV1(input, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	child, err := uuid.Parse(in.ChildID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "child_id must be a uuid")
		return
	}
	result, err := s.mutateEnvelopeOwnedV1(r, sess.OrgID, sess.UserID, "detach_from_envelope", blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopeDetachV1, Root: root, Children: []uuid.UUID{child}})
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		s.writeEnvelopeOwnedErrorV1(w, "detach_from_envelope", err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(result.Document))
}
func (s *Server) handleReorderEnvelope(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	root, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		ChildIDs []string `json:"child_ids"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	input, inputOK := s.newBlocksHTTPInputV1(w, r, sess.OrgID)
	if !inputOK {
		return
	}
	defer input.CloseConsumerV1()
	if err := decodeEnvelopeStreamingInputV1(input, r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	ids := make([]uuid.UUID, 0, len(in.ChildIDs))
	for _, raw := range in.ChildIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "child_ids must be uuids")
			return
		}
		ids = append(ids, id)
	}
	result, err := s.mutateEnvelopeOwnedV1(r, sess.OrgID, sess.UserID, "reorder_envelope", blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopeReorderV1, Root: root, Children: ids})
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		s.writeEnvelopeOwnedErrorV1(w, "reorder_envelope", err)
		return
	}
	out := make([]any, 0, len(result.Children))
	for _, child := range result.Children {
		out = append(out, toEnvelopeChildMetadataResponse(child))
	}
	writeJSON(w, http.StatusOK, map[string]any{"children": out, "count": len(out)})
}

// GET /api/v1/envelopes/{id}/children
func (s *Server) handleListEnvelopeChildren(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	envelopeID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	children, err := s.Queries.ListEnvelopeChildMetadataForRead(r.Context(), generated.ListEnvelopeChildMetadataForReadParams{
		ParentEnvelopeID: pgtype.UUID{Bytes: envelopeID, Valid: true}, OrgID: sess.OrgID,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]any, 0, len(children))
	for _, c := range children {
		out = append(out, toEnvelopeChildMetadataResponse(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"children": out, "count": len(out)})
}

// GET /api/v1/envelopes/{id}/manifest
//
// Returns the audit-cert manifest as JSON. The same shape is rendered
// inside the cert HTML for an envelope's PDFs.
func (s *Server) handleEnvelopeManifest(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	envelopeID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	env, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: envelopeID, OrgID: sess.OrgID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "envelope not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	if !env.IsEnvelope {
		writeError(w, http.StatusBadRequest, "document is not an envelope")
		return
	}
	manifest, err := s.Envelopes.BuildManifest(r.Context(), env)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, manifest)
}
