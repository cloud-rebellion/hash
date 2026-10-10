// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type savePDFTemplateInput struct {
	Name              string                 `json:"name"`
	ExpectedUpdatedAt string                 `json:"expected_updated_at"`
	ExpectedFieldIDs  []uuid.UUID            `json:"expected_field_ids"`
	Parties           []savePDFTemplateParty `json:"parties"`
}

type savePDFTemplateParty struct {
	RecipientID uuid.UUID `json:"recipient_id"`
	Role        string    `json:"role"`
	Label       string    `json:"label"`
}

// handleSavePDFTemplate exports a fresh locked draft's signature placement into
// named slots. Recipient identities, IDs, tokens and captured values are never
// part of the reusable design. The isolated parser runs before the transaction;
// its exact source identity is then checked under the draft guard.
func (s *Server) handleSavePDFTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in savePDFTemplateInput
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 800 {
		writeError(w, http.StatusBadRequest, "template name is required and must be at most 800 bytes")
		return
	}
	if in.ExpectedUpdatedAt == "" {
		writeError(w, http.StatusPreconditionRequired, "expected_updated_at is required")
		return
	}
	expected, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "expected_updated_at must be RFC3339")
		return
	}
	if len(in.ExpectedFieldIDs) == 0 || len(in.ExpectedFieldIDs) > pdflayout.MaxFields || len(in.Parties) == 0 || len(in.Parties) > pdflayout.MaxParties {
		writeError(w, http.StatusBadRequest, "provide the observed signature field IDs and complete party slots")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize PDF layout", err)
		return
	}
	if s.Pool == nil || s.Audit == nil || s.Storage == nil {
		writeInternalErrorMsg(w, "save PDF layout", errors.New("PDF layout dependencies unavailable"))
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		writeError(w, http.StatusTooManyRequests, "PDF layout inspection is busy; retry later")
		return
	}
	defer release()
	inspectionCtx, inspectionCancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer inspectionCancel()
	admitted, err := s.Queries.GetDocument(inspectionCtx, generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if admitted.SourceKind != "pdf" || admitted.Status != "draft" {
		writeError(w, http.StatusConflict, "save a PDF layout from an editable PDF draft")
		return
	}
	if !admitted.UpdatedAt.Valid || !expected.Equal(admitted.UpdatedAt.Time) {
		writeError(w, http.StatusPreconditionFailed, "document changed; review the current design")
		return
	}
	if !admitted.PdfStorageKey.Valid || len(admitted.PdfSha256) != sha256.Size {
		writeError(w, http.StatusConflict, "PDF source has no verified content commitment")
		return
	}
	body, err := readDocumentArtifact(inspectionCtx, s.Storage, admitted, admitted.PdfStorageKey.String, admitted.PdfSha256, admitted.PdfStorageVersionID)
	if err != nil {
		writeInternalErrorMsg(w, "verify PDF layout source", err)
		return
	}
	pages, err := sanitize.PageCountWithContext(inspectionCtx, body)
	if err != nil || pages < 1 || pages > sanitize.MaxPDFPages {
		if err == nil {
			err = errors.New("source page count exceeds intake limit")
		}
		writeInternalErrorMsg(w, "inspect PDF layout pages", err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockDraft(ctx, tx, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
	if err != nil {
		s.writeDraftAuthoringError(w, "save PDF layout", err)
		return
	}
	current := guard.Document
	if !samePDFTemplateSource(admitted, current) || !current.UpdatedAt.Time.Equal(expected) {
		writeError(w, http.StatusPreconditionFailed, "document or PDF source changed; review the current design")
		return
	}
	q := generated.New(tx)
	recs, err := q.ListRecipientsByDocument(ctx, id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	fields, err := q.ListFieldsByDocument(ctx, id)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	layout, err := exportPDFLayout(current, recs, fields, in, int32(pages))
	if errors.Is(err, pdflayout.ErrPrecondition) {
		writeError(w, http.StatusPreconditionFailed, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	canonical, err := json.Marshal(layout)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	template, err := q.CreatePDFTemplate(ctx, generated.CreatePDFTemplateParams{
		OrgID: u.OrgID, Name: strings.TrimSpace(in.Name), CreatedBy: u.UserID, PdfStorageKey: current.PdfStorageKey, PdfSha256: current.PdfSha256,
		PdfStorageVersionID: current.PdfStorageVersionID, EvidenceVersionPinRequired: current.EvidenceVersionPinsRequired,
		PageCount: pgtype.Int4{Int32: int32(pages), Valid: true}, FieldsJson: canonical,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id, Kind: audit.KindTemplateCreated,
		Payload: map[string]any{"template_id": template.ID, "source_kind": "pdf", "name": template.Name, "layout_version": layout.Version, "party_count": len(layout.Parties), "field_count": len(layout.Fields)}})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := guard.Recheck(ctx); err != nil {
		s.writeDraftAuthoringError(w, "save PDF layout", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pending)
	writeTemplateResponse(w, http.StatusCreated, template)
}

func samePDFTemplateSource(a, b *generated.Document) bool {
	return a != nil && b != nil && b.SourceKind == "pdf" && a.PdfStorageKey == b.PdfStorageKey && a.PdfStorageVersionID == b.PdfStorageVersionID &&
		a.EvidenceVersionPinsRequired == b.EvidenceVersionPinsRequired && bytes.Equal(a.PdfSha256, b.PdfSha256)
}

func exportPDFLayout(doc *generated.Document, recs []*generated.Recipient, fields []*generated.DocumentField, in savePDFTemplateInput, pages int32) (*pdflayout.Layout, error) {
	if len(fields) != len(in.ExpectedFieldIDs) {
		return nil, pdflayout.ErrPrecondition
	}
	expected := make(map[uuid.UUID]bool, len(in.ExpectedFieldIDs))
	for _, id := range in.ExpectedFieldIDs {
		if id == uuid.Nil || expected[id] {
			return nil, fmt.Errorf("%w: observed field IDs must be unique", pdflayout.ErrInvalid)
		}
		expected[id] = true
	}
	currentRecipients := make(map[uuid.UUID]*generated.Recipient, len(recs))
	for _, rec := range recs {
		if rec != nil && rec.DocumentID == doc.ID {
			currentRecipients[rec.ID] = rec
		}
	}
	owners := make(map[uuid.UUID]savePDFTemplateParty, len(in.Parties))
	layout := &pdflayout.Layout{Version: 1, Parties: make([]pdflayout.Party, 0, len(in.Parties)), Fields: make([]pdflayout.Field, 0, len(fields))}
	for _, party := range in.Parties {
		if party.RecipientID == uuid.Nil || currentRecipients[party.RecipientID] == nil {
			return nil, pdflayout.ErrPrecondition
		}
		if _, exists := owners[party.RecipientID]; exists {
			return nil, fmt.Errorf("%w: a recipient cannot own multiple slots", pdflayout.ErrInvalid)
		}
		owners[party.RecipientID] = party
		layout.Parties = append(layout.Parties, pdflayout.Party{Role: party.Role, Label: party.Label})
	}
	used := make(map[uuid.UUID]bool, len(owners))
	for _, field := range fields {
		if field == nil || !expected[field.ID] || field.DocumentID != doc.ID {
			return nil, pdflayout.ErrPrecondition
		}
		if field.Type != "signature" || !field.Required || field.Value.Valid || field.CompletedAt.Valid || !field.RecipientID.Valid {
			return nil, fmt.Errorf("%w: save required signature fields only; remove fillable fields before saving", pdflayout.ErrInvalid)
		}
		id := uuid.UUID(field.RecipientID.Bytes)
		party, exists := owners[id]
		if !exists {
			return nil, pdflayout.ErrPrecondition
		}
		used[id] = true
		values := make([]float64, 4)
		for i, value := range []pgtype.Numeric{field.XPct, field.YPct, field.WPct, field.HPct} {
			number, err := value.Float64Value()
			if err != nil || !number.Valid || math.IsNaN(number.Float64) || math.IsInf(number.Float64, 0) {
				return nil, fmt.Errorf("%w: invalid persisted geometry", pdflayout.ErrInvalid)
			}
			values[i] = number.Float64
		}
		layout.Fields = append(layout.Fields, pdflayout.Field{PartyRole: party.Role, Type: "signature", Page: field.Page, XPct: values[0], YPct: values[1], WPct: values[2], HPct: values[3], Required: true, Label: field.Label.String})
	}
	if len(used) != len(owners) {
		return nil, fmt.Errorf("%w: every party must own a signature field", pdflayout.ErrInvalid)
	}
	if err := layout.Validate(pages); err != nil {
		return nil, err
	}
	return layout, nil
}
