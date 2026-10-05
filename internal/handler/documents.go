// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	blockschema "github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/versions"
)

// documentResponse is the JSON shape we return.
type documentResponse struct {
	ID                uuid.UUID       `json:"id"`
	OrgID             uuid.UUID       `json:"org_id"`
	TemplateID        string          `json:"template_id,omitempty"`
	Name              string          `json:"name"`
	Status            string          `json:"status"`
	RoutingMode       string          `json:"routing_mode"`
	SourceKind        string          `json:"source_kind"`
	RequiresSignature bool            `json:"requires_signature"`
	BlocksJSON        json.RawMessage `json:"blocks_json,omitempty"`
	VariablesJSON     json.RawMessage `json:"variables_json"`
	PDFStorageKey     string          `json:"pdf_storage_key,omitempty"`
	PDFSHA256         string          `json:"pdf_sha256,omitempty"`
	FinalPDFKey       string          `json:"final_pdf_key,omitempty"`
	AuditCertKey      string          `json:"audit_cert_key,omitempty"`
	ExpiresAt         string          `json:"expires_at,omitempty"`
	SentAt            string          `json:"sent_at,omitempty"`
	CompletedAt       string          `json:"completed_at,omitempty"`
	SenderID          uuid.UUID       `json:"sender_id"`
	Metadata          json.RawMessage `json:"metadata"`
	DefaultLocale     string          `json:"default_locale"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
}

func toDocumentResponse(d *generated.Document) documentResponse {
	out := documentResponse{
		ID:                d.ID,
		OrgID:             d.OrgID,
		Name:              d.Name,
		Status:            d.Status,
		RoutingMode:       d.RoutingMode,
		SourceKind:        d.SourceKind,
		RequiresSignature: d.RequiresSignature,
		BlocksJSON:        d.BlocksJson,
		VariablesJSON:     d.VariablesJson,
		SenderID:          d.SenderID,
		Metadata:          d.Metadata,
		DefaultLocale:     d.DefaultLocale,
		CreatedAt:         d.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt:         d.UpdatedAt.Time.UTC().Format(time.RFC3339Nano),
	}
	if d.TemplateID.Valid {
		out.TemplateID = uuidFromBytes(d.TemplateID.Bytes).String()
	}
	if d.PdfStorageKey.Valid {
		out.PDFStorageKey = d.PdfStorageKey.String
	}
	if len(d.PdfSha256) > 0 {
		out.PDFSHA256 = hex.EncodeToString(d.PdfSha256)
	}
	if d.FinalPdfKey.Valid {
		out.FinalPDFKey = d.FinalPdfKey.String
	}
	if d.AuditCertKey.Valid {
		out.AuditCertKey = d.AuditCertKey.String
	}
	if d.ExpiresAt.Valid {
		out.ExpiresAt = d.ExpiresAt.Time.Format(time.RFC3339)
	}
	if d.SentAt.Valid {
		out.SentAt = d.SentAt.Time.Format(time.RFC3339)
	}
	if d.CompletedAt.Valid {
		out.CompletedAt = d.CompletedAt.Time.Format(time.RFC3339)
	}
	return out
}

func uuidFromBytes(b [16]byte) uuid.UUID { return uuid.UUID(b) }

// createDocumentInput accepts either source kind. Block path uses blocks +
// variables; pdf path expects template_id pointing to a pdf-source template
// or a fresh upload (multi-step UX, week 2).
type createDocumentInput struct {
	Name          string          `json:"name"`
	TemplateID    string          `json:"template_id,omitempty"`
	SourceKind    string          `json:"source_kind"`
	BlocksJSON    json.RawMessage `json:"blocks_json,omitempty"`
	VariablesJSON json.RawMessage `json:"variables_json,omitempty"`
	ExpiresAt     string          `json:"expires_at,omitempty"`
}

func (s *Server) handleCreateDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in createDocumentInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if in.SourceKind != "blocks" && in.SourceKind != "pdf" {
		writeError(w, http.StatusBadRequest, "source_kind must be blocks or pdf")
		return
	}

	var templateID pgtype.UUID
	if in.TemplateID != "" {
		tid, err := uuid.Parse(in.TemplateID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid template_id")
			return
		}
		templateID = pgtype.UUID{Bytes: tid, Valid: true}
	}

	var expiresAt pgtype.Timestamptz
	if in.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		expiresAt = pgtype.Timestamptz{Time: t, Valid: true}
	}

	switch in.SourceKind {
	case "blocks":
		blocks := in.BlocksJSON
		vars := in.VariablesJSON
		// Instantiate from a blocks template: copy its content + variable
		// defaults into the new document so "New document" actually seeds the
		// agreement. The request can still override either by sending its own.
		if templateID.Valid && (len(blocks) == 0 || len(vars) == 0) {
			tpl, terr := s.Queries.GetTemplate(r.Context(), generated.GetTemplateParams{ID: uuid.UUID(templateID.Bytes), OrgID: u.OrgID})
			if terr != nil {
				writeError(w, http.StatusBadRequest, "template not found")
				return
			}
			if tpl.SourceKind != "blocks" {
				writeError(w, http.StatusBadRequest, "template is not a blocks template")
				return
			}
			if len(blocks) == 0 && len(tpl.BlocksJson) > 0 {
				blocks = tpl.BlocksJson
			}
			if len(vars) == 0 && len(tpl.VariablesJson) > 0 {
				vars = tpl.VariablesJson
			}
		}
		if len(blocks) == 0 {
			blocks = json.RawMessage(`{"version":1,"blocks":[]}`)
		}
		normalizedBlocks, err := blockschema.NormalizeTreeJSON(blocks)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid blocks_json: "+err.Error())
			return
		}
		blocks = normalizedBlocks
		if len(vars) == 0 {
			vars = json.RawMessage(`{}`)
		}
		if _, err := blockschema.ParseVariableValues(vars); err != nil {
			writeError(w, http.StatusBadRequest, "invalid variables_json: "+err.Error())
			return
		}
		d, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
			func(q *generated.Queries) (*generated.Document, error) {
				if err := s.Billing.LockDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
					return nil, err
				}
				doc, err := q.CreateBlocksDocument(r.Context(), generated.CreateBlocksDocumentParams{
					OrgID:         u.OrgID,
					TemplateID:    templateID,
					Name:          in.Name,
					BlocksJson:    blocks,
					VariablesJson: vars,
					SenderID:      u.UserID,
					ExpiresAt:     expiresAt,
				})
				if err != nil {
					return nil, err
				}
				if err := s.Billing.EnforceDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
					return nil, err
				}
				return doc, nil
			},
			func(d *generated.Document) audit.Entry {
				return audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &d.ID,
					Kind:    audit.KindDocumentCreated,
					Payload: map[string]any{"name": d.Name, "source_kind": "blocks"},
				}
			},
		)
		if err != nil {
			if s.writeAuthoringQuotaError(w, err) {
				return
			}
			writeInternalErrorMsg(w, "create document failed", err)
			return
		}
		writeJSON(w, http.StatusCreated, toDocumentResponse(d))
	case "pdf":
		// For week 1 the PDF path requires an existing template (so we have
		// the storage key + sha already). Free-PDF document uploads come in
		// week 2 with the field designer.
		if !templateID.Valid {
			writeError(w, http.StatusBadRequest, "template_id required for source_kind=pdf in v1")
			return
		}
		tpl, err := s.Queries.GetTemplate(r.Context(), generated.GetTemplateParams{
			ID: uuidFromBytes(templateID.Bytes), OrgID: u.OrgID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "template not found")
			return
		}
		if err != nil || tpl.SourceKind != "pdf" || !tpl.PdfStorageKey.Valid {
			writeError(w, http.StatusBadRequest, "template is not a pdf-source template")
			return
		}
		rep, repErr := sanitize.SyntheticTemplateReport()
		if repErr != nil {
			writeInternalErrorMsg(w, "create metadata redaction report", repErr)
			return
		}
		d, err := audit.CommitMutation(r.Context(), s.Pool, s.Audit,
			func(q *generated.Queries) (*generated.Document, error) {
				if err := s.Billing.LockDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
					return nil, err
				}
				d, err := q.CreatePDFDocument(r.Context(), generated.CreatePDFDocumentParams{
					OrgID:                       u.OrgID,
					TemplateID:                  templateID,
					Name:                        in.Name,
					PdfStorageKey:               tpl.PdfStorageKey,
					PdfSha256:                   tpl.PdfSha256,
					PdfStorageVersionID:         tpl.PdfStorageVersionID,
					EvidenceVersionPinsRequired: tpl.EvidenceVersionPinRequired,
					SenderID:                    u.UserID,
					ExpiresAt:                   expiresAt,
				})
				if err != nil {
					return nil, err
				}
				if err := q.UpdateMetadataRedactionReport(r.Context(), generated.UpdateMetadataRedactionReportParams{
					ID: d.ID, MetadataRedactionReport: rep,
				}); err != nil {
					return nil, err
				}
				if err := s.Billing.EnforceDocumentQuotaMutation(r.Context(), q, u.OrgID); err != nil {
					return nil, err
				}
				return d, nil
			},
			func(d *generated.Document) audit.Entry {
				return audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &d.ID,
					Kind:    audit.KindDocumentCreated,
					Payload: map[string]any{"name": d.Name, "source_kind": "pdf"},
				}
			},
		)
		if err != nil {
			if s.writeAuthoringQuotaError(w, err) {
				return
			}
			writeInternalErrorMsg(w, "create document failed", err)
			return
		}
		writeJSON(w, http.StatusCreated, toDocumentResponse(d))
	}
}

func (s *Server) handleListDocuments(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	limit, offset := paginationFromQuery(r, 50, 500)

	var statusFilter []string
	if vs, ok := r.URL.Query()["status"]; ok && len(vs) > 0 {
		statusFilter = vs
	}

	rows, err := s.Queries.ListDocuments(r.Context(), generated.ListDocumentsParams{
		OrgID:   u.OrgID,
		Column2: statusFilter,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list documents failed")
		return
	}
	out := make([]documentResponse, 0, len(rows))
	for _, d := range rows {
		out = append(out, toDocumentResponse(d))
	}
	total, _ := s.Queries.CountDocuments(r.Context(), generated.CountDocumentsParams{
		OrgID:   u.OrgID,
		Column2: statusFilter,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"documents": out,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
	})
}

func (s *Server) handleGetDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	d, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get document failed")
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(d))
}

// GET /api/v1/documents/{id}/pdf
//
// Serves the original uploaded PDF for a pdf-source document so the field
// designer can render its pages in the browser. Session-authed + org-scoped.
func (s *Server) handleGetDocumentPDF(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	d, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get document failed")
		return
	}
	if !d.PdfStorageKey.Valid || d.PdfStorageKey.String == "" {
		writeError(w, http.StatusNotFound, "document has no source pdf")
		return
	}
	body, err := readDocumentArtifact(r.Context(), s.Storage, d, d.PdfStorageKey.String, d.PdfSha256, d.PdfStorageVersionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load pdf failed")
		return
	}
	setDocumentPreviewHeaders(w, false)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline")
	_, _ = w.Write(body)
}

type updateDocumentInput struct {
	ExpectedUpdatedAt string          `json:"expected_updated_at"`
	Name              string          `json:"name,omitempty"`
	BlocksJSON        json.RawMessage `json:"blocks_json,omitempty"`
	VariablesJSON     json.RawMessage `json:"variables_json,omitempty"`
	ExpiresAt         string          `json:"expires_at,omitempty"`
	DefaultLocale     string          `json:"default_locale,omitempty"`
	RequiresSignature *bool           `json:"requires_signature,omitempty"`
}

func (s *Server) handleUpdateDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	authorize, ok := s.sessionMutationAuthorization(w, r, u)
	if !ok {
		return
	}
	var in updateDocumentInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := validateDocumentUpdateStorage(in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.DefaultLocale != "" {
		locale, err := recipients.NormalizeLocale(in.DefaultLocale)
		if err != nil {
			writeError(w, http.StatusBadRequest, "default_locale is not supported")
			return
		}
		in.DefaultLocale = locale
	}

	if in.ExpectedUpdatedAt == "" {
		writeError(w, http.StatusPreconditionRequired, "expected_updated_at is required; fetch the current document before editing")
		return
	}
	expected, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "expected_updated_at must be RFC3339")
		return
	}

	if s.Pool == nil || s.Queries == nil || s.Audit == nil {
		writeInternalErrorMsg(w, "update document unavailable", errors.New("atomic document update dependencies unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := s.Queries.WithTx(tx)
	guard, err := authoring.LockDraft(ctx, tx, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize document update", err)
		return
	}
	existing := guard.Document

	if !existing.UpdatedAt.Valid || !existing.UpdatedAt.Time.Equal(expected) {
		writeError(w, http.StatusPreconditionFailed, "Document changed since this edit began. Download your local draft, then reload and review the latest document.")
		return
	}

	// Reject unsupported content rather than acknowledging a no-op update.
	if existing.SourceKind != "blocks" && (len(in.BlocksJSON) > 0 || len(in.VariablesJSON) > 0) {
		writeError(w, http.StatusBadRequest, "blocks_json and variables_json require a block-source document")
		return
	}

	// Block updates only valid for block-source documents.
	if existing.SourceKind == "blocks" && (len(in.BlocksJSON) > 0 || len(in.VariablesJSON) > 0) {
		blocks := in.BlocksJSON
		if len(blocks) == 0 {
			blocks = existing.BlocksJson
		}
		blocks, err = blockschema.NormalizeTreeJSON(blocks)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid blocks_json: "+err.Error())
			return
		}
		vars := in.VariablesJSON
		if len(vars) == 0 {
			vars = existing.VariablesJson
		}
		if _, err := blockschema.ParseVariableValues(vars); err != nil {
			writeError(w, http.StatusBadRequest, "invalid variables_json: "+err.Error())
			return
		}
		if _, err := q.UpdateDocumentBlocks(r.Context(), generated.UpdateDocumentBlocksParams{
			ID:            id,
			OrgID:         u.OrgID,
			BlocksJson:    blocks,
			VariablesJson: vars,
		}); err != nil {
			writeInternalErrorMsg(w, "update blocks failed", err)
			return
		}
	}

	// Metadata path: name, expires_at. Merge in Go because the SQL uses
	// COALESCE on positional args and pgx doesn't pass Go zero-value strings
	// as NULL.
	name := existing.Name
	if in.Name != "" {
		name = in.Name
	}
	expiresArg := existing.ExpiresAt
	if in.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		expiresArg = pgtype.Timestamptz{Time: t, Valid: true}
	}
	d, err := q.UpdateDocumentMetadata(r.Context(), generated.UpdateDocumentMetadataParams{
		ID:        id,
		OrgID:     u.OrgID,
		Name:      name,
		ExpiresAt: expiresArg,
		Metadata:  existing.Metadata,
	})
	if err != nil {
		writeInternalErrorMsg(w, "update document failed", err)
		return
	}

	// Document-level default signing language: the sender's "send this in
	// Swedish" choice. New recipients inherit it (see handleCreateRecipient).
	if in.DefaultLocale != "" && in.DefaultLocale != d.DefaultLocale {
		d, err = q.SetDocumentDefaultLocale(r.Context(), generated.SetDocumentDefaultLocaleParams{
			ID:            id,
			OrgID:         u.OrgID,
			DefaultLocale: in.DefaultLocale,
		})
		if err != nil {
			writeInternalErrorMsg(w, "update default language failed", err)
			return
		}
	}

	// Signature mode: draft-only toggle between signature-required and
	// acknowledgement (view/accept). Locked once sent.
	if in.RequiresSignature != nil && *in.RequiresSignature != d.RequiresSignature {
		d, err = q.SetDocumentRequiresSignature(r.Context(), generated.SetDocumentRequiresSignatureParams{
			ID:                id,
			OrgID:             u.OrgID,
			RequiresSignature: *in.RequiresSignature,
		})
		if err != nil {
			writeInternalErrorMsg(w, "update signature mode failed", err)
			return
		}
	}

	actorID := guard.UserID()
	if s.Versions != nil {
		if _, err := versions.New(q).Snapshot(ctx, versions.SnapshotInput{
			DocumentID: d.ID, OrgID: d.OrgID, Name: d.Name, SourceKind: d.SourceKind,
			BlocksJSON: d.BlocksJson, VariablesJS: d.VariablesJson, CreatedBy: &actorID,
			Via: versions.ViaHuman, Summary: "update_document",
		}); err != nil {
			writeInternalErrorMsg(w, "snapshot document update failed", err)
			return
		}
	}
	pending, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
		OrgID: u.OrgID, ActorUserID: &actorID, DocumentID: &d.ID,
		Kind: audit.KindDocumentUpdated,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := guard.Recheck(ctx); err != nil {
		s.writeDraftAuthoringError(w, "reauthorize document update", err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pending)
	writeJSON(w, http.StatusOK, toDocumentResponse(d))
}

type changeRequestResponse struct {
	ID             string `json:"id"`
	Message        string `json:"message"`
	Status         string `json:"status"`
	Resolution     string `json:"resolution,omitempty"`
	BlockID        string `json:"block_id,omitempty"`
	Quote          string `json:"quote,omitempty"`
	Context        string `json:"context,omitempty"`
	Proposed       string `json:"proposed,omitempty"`
	RecipientName  string `json:"recipient_name,omitempty"`
	RecipientEmail string `json:"recipient_email,omitempty"`
	CreatedAt      string `json:"created_at"`
}

// handleListChangeRequests returns the change requests a signer raised, so the
// sender can read what was asked before revising.
func (s *Server) handleListChangeRequests(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	rows, err := s.Queries.ListChangeRequests(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list change requests failed")
		return
	}
	out := make([]changeRequestResponse, 0, len(rows))
	for _, cr := range rows {
		resp := changeRequestResponse{
			ID:        cr.ID.String(),
			Message:   cr.Message,
			Status:    cr.Status,
			BlockID:   cr.BlockID,
			Quote:     cr.Quote,
			Context:   cr.Context,
			Proposed:  cr.Proposed,
			CreatedAt: cr.CreatedAt.Time.Format(time.RFC3339),
		}
		if cr.Resolution.Valid {
			resp.Resolution = cr.Resolution.String
		}
		if cr.RecipientName.Valid {
			resp.RecipientName = cr.RecipientName.String
		}
		if cr.RecipientEmail.Valid {
			resp.RecipientEmail = cr.RecipientEmail.String
		}
		out = append(out, resp)
	}
	writeJSON(w, http.StatusOK, map[string]any{"change_requests": out})
}

func (s *Server) resolveChangeRequest(w http.ResponseWriter, r *http.Request, approve bool) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	crID, ok := parseUUIDParam(w, r, "crid")
	if !ok {
		return
	}
	authorize, ok := s.sessionMutationAuthorization(w, r, u)
	if !ok {
		return
	}
	if _, err := s.Sign.ResolveChangeWithAuthorization(r.Context(), u.OrgID, id, crID, u.UserID, approve, authorize); err != nil {
		switch {
		case errors.Is(err, auth.ErrMutationCredentialExpired):
			writeError(w, http.StatusUnauthorized, auth.ErrMutationCredentialExpired.Error())
		case errors.Is(err, auth.ErrMutationPermissionRevoked):
			writeError(w, http.StatusForbidden, "permission or session revoked")
		case errors.Is(err, sign.ErrChangeAlreadyResolved):
			writeError(w, http.StatusConflict, "change request is already resolved")
		case errors.Is(err, sign.ErrChangeRequestNotFound):
			writeError(w, http.StatusNotFound, "change request not found for this document")
		case errors.Is(err, sign.ErrNotRevisable):
			writeError(w, http.StatusConflict, "document is no longer awaiting revision")
		case errors.Is(err, sign.ErrRevisionWouldDestroyEvidence):
			writeError(w, http.StatusConflict, "change cannot be applied after legal evidence has been captured")
		case errors.Is(err, sign.ErrEnvelopeTransitionUnsupported):
			writeError(w, http.StatusConflict, "change resolution is not supported for envelopes")
		default:
			writeInternalErrorMsg(w, "resolve change request failed", err)
		}
		return
	}
	resolution := "denied"
	if approve {
		resolution = "approved"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "resolved", "resolution": resolution})
}

func (s *Server) handleApproveChangeRequest(w http.ResponseWriter, r *http.Request) {
	s.resolveChangeRequest(w, r, true)
}

func (s *Server) handleDenyChangeRequest(w http.ResponseWriter, r *http.Request) {
	s.resolveChangeRequest(w, r, false)
}

type changeApprovalModeInput struct {
	Mode string `json:"mode"`
}

// handleSetChangeApprovalMode sets the org-wide behaviour for approving inline
// change requests: 'accept' (record acceptance, apply on Revise) or 'auto_apply'
// (swap the marked text immediately).
func (s *Server) handleSetChangeApprovalMode(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in changeApprovalModeInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if in.Mode != "accept" && in.Mode != "auto_apply" {
		writeError(w, http.StatusBadRequest, "mode must be accept or auto_apply")
		return
	}
	if _, err := s.Queries.SetOrgChangeApprovalMode(r.Context(), generated.SetOrgChangeApprovalModeParams{ID: u.OrgID, ChangeApprovalMode: in.Mode}); err != nil {
		writeError(w, http.StatusInternalServerError, "update setting failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"change_approval_mode": in.Mode})
}

// handleReviseDocument reopens a document that a signer paused with a change
// request, returning it to draft so the sender can edit and re-send.
func (s *Server) handleReviseDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	authorize, ok := s.sessionMutationAuthorization(w, r, u)
	if !ok {
		return
	}
	doc, err := s.Sign.ReviseWithAuthorization(r.Context(), u.OrgID, id, u.UserID, authorize)
	if err != nil {
		if errors.Is(err, auth.ErrMutationCredentialExpired) {
			writeError(w, http.StatusUnauthorized, auth.ErrMutationCredentialExpired.Error())
			return
		}
		if errors.Is(err, auth.ErrMutationPermissionRevoked) || errors.Is(err, sign.ErrRevisionNotAuthorized) {
			writeError(w, http.StatusForbidden, "permission or session revoked")
			return
		}
		if errors.Is(err, sign.ErrRevisionDocumentNotFound) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		if errors.Is(err, sign.ErrEnvelopeTransitionUnsupported) {
			writeError(w, http.StatusConflict, "envelope revision is not supported; void the envelope and create a new draft instead")
			return
		}
		if errors.Is(err, sign.ErrNotRevisable) {
			writeError(w, http.StatusConflict, "document is not awaiting revision")
			return
		}
		if errors.Is(err, sign.ErrRevisionWouldDestroyEvidence) {
			writeError(w, http.StatusConflict, "revision blocked because this ceremony already contains captured legal evidence; void and create a superseding document instead")
			return
		}
		writeInternalErrorMsg(w, "revise document", err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}

type commentResponse struct {
	ID         string `json:"id"`
	AuthorName string `json:"author_name"`
	AuthorSide string `json:"author_side"`
	Body       string `json:"body"`
	CreatedAt  string `json:"created_at"`
}

func toCommentResponse(c *generated.DocumentComment) commentResponse {
	return commentResponse{
		ID:         c.ID.String(),
		AuthorName: c.AuthorName,
		AuthorSide: c.AuthorSide,
		Body:       c.Body,
		CreatedAt:  c.CreatedAt.Time.Format(time.RFC3339),
	}
}

func toCommentResponses(rows []*generated.DocumentComment) []commentResponse {
	out := make([]commentResponse, 0, len(rows))
	for _, c := range rows {
		out = append(out, toCommentResponse(c))
	}
	return out
}

func (s *Server) handleListComments(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	rows, err := s.Queries.ListComments(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list comments failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"comments": toCommentResponses(rows)})
}

type createCommentInput struct {
	Body string `json:"body"`
}

var (
	errCommentSessionRevoked = errors.New("permission or session revoked")
	errCommentSessionExpired = errors.New("session expired before transaction committed")
)

func (s *Server) handleCreateComment(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in createCommentInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	session, cookie, ok := s.transactionSession(w, r, u)
	if !ok {
		return
	}
	authorize := func(ctx context.Context, user *generated.User) error {
		if user.ID != session.UserID || user.SessionGeneration != session.Generation {
			return errCommentSessionRevoked
		}
		if _, err := s.Cookies.Verify(cookie); err != nil {
			return errCommentSessionExpired
		}
		return ctx.Err()
	}
	c, err := s.Sign.SenderCommentWithAuthorization(r.Context(), u.OrgID, id, u.UserID, u.Email, in.Body, authorize)
	if err != nil {
		switch {
		case errors.Is(err, errCommentSessionExpired):
			writeError(w, http.StatusUnauthorized, errCommentSessionExpired.Error())
		case errors.Is(err, errCommentSessionRevoked), errors.Is(err, sign.ErrSenderCommentNotAuthorized):
			writeError(w, http.StatusForbidden, "permission or session revoked")
		case errors.Is(err, sign.ErrInvalidCommentBody):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, sign.ErrDocumentNotCommentable):
			writeError(w, http.StatusConflict, "document is not open for comments")
		case errors.Is(err, sign.ErrCommentDocumentNotFound):
			writeError(w, http.StatusNotFound, "document not found")
		default:
			writeInternalErrorMsg(w, "post sender comment", err)
		}
		return
	}
	writeJSON(w, http.StatusCreated, toCommentResponse(c))
}

func (s *Server) handleDeleteDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || s.Cookies == nil {
		writeError(w, http.StatusUnauthorized, "session required")
		return
	}
	payload, err := s.Cookies.Verify(cookie.Value)
	var session auth.SessionPayload
	if err != nil || json.Unmarshal(payload, &session) != nil || session.UserID != u.UserID {
		writeError(w, http.StatusUnauthorized, "session invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	// The fresh privacy predicate must see requests committed before acquiring
	// the parent/shared organization fence, regardless of connection defaults.
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Queries.WithTx(tx)
	doc, err := q.GetDocumentForPrivacyUpdate(ctx, generated.GetDocumentForPrivacyUpdateParams{DocumentID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if doc.Status != "draft" {
		writeError(w, http.StatusConflict, "only draft documents can be deleted")
		return
	}
	var role string
	var generation int64
	err = tx.QueryRow(ctx, `SELECT role,session_generation FROM users WHERE id=$1 AND org_id=$2 FOR SHARE`, u.UserID, u.OrgID).Scan(&role, &generation)
	if err != nil || (role != string(auth.RoleSender) && role != string(auth.RoleOwner)) || session.Generation != generation {
		writeError(w, http.StatusForbidden, "document deletion permission or session revoked")
		return
	}
	if _, err := s.Cookies.Verify(cookie.Value); err != nil {
		writeError(w, http.StatusUnauthorized, "session expired while awaiting deletion authorization")
		return
	}
	if doc.DeletedAt.Valid {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	retainedEvidence, err := q.HasRetainedDraftEvidenceForPurge(ctx, generated.HasRetainedDraftEvidenceForPurgeParams{DocumentID: id, OrgID: u.OrgID})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if retainedEvidence {
		writeError(w, http.StatusConflict, "draft evidence or sealing state requires review before deletion")
		return
	}
	privacyFence, err := q.TryCollabArchivePrivacyFence(ctx, u.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if !privacyFence {
		writeError(w, http.StatusConflict, "privacy review is changing; retry after it completes")
		return
	}
	pendingPrivacy, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: id, OrgID: u.OrgID})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if pendingPrivacy {
		writeError(w, http.StatusConflict, "document deletion awaits the open privacy request review")
		return
	}
	if err := q.DeleteDraftDocument(ctx, generated.DeleteDraftDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
		writeInternalError(w, err)
		return
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id,
		Kind: audit.KindDocumentDeleted,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if _, err := s.Cookies.Verify(cookie.Value); err != nil {
		writeError(w, http.StatusUnauthorized, "session expired before document deletion committed")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pending)
	// Retain source bytes throughout the 90-day soft-delete grace period.
	// The worker performs privacy-fenced object cleanup before hard deletion.
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	// Authorization: ensure the document is in the caller's org.
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	rows, err := s.Queries.ListEventsByDocument(r.Context(), generated.ListEventsByDocumentParams{
		DocumentID: pgtype.UUID{Bytes: docID, Valid: true},
		Limit:      500,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list events failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": rows})
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
