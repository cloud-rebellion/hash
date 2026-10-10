// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sanitize"
)

var errHTMLDocumentSourceNotFound = errors.New("document has no retained HTML source")

type htmlDocumentValueResponse struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	MaxChars int    `json:"max_chars"`
	Text     string `json:"text"`
}

type htmlDocumentSectionResponse struct {
	Name        string `json:"name"`
	MaxChars    int    `json:"max_chars"`
	Text        string `json:"text"`
	DefaultText string `json:"default_text"`
}

// Expose declared text and bounded pins, never the private master, inline
// assets, storage keys or object VersionIds. Defaults come from this document's
// immutable approved origin rather than a subsequently edited live template.
type htmlDocumentSourceResponse struct {
	DocumentID              uuid.UUID                     `json:"document_id"`
	OrgID                   uuid.UUID                     `json:"org_id"`
	UpdatedAt               string                        `json:"updated_at"`
	HTMLSourceCommitment    string                        `json:"html_source_commitment"`
	MaterializationRevision int32                         `json:"materialization_revision"`
	PDFSHA256               string                        `json:"pdf_sha256"`
	PageCount               int32                         `json:"page_count"`
	TemplateID              uuid.UUID                     `json:"template_id"`
	TemplateVersion         int32                         `json:"template_version"`
	TemplateContentSHA256   string                        `json:"template_content_sha256"`
	Values                  []htmlDocumentValueResponse   `json:"values"`
	Sections                []htmlDocumentSectionResponse `json:"sections"`
	ChangedSections         []string                      `json:"changed_sections"`
	CanEdit                 bool                          `json:"can_edit"`
	ContractProfile         *htmlmaster.ContractProfile   `json:"contract_profile,omitempty"`
	ContractProfileDigest   string                        `json:"contract_profile_digest,omitempty"`
	ContractParties         []htmlsource.ContractParty    `json:"contract_parties,omitempty"`
}

type htmlDocumentHistoryResponse struct {
	Sequence         int32     `json:"sequence"`
	ID               uuid.UUID `json:"id"`
	SourceCommitment string    `json:"source_commitment"`
	PDFSHA256        string    `json:"pdf_sha256"`
	PageCount        int32     `json:"page_count"`
	CreatedBy        uuid.UUID `json:"created_by"`
	CreatedAt        string    `json:"created_at"`
	Summary          string    `json:"summary"`
	Current          bool      `json:"current"`
}

type htmlDocumentReadScope struct {
	ctx       context.Context
	cancel    context.CancelFunc
	id        uuid.UUID
	user      auth.SessionUser
	authorize auth.TransactionAuthorization
}

func (s *Server) beginHTMLDocumentRead(w http.ResponseWriter, r *http.Request) (*htmlDocumentReadScope, bool) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return nil, false
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writePreviewError(w, err)
		return nil, false
	}
	if s.Pool == nil || s.Queries == nil {
		writeError(w, http.StatusServiceUnavailable, "document history unavailable")
		return nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), resolver.PreviewTimeout)
	return &htmlDocumentReadScope{ctx: ctx, cancel: cancel, id: id, user: u, authorize: authorize}, true
}

func (s *Server) loadHTMLDocumentRead(scope *htmlDocumentReadScope) (*generated.Document, *generated.HtmlDocumentMaterialization, error) {
	doc, err := s.Queries.GetDocument(scope.ctx, generated.GetDocumentParams{ID: scope.id, OrgID: scope.user.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, authoring.ErrDocumentNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if len(doc.HtmlSourceJson) == 0 {
		return nil, nil, errHTMLDocumentSourceNotFound
	}
	current, err := htmlmaterialization.Current(scope.ctx, s.Queries, doc)
	if err != nil {
		return nil, nil, err
	}
	// Refuse a revoked original admission before any external PDF read. The
	// final check still runs after source compilation, storage and parser waits.
	if _, err := s.checkHTMLDocumentRead(scope, doc, current); err != nil {
		return nil, nil, err
	}
	return doc, current, nil
}

func htmlDocumentSourceDescriptor(doc *generated.Document, pages int32) (htmlDocumentSourceResponse, error) {
	var out htmlDocumentSourceResponse
	if doc == nil || pages < 1 || pages > 500 || !doc.UpdatedAt.Valid || doc.UpdatedAt.InfinityModifier != pgtype.Finite {
		return out, htmlmaterialization.ErrInvalid
	}
	input, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		return out, err
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		return out, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return out, err
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil {
		return out, err
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		return out, err
	}
	out = htmlDocumentSourceResponse{
		DocumentID: doc.ID, OrgID: doc.OrgID, UpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano),
		HTMLSourceCommitment: commitment, MaterializationRevision: 1,
		PDFSHA256: hex.EncodeToString(doc.PdfSha256), PageCount: pages,
		TemplateID: input.TemplateID, TemplateVersion: input.TemplateVersion, TemplateContentSHA256: input.TemplateContentSHA256,
		Values:   make([]htmlDocumentValueResponse, 0, len(master.Values)),
		Sections: make([]htmlDocumentSectionResponse, 0, len(master.Sections)), ChangedSections: []string{},
		ContractProfile: compiled.ContractProfile(), ContractProfileDigest: compiled.ProfileDigest(), ContractParties: parties,
	}
	if doc.HtmlCurrentMaterializationSequence.Valid {
		out.MaterializationRevision = doc.HtmlCurrentMaterializationSequence.Int32
	}
	for _, value := range master.Values {
		out.Values = append(out.Values, htmlDocumentValueResponse{Name: value.Name, Required: value.Required, MaxChars: value.MaxChars, Text: input.Values[value.Name]})
	}
	for _, section := range master.Sections {
		text, present := input.Sections[section.Name]
		if !present {
			text = section.DefaultText
		}
		out.Sections = append(out.Sections, htmlDocumentSectionResponse{Name: section.Name, MaxChars: section.MaxChars, Text: text, DefaultText: section.DefaultText})
		if text != section.DefaultText {
			out.ChangedSections = append(out.ChangedSections, section.Name)
		}
	}
	return out, nil
}

// The original admission and complete source/PDF observation survive storage
// and parser waits. Hold only short database locks here; all source compilation
// and object processing have already finished. A live role downgrade can still
// allow a read while correctly removing edit affordances.
func (s *Server) checkHTMLDocumentRead(scope *htmlDocumentReadScope, observed *generated.Document, revision *generated.HtmlDocumentMaterialization) (bool, error) {
	tx, err := s.Pool.BeginTx(scope.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() { _ = authoring.Rollback(scope.ctx, tx) }()
	q := generated.New(tx)
	current, err := q.GetDocumentForShare(scope.ctx, generated.GetDocumentForShareParams{ID: observed.ID, OrgID: observed.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, authoring.ErrDocumentNotFound
	}
	if err != nil {
		return false, err
	}
	if !sameHTMLDocumentReadObservation(observed, current) {
		return false, resolver.ErrPreviewChanged
	}
	user, err := q.GetUserForShare(scope.ctx, generated.GetUserForShareParams{ID: scope.user.UserID, OrgID: observed.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return false, err
	}
	switch auth.Role(user.Role) {
	case auth.RoleOwner, auth.RoleSender, auth.RoleViewer:
	default:
		return false, auth.ErrMutationPermissionRevoked
	}
	if err := scope.authorize(scope.ctx, tx, user); err != nil {
		return false, err
	}
	if revision != nil {
		retained, err := q.GetHTMLDocumentMaterialization(scope.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: observed.ID, OrgID: observed.OrgID, Sequence: revision.Sequence})
		if errors.Is(err, pgx.ErrNoRows) {
			return false, authoring.ErrDocumentNotFound
		}
		if err != nil {
			return false, err
		}
		if !sameHTMLDocumentReadMaterialization(revision, retained) {
			return false, resolver.ErrPreviewChanged
		}
	}
	canEdit := current.Status == "draft" && (user.Role == string(auth.RoleOwner) || (user.Role == string(auth.RoleSender) && user.ID == current.SenderID))
	if canEdit {
		retained, err := q.HasRetainedDraftSigningEvidence(scope.ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: current.ID, OrgID: current.OrgID})
		if err != nil {
			return false, err
		}
		pending, err := q.HasPendingDocumentPrivacyRequests(scope.ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: current.ID, OrgID: current.OrgID})
		if err != nil {
			return false, err
		}
		canEdit = !retained && !pending
	}
	if err := scope.authorize(scope.ctx, tx, user); err != nil {
		return false, err
	}
	if err := scope.ctx.Err(); err != nil {
		return false, err
	}
	if err := tx.Commit(scope.ctx); err != nil {
		return false, err
	}
	return canEdit, nil
}

func sameHTMLDocumentReadObservation(a, b *generated.Document) bool {
	return a != nil && b != nil && a.ID == b.ID && a.OrgID == b.OrgID && a.Status == b.Status && a.SourceKind == b.SourceKind &&
		a.SenderID == b.SenderID && a.TemplateID == b.TemplateID && a.UpdatedAt.Valid == b.UpdatedAt.Valid && a.UpdatedAt.InfinityModifier == b.UpdatedAt.InfinityModifier && a.UpdatedAt.Time.Equal(b.UpdatedAt.Time) &&
		a.PdfStorageKey == b.PdfStorageKey && a.PdfStorageVersionID == b.PdfStorageVersionID && bytes.Equal(a.PdfSha256, b.PdfSha256) &&
		a.HtmlCurrentMaterializationID == b.HtmlCurrentMaterializationID && a.HtmlCurrentPageCount == b.HtmlCurrentPageCount &&
		a.HtmlCurrentMaterializationSequence == b.HtmlCurrentMaterializationSequence && a.HtmlEffectiveSourceCommitment == b.HtmlEffectiveSourceCommitment &&
		bytes.Equal(a.HtmlSourceJson, b.HtmlSourceJson) && bytes.Equal(a.HtmlCurrentSourceJson, b.HtmlCurrentSourceJson) && bytes.Equal(a.VariablesJson, b.VariablesJson)
}

func sameHTMLDocumentReadMaterialization(a, b *generated.HtmlDocumentMaterialization) bool {
	return a != nil && b != nil && a.ID == b.ID && a.DocumentID == b.DocumentID && a.OrgID == b.OrgID && a.Sequence == b.Sequence &&
		a.PdfKey == b.PdfKey && a.PdfVersionID == b.PdfVersionID && a.PageCount == b.PageCount && bytes.Equal(a.PdfSha256, b.PdfSha256) &&
		bytes.Equal(a.SourceCommitment, b.SourceCommitment) && bytes.Equal(a.OriginCommitment, b.OriginCommitment) && bytes.Equal(a.SourceJson, b.SourceJson)
}

func (s *Server) readHTMLDocumentPages(ctx context.Context, doc *generated.Document) ([]byte, int32, error) {
	if s.Storage == nil {
		return nil, 0, errors.New("historical PDF storage unavailable")
	}
	// Every HTML origin/materialization has exact pins. There is deliberately
	// no legacy lookup, latest-version fallback or re-sanitization of evidence.
	body, err := s.Storage.GetVerifiedVersion(ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
	if err != nil {
		return nil, 0, err
	}
	if len(body) == 0 || len(body) > sanitize.MaxPDFBytes {
		return nil, 0, htmlmaterialization.ErrInvalid
	}
	pages, err := sanitize.PageCountWithContext(ctx, body)
	if err != nil {
		return nil, 0, err
	}
	if pages < 1 || pages > 500 || (doc.HtmlCurrentPageCount.Valid && doc.HtmlCurrentPageCount.Int32 != int32(pages)) {
		return nil, 0, htmlmaterialization.ErrInvalid
	}
	return body, int32(pages), nil
}

func (s *Server) handleGetHTMLDocumentSource(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.beginHTMLDocumentRead(w, r)
	if !ok {
		return
	}
	defer scope.cancel()
	doc, current, err := s.loadHTMLDocumentRead(scope)
	if err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	var pages int32
	if current != nil {
		pages = current.PageCount
	} else {
		_, pages, err = s.readHTMLDocumentPages(scope.ctx, doc)
		if err != nil {
			s.writeHTMLDocumentReadError(w, err)
			return
		}
	}
	response, err := htmlDocumentSourceDescriptor(doc, pages)
	if err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	response.CanEdit, err = s.checkHTMLDocumentRead(scope, doc, current)
	if err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleGetHTMLDocumentHistory(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.beginHTMLDocumentRead(w, r)
	if !ok {
		return
	}
	defer scope.cancel()
	doc, current, err := s.loadHTMLDocumentRead(scope)
	if err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	rows, err := s.Queries.ListHTMLDocumentMaterializations(scope.ctx, generated.ListHTMLDocumentMaterializationsParams{DocumentID: doc.ID, OrgID: doc.OrgID, RowLimit: 200})
	if err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	result := make([]htmlDocumentHistoryResponse, 0, len(rows))
	for _, row := range rows {
		if row == nil || row.ID == uuid.Nil || row.DocumentID != doc.ID || row.OrgID != doc.OrgID || row.Sequence < 1 || len(row.SourceCommitment) != sha256.Size || len(row.PdfSha256) != sha256.Size ||
			row.PageCount < 1 || row.PageCount > 500 || row.CreatedBy == uuid.Nil || !row.CreatedAt.Valid || row.CreatedAt.InfinityModifier != pgtype.Finite ||
			!utf8.ValidString(row.Summary) || utf8.RuneCountInString(row.Summary) > 500 || (row.IsCurrent && (current == nil || row.ID != current.ID)) {
			s.writeHTMLDocumentReadError(w, htmlmaterialization.ErrInvalid)
			return
		}
		result = append(result, htmlDocumentHistoryResponse{Sequence: row.Sequence, ID: row.ID, SourceCommitment: hex.EncodeToString(row.SourceCommitment), PDFSHA256: hex.EncodeToString(row.PdfSha256),
			PageCount: row.PageCount, CreatedBy: row.CreatedBy, CreatedAt: row.CreatedAt.Time.UTC().Format(time.RFC3339Nano), Summary: row.Summary, Current: row.IsCurrent})
	}
	if _, err := s.checkHTMLDocumentRead(scope, doc, current); err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"revisions": result})
}

func parseHTMLDocumentRevision(w http.ResponseWriter, r *http.Request) (int32, bool) {
	raw := chi.URLParam(r, "sequence")
	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || value < 1 || strconv.FormatInt(value, 10) != raw {
		writeError(w, http.StatusBadRequest, "invalid materialization revision")
		return 0, false
	}
	return int32(value), true
}

func (s *Server) loadHTMLHistoricalDocumentRevision(scope *htmlDocumentReadScope, sequence int32) (*generated.Document, *generated.Document, *generated.HtmlDocumentMaterialization, error) {
	doc, _, err := s.loadHTMLDocumentRead(scope)
	if err != nil {
		return nil, nil, nil, err
	}
	row, err := s.Queries.GetHTMLDocumentMaterialization(scope.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: doc.OrgID, Sequence: sequence})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil, authoring.ErrDocumentNotFound
	}
	if err != nil {
		return nil, nil, nil, err
	}
	historical, err := htmlmaterialization.HistoricalDocument(doc, row)
	return doc, historical, row, err
}

func (s *Server) handleGetHTMLDocumentRevisionSource(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.beginHTMLDocumentRead(w, r)
	if !ok {
		return
	}
	defer scope.cancel()
	sequence, ok := parseHTMLDocumentRevision(w, r)
	if !ok {
		return
	}
	doc, historical, row, err := s.loadHTMLHistoricalDocumentRevision(scope, sequence)
	if err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	response, err := htmlDocumentSourceDescriptor(historical, row.PageCount)
	if err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	if _, err := s.checkHTMLDocumentRead(scope, doc, row); err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	// Historic text is always a read-only observation, including the row that
	// happens to be current. Restoring it requires a fresh render and review.
	response.CanEdit = false
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleGetHTMLDocumentRevisionPDF(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.beginHTMLDocumentRead(w, r)
	if !ok {
		return
	}
	defer scope.cancel()
	sequence, ok := parseHTMLDocumentRevision(w, r)
	if !ok {
		return
	}
	doc, historical, row, err := s.loadHTMLHistoricalDocumentRevision(scope, sequence)
	if err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	body, pages, err := s.readHTMLDocumentPages(scope.ctx, historical)
	if err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	if _, err := s.checkHTMLDocumentRead(scope, doc, row); err != nil {
		s.writeHTMLDocumentReadError(w, err)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "application/pdf")
	h.Set("Content-Disposition", "inline")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Hash-Document-Id", doc.ID.String())
	h.Set("X-Hash-Materialization-Revision", strconv.FormatInt(int64(row.Sequence), 10))
	h.Set("X-Hash-HTML-Source-Commitment", hex.EncodeToString(row.SourceCommitment))
	h.Set("X-Hash-PDF-SHA256", hex.EncodeToString(row.PdfSha256))
	h.Set("X-Hash-PDF-Pages", strconv.FormatInt(int64(pages), 10))
	setDocumentPreviewHeaders(w, false)
	_, _ = w.Write(body)
}

func (s *Server) writeHTMLDocumentReadError(w http.ResponseWriter, err error) {
	if writePDFWorkerError(w, err) {
		return
	}
	switch {
	case errors.Is(err, errHTMLDocumentSourceNotFound):
		writeError(w, http.StatusNotFound, errHTMLDocumentSourceNotFound.Error())
	case errors.Is(err, htmlsource.ErrInvalid), errors.Is(err, htmlmaster.ErrInvalid), errors.Is(err, htmlmaster.ErrLimit), errors.Is(err, htmlmaterialization.ErrInvalid):
		writeError(w, http.StatusConflict, "retained HTML source or PDF history is inconsistent")
	default:
		s.writePreviewError(w, err)
	}
}
