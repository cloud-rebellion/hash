// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/docintake"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/versions"
)

type htmlDocumentInput struct {
	Name                          string        `json:"name"`
	ExpectedTemplateVersion       int32         `json:"expected_template_version"`
	ExpectedTemplateContentSHA256 string        `json:"expected_template_content_sha256"`
	Values                        htmlStringMap `json:"values"`
	Sections                      htmlStringMap `json:"sections,omitempty"`
	ExpiresAt                     string        `json:"expires_at,omitempty"`
}

// JSON null must never silently replace approved text with an empty string.
// Omitted maps use defaults; explicitly supplied maps contain strings only.
type htmlStringMap map[string]string

func (m *htmlStringMap) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("HTML values and sections must be objects of strings")
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return errors.New("HTML values and sections must be objects of strings")
	}
	parsed := make(htmlStringMap, len(entries))
	for name, value := range entries {
		value = bytes.TrimSpace(value)
		if len(value) == 0 || value[0] != '"' {
			return errors.New("HTML values and sections must contain strings only")
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return err
		}
		parsed[name] = text
	}
	*m = parsed
	return nil
}

func (s *Server) handleInstantiateHTMLTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in htmlDocumentInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(in.Name) == "" || utf8.RuneCountInString(in.Name) > 200 || strings.ContainsRune(in.Name, '\x00') {
		writeError(w, http.StatusBadRequest, "name must contain 1 to 200 characters")
		return
	}
	digest, err := hex.DecodeString(in.ExpectedTemplateContentSHA256)
	if err != nil || len(digest) != 32 || in.ExpectedTemplateVersion <= 0 || in.ExpectedTemplateContentSHA256 != strings.ToLower(in.ExpectedTemplateContentSHA256) {
		writeError(w, http.StatusPreconditionRequired, "reviewed template version and content SHA-256 are required")
		return
	}
	var expires pgtype.Timestamptz
	if in.ExpiresAt != "" {
		value, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil || !value.After(time.Now()) {
			writeError(w, http.StatusBadRequest, "expires_at must be a future RFC3339 time")
			return
		}
		expires = pgtype.Timestamptz{Time: value, Valid: true}
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML document", err)
		return
	}
	if s.Pool == nil || s.Audit == nil || s.Billing == nil || s.Storage == nil || s.Sign == nil || s.Sign.PDF == nil || s.Versions == nil {
		writeError(w, http.StatusServiceUnavailable, "HTML document creation dependencies unavailable")
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	defer release()
	doc, pages, err := s.instantiateHTMLDocument(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, in, digest, expires)
	if err != nil {
		if writePDFWorkerError(w, err) {
			return
		}
		if errors.Is(err, malwarescan.ErrDetected) || errors.Is(err, malwarescan.ErrUnavailable) {
			writeScanError(w, err)
			return
		}
		if errors.Is(err, docintake.ErrSanitizePDF) || errors.Is(err, docintake.ErrTooManyPages) {
			writeError(w, http.StatusBadRequest, "rendered PDF could not be accepted")
			return
		}
		if s.writeAuthoringQuotaError(w, err) {
			return
		}
		s.writeHTMLTemplateError(w, "instantiate HTML template", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"document": toDocumentResponse(doc), "page_count": pages, "review_required": true})
}

func (s *Server) instantiateHTMLDocument(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte, expires pgtype.Timestamptz) (result *generated.Document, pageCount int, failure error) {
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := generated.New(tx)
	if err := s.Billing.LockDocumentQuotaMutation(ctx, q, actor.OrgID); err != nil {
		return nil, 0, err
	}
	template, err := q.GetHTMLTemplateForShare(ctx, generated.GetHTMLTemplateForShareParams{ID: templateID, OrgID: actor.OrgID})
	if err != nil {
		return nil, 0, err
	}
	if template.Version != in.ExpectedTemplateVersion || !bytes.Equal(template.HtmlContentSha256, digest) {
		return nil, 0, errHTMLTemplateConflict
	}
	revision, err := q.GetHTMLTemplateRevisionForShare(ctx, generated.GetHTMLTemplateRevisionForShareParams{TemplateID: templateID, OrgID: actor.OrgID, Version: in.ExpectedTemplateVersion})
	if err != nil {
		return nil, 0, err
	}
	if !revision.ApprovedBy.Valid || !revision.ApprovedAt.Valid || !bytes.Equal(revision.ContentSha256, digest) {
		return nil, 0, errHTMLTemplateConflict
	}
	guard, err := authoring.LockAuthor(ctx, tx, actor)
	if err != nil {
		return nil, 0, err
	}
	content, err := htmlmaster.CanonicalTemplate(revision.HtmlMasterJson, revision.VariablesJson)
	if err != nil || content.SHA256 != in.ExpectedTemplateContentSHA256 {
		return nil, 0, errHTMLTemplateConflict
	}
	master, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		return nil, 0, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return nil, 0, err
	}
	values := map[string]string{}
	if err := json.Unmarshal(content.DefaultsJSON, &values); err != nil {
		return nil, 0, err
	}
	for key, value := range in.Values {
		values[key] = value
	}
	rendered, err := compiled.Materialize(htmlmaster.Input{Values: values, Sections: in.Sections})
	if err != nil {
		return nil, 0, err
	}
	pdf, err := s.Sign.PDF.HTMLToPDF(ctx, rendered.HTML, render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms"})
	if err != nil {
		return nil, 0, err
	}
	if err := guard.Recheck(ctx); err != nil {
		return nil, 0, err
	}
	var composed *sanitize.PDFCompositionResult
	input := htmlmaster.Input{Values: values, Sections: in.Sections}
	if compiled.SigningPagePolicy() != nil {
		artifact, composeErr := s.composeHTMLSigningPage(ctx, compiled, input, pdf)
		if composeErr != nil {
			return nil, 0, composeErr
		}
		composed = &artifact
	}
	var doc *generated.Document
	var pages int
	var owned docintake.OwnedPDFSource
	if composed != nil {
		doc, pages, owned, err = docintake.CreateComposedPDFTemplateDocument(ctx, q, s.Storage, actor.OrgID, actor.UserID, in.Name, templateID, expires, *composed)
	} else {
		doc, pages, owned, err = docintake.CreatePDFTemplateDocument(ctx, q, s.Storage, actor.OrgID, actor.UserID, in.Name, templateID, expires, pdf)
	}
	if err != nil {
		return nil, 0, err
	}
	object := cleanupObjectVersion{Key: owned.Key, VersionID: owned.VersionID, SHA256: owned.SHA256[:]}
	// An ambiguous COMMIT must retain its object until the canonical inventory
	// determines whether the database committed. Never delete a possibly live PDF.
	commitAttempted := false
	defer func() {
		if failure != nil && !commitAttempted {
			failure = errors.Join(failure, deleteObjectDetached(ctx, s.Storage, object))
		}
	}()
	doc, err = q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return nil, 0, err
	}
	variables, _ := json.Marshal(values)
	doc, err = q.FreezeDocumentVariables(ctx, generated.FreezeDocumentVariablesParams{ID: doc.ID, OrgID: actor.OrgID, VariablesJson: variables, ExpectedUpdatedAt: doc.UpdatedAt})
	if err != nil {
		return nil, 0, err
	}
	bindings, err := createHTMLContractParties(ctx, q, doc, compiled, htmlmaster.Input{Values: values, Sections: in.Sections})
	if err != nil {
		return nil, 0, err
	}
	sourceInput := htmlsource.Input{TemplateID: templateID, TemplateVersion: revision.Version,
		TemplateContentSHA256: content.SHA256, MasterJSON: content.MasterJSON, DefaultVarsJSON: content.DefaultsJSON,
		Values: values, Sections: in.Sections, TemplateApprovedBy: uuid.UUID(revision.ApprovedBy.Bytes), TemplateApprovedAt: revision.ApprovedAt.Time,
		PartyBindings: bindings}
	if composed != nil {
		sourceInput.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, input, bindings, composed.Composition)
		if err != nil {
			return nil, 0, err
		}
	}
	provenance, err := htmlsource.New(sourceInput, doc)
	if err != nil {
		return nil, 0, err
	}
	doc, err = q.SetDocumentHTMLSource(ctx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: actor.OrgID, HtmlSourceJson: provenance, ExpectedUpdatedAt: doc.UpdatedAt})
	if err != nil {
		return nil, 0, err
	}
	doc, _, err = htmlmaterialization.RegisterOrigin(ctx, q, doc, int32(pages), actor.UserID)
	if err != nil {
		return nil, 0, err
	}
	if err := createHTMLSigningFields(ctx, q, doc); err != nil {
		return nil, 0, err
	}
	sourceCommitment, err := htmlsource.Commitment(doc)
	if err != nil {
		return nil, 0, err
	}
	if err := s.Billing.EnforceDocumentQuotaMutation(ctx, q, actor.OrgID); err != nil {
		return nil, 0, err
	}
	if _, err := versions.New(q).Snapshot(ctx, versions.SnapshotInput{DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind, VariablesJS: doc.VariablesJson, HTMLSourceJSON: doc.HtmlSourceJson, HTMLMaterializationID: doc.HtmlCurrentMaterializationID, CreatedBy: &actor.UserID, Via: versions.ViaHuman, Summary: "Created from approved HTML design"}); err != nil {
		return nil, 0, err
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &doc.ID, Kind: audit.KindDocumentCreated,
		Payload: map[string]any{"source_kind": "pdf", "authoring_kind": "html", "template_id": templateID, "template_version": revision.Version,
			"template_content_sha256": content.SHA256, "html_source_commitment": sourceCommitment, "pdf_sha256": hex.EncodeToString(doc.PdfSha256), "review_required": true, "changed_sections": rendered.ChangedSections,
			"contract_party_bindings": bindings, "contract_profile_digest": compiled.ProfileDigest()}})
	if err != nil {
		return nil, 0, err
	}
	if err := guard.Recheck(ctx); err != nil {
		return nil, 0, err
	}
	commitAttempted = true
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	s.Audit.Publish(pending)
	return doc, pages, nil
}

type htmlDocumentReviewInput struct {
	ExpectedUpdatedAt            string `json:"expected_updated_at"`
	ExpectedPDFSHA256            string `json:"expected_pdf_sha256"`
	ExpectedHTMLSourceCommitment string `json:"expected_html_source_commitment,omitempty"`
}

func (s *Server) handleReviewHTMLDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in htmlDocumentReviewInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	expected, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	digest, digestErr := hex.DecodeString(in.ExpectedPDFSHA256)
	if err != nil || digestErr != nil || len(digest) != 32 || in.ExpectedPDFSHA256 != strings.ToLower(in.ExpectedPDFSHA256) {
		writeError(w, http.StatusBadRequest, "current expected_updated_at and lowercase PDF SHA-256 are required")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML document review", err)
		return
	}
	if s.Pool == nil || s.Audit == nil {
		writeError(w, http.StatusServiceUnavailable, "document review unavailable")
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
	q := generated.New(tx)
	guard, err := authoring.LockDraft(ctx, tx, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML document review", err)
		return
	}
	if len(guard.Document.HtmlSourceJson) == 0 || !guard.Document.UpdatedAt.Time.Equal(expected) || !bytes.Equal(guard.Document.PdfSha256, digest) {
		writeError(w, http.StatusConflict, "document changed; preview and review its current PDF again")
		return
	}
	sourceCommitment, err := htmlsource.Commitment(guard.Document)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if _, err := htmlmaterialization.Current(ctx, q, guard.Document); err != nil {
		writeError(w, http.StatusConflict, "document source or history is inconsistent; review unavailable")
		return
	}
	if (guard.Document.HtmlCurrentMaterializationID.Valid && in.ExpectedHTMLSourceCommitment == "") ||
		(in.ExpectedHTMLSourceCommitment != "" && in.ExpectedHTMLSourceCommitment != sourceCommitment) {
		writeError(w, http.StatusConflict, "document source changed; preview and review its current PDF again")
		return
	}
	doc, err := q.MarkDocumentHTMLReviewed(ctx, generated.MarkDocumentHTMLReviewedParams{ID: id, OrgID: u.OrgID, ExpectedUpdatedAt: pgtype.Timestamptz{Time: expected, Valid: true}, ExpectedPdfSha256: digest, ReviewedBy: u.UserID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusForbidden, "only the document sender or an owner can review this PDF")
		return
	}
	if err != nil {
		s.writeDraftAuthoringError(w, "record HTML document review", err)
		return
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id, Kind: audit.KindDocumentUpdated,
		Payload: map[string]any{"html_pdf_reviewed": true, "pdf_sha256": in.ExpectedPDFSHA256, "html_source_commitment": sourceCommitment}})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := guard.Recheck(ctx); err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML review commit", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pending)
	writeJSON(w, http.StatusOK, toDocumentResponse(doc))
}
