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
	Name                          string                      `json:"name"`
	ExpectedTemplateVersion       int32                       `json:"expected_template_version"`
	ExpectedTemplateContentSHA256 string                      `json:"expected_template_content_sha256"`
	Values                        htmlStringMap               `json:"values"`
	Sections                      htmlStringMap               `json:"sections,omitempty"`
	ExpiresAt                     string                      `json:"expires_at,omitempty"`
	RequestID                     uuid.UUID                   `json:"request_id,omitempty"`
	ExpectedOrgID                 uuid.UUID                   `json:"expected_org_id,omitempty"`
	ExpectedUserID                uuid.UUID                   `json:"expected_user_id,omitempty"`
	CRMPopulation                 *CRMTemplatePopulationInput `json:"crm_population,omitempty"`
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
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if id == uuid.Nil {
		writeError(w, 400, "invalid template id")
		return
	}
	var in htmlDocumentInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(in.Name) == "" || utf8.RuneCountInString(in.Name) > 200 || strings.ContainsRune(in.Name, '\x00') {
		writeError(w, 400, "name must contain 1 to 200 characters")
		return
	}
	digest, err := hex.DecodeString(in.ExpectedTemplateContentSHA256)
	if err != nil || len(digest) != 32 || in.ExpectedTemplateVersion <= 0 || in.ExpectedTemplateContentSHA256 != strings.ToLower(in.ExpectedTemplateContentSHA256) {
		writeError(w, 428, "reviewed template version and content SHA-256 are required")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML document", err)
		return
	}
	actor := authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}
	if err := in.checkExpectedActor(actor); err != nil {
		writeError(w, 409, "creation actor changed; refresh the current session")
		return
	}
	if s.Pool == nil {
		writeError(w, 503, "HTML document creation unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
	defer cancel()
	var inputDigest string
	if in.RequestID != uuid.Nil {
		inputDigest, err = crmTemplateCreateInputDigest(actor, id, in)
		if err != nil {
			s.writeCRMTemplateError(w, err)
			return
		}
		committed, err := s.findHTMLCreationRequest(ctx, actor, id, in.RequestID, inputDigest)
		if err != nil {
			s.writeHTMLCreationError(w, err)
			return
		}
		if committed != nil {
			writeJSON(w, 200, committed.response())
			return
		}
	}
	// A committed command remains recoverable after its original expiry,
	// approval, account or short review receipt ceases to permit NEW creation.
	var expires pgtype.Timestamptz
	if in.ExpiresAt != "" {
		value, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil || !value.After(time.Now()) {
			writeError(w, 400, "expires_at must be a future RFC3339 time")
			return
		}
		expires = pgtype.Timestamptz{Time: value, Valid: true}
	}
	if s.Audit == nil || s.Billing == nil || s.Storage == nil || s.Sign == nil || s.Sign.PDF == nil || s.Versions == nil {
		writeError(w, 503, "HTML document creation dependencies unavailable")
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, 429, err.Error())
		return
	}
	defer release()
	admission, err := s.prepareCRMTemplatePopulation(ctx, r, actor, id, in)
	if err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	result, err := s.instantiateHTMLDocument(ctx, actor, id, in, digest, expires, admission, inputDigest)
	if err != nil {
		s.writeHTMLCreationError(w, err)
		return
	}
	status := http.StatusCreated
	if result.replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, result.response())
}

func (s *Server) writeHTMLCreationError(w http.ResponseWriter, err error) {
	if errors.Is(err, errHTMLCreationAudit) {
		writeError(w, 500, "document creation audit unavailable")
		return
	}
	if errors.Is(err, errHTMLCreationRequestConflict) || errors.Is(err, errHTMLCreationRequestClosed) {
		writeError(w, 409, err.Error())
		return
	}
	if errors.Is(err, errHTMLCreationClosureUnavailable) || errors.Is(err, context.DeadlineExceeded) {
		writeError(w, 503, "creation request outcome unavailable; inspect this same request")
		return
	}
	if errors.Is(err, errCRMTemplateChanged) || errors.Is(err, errCRMTemplateInput) || errors.Is(err, errCRMTemplateReceipt) {
		s.writeCRMTemplateError(w, err)
		return
	}
	if writePDFWorkerError(w, err) {
		return
	}
	if errors.Is(err, malwarescan.ErrDetected) || errors.Is(err, malwarescan.ErrUnavailable) {
		writeScanError(w, err)
		return
	}
	if errors.Is(err, docintake.ErrSanitizePDF) || errors.Is(err, docintake.ErrTooManyPages) {
		writeError(w, 400, "rendered PDF could not be accepted")
		return
	}
	if s.writeAuthoringQuotaError(w, err) {
		return
	}
	s.writeHTMLTemplateError(w, "instantiate HTML template", err)
}

// The saved origin is captured in a short transaction and rechecked in the
// final transaction. Renderer, worker and storage operations occur between them.
type preparedHTMLDraft struct {
	revision *generated.HtmlTemplateRevision
	content  htmlmaster.TemplateCommitment
	compiled *htmlmaster.Compiled
	values   map[string]string
	sections htmlStringMap
	rendered htmlmaster.Result
}

func (prepared *preparedHTMLDraft) matches(revision *generated.HtmlTemplateRevision, content htmlmaster.TemplateCommitment) bool {
	return prepared != nil && revision != nil && revision.ApprovedBy == prepared.revision.ApprovedBy &&
		revision.ApprovedAt.Time.Equal(prepared.revision.ApprovedAt.Time) &&
		bytes.Equal(content.MasterJSON, prepared.content.MasterJSON) && bytes.Equal(content.DefaultsJSON, prepared.content.DefaultsJSON)
}

// Refuse revoked/expired original credentials or drift before writing an object.
// This short read transaction ends before worker/storage work. The final write
// transaction must still repeat all checks, including quota and audit waits.
func (s *Server) recheckHTMLPreparation(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte, prepared *preparedHTMLDraft, crm *crmTemplatePopulationAdmission) error {
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, revision, content, err := s.lockHTMLCreationTemplate(ctx, tx, actor, templateID, in, digest)
	if err != nil {
		return err
	}
	if !prepared.matches(revision, content) {
		return errHTMLTemplateConflict
	}
	if crm != nil {
		if err = crm.checkLocked(ctx, s, tx, actor); err != nil {
			return err
		}
	}
	if err = guard.Recheck(ctx); err != nil {
		return err
	}
	if in.ExpiresAt != "" {
		at, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil || !at.After(time.Now()) {
			return errCRMTemplateInput
		}
	}
	return tx.Commit(ctx)
}

func (s *Server) lockHTMLCreationTemplate(ctx context.Context, tx pgx.Tx, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte) (*authoring.MemberGuard, *generated.HtmlTemplateRevision, htmlmaster.TemplateCommitment, error) {
	q := generated.New(tx)
	template, err := q.GetHTMLTemplateForShare(ctx, generated.GetHTMLTemplateForShareParams{ID: templateID, OrgID: actor.OrgID})
	if err != nil {
		return nil, nil, htmlmaster.TemplateCommitment{}, err
	}
	if template.Version != in.ExpectedTemplateVersion || !bytes.Equal(template.HtmlContentSha256, digest) {
		return nil, nil, htmlmaster.TemplateCommitment{}, errHTMLTemplateConflict
	}
	revision, err := q.GetHTMLTemplateRevisionForShare(ctx, generated.GetHTMLTemplateRevisionForShareParams{TemplateID: templateID, OrgID: actor.OrgID, Version: in.ExpectedTemplateVersion})
	if err != nil {
		return nil, nil, htmlmaster.TemplateCommitment{}, err
	}
	if !revision.ApprovedBy.Valid || !revision.ApprovedAt.Valid || !bytes.Equal(revision.ContentSha256, digest) {
		return nil, nil, htmlmaster.TemplateCommitment{}, errHTMLTemplateConflict
	}
	guard, err := authoring.LockAuthor(ctx, tx, actor)
	if err != nil {
		return nil, nil, htmlmaster.TemplateCommitment{}, err
	}
	content, err := htmlmaster.CanonicalTemplate(revision.HtmlMasterJson, revision.VariablesJson)
	if err != nil || content.SHA256 != in.ExpectedTemplateContentSHA256 {
		return nil, nil, htmlmaster.TemplateCommitment{}, errHTMLTemplateConflict
	}
	return guard, revision, content, nil
}

func (s *Server) prepareHTMLDraft(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte, crm *crmTemplatePopulationAdmission) (*preparedHTMLDraft, error) {
	readCtx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(readCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(readCtx, tx) }()
	guard, revision, content, err := s.lockHTMLCreationTemplate(readCtx, tx, actor, templateID, in, digest)
	if err != nil {
		return nil, err
	}
	if err = guard.Recheck(readCtx); err != nil {
		return nil, err
	}
	if err = tx.Commit(readCtx); err != nil {
		return nil, err
	}
	master, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		return nil, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	if err = json.Unmarshal(content.DefaultsJSON, &values); err != nil {
		return nil, err
	}
	for name, value := range in.Values {
		values[name] = value
	}
	if crm != nil {
		if err = crm.checkDeadline(); err != nil {
			return nil, err
		}
		values = crm.effectiveValues()
	}
	sections := htmlStringMap{}
	for name, text := range in.Sections {
		sections[name] = text
	}
	rendered, err := compiled.Materialize(htmlmaster.Input{Values: values, Sections: sections})
	if err != nil {
		return nil, err
	}
	return &preparedHTMLDraft{revision: revision, content: content, compiled: compiled, values: values, sections: sections, rendered: rendered}, nil
}

func (s *Server) instantiateHTMLDocument(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte, expires pgtype.Timestamptz, crm *crmTemplatePopulationAdmission, inputDigest string) (result *htmlCreationOutcome, failure error) {
	if err := in.checkExpectedActor(actor); err != nil {
		return nil, err
	}
	prepared, err := s.prepareHTMLDraft(ctx, actor, templateID, in, digest, crm)
	if err != nil {
		return nil, err
	}
	pdf, err := s.Sign.PDF.HTMLToPDF(ctx, prepared.rendered.HTML, render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms"})
	if err != nil {
		return nil, err
	}
	input := htmlmaster.Input{Values: prepared.values, Sections: prepared.sections}
	var composed *sanitize.PDFCompositionResult
	if prepared.compiled.SigningPagePolicy() != nil {
		composition, err := s.composeHTMLSigningPage(ctx, prepared.compiled, input, pdf)
		if err != nil {
			return nil, err
		}
		composed = &composition
	}
	if err = s.recheckHTMLPreparation(ctx, actor, templateID, in, digest, prepared, crm); err != nil {
		return nil, err
	}
	var artifact *docintake.PreparedPDFSource
	if composed != nil {
		artifact, err = docintake.PrepareComposedPDFTemplateSource(ctx, s.Storage, actor.OrgID, *composed)
	} else {
		artifact, err = docintake.PreparePDFTemplateSource(ctx, s.Storage, actor.OrgID, pdf)
	}
	if err != nil {
		return nil, err
	}
	owned := artifact.OwnedSource()
	object := cleanupObjectVersion{Key: owned.Key, VersionID: owned.VersionID, SHA256: owned.SHA256[:]}
	// Before COMMIT the exact newly prepared object belongs to this operation.
	// Once COMMIT is attempted, preserve it even on an ambiguous response.
	commitAttempted := false
	defer func() {
		if !commitAttempted {
			failure = errors.Join(failure, deleteObjectDetached(ctx, s.Storage, object))
		}
	}()
	finalCtx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(finalCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(finalCtx, tx) }()
	q := generated.New(tx)
	if in.RequestID != uuid.Nil {
		// Retiring a request must fence final creation even when billing is
		// intentionally disabled for a direct internal caller.
		if err = q.LockBillingUsageForOrg(finalCtx, actor.OrgID.String()); err != nil {
			return nil, err
		}
	}
	if err = s.Billing.LockDocumentQuotaMutation(finalCtx, q, actor.OrgID); err != nil {
		return nil, err
	}
	// A concurrent exact command can have committed while this request prepared
	// its PDF. The quota lock serializes final creation; discard only our unused
	// object and return the original durable result.
	if in.RequestID != uuid.Nil {
		existing, closed, err := readHTMLCreationResolution(finalCtx, q, actor, templateID, in.RequestID, inputDigest)
		if err != nil {
			return nil, err
		}
		if closed != nil {
			return nil, errHTMLCreationRequestClosed
		}
		if existing != nil {
			guard, err := authoring.LockAuthor(finalCtx, tx, actor)
			if err != nil {
				return nil, err
			}
			if err = guard.Recheck(finalCtx); err != nil {
				return nil, err
			}
			if err = tx.Commit(finalCtx); err != nil {
				return nil, err
			}
			return existing, nil
		}
	}
	guard, revision, content, err := s.lockHTMLCreationTemplate(finalCtx, tx, actor, templateID, in, digest)
	if err != nil {
		return nil, err
	}
	if !prepared.matches(revision, content) {
		return nil, errHTMLTemplateConflict
	}
	if expires.Valid && !expires.Time.After(time.Now()) {
		return nil, errCRMTemplateInput
	}
	if crm != nil {
		if err = crm.checkLocked(finalCtx, s, tx, actor); err != nil {
			return nil, err
		}
	}
	doc, err := artifact.Attach(finalCtx, q, actor.OrgID, actor.UserID, in.Name, templateID, expires)
	if err != nil {
		return nil, err
	}
	doc, err = q.GetDocument(finalCtx, generated.GetDocumentParams{ID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return nil, err
	}
	variables, err := json.Marshal(prepared.values)
	if err != nil {
		return nil, err
	}
	doc, err = q.FreezeDocumentVariables(finalCtx, generated.FreezeDocumentVariablesParams{ID: doc.ID, OrgID: actor.OrgID, VariablesJson: variables, ExpectedUpdatedAt: doc.UpdatedAt})
	if err != nil {
		return nil, err
	}
	bindings, err := createHTMLContractParties(finalCtx, q, doc, prepared.compiled, input)
	if err != nil {
		return nil, err
	}
	sourceInput := htmlsource.Input{TemplateID: templateID, TemplateVersion: revision.Version, TemplateContentSHA256: content.SHA256,
		MasterJSON: content.MasterJSON, DefaultVarsJSON: content.DefaultsJSON, Values: prepared.values, Sections: prepared.sections,
		TemplateApprovedBy: uuid.UUID(revision.ApprovedBy.Bytes), TemplateApprovedAt: revision.ApprovedAt.Time, PartyBindings: bindings}
	if composed != nil {
		sourceInput.SigningArtifact, err = htmlsource.NewSigningArtifact(prepared.compiled, input, bindings, composed.Composition)
		if err != nil {
			return nil, err
		}
	}
	provenance, err := htmlsource.New(sourceInput, doc)
	if err != nil {
		return nil, err
	}
	doc, err = q.SetDocumentHTMLSource(finalCtx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: actor.OrgID, HtmlSourceJson: provenance, ExpectedUpdatedAt: doc.UpdatedAt})
	if err != nil {
		return nil, err
	}
	doc, _, err = htmlmaterialization.RegisterOrigin(finalCtx, q, doc, int32(artifact.PageCount()), actor.UserID)
	if err != nil {
		return nil, err
	}
	if err = createHTMLSigningFields(finalCtx, q, doc); err != nil {
		return nil, err
	}
	sourceCommitment, err := htmlsource.Commitment(doc)
	if err != nil {
		return nil, err
	}
	if err = s.Billing.EnforceDocumentQuotaMutation(finalCtx, q, actor.OrgID); err != nil {
		return nil, err
	}
	if _, err = versions.New(q).Snapshot(finalCtx, versions.SnapshotInput{DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind,
		VariablesJS: doc.VariablesJson, HTMLSourceJSON: doc.HtmlSourceJson, HTMLMaterializationID: doc.HtmlCurrentMaterializationID,
		CreatedBy: &actor.UserID, Via: versions.ViaHuman, Summary: "Created from approved HTML design"}); err != nil {
		return nil, err
	}
	pending := []audit.PendingEvent{}
	if crm != nil {
		event, err := crm.persist(finalCtx, s, tx, actor, doc)
		if err != nil {
			return nil, err
		}
		pending = append(pending, event)
	}
	var request *generated.HtmlDocumentCreationRequest
	if in.RequestID != uuid.Nil {
		commandDigest, err := hex.DecodeString(inputDigest)
		if err != nil || len(commandDigest) != 32 {
			return nil, errHTMLCreationRequestConflict
		}
		request, err = q.InsertHTMLDocumentCreationRequest(finalCtx, generated.InsertHTMLDocumentCreationRequestParams{RequestID: in.RequestID, InputDigest: commandDigest,
			HtmlSourceCommitment: sourceCommitment, PageCount: int32(artifact.PageCount()), DocumentID: doc.ID, OrgID: actor.OrgID, ActorUserID: actor.UserID, TemplateID: templateID})
		if err != nil {
			return nil, err
		}
	}
	event, err := s.Audit.LogTx(finalCtx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &doc.ID, Kind: audit.KindDocumentCreated,
		Payload: map[string]any{"source_kind": "pdf", "authoring_kind": "html", "template_id": templateID, "template_version": revision.Version,
			"template_content_sha256": content.SHA256, "html_source_commitment": sourceCommitment, "pdf_sha256": hex.EncodeToString(doc.PdfSha256),
			"review_required": true, "changed_sections": prepared.rendered.ChangedSections, "contract_party_bindings": bindings,
			"contract_profile_digest": prepared.compiled.ProfileDigest(), "creation_request_id": in.RequestID, "creation_input_digest": inputDigest}})
	if err != nil {
		return nil, errors.Join(errHTMLCreationAudit, err)
	}
	pending = append(pending, event)
	if err = guard.Recheck(finalCtx); err != nil {
		return nil, err
	}
	if crm != nil {
		if err = crm.checkLocked(finalCtx, s, tx, actor); err != nil {
			return nil, err
		}
	}
	if expires.Valid && !expires.Time.After(time.Now()) {
		return nil, errCRMTemplateInput
	}
	commitAttempted = true
	if err = tx.Commit(finalCtx); err != nil {
		return nil, err
	}
	for _, event := range pending {
		s.Audit.Publish(event)
	}
	return &htmlCreationOutcome{document: doc, pages: artifact.PageCount(), request: request}, nil
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
