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
	"sync"
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
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
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
	if !s.requireHTMLAuthoringRuntimeV1(w) {
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
	r, closeInput, inputOK := s.beginHTMLAuthoringInputV1(w, r, u.OrgID, pdfadmission.HTMLDocumentCreationInputV1)
	if !inputOK {
		return
	}
	defer closeInput()
	var in htmlDocumentInput
	if err := decodeSignerJSON(r, &in); err != nil {
		if writeHTMLAuthoringInputFailureV1(w, err) {
			return
		}
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
			defer committed.closeOwnedWriterV1()
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
	defer admission.closeOwnedV1()
	result, err := s.instantiateHTMLDocument(ctx, actor, id, in, digest, expires, admission, inputDigest)
	if err != nil {
		s.writeHTMLCreationError(w, err)
		return
	}
	defer result.closeOwnedWriterV1()
	status := http.StatusCreated
	if result.replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, result.response())
}

func (s *Server) writeHTMLCreationError(w http.ResponseWriter, err error) {
	if errors.Is(err, pdfadmission.ErrHTMLCreationWriterV1) || errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) || errors.Is(err, pdfadmission.ErrHTMLAuditEventV1) {
		writeError(w, 503, "HTML document creation is temporarily unavailable")
		return
	}
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
	revision   *generated.HtmlTemplateRevision
	content    htmlmaster.TemplateCommitment
	compiled   *htmlmaster.Compiled
	values     map[string]string
	sections   htmlStringMap
	rendered   htmlmaster.Result
	closeOwned func()
}

func (prepared *preparedHTMLDraft) matches(revision *generated.HtmlTemplateRevision, content htmlmaster.TemplateCommitment) bool {
	return prepared != nil && revision != nil && revision.ApprovedBy == prepared.revision.ApprovedBy &&
		revision.ApprovedAt.Time.Equal(prepared.revision.ApprovedAt.Time) &&
		bytes.Equal(content.MasterJSON, prepared.content.MasterJSON) && bytes.Equal(content.DefaultsJSON, prepared.content.DefaultsJSON)
}

// Refuse revoked/expired original credentials or drift before writing an object.
// This short read transaction ends before worker/storage work. The final write
// transaction must still repeat all checks, including quota and audit waits.
func (s *Server) recheckHTMLPreparation(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte, prepared *preparedHTMLDraft, crm htmlPopulationV1) (failure error) {
	defer func() { failure = preSignAPIHTMLCreationFailureV1(ctx, "html_recheck", failure) }()
	crm = normalizeHTMLPopulationV1(crm)
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	o, err := s.openHTMLAuthoringV1(ctx, actor.OrgID, templateID)
	if err != nil {
		return err
	}
	defer o.closeConsumerV1(ctx)
	defer func() { _ = o.closeSQLV1(ctx) }()
	err = o.session.WithTxV1(ctx, func(ctx context.Context, owned generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		guard, revision, content, err := s.lockHTMLCreationTemplateRecheckV1(ctx, tx, actor, templateID, in, digest)
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
		return nil
	})
	if err != nil {
		return err
	}
	return o.session.CommitV1(ctx)
}

func (s *Server) lockHTMLCreationTemplate(ctx context.Context, tx pgx.Tx, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte) (*authoring.MemberGuard, *generated.HtmlTemplateRevision, htmlmaster.TemplateCommitment, error) {
	return s.lockHTMLCreationTemplateForV1(ctx, tx, actor, templateID, in, digest, false)
}

func (s *Server) lockHTMLCreationTemplateRecheckV1(ctx context.Context, tx pgx.Tx, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte) (*authoring.MemberGuard, *generated.HtmlTemplateRevision, htmlmaster.TemplateCommitment, error) {
	return s.lockHTMLCreationTemplateForV1(ctx, tx, actor, templateID, in, digest, true)
}

// Only preparation/preview use the full retained materialization profile.
// Final/recheck transactions compare pins and retain declarations/defaults only.
func (s *Server) lockHTMLCreationTemplateForV1(ctx context.Context, tx pgx.Tx, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte, recheck bool) (*authoring.MemberGuard, *generated.HtmlTemplateRevision, htmlmaster.TemplateCommitment, error) {
	reader, err := htmlAuthoringReaderV1(tx)
	if err != nil {
		return nil, nil, htmlmaster.TemplateCommitment{}, preSignAPIHTMLCreationFailureV1(ctx, "html_template_revision", err)
	}
	template, revision, err := reader.ReadTemplateRevisionV1(ctx, templateID, in.ExpectedTemplateVersion)
	if err != nil {
		return nil, nil, htmlmaster.TemplateCommitment{}, preSignAPIHTMLCreationFailureV1(ctx, "html_template_revision", err)
	}
	if template.Version != in.ExpectedTemplateVersion || !bytes.Equal(template.HtmlContentSha256, digest) ||
		!revision.ApprovedBy.Valid || !revision.ApprovedAt.Valid || !bytes.Equal(revision.ContentSha256, digest) {
		return nil, nil, htmlmaster.TemplateCommitment{}, errHTMLTemplateConflict
	}
	guard, err := lockHTMLAuthorV1(ctx, tx, actor, false)
	if err != nil {
		return nil, nil, htmlmaster.TemplateCommitment{}, preSignAPIHTMLCreationFailureV1(ctx, "html_template_author", err)
	}
	var content htmlmaster.TemplateCommitment
	if recheck {
		content, err = reader.CanonicalRetainedTemplateRecheckV1(ctx, templateID, in.ExpectedTemplateVersion)
	} else {
		content, err = reader.CanonicalRetainedTemplateV1(ctx, templateID, in.ExpectedTemplateVersion)
	}
	if errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
		return nil, nil, htmlmaster.TemplateCommitment{}, preSignAPIHTMLCreationFailureV1(ctx, "html_template_canonical", err)
	}
	if err != nil || content.SHA256 != in.ExpectedTemplateContentSHA256 {
		return nil, nil, htmlmaster.TemplateCommitment{}, errHTMLTemplateConflict
	}
	return guard, revision, content, nil
}

func (s *Server) prepareHTMLDraft(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte, crm htmlPopulationV1) (result *preparedHTMLDraft, failure error) {
	phase := "html_prepare"
	defer func() { failure = preSignAPIHTMLCreationFailureV1(ctx, phase, failure) }()
	crm = normalizeHTMLPopulationV1(crm)
	readCtx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	phase = "html_prepare_open"
	o, err := s.openHTMLAuthoringV1(readCtx, actor.OrgID, templateID)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = o.closeSQLV1(ctx)
		if result == nil {
			o.closeConsumerV1(ctx)
		}
	}()
	var revision *generated.HtmlTemplateRevision
	var content htmlmaster.TemplateCommitment
	err = o.session.WithTxV1(readCtx, func(readCtx context.Context, owned generated.DBTX) error {
		// Bind actual typed input maps before defaults/input clones, Marshal or HTML.
		producerValues := map[string]string(in.Values)
		if crm != nil {
			if retained := crm.retainedInputValuesV1(); retained != nil {
				producerValues = retained
			}
		}
		phase = "html_prepare_maps"
		if err := o.reader.AcquireStringMapsV1(readCtx, producerValues, in.Sections); err != nil {
			return err
		}
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: o.reader}
		guard, r, c, err := s.lockHTMLCreationTemplate(readCtx, tx, actor, templateID, in, digest)
		if err != nil {
			return err
		}
		revision, content = r, c
		phase = "html_template_author"
		return guard.Recheck(readCtx)
	})
	if err != nil {
		return nil, err
	}
	phase = "html_prepare_commit"
	if err = o.session.CommitV1(readCtx); err != nil {
		return nil, err
	}
	phase = "html_prepare"
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
	return &preparedHTMLDraft{revision: revision, content: content, compiled: compiled, values: values, sections: sections, rendered: rendered, closeOwned: func() { o.closeConsumerV1(ctx) }}, nil
}

func (s *Server) instantiateHTMLDocument(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte, expires pgtype.Timestamptz, crm *crmTemplatePopulationAdmission, inputDigest string) (result *htmlCreationOutcome, failure error) {
	return s.instantiateHTMLDocumentPopulationV1(ctx, actor, templateID, in, digest, expires, normalizeHTMLPopulationV1(crm), inputDigest)
}

func (s *Server) instantiateHTMLDocumentPopulationV1(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, in htmlDocumentInput, digest []byte, expires pgtype.Timestamptz, crm htmlPopulationV1, inputDigest string) (result *htmlCreationOutcome, failure error) {
	phase := "html_prepare"
	defer func() { failure = preSignAPIHTMLCreationFailureV1(ctx, phase, failure) }()
	crm = normalizeHTMLPopulationV1(crm)
	if err := in.checkExpectedActor(actor); err != nil {
		return nil, err
	}
	if s.HTMLCreationSessions == nil {
		return nil, pdfadmission.ErrHTMLCreationWriterV1
	}
	prepared, err := s.prepareHTMLDraft(ctx, actor, templateID, in, digest, crm)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil && prepared.closeOwned != nil {
			prepared.closeOwned()
		}
	}()
	phase = "html_render"
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
	phase = "html_recheck"
	if err = s.recheckHTMLPreparation(ctx, actor, templateID, in, digest, prepared, crm); err != nil {
		return nil, err
	}
	phase = "html_artifact"
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
	variables, err := json.Marshal(prepared.values)
	if err != nil {
		return nil, err
	}
	sections, err := json.Marshal(prepared.sections)
	if err != nil {
		return nil, err
	}
	// Resource identity precedes only a real fresh INSERT; it grants no contract authority.
	documentID := uuid.New()
	phase = "html_final_open"
	session, err := s.HTMLCreationSessions.OpenV1(finalCtx, actor.OrgID, documentID)
	if err != nil {
		if session != nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cleanupCancel()
			_ = session.CloseV1(cleanupCtx)
		}
		return nil, err
	}
	admission, err := session.NewAdmissionV1(finalCtx)
	if err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cleanupCancel()
		_ = session.CloseV1(cleanupCtx)
		return nil, err
	}
	var reader *pdfadmission.ApplicationHTMLAuthoringReaderV1
	var writer *pdfadmission.ApplicationHTMLCreationWriterV1
	var pending []audit.PendingEvent
	var pendingOwners []*pdfadmission.ApplicationHTMLAuditEventConsumerV1
	defer func() {
		if result == nil {
			for _, owner := range pendingOwners {
				if owner != nil {
					owner.CloseConsumerV1()
				}
			}
		}
		if result == nil && reader != nil {
			reader.CloseConsumerV1()
		}
		if result == nil && writer != nil {
			writer.CloseConsumerV1()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cleanupCancel()
		closeErr := session.CloseV1(cleanupCtx)
		_, reconcileErr := admission.ReconcileCleanupV1(cleanupCtx)
		if result == nil {
			failure = errors.Join(failure, closeErr, reconcileErr)
		}
	}()
	err = session.WithTxV1(finalCtx, func(finalCtx context.Context, owned generated.DBTX) error {
		phase = "html_final_open"
		reader, err = session.NewHTMLAuthoringReaderV1(finalCtx)
		if err != nil {
			return err
		}
		tx := &htmlCreationPolicyTxV1{DBTX: owned, reader: reader}
		q := generated.New(tx)
		phase = "html_final_writer"
		writer, err = session.NewHTMLCreationWriterV1(finalCtx, pdfadmission.HTMLCreationInputsV1{
			StoredMaster: prepared.revision.HtmlMasterJson, StoredDefaults: prepared.revision.VariablesJson,
			CanonicalMaster: prepared.content.MasterJSON, CanonicalDefaults: prepared.content.DefaultsJSON, Variables: variables, Sections: sections,
		})
		if err != nil {
			return err
		}

		phase = "html_final_source"
		if in.RequestID != uuid.Nil {
			// Retiring a request must fence final creation even when billing is
			// intentionally disabled for a direct internal caller.
			if err = q.LockBillingUsageForOrg(finalCtx, actor.OrgID.String()); err != nil {
				return err
			}
		}
		if err = s.Billing.LockDocumentQuotaMutation(finalCtx, q, actor.OrgID); err != nil {
			return err
		}
		// A concurrent exact command can have committed while this request prepared
		// its PDF. The quota lock serializes final creation; discard only our unused
		// object and return the original durable result.
		if in.RequestID != uuid.Nil {
			existing, closed, err := readHTMLCreationResolution(finalCtx, q, actor, templateID, in.RequestID, inputDigest, reader)
			if err != nil {
				return err
			}
			if closed != nil {
				return errHTMLCreationRequestClosed
			}
			if existing != nil {
				guard, err := lockHTMLAuthorV1(finalCtx, tx, actor, false)
				if err != nil {
					return err
				}
				if err = guard.Recheck(finalCtx); err != nil {
					return err
				}
				result = existing
				result.replayed = true
				return nil
			}
		}
		guard, revision, content, err := s.lockHTMLCreationTemplateRecheckV1(finalCtx, tx, actor, templateID, in, digest)
		if err != nil {
			return err
		}
		if !prepared.matches(revision, content) {
			return errHTMLTemplateConflict
		}
		if expires.Valid && !expires.Time.After(time.Now()) {
			return errCRMTemplateInput
		}
		if crm != nil {
			if err = crm.checkLocked(finalCtx, s, tx, actor); err != nil {
				return err
			}
		}
		doc, err := artifact.Attach(finalCtx, &htmlCreationAttachQueriesV1{Queries: q, writer: writer}, actor.OrgID, actor.UserID, in.Name, templateID, expires)
		if err != nil {
			return err
		}
		doc, err = q.GetDocument(finalCtx, generated.GetDocumentParams{ID: doc.ID, OrgID: actor.OrgID})
		if err != nil {
			return err
		}
		doc, err = writer.FreezeVariablesV1(finalCtx, doc.UpdatedAt)
		if err != nil {
			return err
		}
		bindings, err := createHTMLContractParties(finalCtx, q, doc, prepared.compiled, input)
		if err != nil {
			return err
		}
		sourceInput := htmlsource.Input{TemplateID: templateID, TemplateVersion: revision.Version, TemplateContentSHA256: content.SHA256,
			MasterJSON: content.MasterJSON, DefaultVarsJSON: content.DefaultsJSON, Values: prepared.values, Sections: prepared.sections,
			TemplateApprovedBy: uuid.UUID(revision.ApprovedBy.Bytes), TemplateApprovedAt: revision.ApprovedAt.Time, PartyBindings: bindings}
		if composed != nil {
			sourceInput.SigningArtifact, err = htmlsource.NewSigningArtifact(prepared.compiled, input, bindings, composed.Composition)
			if err != nil {
				return err
			}
		}
		provenance, err := htmlsource.New(sourceInput, doc)
		if err != nil {
			return err
		}
		doc, err = writer.SetSourceAndOriginV1(finalCtx, provenance, doc.UpdatedAt, int32(artifact.PageCount()), actor.UserID)
		if err != nil {
			return err
		}
		if err = createHTMLSigningFields(finalCtx, q, doc); err != nil {
			return err
		}
		if err = writer.MeasureFreshPolicyV1(finalCtx); err != nil {
			return err
		}
		sourceCommitment, err := htmlsource.Commitment(doc)
		if err != nil {
			return err
		}
		if err = s.Billing.EnforceDocumentQuotaMutation(finalCtx, q, actor.OrgID); err != nil {
			return err
		}
		if _, err = versions.New(q).Snapshot(finalCtx, versions.SnapshotInput{DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind,
			VariablesJS: doc.VariablesJson, HTMLSourceJSON: doc.HtmlSourceJson, HTMLMaterializationID: doc.HtmlCurrentMaterializationID,
			CreatedBy: &actor.UserID, Via: versions.ViaHuman, Summary: "Created from approved HTML design"}); err != nil {
			return err
		}
		pending = []audit.PendingEvent{}
		pendingOwners = []*pdfadmission.ApplicationHTMLAuditEventConsumerV1{}
		if crm != nil {
			event, err := crm.persist(finalCtx, s, tx, actor, doc)
			if err != nil {
				return err
			}
			pending = append(pending, event)
			pendingOwners = append(pendingOwners, nil)
		}
		var request *generated.HtmlDocumentCreationRequest
		if in.RequestID != uuid.Nil {
			commandDigest, err := hex.DecodeString(inputDigest)
			if err != nil || len(commandDigest) != 32 {
				return errHTMLCreationRequestConflict
			}
			request, err = q.InsertHTMLDocumentCreationRequest(finalCtx, generated.InsertHTMLDocumentCreationRequestParams{RequestID: in.RequestID, InputDigest: commandDigest,
				HtmlSourceCommitment: sourceCommitment, PageCount: int32(artifact.PageCount()), DocumentID: doc.ID, OrgID: actor.OrgID, ActorUserID: actor.UserID, TemplateID: templateID})
			if err != nil {
				return err
			}
		}
		event, eventOwner, err := ownedaudit.LogV1(s.Audit, finalCtx, session, pdfadmission.HTMLAuditDocumentCreatedV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &doc.ID, Kind: audit.KindDocumentCreated,
			Payload: map[string]any{"source_kind": "pdf", "authoring_kind": "html", "template_id": templateID, "template_version": revision.Version,
				"template_content_sha256": content.SHA256, "html_source_commitment": sourceCommitment, "pdf_sha256": hex.EncodeToString(doc.PdfSha256),
				"review_required": true, "changed_sections": prepared.rendered.ChangedSections, "contract_party_bindings": bindings,
				"contract_profile_digest": prepared.compiled.ProfileDigest(), "creation_request_id": in.RequestID, "creation_input_digest": inputDigest}})
		if err != nil {
			return errors.Join(errHTMLCreationAudit, err)
		}
		pending = append(pending, event)
		pendingOwners = append(pendingOwners, eventOwner)
		if err = guard.Recheck(finalCtx); err != nil {
			return err
		}
		if crm != nil {
			if err = crm.checkLocked(finalCtx, s, tx, actor); err != nil {
				return err
			}
		}
		if expires.Valid && !expires.Time.After(time.Now()) {
			return errCRMTemplateInput
		}
		result = &htmlCreationOutcome{document: doc, pages: artifact.PageCount(), request: request}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, pdfadmission.ErrHTMLCreationWriterV1
	}
	// A replay has no newly attached object; preserve only genuine new-creation uncertainty.
	commitAttempted = !result.replayed
	phase = "html_final_commit"
	if err = session.CommitV1(finalCtx); err != nil {
		// Observe only this SAME native owner after its synchronous Commit returns.
		// A genuine pre-dispatch refusal may compensate the unused fresh object;
		// every actual/unknown attempt retains it. This is no retirement/replay proof.
		if !result.replayed && session.CommitDispatchObservationV1().NeverDispatchedV1() {
			commitAttempted = false
		}
		result = nil
		return nil, err
	}
	phase = "html_postcommit_publish"
	for i, event := range pending {
		if pendingOwners[i] != nil {
			if err = ownedaudit.PublishV1(s.Audit, event, pendingOwners[i]); err != nil {
				return nil, err
			}
			pendingOwners[i] = nil
		} else {
			s.Audit.Publish(detachHTMLCreationEventIDsV1(event))
		}
	}
	var closeOnce sync.Once
	result.closeOwnedWriter = func() {
		closeOnce.Do(func() {
			writer.CloseConsumerV1()
			reader.CloseConsumerV1()
			if prepared.closeOwned != nil {
				prepared.closeOwned()
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cleanupCancel()
			_ = s.HTMLCreationSessions.ReconcileCleanupV1(cleanupCtx)
		})
	}
	return result, nil
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
	document, release, err := s.reviewHTMLDocumentOwnedV1(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, in, expected, digest)
	if err != nil {
		s.writeOwnedHTMLReviewErrorV1(w, err)
		return
	}
	defer release()
	writeJSON(w, http.StatusOK, toDocumentResponse(document))
}
