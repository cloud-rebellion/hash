// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/versions"
)

var errHTMLTemplateMovePinsV1 = errors.New("expected_updated_at, expected_html_source_commitment, template_version and expected_template_content_sha256 are required")

// All four pins are mandatory. Values and sections are optional overrides that
// must be declared by the target version; undeclared names are refused.
type htmlDocumentTemplateMoveInputV1 struct {
	ExpectedUpdatedAt             string        `json:"expected_updated_at"`
	ExpectedHTMLSourceCommitment  string        `json:"expected_html_source_commitment"`
	TemplateVersion               int32         `json:"template_version"`
	ExpectedTemplateContentSHA256 string        `json:"expected_template_content_sha256"`
	Values                        htmlStringMap `json:"values,omitempty"`
	Sections                      htmlStringMap `json:"sections,omitempty"`
	Summary                       string        `json:"summary,omitempty"`
	// via is set by the transport, never decoded from a request.
	via versions.Via
}

type htmlTemplateMoveResultV1 struct {
	Document                *generated.Document
	MaterializationRevision int32
	PageCount               int
	Diff                    pdfadmission.HTMLTemplateMoveDiffV1
}

func (in htmlDocumentTemplateMoveInputV1) validatePinsV1() (time.Time, error) {
	expected, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil || !htmlPreviewSHA256(in.ExpectedHTMLSourceCommitment) || !htmlPreviewSHA256(in.ExpectedTemplateContentSHA256) || in.TemplateVersion < 1 {
		return time.Time{}, errHTMLTemplateMovePinsV1
	}
	return expected, nil
}

func (in htmlDocumentTemplateMoveInputV1) snapshotViaV1() versions.Via {
	if in.via != "" {
		return in.via
	}
	return versions.ViaHuman
}

func validHTMLMoveSummaryV1(summary string) bool {
	return utf8.ValidString(summary) && utf8.RuneCountInString(summary) <= 500 && !strings.ContainsRune(summary, '\x00')
}

func (in htmlDocumentTemplateMoveInputV1) revisionPinsV1() htmlDocumentRevisionInput {
	return htmlDocumentRevisionInput{ExpectedUpdatedAt: in.ExpectedUpdatedAt, ExpectedHTMLSourceCommitment: in.ExpectedHTMLSourceCommitment}
}

// loadHTMLTemplateMoveV1 runs under the draft lock in the caller's transaction.
// It checks the document pins, then proves the target is an approved, content
// verified, newer revision of the document's own template and plans the inputs.
func (s *Server) loadHTMLTemplateMoveV1(ctx context.Context, tx pgx.Tx, actor authoring.Actor, id uuid.UUID, in htmlDocumentTemplateMoveInputV1, expected time.Time) (*authoring.DraftGuard, htmlsource.Input, pdfadmission.HTMLTemplateMoveDiffV1, error) {
	var none pdfadmission.HTMLTemplateMoveDiffV1
	guard, err := s.lockHTMLDocumentRevision(ctx, tx, actor, id, in.revisionPinsV1(), expected)
	if err != nil {
		return nil, htmlsource.Input{}, none, err
	}
	current, err := htmlsource.InputForCurrent(guard.Document)
	if err != nil {
		return nil, htmlsource.Input{}, none, err
	}
	target, err := pdfadmission.LoadHTMLTemplateMoveTargetV1(ctx, generated.New(tx), actor.OrgID, current.TemplateID, in.TemplateVersion, in.ExpectedTemplateContentSHA256)
	if err != nil {
		return nil, htmlsource.Input{}, none, err
	}
	next, diff, err := pdfadmission.PlanHTMLTemplateMoveV1(current, target, in.Values, in.Sections)
	if err != nil {
		return nil, htmlsource.Input{}, none, err
	}
	return guard, next, diff, nil
}

func (s *Server) readHTMLTemplateMoveV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, in htmlDocumentTemplateMoveInputV1, expected time.Time) (*generated.Document, htmlsource.Input, pdfadmission.HTMLTemplateMoveDiffV1, error) {
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, htmlsource.Input{}, pdfadmission.HTMLTemplateMoveDiffV1{}, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, next, diff, err := s.loadHTMLTemplateMoveV1(ctx, tx, actor, id, in, expected)
	if err != nil {
		return nil, htmlsource.Input{}, pdfadmission.HTMLTemplateMoveDiffV1{}, err
	}
	if err = guard.Recheck(ctx); err != nil {
		return nil, htmlsource.Input{}, pdfadmission.HTMLTemplateMoveDiffV1{}, err
	}
	return guard.Document, next, diff, nil
}

// moveHTMLDocumentTemplateV1 follows the revision order: pins and target are
// read and the PDF is rendered and stored with no database lock held, then one
// transaction rechecks everything, appends the revision (which resets review
// and placed fields), updates parties, regenerates fields, snapshots the
// version and writes the audit event before commit.
func (s *Server) moveHTMLDocumentTemplateV1(parent context.Context, actor authoring.Actor, id uuid.UUID, in htmlDocumentTemplateMoveInputV1) (result *htmlTemplateMoveResultV1, failure error) {
	expected, err := in.validatePinsV1()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	doc, next, diff, err := s.readHTMLTemplateMoveV1(ctx, actor, id, in, expected)
	if err != nil {
		return nil, err
	}
	master, err := htmlmaster.Decode(next.MasterJSON)
	if err != nil {
		return nil, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return nil, err
	}
	rendered, err := compiled.Materialize(htmlmaster.Input{Values: next.Values, Sections: next.Sections})
	if err != nil {
		return nil, err
	}
	if err = scanHTMLMaster(ctx, next.MasterJSON); err != nil {
		return nil, err
	}
	previousPages := doc.HtmlCurrentPageCount.Int32
	if !doc.HtmlCurrentMaterializationID.Valid {
		previous, e := s.Storage.GetVerifiedVersion(ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
		if e != nil {
			return nil, e
		}
		count, e := sanitize.PageCountWithContext(ctx, previous)
		if e != nil || count < 1 || count > sanitize.MaxPDFPages {
			return nil, errHTMLDocumentRevisionConflict
		}
		previousPages = int32(count)
	}
	if _, _, _, err = s.readHTMLTemplateMoveV1(ctx, actor, id, in, expected); err != nil {
		return nil, err
	}
	processing, stopProcessing := context.WithTimeout(ctx, htmlTemplatePreviewTimeout)
	pdf, err := s.Sign.PDF.HTMLToPDF(processing, rendered.HTML, render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms"})
	if err != nil {
		stopProcessing()
		return nil, errHTMLDocumentRevisionRenderUnavailable
	}
	if len(pdf) == 0 || len(pdf) > sanitize.MaxPDFBytes {
		stopProcessing()
		return nil, errHTMLDocumentRevisionConflict
	}
	var cleaned sanitize.Result
	pages := 0
	htmlInput := htmlmaster.Input{Values: next.Values, Sections: next.Sections}
	if compiled.SigningPagePolicy() != nil {
		composed, composeErr := s.composeHTMLSigningPage(processing, compiled, htmlInput, pdf)
		if composeErr != nil {
			stopProcessing()
			return nil, composeErr
		}
		cleaned = composed.Result
		pages = composed.Composition.FinalPages
		next.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, htmlInput, next.PartyBindings, composed.Composition)
	} else {
		cleaned, err = sanitize.CleanWithContext(processing, "html-document-template-move", "application/pdf", pdf)
		if err == nil {
			pages, err = sanitize.PageCountWithContext(processing, cleaned.Bytes)
		}
	}
	stopProcessing()
	if err != nil {
		return nil, err
	}
	if cleaned.Report.UnsupportedT || pages < 1 || pages > sanitize.MaxPDFPages || len(cleaned.Bytes) == 0 || len(cleaned.Bytes) > sanitize.MaxPDFBytes {
		return nil, errHTMLDocumentRevisionConflict
	}
	report, err := sanitize.MergeReports(nil, cleaned.Report)
	if err != nil {
		return nil, err
	}
	if _, _, _, err = s.readHTMLTemplateMoveV1(ctx, actor, id, in, expected); err != nil {
		return nil, err
	}
	// A new object key even if the bytes happen to be identical to the old PDF.
	key := path.Join("org", actor.OrgID.String(), "documents", uuid.NewString()+".pdf")
	stored, err := s.Storage.PutVersioned(ctx, key, "application/pdf", cleaned.Bytes)
	if err != nil {
		return nil, err
	}
	owned := cleanupObjectVersion{Key: key, VersionID: stored.VersionID, SHA256: bytes.Clone(stored.SHA256[:])}
	commitAttempted := false
	defer func() {
		if failure != nil && !commitAttempted {
			failure = errors.Join(failure, deleteObjectDetached(parent, s.Storage, owned))
		}
	}()
	commitCtx, stopCommit := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer stopCommit()
	tx, err := s.Pool.BeginTx(commitCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(commitCtx, tx) }()
	guard, finalInput, _, err := s.loadHTMLTemplateMoveV1(commitCtx, tx, actor, id, in, expected)
	if err != nil {
		return nil, err
	}
	if finalInput.TemplateContentSHA256 != next.TemplateContentSHA256 {
		return nil, errHTMLDocumentRevisionConflict
	}
	oldCommitment, err := htmlsource.Commitment(guard.Document)
	if err != nil {
		return nil, err
	}
	oldInput, err := htmlsource.InputForCurrent(guard.Document)
	if err != nil {
		return nil, err
	}
	candidate := *guard.Document
	candidate.PdfStorageKey = pgtype.Text{String: key, Valid: true}
	candidate.PdfStorageVersionID = pgtype.Text{String: stored.VersionID, Valid: true}
	candidate.PdfSha256 = bytes.Clone(stored.SHA256[:])
	candidate.VariablesJson, err = json.Marshal(next.Values)
	if err != nil {
		return nil, err
	}
	source, err := htmlsource.New(next, &candidate)
	if err != nil {
		return nil, err
	}
	q := generated.New(tx)
	updated, row, err := htmlmaterialization.Append(commitCtx, q, guard.Document, &candidate, htmlmaterialization.AppendInput{SourceJSON: source, PageCount: int32(pages), PreviousPageCount: previousPages, ActorID: actor.UserID, Summary: strings.TrimSpace(in.Summary), MetadataRedactionReport: report, MeasureSnapshotSize: true})
	if err != nil {
		return nil, err
	}
	partiesChanged, err := updateHTMLContractParties(commitCtx, q, guard.Document, next)
	if err != nil {
		return nil, err
	}
	currentRecipients, err := q.ListRecipientsByDocument(commitCtx, id)
	if err != nil {
		return nil, err
	}
	if err = htmlsource.ValidateContractParties(updated, currentRecipients); err != nil {
		return nil, err
	}
	if err = createHTMLSigningFields(commitCtx, q, updated); err != nil {
		return nil, err
	}
	if _, err = versions.New(q).Snapshot(commitCtx, versions.SnapshotInput{DocumentID: id, OrgID: actor.OrgID, Name: updated.Name, SourceKind: updated.SourceKind, VariablesJS: updated.VariablesJson, HTMLSourceJSON: source, HTMLMaterializationID: updated.HtmlCurrentMaterializationID, CreatedBy: &actor.UserID, Via: in.snapshotViaV1(), Summary: "HTML design moved to a newer template version"}); err != nil {
		return nil, err
	}
	if err = measureMovedHTMLDocumentV1(commitCtx, q, updated); err != nil {
		return nil, err
	}
	pending, err := s.Audit.LogTx(commitCtx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &id, Kind: audit.KindDocumentUpdated, Payload: map[string]any{
		"html_materialization_revision": row.Sequence, "html_source_commitment": updated.HtmlEffectiveSourceCommitment.String,
		"previous_html_source_commitment": oldCommitment,
		"template_move":                   true, "via": in.snapshotViaV1(), "previous_template_version": oldInput.TemplateVersion, "template_version": next.TemplateVersion,
		"previous_template_content_sha256": oldInput.TemplateContentSHA256, "template_content_sha256": next.TemplateContentSHA256,
		"review_required": true, "placement_reset": true, "contract_party_identities_updated": partiesChanged,
		"adopted_default_values": nonNilStringsV1(diff.AdoptedDefaultValues), "dropped_values": nonNilStringsV1(diff.DroppedValues), "dropped_sections": nonNilStringsV1(diff.DroppedSections)}})
	if err != nil {
		return nil, err
	}
	if err = measureBorrowedAuditEventV1(commitCtx, q, actor.OrgID, id, pending.ID); err != nil {
		return nil, err
	}
	if err = guard.Recheck(commitCtx); err != nil {
		return nil, err
	}
	commitAttempted = true
	if err = tx.Commit(commitCtx); err != nil {
		return nil, err
	}
	s.Audit.Publish(pending)
	return &htmlTemplateMoveResultV1{Document: updated, MaterializationRevision: row.Sequence, PageCount: pages, Diff: diff}, nil
}

// The triggers drop the signing-policy, field-options and report size caches
// whenever the source, fields or report change. The live revise route measures
// them again with these same statements, under the document lock held here;
// without them the next review, revise or send answers 503.
// The owned revise writer gives every document event a payload size row
// (00094). audit.Logger now measures every document event it appends, in the
// caller's transaction, so a new LogTx writer needs nothing. These writers
// (template move, CRM population, pre-sign births) keep this call as an
// idempotent second proof; the statement is ON CONFLICT DO UPDATE.
func measureBorrowedAuditEventV1(ctx context.Context, q *generated.Queries, org, doc, event uuid.UUID) error {
	cache, err := q.MeasureHTMLSnapshotEventPayloadV1(ctx, generated.MeasureHTMLSnapshotEventPayloadV1Params{EventID: event, DocumentID: doc, OrgID: org})
	if err != nil {
		return err
	}
	if cache == nil || cache.EventID != event || cache.DocumentID != doc || cache.OrgID != org || cache.PayloadWireBytes < 2 || cache.MeasurementServerVersionNum <= 0 || !cache.MeasuredAt.Valid {
		return errors.New("borrowed audit event measurement refused")
	}
	return nil
}

func measureMovedHTMLDocumentV1(ctx context.Context, q *generated.Queries, doc *generated.Document) error {
	if _, err := q.MeasureSignatureFitHTMLPolicyDocumentV1(ctx, generated.MeasureSignatureFitHTMLPolicyDocumentV1Params{DocumentID: doc.ID, OrgID: doc.OrgID}); err != nil {
		return err
	}
	fields, err := q.ListFieldsByDocument(ctx, doc.ID)
	if err != nil {
		return err
	}
	for _, field := range fields {
		if _, err = q.MeasureSignatureFitHTMLPolicyFieldV1(ctx, generated.MeasureSignatureFitHTMLPolicyFieldV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, FieldID: field.ID}); err != nil {
			return err
		}
	}
	_, err = q.MeasureSignerDocumentReportV1(ctx, generated.MeasureSignerDocumentReportV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	return err
}

func (s *Server) handleMoveHTMLDocumentTemplateV1(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r, closeInput, ok := s.beginHTMLAuthoringInputV1(w, r, u.OrgID, pdfadmission.HTMLDocumentTemplateMoveInputV1)
	if !ok {
		return
	}
	defer closeInput()
	var in htmlDocumentTemplateMoveInputV1
	if err := decodeSignerJSON(r, &in); err != nil {
		if writeHTMLAuthoringInputFailureV1(w, err) {
			return
		}
		writeTemplateMoveErrorV1(w, http.StatusBadRequest, "template_move_invalid_body", "request body is not valid JSON for a template move")
		return
	}
	if _, err := in.validatePinsV1(); err != nil {
		writeTemplateMoveErrorV1(w, http.StatusPreconditionRequired, "template_move_pins_required", err.Error())
		return
	}
	if !validHTMLMoveSummaryV1(in.Summary) {
		writeTemplateMoveErrorV1(w, http.StatusBadRequest, "template_move_invalid_summary", "summary must contain at most 500 plain-text characters")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML template move", err)
		return
	}
	if s.Pool == nil || s.Audit == nil || s.Storage == nil || s.Sign == nil || s.Sign.PDF == nil || s.Versions == nil {
		writeTemplateMoveErrorV1(w, http.StatusServiceUnavailable, "template_move_unavailable", "HTML document revision dependencies unavailable")
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeTemplateMoveErrorV1(w, http.StatusTooManyRequests, "template_move_capacity", "HTML document revision capacity exceeded")
		return
	}
	defer release()
	result, err := s.moveHTMLDocumentTemplateV1(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, in)
	if err != nil {
		s.writeHTMLTemplateMoveErrorV1(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"document": toDocumentResponse(result.Document), "materialization_revision": result.MaterializationRevision, "page_count": result.PageCount, "review_required": true, "placement_reset": true, "adopted_default_values": nonNilStringsV1(result.Diff.AdoptedDefaultValues), "dropped_values": nonNilStringsV1(result.Diff.DroppedValues), "dropped_sections": nonNilStringsV1(result.Diff.DroppedSections)})
}

// Every template move refusal carries a stable machine code beside the text.
func writeTemplateMoveErrorV1(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": message, "code": code})
}

func nonNilStringsV1(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// Stale pins, a target that is not an approved revision of this template, a
// target that is not forward and a superseded target are 409; a request the
// document can never satisfy (schema or party slots change, undeclared names)
// is 422.
func (s *Server) writeHTMLTemplateMoveErrorV1(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errHTMLTemplateMovePinsV1):
		writeTemplateMoveErrorV1(w, http.StatusPreconditionRequired, "template_move_pins_required", err.Error())
	case errors.Is(err, pdfadmission.ErrHTMLTemplateMoveStaleV1):
		writeTemplateMoveErrorV1(w, http.StatusConflict, "template_move_stale", "template version or content changed, or is not an approved revision of this document's template")
	case errors.Is(err, pdfadmission.ErrHTMLTemplateMoveNotForwardV1):
		writeTemplateMoveErrorV1(w, http.StatusConflict, "template_move_not_forward", pdfadmission.ErrHTMLTemplateMoveNotForwardV1.Error())
	case errors.Is(err, pdfadmission.ErrHTMLTemplateMoveSupersededV1):
		writeTemplateMoveErrorV1(w, http.StatusConflict, "template_move_superseded", pdfadmission.ErrHTMLTemplateMoveSupersededV1.Error())
	case errors.Is(err, pdfadmission.ErrHTMLTemplateMoveSchemaV1):
		writeTemplateMoveErrorV1(w, http.StatusUnprocessableEntity, "template_move_schema_changed", pdfadmission.ErrHTMLTemplateMoveSchemaV1.Error())
	case errors.Is(err, pdfadmission.ErrHTMLTemplateMoveUndeclaredV1):
		writeTemplateMoveErrorV1(w, http.StatusUnprocessableEntity, "template_move_undeclared_name", err.Error())
	case errors.Is(err, malwarescan.ErrDetected), errors.Is(err, malwarescan.ErrUnavailable):
		writeScanError(w, err)
	default:
		s.writeCodedHTMLDocumentRevisionErrorV1(w, err)
	}
}

// The shared revision error writer emits plain text bodies. A move refusal keeps
// its status, headers and text and gains a stable code chosen by status, unless
// the body already carries one.
func (s *Server) writeCodedHTMLDocumentRevisionErrorV1(w http.ResponseWriter, err error) {
	rec := httptest.NewRecorder()
	s.writeHTMLDocumentRevisionError(rec, err)
	var body map[string]any
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil || body == nil {
		body = map[string]any{"error": "HTML template move failed"}
	}
	if code, _ := body["code"].(string); code == "" {
		body["code"] = templateMoveCodeForStatusV1(rec.Code)
	}
	for k, v := range rec.Header() {
		if k != "Content-Length" && k != "Content-Type" {
			w.Header()[k] = v
		}
	}
	writeJSON(w, rec.Code, body)
}

func templateMoveCodeForStatusV1(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "template_move_invalid_values"
	case http.StatusForbidden:
		return "template_move_forbidden"
	case http.StatusNotFound:
		return "template_move_not_found"
	case http.StatusConflict:
		return "template_move_document_changed"
	case http.StatusUnprocessableEntity:
		return "template_move_unprocessable"
	case http.StatusTooManyRequests:
		return "template_move_capacity"
	case http.StatusServiceUnavailable:
		return "template_move_unavailable"
	default:
		return "template_move_failed"
	}
}
