// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/versions"
)

var errHTMLDocumentRevisionConflict = errors.New("document changed; reload its current declared text and PDF before revising")
var errHTMLDocumentRevisionRenderUnavailable = errors.New("HTML document rendering unavailable")

type htmlDocumentRevisionInput struct {
	ExpectedUpdatedAt            string        `json:"expected_updated_at"`
	ExpectedHTMLSourceCommitment string        `json:"expected_html_source_commitment"`
	Values                       htmlStringMap `json:"values,omitempty"`
	Sections                     htmlStringMap `json:"sections,omitempty"`
	Summary                      string        `json:"summary,omitempty"`
}

// A revision changes declared plain text only. Its master, approved defaults,
// template identity and assets come from the document's frozen original source.
func materializeHTMLDocumentRevision(doc *generated.Document, in htmlDocumentRevisionInput) (htmlsource.Input, htmlmaster.Result, error) {
	input, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		return htmlsource.Input{}, htmlmaster.Result{}, err
	}
	input.Values, input.Sections = maps.Clone(input.Values), maps.Clone(input.Sections)
	if input.Values == nil {
		input.Values = map[string]string{}
	}
	if input.Sections == nil {
		input.Sections = map[string]string{}
	}
	for name, text := range in.Values {
		input.Values[name] = text
	}
	for name, text := range in.Sections {
		input.Sections[name] = text
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		return htmlsource.Input{}, htmlmaster.Result{}, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return htmlsource.Input{}, htmlmaster.Result{}, err
	}
	rendered, err := compiled.Materialize(htmlmaster.Input{Values: input.Values, Sections: input.Sections})
	if err != nil {
		return htmlsource.Input{}, htmlmaster.Result{}, err
	}
	before, err := htmlsource.MaterializationDigest(doc)
	if err != nil || before == rendered.ContentDigest {
		return htmlsource.Input{}, htmlmaster.Result{}, errHTMLDocumentRevisionConflict
	}
	return input, rendered, nil
}

func (s *Server) lockHTMLDocumentRevision(ctx context.Context, tx pgx.Tx, actor authoring.Actor, id uuid.UUID, in htmlDocumentRevisionInput, expected time.Time) (*authoring.DraftGuard, error) {
	guard, err := authoring.LockDraft(ctx, tx, actor, id)
	if err != nil {
		return nil, err
	}
	q := generated.New(tx)
	user, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
	if err != nil {
		return nil, err
	}
	if user.Role != string(auth.RoleOwner) && guard.Document.SenderID != actor.UserID {
		return nil, auth.ErrMutationPermissionRevoked
	}
	commitment, err := htmlsource.Commitment(guard.Document)
	if err != nil {
		return nil, err
	}
	if !guard.Document.UpdatedAt.Time.Equal(expected) || commitment != in.ExpectedHTMLSourceCommitment {
		return nil, errHTMLDocumentRevisionConflict
	}
	if _, err := htmlmaterialization.Current(ctx, q, guard.Document); err != nil {
		return nil, err
	}
	if err := htmlsource.ValidateSigningPageState(ctx, q, guard.Document, 0); err != nil {
		return nil, err
	}
	return guard, nil
}

// Release all database locks before scanner, Chromium, PDF worker and object
// storage operations. Both this read and the final append recheck the original
// admitted session; an intervening change cannot acquire a fresh authorization.
func (s *Server) loadHTMLDocumentRevision(ctx context.Context, actor authoring.Actor, id uuid.UUID, in htmlDocumentRevisionInput, expected time.Time) (*generated.Document, error) {
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := s.lockHTMLDocumentRevision(ctx, tx, actor, id, in, expected)
	if err != nil {
		return nil, err
	}
	if err := guard.Recheck(ctx); err != nil {
		return nil, err
	}
	return guard.Document, nil
}

func (s *Server) handleReviseHTMLDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in htmlDocumentRevisionInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	expected, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil || !htmlPreviewSHA256(in.ExpectedHTMLSourceCommitment) {
		writeError(w, http.StatusPreconditionRequired, "current expected_updated_at and HTML source commitment are required")
		return
	}
	if !utf8.ValidString(in.Summary) || utf8.RuneCountInString(in.Summary) > 500 || strings.ContainsRune(in.Summary, '\x00') {
		writeError(w, http.StatusBadRequest, "summary must contain at most 500 plain-text characters")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML document revision", err)
		return
	}
	if s.Pool == nil || s.Audit == nil || s.Storage == nil || s.Sign == nil || s.Sign.PDF == nil || s.Versions == nil {
		writeError(w, http.StatusServiceUnavailable, "HTML document revision dependencies unavailable")
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "HTML document revision capacity exceeded")
		return
	}
	defer release()
	doc, revision, pages, err := s.reviseHTMLDocument(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, in, expected)
	if err != nil {
		s.writeHTMLDocumentRevisionError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"document": toDocumentResponse(doc), "materialization_revision": revision, "page_count": pages, "review_required": true, "placement_reset": true})
}

func (s *Server) writeHTMLDocumentRevisionError(w http.ResponseWriter, err error) {
	if errors.Is(err, errHTMLDocumentRevisionRenderUnavailable) {
		writeError(w, http.StatusServiceUnavailable, errHTMLDocumentRevisionRenderUnavailable.Error())
		return
	}
	if writePDFWorkerError(w, err) {
		return
	}
	if errors.Is(err, malwarescan.ErrDetected) || errors.Is(err, malwarescan.ErrUnavailable) {
		writeScanError(w, err)
		return
	}
	if errors.Is(err, errHTMLDocumentRevisionConflict) || errors.Is(err, htmlsource.ErrInvalid) || errors.Is(err, htmlmaterialization.ErrInvalid) {
		writeError(w, http.StatusConflict, "document source changed or is inconsistent; reload and review its current PDF")
		return
	}
	if errors.Is(err, htmlmaster.ErrInvalid) || errors.Is(err, htmlmaster.ErrLimit) || errors.Is(err, htmlmaster.ErrMissingValues) || errors.Is(err, htmlmaster.ErrContractIncomplete) {
		writeError(w, http.StatusBadRequest, "declared values or sections are invalid or exceed their limits")
		return
	}
	s.writeDraftAuthoringError(w, "revise HTML document", err)
}

func (s *Server) reviseHTMLDocument(ctx context.Context, actor authoring.Actor, id uuid.UUID, in htmlDocumentRevisionInput, expected time.Time) (result *generated.Document, revision int32, pages int, failure error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	doc, err := s.loadHTMLDocumentRevision(ctx, actor, id, in, expected)
	if err != nil {
		return nil, 0, 0, err
	}
	input, rendered, err := materializeHTMLDocumentRevision(doc, in)
	if err != nil {
		return nil, 0, 0, err
	}
	if err := scanHTMLMaster(ctx, input.MasterJSON); err != nil {
		return nil, 0, 0, err
	}
	previousPages := doc.HtmlCurrentPageCount.Int32
	if !doc.HtmlCurrentMaterializationID.Valid {
		previous, err := s.Storage.GetVerifiedVersion(ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
		if err != nil {
			return nil, 0, 0, err
		}
		count, err := sanitize.PageCountWithContext(ctx, previous)
		if err != nil || count < 1 || count > sanitize.MaxPDFPages {
			return nil, 0, 0, errHTMLDocumentRevisionConflict
		}
		previousPages = int32(count)
	}
	if _, err := s.loadHTMLDocumentRevision(ctx, actor, id, in, expected); err != nil {
		return nil, 0, 0, err
	}
	processing, stopProcessing := context.WithTimeout(ctx, htmlTemplatePreviewTimeout)
	pdf, err := s.Sign.PDF.HTMLToPDF(processing, rendered.HTML, render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms"})
	if err != nil {
		stopProcessing()
		// Provider diagnostics can contain private submitted contract text.
		return nil, 0, 0, errHTMLDocumentRevisionRenderUnavailable
	}
	if len(pdf) == 0 || len(pdf) > sanitize.MaxPDFBytes {
		stopProcessing()
		return nil, 0, 0, errHTMLDocumentRevisionConflict
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		stopProcessing()
		return nil, 0, 0, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		stopProcessing()
		return nil, 0, 0, err
	}
	var cleaned sanitize.Result
	if compiled.SigningPagePolicy() != nil {
		composed, composeErr := s.composeHTMLSigningPage(processing, compiled, htmlmaster.Input{Values: input.Values, Sections: input.Sections}, pdf)
		if composeErr != nil {
			stopProcessing()
			return nil, 0, 0, composeErr
		}
		cleaned = composed.Result
		pages = composed.Composition.FinalPages
		input.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, htmlmaster.Input{Values: input.Values, Sections: input.Sections}, input.PartyBindings, composed.Composition)
	} else {
		cleaned, err = sanitize.CleanWithContext(processing, "html-document-revision", "application/pdf", pdf)
		if err == nil {
			pages, err = sanitize.PageCountWithContext(processing, cleaned.Bytes)
		}
	}
	stopProcessing()
	if err != nil {
		return nil, 0, 0, err
	}
	if cleaned.Report.UnsupportedT || pages < 1 || pages > sanitize.MaxPDFPages || len(cleaned.Bytes) == 0 || len(cleaned.Bytes) > sanitize.MaxPDFBytes {
		return nil, 0, 0, errHTMLDocumentRevisionConflict
	}
	// The immutable old row/snapshot retains its own report. This fresh report
	// describes only the exact newly cleaned PDF selected by this revision.
	report, err := sanitize.MergeReports(nil, cleaned.Report)
	if err != nil {
		return nil, 0, 0, err
	}
	if _, err := s.loadHTMLDocumentRevision(ctx, actor, id, in, expected); err != nil {
		return nil, 0, 0, err
	}
	key := path.Join("org", actor.OrgID.String(), "documents", uuid.NewString()+".pdf")
	stored, err := s.Storage.PutVersioned(ctx, key, "application/pdf", cleaned.Bytes)
	if err != nil {
		return nil, 0, 0, err
	}
	owned := cleanupObjectVersion{Key: key, VersionID: stored.VersionID, SHA256: bytes.Clone(stored.SHA256[:])}
	commitAttempted := false
	defer func() {
		if failure != nil && !commitAttempted {
			failure = errors.Join(failure, deleteObjectDetached(ctx, s.Storage, owned))
		}
	}()
	candidate := *doc
	candidate.PdfStorageKey = pgtype.Text{String: key, Valid: true}
	candidate.PdfStorageVersionID = pgtype.Text{String: stored.VersionID, Valid: true}
	candidate.PdfSha256 = bytes.Clone(stored.SHA256[:])
	candidate.VariablesJson, err = json.Marshal(input.Values)
	if err != nil {
		return nil, 0, 0, err
	}
	source, err := htmlsource.New(input, &candidate)
	if err != nil {
		return nil, 0, 0, err
	}
	commitCtx, stopCommit := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer stopCommit()
	tx, err := s.Pool.BeginTx(commitCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = authoring.Rollback(commitCtx, tx) }()
	guard, err := s.lockHTMLDocumentRevision(commitCtx, tx, actor, id, in, expected)
	if err != nil {
		return nil, 0, 0, err
	}
	q := generated.New(tx)
	updated, row, err := htmlmaterialization.Append(commitCtx, q, guard.Document, &candidate, htmlmaterialization.AppendInput{SourceJSON: source, PageCount: int32(pages), PreviousPageCount: previousPages, ActorID: actor.UserID, Summary: strings.TrimSpace(in.Summary), MetadataRedactionReport: report})
	if err != nil {
		return nil, 0, 0, err
	}
	// Append captures the old source, fields, review and recipient assertions
	// before projecting the fresh PDF. Change identities only after that capture
	// so the retained old revision never contains the new representative.
	partiesChanged, err := updateHTMLContractParties(commitCtx, q, guard.Document, input)
	if err != nil {
		return nil, 0, 0, err
	}
	currentRecipients, err := q.ListRecipientsByDocument(commitCtx, id)
	if err != nil {
		return nil, 0, 0, err
	}
	if err := htmlsource.ValidateContractParties(updated, currentRecipients); err != nil {
		return nil, 0, 0, err
	}
	if err := createHTMLSigningFields(commitCtx, q, updated); err != nil {
		return nil, 0, 0, err
	}
	if _, err := versions.New(q).Snapshot(commitCtx, versions.SnapshotInput{DocumentID: id, OrgID: actor.OrgID, Name: updated.Name, SourceKind: updated.SourceKind, VariablesJS: updated.VariablesJson, HTMLSourceJSON: source, HTMLMaterializationID: updated.HtmlCurrentMaterializationID, CreatedBy: &actor.UserID, Via: versions.ViaHuman, Summary: "HTML contract text revised"}); err != nil {
		return nil, 0, 0, err
	}
	pending, err := s.Audit.LogTx(commitCtx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &id, Kind: audit.KindDocumentUpdated, Payload: map[string]any{"html_materialization_revision": row.Sequence, "html_source_commitment": updated.HtmlEffectiveSourceCommitment.String, "review_required": true, "placement_reset": true, "changed_sections": rendered.ChangedSections, "contract_party_identities_updated": partiesChanged}})
	if err != nil {
		return nil, 0, 0, err
	}
	if err := guard.Recheck(commitCtx); err != nil {
		return nil, 0, 0, err
	}
	commitAttempted = true
	if err := tx.Commit(commitCtx); err != nil {
		return nil, 0, 0, err
	}
	s.Audit.Publish(pending)
	return updated, row.Sequence, pages, nil
}
