// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/docintake"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Replacing the imported PDF of a draft keeps the document ID, link, recipients
// and audit trail. The new PDF is a retained, append-only revision; its review
// and the field layout reset every time. Only a replaced PDF is gated at send,
// a never-replaced imported PDF keeps its historical behaviour.

const pdfRevisionMaxSummaryRunesV1 = 500

type pdfRevisionBusinessV1 struct {
	status  int
	message string
	code    string
}

func (e *pdfRevisionBusinessV1) Error() string { return e.message }
func pdfRevisionConflictV1(message string) error {
	return &pdfRevisionBusinessV1{http.StatusConflict, message, "pdf_revision_conflict"}
}
func pdfRevisionRefusedV1(status int, code, message string) error {
	return &pdfRevisionBusinessV1{status, message, code}
}

// pdfRevisionMaxPerDocumentV1 caps retained revisions of one draft.
const pdfRevisionMaxPerDocumentV1 = 50

// errPDFRevisionPinsMissingV1 maps to 428, a stale pin maps to 409.
var errPDFRevisionPinsMissingV1 = &pdfRevisionBusinessV1{http.StatusPreconditionRequired, "current expected_updated_at and expected_pdf_sha256 are required", "pdf_revision_pins_required"}

type pdfRevisionPinsV1 struct {
	ExpectedUpdatedAt time.Time
	ExpectedPDFSHA256 []byte
}

// parsePDFRevisionPinsV1 returns errPDFRevisionPinsMissingV1 for an absent or
// malformed pin so a client cannot skip the check by sending garbage.
func parsePDFRevisionPinsV1(updatedAt, pdfSHA256 string) (pdfRevisionPinsV1, error) {
	expected, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil || !htmlPreviewSHA256(pdfSHA256) {
		return pdfRevisionPinsV1{}, errPDFRevisionPinsMissingV1
	}
	digest, _ := hex.DecodeString(pdfSHA256)
	return pdfRevisionPinsV1{ExpectedUpdatedAt: expected, ExpectedPDFSHA256: digest}, nil
}

func (p pdfRevisionPinsV1) matches(d *generated.Document) bool {
	return d != nil && d.UpdatedAt.Valid && d.UpdatedAt.Time.Equal(p.ExpectedUpdatedAt) && bytes.Equal(d.PdfSha256, p.ExpectedPDFSHA256)
}

func validPDFRevisionSummaryV1(summary string) bool {
	if !utf8.ValidString(summary) || utf8.RuneCountInString(summary) > pdfRevisionMaxSummaryRunesV1 {
		return false
	}
	for _, r := range summary {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C || r == 0xFEFF {
			return false
		}
	}
	return true
}

// pdfRevisionRefusalV1 names why a document cannot take a PDF revision. The
// M124 trigger repeats these rules for direct SQL.
func pdfRevisionRefusalV1(b *generated.GetPDFRevisionBlockersV1Row) error {
	switch {
	case b.IsEnvelope || b.InEnvelope:
		return pdfRevisionConflictV1("a document in an envelope cannot take a PDF revision")
	case b.AmendmentLinked:
		return pdfRevisionConflictV1("a document linked to an amendment cannot take a PDF revision")
	case b.TemplateBacked:
		return pdfRevisionConflictV1("a template-backed PDF cannot be replaced here")
	case b.HtmlSource:
		return pdfRevisionConflictV1("a designed HTML document cannot take a PDF revision")
	case b.SourceKind != "pdf":
		return pdfRevisionConflictV1("only an imported PDF document can take a PDF revision")
	}
	return nil
}

// pdfRevisionCommitV1 is the outcome of one owned transaction. CommitAttempted
// is true once COMMIT was dispatched, after which the caller must not delete
// anything the transaction may have made durable.
type pdfRevisionCommitV1 struct {
	Document        *generated.Document
	CommitAttempted bool
	release         func()
}

func (c *pdfRevisionCommitV1) Release() {
	if c != nil && c.release != nil {
		c.release()
		c.release = nil
	}
}

// runPDFRevisionTxV1 owns the draft lock, the owner-or-sender check, one audit
// event and the commit. work runs under the lock and returns the audit entry
// for the document.updated event, which is published only after COMMIT.
func (s *Server) runPDFRevisionTxV1(parent context.Context, actor authoring.Actor, id uuid.UUID, purpose pdfadmission.HTMLAuditPurposeV1,
	work func(call context.Context, q *generated.Queries, doc *generated.Document) (*generated.Document, map[string]any, error)) (out *pdfRevisionCommitV1, failure error) {
	if s.HTMLCreationSessions == nil || s.Audit == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, pdfadmission.ErrApplicationSessionV1
	}
	ctx, cancel := context.WithTimeout(parent, authoring.MutationTimeout)
	defer cancel()
	session, err := s.HTMLCreationSessions.OpenV1(ctx, actor.OrgID, id)
	if err != nil {
		if session != nil {
			cleanup, stop := revisionCleanupContextV1(parent)
			defer stop()
			_ = session.CloseV1(cleanup)
		}
		return nil, err
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := revisionCleanupContextV1(parent)
		defer stop()
		_ = session.CloseV1(cleanup)
		return nil, err
	}
	via, tool := s.pdfRevisionVia(parent)
	out = &pdfRevisionCommitV1{}
	committed := false
	var consumer *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	defer func() {
		cleanup, stop := revisionCleanupContextV1(parent)
		defer stop()
		closeErr := session.CloseV1(cleanup)
		_, reconcileErr := admission.ReconcileCleanupV1(cleanup)
		if !committed {
			failure = errors.Join(failure, closeErr, reconcileErr)
			if consumer != nil {
				consumer.CloseConsumerV1()
			}
		}
	}()
	var doc *generated.Document
	var pending audit.PendingEvent
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		tx := &htmlCreationPolicyTxV1{DBTX: db}
		guard, e := authoring.LockDraft(call, tx, actor, id)
		if e != nil {
			return e
		}
		q := generated.New(tx)
		user, e := q.GetUserForShare(call, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
		if e != nil {
			return e
		}
		if user.Role != string(auth.RoleOwner) && guard.Document.SenderID != actor.UserID {
			return auth.ErrMutationPermissionRevoked
		}
		blockers, e := q.GetPDFRevisionBlockersV1(call, generated.GetPDFRevisionBlockersV1Params{DocumentID: id, OrgID: actor.OrgID})
		if e != nil {
			return e
		}
		if e = pdfRevisionRefusalV1(blockers); e != nil {
			return e
		}
		updated, payload, e := work(call, q, guard.Document)
		if e != nil {
			return e
		}
		doc = updated
		payload["via"], payload["tool"] = via, tool
		entry := audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &id, Kind: audit.KindDocumentUpdated, Payload: payload}
		pending, consumer, e = ownedaudit.LogV1(s.Audit, call, session, purpose, entry)
		if e != nil {
			return e
		}
		pending = detachPendingEventIDsV1(pending)
		return guard.Recheck(call)
	})
	if err != nil {
		return nil, err
	}
	out.CommitAttempted = true
	if err = session.CommitV1(ctx); err != nil {
		out.CommitAttempted = pdfRevisionCommitMayHaveLandedV1(err)
		return out, err
	}
	committed = true
	out.Document = doc
	if err = ownedaudit.PublishV1(s.Audit, pending, consumer); err != nil {
		consumer.CloseConsumerV1()
		return out, err
	}
	out.release = func() { consumer.CloseConsumerV1() }
	return out, nil
}

// pdfRevisionCommitMayHaveLandedV1 reports whether a CommitV1 error leaves the
// outcome unknown. Only a dispatched COMMIT can be unknown. A refusal before
// dispatch leaves nothing committed, so the caller may delete its stored
// object; an unknown outcome must keep it, because deleting it could orphan a
// committed revision.
func pdfRevisionCommitMayHaveLandedV1(err error) bool {
	return errors.Is(err, pdfadmission.ErrApplicationSessionCommitUnknownV1)
}

type pdfRevisionViaKeyV1 struct{}

// pdfRevisionVia reports the transport recorded in the audit payload. REST is
// the default; the MCP bridge marks its context with the tool name.
func (s *Server) pdfRevisionVia(ctx context.Context) (string, string) {
	if tool, ok := ctx.Value(pdfRevisionViaKeyV1{}).(string); ok && tool != "" {
		return "mcp", tool
	}
	return "rest", ""
}

func withPDFRevisionToolV1(ctx context.Context, tool string) context.Context {
	return context.WithValue(ctx, pdfRevisionViaKeyV1{}, tool)
}

func detachPendingEventIDsV1(event audit.PendingEvent) audit.PendingEvent {
	if event.Entry.DocumentID != nil {
		id := *event.Entry.DocumentID
		event.Entry.DocumentID = &id
	}
	if event.Entry.RecipientID != nil {
		id := *event.Entry.RecipientID
		event.Entry.RecipientID = &id
	}
	if event.Entry.ActorUserID != nil {
		id := *event.Entry.ActorUserID
		event.Entry.ActorUserID = &id
	}
	return event
}

type pdfRevisionReplacedV1 struct {
	Document  *generated.Document
	Revision  *generated.DocumentPdfRevisionsV1
	PageCount int
	release   func()
}

func (r *pdfRevisionReplacedV1) Release() {
	if r != nil && r.release != nil {
		r.release()
		r.release = nil
	}
}

// replaceDraftPDFOwnedV1 follows the transaction order of the HTML revision
// writer. Pins and policy are checked, then the bytes are scanned, sanitized and
// stored under a new key (even for identical bytes) before any lock is taken.
// The object is deleted on every failure unless COMMIT was dispatched.
func (s *Server) replaceDraftPDFOwnedV1(parent context.Context, actor authoring.Actor, id uuid.UUID, pins pdfRevisionPinsV1, data []byte, summary string) (result *pdfRevisionReplacedV1, failure error) {
	if s.Pool == nil || s.Storage == nil || s.Queries == nil {
		return nil, pdfadmission.ErrApplicationSessionV1
	}
	if !validPDFRevisionSummaryV1(summary) {
		return nil, &pdfRevisionBusinessV1{http.StatusBadRequest, "summary must contain at most 500 plain-text characters", "pdf_revision_summary_invalid"}
	}
	if !looksLikePDF(data) {
		return nil, &pdfRevisionBusinessV1{http.StatusBadRequest, "uploaded file is not a PDF (magic bytes mismatch)", "pdf_revision_not_pdf"}
	}
	// Early, unlocked pin check so a stale tab does not pay for scanning.
	current, err := s.Queries.GetDocument(parent, generated.GetDocumentParams{ID: id, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, authoring.ErrDocumentNotFound
	}
	if err != nil {
		return nil, err
	}
	if current.Status != "draft" || current.SourceKind != "pdf" {
		return nil, pdfRevisionRefusedV1(http.StatusConflict, "pdf_revision_not_draft_pdf", "only an unsent imported PDF draft can take a PDF revision")
	}
	if !pins.matches(current) {
		return nil, pdfRevisionConflictV1("document or PDF changed; reload before replacing the PDF")
	}
	user, err := s.Queries.GetUserForShare(parent, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
	if err != nil {
		return nil, err
	}
	if user.Role != string(auth.RoleOwner) && current.SenderID != actor.UserID {
		return nil, auth.ErrMutationPermissionRevoked
	}
	prepareCtx, stopPrepare := context.WithTimeout(parent, authoring.MutationTimeout)
	defer stopPrepare()
	prepared, err := docintake.PreparePDFTemplateSource(prepareCtx, s.Storage, actor.OrgID, data)
	if err != nil {
		return nil, err
	}
	owned := prepared.OwnedSource()
	cleanup := cleanupObjectVersion{Key: owned.Key, VersionID: owned.VersionID, SHA256: bytes.Clone(owned.SHA256[:])}
	var commit *pdfRevisionCommitV1
	defer func() {
		if failure != nil && (commit == nil || !commit.CommitAttempted) {
			failure = errors.Join(failure, deleteObjectDetached(parent, s.Storage, cleanup))
		}
	}()
	var revision *generated.DocumentPdfRevisionsV1
	commit, err = s.runPDFRevisionTxV1(parent, actor, id, pdfadmission.HTMLAuditPDFRevisionV1,
		func(call context.Context, q *generated.Queries, doc *generated.Document) (*generated.Document, map[string]any, error) {
			if !pins.matches(doc) {
				return nil, nil, pdfRevisionConflictV1("document or PDF changed; reload before replacing the PDF")
			}
			count, e := q.CountDocumentPDFRevisionsV1(call, generated.CountDocumentPDFRevisionsV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
			if e != nil {
				return nil, nil, e
			}
			if count >= pdfRevisionMaxPerDocumentV1 {
				return nil, nil, pdfRevisionRefusedV1(http.StatusConflict, "pdf_revision_limit", "this draft already has the maximum number of PDF revisions")
			}
			sequence, parentID := int32(1), pgtype.UUID{}
			latest, e := q.GetLatestDocumentPDFRevisionV1(call, generated.GetLatestDocumentPDFRevisionV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return nil, nil, e
			}
			if e == nil {
				sequence, parentID = latest.Sequence+1, pgtype.UUID{Bytes: latest.ID, Valid: true}
			}
			// Archive first: the revision row captures the field layout and
			// recipients exactly as they are before the reset.
			revision, e = q.InsertDocumentPDFRevisionV1(call, generated.InsertDocumentPDFRevisionV1Params{
				ID: uuid.New(), OrgID: doc.OrgID, DocumentID: doc.ID, Sequence: sequence, ParentID: parentID,
				PreviousPdfKey: doc.PdfStorageKey.String, PreviousPdfSha256: bytes.Clone(doc.PdfSha256), PreviousPdfVersionID: doc.PdfStorageVersionID.String,
				PdfKey: owned.Key, PdfSha256: bytes.Clone(owned.SHA256[:]), PdfVersionID: owned.VersionID,
				PageCount: int32(prepared.PageCount()), MetadataRedactionReport: prepared.MetadataRedactionReport(),
				Summary: summary, CreatedBy: actor.UserID,
			})
			if e != nil {
				return nil, nil, e
			}
			if _, e = q.ClearDraftFieldsForPDFRevisionV1(call, generated.ClearDraftFieldsForPDFRevisionV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, ExpectedUpdatedAt: doc.UpdatedAt}); e != nil {
				return nil, nil, e
			}
			updated, e := q.ProjectPDFRevisionV1(call, generated.ProjectPDFRevisionV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, ExpectedUpdatedAt: doc.UpdatedAt, RevisionID: revision.ID})
			if e != nil {
				return nil, nil, e
			}
			// The projection rewrote the redaction report, which cleared the
			// signer-read size cache (M93). Measure it again in this transaction.
			if _, e = q.MeasureSignerDocumentReportV1(call, generated.MeasureSignerDocumentReportV1Params{DocumentID: doc.ID, OrgID: doc.OrgID}); e != nil {
				return nil, nil, e
			}
			return updated, map[string]any{
				"pdf_revision": int(sequence), "summary_present": summary != "",
				"previous_pdf_sha256": hex.EncodeToString(doc.PdfSha256), "pdf_sha256": hex.EncodeToString(owned.SHA256[:]),
				"previous_pdf_version_id": doc.PdfStorageVersionID.String, "pdf_version_id": owned.VersionID,
				"page_count": prepared.PageCount(), "review_required": true, "placement_reset": true,
			}, nil
		})
	if err != nil {
		if commit != nil {
			commit.Release()
		}
		return nil, err
	}
	return &pdfRevisionReplacedV1{Document: commit.Document, Revision: revision, PageCount: prepared.PageCount(), release: commit.Release}, nil
}

type pdfRevisionReviewedV1 struct {
	Document *generated.Document
	Review   *generated.DocumentPdfReviewsV1
	release  func()
}

func (r *pdfRevisionReviewedV1) Release() {
	if r != nil && r.release != nil {
		r.release()
		r.release = nil
	}
}

// reviewDraftPDFOwnedV1 records that the latest replaced PDF was reviewed.
// reviewerKind is chosen by the transport, never by the request body. A signing
// document is refused for an agent here and again by the M124 trigger.
func (s *Server) reviewDraftPDFOwnedV1(parent context.Context, actor authoring.Actor, id uuid.UUID, pins pdfRevisionPinsV1, reviewerKind string, reviewedPages int32) (result *pdfRevisionReviewedV1, failure error) {
	if reviewerKind != reviewerKindHumanV1 && reviewerKind != reviewerKindAgentV1 {
		return nil, errors.New("review requires a recorded reviewer kind")
	}
	var review *generated.DocumentPdfReviewsV1
	commit, err := s.runPDFRevisionTxV1(parent, actor, id, pdfadmission.HTMLAuditPDFReviewV1,
		func(call context.Context, q *generated.Queries, doc *generated.Document) (*generated.Document, map[string]any, error) {
			if !pins.matches(doc) {
				return nil, nil, pdfRevisionConflictV1("document or PDF changed; reload and review the current PDF again")
			}
			if reviewerKind == reviewerKindAgentV1 {
				if e := requireNonSigningForAgentReviewV1(doc.Metadata); e != nil {
					return nil, nil, e
				}
			}
			state, e := q.GetPDFReviewStateV1(call, generated.GetPDFReviewStateV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
			if errors.Is(e, pgx.ErrNoRows) {
				return nil, nil, pdfRevisionConflictV1("this document has no replaced PDF to review")
			}
			if e != nil {
				return nil, nil, e
			}
			// One human review may sit on top of an agent review; nothing is
			// ever added on top of a human review, and an agent adds only once.
			if state.HumanReviewed || (state.Reviewed && reviewerKind == reviewerKindAgentV1) {
				return nil, nil, pdfRevisionConflictV1("the current PDF is already reviewed")
			}
			if !bytes.Equal(state.PdfSha256, doc.PdfSha256) {
				return nil, nil, pdfRevisionConflictV1("document changed; reload and review the current PDF again")
			}
			pages := reviewedPages
			if pages == 0 {
				pages = state.PageCount
			}
			if pages != state.PageCount {
				return nil, nil, pdfRevisionConflictV1(fmt.Sprintf("a review must cover all %d pages of the PDF", state.PageCount))
			}
			review, e = q.InsertDocumentPDFReviewV1(call, generated.InsertDocumentPDFReviewV1Params{
				ID: uuid.New(), OrgID: doc.OrgID, DocumentID: doc.ID, RevisionID: state.RevisionID, PdfSha256: bytes.Clone(state.PdfSha256),
				ReviewerKind: reviewerKind, ReviewedBy: actor.UserID, VisuallyReviewed: true, ReviewedPages: pages,
			})
			if e != nil {
				return nil, nil, e
			}
			touched, e := q.TouchDocumentForPDFReviewV1(call, generated.TouchDocumentForPDFReviewV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, ExpectedUpdatedAt: doc.UpdatedAt})
			if e != nil {
				return nil, nil, e
			}
			return touched, map[string]any{
				"pdf_revision": int(state.Sequence), "pdf_sha256": hex.EncodeToString(state.PdfSha256),
				"reviewer_kind": reviewerKind, "reviewed_pages": int(pages),
			}, nil
		})
	if err != nil {
		if commit != nil {
			commit.Release()
		}
		return nil, err
	}
	return &pdfRevisionReviewedV1{Document: commit.Document, Review: review, release: commit.Release}, nil
}

// ---- REST ----

func (s *Server) writePDFRevisionErrorV1(w http.ResponseWriter, err error) {
	var business *pdfRevisionBusinessV1
	switch {
	case errors.As(err, &business):
		body := map[string]string{"error": business.message}
		if business.code != "" {
			body["code"] = business.code
		}
		writeJSON(w, business.status, body)
	case errors.Is(err, errHumanReviewRequiredV1):
		writeError(w, http.StatusForbidden, errHumanReviewRequiredV1.Error())
	case errors.Is(err, malwarescan.ErrUnavailable), errors.Is(err, malwarescan.ErrDetected):
		writeScanError(w, err)
	case writePDFWorkerError(w, err):
	case errors.Is(err, docintake.ErrSanitizePDF), errors.Is(err, docintake.ErrTooManyPages):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the PDF could not be sanitized or exceeds the page limit", "code": "pdf_revision_unprocessable"})
	case writePDFRevisionDBRefusalV1(w, err):
	case errors.Is(err, pdfadmission.ErrApplicationAdmissionV1), errors.Is(err, pdfadmission.ErrApplicationSessionV1), errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1),
		errors.Is(err, pdfadmission.ErrHTMLAuditEventV1), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "PDF revision temporarily unavailable")
	default:
		if status, known := draftAuthoringErrorStatus(err); known {
			writeJSON(w, status, map[string]string{"error": http.StatusText(status), "code": "pdf_revision_draft_refused"})
			return
		}
		s.writeDraftAuthoringError(w, "replace draft PDF", err)
	}
}

// pdfReviewRequiredV1 is true while the latest replaced PDF has no review.
// A document that never had its PDF replaced is never gated.
func (s *Server) pdfReviewRequiredV1(ctx context.Context, d *generated.Document) bool {
	if s.Queries == nil || d == nil || d.SourceKind != "pdf" {
		return false
	}
	state, err := s.Queries.GetPDFReviewStateV1(ctx, generated.GetPDFReviewStateV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	// Fail closed: a failed lookup reports that review is required.
	if err != nil {
		return true
	}
	return !s.pdfReviewSatisfiedV1(d, state.Reviewed, state.HumanReviewed)
}

func (s *Server) documentResponseWithPDFReviewV1(ctx context.Context, d *generated.Document) documentResponse {
	out := toDocumentResponse(d)
	out.PDFReviewRequired = s.pdfReviewRequiredV1(ctx, d)
	return out
}

// loadPDFRevisionReadDocumentV1 serves the two GET routes. They are staff
// session only and limited to an owner or the document's sender; history stays
// readable after the document leaves draft.
func (s *Server) loadPDFRevisionReadDocumentV1(w http.ResponseWriter, r *http.Request) (*generated.Document, bool) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return nil, false
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return nil, false
	}
	d, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return nil, false
	}
	if err != nil {
		writeInternalErrorMsg(w, "get document failed", err)
		return nil, false
	}
	// The role comes from the database, not the request context, so a demotion
	// during a long storage read is seen by the recheck.
	current, err := s.Queries.GetUser(r.Context(), u.UserID)
	generation, hasGeneration := r.Context().Value(auth.SessionGenerationKey).(int64)
	access := pdfRevisionReadAccessV1(current, err, u.OrgID, u.UserID, d.SenderID, generation, true)
	if !hasGeneration && access == pdfRevisionAccessAllowedV1 {
		access = pdfRevisionAccessDeniedV1 // fail closed without a generation
	}
	switch access {
	case pdfRevisionAccessUnavailableV1:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "session authorization unavailable")
		return nil, false
	case pdfRevisionAccessDeniedV1:
		writeError(w, http.StatusForbidden, "only the document sender or an owner can use PDF revisions")
		return nil, false
	}
	return d, true
}

type pdfRevisionAccessV1 int

const (
	pdfRevisionAccessAllowedV1 pdfRevisionAccessV1 = iota
	pdfRevisionAccessDeniedV1
	pdfRevisionAccessUnavailableV1
)

// pdfRevisionReadAccessV1 decides the sender-or-owner rule from a fresh user
// row. A lookup error other than a missing row is unavailable (503), as in the
// session middleware, never a denial. For a session caller the request's
// session generation must still match, so a "log out everywhere" during a
// long read refuses the bytes; MCP callers pass checkGeneration=false because a
// key credential has no session generation.
func pdfRevisionReadAccessV1(current *generated.User, getErr error, orgID, userID, senderID uuid.UUID, generation int64, checkGeneration bool) pdfRevisionAccessV1 {
	if getErr != nil {
		if errors.Is(getErr, pgx.ErrNoRows) {
			return pdfRevisionAccessDeniedV1
		}
		return pdfRevisionAccessUnavailableV1
	}
	if current == nil || current.ID != userID || current.OrgID != orgID {
		return pdfRevisionAccessDeniedV1
	}
	if checkGeneration && current.SessionGeneration != generation {
		return pdfRevisionAccessDeniedV1
	}
	if current.Role != string(auth.RoleOwner) && senderID != userID {
		return pdfRevisionAccessDeniedV1
	}
	return pdfRevisionAccessAllowedV1
}

func pdfRevisionJSONV1(row *generated.ListDocumentPDFRevisionsV1Row) map[string]any {
	out := map[string]any{
		"sequence": row.Sequence, "pdf_sha256": hex.EncodeToString(row.PdfSha256),
		"previous_pdf_sha256": hex.EncodeToString(row.PreviousPdfSha256), "page_count": row.PageCount,
		"summary": row.Summary, "created_by": row.CreatedBy, "created_at": row.CreatedAt.Time.UTC().Format(time.RFC3339Nano),
		"reviewed": row.Reviewed,
	}
	if row.Reviewed {
		out["review"] = map[string]any{"reviewer_kind": row.ReviewKind, "reviewed_by": row.ReviewBy, "reviewed_at": row.ReviewAt.Time.UTC().Format(time.RFC3339Nano)}
	}
	return out
}

// GET /api/v1/documents/{id}/pdf/history
func (s *Server) handleGetPDFHistoryV1(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadPDFRevisionReadDocumentV1(w, r)
	if !ok {
		return
	}
	history, err := s.pdfHistoryV1(r.Context(), d)
	if err != nil {
		writeInternalErrorMsg(w, "list PDF revisions failed", err)
		return
	}
	writeJSON(w, http.StatusOK, history)
}

// pdfHistoryV1 is shared with the MCP read. Newest first; revision 0 is the PDF
// that was imported before any replacement and stays downloadable.
func (s *Server) pdfHistoryV1(ctx context.Context, d *generated.Document) (map[string]any, error) {
	rows, err := s.Queries.ListDocumentPDFRevisionsV1(ctx, generated.ListDocumentPDFRevisionsV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	if err != nil {
		return nil, err
	}
	revisions := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		revisions = append(revisions, pdfRevisionJSONV1(row))
	}
	out := map[string]any{
		"document_id": d.ID, "status": d.Status, "updated_at": d.UpdatedAt.Time.UTC().Format(time.RFC3339Nano),
		"pdf_sha256": hex.EncodeToString(d.PdfSha256), "pdf_review_required": s.pdfReviewRequiredV1(ctx, d), "revisions": revisions,
	}
	if len(rows) > 0 {
		out["original_pdf_sha256"] = hex.EncodeToString(rows[len(rows)-1].PreviousPdfSha256)
	}
	return out, nil
}

// GET /api/v1/documents/{id}/pdf/revisions/{sequence}/pdf
// Sequence 0 is the originally imported PDF; N is the PDF that revision N put in place.
func (s *Server) handleGetPDFRevisionPDFV1(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadPDFRevisionReadDocumentV1(w, r)
	if !ok {
		return
	}
	rawSequence := chi.URLParam(r, "sequence")
	sequence, err := strconv.ParseInt(rawSequence, 10, 32)
	if err != nil || sequence < 0 || len(rawSequence) > 9 || strings.TrimLeft(rawSequence, "0123456789") != "" {
		writeError(w, http.StatusBadRequest, "invalid revision sequence")
		return
	}
	var key, version string
	var digest []byte
	lookup := int32(sequence)
	if sequence == 0 {
		lookup = 1
	}
	row, err := s.Queries.GetDocumentPDFRevisionBySequenceV1(r.Context(), generated.GetDocumentPDFRevisionBySequenceV1Params{DocumentID: d.ID, OrgID: d.OrgID, Sequence: lookup})
	if errors.Is(err, pgx.ErrNoRows) {
		if sequence == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "this document's PDF was never replaced; download the current PDF instead", "code": "pdf_revision_never_replaced"})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "PDF revision not found", "code": "pdf_revision_not_found"})
		return
	}
	if err != nil {
		writeInternalErrorMsg(w, "load PDF revision failed", err)
		return
	}
	if sequence == 0 {
		key, version, digest = row.PreviousPdfKey, row.PreviousPdfVersionID, row.PreviousPdfSha256
	} else {
		key, version, digest = row.PdfKey, row.PdfVersionID, row.PdfSha256
	}
	if s.Storage == nil {
		writeError(w, http.StatusServiceUnavailable, "PDF storage unavailable")
		return
	}
	readCtx, stopRead := context.WithTimeout(r.Context(), 30*time.Second)
	defer stopRead()
	body, err := s.Storage.GetVerifiedVersion(readCtx, key, version, digest)
	if err != nil {
		writeInternalErrorMsg(w, "load PDF revision failed", err)
		return
	}
	// Access is checked again after the storage read so a revoked sender or
	// owner does not receive bytes fetched before the revocation.
	if _, ok := s.loadPDFRevisionReadDocumentV1(w, r); !ok {
		return
	}
	setDocumentPreviewHeaders(w, false)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline")
	_, _ = w.Write(body)
}

type pdfRevisionReviewInputV1 struct {
	ExpectedUpdatedAt string `json:"expected_updated_at"`
	ExpectedPDFSHA256 string `json:"expected_pdf_sha256"`
}

// POST /api/v1/documents/{id}/pdf/review
// A staff session records a human review; there is no reviewer field to forge.
func (s *Server) handleReviewPDFV1(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in pdfRevisionReviewInputV1
	if err := decodeSignerJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body is not valid JSON for a PDF review", "code": "pdf_review_invalid_body"})
		return
	}
	pins, err := parsePDFRevisionPinsV1(in.ExpectedUpdatedAt, in.ExpectedPDFSHA256)
	if err != nil {
		s.writePDFRevisionErrorV1(w, err)
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize PDF review", err)
		return
	}
	result, err := s.reviewDraftPDFOwnedV1(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, pins, reviewerKindHumanV1, 0)
	if err != nil {
		s.writePDFRevisionErrorV1(w, err)
		return
	}
	defer result.Release()
	writeJSON(w, http.StatusOK, map[string]any{"document": s.documentResponseWithPDFReviewV1(r.Context(), result.Document), "reviewer_kind": result.Review.ReviewerKind, "reviewed_pages": result.Review.ReviewedPages})
}

// POST /api/v1/documents/{id}/pdf/revisions (multipart)
func (s *Server) handleReplaceDraftPDFV1(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	defer release()
	r.Body = http.MaxBytesReader(w, r.Body, maxPDFUpload+(1<<20))
	defer cleanupMultipart(r)
	if err := r.ParseMultipartForm(multipartFileMemory); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "PDF exceeds the upload limit", "code": "pdf_too_large"})
			return
		}
		writeError(w, http.StatusBadRequest, "could not parse the upload")
		return
	}
	pins, err := parsePDFRevisionPinsV1(r.PostFormValue("expected_updated_at"), r.PostFormValue("expected_pdf_sha256"))
	if err != nil {
		s.writePDFRevisionErrorV1(w, err)
		return
	}
	file, _, err := r.FormFile("pdf")
	if err != nil {
		writeError(w, http.StatusBadRequest, "pdf file required (form field 'pdf')")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxPDFUpload+1))
	if err != nil || len(data) > maxPDFUpload {
		writeError(w, http.StatusRequestEntityTooLarge, "PDF exceeds the upload limit")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize PDF revision", err)
		return
	}
	result, err := s.replaceDraftPDFOwnedV1(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, pins, data, r.PostFormValue("summary"))
	if err != nil {
		s.writePDFRevisionErrorV1(w, err)
		return
	}
	defer result.Release()
	writeJSON(w, http.StatusCreated, map[string]any{
		"document": s.documentResponseWithPDFReviewV1(r.Context(), result.Document), "revision": result.Revision.Sequence,
		"page_count": result.PageCount, "review_required": true, "placement_reset": true,
	})
}

// writePDFRevisionDBRefusalV1 classifies a database refusal before any
// availability branch. The application session wraps every in-transaction
// error with ErrApplicationSessionV1 but keeps the cause reachable, so the
// review gate and the M124 checks are found through the wrapper. Lock and
// serialization failures stay retryable 503s.
func writePDFRevisionDBRefusalV1(w http.ResponseWriter, err error) bool {
	if message, ok := sendReviewGateMessageV1(err); ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": message, "code": "pdf_review_required"})
		return true
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "55P03", "40001", "40P01":
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusServiceUnavailable, "PDF revision temporarily unavailable")
			return true
		}
	}
	if status, code, message, ok := pdfRevisionDBRefusalV1(err); ok {
		writeJSON(w, status, map[string]string{"error": message, "code": code})
		return true
	}
	return false
}

// pdfRevisionDBRefusalV1 maps database refusals (M124 guards, lost races,
// legacy drafts without a storage version) to a 4xx with a stable code. The
// body never carries database text. Lock and serialization failures (55P03,
// 40001, 40P01) are not refusals; the caller maps them to a retryable 503.
func pdfRevisionDBRefusalV1(err error) (int, string, string, bool) {
	if errors.Is(err, pgx.ErrNoRows) {
		return http.StatusConflict, "pdf_revision_state_changed", "the document changed; reload and try again", true
	}
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return 0, "", "", false
	}
	switch pg.Code {
	case "23514", "P0002", "23505", "23503":
		return http.StatusConflict, "pdf_revision_refused", "the document cannot take this PDF revision in its current state; reload and try again", true
	}
	return 0, "", "", false
}

// pdfReviewSatisfiedV1 mirrors hash_pdf_bytes_reviewed_v1: a signing document
// needs a human review, any other document any review.
func (s *Server) pdfReviewSatisfiedV1(d *generated.Document, reviewed, human bool) bool {
	if requireNonSigningForAgentReviewV1(d.Metadata) != nil {
		return human
	}
	return reviewed
}
