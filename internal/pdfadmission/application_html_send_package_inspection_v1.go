// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrHTMLSendPackageInspectionV1 = errors.New("pdfadmission: exact package Send inspection unavailable")

type HTMLSendPackageAttemptOutcomeV1 uint8

const (
	HTMLSendPackageAttemptMissingV1 HTMLSendPackageAttemptOutcomeV1 = iota + 1
	HTMLSendPackageAttemptActiveV1
	HTMLSendPackageAttemptCompletedV1
	HTMLSendPackageAttemptAbortedV1
	// Fresh authenticated history has no such persisted job. Unlike Missing,
	// this says nothing about rolled-back original subjects or backend retirement.
	HTMLSendPackageAttemptNotRecordedV1
)

// Point-in-time copied observation. No outcome grants retry, mutation, provider
// access or acknowledgement of the original COMMIT. Missing is deliberately
// distinct from a failed policy/read or an inconsistent row.
type HTMLSendPackageAttemptObservationV1 struct {
	AttemptID                                            uuid.UUID
	Outcome                                              HTMLSendPackageAttemptOutcomeV1
	Capture                                              HTMLSendPackageCaptureMetadataV1
	Article13NoticeEpochAt, RetainUntil, CreatedAt       time.Time
	RetentionStartedAt, RetentionCompletedAt, TerminalAt time.Time
}

// Independently funded fixed private tuple and subjects, retained after birth
// Work/SQL close but only until the original operation consumer closes. No
// variable model/report body, caller metadata or caller identity is retained.
type applicationHTMLSendPackageAttemptReferenceV1 struct {
	mu                  sync.Mutex
	activity            applicationJoinedActivityV1
	closeRequested      atomic.Bool
	operation           *ApplicationHTMLSendOperationV1
	birth               *ApplicationHTMLSendSQLStageV1
	grant               *workguard.GrantV1
	attemptID           uuid.UUID
	capture             HTMLSendPackageCaptureMetadataV1
	subjects            [documentpackage.MaxAnnexesV1 + 2]uuid.UUID
	subjectCount        int
	inspectionAttempted bool
}

func (r *applicationHTMLSendPackageAttemptReferenceV1) lockV1() bool {
	if r == nil || !r.activity.enterV1() {
		return false
	}
	r.mu.Lock()
	return true
}
func (r *applicationHTMLSendPackageAttemptReferenceV1) unlockV1() {
	r.mu.Unlock()
	if r.activity.leaveV1() {
		r.retireV1()
	}
}
func (r *applicationHTMLSendPackageAttemptReferenceV1) closeV1() {
	if r == nil {
		return
	}
	r.closeRequested.Store(true)
	if r.activity.closeV1() {
		r.retireV1()
	}
}
func (r *applicationHTMLSendPackageAttemptReferenceV1) retireV1() {
	grant := r.grant
	r.grant, r.operation, r.birth = nil, nil, nil
	r.capture = HTMLSendPackageCaptureMetadataV1{}
	r.subjects = [documentpackage.MaxAnnexesV1 + 2]uuid.UUID{}
	r.subjectCount = 0
	if grant != nil {
		grant.Close()
	}
}

// Called with genuine birth Work locked, after its complete statement quote
// and before UUID/DML. The separate Parent grant survives that Work's loans.
func (w *ApplicationHTMLSendWorkV1) newPackageSendAttemptReferenceV1(call context.Context) (*applicationHTMLSendPackageAttemptReferenceV1, error) {
	c := w.packageCapture
	if c == nil || !c.metadata.Present || c.subjectCount != int(c.metadata.MemberCount) || c.subjectCount < 1 || c.subjectCount > documentpackage.MaxAnnexesV1+1 || c.subjects[0] != c.metadata.DocumentID {
		return nil, ErrHTMLSendPackageInspectionV1
	}
	for i := 0; i < c.subjectCount; i++ {
		if c.subjects[i] == uuid.Nil {
			return nil, ErrHTMLSendPackageInspectionV1
		}
		for j := 0; j < i; j++ {
			if c.subjects[i] == c.subjects[j] {
				return nil, ErrHTMLSendPackageInspectionV1
			}
		}
	}
	op := w.stage.operation
	p := op.factory.state
	p.mu.Lock()
	available := !p.closing && p.work != nil && p.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if !available {
		return nil, ErrHTMLSendPackageInspectionV1
	}
	fixed := 8 * (int64(unsafe.Sizeof(applicationHTMLSendPackageAttemptReferenceV1{})) + 2*int64(unsafe.Sizeof(workguard.GrantV1{})) + 8*int64(unsafe.Sizeof(uintptr(0))))
	grant, err := coordinator.TryAcquireV1(call, c.metadata.OrgID, workguard.VectorV1{ParentBytes: fixed})
	if err != nil {
		return nil, err
	}
	return &applicationHTMLSendPackageAttemptReferenceV1{operation: op, birth: w.stage, grant: grant, capture: c.metadata, subjects: c.subjects, subjectCount: c.subjectCount}, nil
}

// Same-operation native read after physical birth-session retirement. This is
// the fixed primitive used by the application's original credential policy:
// StateV1, ReadActorV1 and original Authorize must run before this call and
// original Authorize again before delivery. No generic new recovery capability
// is issued. Closed/expired requests require separate authenticated durable
// recovery; copying an operation or this output cannot reopen it.
func (w *ApplicationHTMLSendWorkV1) InspectPackageSendAttemptV1(call context.Context) (out HTMLSendPackageAttemptObservationV1, failure error) {
	defer func() {
		if failure != nil {
			out = HTMLSendPackageAttemptObservationV1{}
			if !errors.Is(failure, ErrHTMLSendPackageInspectionV1) {
				failure = errors.Join(ErrHTMLSendPackageInspectionV1, failure)
			}
		}
	}()
	if w == nil || w.self != w {
		return out, ErrHTMLSendPackageInspectionV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLSendIntentReadV1 || w.stage.operation == nil || w.familyRoot != nil || w.state == nil || w.sourceActor == nil {
		return out, ErrHTMLSendPackageInspectionV1
	}
	op := w.stage.operation
	op.mu.Lock()
	r := op.packageSendReference
	birth := (*ApplicationHTMLSendSQLStageV1)(nil)
	if r != nil {
		birth = r.birth
	}
	valid := op.self == op && !op.closed && op.original.Err() == nil && r != nil && r.operation == op && r.attemptID == op.packageSendAttemptID && r.attemptID != uuid.Nil && birth != nil && birth.self == birth && birth.operation == op && birth.purpose == HTMLSendAdmissionV1 && birth.used && !birth.active && !birth.opening && !birth.startingWork && birth.session != nil && birth.session.state != nil && birth.session != w.session && w.stage.active && w.stage.work == w && w.stage.session == w.session
	if !valid || !birth.session.RetiredV1() || !r.lockV1() {
		op.mu.Unlock()
		return out, ErrHTMLSendPackageInspectionV1
	}
	op.mu.Unlock()
	defer r.unlockV1()
	if r.closeRequested.Load() || r.inspectionAttempted || r.grant == nil || w.sourceActor.ID != r.capture.CreatedBy || w.sourceActor.OrgID != r.capture.OrgID || w.state.ID != r.capture.DocumentID || w.state.OrgID != r.capture.OrgID || (w.sourceActor.Role != "owner" && (w.sourceActor.Role != "sender" || w.state.SenderID != w.sourceActor.ID)) {
		return out, ErrHTMLSendPackageInspectionV1
	}
	// Require this same genuine server incarnation, not just an equal tenant ID.
	old := birth.session.state
	old.mu.Lock()
	oldFence := old.fence
	oldIdentity := applicationBackendIdentityV1{}
	if oldFence != nil {
		oldIdentity = oldFence.identity
	}
	old.mu.Unlock()
	now := w.session.state
	now.mu.Lock()
	newFence := now.fence
	newIdentity := applicationBackendIdentityV1{}
	if newFence != nil {
		newIdentity = newFence.identity
	}
	now.mu.Unlock()
	if oldFence == nil || newFence == nil || !applicationServerSameV1(oldIdentity, newIdentity) {
		return out, ErrHTMLSendPackageInspectionV1
	}
	r.inspectionAttempted = true
	raw := int64(16384) + 8*(int64(unsafe.Sizeof(generated.InspectDocumentPackageSendAttemptStateV1Params{}))+int64(unsafe.Sizeof(generated.InspectDocumentPackageSendAttemptStateV1Row{}))+int64(unsafe.Sizeof(HTMLSendPackageAttemptObservationV1{}))+int64(unsafe.Sizeof(r.subjects))) + 16*(64+9)
	db := int64(16384) + 8*raw
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, db)
	if err != nil {
		return out, err
	}
	w.closes = append(w.closes, closeBody)
	// Includes the original frozen subjects even if the entire birth transaction
	// rolled back and left neither capture nor history to discover them from.
	if err = fenceDocumentPackageSubjectsV1(call, w.session, r.subjects, r.subjectCount); err != nil {
		return out, err
	}
	row, err := w.queries.InspectDocumentPackageSendAttemptStateV1(call, generated.InspectDocumentPackageSendAttemptStateV1Params{AttemptID: r.attemptID, OrgID: r.capture.OrgID, DocumentID: r.capture.DocumentID})
	if errors.Is(err, pgx.ErrNoRows) {
		if call.Err() != nil || r.closeRequested.Load() {
			return out, ErrHTMLSendPackageInspectionV1
		}
		return HTMLSendPackageAttemptObservationV1{AttemptID: r.attemptID, Outcome: HTMLSendPackageAttemptMissingV1}, nil
	}
	if err != nil {
		return out, err
	}
	out, err = htmlSendPackageAttemptObservationV1(row, r.attemptID, r.capture)
	if err != nil {
		return out, err
	}
	if call.Err() != nil || r.closeRequested.Load() {
		return out, ErrHTMLSendPackageInspectionV1
	}
	return out, nil
}

func htmlSendPackageAttemptObservationV1(row *generated.InspectDocumentPackageSendAttemptStateV1Row, id uuid.UUID, c HTMLSendPackageCaptureMetadataV1) (HTMLSendPackageAttemptObservationV1, error) {
	empty := HTMLSendPackageAttemptObservationV1{}
	if row == nil || id == uuid.Nil || row.AttemptID != id || row.OrgID != c.OrgID || row.DocumentID != c.DocumentID || row.PackageID != c.PackageID || row.CaptureRevision != c.Revision || row.PreviousRevision != c.PreviousRevision || row.CapturedDraftGeneration != c.DraftGeneration || !applicationStampV1(row.CapturedRootUpdatedAt) || !row.CapturedRootUpdatedAt.Time.Equal(c.RootUpdatedAt) || row.ManifestBytes != c.ManifestBytes || row.MemberCount != c.MemberCount || row.PdfBytes != c.PDFBytes || row.PdfPages != c.PDFPages || !bytes.Equal(row.ManifestSha256, c.CanonicalSHA256[:]) || !bytes.Equal(row.LegalCommitmentSha256, c.CommitmentSHA256[:]) || row.ActorUserID != c.CreatedBy || !applicationStampV1(row.CaptureCreatedAt) || !row.CaptureCreatedAt.Time.Equal(c.CreatedAt) || !row.ExactCapture || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.Article13NoticeEpochAt) || !applicationStampV1(row.RetainUntil) || !row.RetainUntil.Time.Equal(storage.EvidenceRetentionDeadline(row.Article13NoticeEpochAt.Time, article13.RetentionYearsV1)) {
		return empty, ErrHTMLSendPackageInspectionV1
	}
	if (row.RetentionStartedAt.Valid && !applicationStampV1(row.RetentionStartedAt)) || (row.RetentionCompletedAt.Valid && (!applicationStampV1(row.RetentionCompletedAt) || !row.RetentionStartedAt.Valid)) || (row.TerminalAt.Valid && !applicationStampV1(row.TerminalAt)) {
		return empty, ErrHTMLSendPackageInspectionV1
	}
	out := HTMLSendPackageAttemptObservationV1{AttemptID: id, Capture: c, Article13NoticeEpochAt: row.Article13NoticeEpochAt.Time.UTC(), RetainUntil: row.RetainUntil.Time.UTC(), CreatedAt: row.CreatedAt.Time.UTC()}
	if row.RetentionStartedAt.Valid {
		out.RetentionStartedAt = row.RetentionStartedAt.Time.UTC()
	}
	if row.RetentionCompletedAt.Valid {
		out.RetentionCompletedAt = row.RetentionCompletedAt.Time.UTC()
	}
	if row.TerminalAt.Valid {
		out.TerminalAt = row.TerminalAt.Time.UTC()
	}
	if !row.TerminalOutcome.Valid {
		if row.TerminalAt.Valid || !row.IntentAttemptID.Valid || uuid.UUID(row.IntentAttemptID.Bytes) != id || !row.IntentActorUserID.Valid || uuid.UUID(row.IntentActorUserID.Bytes) != c.CreatedBy || row.IntentPresignExecutionID.Valid || !applicationStampEqualV1(row.IntentArticle13NoticeEpochAt, row.Article13NoticeEpochAt) || !applicationStampEqualV1(row.IntentRetainUntil, row.RetainUntil) || !applicationStampEqualV1(row.IntentRetentionStartedAt, row.RetentionStartedAt) || !applicationStampEqualV1(row.IntentRetentionCompletedAt, row.RetentionCompletedAt) {
			return empty, ErrHTMLSendPackageInspectionV1
		}
		out.Outcome = HTMLSendPackageAttemptActiveV1
	} else {
		if !row.TerminalAt.Valid || row.IntentAttemptID.Valid {
			return empty, ErrHTMLSendPackageInspectionV1
		}
		switch row.TerminalOutcome.String {
		case "completed":
			if !row.RetentionStartedAt.Valid || !row.RetentionCompletedAt.Valid {
				return empty, ErrHTMLSendPackageInspectionV1
			}
			out.Outcome = HTMLSendPackageAttemptCompletedV1
		case "aborted":
			if row.RetentionStartedAt.Valid || row.RetentionCompletedAt.Valid {
				return empty, ErrHTMLSendPackageInspectionV1
			}
			out.Outcome = HTMLSendPackageAttemptAbortedV1
		default:
			return empty, ErrHTMLSendPackageInspectionV1
		}
	}
	return out, nil
}
