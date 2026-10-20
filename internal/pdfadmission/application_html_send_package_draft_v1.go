// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ApplicationHTMLSendPackageDraftV1 retains the original Send root and its
// selected immutable annex rows across SQL retirement. Copies share one owner.
// This read creates neither a capture nor authority to send or sign a package.
type ApplicationHTMLSendPackageDraftV1 struct {
	state *applicationHTMLSendPackageDraftStateV1
}

// These copied observations cannot authorize a later append or sealing step.
type HTMLSendPackageDraftMetadataV1 struct {
	Present    bool
	PackageID  uuid.UUID
	Generation int64
	Head       int64
	Annexes    int
}

type applicationHTMLSendPackageDraftStateV1 struct {
	activityMutex                sync.Mutex
	activity                     applicationJoinedActivityV1
	closeRequested               atomic.Bool
	cancelOnce                   sync.Once
	ctx                          context.Context
	cancel                       context.CancelFunc
	work                         *ApplicationHTMLSendWorkV1
	source                       *applicationHTMLSendSourceStateV1
	sourceOwner                  *applicationHTMLRevisionSourceOwnerV1
	root                         *generated.Document
	releaseSource                func()
	closes                       []func()
	draft                        *applicationDocumentPackageDraftSnapshotV1
	head                         int64
	readAttempted                bool
	client                       *storage.Client
	observations                 [documentpackage.MaxAnnexesV1 + 1]*storage.PinnedPDFReadV1
	measured                     [documentpackage.MaxAnnexesV1 + 1]DocumentPackagePDFMeasurementV1
	measureAttempted, measuredOK bool
	captureAttempted             bool
}

// ReadDocumentPackageDraftV1 uses only this Work's validated ORIGINAL source
// and genuine root-locked SQL session. It never needs a candidate document,
// caller rows/proofs, or locks on the mutable sources of selected annexes.
func (w *ApplicationHTMLSendWorkV1) ReadDocumentPackageDraftV1(call context.Context, source *ApplicationHTMLSendSourceV1, expected DocumentPackageDraftExpectedV1) (*ApplicationHTMLSendPackageDraftV1, error) {
	if w == nil || w.self != w || source == nil || source.state == nil || expected.Generation < 0 || (expected.PackageID == uuid.Nil) != (expected.Generation == 0) {
		return nil, ErrDocumentPackageDraftV1
	}
	s := source.state
	w.mu.Lock()
	valid := w.valid(call) && w.stage != nil && w.familyRoot == nil && w.sourceState == s && !w.packageDraftAttempted &&
		(w.stage.purpose == HTMLSendPreparationV1 || w.stage.purpose == HTMLSendAdmissionV1)
	if valid {
		w.packageDraftAttempted = true
	}
	w.mu.Unlock()
	if !valid || !s.lockV1() {
		return nil, ErrDocumentPackageDraftV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.work != w || s.candidate || s.owner == nil || !s.attempted || s.failure != nil || !s.currentAttempted || s.currentFailure != nil {
		return nil, ErrDocumentPackageDraftV1
	}
	owner := s.owner
	if err := owner.beginV1(); err != nil {
		return nil, err
	}
	defer owner.finishV1()
	if owner.purpose != htmlSendSourcePurposeV1 || owner.snapshot == nil || owner.snapshot.document == nil || !owner.currentValidated {
		return nil, ErrDocumentPackageDraftV1
	}
	// Fund the owner, public shell, two body-loan closures and once-only source
	// release before allocation. The real source owner supplies the original
	// context, admission and resource loans; public metadata supplies none.
	fixed := int64(unsafe.Sizeof(applicationHTMLSendPackageDraftStateV1{})) + int64(unsafe.Sizeof(ApplicationHTMLSendPackageDraftV1{})) +
		int64(unsafe.Sizeof(sync.Once{})) + 8*int64(unsafe.Sizeof(uintptr(0))) + 4096
	if err := owner.holdV1(htmlRevisionSourceStateV1, 0, fixed); err != nil {
		return nil, err
	}
	if err := owner.beginV1(); err != nil {
		return nil, err
	}
	var once sync.Once
	p := &applicationHTMLSendPackageDraftStateV1{work: w, source: s, sourceOwner: owner, root: owner.snapshot.document}
	p.ctx, p.cancel = context.WithCancel(owner.binding.ctx)
	p.releaseSource = func() { once.Do(owner.finishV1) }
	// Register this active frame BEFORE exposing the owner to Work shutdown.
	if !p.lockV1() {
		p.closeV1()
		return nil, ErrDocumentPackageDraftV1
	}
	defer p.unlockV1()
	w.mu.Lock()
	valid = w.valid(call) && w.packageDraft == nil && w.sourceState == s && w.sourceOwner == owner
	if valid {
		w.packageDraft = p
	}
	w.mu.Unlock()
	if !valid {
		p.closeV1()
		return nil, ErrDocumentPackageDraftV1
	}
	if err := p.readRootDraftV1(call, expected); err != nil {
		p.closeV1()
		return nil, err
	}
	return &ApplicationHTMLSendPackageDraftV1{state: p}, nil
}

func (p *applicationHTMLSendPackageDraftStateV1) lockV1() bool {
	if !p.activity.enterV1() {
		return false
	}
	p.activityMutex.Lock()
	return true
}
func (p *applicationHTMLSendPackageDraftStateV1) unlockV1() {
	p.activityMutex.Unlock()
	if p.activity.leaveV1() {
		p.retireClosedV1()
	}
}
func (p *applicationHTMLSendPackageDraftStateV1) closeV1() {
	p.closeRequested.Store(true)
	// Cancel this consumer before closing its activity gate. Concurrent closes
	// join this one call before retirement can clear the cancellation closure.
	p.cancelOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
	})
	if p.activity.closeV1() {
		p.retireClosedV1()
	}
}
func (p *applicationHTMLSendPackageDraftStateV1) retireClosedV1() {
	closes, release := p.closes, p.releaseSource
	p.closes, p.releaseSource, p.draft, p.root = nil, nil, nil, nil
	p.work, p.source, p.sourceOwner = nil, nil, nil
	p.client, p.ctx, p.cancel = nil, nil, nil
	p.observations = [documentpackage.MaxAnnexesV1 + 1]*storage.PinnedPDFReadV1{}
	p.measured = [documentpackage.MaxAnnexesV1 + 1]DocumentPackagePDFMeasurementV1{}
	for _, closeBody := range closes {
		closeBody()
	}
	if release != nil {
		release()
	}
}
func (h *ApplicationHTMLSendPackageDraftV1) CloseConsumerV1() {
	if h != nil && h.state != nil {
		h.state.closeV1()
	}
}

func (h *ApplicationHTMLSendPackageDraftV1) MetadataV1() (HTMLSendPackageDraftMetadataV1, error) {
	var out HTMLSendPackageDraftMetadataV1
	if h == nil || h.state == nil || !h.state.lockV1() {
		return out, ErrDocumentPackageDraftV1
	}
	p := h.state
	defer p.unlockV1()
	if p.closeRequested.Load() || p.draft == nil || p.sourceOwner == nil || p.sourceOwner.binding == nil || p.sourceOwner.binding.ctx.Err() != nil {
		return out, ErrDocumentPackageDraftV1
	}
	d := p.draft
	return HTMLSendPackageDraftMetadataV1{Present: d.present, PackageID: d.header.ID, Generation: d.header.DraftGeneration, Head: p.head, Annexes: d.count}, nil
}

// Caller holds the registered owner mutex and original source frame. Full
// reports are prepaid and read only after fresh privacy checks. Sparse draft
// ordering is retained here; canonical capture construction normalizes it later.
func (p *applicationHTMLSendPackageDraftStateV1) readRootDraftV1(call context.Context, expected DocumentPackageDraftExpectedV1) error {
	if p == nil || p.work == nil || p.sourceOwner == nil || p.root == nil || p.readAttempted || p.closeRequested.Load() {
		return ErrDocumentPackageDraftV1
	}
	p.readAttempted = true
	w, d := p.work, p.root
	w.mu.Lock()
	valid := w.valid(call) && w.state != nil && w.sourceState == p.source && w.sourceOwner == p.sourceOwner &&
		w.familyRoot == nil && w.state.ID == d.ID && w.state.OrgID == d.OrgID && w.state.UpdatedAt == d.UpdatedAt &&
		w.session.state.document == d.ID && w.session.state.org == d.OrgID
	q, actor, session := w.queries, w.actor, w.session
	w.mu.Unlock()
	if !valid || d.Status != "draft" || d.SourceKind != "pdf" || d.IsEnvelope || d.ParentEnvelopeID.Valid || d.DeletedAt.Valid ||
		!d.PdfStorageKey.Valid || !d.PdfStorageVersionID.Valid || len(d.PdfSha256) != sha256.Size {
		return ErrDocumentPackageDraftV1
	}
	fixed := 4*int64(unsafe.Sizeof(applicationDocumentPackageDraftSnapshotV1{})) +
		4*int64(unsafe.Sizeof(generated.DocumentPackagesV1{})) + 4*int64(unsafe.Sizeof(generated.GetDocumentPackageDraftSizesV1Row{})) +
		4*(63*int64(unsafe.Sizeof((*generated.ListDocumentPackageDraftSubjectsV1Row)(nil)))+17*int64(unsafe.Sizeof(generated.ListDocumentPackageDraftSubjectsV1Row{}))) + 4096
	closeBody, err := actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		return err
	}
	p.closes = append(p.closes, closeBody)
	snap := new(applicationDocumentPackageDraftSnapshotV1)
	var ids [documentpackage.MaxAnnexesV1 + 2]uuid.UUID
	ids[0] = d.ID
	header, err := q.LockDocumentPackageByRootV1(call, generated.LockDocumentPackageByRootV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		if expected.PackageID != uuid.Nil {
			return ErrDocumentPackageSourceChangedV1
		}
		if err = fenceDocumentPackageSubjectsV1(call, session, ids, 1); err != nil {
			return err
		}
		if call.Err() != nil || p.closeRequested.Load() {
			return ErrDocumentPackageDraftV1
		}
		p.draft = snap
		return nil
	}
	if err != nil {
		return err
	}
	if header == nil || header.ID == uuid.Nil || header.DocumentID != d.ID || header.OrgID != d.OrgID || header.CreatedBy == uuid.Nil ||
		!applicationStampV1(header.CreatedAt) || header.DraftGeneration < 1 || header.DraftGeneration == math.MaxInt64 {
		return ErrDocumentPackageDraftV1
	}
	if header.ID != expected.PackageID || header.DraftGeneration != expected.Generation {
		return ErrDocumentPackageSourceChangedV1
	}
	head, err := q.GetDocumentPackageCaptureHeadV1(call, generated.GetDocumentPackageCaptureHeadV1Params{PackageID: header.ID, OrgID: d.OrgID, DocumentID: d.ID})
	if err != nil {
		return err
	}
	if head < 0 || head == math.MaxInt64 {
		return ErrDocumentPackageDraftV1
	}
	h, err := q.GetDocumentPackageDraftSizesV1(call, generated.GetDocumentPackageDraftSizesV1Params{PackageID: header.ID, DocumentID: d.ID, OrgID: d.OrgID, ExpectedGeneration: header.DraftGeneration})
	if err != nil {
		return err
	}
	if h == nil || h.PackageID != header.ID || h.DocumentID != d.ID || h.OrgID != d.OrgID || h.DraftGeneration != header.DraftGeneration || h.MemberCount < 0 || h.MemberCount > documentpackage.MaxAnnexesV1 {
		return ErrDocumentPackageDraftV1
	}
	subjects, err := q.ListDocumentPackageDraftSubjectsV1(call, generated.ListDocumentPackageDraftSubjectsV1Params{PackageID: header.ID, DocumentID: d.ID, OrgID: d.OrgID, ExpectedGeneration: header.DraftGeneration})
	if err != nil {
		return err
	}
	if int64(len(subjects)) != h.MemberCount || len(subjects) > documentpackage.MaxAnnexesV1 {
		return ErrDocumentPackageDraftV1
	}
	var previous int16
	for i, subject := range subjects {
		if subject == nil || subject.MemberDocumentID == uuid.Nil || subject.MemberDocumentID == d.ID || subject.Ordinal <= previous || subject.Ordinal > 16 {
			return ErrDocumentPackageDraftV1
		}
		for j := 0; j < i; j++ {
			if subjects[j].MemberDocumentID == subject.MemberDocumentID {
				return ErrDocumentPackageDraftV1
			}
		}
		ids[i+1], previous = subject.MemberDocumentID, subject.Ordinal
	}
	if err = fenceDocumentPackageSubjectsV1(call, session, ids, len(subjects)+1); err != nil {
		return err
	}
	raw, wire, err := documentPackageDraftBodyCostV1(h)
	if err != nil {
		return err
	}
	closeBody, err = actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return err
	}
	p.closes = append(p.closes, closeBody)
	rows, err := q.ListDocumentAttachmentDraftsV1(call, generated.ListDocumentAttachmentDraftsV1Params{PackageID: header.ID, OrgID: d.OrgID, ExpectedGeneration: header.DraftGeneration})
	if err != nil {
		return err
	}
	if len(rows) != len(subjects) {
		return ErrDocumentPackageDraftV1
	}
	var rawSum, reportSum, pdfBytes, pdfPages int64
	for i, a := range rows {
		if a == nil || a.PackageID != header.ID || a.OrgID != d.OrgID || a.MemberDocumentID != subjects[i].MemberDocumentID || a.Ordinal != subjects[i].Ordinal ||
			!applicationStampV1(a.CreatedAt) || len(a.PdfSha256) != sha256.Size || len(a.PdfIntakeReport) < 1 || len(a.PdfIntakeReport) > 65536 ||
			len(a.PdfIntakeReportSha256) != sha256.Size || a.PdfBytes < 1 || a.PdfPages < 1 {
			return ErrDocumentPackageDraftV1
		}
		if a.PdfKey == d.PdfStorageKey.String && a.PdfVersionID == d.PdfStorageVersionID.String {
			return ErrDocumentPackageDraftV1
		}
		for j := 0; j < i; j++ {
			b := rows[j]
			if b.MemberDocumentID == a.MemberDocumentID || (b.PdfKey == a.PdfKey && b.PdfVersionID == a.PdfVersionID) {
				return ErrDocumentPackageDraftV1
			}
		}
		digest := sha256.Sum256(a.PdfIntakeReport)
		if !bytes.Equal(digest[:], a.PdfIntakeReportSha256) {
			return ErrDocumentPackageDraftV1
		}
		n, e := documentPackageDraftRowRawV1(a)
		if e != nil || !htmlInputAddV1(&rawSum, n, 1) || !htmlInputAddV1(&reportSum, int64(len(a.PdfIntakeReport)), 1) ||
			!htmlInputAddV1(&pdfBytes, a.PdfBytes, 1) || !htmlInputAddV1(&pdfPages, int64(a.PdfPages), 1) {
			return ErrDocumentPackageDraftV1
		}
		snap.rows[i] = documentPackageDraftCloneV1(a)
	}
	if rawSum != h.RawTextBytes || reportSum != h.ReportBytes || pdfBytes != h.PdfBytes || pdfPages != h.PdfPages || call.Err() != nil || p.closeRequested.Load() {
		return ErrDocumentPackageDraftV1
	}
	snap.present, snap.header, snap.sizes, snap.count = true, *header, *h, len(rows)
	p.draft, p.head = snap, head
	return nil
}
