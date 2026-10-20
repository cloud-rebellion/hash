// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
)

func (p *applicationHTMLSendPackageDraftStateV1) pdfTargetV1(index int) (applicationDocumentPackagePDFTargetV1, error) {
	var empty applicationDocumentPackagePDFTargetV1
	if p.draft == nil || p.root == nil || index < 0 || index > p.draft.count || index >= len(p.observations) {
		return empty, ErrDocumentPackageMeasurementV1
	}
	if index == 0 {
		d := p.root
		if p.sourceOwner == nil || p.sourceOwner.snapshot == nil || !d.PdfStorageKey.Valid || !d.PdfStorageVersionID.Valid || len(d.PdfSha256) != sha256.Size {
			return empty, ErrDocumentPackageMeasurementV1
		}
		return applicationDocumentPackagePDFTargetV1{id: d.ID, key: d.PdfStorageKey.String, version: d.PdfStorageVersionID.String, sha: d.PdfSha256, report: d.MetadataRedactionReport, source: p.sourceOwner.snapshot}, nil
	}
	a := &p.draft.rows[index-1]
	return applicationDocumentPackagePDFTargetV1{id: a.MemberDocumentID, key: a.PdfKey, version: a.PdfVersionID, sha: a.PdfSha256, report: a.PdfIntakeReport, bytes: a.PdfBytes, pages: a.PdfPages}, nil
}

func (p *applicationHTMLSendPackageDraftStateV1) coordinatorV1() (*workguard.CoordinatorV1, error) {
	if p.sourceOwner == nil || p.sourceOwner.binding == nil || p.sourceOwner.binding.factory == nil {
		return nil, ErrDocumentPackageMeasurementV1
	}
	f := p.sourceOwner.binding.factory
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing || f.work == nil || f.work.coordinator == nil {
		return nil, ErrDocumentPackageMeasurementV1
	}
	return f.work.coordinator, nil
}

func (p *applicationHTMLSendPackageDraftStateV1) observePDFV1(index int) error {
	target, err := p.pdfTargetV1(index)
	if err != nil {
		return err
	}
	coordinator, err := p.coordinatorV1()
	if err != nil {
		return err
	}
	stream, err := coordinator.TryAcquireV1(p.ctx, p.root.OrgID, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		return err
	}
	defer stream.Close()
	observed, err := p.client.ObservePinnedPDFV1(p.ctx, target.key, target.version, target.sha)
	if err != nil {
		return errors.Join(ErrDocumentPackageMeasurementV1, err)
	}
	p.observations[index] = observed
	return nil
}

func (p *applicationHTMLSendPackageDraftStateV1) measurePDFV1(index int) error {
	target, err := p.pdfTargetV1(index)
	if err != nil {
		return err
	}
	observed := p.observations[index]
	if observed == nil {
		return ErrDocumentPackageMeasurementV1
	}
	coordinator, err := p.coordinatorV1()
	if err != nil {
		return err
	}
	parent, err := observed.ParentReadWorkV1()
	if err != nil {
		return err
	}
	bodyCredit, err := coordinator.TryAcquireV1(p.ctx, p.root.OrgID, workguard.VectorV1{ParentBytes: parent})
	if err != nil {
		return err
	}
	defer bodyCredit.Close()
	var raw []byte
	err = func() error {
		stream, err := coordinator.TryAcquireV1(p.ctx, p.root.OrgID, workguard.VectorV1{ProviderStreams: 1})
		if err != nil {
			return err
		}
		defer stream.Close()
		raw, err = observed.ReadV1(p.ctx)
		return err
	}()
	if err != nil {
		return errors.Join(ErrDocumentPackageMeasurementV1, err)
	}
	defer func() { clear(raw); raw = nil }()
	if int64(len(raw)) != observed.SizeV1() {
		return ErrDocumentPackageMeasurementV1
	}
	parentFrames, err := sanitize.PageCountIsolatedParentWorkV1(observed.SizeV1())
	if err != nil {
		return err
	}
	frames, err := coordinator.TryAcquireV1(p.ctx, p.root.OrgID, workguard.VectorV1{ParentBytes: parentFrames})
	if err != nil {
		return err
	}
	defer frames.Close()
	f := p.sourceOwner.binding.factory
	f.mu.Lock()
	work, closing := f.work, f.closing
	f.mu.Unlock()
	if closing || work == nil {
		return ErrDocumentPackageMeasurementV1
	}
	child, err := work.PDFWorkerV1(p.ctx, OrdinaryInspectionWorkerBudgetV1{Phase: "source", OrgID: p.root.OrgID, DocumentID: target.id})
	if err != nil {
		return err
	}
	pages, err := func() (int, error) {
		defer child()
		return sanitize.PageCountIsolatedWithContextV1(p.ctx, raw)
	}()
	if err != nil {
		return errors.Join(ErrDocumentPackageMeasurementV1, err)
	}
	if pages < 1 || pages > int(documentpackage.MaxPDFPagesV1) || (target.bytes > 0 && target.bytes != observed.SizeV1()) || (target.pages > 0 && target.pages != int32(pages)) {
		return ErrDocumentPackageMeasurementV1
	}
	if snap := target.source; snap != nil {
		d := snap.document
		if (d.HtmlCurrentPageCount.Valid && d.HtmlCurrentPageCount.Int32 != int32(pages)) || (snap.current != nil && snap.current.PageCount != int32(pages)) {
			return ErrDocumentPackageMeasurementV1
		}
	}
	if err = sanitize.ValidateStoredPDFProvenanceV1(target.report, hex.EncodeToString(target.sha), observed.SizeV1(), pages); err != nil {
		return errors.Join(ErrDocumentPackageMeasurementV1, err)
	}
	p.measured[index] = DocumentPackagePDFMeasurementV1{DocumentID: target.id, Bytes: observed.SizeV1(), Pages: int32(pages)}
	return p.ctx.Err()
}

// MeasurePDFsV1 is a one-shot continuation of the original native draft owner.
// Its original SQL backend must actually retire before any provider call. The
// concrete client is bound once; keys, versions, hashes, reports and costs come
// only from the owner's private snapshot and actual provider observations.
func (h *ApplicationHTMLSendPackageDraftV1) MeasurePDFsV1(client *storage.Client) error {
	if h == nil || h.state == nil || !h.state.lockV1() {
		return ErrDocumentPackageMeasurementV1
	}
	p := h.state
	defer p.unlockV1()
	if p.closeRequested.Load() || p.measureAttempted || p.draft == nil || p.source == nil || p.sourceOwner == nil || p.ctx == nil || p.ctx.Err() != nil {
		return ErrDocumentPackageMeasurementV1
	}
	p.measureAttempted = true
	s := p.source
	if !s.lockV1() {
		return ErrDocumentPackageMeasurementV1
	}
	defer s.unlockV1()
	owner := p.sourceOwner
	if s.closeRequested.Load() || s.owner != owner || s.candidate || !s.attempted || s.failure != nil || !s.currentAttempted || s.currentFailure != nil {
		return ErrDocumentPackageMeasurementV1
	}
	if err := owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	if owner.binding == nil || owner.binding.session == nil || !owner.binding.session.RetiredV1() || owner.binding.session.CommitUnknownV1() {
		return ErrDocumentPackageMeasurementV1
	}
	w := p.work
	if w == nil {
		return ErrDocumentPackageMeasurementV1
	}
	w.mu.Lock()
	valid := !w.closed && w.sourceState == s && w.sourceOwner == owner && w.familyRoot == nil && w.packageDraft == p
	stage := w.stage
	w.mu.Unlock()
	if !valid || stage == nil || stage.operation == nil {
		return ErrDocumentPackageMeasurementV1
	}
	o := stage.operation
	o.mu.Lock()
	valid = !o.closed && stage.used && !stage.active && !stage.opening && stage.work == w && stage.session == owner.binding.session
	o.mu.Unlock()
	if !valid {
		return ErrDocumentPackageMeasurementV1
	}
	metadata, err := client.PinnedPDFObservationParentWorkV1()
	if err != nil {
		return ErrDocumentPackageMeasurementV1
	}
	count := 1 + p.draft.count
	if count < 1 || count > len(p.observations) {
		return ErrDocumentPackageMeasurementV1
	}
	cost := int64(0)
	if !htmlInputAddV1(&cost, metadata, int64(count)) {
		return ErrDocumentPackageMeasurementV1
	}
	if err = owner.holdV1(htmlRevisionSourceStateV1, 0, cost); err != nil {
		return err
	}
	p.client = client
	// Check every identity before HEAD and every HEAD before allocating any PDF.
	for i := 0; i < count; i++ {
		a, err := p.pdfTargetV1(i)
		if err != nil {
			return err
		}
		for j := 0; j < i; j++ {
			b, err := p.pdfTargetV1(j)
			if err != nil {
				return err
			}
			if a.id == b.id || (a.key == b.key && a.version == b.version) {
				return ErrDocumentPackageMeasurementV1
			}
		}
	}
	var bytes int64
	for i := 0; i < count; i++ {
		if err = p.observePDFV1(i); err != nil {
			return err
		}
		target, err := p.pdfTargetV1(i)
		if err != nil {
			return err
		}
		size := p.observations[i].SizeV1()
		if size < 1 || size > documentpackage.MaxPDFBytesV1-bytes || (target.bytes > 0 && target.bytes != size) {
			return ErrDocumentPackageMeasurementV1
		}
		bytes += size
	}
	var pages int32
	for i := 0; i < count; i++ {
		if err = p.measurePDFV1(i); err != nil {
			return err
		}
		if p.measured[i].Pages > documentpackage.MaxPDFPagesV1-pages {
			return ErrDocumentPackageMeasurementV1
		}
		pages += p.measured[i].Pages
	}
	if p.closeRequested.Load() || p.ctx.Err() != nil {
		return ErrDocumentPackageMeasurementV1
	}
	p.measuredOK = true
	return nil
}

// MeasurementsV1 returns copied diagnostics. Only the private native owner can
// later use its measured snapshot for a fresh package capture/sealing policy.
func (h *ApplicationHTMLSendPackageDraftV1) MeasurementsV1() ([documentpackage.MaxAnnexesV1 + 1]DocumentPackagePDFMeasurementV1, int, error) {
	var empty [documentpackage.MaxAnnexesV1 + 1]DocumentPackagePDFMeasurementV1
	if h == nil || h.state == nil || !h.state.lockV1() {
		return empty, 0, ErrDocumentPackageMeasurementV1
	}
	p := h.state
	defer p.unlockV1()
	if p.closeRequested.Load() || !p.measuredOK || p.draft == nil || p.ctx == nil || p.ctx.Err() != nil {
		return empty, 0, ErrDocumentPackageMeasurementV1
	}
	return p.measured, 1 + p.draft.count, nil
}
