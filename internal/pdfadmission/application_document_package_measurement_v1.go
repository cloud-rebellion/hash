// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrDocumentPackageMeasurementV1 = errors.New("pdfadmission: exact package PDFs could not be measured")

type DocumentPackagePDFMeasurementV1 struct {
	DocumentID uuid.UUID
	Bytes      int64
	Pages      int32
}

// Root and candidate remain the two actual live authorization subjects.
// Existing annexes derive exclusively from retained immutable M101 rows.
type applicationDocumentPackagePDFTargetV1 struct {
	id           uuid.UUID
	key, version string
	sha, report  []byte
	bytes        int64
	pages        int32
	source       *applicationHTMLRevisionSourceSnapshotV1
}

func (s *applicationDocumentPackageOperationStateV1) pdfCountV1() int {
	n := 2
	if s.draft != nil {
		n += s.draft.count
	}
	return n
}
func (s *applicationDocumentPackageOperationStateV1) pdfTargetV1(index int) (applicationDocumentPackagePDFTargetV1, error) {
	var t applicationDocumentPackagePDFTargetV1
	if index < 0 || index >= s.pdfCountV1() || index >= len(s.observations) {
		return t, ErrDocumentPackageMeasurementV1
	}
	if index < 2 {
		snap := s.snapshots[index]
		if snap == nil || snap.document == nil {
			return t, ErrDocumentPackageMeasurementV1
		}
		d := snap.document
		if !d.PdfStorageKey.Valid || !d.PdfStorageVersionID.Valid || len(d.PdfSha256) != sha256.Size {
			return t, ErrDocumentPackageMeasurementV1
		}
		return applicationDocumentPackagePDFTargetV1{id: d.ID, key: d.PdfStorageKey.String, version: d.PdfStorageVersionID.String, sha: d.PdfSha256, report: d.MetadataRedactionReport, source: snap}, nil
	}
	a := &s.draft.rows[index-2]
	return applicationDocumentPackagePDFTargetV1{id: a.MemberDocumentID, key: a.PdfKey, version: a.PdfVersionID, sha: a.PdfSha256, report: a.PdfIntakeReport, bytes: a.PdfBytes, pages: a.PdfPages}, nil
}

func (s *applicationDocumentPackageOperationStateV1) coordinatorV1() (*workguard.CoordinatorV1, error) {
	p := s.factory.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.work == nil || p.work.coordinator == nil {
		return nil, ErrDocumentPackageOperationV1
	}
	return p.work.coordinator, nil
}
func (s *applicationDocumentPackageOperationStateV1) observePDFV1(index int) error {
	target, err := s.pdfTargetV1(index)
	if err != nil {
		return err
	}
	coordinator, err := s.coordinatorV1()
	if err != nil {
		return err
	}
	stream, err := coordinator.TryAcquireV1(s.ctx, s.org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		return err
	}
	defer stream.Close()
	observed, err := s.client.ObservePinnedPDFV1(s.ctx, target.key, target.version, target.sha)
	if err != nil {
		return errors.Join(ErrDocumentPackageMeasurementV1, err)
	}
	s.observations[index] = observed
	return nil
}
func (s *applicationDocumentPackageOperationStateV1) measurePDFV1(index int) error {
	target, err := s.pdfTargetV1(index)
	if err != nil {
		return err
	}
	observed := s.observations[index]
	if observed == nil {
		return ErrDocumentPackageMeasurementV1
	}
	coordinator, err := s.coordinatorV1()
	if err != nil {
		return err
	}
	parent, err := observed.ParentReadWorkV1()
	if err != nil {
		return err
	}
	bodyCredit, err := coordinator.TryAcquireV1(s.ctx, s.org, workguard.VectorV1{ParentBytes: parent})
	if err != nil {
		return err
	}
	defer bodyCredit.Close()
	var raw []byte
	err = func() error {
		stream, err := coordinator.TryAcquireV1(s.ctx, s.org, workguard.VectorV1{ProviderStreams: 1})
		if err != nil {
			return err
		}
		defer stream.Close()
		raw, err = observed.ReadV1(s.ctx)
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
	frames, err := coordinator.TryAcquireV1(s.ctx, s.org, workguard.VectorV1{ParentBytes: parentFrames})
	if err != nil {
		return err
	}
	defer frames.Close()
	// This actual fixed owner supplies the immutable source identity; no caller
	// cost or release flag can create or refund a child execution grant.
	p := s.factory.state
	p.mu.Lock()
	work := p.work
	closing := p.closing
	p.mu.Unlock()
	if closing || work == nil {
		return ErrDocumentPackageMeasurementV1
	}
	child, err := work.PDFWorkerV1(s.ctx, OrdinaryInspectionWorkerBudgetV1{Phase: "source", OrgID: s.org, DocumentID: target.id})
	if err != nil {
		return err
	}
	pages, err := func() (int, error) { defer child(); return sanitize.PageCountIsolatedWithContextV1(s.ctx, raw) }()
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
	s.mu.Lock()
	s.allMeasured[index] = DocumentPackagePDFMeasurementV1{DocumentID: target.id, Bytes: observed.SizeV1(), Pages: int32(pages)}
	if index < 2 {
		s.measured[index] = s.allMeasured[index]
	}
	s.mu.Unlock()
	return s.ctx.Err()
}

// MeasurePDFsV1 runs only after actual initial SQL retirement. Every HEAD size
// precedes PDF allocation; raw PDFs are read/inspected/cleared sequentially.
// A ReadDraftV1 snapshot adds every immutable stored annex to the same budget.
func (h *ApplicationDocumentPackageOperationV1) MeasurePDFsV1() error {
	return h.measurePDFsV1(false)
}
func (h *ApplicationDocumentPackageOperationV1) measurePDFsV1(selecting bool) error {
	if h == nil || h.state == nil {
		return ErrDocumentPackageOperationV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if !s.initialRead || s.measureAttempted || s.closed || selecting != s.selectionAttempted {
		s.mu.Unlock()
		return ErrDocumentPackageOperationV1
	}
	s.measureAttempted = true
	session := s.stages[0].session
	s.mu.Unlock()
	if session == nil || !session.RetiredV1() || session.CommitUnknownV1() {
		return ErrDocumentPackageOperationV1
	}
	count := s.pdfCountV1()
	if count > len(s.observations) {
		return ErrDocumentPackageMeasurementV1
	}
	for i := 0; i < count; i++ {
		a, err := s.pdfTargetV1(i)
		if err != nil {
			return err
		}
		for j := 0; j < i; j++ {
			b, err := s.pdfTargetV1(j)
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
		if err := s.observePDFV1(i); err != nil {
			return err
		}
		size := s.observations[i].SizeV1()
		target, err := s.pdfTargetV1(i)
		if err != nil {
			return err
		}
		if target.bytes > 0 && target.bytes != size {
			return ErrDocumentPackageMeasurementV1
		}
		if size < 1 || size > documentpackage.MaxPDFBytesV1-bytes {
			return ErrDocumentPackageMeasurementV1
		}
		bytes += size
	}
	var pages int32
	for i := 0; i < count; i++ {
		if err := s.measurePDFV1(i); err != nil {
			return err
		}
		if s.allMeasured[i].Pages > documentpackage.MaxPDFPagesV1-pages {
			return ErrDocumentPackageMeasurementV1
		}
		pages += s.allMeasured[i].Pages
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrDocumentPackageOperationV1
	}
	s.measuredOK = true
	s.mu.Unlock()
	return nil
}

// Diagnostic values only: root,candidate,then frozen annexes in ordinal order.
// They are not a legal manifest, a storage grant or fixed-writer authority.
func (h *ApplicationDocumentPackageOperationV1) PackageMeasurementsV1() ([documentpackage.MaxAnnexesV1 + 1]DocumentPackagePDFMeasurementV1, int, error) {
	var empty [documentpackage.MaxAnnexesV1 + 1]DocumentPackagePDFMeasurementV1
	if h == nil || h.state == nil {
		return empty, 0, ErrDocumentPackageOperationV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.measuredOK {
		return empty, 0, ErrDocumentPackageOperationV1
	}
	return s.allMeasured, s.pdfCountV1(), nil
}
func (h *ApplicationDocumentPackageOperationV1) MeasurementsV1() ([2]DocumentPackagePDFMeasurementV1, error) {
	if h == nil || h.state == nil {
		return [2]DocumentPackagePDFMeasurementV1{}, ErrDocumentPackageOperationV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.measuredOK {
		return [2]DocumentPackagePDFMeasurementV1{}, ErrDocumentPackageOperationV1
	}
	return s.measured, nil
}
