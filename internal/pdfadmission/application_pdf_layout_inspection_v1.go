// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var (
	ErrPDFLayoutInspectionV1        = errors.New("pdfadmission: owned PDF layout inspection unavailable")
	ErrPDFLayoutNotEditableV1       = errors.New("save a PDF layout from an editable PDF draft")
	ErrPDFLayoutHTMLSourceV1        = errors.New("reuse the approved HTML design to render a fresh document; static PDF template export of HTML documents is unavailable")
	ErrPDFLayoutInspectionChangedV1 = errors.New("document changed; review the current design")
	ErrPDFLayoutCommitmentV1        = errors.New("PDF source has no verified content commitment")
)

type ApplicationPDFLayoutInspectionV1 struct {
	self  *ApplicationPDFLayoutInspectionV1
	state *pdfLayoutInspectionStateV1
}
type pdfLayoutInspectionStateV1 struct {
	mu                                      sync.Mutex
	factory                                 *ApplicationSessionFactoryV1
	session                                 *ApplicationSessionV1
	reader                                  *ApplicationHTMLAuthoringReaderV1
	client                                  *storage.Client
	limits                                  storage.SendEvidenceLimitsV1
	org, document                           uuid.UUID
	source                                  *generated.Document
	closes                                  []func()
	pages                                   int
	read, inspected, closeRequested, closed bool
	borrowers                               int
}

// Original UNLOCKED pre-inspection, before the later locked draft/actor guard.
// This fixed producer owns its own real source session and concrete provider,
// never receives a caller row/transaction or borrows Sign/Send-stage authority.
func (f *ApplicationSessionFactoryV1) InspectPDFLayoutSourceV1(ctx context.Context, org, document uuid.UUID, expected time.Time, client *storage.Client) (result *ApplicationPDFLayoutInspectionV1, failure error) {
	if f == nil || f.state == nil || org == uuid.Nil || document == uuid.Nil || client == nil || !applicationContextV1(ctx) {
		return nil, ErrPDFLayoutInspectionV1
	}
	limits, err := client.SendEvidenceLimitsV1()
	if err != nil {
		return nil, err
	}
	session, err := f.OpenV1(ctx, org, document)
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = session.CloseV1(cleanup)
		}
		return nil, err
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = session.CloseV1(cleanup)
		return nil, err
	}
	var reader *ApplicationHTMLAuthoringReaderV1
	closeSQL := func() error {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		closed := session.CloseV1(cleanup)
		_, reconciled := admission.ReconcileCleanupV1(cleanup)
		return errors.Join(closed, reconciled)
	}
	err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		raw := 2*int64(unsafe.Sizeof(pdfLayoutInspectionStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationPDFLayoutInspectionV1{})) + 2*int64(unsafe.Sizeof(generated.GetPDFLayoutInspectionSourceHeaderV1Row{})) + int64(unsafe.Sizeof(generated.ReadPDFLayoutInspectionDocumentV1Params{})) + 16*int64(unsafe.Sizeof((func())(nil)))
		// Bounded concrete Client/worker error metadata may escape the synchronous
		// provider grant; prepay its retained error/control storage before any call.
		if !htmlInputAddV1(&raw, limits.MetadataBytes, 4) || !htmlInputAddV1(&raw, limits.HeaderBytes, 4) || !htmlInputAddV1(&raw, limits.VersionIDBytes, 2) || !htmlInputAddV1(&raw, 1, 65536) {
			return ErrPDFLayoutInspectionV1
		}
		close, err := reader.acquireOwnedRetainedBodyV1(call, raw, 0)
		if err != nil {
			return err
		}
		s := &pdfLayoutInspectionStateV1{factory: f, session: session, reader: reader, client: client, limits: limits, org: org, document: document, closes: []func(){close}}
		result = &ApplicationPDFLayoutInspectionV1{state: s}
		result.self = result
		q := generated.New(&applicationOwnedDBTXV1{session: session.state})
		h, err := q.GetPDFLayoutInspectionSourceHeaderV1(call, generated.GetPDFLayoutInspectionSourceHeaderV1Params{DocumentID: document, OrgID: org})
		if err != nil {
			return err
		}
		if h == nil || h.ID != document || h.OrgID != org {
			return ErrPDFLayoutInspectionV1
		}
		if !h.IsPdfSource || !h.IsDraft {
			return ErrPDFLayoutNotEditableV1
		}
		if h.HasHtmlSource {
			return ErrPDFLayoutHTMLSourceV1
		}
		if !h.UpdatedAt.Valid || !expected.Equal(h.UpdatedAt.Time) {
			return ErrPDFLayoutInspectionChangedV1
		}
		if !h.HasVerifiedPdfCommitment {
			return ErrPDFLayoutCommitmentV1
		}
		if h.ServerVersionNum <= 0 || h.PolicyMeasurementServerVersionNum != h.ServerVersionNum || h.ResponseMeasurementServerVersionNum != h.ServerVersionNum || h.ReportMeasurementServerVersionNum != h.ServerVersionNum {
			return ErrPDFLayoutInspectionV1
		}
		wire, err := htmlAuthoringSumV1(h.HtmlOriginWireBytes, h.HtmlCurrentWireBytes, h.VariablesWireBytes, h.BlocksWireBytes, h.MetadataWireBytes, h.ReportWireBytes)
		if err != nil {
			return err
		}
		sourceRaw := h.RawTextBytes
		if !htmlInputAddV1(&sourceRaw, h.RawTextBytes, 4) {
			return ErrPDFLayoutInspectionV1
		}
		closeBody, err := reader.acquireOwnedRetainedBodyV1(call, sourceRaw, wire)
		if err != nil {
			return err
		}
		s.closes = append(s.closes, closeBody)
		row, err := q.ReadPDFLayoutInspectionDocumentV1(call, generated.ReadPDFLayoutInspectionDocumentV1Params{DocumentID: document, OrgID: org, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes, ExpectedHtmlOriginWireBytes: h.HtmlOriginWireBytes, ExpectedHtmlCurrentWireBytes: h.HtmlCurrentWireBytes, ExpectedVariablesWireBytes: h.VariablesWireBytes, ExpectedBlocksWireBytes: h.BlocksWireBytes, ExpectedMetadataWireBytes: h.MetadataWireBytes, ExpectedReportWireBytes: h.ReportWireBytes})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPDFLayoutInspectionChangedV1
		}
		if err != nil {
			return err
		}
		if row == nil || row.ID != document || row.OrgID != org || row.SourceKind != "pdf" || row.Status != "draft" || row.UpdatedAt != h.UpdatedAt || len(row.HtmlSourceJson) != 0 || signerDocumentRawBytesV1(row) != h.RawTextBytes || int64(len(row.HtmlSourceJson)) != h.HtmlOriginWireBytes || int64(len(row.HtmlCurrentSourceJson)) != h.HtmlCurrentWireBytes || int64(len(row.VariablesJson)) != h.VariablesWireBytes || int64(len(row.BlocksJson)) != h.BlocksWireBytes || int64(len(row.Metadata)) != h.MetadataWireBytes || int64(len(row.MetadataRedactionReport)) != h.ReportWireBytes {
			return ErrPDFLayoutInspectionV1
		}
		s.source = htmlRevisionCloneDocumentV1(row)
		s.read = true
		return nil
	})
	closeErr := closeSQL()
	if err != nil || closeErr != nil {
		if result == nil && reader != nil {
			reader.CloseConsumerV1()
		}
		return result, errors.Join(err, closeErr)
	}
	s := result.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.read || s.source == nil {
		return result, ErrPDFLayoutInspectionV1
	}
	p := f.state
	p.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !p.closing && p.work != nil {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if coordinator == nil {
		return result, ErrPDFLayoutInspectionV1
	}
	scratch := int64(0)
	if !htmlInputAddV1(&scratch, limits.ObjectBytes+1, 4) || !htmlInputAddV1(&scratch, limits.MetadataBytes, 4) || !htmlInputAddV1(&scratch, limits.HeaderBytes, 4) || !htmlInputAddV1(&scratch, limits.VersionIDBytes, 2) {
		return result, ErrPDFLayoutInspectionV1
	}
	grant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: scratch, ProviderStreams: 1})
	if err != nil {
		return result, errors.Join(ErrPDFLayoutInspectionV1, err)
	}
	var body []byte
	defer func() { clear(body); body = nil; grant.Close() }()
	d := s.source
	if !d.PdfStorageKey.Valid || strings.TrimSpace(d.PdfStorageKey.String) == "" || len(d.PdfSha256) != sha256.Size {
		return result, errors.New("document artifact commitment is incomplete")
	}
	if d.PdfStorageVersionID.Valid && strings.TrimSpace(d.PdfStorageVersionID.String) != "" {
		body, err = client.GetVerifiedVersionForSendV1(ctx, d.PdfStorageKey.String, d.PdfStorageVersionID.String, d.PdfSha256)
	} else if d.EvidenceVersionPinsRequired {
		err = errors.New("document artifact is missing its required object VersionId")
	} else {
		body, _, err = client.ResolveVerifiedLegacyForSendV1(ctx, d.PdfStorageKey.String, d.PdfSha256)
	}
	if err != nil {
		return result, fmt.Errorf("verify PDF layout source: %w", err)
	}
	pages, err := sanitize.PageCountWithContext(ctx, body)
	if err != nil {
		return result, fmt.Errorf("inspect PDF layout pages: %w", err)
	}
	if pages < 1 || pages > sanitize.MaxPDFPages {
		return result, errors.New("source page count exceeds intake limit")
	}
	s.pages = pages
	s.inspected = true
	return result, nil
}
func (i *ApplicationPDFLayoutInspectionV1) borrowV1(org, document uuid.UUID) (*generated.Document, int, func(), error) {
	if i == nil || i.self != i || i.state == nil {
		return nil, 0, nil, ErrPDFLayoutInspectionV1
	}
	s := i.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closeRequested || !s.read || !s.inspected || s.source == nil || s.org != org || s.document != document || s.pages < 1 {
		return nil, 0, nil, ErrPDFLayoutInspectionV1
	}
	s.borrowers++
	var once sync.Once
	return s.source, s.pages, func() { once.Do(func() { s.mu.Lock(); s.borrowers--; s.releaseLockedV1(); s.mu.Unlock() }) }, nil
}
func (s *pdfLayoutInspectionStateV1) releaseLockedV1() {
	if !s.closeRequested || s.borrowers != 0 || s.closed {
		return
	}
	s.closed = true
	s.source = nil
	s.client = nil
	if s.reader != nil {
		s.reader.CloseConsumerV1()
		s.reader = nil
	}
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
func (i *ApplicationPDFLayoutInspectionV1) CloseConsumerV1() {
	if i == nil || i.self != i || i.state == nil {
		return
	}
	s := i.state
	s.mu.Lock()
	s.closeRequested = true
	s.releaseLockedV1()
	s.mu.Unlock()
}
