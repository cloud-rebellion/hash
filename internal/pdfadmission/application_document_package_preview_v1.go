// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Observations only: the original locked root and package derive every pin.
type DocumentPackagePreviewExpectedV1 struct {
	UpdatedAt  time.Time
	PackageID  uuid.UUID
	Generation int64
}
type DocumentPackagePreviewMetadataV1 struct {
	DocumentID, MemberDocumentID, PackageID uuid.UUID
	UpdatedAt                               time.Time
	Generation, PDFVersionID, PDFSHA256     string
	PDFBytes                                int64
	PDFPages                                int32
}
type applicationDocumentPackagePreviewPinV1 struct {
	org      uuid.UUID
	metadata DocumentPackagePreviewMetadataV1
	key      string
	sha      [32]byte
}
type applicationDocumentPackagePreviewStateV1 struct {
	expected                    DocumentPackagePreviewExpectedV1
	readers                     [2]*ApplicationHTMLRevisionReaderV1
	pin                         applicationDocumentPackagePreviewPinV1
	body                        []byte
	loan                        *workguard.GrantV1
	attempted, ready, delivered bool
}

// A distinct opaque purpose reuses the actual factory registry and joined
// native-stage/consumer retirement. It cannot run a selection or fixed writer.
type ApplicationDocumentPackagePreviewV1 struct {
	state *applicationDocumentPackageOperationStateV1
}
type DocumentPackagePreviewPolicyV1 func(context.Context, generated.DBTX, *ApplicationHTMLRevisionReaderV1) (func(context.Context) error, error)

func (f *ApplicationSessionFactoryV1) NewDocumentPackagePreviewV1(ctx context.Context, org, root, member, actor uuid.UUID, client *storage.Client, expected DocumentPackagePreviewExpectedV1) (*ApplicationDocumentPackagePreviewV1, error) {
	if root == uuid.Nil || member == uuid.Nil || root == member || expected.UpdatedAt.IsZero() || expected.PackageID == uuid.Nil || expected.Generation < 1 {
		return nil, ErrDocumentPackageInputV1
	}
	op, e := f.newDocumentPackageOperationV1(ctx, org, root, member, actor, client, &expected)
	if e != nil {
		return nil, e
	}
	return &ApplicationDocumentPackagePreviewV1{state: op.state}, nil
}
func (h *ApplicationDocumentPackagePreviewV1) CloseV1(cleanup context.Context) error {
	if h == nil {
		return nil
	}
	return (&ApplicationDocumentPackageOperationV1{state: h.state}).CloseV1(cleanup)
}
func (h *ApplicationDocumentPackagePreviewV1) CloseConsumerV1() {
	if h != nil {
		(&ApplicationDocumentPackageOperationV1{state: h.state}).CloseConsumerV1()
	}
}

// The real inventory supplies subject privacy fences, row/text bounds, package
// lock and immutable metadata. Only this native method sees the storage key.
func (r *ApplicationHTMLRevisionReaderV1) readDocumentPackagePreviewPinV1(call context.Context, member uuid.UUID, expected DocumentPackagePreviewExpectedV1) (out applicationDocumentPackagePreviewPinV1, failure error) {
	view, e := r.ReadDocumentPackageInventoryV1(call)
	if e != nil {
		return out, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(call) || r.snapshot == nil || r.snapshot.document == nil {
		return out, ErrDocumentPackageDraftV1
	}
	d := r.snapshot.document
	if view.DocumentID != d.ID || !view.UpdatedAt.Equal(expected.UpdatedAt) || view.PackageID != expected.PackageID.String() || view.Generation != strconv.FormatInt(expected.Generation, 10) {
		return out, ErrDocumentPackageSourceChangedV1
	}
	var selected *DocumentPackageInventoryMemberV1
	for i := range view.Members {
		if view.Members[i].DocumentID == member {
			selected = &view.Members[i]
			break
		}
	}
	if selected == nil {
		return out, ErrDocumentPackageSourceChangedV1
	}
	// Native singleton row+key+version/hash copies and wire overlap. Inventory
	// already counted/funded every member; no internal report is expanded here.
	close, e := r.authoring.acquireOwnedRetainedBodyV1(call, 65536, 16384)
	if e != nil {
		return out, e
	}
	r.closeConsumers = append(r.closeConsumers, close)
	row, e := r.queries.GetDocumentPackageAttachmentPreviewPinV1(call, generated.GetDocumentPackageAttachmentPreviewPinV1Params{PackageID: expected.PackageID, DocumentID: d.ID, OrgID: d.OrgID, ExpectedGeneration: expected.Generation, MemberDocumentID: member})
	if e != nil {
		return out, e
	}
	if row == nil || len(row.PdfKey) < 1 || len(row.PdfKey) > 1024 || row.PdfVersionID != selected.PDFVersionID || len(row.PdfSha256) != 32 || hex.EncodeToString(row.PdfSha256) != selected.PDFSHA256 || row.PdfBytes != selected.PDFBytes || row.PdfPages != selected.PDFPages {
		return out, ErrDocumentPackageDraftV1
	}
	out.org = d.OrgID
	copy(out.sha[:], row.PdfSha256)
	out.key = strings.Clone(row.PdfKey)
	out.metadata = DocumentPackagePreviewMetadataV1{DocumentID: d.ID, MemberDocumentID: member, PackageID: expected.PackageID, UpdatedAt: view.UpdatedAt, Generation: view.Generation, PDFVersionID: strings.Clone(row.PdfVersionID), PDFSHA256: selected.PDFSHA256, PDFBytes: row.PdfBytes, PDFPages: row.PdfPages}
	return out, call.Err()
}
func (s *applicationDocumentPackageOperationStateV1) previewStageV1(index int, policy DocumentPackagePreviewPolicyV1) (failure error) {
	session, e := s.openStageV1(index)
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(s.ctx), 5*time.Second)
		defer stop()
		failure = errors.Join(failure, s.closeStageSQLV1(index, cleanup))
	}()
	if e != nil {
		return e
	}
	stage := s.stageContextV1(index)
	return session.WithTxV1(stage, func(call context.Context, db generated.DBTX) error {
		reader, e := session.NewHTMLRevisionReaderV1(call)
		s.mu.Lock()
		s.preview.readers[index] = reader
		s.mu.Unlock()
		if e != nil {
			return e
		}
		recheck, e := policy(call, db, reader)
		if e != nil {
			return e
		}
		if recheck == nil {
			return ErrDocumentPackageOperationV1
		}
		pin, e := reader.readDocumentPackagePreviewPinV1(call, s.ids[1], s.preview.expected)
		if e != nil {
			return e
		}
		if pin.metadata.DocumentID != s.ids[0] || pin.metadata.MemberDocumentID != s.ids[1] || pin.org != s.org {
			return ErrDocumentPackageDraftV1
		}
		if index == 0 {
			s.preview.pin = pin
		} else if !reflect.DeepEqual(pin, s.preview.pin) {
			return ErrDocumentPackageSourceChangedV1
		}
		if e = recheck(call); e != nil {
			return e
		}
		return call.Err()
	})
}

// One original-context attempt. Physical initial SQL retirement precedes HEAD;
// fresh final native policy, exact selection and original credential follow GET.
// Preview proves stored byte identity, not malware clearance or Send consent.
func (h *ApplicationDocumentPackagePreviewV1) LoadV1(policy DocumentPackagePreviewPolicyV1) error {
	if h == nil || h.state == nil || policy == nil {
		return ErrDocumentPackageOperationV1
	}
	s := h.state
	if e := s.beginV1(); e != nil {
		return e
	}
	defer s.finishV1()
	s.mu.Lock()
	if !s.previewMode || s.preview.attempted {
		s.mu.Unlock()
		return ErrDocumentPackageOperationV1
	}
	s.preview.attempted = true
	s.mu.Unlock()
	if e := s.previewStageV1(0, policy); e != nil {
		return e
	}
	first := s.stages[0].session
	if first == nil || !first.RetiredV1() || first.CommitUnknownV1() {
		return ErrDocumentPackageOperationV1
	}
	c, e := s.coordinatorV1()
	if e != nil {
		return e
	}
	pin := s.preview.pin
	var observed *storage.PinnedPDFReadV1
	e = func() error {
		stream, e := c.TryAcquireV1(s.ctx, s.org, workguard.VectorV1{ProviderStreams: 1})
		if e != nil {
			return e
		}
		defer stream.Close()
		observed, e = s.client.ObservePinnedPDFV1(s.ctx, pin.key, pin.metadata.PDFVersionID, pin.sha[:])
		return e
	}()
	if e != nil {
		return errors.Join(ErrDocumentPackageMeasurementV1, e)
	}
	if observed.SizeV1() != pin.metadata.PDFBytes {
		return ErrDocumentPackageMeasurementV1
	}
	parent, e := observed.ParentReadWorkV1()
	if e != nil {
		return e
	}
	loan, e := c.TryAcquireV1(s.ctx, s.org, workguard.VectorV1{ParentBytes: parent})
	if e != nil {
		return e
	}
	s.preview.loan = loan
	e = func() error {
		stream, e := c.TryAcquireV1(s.ctx, s.org, workguard.VectorV1{ProviderStreams: 1})
		if e != nil {
			return e
		}
		defer stream.Close()
		s.preview.body, e = observed.ReadV1(s.ctx)
		return e
	}()
	if e != nil {
		return errors.Join(ErrDocumentPackageMeasurementV1, e)
	}
	if int64(len(s.preview.body)) != pin.metadata.PDFBytes {
		return ErrDocumentPackageMeasurementV1
	}
	if e = s.previewStageV1(1, policy); e != nil {
		return e
	}
	last := s.stages[1].session
	if last == nil || !last.RetiredV1() || last.CommitUnknownV1() {
		return ErrDocumentPackageOperationV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return ErrDocumentPackageOperationV1
	}
	s.preview.ready = true
	return nil
}

// The actual synchronous response callback borrows the same owner/body grant.
// Concurrent copied-shell close/cancel cannot refund an active HTTP write.
func (h *ApplicationDocumentPackagePreviewV1) WithPDFV1(fn func(DocumentPackagePreviewMetadataV1, []byte) error) error {
	if h == nil || h.state == nil || fn == nil {
		return ErrDocumentPackageOperationV1
	}
	s := h.state
	if e := s.beginV1(); e != nil {
		return e
	}
	defer s.finishV1()
	s.mu.Lock()
	if !s.previewMode || !s.preview.ready || s.preview.delivered {
		s.mu.Unlock()
		return ErrDocumentPackageOperationV1
	}
	s.preview.delivered = true
	metadata, body := s.preview.pin.metadata, s.preview.body
	s.mu.Unlock()
	return fn(metadata, body)
}
