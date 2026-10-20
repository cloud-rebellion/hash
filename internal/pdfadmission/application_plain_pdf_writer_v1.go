// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
)

var ErrPlainPDFWriterV1 = errors.New("pdfadmission: owned plain PDF writer unavailable")

// This owner can only INSERT the private native session's new document ID.
// It never adopts a caller Document or measures a historical uncached row.
// All loans precede SQL/copy/RETURNING and remain until real application last
// use AND the original native client/backend retirement fence has joined.
// This is logical bounded working-set accounting, not measured heap or RSS.
type ApplicationPlainPDFCreationWriterV1 struct {
	state *applicationPlainPDFCreationStateV1
}
type applicationPlainPDFCreationStateV1 struct {
	mu                                                         sync.Mutex
	session                                                    *ApplicationSessionV1
	reader                                                     *ApplicationHTMLAuthoringReaderV1
	queries                                                    *generated.Queries
	closes                                                     []func()
	doc                                                        *generated.Document
	created, reportWritten, variablesWritten, measured, closed bool
	reportWire, variablesWire                                  int64
}

func (h *ApplicationSessionV1) NewPlainPDFCreationWriterV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*ApplicationPlainPDFCreationWriterV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrPlainPDFWriterV1
	}
	// Positive owner/handle/slice/typed-record credit exists even before the
	// first real input. This uses the same private native retained-body grant.
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, 2*int64(unsafe.Sizeof(applicationPlainPDFCreationStateV1{}))+2*int64(unsafe.Sizeof(ApplicationPlainPDFCreationWriterV1{})), 0)
	if err != nil {
		return nil, errors.Join(ErrPlainPDFWriterV1, err)
	}
	s := &applicationPlainPDFCreationStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}, reportWire: 2, variablesWire: 2}
	return &ApplicationPlainPDFCreationWriterV1{state: s}, nil
}
func (s *applicationPlainPDFCreationStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.session != nil && s.session.state != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (s *applicationPlainPDFCreationStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return errors.Join(ErrPlainPDFWriterV1, err)
	}
	s.closes = append(s.closes, close)
	return nil
}
func (s *applicationPlainPDFCreationStateV1) acceptV1(doc *generated.Document) error {
	physical := s.session.state
	if doc == nil || doc.ID != physical.document || doc.OrgID != physical.org || doc.Status != "draft" || doc.SourceKind != "pdf" ||
		len(doc.HtmlSourceJson) != 0 || len(doc.HtmlCurrentSourceJson) != 0 || len(doc.BlocksJson) != 0 || !bytes.Equal(doc.Metadata, []byte("{}")) ||
		doc.HtmlCurrentMaterializationID.Valid || !applicationStampV1(doc.UpdatedAt) {
		return ErrPlainPDFWriterV1
	}
	s.doc = htmlRevisionCloneDocumentV1(doc)
	return nil
}
func (w *ApplicationPlainPDFCreationWriterV1) CreatePDFDocument(ctx context.Context, p generated.CreatePDFDocumentParams) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.created || p.OrgID != s.session.state.org || p.SenderID == uuid.Nil {
		return nil, ErrPlainPDFWriterV1
	}
	raw, err := htmlAuthoringSumV1(int64(len(p.Name)), int64(len(p.PdfStorageKey.String)), int64(len(p.PdfStorageVersionID.String)), int64(len(p.PdfSha256)), 2*int64(unsafe.Sizeof(generated.CreatePDFDocumentParams{})))
	if err != nil {
		return nil, err
	}
	// The actual INSERT supplies default variables/report/metadata, each literal{}.
	if err = s.holdV1(ctx, raw, 6); err != nil {
		return nil, err
	}
	doc, err := s.queries.CreateFreshPlainPDFDocumentV1(ctx, generated.CreateFreshPlainPDFDocumentV1Params{ID: s.session.state.document, OrgID: p.OrgID, TemplateID: p.TemplateID, Name: p.Name,
		PdfStorageKey: p.PdfStorageKey, PdfSha256: p.PdfSha256, PdfStorageVersionID: p.PdfStorageVersionID, EvidenceVersionPinsRequired: p.EvidenceVersionPinsRequired, SenderID: p.SenderID, ExpiresAt: p.ExpiresAt})
	if err != nil {
		return nil, err
	}
	if err = s.acceptV1(doc); err != nil {
		return nil, err
	}
	if !bytes.Equal(doc.VariablesJson, []byte("{}")) || !bytes.Equal(doc.MetadataRedactionReport, []byte("{}")) {
		return nil, ErrPlainPDFWriterV1
	}
	s.created = true
	return doc, nil
}
func (w *ApplicationPlainPDFCreationWriterV1) UpdateMetadataRedactionReport(ctx context.Context, p generated.UpdateMetadataRedactionReportParams) error {
	if w == nil || w.state == nil {
		return ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.reportWritten || s.measured || p.ID != s.session.state.document {
		return ErrPlainPDFWriterV1
	}
	wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, p.MetadataRedactionReport)
	if err != nil {
		return err
	}
	if err = s.holdV1(ctx, int64(len(p.MetadataRedactionReport)), wire); err != nil {
		return err
	}
	// This is the inspected/sanitized report actually supplied to this fresh
	// producer. Preserve its bytes and source provenance; never resanitize it.
	p.MetadataRedactionReport = bytes.Clone(p.MetadataRedactionReport)
	if err = s.queries.UpdateMetadataRedactionReport(ctx, p); err != nil {
		return err
	}
	// The new row is owned by this uncommitted INSERT, with every variable-width
	// input already retained above. Refresh only that row after report timestamp.
	doc, err := s.queries.GetDocument(ctx, generated.GetDocumentParams{ID: s.session.state.document, OrgID: s.session.state.org})
	if err != nil {
		return err
	}
	if err = s.acceptV1(doc); err != nil {
		return err
	}
	if int64(len(doc.MetadataRedactionReport)) > wire {
		return ErrPlainPDFWriterV1
	}
	s.reportWire = wire
	s.reportWritten = true
	return nil
}
func (w *ApplicationPlainPDFCreationWriterV1) FreezeVariablesV1(ctx context.Context, variables []byte) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.variablesWritten || s.measured || s.doc == nil {
		return nil, ErrPlainPDFWriterV1
	}
	wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, variables)
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(ctx, int64(len(variables)), wire); err != nil {
		return nil, err
	}
	doc, err := s.queries.FreezeDocumentVariables(ctx, generated.FreezeDocumentVariablesParams{ID: s.session.state.document, OrgID: s.session.state.org, VariablesJson: bytes.Clone(variables), ExpectedUpdatedAt: s.doc.UpdatedAt})
	if err != nil {
		return nil, err
	}
	if err = s.acceptV1(doc); err != nil {
		return nil, err
	}
	if int64(len(doc.VariablesJson)) > wire {
		return nil, ErrPlainPDFWriterV1
	}
	s.variablesWire = wire
	s.variablesWritten = true
	return doc, nil
}
func (w *ApplicationPlainPDFCreationWriterV1) SetRequiresSignatureV1(ctx context.Context, required bool) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured {
		return nil, ErrPlainPDFWriterV1
	}
	doc, err := s.queries.SetDocumentRequiresSignature(ctx, generated.SetDocumentRequiresSignatureParams{ID: s.session.state.document, OrgID: s.session.state.org, RequiresSignature: required})
	if err != nil {
		return nil, err
	}
	if err = s.acceptV1(doc); err != nil {
		return nil, err
	}
	return doc, nil
}
func (w *ApplicationPlainPDFCreationWriterV1) CurrentDocumentV1(ctx context.Context) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.doc == nil {
		return nil, ErrPlainPDFWriterV1
	}
	return htmlRevisionCloneDocumentV1(s.doc), nil
}
func (w *ApplicationPlainPDFCreationWriterV1) MeasureFreshPolicyV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured || s.doc == nil || s.reportWire < 1 || s.variablesWire < 1 {
		return ErrPlainPDFWriterV1
	}
	document, org := s.session.state.document, s.session.state.org
	m, err := s.queries.MeasureSignatureFitHTMLPolicyDocumentV1(ctx, generated.MeasureSignatureFitHTMLPolicyDocumentV1Params{DocumentID: document, OrgID: org})
	if err != nil {
		return err
	}
	if m == nil || m.DocumentID != document || m.OrgID != org || m.HtmlOriginWireBytes != 0 || m.HtmlCurrentWireBytes != 0 || m.VariablesWireBytes < 1 || m.VariablesWireBytes > s.variablesWire || m.MeasurementServerVersionNum < 1 {
		return ErrPlainPDFWriterV1
	}
	response, err := s.queries.MeasurePlainPDFCreationResponseV1(ctx, generated.MeasurePlainPDFCreationResponseV1Params{DocumentID: document, OrgID: org, ExpectedUpdatedAt: s.doc.UpdatedAt})
	if err != nil {
		return err
	}
	if response == nil || response.DocumentID != document || response.OrgID != org || response.BlocksWireBytes != 0 || response.MetadataWireBytes != 2 || response.MeasurementServerVersionNum != m.MeasurementServerVersionNum {
		return ErrPlainPDFWriterV1
	}
	report, err := s.queries.MeasureSignerDocumentReportV1(ctx, generated.MeasureSignerDocumentReportV1Params{DocumentID: document, OrgID: org})
	if err != nil {
		return err
	}
	if report == nil || report.DocumentID != document || report.OrgID != org || report.ReportWireBytes < 1 || report.ReportWireBytes > s.reportWire || report.MeasurementServerVersionNum != m.MeasurementServerVersionNum || !s.validV1(ctx) {
		return ErrPlainPDFWriterV1
	}
	s.measured = true
	return nil
}
func (w *ApplicationPlainPDFCreationWriterV1) NewFieldBatchV1(ctx context.Context, fields []generated.CreateDraftFieldParams) (pdflayout.FreshFieldBatchV1, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured {
		return nil, ErrPlainPDFWriterV1
	}
	return s.session.newPlainPDFFieldBatchV1(ctx, s.reader, fields)
}
func (w *ApplicationPlainPDFCreationWriterV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.doc = nil
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
