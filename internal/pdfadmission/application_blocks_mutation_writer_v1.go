// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"sync"
	"unsafe"
)

type BlocksEditV1 func(*blocks.Tree, blocks.ConditionalSendAdmissionV1) error
type ApplicationBlocksMutationWriterV1 struct {
	state *applicationBlocksMutationStateV1
}
type applicationBlocksMutationStateV1 struct {
	mu                          sync.Mutex
	session                     *ApplicationSessionV1
	reader                      *ApplicationHTMLRevisionReaderV1
	snapshot                    *applicationHTMLRevisionSourceSnapshotV1
	sourceWork                  *applicationBlocksCreationStateV1
	release                     func()
	doc                         *generated.Document
	restoreTarget               *generated.DocumentVersion
	intermediate                [8]*generated.Document
	retainedRows                int
	sourceWritten               bool
	blocksWire, variablesWire   int64
	topCount                    int
	attempted, measured, closed bool
}

// The only source is this SAME genuine reader's private locked six-JSON body.
// A caller Document, UUID, missing cache or external transaction cannot be
// adopted. Both old and newly returned source remain charged until last use.
func (h *ApplicationSessionV1) NewBlocksMutationWriterV1(ctx context.Context, reader *ApplicationHTMLRevisionReaderV1) (*ApplicationBlocksMutationWriterV1, error) {
	return h.newBlocksMutationWriterV1(ctx, reader, false)
}
func (h *ApplicationSessionV1) newBlocksMutationWriterV1(ctx context.Context, reader *ApplicationHTMLRevisionReaderV1, allowPDF bool) (*ApplicationBlocksMutationWriterV1, error) {
	return h.newBlocksMutationWriterWithCRMV1(ctx, reader, allowPDF, false)
}
func (h *ApplicationSessionV1) newBlocksMutationWriterWithCRMV1(ctx context.Context, reader *ApplicationHTMLRevisionReaderV1, allowPDF, allowHTMLMapping bool) (*ApplicationBlocksMutationWriterV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h {
		return nil, ErrBlocksWriterV1
	}
	snapshot, release, err := reader.borrowHTMLRevisionSourceV1(ctx)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	old := snapshot.document
	htmlMapping := allowHTMLMapping && old != nil && len(old.HtmlSourceJson) > 0
	if old == nil || old.ID != h.state.document || old.OrgID != h.state.org || old.Status != "draft" || (!htmlMapping && ((old.SourceKind != "blocks" && (!allowPDF || old.SourceKind != "pdf")) || len(old.HtmlSourceJson) != 0 || len(old.HtmlCurrentSourceJson) != 0 || old.HtmlCurrentMaterializationID.Valid)) {
		return nil, ErrBlocksWriterV1
	}
	// The same fixed writer header also covers a historical restore's scalar
	// projection and target/snapshot DTOs before any version metadata query.
	close, err := reader.authoring.acquireOwnedRetainedBodyV1(ctx, 2*int64(unsafe.Sizeof(applicationBlocksMutationStateV1{}))+2*int64(unsafe.Sizeof(ApplicationBlocksMutationWriterV1{}))+2*int64(unsafe.Sizeof(applicationBlocksCreationStateV1{}))+2*int64(unsafe.Sizeof(ApplicationBlocksCreationWriterV1{}))+2*int64(unsafe.Sizeof(generated.HtmlCreationResponseSizesV1{}))+4*int64(unsafe.Sizeof(generated.DocumentVersion{}))+512, 0)
	if err != nil {
		return nil, err
	}
	work := &applicationBlocksCreationStateV1{session: h, reader: reader.authoring, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}}
	state := &applicationBlocksMutationStateV1{session: h, reader: reader, snapshot: snapshot, sourceWork: work, release: release}
	success = true
	return &ApplicationBlocksMutationWriterV1{state: state}, nil
}
func (s *applicationBlocksMutationStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.session != nil && s.reader != nil && s.reader.self == s.reader && s.reader.session == s.session && s.sourceWork != nil && s.sourceWork.validV1(ctx) && s.snapshot != nil && s.snapshot.owner == s.reader && s.snapshot.document != nil
}
func (w *ApplicationBlocksMutationWriterV1) EditTreeV1(ctx context.Context, edit BlocksEditV1) (*generated.Document, int, error) {
	if w == nil || w.state == nil || edit == nil {
		return nil, 0, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.attempted {
		return nil, 0, ErrBlocksWriterV1
	}
	s.attempted = true
	old := s.snapshot.document
	work := s.sourceWork
	rawWork, err := plainSendBlockLexicalWorkV1(ctx, old.BlocksJson)
	if err != nil {
		return nil, 0, err
	}
	if err = work.holdV1(ctx, rawWork, 0); err != nil {
		return nil, 0, err
	}
	work.processing = true
	defer func() { work.processing = false }()
	admission := blocksCreationDecimalAdmissionV1{state: work, ctx: ctx}
	tree, err := blocks.ParseTreeForAuthoringV1(ctx, old.BlocksJson, admission)
	if work.admissionFailure != nil {
		return nil, 0, work.admissionFailure
	}
	if err != nil {
		return nil, 0, fmt.Errorf("existing blocks_json invalid: %w", err)
	}
	if err = edit(tree, admission); err != nil {
		if work.admissionFailure != nil {
			return nil, 0, work.admissionFailure
		}
		return nil, 0, err
	}
	if err = blocks.ValidateForSendV1(tree, admission); err != nil {
		if work.admissionFailure != nil {
			return nil, 0, work.admissionFailure
		}
		return nil, 0, fmt.Errorf("post-edit validation: %w", err)
	}
	upper, err := blocksCanonicalOutputUpperV1(ctx, tree)
	if err != nil {
		return nil, 0, err
	}
	if err = work.holdV1(ctx, upper, upper); err != nil {
		return nil, 0, err
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, 0, err
	}
	bw, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, raw)
	if err != nil {
		return nil, 0, err
	}
	if err = work.holdV1(ctx, int64(len(raw)), bw); err != nil {
		return nil, 0, err
	}
	doc, err := work.queries.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: old.ID, OrgID: old.OrgID, BlocksJson: raw, VariablesJson: old.VariablesJson})
	if err != nil {
		return nil, 0, err
	}
	if doc == nil || !applicationStampV1(doc.UpdatedAt) || int64(len(doc.BlocksJson)) > bw {
		return nil, 0, ErrBlocksWriterV1
	}
	expected := *old
	expected.BlocksJson = doc.BlocksJson
	expected.UpdatedAt = doc.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&expected, doc) {
		return nil, 0, ErrBlocksWriterV1
	}
	s.doc = htmlRevisionCloneDocumentV1(doc)
	s.blocksWire = bw
	s.variablesWire = int64(len(old.VariablesJson))
	s.topCount = len(tree.Blocks)
	return doc, s.topCount, nil
}
func (w *ApplicationBlocksMutationWriterV1) MeasureFreshPolicyV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.attempted || s.doc == nil || s.measured {
		return ErrBlocksWriterV1
	}
	q := s.sourceWork.queries
	document, org := s.doc.ID, s.doc.OrgID
	m, err := q.MeasureSignatureFitHTMLPolicyDocumentV1(ctx, generated.MeasureSignatureFitHTMLPolicyDocumentV1Params{DocumentID: document, OrgID: org})
	if err != nil {
		return err
	}
	if m == nil || m.DocumentID != document || m.OrgID != org || m.HtmlOriginWireBytes != 0 || m.HtmlCurrentWireBytes != 0 || m.VariablesWireBytes != s.variablesWire || m.MeasurementServerVersionNum < 1 {
		return ErrBlocksWriterV1
	}
	response, err := q.MeasureNativeBlocksResponseV1(ctx, generated.MeasureNativeBlocksResponseV1Params{DocumentID: document, OrgID: org, ExpectedUpdatedAt: s.doc.UpdatedAt})
	if err != nil {
		return err
	}
	if response == nil || response.DocumentID != document || response.OrgID != org || response.BlocksWireBytes < 1 || response.BlocksWireBytes > s.blocksWire || response.MetadataWireBytes != int64(len(s.snapshot.document.Metadata)) || response.MeasurementServerVersionNum != m.MeasurementServerVersionNum {
		return ErrBlocksWriterV1
	}
	report, err := q.MeasureSignerDocumentReportV1(ctx, generated.MeasureSignerDocumentReportV1Params{DocumentID: document, OrgID: org})
	if err != nil {
		return err
	}
	if report == nil || report.DocumentID != document || report.OrgID != org || report.ReportWireBytes != int64(len(s.snapshot.document.MetadataRedactionReport)) || report.MeasurementServerVersionNum != m.MeasurementServerVersionNum {
		return ErrBlocksWriterV1
	}
	s.measured = true
	return nil
}
func (w *ApplicationBlocksMutationWriterV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.doc = nil
	s.restoreTarget = nil
	s.intermediate = [8]*generated.Document{}
	s.snapshot = nil
	work, release := s.sourceWork, s.release
	s.sourceWork = nil
	s.release = nil
	s.mu.Unlock()
	if work != nil {
		(&ApplicationBlocksCreationWriterV1{state: work}).CloseConsumerV1()
	}
	if release != nil {
		release()
	}
}
