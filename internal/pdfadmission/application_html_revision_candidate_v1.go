// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/jackc/pgx/v5/pgtype"
)

// Only the fixed renderer/worker/storage route supplies these actual output
// values. This tuple is DATA: it grants no provider provenance, actor, storage,
// review or SQL authority. Original manifest/report/identity checks still run.
// The parent source operation, exact declaration and original deadline cannot
// be supplied/replaced here.
type HTMLRevisionPDFOutputV1 struct {
	Key, VersionID               string
	SHA256                       []byte
	PageCount, PreviousPageCount int32
	MetadataRedactionReport      []byte
	Composition                  sanitize.PDFCompositionManifest
}
type ApplicationHTMLRevisionCandidateV1 struct {
	state *applicationHTMLRevisionCandidateV1
}
type applicationHTMLRevisionCandidateV1 struct {
	mu                   sync.Mutex
	self                 *applicationHTMLRevisionCandidateV1
	source               *applicationHTMLRevisionSourceOwnerV1
	document, check      *generated.Document
	input                htmlsource.Input
	sourceJSON, report   []byte
	validation           *htmlsource.RevisionValidationV1
	pages, previousPages int32
	summary              string
	active               int
	closed, retired      bool
}

func (c *applicationHTMLRevisionCandidateV1) beginV1() error {
	if c == nil || c.self != c {
		return ErrHTMLRevisionSourceV1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.retired || c.source == nil || !applicationContextV1(c.source.binding.ctx) {
		return ErrHTMLRevisionSourceV1
	}
	c.active++
	return nil
}
func (c *applicationHTMLRevisionCandidateV1) finishV1() {
	c.mu.Lock()
	c.active--
	source := c.retireLockedV1()
	c.mu.Unlock()
	if source != nil {
		source.finishV1()
	}
}
func (c *applicationHTMLRevisionCandidateV1) retireLockedV1() *applicationHTMLRevisionSourceOwnerV1 {
	if !c.closed || c.retired || c.active != 0 {
		return nil
	}
	c.retired = true
	c.document = nil
	c.check = nil
	c.input = htmlsource.Input{}
	c.sourceJSON = nil
	c.report = nil
	c.validation = nil
	return c.source
}
func (h *ApplicationHTMLRevisionCandidateV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	c := h.state
	c.mu.Lock()
	c.closed = true
	source := c.retireLockedV1()
	c.mu.Unlock()
	if source != nil {
		source.finishV1()
	}
}

// NewCandidateV1 executes the actual source.New producer under the same native
// source loan, then a DISTINCT exact immutable validation operation for the new
// PDF/input tuple. No original result or claimed SHA can validate the candidate.
func (h *ApplicationHTMLRevisionSourceV1) NewCandidateV1(pdf HTMLRevisionPDFOutputV1) (*ApplicationHTMLRevisionCandidateV1, error) {
	if h == nil || h.state == nil || h.state.purpose != htmlRevisionSourcePurposeV1 || h.state.operation == nil {
		return nil, ErrHTMLRevisionSourceV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			s.finishV1()
		}
	}()
	s.mu.Lock()
	if s.closed || s.processing || s.candidateAttempted || s.prepared == nil || !s.currentValidated {
		s.mu.Unlock()
		return nil, ErrHTMLRevisionSourceV1
	}
	s.candidateAttempted = true
	s.processing = true
	prepared := s.prepared
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.processing = false; s.mu.Unlock() }()
	if len(pdf.SHA256) != 32 || pdf.Key == "" || pdf.VersionID == "" || pdf.PageCount < 1 || pdf.PageCount > 500 || pdf.PreviousPageCount < 1 || pdf.PreviousPageCount > 500 {
		return nil, htmlmaterialization.ErrInvalid
	}
	parent := s.snapshot.document
	copies, err := htmlRevisionPreparedDocumentCloneV1(parent)
	if err != nil {
		return nil, err
	}
	inputCopies, err := htmlRevisionPreparedInputProjectionV1(prepared.input)
	if err != nil {
		return nil, err
	}
	for _, n := range []int64{int64(len(pdf.Key)), int64(len(pdf.VersionID)), int64(len(pdf.SHA256)), int64(len(pdf.MetadataRedactionReport)), inputCopies} {
		if !htmlRevisionRetentionAllocV1(&copies, n) {
			return nil, ErrHTMLRevisionSourceV1
		}
	}
	if err = s.holdV1(htmlRevisionSourceCandidateV1, 0, copies); err != nil {
		return nil, err
	}
	input := htmlRevisionCopyInputV1(prepared.input)
	candidate := htmlRevisionCloneDocumentV1(parent)
	candidate.PdfStorageKey = pgtype.Text{String: strings.Clone(pdf.Key), Valid: true}
	candidate.PdfStorageVersionID = pgtype.Text{String: strings.Clone(pdf.VersionID), Valid: true}
	candidate.PdfSha256 = bytes.Clone(pdf.SHA256)
	report := bytes.Clone(pdf.MetadataRedactionReport)
	// Price New's typed future Variables encoder/parser directly from actual
	// private Values; no existing VariablesJSON or fabricated origin flag is used.
	record, err := htmlRevisionTypedSourceEncodingForV1(s.binding.ctx, input, s.effectiveCanonical, pdf.Key, pdf.VersionID)
	if err != nil {
		return nil, err
	}
	scratch, retained, err := htmlRevisionRecordStageComponentsV1(s.effectiveRawMaster, input, record, s.effectiveOutput, max(s.effectiveRawScratch, s.effectiveCanonicalScratch))
	if err != nil {
		return nil, err
	}
	if !htmlInputAddV1(&scratch, record.sourceNewEncoderBytes, 1) || !htmlInputAddV1(&scratch, record.originValuesEncoderBytes, 1) {
		return nil, ErrHTMLRevisionSourceV1
	}
	// New produces one complete fresh source. PrepareAppend clones old/new
	// sources before its distinct builder; all are retained separately here.
	if !htmlInputAddV1(&retained, record.sourceJSONBytes, 3) || !htmlInputAddV1(&retained, int64(len(parent.HtmlSourceJson)), 1) ||
		!htmlInputAddV1(&retained, record.valuesJSONBytes, 2) {
		return nil, ErrHTMLRevisionSourceV1
	}
	if err = s.holdV1(htmlRevisionSourceCandidateV1, scratch, retained); err != nil {
		return nil, err
	}
	if s.effectiveRawMaster.SchemaVersion == 3 {
		input.SigningArtifact, err = s.validation.NewSigningArtifactV1(input.Values, input.Sections, pdf.Composition)
		if err != nil {
			return nil, err
		}
	}
	candidate.VariablesJson, err = json.Marshal(input.Values)
	if err != nil {
		return nil, err
	}
	raw, err := htmlsource.New(input, candidate)
	if err != nil {
		return nil, err
	}
	check, err := htmlmaterialization.PrepareAppendValidationV1(parent, candidate, htmlmaterialization.AppendInput{
		SourceJSON: raw, PageCount: pdf.PageCount, PreviousPageCount: pdf.PreviousPageCount, ActorID: s.operation.actor,
		Summary: strings.TrimSpace(s.operation.declaration.Summary), MetadataRedactionReport: report})
	if err != nil {
		return nil, err
	}
	initial, err := s.initialDocumentComponentsV1(check)
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(htmlRevisionSourceCandidateV1, 0, initial); err != nil {
		return nil, err
	}
	oldInput, oldMaster, oldOutput, oldScratch, oldCanonical, oldCanonicalScratch := s.effectiveInput, s.effectiveRawMaster, s.effectiveOutput, s.effectiveRawScratch, s.effectiveCanonical, s.effectiveCanonicalScratch
	validated, err := s.validateDocumentV1(check)
	s.effectiveInput, s.effectiveRawMaster, s.effectiveOutput, s.effectiveRawScratch, s.effectiveCanonical, s.effectiveCanonicalScratch = oldInput, oldMaster, oldOutput, oldScratch, oldCanonical, oldCanonicalScratch
	if err != nil {
		return nil, err
	}
	// Exact original Append no-op/optional addition checks use these separately
	// validated before/after inputs; the fixed route's earlier materialization
	// already preserved the same original addition rule. No new PDF tuple reuse.
	before, err := s.validation.MaterializationDigestV1()
	if err != nil {
		return nil, err
	}
	after, err := validated.MaterializationDigestV1()
	if err != nil {
		return nil, htmlmaterialization.ErrInvalid
	}
	if before == after && candidate.PdfStorageKey.String == parent.PdfStorageKey.String && candidate.PdfStorageVersionID.String == parent.PdfStorageVersionID.String {
		return nil, htmlmaterialization.ErrInvalid
	}
	if !applicationContextV1(s.binding.ctx) {
		return nil, ErrHTMLRevisionSourceV1
	}
	state := &applicationHTMLRevisionCandidateV1{source: s, document: candidate, check: check, input: input, sourceJSON: raw, report: report, validation: validated,
		pages: pdf.PageCount, previousPages: pdf.PreviousPageCount, summary: strings.TrimSpace(s.operation.declaration.Summary)}
	state.self = state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrHTMLRevisionSourceV1
	}
	s.candidate = state
	s.mu.Unlock()
	transferred = true
	return &ApplicationHTMLRevisionCandidateV1{state: state}, nil
}
