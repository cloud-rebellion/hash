// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/bright-interaction/hash/internal/templatepin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrBlocksWriterV1 = errors.New("pdfadmission: owned block document writer unavailable")

type BlocksCreationInputErrorV1 struct {
	Field string
	Cause error
}

func (e BlocksCreationInputErrorV1) Error() string { return e.Cause.Error() }
func (e BlocksCreationInputErrorV1) Unwrap() error { return e.Cause }

type ApplicationBlocksCreationWriterV1 struct {
	state *applicationBlocksCreationStateV1
}
type applicationBlocksCreationStateV1 struct {
	mu                                  sync.Mutex
	session                             *ApplicationSessionV1
	reader                              *ApplicationHTMLAuthoringReaderV1
	queries                             *generated.Queries
	closes                              []func()
	doc                                 *generated.Document
	blocks, variables                   []byte
	blocksWire, variablesWire           int64
	decimalPeak                         int64
	prepared, created, measured, closed bool
	consumerClosed                      bool
	borrowers                           int
	processing                          bool
	admissionFailure                    error
	template                            *generated.Template
	releaseTemplate                     func()
}

func (h *ApplicationSessionV1) NewBlocksCreationWriterV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*ApplicationBlocksCreationWriterV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrBlocksWriterV1
	}
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, 2*int64(unsafe.Sizeof(applicationBlocksCreationStateV1{}))+2*int64(unsafe.Sizeof(ApplicationBlocksCreationWriterV1{}))+2*int64(unsafe.Sizeof(generated.HtmlCreationResponseSizesV1{}))+2*int64(unsafe.Sizeof(generated.CreateFreshBlocksDocumentV1Params{}))+int64(unsafe.Sizeof(blocksCreationQuotaSourceReadsV1{})), 0)
	if err != nil {
		return nil, errors.Join(ErrBlocksWriterV1, err)
	}
	s := &applicationBlocksCreationStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}}
	return &ApplicationBlocksCreationWriterV1{state: s}, nil
}
func (s *applicationBlocksCreationStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && !s.consumerClosed && s.session != nil && s.session.state != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (s *applicationBlocksCreationStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return errors.Join(ErrBlocksWriterV1, err)
	}
	s.closes = append(s.closes, close)
	return nil
}

// Concrete canonical output envelope. The original validator has already
// checked attribute types and total tree limits. It does not Marshal, recurse
// through arbitrary JSON, impose new input limits, or assign document authority.
func blocksCanonicalOutputUpperV1(ctx context.Context, tree *blocks.Tree) (int64, error) {
	total := int64(64)
	text := func(value string) bool {
		return htmlInputAddV1(&total, int64(len(value)), 6) && htmlInputAddV1(&total, 1, 8)
	}
	var walk func([]blocks.Block) error
	walk = func(items []blocks.Block) error {
		for i := range items {
			if err := ctx.Err(); err != nil {
				return err
			}
			b := &items[i]
			if !htmlInputAddV1(&total, 1, 160) || !text(b.ID) || !text(string(b.Type)) || !text(b.Text) {
				return ErrBlocksWriterV1
			}
			for name, value := range b.Attrs {
				if !text(name) {
					return ErrBlocksWriterV1
				}
				switch v := value.(type) {
				case string:
					if !text(v) {
						return ErrBlocksWriterV1
					}
				case bool:
					if !htmlInputAddV1(&total, 1, 8) {
						return ErrBlocksWriterV1
					}
				case float64:
					if math.IsNaN(v) || math.IsInf(v, 0) || !htmlInputAddV1(&total, 1, 32) {
						return ErrBlocksWriterV1
					}
				case int:
					if !htmlInputAddV1(&total, 1, 32) {
						return ErrBlocksWriterV1
					}
				case []any:
					if !htmlInputAddV1(&total, 1, 8) {
						return ErrBlocksWriterV1
					}
					for _, cell := range v {
						str, ok := cell.(string)
						if !ok || !text(str) {
							return ErrBlocksWriterV1
						}
					}
				default:
					return ErrBlocksWriterV1
				}
			}
			for _, row := range b.Rows {
				if !htmlInputAddV1(&total, 1, 8) {
					return ErrBlocksWriterV1
				}
				for _, cell := range row {
					if !text(cell) {
						return ErrBlocksWriterV1
					}
				}
			}
			if err := walk(b.Content); err != nil {
				return err
			}
		}
		return nil
	}
	if tree == nil {
		return 0, ErrBlocksWriterV1
	}
	if err := walk(tree.Blocks); err != nil {
		return 0, err
	}
	return total, nil
}

type blocksCreationDecimalAdmissionV1 struct {
	state *applicationBlocksCreationStateV1
	ctx   context.Context
}

func (a blocksCreationDecimalAdmissionV1) BeforeDecimalV1(value string) (failure error) {
	s := a.state
	defer func() {
		if failure != nil && s != nil {
			s.admissionFailure = failure
		}
	}()
	if s == nil || !s.processing || !s.validV1(a.ctx) {
		return ErrBlocksWriterV1
	}
	b, err := blocks.DecimalLogicalBoundForSendV1(value)
	if err != nil {
		return err
	}
	bits := int64(0)
	for _, n := range []int64{b.MantissaBits, b.PowerFiveBits, b.NumeratorBits, b.DenominatorBits} {
		if !htmlInputAddV1(&bits, n, 1) {
			return ErrBlocksWriterV1
		}
	}
	words := bits / 64
	if bits%64 != 0 {
		words++
	}
	cost := int64(0)
	if !htmlInputAddV1(&cost, words, 64*8) || !htmlInputAddV1(&cost, b.SourceBytes, 8) || !htmlInputAddV1(&cost, 1, 32*int64(unsafe.Sizeof(big.Int{}))+8*int64(unsafe.Sizeof(big.Rat{}))) {
		return ErrBlocksWriterV1
	}
	// Retain only additional increasing logical expression credit. Prior loans
	// remain continuously owned until this source's true last use and native
	// retirement. This never releases credit on cancellation or inferred GC.
	if cost > s.decimalPeak {
		if err = s.holdV1(a.ctx, cost-s.decimalPeak, 0); err != nil {
			return err
		}
		s.decimalPeak = cost
	}
	return nil
}

// This is the original no-template ResolveDocumentSeed block path at its
// original position before author authorization. It retains actual request
// bytes and funds the unchanged typed decoder/validator BEFORE either runs.
func (w *ApplicationBlocksCreationWriterV1) PrepareSourceV1(ctx context.Context, blockTree, variables json.RawMessage) error {
	if w == nil || w.state == nil {
		return ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.prepared || s.created {
		return ErrBlocksWriterV1
	}
	if len(blockTree) == 0 && s.template != nil {
		blockTree = s.template.BlocksJson
	}
	if len(variables) == 0 && s.template != nil {
		variables = s.template.VariablesJson
	}
	if len(blockTree) == 0 {
		blockTree = json.RawMessage("{\"version\":1,\"blocks\":[]}")
	}
	if len(variables) == 0 {
		variables = json.RawMessage("{}")
	}
	rawWork, err := plainSendBlockLexicalWorkV1(ctx, blockTree)
	if err != nil {
		return err
	}
	varsWork, err := plainSendBlockLexicalWorkV1(ctx, variables)
	if err != nil {
		return err
	}
	if !htmlInputAddV1(&rawWork, varsWork, 4) {
		return ErrBlocksWriterV1
	}
	if err = s.holdV1(ctx, rawWork, 0); err != nil {
		return err
	}
	s.processing = true
	defer func() { s.processing = false }()
	normalized, err := blocks.NormalizeTreeForAuthoringV1(ctx, blockTree, blocksCreationDecimalAdmissionV1{s, ctx}, func(tree *blocks.Tree) error {
		upper, e := blocksCanonicalOutputUpperV1(ctx, tree)
		if e != nil {
			return e
		}
		// Canonical output contains only the original validated attribute grammar;
		// its JSON strings need at most6 bytes per source byte. JSONB textual space
		// can add no more than one extra byte per canonical output byte.
		if upper > math.MaxInt64/2 {
			return ErrBlocksWriterV1
		}
		return s.holdV1(ctx, upper, 2*upper)
	})
	if s.admissionFailure != nil {
		return s.admissionFailure
	}
	if err != nil {
		return BlocksCreationInputErrorV1{Field: "blocks_json", Cause: err}
	}
	// Preserve original string-variable grammar and error wrappers in the fixed
	// shared producer. This parser does not evaluate unresolved contract values.
	if _, err = blocks.ParseVariableValues(variables); err != nil {
		return BlocksCreationInputErrorV1{Field: "variables_json", Cause: err}
	}
	bw, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, normalized)
	if err != nil {
		return err
	}
	vw, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, variables)
	if err != nil {
		return err
	}
	total, err := htmlAuthoringSumV1(int64(len(normalized)), int64(len(variables)))
	if err != nil {
		return err
	}
	wire, err := htmlAuthoringSumV1(bw, vw)
	if err != nil {
		return err
	}
	if err = s.holdV1(ctx, total, wire); err != nil {
		return err
	}
	s.blocks = bytes.Clone(normalized)
	s.variables = bytes.Clone(variables)
	s.blocksWire = bw
	s.variablesWire = vw
	s.prepared = true
	return nil
}
func (w *ApplicationBlocksCreationWriterV1) CreateBlocksDocument(ctx context.Context, p generated.CreateBlocksDocumentParams) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.prepared || s.created || p.OrgID != s.session.state.org || p.SenderID == uuid.Nil {
		return nil, ErrBlocksWriterV1
	}
	expectedTemplate := pgtype.UUID{}
	if s.template != nil {
		expectedTemplate = pgtype.UUID{Bytes: s.template.ID, Valid: true}
	}
	if p.TemplateID != expectedTemplate {
		return nil, ErrBlocksWriterV1
	}
	if err := s.holdV1(ctx, int64(len(p.Name))+2*int64(unsafe.Sizeof(generated.CreateBlocksDocumentParams{})), 4); err != nil {
		return nil, err
	}
	doc, err := s.queries.CreateFreshBlocksDocumentV1(ctx, generated.CreateFreshBlocksDocumentV1Params{ID: s.session.state.document, OrgID: p.OrgID, TemplateID: p.TemplateID, Name: p.Name, BlocksJson: s.blocks, VariablesJson: s.variables, SenderID: p.SenderID, ExpiresAt: p.ExpiresAt})
	if err != nil {
		return nil, err
	}
	if doc == nil || doc.ID != s.session.state.document || doc.OrgID != s.session.state.org || doc.SourceKind != "blocks" || doc.Status != "draft" || doc.TemplateID != expectedTemplate || len(doc.HtmlSourceJson) != 0 || len(doc.HtmlCurrentSourceJson) != 0 || doc.HtmlCurrentMaterializationID.Valid || !bytes.Equal(doc.Metadata, []byte("{}")) || !bytes.Equal(doc.MetadataRedactionReport, []byte("{}")) || int64(len(doc.BlocksJson)) > s.blocksWire || int64(len(doc.VariablesJson)) > s.variablesWire || !applicationStampV1(doc.UpdatedAt) {
		return nil, ErrBlocksWriterV1
	}
	s.doc = htmlRevisionCloneDocumentV1(doc)
	s.created = true
	return doc, nil
}
func (w *ApplicationBlocksCreationWriterV1) MeasureFreshPolicyV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured || s.doc == nil {
		return ErrBlocksWriterV1
	}
	document, org := s.session.state.document, s.session.state.org
	m, err := s.queries.MeasureSignatureFitHTMLPolicyDocumentV1(ctx, generated.MeasureSignatureFitHTMLPolicyDocumentV1Params{DocumentID: document, OrgID: org})
	if err != nil {
		return err
	}
	if m == nil || m.DocumentID != document || m.OrgID != org || m.HtmlOriginWireBytes != 0 || m.HtmlCurrentWireBytes != 0 || m.VariablesWireBytes < 1 || m.VariablesWireBytes > s.variablesWire || m.MeasurementServerVersionNum < 1 {
		return ErrBlocksWriterV1
	}
	response, err := s.queries.MeasureNativeBlocksResponseV1(ctx, generated.MeasureNativeBlocksResponseV1Params{DocumentID: document, OrgID: org, ExpectedUpdatedAt: s.doc.UpdatedAt})
	if err != nil {
		return err
	}
	if response == nil || response.DocumentID != document || response.OrgID != org || response.BlocksWireBytes < 1 || response.BlocksWireBytes > s.blocksWire || response.MetadataWireBytes != 2 || response.MeasurementServerVersionNum != m.MeasurementServerVersionNum {
		return ErrBlocksWriterV1
	}
	report, err := s.queries.MeasureSignerDocumentReportV1(ctx, generated.MeasureSignerDocumentReportV1Params{DocumentID: document, OrgID: org})
	if err != nil {
		return err
	}
	if report == nil || report.DocumentID != document || report.OrgID != org || report.ReportWireBytes != 2 || report.MeasurementServerVersionNum != m.MeasurementServerVersionNum || !s.validV1(ctx) {
		return ErrBlocksWriterV1
	}
	s.measured = true
	return nil
}
func (s *applicationBlocksCreationStateV1) releaseIfCompleteV1() {
	if s.closed || !s.consumerClosed || s.borrowers != 0 {
		return
	}
	s.closed = true
	s.doc = nil
	s.blocks = nil
	s.variables = nil
	s.template = nil
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
	if s.releaseTemplate != nil {
		s.releaseTemplate()
		s.releaseTemplate = nil
	}
}
func (w *ApplicationBlocksCreationWriterV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consumerClosed = true
	s.releaseIfCompleteV1()
}

// Only a genuine same-session measured fresh INSERT can lend a private source
// to the fixed automation recipient producer. No caller Document/ID is adopted.
func (s *applicationBlocksCreationStateV1) borrowFreshV1(ctx context.Context, session *ApplicationSessionV1, reader *ApplicationHTMLAuthoringReaderV1) (*generated.Document, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.session != session || s.reader != reader || !s.created || !s.measured || s.doc == nil {
		return nil, nil, ErrBlocksWriterV1
	}
	s.borrowers++
	doc := s.doc
	var once sync.Once
	release := func() { once.Do(func() { s.mu.Lock(); s.borrowers--; s.releaseIfCompleteV1(); s.mu.Unlock() }) }
	return doc, release, nil
}

// Only the actual same-session protected block-template source can bind this
// producer's referenced identity/defaults. Public Template/UUID/size values do
// not become source authority; its real reader borrower joins at writer close.
func (w *ApplicationBlocksCreationWriterV1) BindTemplateV1(ctx context.Context, source *ApplicationBlocksTemplateSourceV1) error {
	if w == nil || w.state == nil || source == nil || source.state == nil {
		return ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.prepared || s.created || s.template != nil {
		return ErrBlocksWriterV1
	}
	tpl, release, err := source.state.borrowV1(ctx, s.session, s.reader)
	if err != nil {
		return err
	}
	s.template = tpl
	s.releaseTemplate = release
	return nil
}

// The same concrete block-source work owner prices the original persisted-ID
// commitment parser and marshal. It confers no document/template write identity.
func (s *applicationBlocksCreationStateV1) canonicalContentV1(ctx context.Context, tpl *generated.Template) (templatepin.Content, error) {
	if s == nil {
		return templatepin.Content{}, ErrBlocksWriterV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.processing || tpl == nil || tpl.SourceKind != "blocks" {
		return templatepin.Content{}, ErrBlocksWriterV1
	}
	raw, err := plainSendBlockLexicalWorkV1(ctx, tpl.BlocksJson)
	if err != nil {
		return templatepin.Content{}, err
	}
	variables, err := plainSendBlockLexicalWorkV1(ctx, tpl.VariablesJson)
	if err != nil {
		return templatepin.Content{}, err
	}
	if !htmlInputAddV1(&raw, variables, 1) {
		return templatepin.Content{}, ErrBlocksWriterV1
	}
	if err = s.holdV1(ctx, raw, 0); err != nil {
		return templatepin.Content{}, err
	}
	// This is a second real parse after preparation; prior loans remain held.
	s.decimalPeak = 0
	s.processing = true
	defer func() { s.processing = false }()
	content, err := templatepin.CanonicalizeWithAdmissionV1(ctx, tpl.BlocksJson, tpl.VariablesJson, blocksCreationDecimalAdmissionV1{s, ctx}, func(tree *blocks.Tree) error {
		upper, e := blocksCanonicalOutputUpperV1(ctx, tree)
		if e != nil {
			return e
		}
		if !htmlInputAddV1(&upper, int64(len(tpl.VariablesJson)), 6) || !htmlInputAddV1(&upper, 1, 2*int64(unsafe.Sizeof(templatepin.Content{}))+128) {
			return ErrBlocksWriterV1
		}
		return s.holdV1(ctx, upper, 0)
	})
	if s.admissionFailure != nil {
		return templatepin.Content{}, s.admissionFailure
	}
	return content, err
}
