// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"math/big"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var ErrPDFTemplateDocumentV1 = errors.New("pdfadmission: owned PDF template document unavailable")

type PDFTemplateDocumentInputV1 struct {
	Name, TemplateText, Via, Tool string
	Variables                     []byte
	ExpiresAt                     pgtype.Timestamptz
	ExpectedTemplateVersion       *int32
	Parties                       []pdflayout.Binding
}
type ApplicationPDFTemplateDocumentV1 struct {
	state *applicationPDFTemplateDocumentStateV1
}
type applicationPDFTemplateDocumentStateV1 struct {
	mu                                                                                                       sync.Mutex
	session                                                                                                  *ApplicationSessionV1
	reader                                                                                                   *ApplicationHTMLAuthoringReaderV1
	source                                                                                                   *ApplicationPDFTemplateSourceV1
	sourcePin                                                                                                *generated.Template
	writer                                                                                                   *ApplicationPlainPDFCreationWriterV1
	queries                                                                                                  *generated.Queries
	closes                                                                                                   []func()
	input                                                                                                    PDFTemplateDocumentInputV1
	user                                                                                                     uuid.UUID
	variables, report                                                                                        []byte
	layout                                                                                                   *pdflayout.Layout
	values                                                                                                   []recipients.Values
	recipientIDs, fieldIDs                                                                                   []uuid.UUID
	roleIDs                                                                                                  map[string]uuid.UUID
	nextRecipient, nextField, auditNext, quotaAppliedRecipient                                               int
	seeded, prepared, created, quotaApplied, recipientFunded, fieldsFunded, measured, consumerClosed, closed bool
	fields                                                                                                   *ApplicationPlainPDFFieldBatchV1
	audits                                                                                                   *applicationPDFLayoutAuditBatchV1
	quota                                                                                                    *pdfTemplateDocumentQuotaReadsV1
}

func (h *ApplicationSessionV1) NewPDFTemplateDocumentV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1, source *ApplicationPDFTemplateSourceV1, user uuid.UUID, input PDFTemplateDocumentInputV1) (*ApplicationPDFTemplateDocumentV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) || source == nil || source.state == nil || user == uuid.Nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	p := source.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.validV1(ctx) || p.session != h || p.reader != reader || p.template == nil || p.template.SourceKind != "pdf" || p.template.OrgID != h.state.org {
		return nil, ErrPDFTemplateDocumentV1
	}
	if !p.template.PdfStorageKey.Valid || p.template.PdfStorageKey.String == "" {
		return nil, fmt.Errorf("%w: template has no PDF source", authoring.ErrCreationInput)
	}
	observed, err := uuid.Parse(input.TemplateText)
	if err != nil || observed != p.template.ID || (input.Via != "rest" && input.Via != "mcp") || (input.Via == "rest" && input.Tool != "") || (input.Via == "mcp" && input.Tool != "create_document") {
		return nil, ErrPDFTemplateDocumentV1
	}
	raw, err := htmlAuthoringSumV1(2*int64(unsafe.Sizeof(applicationPDFTemplateDocumentStateV1{})), 2*int64(unsafe.Sizeof(applicationPDFLayoutAuditBatchV1{})), 2*8*int64(unsafe.Sizeof("")+unsafe.Sizeof(any(nil))), 2*int64(unsafe.Sizeof(ApplicationPDFTemplateDocumentV1{})), 2*int64(unsafe.Sizeof(PDFTemplateDocumentInputV1{})), 2*16*int64(unsafe.Sizeof((func())(nil))), int64(len(input.Name)+len(input.TemplateText)+len(input.Via)+len(input.Tool)+len(input.Variables)), 2*int64(len(input.Parties))*int64(unsafe.Sizeof(pdflayout.Binding{})), 2*int64(unsafe.Sizeof(sanitize.Report{})), 2*int64(unsafe.Sizeof(pdfTemplateDocumentQuotaReadsV1{})), int64(len("template-pdfapplication/pdflegacy-templatelegacy-unknown")))
	if err != nil {
		return nil, err
	}
	for _, binding := range input.Parties {
		raw, err = htmlAuthoringSumV1(raw, int64(len(binding.Role)+len(binding.Name)+len(binding.Email)+len(binding.Locale)))
		if err != nil {
			return nil, err
		}
	}
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, err
	}
	s := &applicationPDFTemplateDocumentStateV1{session: h, reader: reader, source: source, sourcePin: p.template, user: user, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}, input: input}
	s.input.Name = strings.Clone(input.Name)
	s.input.TemplateText = strings.Clone(input.TemplateText)
	s.input.Via = strings.Clone(input.Via)
	s.input.Tool = strings.Clone(input.Tool)
	s.input.Variables = bytes.Clone(input.Variables)
	s.input.Parties = make([]pdflayout.Binding, len(input.Parties))
	for i, b := range input.Parties {
		b.Role = strings.Clone(b.Role)
		b.Name = strings.Clone(b.Name)
		b.Email = strings.Clone(b.Email)
		b.Locale = strings.Clone(b.Locale)
		s.input.Parties[i] = b
	}
	if input.ExpectedTemplateVersion != nil {
		version := *input.ExpectedTemplateVersion
		s.input.ExpectedTemplateVersion = &version
	}
	return &ApplicationPDFTemplateDocumentV1{state: s}, nil
}
func (s *applicationPDFTemplateDocumentStateV1) validV1(ctx context.Context) bool {
	if s == nil || s.consumerClosed || s.closed || s.session == nil || s.session.state == nil || s.reader == nil || s.reader.session != s.session || !s.reader.valid(ctx) || s.source == nil || s.source.state == nil || s.sourcePin == nil || s.queries == nil {
		return false
	}
	p := s.source.state
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.validV1(ctx) && p.session == s.session && p.template == s.sourcePin
}
func (s *applicationPDFTemplateDocumentStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, close)
	return nil
}

// The original two maps can decode invalid keys before validation. Empty JSON
// key syntax alone uses two bytes; twice that slot ceiling funds actual Swiss
// string/RawMessage and string/string groups, headers and controls BEFORE the
// ORIGINAL parser. It introduces no declaration/count/depth limit or grammar.
func pdfTemplateVariablesInputRawV1(size int64) (int64, error) {
	if size < 0 {
		return 0, ErrPDFTemplateDocumentV1
	}
	entries := size/2 + 1
	needed := int64(0)
	if !htmlInputAddV1(&needed, entries, 8) || !htmlInputAddV1(&needed, 1, 6) {
		return 0, ErrPDFTemplateDocumentV1
	}
	slots := htmlInputPowerV1(max(8, needed/7))
	total := int64(0)
	if !htmlInputAddV1(&total, slots, 2*(80+1)) || !htmlInputAddV1(&total, 2, 2*16*256) || !htmlInputAddV1(&total, 1, size) {
		return 0, ErrPDFTemplateDocumentV1
	}
	return total, nil
}
func (w *ApplicationPDFTemplateDocumentV1) SeedVariablesV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrPDFTemplateDocumentV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.seeded {
		return ErrPDFTemplateDocumentV1
	}
	variables := s.input.Variables
	if len(variables) == 0 {
		variables = s.sourcePin.VariablesJson
	}
	if len(variables) == 0 {
		variables = []byte("{}")
	}
	raw, err := pdfTemplateVariablesInputRawV1(int64(len(variables)))
	if err != nil {
		return err
	}
	wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, variables)
	if err != nil {
		return err
	}
	if err = s.holdV1(ctx, raw, wire); err != nil {
		return err
	}
	if _, err = blocks.ParseVariableValues(variables); err != nil {
		return fmt.Errorf("%w: invalid variables_json: %v", authoring.ErrCreationInput, err)
	}
	s.variables = bytes.Clone(variables)
	s.seeded = true
	return nil
}
func (w *ApplicationPDFTemplateDocumentV1) PrepareSigningV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrPDFTemplateDocumentV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.seeded || s.prepared {
		return ErrPDFTemplateDocumentV1
	}
	raw, err := pdfLayoutParseInputRawV1(int64(len(s.sourcePin.FieldsJson)))
	if err != nil {
		return err
	}
	raw, err = htmlAuthoringSumV1(raw, int64(len(s.sourcePin.PdfSanitizationReport)), 2*int64(unsafe.Sizeof(sanitize.Report{})), int64(pdflayout.MaxParties)*(int64(unsafe.Sizeof(recipients.Values{}))+int64(unsafe.Sizeof(uuid.UUID{}))), int64(pdflayout.MaxFields)*int64(unsafe.Sizeof(uuid.UUID{})))
	if err != nil {
		return err
	}
	sourceWire := int64(len(s.sourcePin.FieldsJson) + len(s.sourcePin.PdfSanitizationReport))
	if err = s.holdV1(ctx, raw, sourceWire); err != nil {
		return err
	}
	s.report, err = authoring.PDFTemplateDocumentReport(s.sourcePin)
	if err != nil {
		return err
	}
	s.layout, s.values, err = pdflayout.Prepare(s.sourcePin, s.input.ExpectedTemplateVersion, s.input.Parties)
	if err != nil {
		return err
	}
	s.recipientIDs = make([]uuid.UUID, len(s.values))
	fieldCount := 0
	if s.layout != nil {
		fieldCount = len(s.layout.Fields)
	}
	s.fieldIDs = make([]uuid.UUID, fieldCount)
	s.writer, err = s.session.NewPlainPDFCreationWriterV1(ctx, s.reader)
	if err != nil {
		return err
	}
	s.prepared = true
	s.audits, err = newPDFLayoutAuditBatchV1(ctx, s)
	return err
}
func (w *ApplicationPDFTemplateDocumentV1) CreateDocumentV1(ctx context.Context) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.prepared || s.created || s.writer == nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	t := s.sourcePin
	doc, err := s.writer.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{OrgID: s.session.state.org, TemplateID: pgtype.UUID{Bytes: t.ID, Valid: true}, Name: s.input.Name, PdfStorageKey: t.PdfStorageKey, PdfSha256: t.PdfSha256, PdfStorageVersionID: t.PdfStorageVersionID, EvidenceVersionPinsRequired: t.EvidenceVersionPinRequired, SenderID: s.user, ExpiresAt: s.input.ExpiresAt})
	if err != nil {
		return nil, err
	}
	if doc == nil || doc.SenderID != s.user || doc.TemplateID != (pgtype.UUID{Bytes: t.ID, Valid: true}) || doc.PdfStorageKey != t.PdfStorageKey || doc.PdfStorageVersionID != t.PdfStorageVersionID || doc.EvidenceVersionPinsRequired != t.EvidenceVersionPinRequired || !bytes.Equal(doc.PdfSha256, t.PdfSha256) {
		return nil, ErrPDFTemplateDocumentV1
	}
	if err = s.writer.UpdateMetadataRedactionReport(ctx, generated.UpdateMetadataRedactionReportParams{ID: doc.ID, MetadataRedactionReport: s.report}); err != nil {
		return nil, err
	}
	doc, err = s.writer.FreezeVariablesV1(ctx, s.variables)
	if err != nil {
		return nil, err
	}
	s.created = true
	return doc, nil
}
func (s *applicationPDFTemplateDocumentStateV1) fundRecipientsV1(ctx context.Context) error {
	if s.recipientFunded {
		return nil
	}
	raw := 2 * int64(len(s.values)) * (int64(unsafe.Sizeof(generated.CreateRecipientParams{})) + int64(unsafe.Sizeof(generated.Recipient{})) + int64(unsafe.Sizeof(uuid.UUID{})) + 32 + int64(len("pending")))
	for _, v := range s.values {
		var err error
		raw, err = htmlAuthoringSumV1(raw, int64(len(v.Email)+len(v.Name)+len(v.Role)+len(v.Locale)))
		if err != nil {
			return err
		}
	}
	slots := htmlInputPowerV1(max(8, (int64(len(s.values))*8+6)/7))
	if !htmlInputAddV1(&raw, slots, 2*(64+1)) || !htmlInputAddV1(&raw, 1, 2*16*256) {
		return ErrPDFTemplateDocumentV1
	}
	if err := s.holdV1(ctx, raw, 0); err != nil {
		return err
	}
	s.roleIDs = make(map[string]uuid.UUID, len(s.values))
	s.recipientFunded = true
	return nil
}
func (w *ApplicationPDFTemplateDocumentV1) NextRecipientV1(ctx context.Context) (*generated.Recipient, error) {
	if w == nil || w.state == nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || !s.quotaApplied || s.quotaAppliedRecipient != s.nextRecipient || s.nextRecipient >= len(s.values) || s.auditNext != s.nextRecipient {
		return nil, ErrPDFTemplateDocumentV1
	}
	if err := s.fundRecipientsV1(ctx); err != nil {
		return nil, err
	}
	value := s.values[s.nextRecipient]
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		return nil, fmt.Errorf("mint layout recipient: %w", err)
	}
	doc := s.writer.state.doc
	row, err := s.queries.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: s.session.state.document, Role: value.Role, Name: value.Name, Email: value.Email, Locale: value.Locale, OrderIndex: value.OrderIndex, MagicTokenHash: hash, MagicTokenExpiresAt: magictoken.Expiry(doc.ExpiresAt, time.Now())})
	if err != nil {
		return nil, fmt.Errorf("create layout recipient: %w", err)
	}
	if row == nil || row.ID == uuid.Nil || row.DocumentID != s.session.state.document || row.Role != value.Role || row.Name != value.Name || row.Email != value.Email || row.Locale != value.Locale || row.OrderIndex != value.OrderIndex || row.Status != "pending" || !bytes.Equal(row.MagicTokenHash, hash) {
		return nil, ErrPDFTemplateDocumentV1
	}
	s.recipientIDs[s.nextRecipient] = row.ID
	s.roleIDs[value.Role] = row.ID
	s.nextRecipient++
	return row, nil
}
func (s *applicationPDFTemplateDocumentStateV1) fundFieldsV1(ctx context.Context) error {
	if s.fieldsFunded {
		return nil
	}
	if s.layout == nil || len(s.layout.Fields) == 0 {
		return ErrPDFTemplateDocumentV1
	}
	raw := 2 * int64(len(s.layout.Fields)) * (int64(unsafe.Sizeof(generated.CreateDraftFieldParams{})) + int64(unsafe.Sizeof(generated.DocumentField{})) + 4*(int64(unsafe.Sizeof(big.Int{}))+int64(unsafe.Sizeof(big.Word(0)))))
	for _, f := range s.layout.Fields {
		var err error
		raw, err = htmlAuthoringSumV1(raw, int64(len(f.Label)+len(f.PartyRole)+len("signature{}")))
		if err != nil {
			return err
		}
	}
	if err := s.holdV1(ctx, raw, 2*int64(len(s.layout.Fields))); err != nil {
		return err
	}
	parameters := make([]generated.CreateDraftFieldParams, len(s.layout.Fields))
	for i, field := range s.layout.Fields {
		recipient, ok := s.roleIDs[field.PartyRole]
		if !ok || recipient == uuid.Nil {
			return ErrPDFTemplateDocumentV1
		}
		parameters[i] = pdflayout.MaterializationFieldParamsV1(s.session.state.document, s.session.state.org, recipient, field)
	}
	var err error
	s.fields, err = s.session.newPlainPDFFieldBatchV1(ctx, s.reader, parameters)
	if err != nil {
		return err
	}
	s.fieldsFunded = true
	return nil
}
func (w *ApplicationPDFTemplateDocumentV1) NextFieldV1(ctx context.Context) (*generated.DocumentField, error) {
	if w == nil || w.state == nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.nextRecipient != len(s.values) || s.auditNext != len(s.values)+s.nextField || s.nextField >= len(s.fieldIDs) || !s.quotaApplied || s.quotaAppliedRecipient != s.nextRecipient {
		return nil, ErrPDFTemplateDocumentV1
	}
	if err := s.fundFieldsV1(ctx); err != nil {
		return nil, err
	}
	row, err := s.fields.CreateNextV1(ctx)
	if err != nil {
		return nil, fmt.Errorf("create layout field: %w", err)
	}
	field := s.layout.Fields[s.nextField]
	if row == nil || row.ID == uuid.Nil || row.DocumentID != s.session.state.document || !row.RecipientID.Valid || uuid.UUID(row.RecipientID.Bytes) != s.roleIDs[field.PartyRole] || row.Type != "signature" || !row.Required || row.Page != field.Page {
		return nil, ErrPDFTemplateDocumentV1
	}
	s.fieldIDs[s.nextField] = row.ID
	s.nextField++
	return row, nil
}
func (w *ApplicationPDFTemplateDocumentV1) MeasureFreshSourceV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrPDFTemplateDocumentV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured || s.nextRecipient != len(s.values) || s.nextField != len(s.fieldIDs) || s.auditNext != len(s.values)+len(s.fieldIDs) || !s.quotaApplied || s.quotaAppliedRecipient != s.nextRecipient {
		return ErrPDFTemplateDocumentV1
	}
	if err := s.writer.MeasureFreshPolicyV1(ctx); err != nil {
		return err
	}
	s.measured = true
	return nil
}
func (w *ApplicationPDFTemplateDocumentV1) CountsV1(ctx context.Context) (int, int, error) {
	if w == nil || w.state == nil {
		return 0, 0, ErrPDFTemplateDocumentV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.prepared {
		return 0, 0, ErrPDFTemplateDocumentV1
	}
	return len(s.values), len(s.fieldIDs), nil
}
func (w *ApplicationPDFTemplateDocumentV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	if s.consumerClosed {
		s.mu.Unlock()
		return
	}
	s.consumerClosed = true
	batch := s.audits
	s.mu.Unlock()
	if batch != nil {
		batch.closeConsumerV1()
	} else {
		s.releaseConsumerSourceV1()
	}
}
func (s *applicationPDFTemplateDocumentStateV1) releaseConsumerSourceV1() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.sourcePin = nil
	s.variables = nil
	s.report = nil
	s.layout = nil
	s.values = nil
	s.recipientIDs = nil
	s.fieldIDs = nil
	s.roleIDs = nil
	s.input = PDFTemplateDocumentInputV1{}
	if s.fields != nil {
		s.fields.CloseConsumerV1()
		s.fields = nil
	}
	if s.writer != nil {
		s.writer.CloseConsumerV1()
		s.writer = nil
	}
	if s.source != nil {
		s.source.CloseConsumerV1()
		s.source = nil
	}
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
