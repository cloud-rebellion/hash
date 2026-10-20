// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"math/big"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var ErrPDFLayoutCaptureV1 = errors.New("pdfadmission: owned PDF layout capture unavailable")
var ErrPDFLayoutSourceChangedV1 = errors.New("document or PDF source changed; review the current design")

type ApplicationPDFLayoutCaptureV1 struct {
	self  *ApplicationPDFLayoutCaptureV1
	state *pdfLayoutCaptureStateV1
}
type pdfLayoutCaptureStateV1 struct {
	mu                                                                  sync.Mutex
	session                                                             *ApplicationSessionV1
	reader                                                              *ApplicationHTMLRevisionReaderV1
	source                                                              *applicationHTMLRevisionSourceSnapshotV1
	releaseSource                                                       func()
	inspection                                                          *ApplicationPDFLayoutInspectionV1
	releaseInspection                                                   func()
	queries                                                             *generated.Queries
	input                                                               pdflayout.ExportInputV1
	user                                                                uuid.UUID
	pages                                                               int
	closes                                                              []func()
	layout                                                              *pdflayout.Layout
	writer                                                              *ApplicationPDFTemplateCreationV1
	template                                                            *generated.Template
	auditOwner                                                          *ApplicationHTMLAuditEventConsumerV1
	prepared, written, auditStarted, auditAlive, consumerClosed, closed bool
}

// Same actual native reader and genuine independent pre-inspection source. The
// future template identity is private/new and cannot authorize an existing row.
func (h *ApplicationSessionV1) NewPDFLayoutCaptureV1(ctx context.Context, reader *ApplicationHTMLRevisionReaderV1, inspection *ApplicationPDFLayoutInspectionV1, user uuid.UUID, input pdflayout.ExportInputV1) (*ApplicationPDFLayoutCaptureV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || inspection == nil || inspection.self != inspection || inspection.state == nil || inspection.state.factory == nil || inspection.state.factory.state != h.state.factory || user == uuid.Nil {
		return nil, ErrPDFLayoutCaptureV1
	}
	snapshot, release, err := reader.borrowHTMLRevisionSourceV1(ctx)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			release()
		}
	}()
	if snapshot == nil || snapshot.document == nil {
		return nil, ErrPDFLayoutCaptureV1
	}
	current := snapshot.document
	old, pages, releaseInspection, err := inspection.borrowV1(h.state.org, h.state.document)
	if err != nil {
		return nil, err
	}
	keepInspection := false
	defer func() {
		if !keepInspection {
			releaseInspection()
		}
	}()
	if len(current.HtmlSourceJson) > 0 {
		return nil, ErrPDFLayoutHTMLSourceV1
	}
	expected, err := time.Parse(time.RFC3339Nano, input.ExpectedUpdatedAt)
	if err != nil || !pdflayout.SamePDFTemplateSourceV1(old, current) || !current.UpdatedAt.Valid || !current.UpdatedAt.Time.Equal(expected) || !old.UpdatedAt.Time.Equal(expected) {
		return nil, ErrPDFLayoutSourceChangedV1
	}
	raw, err := htmlAuthoringSumV1(2*int64(unsafe.Sizeof(pdfLayoutCaptureStateV1{})), 2*int64(unsafe.Sizeof(ApplicationPDFLayoutCaptureV1{})), 2*int64(unsafe.Sizeof(generated.GetHTMLSendCollectionReadHeaderV1Row{})), 2*int64(unsafe.Sizeof(generated.LockHTMLSendCollectionRowsV1Row{})), 2*int64(unsafe.Sizeof(generated.VerifyHTMLSendCollectionReadHeaderV1Row{})), 2*int64(unsafe.Sizeof(pdflayout.ExportInputV1{})), 2*6*int64(unsafe.Sizeof("")+unsafe.Sizeof(any(nil))), 2*int64(len(input.ExpectedFieldIDs))*int64(unsafe.Sizeof(uuid.UUID{})), 2*int64(len(input.Parties))*int64(unsafe.Sizeof(pdflayout.ExportPartyV1{})), int64(len(input.Name)+len(input.ExpectedUpdatedAt)), 16*int64(unsafe.Sizeof((func())(nil))))
	if err != nil {
		return nil, err
	}
	for _, party := range input.Parties {
		raw, err = htmlAuthoringSumV1(raw, int64(len(party.Role)+len(party.Label)))
		if err != nil {
			return nil, err
		}
	}
	close, err := reader.authoring.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, err
	}
	s := &pdfLayoutCaptureStateV1{session: h, reader: reader, source: snapshot, releaseSource: release, inspection: inspection, releaseInspection: releaseInspection, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), input: input, user: user, pages: pages, closes: []func(){close}}
	s.input.Name = strings.Clone(input.Name)
	s.input.ExpectedUpdatedAt = strings.Clone(input.ExpectedUpdatedAt)
	s.input.ExpectedFieldIDs = append([]uuid.UUID(nil), input.ExpectedFieldIDs...)
	s.input.Parties = make([]pdflayout.ExportPartyV1, len(input.Parties))
	for i, party := range input.Parties {
		party.Role = strings.Clone(party.Role)
		party.Label = strings.Clone(party.Label)
		s.input.Parties[i] = party
	}
	out := &ApplicationPDFLayoutCaptureV1{state: s}
	out.self = out
	keep = true
	keepInspection = true
	return out, nil
}
func (s *pdfLayoutCaptureStateV1) validV1(ctx context.Context) bool {
	if s == nil || s.closed || s.consumerClosed || s.session == nil || s.reader == nil || s.source == nil || s.source.document == nil || s.queries == nil {
		return false
	}
	s.reader.mu.Lock()
	defer s.reader.mu.Unlock()
	return s.reader.session == s.session && s.reader.valid(ctx) && s.reader.snapshot == s.source
}
func (s *pdfLayoutCaptureStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.authoring.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, close)
	return nil
}

// Four original finite UUID-key maps. Slot/directory/control storage is
// prepriced from actual complete counts before the original export kernel.
// This fixed input inventory creates no parser/grammar/count policy.
func pdfLayoutExportMapRawV1(count, key, value int64) (int64, error) {
	needed := int64(0)
	if count < 0 || !htmlInputAddV1(&needed, count, 8) || !htmlInputAddV1(&needed, 1, 6) {
		return 0, ErrPDFLayoutCaptureV1
	}
	slots := htmlInputPowerV1(max(8, needed/7))
	raw := int64(0)
	if !htmlInputAddV1(&raw, slots, 2*(key+value+16)) || !htmlInputAddV1(&raw, 1, 2*16*256) {
		return 0, ErrPDFLayoutCaptureV1
	}
	return raw, nil
}
func (s *pdfLayoutCaptureStateV1) fundCollectionV1(ctx context.Context, h *generated.GetHTMLSendCollectionReadHeaderV1Row) error {
	if h == nil {
		return ErrPDFLayoutCaptureV1
	}
	raw, err := htmlAuthoringSumV1(h.RecipientRawBytes, h.FieldRawBytes, h.BindingRawBytes, 2*int64(unsafe.Sizeof(pdflayout.Layout{})))
	if err != nil {
		return err
	}
	// Existing complete collection model/pin/NUMERIC(7,4) inventory. No input
	// or old-row body is substituted for the observed native scalar contract.
	for _, part := range [][2]int64{{h.RecipientCount, 4 * (int64(unsafe.Sizeof(generated.Recipient{})) + 16)}, {h.FieldCount, 4 * (int64(unsafe.Sizeof(generated.DocumentField{})) + 16)}, {h.BindingCount, 4 * (int64(unsafe.Sizeof(generated.DocumentVariableBinding{})) + 16)}, {h.FieldCount, 8 * 4 * (int64(unsafe.Sizeof(big.Int{})) + 16)}, {h.FieldCount, 2 * int64(unsafe.Sizeof(pdflayout.Field{}))}, {int64(len(s.input.Parties)), 2 * int64(unsafe.Sizeof(pdflayout.Party{}))}} {
		if !htmlInputAddV1(&raw, part[0], part[1]) {
			return ErrPDFLayoutCaptureV1
		}
	}
	for _, m := range [][3]int64{{int64(len(s.input.ExpectedFieldIDs)), 16, 1}, {h.RecipientCount, 16, int64(unsafe.Sizeof((*generated.Recipient)(nil)))}, {int64(len(s.input.Parties)), 16, int64(unsafe.Sizeof(pdflayout.ExportPartyV1{}))}, {int64(len(s.input.Parties)), 16, 1}} {
		n, err := pdfLayoutExportMapRawV1(m[0], m[1], m[2])
		if err != nil {
			return err
		}
		raw, err = htmlAuthoringSumV1(raw, n)
		if err != nil {
			return err
		}
	}
	wire := h.FieldOptionsWireBytes
	for _, count := range [...]int64{h.RecipientCount, h.FieldCount, h.BindingCount} {
		if !htmlInputAddV1(&wire, count, 64) {
			return ErrPDFLayoutCaptureV1
		}
	}
	return s.holdV1(ctx, raw, wire)
}
func (h *ApplicationPDFLayoutCaptureV1) CreateTemplateV1(ctx context.Context) (*generated.Template, error) {
	if h == nil || h.self != h || h.state == nil {
		return nil, ErrPDFLayoutCaptureV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.prepared {
		return nil, ErrPDFLayoutCaptureV1
	}
	s.prepared = true
	org, doc := s.session.state.org, s.session.state.document
	header, err := s.queries.GetHTMLSendCollectionReadHeaderV1(ctx, generated.GetHTMLSendCollectionReadHeaderV1Params{DocumentID: doc, OrgID: org})
	if err != nil {
		return nil, err
	}
	if header == nil || header.DocumentID != doc || header.OrgID != org || header.ServerVersionNum <= 0 || header.FieldMissingSizeCount < 0 || header.FieldMissingSizeCount > header.FieldCount {
		return nil, ErrPDFLayoutCaptureV1
	}
	if err = s.fundCollectionV1(ctx, header); err != nil {
		return nil, err
	}
	pins, err := s.queries.LockHTMLSendCollectionRowsV1(ctx, generated.LockHTMLSendCollectionRowsV1Params{DocumentID: doc, OrgID: org})
	if err != nil {
		return nil, err
	}
	if pins == nil || pins.DocumentID != doc || pins.OrgID != org || pins.RecipientCount != header.RecipientCount || pins.FieldCount != header.FieldCount || pins.FieldCacheCount != header.FieldCount-header.FieldMissingSizeCount || pins.BindingCount != header.BindingCount {
		return nil, ErrPDFLayoutCaptureV1
	}
	fresh, err := s.queries.GetHTMLSendCollectionReadHeaderV1(ctx, generated.GetHTMLSendCollectionReadHeaderV1Params{DocumentID: doc, OrgID: org})
	if err != nil {
		return nil, err
	}
	if fresh == nil || *fresh != *header {
		return nil, ErrPDFLayoutCaptureV1
	}
	recipients, err := s.queries.ListHTMLSendRecipientsV1(ctx, generated.ListHTMLSendRecipientsV1Params{DocumentID: doc, OrgID: org, ExpectedCount: header.RecipientCount, ExpectedRawBytes: header.RecipientRawBytes})
	if err != nil {
		return nil, err
	}
	if int64(len(recipients)) != header.RecipientCount {
		return nil, ErrPDFLayoutCaptureV1
	}
	raw := int64(0)
	for _, recipient := range recipients {
		if recipient == nil || recipient.DocumentID != doc || recipient.ID == uuid.Nil {
			return nil, ErrPDFLayoutCaptureV1
		}
		n, err := htmlAuthoringSumV1(int64(len(recipient.Role) + len(recipient.Name) + len(recipient.Email) + len(recipient.Status) + len(recipient.Locale) + len(recipient.DeclinedReason.String) + len(recipient.MagicTokenHash)))
		if err != nil || !htmlInputAddV1(&raw, n, 1) {
			return nil, ErrPDFLayoutCaptureV1
		}
	}
	if raw != header.RecipientRawBytes {
		return nil, ErrPDFLayoutCaptureV1
	}
	if header.FieldMissingSizeCount != 0 || header.FieldMeasurementServerMismatchCount != 0 {
		return nil, ErrPDFLayoutCaptureV1
	}
	fields, err := s.queries.ListHTMLSendFieldsV1(ctx, generated.ListHTMLSendFieldsV1Params{DocumentID: doc, OrgID: org, ExpectedCount: header.FieldCount, ExpectedRawBytes: header.FieldRawBytes, ExpectedOptionsWireBytes: header.FieldOptionsWireBytes})
	if err != nil {
		return nil, err
	}
	if int64(len(fields)) != header.FieldCount {
		return nil, ErrPDFLayoutCaptureV1
	}
	raw, wire := int64(0), int64(0)
	for _, field := range fields {
		if field == nil || field.ID == uuid.Nil || field.DocumentID != doc {
			return nil, ErrPDFLayoutCaptureV1
		}
		n, err := htmlAuthoringSumV1(int64(len(field.Type) + len(field.Label.String) + len(field.Value.String)))
		if err != nil || !htmlInputAddV1(&raw, n, 1) || !htmlInputAddV1(&wire, int64(len(field.OptionsJson)), 1) {
			return nil, ErrPDFLayoutCaptureV1
		}
	}
	if raw != header.FieldRawBytes || wire != header.FieldOptionsWireBytes {
		return nil, ErrPDFLayoutCaptureV1
	}
	s.layout, err = pdflayout.ExportDocumentLayoutV1(s.source.document, recipients, fields, s.input, int32(s.pages))
	if err != nil {
		return nil, err
	}
	// Actual valid canonical source funds original Marshal BEFORE allocation.
	// Fixed key/number punctuation and real UTF8 string escape bounds are finite.
	canonicalWire := int64(64)
	for _, party := range s.layout.Parties {
		if !htmlInputAddV1(&canonicalWire, 1, 64) || !htmlInputAddV1(&canonicalWire, int64(len(party.Role)+len(party.Label)), 6) {
			return nil, ErrPDFLayoutCaptureV1
		}
	}
	for _, field := range s.layout.Fields {
		if !htmlInputAddV1(&canonicalWire, 1, 384) || !htmlInputAddV1(&canonicalWire, int64(len(field.PartyRole)+len(field.Type)+len(field.Label)), 6) {
			return nil, ErrPDFLayoutCaptureV1
		}
	}
	if err = s.holdV1(ctx, 0, canonicalWire); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(s.layout)
	if err != nil {
		return nil, err
	}
	measured, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, canonical)
	if err != nil || measured > canonicalWire {
		return nil, ErrPDFLayoutCaptureV1
	}
	s.writer, err = s.session.NewPDFTemplateCreationV1(ctx, s.reader.authoring)
	if err != nil {
		return nil, err
	}
	s.writer.state.mu.Lock()
	s.writer.state.templateIdentity = uuid.New()
	s.writer.state.mu.Unlock()
	current := s.source.document
	row, err := s.writer.CreatePDFTemplateV1(ctx, generated.CreatePDFTemplateParams{OrgID: org, Name: strings.TrimSpace(s.input.Name), CreatedBy: s.user, PdfStorageKey: current.PdfStorageKey, PdfSha256: current.PdfSha256, PdfStorageVersionID: current.PdfStorageVersionID, EvidenceVersionPinRequired: current.EvidenceVersionPinsRequired, PageCount: pgtype.Int4{Int32: int32(s.pages), Valid: true}, FieldsJson: canonical})
	if err != nil {
		return nil, err
	}
	if row == nil || row.CreatedBy != s.user || row.PdfStorageKey != current.PdfStorageKey || row.PdfStorageVersionID != current.PdfStorageVersionID || row.EvidenceVersionPinRequired != current.EvidenceVersionPinsRequired || !bytes.Equal(row.PdfSha256, current.PdfSha256) || len(row.PdfSanitizationReport) != 0 {
		return nil, ErrPDFLayoutCaptureV1
	}
	if err = s.writer.MeasureFreshSourceV1(ctx); err != nil {
		return nil, err
	}
	s.template = s.writer.state.template
	s.written = true
	return row, nil
}
func (h *ApplicationPDFLayoutCaptureV1) NewAuditV1(ctx context.Context) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if h == nil || h.self != h || h.state == nil {
		return nil, ErrPDFLayoutCaptureV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.written || s.auditStarted || s.template == nil || s.layout == nil {
		return nil, ErrPDFLayoutCaptureV1
	}
	s.auditStarted = true
	payload := map[string]any{"template_id": s.template.ID, "source_kind": "pdf", "name": s.template.Name, "layout_version": s.layout.Version, "party_count": len(s.layout.Parties), "field_count": len(s.layout.Fields)}
	owner, err := s.session.NewHTMLAuditEventV1(ctx, HTMLAuditPDFLayoutTemplateCreatedV1, s.session.state.org, s.session.state.document, pgtype.UUID{}, pgtype.UUID{Bytes: s.user, Valid: true}, HTMLAuditPDFLayoutTemplateCreatedV1.KindV1(), "", "", payload)
	if err != nil {
		return nil, err
	}
	s.auditOwner = owner
	s.auditAlive = true
	originalClose := owner.closeConsumer
	owner.closeConsumer = func() { originalClose(); s.mu.Lock(); s.auditAlive = false; s.releaseLockedV1(); s.mu.Unlock() }
	return owner, nil
}
func (s *pdfLayoutCaptureStateV1) releaseLockedV1() {
	if !s.consumerClosed || s.closed || s.auditAlive {
		return
	}
	s.closed = true
	s.source = nil
	s.template = nil
	s.layout = nil
	s.input = pdflayout.ExportInputV1{}
	s.auditOwner = nil
	if s.writer != nil {
		s.writer.CloseConsumerV1()
		s.writer = nil
	}
	if s.releaseSource != nil {
		s.releaseSource()
		s.releaseSource = nil
	}
	if s.releaseInspection != nil {
		s.releaseInspection()
		s.releaseInspection = nil
	}
	if s.inspection != nil {
		s.inspection.CloseConsumerV1()
		s.inspection = nil
	}
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
	s.reader = nil
	s.session = nil
	s.queries = nil
}
func (h *ApplicationPDFLayoutCaptureV1) CloseConsumerV1() {
	if h == nil || h.self != h || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	s.consumerClosed = true
	owner := s.auditOwner
	s.mu.Unlock()
	if owner != nil {
		owner.CloseConsumerV1()
	}
	s.mu.Lock()
	s.releaseLockedV1()
	s.mu.Unlock()
}

// Existing reader's actual locked body/actor machinery with deferred current:
// original static-export HTML refusal follows the unchanged draft guard policy.
func (r *ApplicationHTMLRevisionReaderV1) ReadPDFLayoutDocumentWithActorV1(ctx context.Context, user uuid.UUID, preflight func(HTMLRevisionReadAccessV1) error, gate func(HTMLRevisionReadAccessV1, *generated.User) error) (*HTMLRevisionReadModelsV1, error) {
	if gate == nil {
		return nil, ErrHTMLRevisionReadV1
	}
	return r.readDocumentBodyModeV1(ctx, user, preflight, gate, false, true)
}
