// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
	"time"
	"unsafe"
)

// Existing-source PDF fields mutation: only a genuine same-session M97 update
// pin enters this writer. It never adopts a caller Template or repairs a read.
type ApplicationPDFTemplateFieldsMutationV1 struct {
	state *applicationPDFTemplateFieldsMutationStateV1
}
type applicationPDFTemplateFieldsMutationStateV1 struct {
	mu                                                                                  sync.Mutex
	session                                                                             *ApplicationSessionV1
	source                                                                              *ApplicationPDFTemplateSourceV1
	sourcePin                                                                           *generated.Template
	reader                                                                              *ApplicationHTMLAuthoringReaderV1
	queries                                                                             *generated.Queries
	closes                                                                              []func()
	template                                                                            *generated.Template
	mutated, measured, auditStarted, published, publicationDone, consumerClosed, closed bool
	pending                                                                             audit.PendingEvent
}

func (h *ApplicationSessionV1) NewPDFTemplateFieldsMutationV1(ctx context.Context, source *ApplicationPDFTemplateSourceV1) (*ApplicationPDFTemplateFieldsMutationV1, error) {
	if h == nil || h.state == nil || source == nil || source.state == nil {
		return nil, ErrPDFTemplateSourceV1
	}
	p := source.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.validV1(ctx) || p.session != h || !p.updateLocked || p.template == nil || p.template.ID != h.state.document || p.template.OrgID != h.state.org || p.template.SourceKind != "pdf" {
		return nil, ErrPDFTemplateSourceV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationPDFTemplateFieldsMutationStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationPDFTemplateFieldsMutationV1{})) + 2*int64(unsafe.Sizeof(generated.Template{})) + int64(unsafe.Sizeof(generated.UpdatePDFTemplateFieldsParams{})) + int64(unsafe.Sizeof(generated.PdfTemplateSourceSizesV1{})) + int64(unsafe.Sizeof(generated.GetPDFTemplateSourceHeaderForUpdateV1Row{}))
	close, err := p.reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, err
	}
	return &ApplicationPDFTemplateFieldsMutationV1{state: &applicationPDFTemplateFieldsMutationStateV1{session: h, source: source, sourcePin: p.template, reader: p.reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}, template: plainPDFCloneTemplateV1(p.template)}}, nil
}
func (s *applicationPDFTemplateFieldsMutationStateV1) validV1(ctx context.Context) bool {
	if s == nil || s.consumerClosed || s.closed || s.session == nil || s.session.state == nil || s.reader == nil || s.reader.session != s.session || !s.reader.valid(ctx) || s.queries == nil || s.template == nil || s.source == nil || s.source.state == nil || s.sourcePin == nil {
		return false
	}
	p := s.source.state
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.validV1(ctx) && p.session == s.session && p.updateLocked && p.template == s.sourcePin
}
func (s *applicationPDFTemplateFieldsMutationStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, close)
	return nil
}

// The original decoder can temporarily decode invalid arrays before its same
// 100/1000 validation. Each party/field object requires at least two input bytes;
// slice growth is below twice that many concrete Field+Party records. This finite
// original-type inventory pays before the ORIGINAL parser/normalizer, with no
// grammar replacement, count/depth change or generic allocation framework.
func pdfLayoutParseInputRawV1(size int64) (int64, error) {
	if size < 0 {
		return 0, ErrPDFTemplateSourceV1
	}
	objects := size/2 + 1
	records, err := htmlAuthoringSumV1(int64(unsafe.Sizeof(pdflayout.Field{})), int64(unsafe.Sizeof(pdflayout.Party{})))
	if err != nil {
		return 0, err
	}
	total := int64(0)
	if !htmlInputAddV1(&total, 2*objects, records) || !htmlInputAddV1(&total, 1, size) || !htmlInputAddV1(&total, 2, int64(unsafe.Sizeof(pdflayout.Layout{}))) {
		return 0, ErrPDFTemplateSourceV1
	}
	return total, nil
}
func (h *ApplicationPDFTemplateFieldsMutationV1) UpdateFieldsV1(ctx context.Context, input []byte) (*generated.Template, error) {
	if h == nil || h.state == nil {
		return nil, ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.mutated {
		return nil, ErrPDFTemplateSourceV1
	}
	fields := s.template.FieldsJson
	if len(input) > 0 {
		raw, err := pdfLayoutParseInputRawV1(int64(len(input)))
		if err != nil {
			return nil, err
		}
		wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, input)
		if err != nil {
			return nil, err
		}
		if err = s.holdV1(ctx, raw, wire); err != nil {
			return nil, err
		}
		fields, err = pdflayout.CanonicalForUpdate(input, s.template.PageCount.Int32)
		if err != nil {
			return nil, err
		}
	}
	wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, fields)
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(ctx, int64(len(fields)), wire); err != nil {
		return nil, err
	}
	before := s.template
	s.mutated = true
	row, err := s.queries.UpdatePDFTemplateFields(ctx, generated.UpdatePDFTemplateFieldsParams{ID: before.ID, OrgID: before.OrgID, FieldsJson: bytes.Clone(fields)})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != before.ID || row.OrgID != before.OrgID || row.SourceKind != "pdf" || row.Version != before.Version+1 || !applicationStampV1(row.UpdatedAt) || row.CreatedAt != before.CreatedAt || row.Name != before.Name || row.CreatedBy != before.CreatedBy || row.ArchivedAt != before.ArchivedAt || row.PageCount != before.PageCount || row.PdfStorageKey != before.PdfStorageKey || row.PdfStorageVersionID != before.PdfStorageVersionID || row.EvidenceVersionPinRequired != before.EvidenceVersionPinRequired || !bytes.Equal(row.PdfSha256, before.PdfSha256) || !bytes.Equal(row.HtmlMasterJson, before.HtmlMasterJson) || !bytes.Equal(row.HtmlContentSha256, before.HtmlContentSha256) || !bytes.Equal(row.BlocksJson, before.BlocksJson) || !bytes.Equal(row.VariablesJson, before.VariablesJson) || !bytes.Equal(row.PdfSanitizationReport, before.PdfSanitizationReport) || int64(len(row.FieldsJson)) > wire {
		return nil, ErrPDFTemplateSourceV1
	}
	s.template = plainPDFCloneTemplateV1(row)
	measured, err := s.queries.MeasurePDFTemplateSourceV1(ctx, generated.MeasurePDFTemplateSourceV1Params{TemplateID: row.ID, OrgID: row.OrgID, ExpectedCreatedAt: row.CreatedAt, ExpectedUpdatedAt: row.UpdatedAt, ExpectedVersion: row.Version})
	if err != nil {
		return nil, err
	}
	header, err := s.queries.GetPDFTemplateSourceHeaderForUpdateV1(ctx, generated.GetPDFTemplateSourceHeaderForUpdateV1Params{TemplateID: row.ID, OrgID: row.OrgID})
	if err != nil {
		return nil, err
	}
	rawBytes, allWire := htmlAuthoringTemplateBodyBytesV1(row)
	if measured == nil || measured.TemplateID != row.ID || measured.OrgID != row.OrgID || measured.SourceKind != "pdf" || measured.TemplateCreatedAt != row.CreatedAt || measured.TemplateUpdatedAt != row.UpdatedAt || measured.TemplateVersion != row.Version || measured.MasterWireBytes != int64(len(row.HtmlMasterJson)) || measured.VariablesWireBytes != int64(len(row.VariablesJson)) || measured.BlocksWireBytes != int64(len(row.BlocksJson)) || measured.FieldsWireBytes != int64(len(row.FieldsJson)) || measured.SanitizationWireBytes != int64(len(row.PdfSanitizationReport)) || measured.MeasurementServerVersionNum < 1 || allWire < 0 {
		return nil, ErrPDFTemplateSourceV1
	}
	if header == nil || header.ID != row.ID || header.OrgID != row.OrgID || header.SourceKind != "pdf" || header.CreatedAt != row.CreatedAt || header.UpdatedAt != row.UpdatedAt || header.Version != row.Version || header.RawTextBytes != rawBytes || header.MasterWireBytes != measured.MasterWireBytes || header.VariablesWireBytes != measured.VariablesWireBytes || header.BlocksWireBytes != measured.BlocksWireBytes || header.FieldsWireBytes != measured.FieldsWireBytes || header.SanitizationWireBytes != measured.SanitizationWireBytes || header.MeasurementServerVersionNum != measured.MeasurementServerVersionNum || header.ServerVersionNum != measured.MeasurementServerVersionNum {
		return nil, ErrPDFTemplateSourceV1
	}
	s.measured = true
	return row, nil
}

// Preserve original org-only template.updated payload/hash/chain bytes. This
// fixed writer owns actual updated source and audit consumers together; no
// document identity/M94 measurement is fabricated for an org-only event.
func (h *ApplicationPDFTemplateFieldsMutationV1) LogUpdatedV1(ctx context.Context, logger *audit.Logger, actor uuid.UUID) error {
	if h == nil || h.state == nil || logger == nil || actor == uuid.Nil {
		return ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.mutated || !s.measured || s.auditStarted {
		return ErrPDFTemplateSourceV1
	}
	s.auditStarted = true
	shape := htmlAuditShapeV1{}
	for _, key := range [...]string{"template_id", "source_kind"} {
		if err := shape.text(key, true); err != nil {
			return err
		}
		if err := shape.add(0, 2, 1); err != nil {
			return err
		}
	}
	for _, value := range []any{s.template.ID, "pdf"} {
		if err := shape.value(ctx, value, 1); err != nil {
			return err
		}
	}
	if err := shape.add(192, 4098, 17); err != nil {
		return err
	}
	if err := shape.text(audit.KindTemplateUpdated, false); err != nil {
		return err
	}
	resources, err := htmlAuditResourcesV1(shape.raw, shape.wire, shape.nodes)
	if err != nil {
		return err
	}
	close, err := s.acquireAuditV1(ctx, shape, resources)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, close)
	payload := map[string]any{"template_id": s.template.ID, "source_kind": "pdf"}
	raw, err := json.Marshal(payload)
	if err != nil || int64(len(raw)) > shape.wire {
		return ErrPDFTemplateSourceV1
	}
	if err = s.queries.AcquireOrgChainLock(ctx, s.template.OrgID.String()); err != nil {
		return err
	}
	head, err := s.queries.GetOwnedHTMLAuditChainHeadV1(ctx, s.template.OrgID)
	var previous []byte
	stamp := time.Now().UTC().Truncate(time.Microsecond)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	} else {
		if !htmlAuditHeadValidV1(head) {
			return ErrPDFTemplateSourceV1
		}
		previous = bytes.Clone(head.RowHash)
		if !stamp.After(head.CreatedAt.Time) {
			stamp = head.CreatedAt.Time.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
		}
	}
	hash := audit.ChainHashRecord(audit.HashInput{Prev: previous, OrgID: s.template.OrgID, ActorID: actor, Kind: audit.KindTemplateUpdated, CreatedAt: stamp, Payload: raw})
	id, err := s.queries.InsertEventIdentityV1(ctx, generated.InsertEventIdentityV1Params{OrgID: s.template.OrgID, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Kind: audit.KindTemplateUpdated, PayloadJson: raw, PayloadHashed: raw, PrevHash: previous, RowHash: hash, CreatedAt: pgtype.Timestamptz{Time: stamp, Valid: true}})
	if err != nil {
		return applicationInternalWriteErrorV1(ctx, applicationAuditIdentityWriteV1, err)
	}
	if id == uuid.Nil {
		return ErrPDFTemplateSourceV1
	}
	s.pending = audit.PendingEvent{ID: id, Entry: audit.Entry{OrgID: s.template.OrgID, ActorUserID: &actor, Kind: audit.KindTemplateUpdated, Payload: payload}}
	return nil
}
func (s *applicationPDFTemplateFieldsMutationStateV1) acquireAuditV1(ctx context.Context, shape htmlAuditShapeV1, resources ApplicationRequestPayloadResourcesV1) (func(), error) {
	physical := s.session.state
	p := physical.factory
	if p == nil {
		return nil, ErrPDFTemplateSourceV1
	}
	p.mu.Lock()
	physical.mu.Lock()
	defer p.mu.Unlock()
	defer physical.mu.Unlock()
	a := physical.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || !physical.dialed || physical.observer || physical.closed || physical.unknown || physical.ended || physical.retired || physical.creating || physical.sqlActive || physical.tx == nil || physical.conn == nil || physical.fence == nil || !applicationIdentityValidV1(physical.fence.identity) || a == nil || !a.valid() || a.fence != physical.fence || a.cleanupDone != physical.fence.clientDone || !physical.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != physical || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		return nil, ErrPDFTemplateSourceV1
	}
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	return a.admit(ctx, ApplicationBudgetV1{Phase: "locked-html-fresh-event", OrgID: physical.org, DocumentID: physical.document, HTMLAuditRawBytes: shape.raw, HTMLAuditWireBytes: shape.wire, HTMLAuditNodes: shape.nodes, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes})
}
func (h *ApplicationPDFTemplateFieldsMutationV1) PublishV1(logger *audit.Logger) error {
	if h == nil || h.state == nil || logger == nil {
		return ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	if s.closed || s.published || s.pending.ID == uuid.Nil || s.session == nil || s.session.state == nil {
		s.mu.Unlock()
		return ErrPDFTemplateSourceV1
	}
	native := s.session.state
	native.mu.Lock()
	ack := native.commitAttempted && native.ended && !native.commitUnknown
	native.mu.Unlock()
	if !ack {
		s.mu.Unlock()
		return ErrPDFTemplateSourceV1
	}
	s.published = true
	pending := s.pending
	s.mu.Unlock()
	var once sync.Once
	logger.PublishJoinedV1(pending, func() {
		once.Do(func() { s.mu.Lock(); s.publicationDone = true; s.releaseIfCompleteV1(); s.mu.Unlock() })
	})
	return nil
}
func (s *applicationPDFTemplateFieldsMutationStateV1) releaseIfCompleteV1() {
	if s.closed || !s.consumerClosed || (s.published && !s.publicationDone) {
		return
	}
	s.closed = true
	s.template = nil
	s.sourcePin = nil
	s.pending = audit.PendingEvent{}
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
	if s.source != nil {
		s.source.CloseConsumerV1()
		s.source = nil
	}
}
func (h *ApplicationPDFTemplateFieldsMutationV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consumerClosed = true
	s.releaseIfCompleteV1()
}
