// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/agreement"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/templatepin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Fresh template identity comes only from this native private scope's INSERT.
// SQL result/cache/audit bytes and the actual response+hook users retain one
// owner. Neither a caller Template nor an existing uncached row can enter it.
type ApplicationBlocksTemplateWriterV1 struct {
	state *applicationBlocksTemplateWriterStateV1
}
type applicationBlocksTemplateWriterStateV1 struct {
	mu                                       sync.Mutex
	session                                  *ApplicationSessionV1
	reader                                   *ApplicationHTMLAuthoringReaderV1
	queries                                  *generated.Queries
	closes                                   []func()
	template                                 *generated.Template
	source                                   *ApplicationBlocksCreationWriterV1
	old                                      *generated.Template
	releaseOld                               func()
	created, updated                         bool
	content                                  *templatepin.Content
	measured, consumerClosed, closed         bool
	pending                                  audit.PendingEvent
	auditStarted, published, publicationDone bool
}

func (h *ApplicationSessionV1) NewBlocksTemplateWriterV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*ApplicationBlocksTemplateWriterV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrBlocksTemplateSourceV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationBlocksTemplateWriterStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationBlocksTemplateWriterV1{}))
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, err
	}
	source, err := h.NewBlocksCreationWriterV1(ctx, reader)
	if err != nil {
		close()
		return nil, err
	}
	return &ApplicationBlocksTemplateWriterV1{state: &applicationBlocksTemplateWriterStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}, source: source}}, nil
}
func (s *applicationBlocksTemplateWriterStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.consumerClosed && !s.closed && s.session != nil && s.session.state != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (s *applicationBlocksTemplateWriterStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, close)
	return nil
}

// Preparation uses the existing authoring normalizer and its concrete owned
// lexical/decimal/canonical-output loans. No second block grammar is introduced.
func (h *ApplicationBlocksTemplateWriterV1) PrepareSourceV1(ctx context.Context, raw, variables json.RawMessage) error {
	if h == nil || h.state == nil {
		return ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.created || s.updated {
		return ErrBlocksTemplateSourceV1
	}
	return s.source.PrepareSourceV1(ctx, raw, variables)
}
func (h *ApplicationBlocksTemplateWriterV1) BindCurrentV1(ctx context.Context, current *ApplicationBlocksTemplateSourceV1) error {
	if h == nil || h.state == nil || current == nil || current.state == nil {
		return ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.old != nil || s.created || s.updated {
		return ErrBlocksTemplateSourceV1
	}
	tpl, release, err := current.state.borrowUpdateV1(ctx, s.session, s.reader)
	if err != nil {
		return err
	}
	if tpl.ID != s.session.state.document {
		release()
		return ErrBlocksTemplateSourceV1
	}
	s.old = tpl
	s.releaseOld = release
	return nil
}
func (h *ApplicationBlocksTemplateWriterV1) WriteV1(ctx context.Context, name string, actor uuid.UUID) (*generated.Template, error) {
	if h == nil || h.state == nil {
		return nil, ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.created || s.updated || actor == uuid.Nil || s.source == nil || s.source.state == nil || !s.source.state.prepared {
		return nil, ErrBlocksTemplateSourceV1
	}
	prepared := s.source.state
	if name == "" && s.old != nil {
		name = s.old.Name
	}
	typed := 4*int64(unsafe.Sizeof(generated.Template{})) + 2*int64(unsafe.Sizeof(generated.CreateFreshBlocksTemplateSourceV1Params{})) + 2*int64(unsafe.Sizeof(generated.UpdateBlocksTemplateParams{})) + int64(unsafe.Sizeof(generated.PdfTemplateSourceSizesV1{}))
	raw, err := htmlAuthoringSumV1(int64(len(name)), int64(len(prepared.blocks)), int64(len(prepared.variables)), typed)
	if err != nil {
		return nil, err
	}
	wire, err := htmlAuthoringSumV1(prepared.blocksWire, prepared.variablesWire, 2)
	if err != nil {
		return nil, err
	}
	if s.old != nil {
		oldraw, oldwire := htmlAuthoringTemplateBodyBytesV1(s.old)
		raw, err = htmlAuthoringSumV1(raw, oldraw)
		if err != nil {
			return nil, err
		}
		wire, err = htmlAuthoringSumV1(wire, oldwire)
		if err != nil {
			return nil, err
		}
	}
	if err = s.holdV1(ctx, raw, wire); err != nil {
		return nil, err
	}
	var row *generated.Template
	if s.old == nil {
		row, err = s.queries.CreateFreshBlocksTemplateSourceV1(ctx, generated.CreateFreshBlocksTemplateSourceV1Params{ID: s.session.state.document, OrgID: s.session.state.org, Name: name, BlocksJson: prepared.blocks, VariablesJson: prepared.variables, CreatedBy: actor})
	} else {
		row, err = s.queries.UpdateBlocksTemplate(ctx, generated.UpdateBlocksTemplateParams{ID: s.old.ID, OrgID: s.old.OrgID, Name: name, BlocksJson: prepared.blocks, VariablesJson: prepared.variables})
	}
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != s.session.state.document || row.OrgID != s.session.state.org || row.SourceKind != "blocks" || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.UpdatedAt) || int64(len(row.BlocksJson)) > prepared.blocksWire || int64(len(row.VariablesJson)) > prepared.variablesWire {
		return nil, ErrBlocksTemplateSourceV1
	}
	if s.old == nil {
		if row.Version != 1 || row.CreatedBy != actor || row.Name != name || row.PdfStorageKey.Valid || row.PdfStorageVersionID.Valid || len(row.PdfSha256) != 0 || row.PageCount.Valid || !bytes.Equal(row.FieldsJson, []byte("[]")) || len(row.HtmlMasterJson) != 0 || len(row.HtmlContentSha256) != 0 || len(row.PdfSanitizationReport) != 0 {
			return nil, ErrBlocksTemplateSourceV1
		}
		s.created = true
	} else {
		if s.old.Version == int32(^uint32(0)>>1) || row.Version != s.old.Version+1 || row.Name != name || !blocksTemplateImmutableEqualV1(s.old, row) {
			return nil, ErrBlocksTemplateSourceV1
		}
		s.updated = true
	}
	s.template = plainPDFCloneTemplateV1(row)
	return row, nil
}
func blocksTemplateImmutableEqualV1(a, b *generated.Template) bool {
	return a != nil && b != nil && a.ID == b.ID && a.OrgID == b.OrgID && a.SourceKind == b.SourceKind && a.PdfStorageKey == b.PdfStorageKey && bytes.Equal(a.PdfSha256, b.PdfSha256) && a.PageCount == b.PageCount && bytes.Equal(a.FieldsJson, b.FieldsJson) && a.CreatedBy == b.CreatedBy && a.CreatedAt == b.CreatedAt && a.ArchivedAt == b.ArchivedAt && a.PdfStorageVersionID == b.PdfStorageVersionID && a.EvidenceVersionPinRequired == b.EvidenceVersionPinRequired && bytes.Equal(a.HtmlMasterJson, b.HtmlMasterJson) && bytes.Equal(a.HtmlContentSha256, b.HtmlContentSha256) && bytes.Equal(a.PdfSanitizationReport, b.PdfSanitizationReport)
}
func (h *ApplicationBlocksTemplateWriterV1) MeasureFreshSourceV1(ctx context.Context) error {
	if h == nil || h.state == nil {
		return ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || (!s.created && !s.updated) || s.measured || s.template == nil {
		return ErrBlocksTemplateSourceV1
	}
	tpl := s.template
	m, err := s.queries.MeasureNonHTMLTemplateSourceV1(ctx, generated.MeasureNonHTMLTemplateSourceV1Params{TemplateID: tpl.ID, OrgID: tpl.OrgID, ExpectedCreatedAt: tpl.CreatedAt, ExpectedUpdatedAt: tpl.UpdatedAt, ExpectedVersion: tpl.Version})
	if err != nil {
		return err
	}
	raw, wire := htmlAuthoringTemplateBodyBytesV1(tpl)
	if m == nil || m.TemplateID != tpl.ID || m.OrgID != tpl.OrgID || m.SourceKind != "blocks" || m.TemplateCreatedAt != tpl.CreatedAt || m.TemplateUpdatedAt != tpl.UpdatedAt || m.TemplateVersion != tpl.Version || m.MasterWireBytes != int64(len(tpl.HtmlMasterJson)) || m.VariablesWireBytes != int64(len(tpl.VariablesJson)) || m.BlocksWireBytes != int64(len(tpl.BlocksJson)) || m.FieldsWireBytes != int64(len(tpl.FieldsJson)) || m.SanitizationWireBytes != int64(len(tpl.PdfSanitizationReport)) || m.MeasurementServerVersionNum < 1 {
		return ErrBlocksTemplateSourceV1
	}
	if raw < 0 || wire < 0 {
		return ErrBlocksTemplateSourceV1
	}
	if err = s.holdV1(ctx, int64(unsafe.Sizeof(generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Row{}))+int64(unsafe.Sizeof(generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Params{})), 0); err != nil {
		return err
	}
	header, err := s.queries.GetNonHTMLTemplateSourceHeaderForUpdateV1(ctx, generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Params{TemplateID: tpl.ID, OrgID: tpl.OrgID})
	if err != nil {
		return err
	}
	if header.ID != tpl.ID || header.OrgID != tpl.OrgID || header.SourceKind != "blocks" || header.Version != tpl.Version || header.CreatedAt != tpl.CreatedAt || header.UpdatedAt != tpl.UpdatedAt || header.RawTextBytes != raw || header.MasterWireBytes != m.MasterWireBytes || header.VariablesWireBytes != m.VariablesWireBytes || header.BlocksWireBytes != m.BlocksWireBytes || header.FieldsWireBytes != m.FieldsWireBytes || header.SanitizationWireBytes != m.SanitizationWireBytes || header.MeasurementServerVersionNum != m.MeasurementServerVersionNum || header.ServerVersionNum != m.MeasurementServerVersionNum {
		return ErrBlocksTemplateSourceV1
	}
	s.measured = true
	return nil
}
func (h *ApplicationBlocksTemplateWriterV1) CanonicalContentV1(ctx context.Context) (templatepin.Content, error) {
	if h == nil || h.state == nil {
		return templatepin.Content{}, ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.measured || s.template == nil {
		return templatepin.Content{}, ErrBlocksTemplateSourceV1
	}
	if s.content != nil {
		return *s.content, nil
	}
	content, err := s.source.state.canonicalContentV1(ctx, s.template)
	if err != nil {
		return templatepin.Content{}, err
	}
	s.content = &content
	return content, nil
}

// The existing Logger already reads only scalar row_hash/created_at head data.
// This fixed native producer keeps that original chain/hash meaning while
// bounding its actual head and identity-only append, then joins every hook;
// org-only template events are not document snapshot-history/M94 rows.
func (h *ApplicationBlocksTemplateWriterV1) LogMutationV1(ctx context.Context, logger *audit.Logger, actor uuid.UUID, starter string) error {
	if h == nil || h.state == nil || logger == nil {
		return ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || (!s.created && !s.updated) || !s.measured || s.auditStarted || s.template == nil || actor == uuid.Nil {
		return ErrBlocksTemplateSourceV1
	}
	s.auditStarted = true

	kind := audit.KindTemplateCreated
	keys := []string{"template_id", "source_kind", "name"}
	values := []any{s.template.ID, "blocks", s.template.Name}
	if s.updated {
		kind = audit.KindTemplateUpdated
		keys = []string{"template_id", "source_kind"}
		values = []any{s.template.ID, "blocks"}
	} else if starter != "" {
		keys = append(keys, "starter")
		values = append(values, starter)
	}
	shape := htmlAuditShapeV1{}
	for _, key := range keys {
		if err := shape.text(key, true); err != nil {
			return err
		}
		if err := shape.add(0, 2, 1); err != nil {
			return err
		}
	}
	for _, value := range values {
		if err := shape.value(ctx, value, 1); err != nil {
			return err
		}
	}
	if err := shape.add(192, 4098, 17); err != nil {
		return err
	}
	for _, text := range [...]string{kind, "", ""} {
		if err := shape.text(text, false); err != nil {
			return err
		}
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
	payload := map[string]any{"template_id": s.template.ID, "source_kind": "blocks"}
	if s.created {
		payload["name"] = strings.Clone(s.template.Name)
		if starter != "" {
			payload["starter"] = strings.Clone(starter)
		}
	}
	// Use the same original scalar chain/timestamp/hash behavior, with the
	// bounded native hash32 head guard. No historical payload model or fresh
	// RETURNING* event is needed for this org-only template event.
	if err = s.queries.AcquireOrgChainLock(ctx, s.template.OrgID.String()); err != nil {
		return err
	}
	head, err := s.queries.GetOwnedHTMLAuditChainHeadV1(ctx, s.template.OrgID)
	var previous []byte
	created := time.Now().UTC().Truncate(time.Microsecond)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	} else {
		if !htmlAuditHeadValidV1(head) {
			return ErrBlocksTemplateSourceV1
		}
		previous = bytes.Clone(head.RowHash)
		if !created.After(head.CreatedAt.Time) {
			created = head.CreatedAt.Time.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil || int64(len(raw)) > shape.wire {
		return ErrBlocksTemplateSourceV1
	}
	hash := audit.ChainHashRecord(audit.HashInput{Prev: previous, OrgID: s.template.OrgID, ActorID: actor, Kind: kind, CreatedAt: created, Payload: raw})
	id, err := s.queries.InsertEventIdentityV1(ctx, generated.InsertEventIdentityV1Params{OrgID: s.template.OrgID, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Kind: kind, PayloadJson: raw, PayloadHashed: raw, PrevHash: previous, RowHash: hash, CreatedAt: pgtype.Timestamptz{Time: created, Valid: true}})
	if err != nil {
		return err
	}
	if id == uuid.Nil {
		return ErrBlocksTemplateSourceV1
	}
	s.pending = audit.PendingEvent{ID: id, Entry: audit.Entry{OrgID: s.template.OrgID, ActorUserID: &actor, Kind: kind, Payload: payload}}
	return nil
}

func (s *applicationBlocksTemplateWriterStateV1) acquireAuditV1(ctx context.Context, shape htmlAuditShapeV1, resources ApplicationRequestPayloadResourcesV1) (func(), error) {
	physical := s.session.state
	p := physical.factory
	if p == nil {
		return nil, ErrBlocksTemplateSourceV1
	}
	p.mu.Lock()
	physical.mu.Lock()
	defer p.mu.Unlock()
	defer physical.mu.Unlock()
	a := physical.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || !physical.dialed || physical.observer || physical.closed || physical.unknown || physical.ended || physical.retired || physical.creating || physical.sqlActive || physical.tx == nil || physical.conn == nil || physical.fence == nil || !applicationIdentityValidV1(physical.fence.identity) || a == nil || !a.valid() || a.fence != physical.fence || a.cleanupDone != physical.fence.clientDone || !physical.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != physical || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		return nil, ErrBlocksTemplateSourceV1
	}
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	return a.admit(ctx, ApplicationBudgetV1{Phase: "locked-html-fresh-event", OrgID: physical.org, DocumentID: physical.document, HTMLAuditRawBytes: shape.raw, HTMLAuditWireBytes: shape.wire, HTMLAuditNodes: shape.nodes, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes})
}
func (h *ApplicationBlocksTemplateWriterV1) PublishV1(logger *audit.Logger) error {
	if h == nil || h.state == nil || logger == nil {
		return ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	if s.closed || s.published || s.pending.ID == uuid.Nil || s.session == nil || s.session.state == nil {
		s.mu.Unlock()
		return ErrBlocksTemplateSourceV1
	}
	native := s.session.state
	native.mu.Lock()
	ack := native.commitAttempted && native.ended && !native.commitUnknown
	native.mu.Unlock()
	if !ack {
		s.mu.Unlock()
		return ErrBlocksTemplateSourceV1
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
func (s *applicationBlocksTemplateWriterStateV1) releaseIfCompleteV1() {
	if s.closed || !s.consumerClosed || (s.published && !s.publicationDone) {
		return
	}
	s.closed = true
	s.template = nil
	s.content = nil
	s.old = nil
	s.pending = audit.PendingEvent{}
	if s.source != nil {
		s.source.CloseConsumerV1()
		s.source = nil
	}
	if s.releaseOld != nil {
		s.releaseOld()
		s.releaseOld = nil
	}
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
func (h *ApplicationBlocksTemplateWriterV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consumerClosed = true
	s.releaseIfCompleteV1()
}

// Only the existing built-in catalog is used here. Its actual fixed tree and
// variable strings fund the original two catalog marshals before they run;
// the original member/credential guard has already completed in the caller.
func (h *ApplicationBlocksTemplateWriterV1) PrepareStarterSourceV1(ctx context.Context, key string) error {
	if h == nil || h.state == nil {
		return ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.created || s.updated {
		return ErrBlocksTemplateSourceV1
	}
	starter, ok := agreement.Get(key)
	if !ok {
		return errors.New("unknown starter key")
	}
	upper, err := blocksCanonicalOutputUpperV1(ctx, &starter.Tree)
	if err != nil {
		return err
	}
	for name, value := range starter.Variables {
		if !htmlInputAddV1(&upper, int64(len(name)), 6) || !htmlInputAddV1(&upper, int64(len(value)), 6) || !htmlInputAddV1(&upper, 1, 8) {
			return ErrBlocksTemplateSourceV1
		}
	}
	if err = s.source.state.holdV1(ctx, upper, 0); err != nil {
		return err
	}
	raw, err := json.Marshal(starter.Tree)
	if err != nil {
		return err
	}
	variables, err := json.Marshal(starter.Variables)
	if err != nil {
		return err
	}
	return s.source.PrepareSourceV1(ctx, raw, variables)
}
