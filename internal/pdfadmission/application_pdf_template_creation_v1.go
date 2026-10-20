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

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Fresh template identity comes only from this native private scope's INSERT.
// SQL result/cache/audit bytes and the actual response+hook users retain one
// owner. Neither a caller Template nor an existing uncached row can enter it.
type ApplicationPDFTemplateCreationV1 struct {
	state *applicationPDFTemplateCreationStateV1
}
type applicationPDFTemplateCreationStateV1 struct {
	mu                                        sync.Mutex
	session                                   *ApplicationSessionV1
	reader                                    *ApplicationHTMLAuthoringReaderV1
	queries                                   *generated.Queries
	closes                                    []func()
	template                                  *generated.Template
	templateIdentity                          uuid.UUID
	fieldsWire, reportWire                    int64
	created, measured, consumerClosed, closed bool
	pending                                   audit.PendingEvent
	auditStarted, published, publicationDone  bool
}

func (h *ApplicationSessionV1) NewPDFTemplateCreationV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*ApplicationPDFTemplateCreationV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrPDFTemplateSourceV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationPDFTemplateCreationStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationPDFTemplateCreationV1{}))
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, err
	}
	return &ApplicationPDFTemplateCreationV1{state: &applicationPDFTemplateCreationStateV1{session: h, reader: reader, templateIdentity: h.state.document, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}}}, nil
}
func (s *applicationPDFTemplateCreationStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.consumerClosed && !s.closed && s.session != nil && s.session.state != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (s *applicationPDFTemplateCreationStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, close)
	return nil
}
func (h *ApplicationPDFTemplateCreationV1) CreatePDFTemplateV1(ctx context.Context, p generated.CreatePDFTemplateParams) (*generated.Template, error) {
	if h == nil || h.state == nil {
		return nil, ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.created || s.templateIdentity == uuid.Nil || p.OrgID != s.session.state.org || p.CreatedBy == uuid.Nil || !p.PdfStorageKey.Valid || !p.PageCount.Valid {
		return nil, ErrPDFTemplateSourceV1
	}
	fields, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, p.FieldsJson)
	if err != nil {
		return nil, err
	}
	report := int64(0)
	if len(p.PdfSanitizationReport) > 0 {
		report, err = sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, p.PdfSanitizationReport)
		if err != nil {
			return nil, err
		}
	}
	raw, err := htmlAuthoringSumV1(int64(len(p.Name)), int64(len(p.PdfStorageKey.String)), int64(len(p.PdfStorageVersionID.String)), int64(len(p.PdfSha256)), int64(len(p.FieldsJson)), int64(len(p.PdfSanitizationReport)), 2*int64(unsafe.Sizeof(generated.Template{})), 2*int64(unsafe.Sizeof(generated.CreatePDFTemplateParams{})))
	if err != nil {
		return nil, err
	}
	wire, err := htmlAuthoringSumV1(fields, report, 2)
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(ctx, raw, wire); err != nil {
		return nil, err
	}
	row, err := s.queries.CreateFreshPDFTemplateSourceV1(ctx, generated.CreateFreshPDFTemplateSourceV1Params{ID: s.templateIdentity, OrgID: p.OrgID, Name: p.Name, PdfStorageKey: p.PdfStorageKey.String, PdfSha256: p.PdfSha256, PdfStorageVersionID: p.PdfStorageVersionID.String, EvidenceVersionPinRequired: p.EvidenceVersionPinRequired, PageCount: p.PageCount.Int32, FieldsJson: bytes.Clone(p.FieldsJson), CreatedBy: p.CreatedBy, PdfSanitizationReport: bytes.Clone(p.PdfSanitizationReport)})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != s.templateIdentity || row.OrgID != s.session.state.org || row.SourceKind != "pdf" || row.Version != 1 || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.UpdatedAt) || len(row.BlocksJson) != 0 || len(row.HtmlMasterJson) != 0 || len(row.HtmlContentSha256) != 0 || !bytes.Equal(row.VariablesJson, []byte("{}")) || int64(len(row.FieldsJson)) > fields || int64(len(row.PdfSanitizationReport)) > report {
		return nil, ErrPDFTemplateSourceV1
	}
	s.created = true
	s.template = plainPDFCloneTemplateV1(row)
	s.fieldsWire = fields
	s.reportWire = report
	return row, nil
}
func (h *ApplicationPDFTemplateCreationV1) MeasureFreshSourceV1(ctx context.Context) error {
	if h == nil || h.state == nil {
		return ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured || s.template == nil {
		return ErrPDFTemplateSourceV1
	}
	tpl := s.template
	m, err := s.queries.MeasurePDFTemplateSourceV1(ctx, generated.MeasurePDFTemplateSourceV1Params{TemplateID: tpl.ID, OrgID: tpl.OrgID, ExpectedCreatedAt: tpl.CreatedAt, ExpectedUpdatedAt: tpl.UpdatedAt, ExpectedVersion: tpl.Version})
	if err != nil {
		return err
	}
	if m == nil || m.TemplateID != tpl.ID || m.OrgID != tpl.OrgID || m.SourceKind != "pdf" || m.TemplateCreatedAt != tpl.CreatedAt || m.TemplateUpdatedAt != tpl.UpdatedAt || m.TemplateVersion != tpl.Version || m.MasterWireBytes != 0 || m.BlocksWireBytes != 0 || m.VariablesWireBytes != 2 || m.FieldsWireBytes < 1 || m.FieldsWireBytes > s.fieldsWire || m.SanitizationWireBytes < 0 || m.SanitizationWireBytes > s.reportWire || m.MeasurementServerVersionNum < 1 {
		return ErrPDFTemplateSourceV1
	}
	s.measured = true
	return nil
}
func (h *ApplicationPDFTemplateCreationV1) CurrentTemplateV1(ctx context.Context) (*generated.Template, error) {
	if h == nil || h.state == nil {
		return nil, ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.template == nil {
		return nil, ErrPDFTemplateSourceV1
	}
	return plainPDFCloneTemplateV1(s.template), nil
}

// The existing Logger already reads only scalar row_hash/created_at head data.
// This fixed native producer keeps that original chain/hash meaning while
// bounding its actual head and identity-only append, then joins every hook;
// org-only template events are not document snapshot-history/M94 rows.
func (h *ApplicationPDFTemplateCreationV1) LogUploadCreatedV1(ctx context.Context, logger *audit.Logger, size int64) error {
	if h == nil || h.state == nil || logger == nil {
		return ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || !s.measured || s.auditStarted || s.template == nil {
		return ErrPDFTemplateSourceV1
	}
	s.auditStarted = true
	// The map topology is fixed4keys, and all values are concrete typed values.
	// Build shape before any scalable copies/Marshal/SQL; fixed local envelope
	// storage is already held by the actual creation constructor above.
	shape := htmlAuditShapeV1{}
	for _, key := range [...]string{"template_id", "source_kind", "name", "size_bytes"} {
		if err := shape.text(key, true); err != nil {
			return err
		}
		if err := shape.add(0, 2, 1); err != nil {
			return err
		}
	}
	for _, value := range []any{s.template.ID, "pdf", s.template.Name, size} {
		if err := shape.value(ctx, value, 1); err != nil {
			return err
		}
	}
	if err := shape.add(192, 4098, 17); err != nil {
		return err
	}
	for _, text := range [...]string{audit.KindTemplateCreated, "", ""} {
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
	payload := map[string]any{"template_id": s.template.ID, "source_kind": "pdf", "name": stringsClonePDFTemplateV1(s.template.Name), "size_bytes": size}
	actor := s.template.CreatedBy
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
			return ErrPDFTemplateSourceV1
		}
		previous = bytes.Clone(head.RowHash)
		if !created.After(head.CreatedAt.Time) {
			created = head.CreatedAt.Time.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil || int64(len(raw)) > shape.wire {
		return ErrPDFTemplateSourceV1
	}
	hash := audit.ChainHashRecord(audit.HashInput{Prev: previous, OrgID: s.template.OrgID, ActorID: actor, Kind: audit.KindTemplateCreated, CreatedAt: created, Payload: raw})
	id, err := s.queries.InsertEventIdentityV1(ctx, generated.InsertEventIdentityV1Params{OrgID: s.template.OrgID, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Kind: audit.KindTemplateCreated, PayloadJson: raw, PayloadHashed: raw, PrevHash: previous, RowHash: hash, CreatedAt: pgtype.Timestamptz{Time: created, Valid: true}})
	if err != nil {
		return err
	}
	if id == uuid.Nil {
		return ErrPDFTemplateSourceV1
	}
	s.pending = audit.PendingEvent{ID: id, Entry: audit.Entry{OrgID: s.template.OrgID, ActorUserID: &actor, Kind: audit.KindTemplateCreated, Payload: payload}}
	return nil
}
func stringsClonePDFTemplateV1(value string) string { return strings.Clone(value) }
func (s *applicationPDFTemplateCreationStateV1) acquireAuditV1(ctx context.Context, shape htmlAuditShapeV1, resources ApplicationRequestPayloadResourcesV1) (func(), error) {
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
func (h *ApplicationPDFTemplateCreationV1) PublishV1(logger *audit.Logger) error {
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
func (s *applicationPDFTemplateCreationStateV1) releaseIfCompleteV1() {
	if s.closed || !s.consumerClosed || (s.published && !s.publicationDone) {
		return
	}
	s.closed = true
	s.template = nil
	s.pending = audit.PendingEvent{}
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
func (h *ApplicationPDFTemplateCreationV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consumerClosed = true
	s.releaseIfCompleteV1()
}
