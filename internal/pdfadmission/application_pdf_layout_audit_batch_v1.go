// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
	"unsafe"
)

// One finite aggregate native grant retains every REAL original event owner and
// hook in the original atomic100-party/1000-field materialization. Event count
// comes only from the original validated private layout, never a public cap or
// caller size. No512-loan/64-grant limit is changed and no event is skipped.
type applicationPDFLayoutAuditBatchV1 struct {
	mu                       sync.Mutex
	self                     *applicationPDFLayoutAuditBatchV1
	parent                   *applicationPDFTemplateDocumentStateV1
	session                  *ApplicationSessionV1
	header                   *applicationHTMLAuthoringBodyHeaderV1
	admission                *ApplicationAdmissionV1
	callbackDone             <-chan struct{}
	budget                   ApplicationBudgetV1
	sourcePin                *generated.Template
	slots                    []applicationPDFLayoutAuditSlotV1
	close                    func()
	opened                   int
	consumerClosed, released bool
}
type applicationPDFLayoutAuditSlotV1 struct {
	self                  *applicationPDFLayoutAuditSlotV1
	batch                 *applicationPDFLayoutAuditBatchV1
	index                 int
	shape                 htmlAuditShapeV1
	purpose               HTMLAuditPurposeV1
	recipient             pgtype.UUID
	owner                 *ApplicationHTMLAuditEventConsumerV1
	ready, issued, closed bool
}

func pdfLayoutAuditBatchResourcesV1(events, raw, wire, nodes int64) (ApplicationRequestPayloadResourcesV1, error) {
	var empty ApplicationRequestPayloadResourcesV1
	if events < 1 || events > pdflayout.MaxParties+pdflayout.MaxFields+1 || raw < 0 || wire < 2*events || nodes < events {
		return empty, workguard.ErrUnavailableV1
	}
	base, err := htmlAuditFixedResourcesV1()
	if err != nil {
		return empty, err
	}
	db, parent := int64(0), int64(0)
	if !htmlInputAddV1(&db, events, base) || !htmlInputAddV1(&db, wire, 16) {
		return empty, workguard.ErrUnavailableV1
	}
	parent = db
	// Sum of the exact existing per-event formula, plus real aggregate control.
	if !htmlInputAddV1(&parent, wire, 16) || !htmlInputAddV1(&parent, raw, 16) || !htmlInputAddV1(&parent, nodes, 256) || !htmlInputAddV1(&parent, 2, int64(unsafe.Sizeof(applicationPDFLayoutAuditBatchV1{}))) || !htmlInputAddV1(&parent, events, 2*int64(unsafe.Sizeof(applicationPDFLayoutAuditSlotV1{}))) {
		return empty, workguard.ErrUnavailableV1
	}
	return ApplicationRequestPayloadResourcesV1{WorkingBytes: parent, DBStagingBytes: db}, nil
}
func pdfLayoutAuditShapeFieldsV1(ctx context.Context, purpose HTMLAuditPurposeV1, keys []string, values []any) (htmlAuditShapeV1, error) {
	var shape htmlAuditShapeV1
	if len(keys) != len(values) || !applicationContextV1(ctx) || purpose.KindV1() == "" {
		return shape, ErrHTMLAuditEventV1
	}
	if err := shape.add(0, 2, 1); err != nil {
		return shape, err
	}
	for i, key := range keys {
		if !htmlAuditRootKeyV1(purpose, key) {
			return shape, ErrHTMLAuditEventV1
		}
		if err := shape.text(key, true); err != nil {
			return shape, err
		}
		if err := shape.add(0, 2, 1); err != nil {
			return shape, err
		}
		if err := shape.value(ctx, values[i], 1); err != nil {
			return shape, err
		}
	}
	if err := shape.text(purpose.KindV1(), false); err != nil {
		return shape, err
	}
	if err := shape.text("", false); err != nil {
		return shape, err
	}
	if err := shape.text("", false); err != nil {
		return shape, err
	}
	if err := shape.add(192, 4096, 16); err != nil {
		return shape, err
	}
	return shape, nil
}
func (s *applicationPDFTemplateDocumentStateV1) auditSourceShapeV1(ctx context.Context, index int) (HTMLAuditPurposeV1, htmlAuditShapeV1, error) {
	count := len(s.values)
	fields := len(s.fieldIDs)
	if index < 0 || index > count+fields {
		return 0, htmlAuditShapeV1{}, ErrHTMLAuditEventV1
	}
	if index < count {
		v := s.values[index]
		p := HTMLAuditPlainLayoutRecipientCreatedV1
		shape, err := pdfLayoutAuditShapeFieldsV1(ctx, p, []string{"role", "name", "email", "via", "template_layout_version"}, []any{v.Role, v.Name, v.Email, s.input.Via, s.layout.Version})
		return p, shape, err
	}
	if index < count+fields {
		f := s.layout.Fields[index-count]
		p := HTMLAuditPlainFieldAddedV1
		shape, err := pdfLayoutAuditShapeFieldsV1(ctx, p, []string{"field_id", "recipient_id", "party_role", "type", "page", "required", "via"}, []any{uuid.Nil, uuid.Nil, f.PartyRole, "signature", f.Page, true, s.input.Via})
		return p, shape, err
	}
	p := HTMLAuditPlainPDFCreatedV1
	keys := [8]string{"name", "source_kind"}
	values := [8]any{s.input.Name, "pdf"}
	n := 2
	if s.input.Via == "mcp" {
		keys[n] = "via"
		values[n] = s.input.Via
		n++
		keys[n] = "tool"
		values[n] = s.input.Tool
		n++
	}
	if s.layout != nil {
		keys[n] = "template_id"
		values[n] = s.input.TemplateText
		n++
		keys[n] = "template_version"
		values[n] = *s.input.ExpectedTemplateVersion
		n++
		keys[n] = "layout_version"
		values[n] = 1
		n++
		keys[n] = "party_count"
		values[n] = len(s.input.Parties)
		n++
	}
	shape, err := pdfLayoutAuditShapeFieldsV1(ctx, p, keys[:n], values[:n])
	return p, shape, err
}
func newPDFLayoutAuditBatchV1(ctx context.Context, parent *applicationPDFTemplateDocumentStateV1) (*applicationPDFLayoutAuditBatchV1, error) {
	if parent == nil || !parent.validV1(ctx) || !parent.prepared || parent.audits != nil || parent.sourcePin == nil || parent.writer == nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	count := len(parent.values) + len(parent.fieldIDs) + 1
	var total htmlAuditShapeV1
	for i := 0; i < count; i++ {
		_, shape, err := parent.auditSourceShapeV1(ctx, i)
		if err != nil {
			return nil, err
		}
		if err = total.add(shape.raw, shape.wire, shape.nodes); err != nil {
			return nil, err
		}
	}
	resources, err := pdfLayoutAuditBatchResourcesV1(int64(count), total.raw, total.wire, total.nodes)
	if err != nil {
		return nil, err
	}
	h := parent.session
	s := h.state
	p := s.factory
	if p == nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	// Fixed local owner construction precedes only this grant; its concrete type
	// and source metadata already have the original private producer header loan.
	g := &applicationPDFLayoutAuditBatchV1{parent: parent, session: h, header: parent.reader.bodyHeader, callbackDone: ctx.Done(), sourcePin: parent.sourcePin}
	g.self = g
	p.mu.Lock()
	s.mu.Lock()
	a := s.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || s.observer || s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) || a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone || !s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrPDFTemplateDocumentV1
	}
	g.admission = a
	g.budget = ApplicationBudgetV1{Phase: "locked-pdf-layout-fresh-events", OrgID: s.org, DocumentID: s.document, HTMLAuditRawBytes: total.raw, HTMLAuditWireBytes: total.wire, HTMLAuditNodes: total.nodes, PDFLayoutAuditEventCount: int64(count), WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes, pdfLayoutAuditGrant: g}
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	g.close, err = a.admit(ctx, g.budget)
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	g.slots = make([]applicationPDFLayoutAuditSlotV1, count)
	for i := range g.slots {
		purpose, shape, err := parent.auditSourceShapeV1(ctx, i)
		if err != nil {
			g.close()
			return nil, err
		}
		g.slots[i] = applicationPDFLayoutAuditSlotV1{batch: g, index: i, purpose: purpose, shape: shape}
		g.slots[i].self = &g.slots[i]
	}
	return g, nil
}
func (g *applicationPDFLayoutAuditBatchV1) validBudgetV1(ctx context.Context, work *WorkAdmissionV1, b ApplicationBudgetV1) bool {
	if g == nil || g.self != g || g.session == nil || g.session.state == nil || g.parent == nil || g.parent.session != g.session || g.parent.sourcePin != g.sourcePin || g.sourcePin == nil || ctx == nil || g.callbackDone == nil || ctx.Done() != g.callbackDone || g.header == nil || g.header.self != g.header || g.header.reader != g.parent.reader || g.header.session != g.session || g.header.admission != g.admission || g.header.closed.Load() || g.budget != b || b.pdfLayoutAuditGrant != g || b.PDFLayoutAuditEventCount != int64(len(g.parent.values)+len(g.parent.fieldIDs)+1) {
		return false
	}
	select {
	case <-g.callbackDone:
		return false
	default:
	}
	s := g.session.state
	return s.factory != nil && s.factory.work == work && s.admission == g.admission && g.admission != nil && g.admission.fence == s.fence && g.header.fence == s.fence && g.header.loanClose != nil && ctx.Value(applicationSessionCallbackKeyV1{}) == s && s.org == b.OrgID && s.document == b.DocumentID
}
func (slot *applicationPDFLayoutAuditSlotV1) acquireV1(ctx context.Context, h *ApplicationSessionV1, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, shape htmlAuditShapeV1) (func(), error) {
	if slot == nil || slot.self != slot || slot.batch == nil {
		return nil, ErrHTMLAuditEventV1
	}
	g := slot.batch
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.self != g || g.session != h || g.consumerClosed || g.released || g.close == nil || !slot.ready || slot.issued || slot.closed || slot.shape != shape || slot.purpose != purpose || slot.recipient != recipient || actor != (pgtype.UUID{Bytes: g.parent.user, Valid: true}) || org != g.budget.OrgID || document != g.budget.DocumentID || kind != purpose.KindV1() || ip != "" || ua != "" || ctx.Done() != g.callbackDone || ctx.Value(applicationSessionCallbackKeyV1{}) != h.state {
		return nil, ErrHTMLAuditEventV1
	}
	slot.issued = true
	g.opened++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			if !slot.closed {
				slot.closed = true
				g.opened--
			}
			ready := g.consumerClosed && g.opened == 0 && !g.released
			close := g.close
			parent := g.parent
			if ready {
				g.released = true
				g.close = nil
				g.sourcePin = nil
				g.header = nil
				g.parent = nil
				g.session = nil
				g.admission = nil
			}
			g.mu.Unlock()
			if ready {
				if close != nil {
					close()
				}
				parent.releaseConsumerSourceV1()
			}
		})
	}, nil
}
func (g *applicationPDFLayoutAuditBatchV1) closeConsumerV1() {
	if g == nil || g.self != g {
		return
	}
	g.mu.Lock()
	if g.consumerClosed {
		g.mu.Unlock()
		return
	}
	g.consumerClosed = true
	g.mu.Unlock()
	// Do not hold aggregate lock while an actual event/hook closes its child ref.
	for i := range g.slots {
		g.mu.Lock()
		owner := g.slots[i].owner
		g.mu.Unlock()
		if owner != nil {
			owner.CloseConsumerV1()
		}
	}
	g.mu.Lock()
	ready := g.opened == 0 && !g.released
	close := g.close
	parent := g.parent
	if ready {
		g.released = true
		g.close = nil
		g.sourcePin = nil
		g.header = nil
		g.parent = nil
		g.session = nil
		g.admission = nil
	}
	g.mu.Unlock()
	if ready {
		if close != nil {
			close()
		}
		parent.releaseConsumerSourceV1()
	}
}
func (w *ApplicationPDFTemplateDocumentV1) NewNextAuditV1(ctx context.Context) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if w == nil || w.state == nil {
		return nil, ErrPDFTemplateDocumentV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.audits == nil || s.auditNext >= len(s.audits.slots) || !s.quotaApplied || s.quotaAppliedRecipient != s.nextRecipient {
		return nil, ErrPDFTemplateDocumentV1
	}
	index := s.auditNext
	recipients := len(s.values)
	fields := len(s.fieldIDs)
	var payload map[string]any
	recipient := pgtype.UUID{}
	if index < recipients {
		if s.nextRecipient != index+1 || s.recipientIDs[index] == uuid.Nil {
			return nil, ErrPDFTemplateDocumentV1
		}
		v := s.values[index]
		recipient = pgtype.UUID{Bytes: s.recipientIDs[index], Valid: true}
		payload = map[string]any{"role": v.Role, "name": v.Name, "email": v.Email, "via": s.input.Via, "template_layout_version": s.layout.Version}
	} else if index < recipients+fields {
		offset := index - recipients
		if s.nextRecipient != recipients || s.nextField != offset+1 || s.fieldIDs[offset] == uuid.Nil {
			return nil, ErrPDFTemplateDocumentV1
		}
		field := s.layout.Fields[offset]
		payload = map[string]any{"field_id": s.fieldIDs[offset], "recipient_id": s.roleIDs[field.PartyRole], "party_role": field.PartyRole, "type": "signature", "page": field.Page, "required": true, "via": s.input.Via}
	} else {
		if !s.measured || s.nextRecipient != recipients || s.nextField != fields {
			return nil, ErrPDFTemplateDocumentV1
		}
		payload = map[string]any{"name": s.input.Name, "source_kind": "pdf"}
		if s.input.Via == "mcp" {
			payload["via"] = s.input.Via
			payload["tool"] = s.input.Tool
		}
		if s.layout != nil {
			payload["template_id"] = s.input.TemplateText
			payload["template_version"] = *s.input.ExpectedTemplateVersion
			payload["layout_version"] = 1
			payload["party_count"] = len(s.input.Parties)
		}
	}
	slot := &s.audits.slots[index]
	s.audits.mu.Lock()
	slot.ready = true
	slot.recipient = recipient
	s.audits.mu.Unlock()
	owner, err := s.session.newHTMLAuditEventV1(ctx, slot.purpose, s.session.state.org, s.session.state.document, recipient, pgtype.UUID{Bytes: s.user, Valid: true}, slot.purpose.KindV1(), "", "", payload, nil, slot)
	if err != nil {
		return nil, err
	}
	s.audits.mu.Lock()
	slot.owner = owner
	s.audits.mu.Unlock()
	s.auditNext++
	return owner, nil
}
