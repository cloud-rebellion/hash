// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"sync"
	"unsafe"
)

// One finite owner derives the original document.created + <=50 actual
// recipient.created slots from THIS freshly measured document, durable claim,
// locked M97 block template and original canonical recipient batch. No public
// count/size/payload can mint a slot. Each original event retains its real hook.
type ApplicationAutomationAuditsV1 struct {
	state *applicationAutomationAuditBatchV1
}
type applicationAutomationAuditBatchV1 struct {
	mu                       sync.Mutex
	self                     *applicationAutomationAuditBatchV1
	session                  *ApplicationSessionV1
	reader                   *ApplicationHTMLAuthoringReaderV1
	header                   *applicationHTMLAuthoringBodyHeaderV1
	admission                *ApplicationAdmissionV1
	callbackDone             <-chan struct{}
	budget                   ApplicationBudgetV1
	parent                   *applicationAutomationRecipientsStateV1
	claim                    *applicationAutomationRequestStateV1
	source                   *applicationBlocksTemplateSourceStateV1
	sourcePin                *generated.Template
	request, template, user  uuid.UUID
	version                  int32
	name, digest, ip, ua     string
	values                   []recipients.Values
	slots                    []applicationAutomationAuditSlotV1
	close                    func()
	next, opened, active     int
	consumerClosed, released bool
}
type applicationAutomationAuditSlotV1 struct {
	self                  *applicationAutomationAuditSlotV1
	batch                 *applicationAutomationAuditBatchV1
	index                 int
	shape                 htmlAuditShapeV1
	purpose               HTMLAuditPurposeV1
	recipient             pgtype.UUID
	owner                 *ApplicationHTMLAuditEventConsumerV1
	ready, issued, closed bool
}

func automationAuditBatchResourcesV1(events, raw, wire, nodes int64) (ApplicationRequestPayloadResourcesV1, error) {
	var empty ApplicationRequestPayloadResourcesV1
	if events < 2 || events > 51 || raw < 0 || wire < 2*events || nodes < events {
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
	if !htmlInputAddV1(&parent, wire, 16) || !htmlInputAddV1(&parent, raw, 16) || !htmlInputAddV1(&parent, nodes, 256) || !htmlInputAddV1(&parent, 2, int64(unsafe.Sizeof(applicationAutomationAuditBatchV1{}))) || !htmlInputAddV1(&parent, events, 2*int64(unsafe.Sizeof(applicationAutomationAuditSlotV1{}))+2*int64(unsafe.Sizeof(recipients.Values{}))) {
		return empty, workguard.ErrUnavailableV1
	}
	return ApplicationRequestPayloadResourcesV1{WorkingBytes: parent, DBStagingBytes: db}, nil
}
func (g *applicationAutomationAuditBatchV1) shapeV1(ctx context.Context, index int) (HTMLAuditPurposeV1, htmlAuditShapeV1, error) {
	var p HTMLAuditPurposeV1
	var keys [7]string
	var vals [7]any
	n := 0
	if index == 0 {
		p = HTMLAuditAutomationDocumentCreatedV1
		keys = [7]string{"name", "source_kind", "via", "automation_request_id", "template_id", "template_version", "template_content_sha256"}
		vals = [7]any{g.name, "blocks", "automation", g.request, g.template, g.version, g.digest}
		n = 7
	} else if index > 0 && index <= len(g.values) {
		p = HTMLAuditAutomationRecipientCreatedV1
		v := g.values[index-1]
		keys = [7]string{"email", "name", "role", "via", "automation_request_id"}
		vals = [7]any{v.Email, v.Name, v.Role, "automation", g.request}
		n = 5
	} else {
		return 0, htmlAuditShapeV1{}, ErrHTMLAuditEventV1
	}
	var shape htmlAuditShapeV1
	if err := shape.add(0, 2, 1); err != nil {
		return 0, shape, err
	}
	for i := 0; i < n; i++ {
		if !htmlAuditRootKeyV1(p, keys[i]) {
			return 0, shape, ErrHTMLAuditEventV1
		}
		if err := shape.text(keys[i], true); err != nil {
			return 0, shape, err
		}
		if err := shape.add(0, 2, 1); err != nil {
			return 0, shape, err
		}
		if err := shape.value(ctx, vals[i], 1); err != nil {
			return 0, shape, err
		}
	}
	for _, text := range [...]string{p.KindV1(), g.ip, g.ua} {
		if err := shape.text(text, false); err != nil {
			return 0, shape, err
		}
	}
	if err := shape.add(192, 4096, 16); err != nil {
		return 0, shape, err
	}
	return p, shape, nil
}
func (h *ApplicationSessionV1) NewAutomationAuditsV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1, request *ApplicationAutomationRequestWriterV1, source *ApplicationBlocksTemplateSourceV1, recips *ApplicationAutomationRecipientsV1, user uuid.UUID, ip, ua string) (*ApplicationAutomationAuditsV1, error) {
	if h == nil || h.state == nil || reader == nil || !reader.valid(ctx) || reader.session != h || request == nil || request.state == nil || source == nil || source.state == nil || recips == nil || recips.state == nil {
		return nil, ErrAutomationMaterializationV1
	}
	r, t, parent := request.state, source.state, recips.state
	r.mu.Lock()
	defer r.mu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()
	parent.mu.Lock()
	defer parent.mu.Unlock()
	if !r.validV1(ctx) || r.session != h || r.reader != reader || !r.claimed || r.replayed || r.bound || r.request == nil || r.request.DocumentID.Valid || !t.validV1(ctx) || t.session != h || t.reader != reader || t.template == nil || t.content == nil || t.automationSeed == nil || parent.closed || parent.session != h || parent.reader != reader || parent.doc == nil || parent.doc.SenderID != user || parent.doc.OrgID != r.request.OrgID || parent.doc.TemplateID != (pgtype.UUID{Bytes: t.template.ID, Valid: true}) || parent.next != 0 || parent.audits != nil || len(parent.values) < 1 || len(parent.values) > 50 {
		return nil, ErrAutomationMaterializationV1
	}
	g := &applicationAutomationAuditBatchV1{session: h, reader: reader, header: reader.bodyHeader, callbackDone: ctx.Done(), parent: parent, claim: r, source: t, sourcePin: t.template, request: r.request.ID, template: t.template.ID, user: user, version: t.template.Version, name: parent.doc.Name, digest: t.automationSeed.ContentSHA256, ip: ip, ua: ua, values: parent.values}
	g.self = g
	count := len(parent.values) + 1
	var total htmlAuditShapeV1
	for i := 0; i < count; i++ {
		_, shape, err := g.shapeV1(ctx, i)
		if err != nil {
			return nil, err
		}
		if err = total.add(shape.raw, shape.wire, shape.nodes); err != nil {
			return nil, err
		}
	}
	resources, err := automationAuditBatchResourcesV1(int64(count), total.raw, total.wire, total.nodes)
	if err != nil {
		return nil, err
	}
	s := h.state
	p := s.factory
	if p == nil {
		return nil, ErrAutomationMaterializationV1
	}
	p.mu.Lock()
	s.mu.Lock()
	a := s.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || s.observer || s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) || a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone || !s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrAutomationMaterializationV1
	}
	g.admission = a
	g.budget = ApplicationBudgetV1{Phase: "locked-automation-fresh-events", OrgID: s.org, DocumentID: s.document, HTMLAuditRawBytes: total.raw, HTMLAuditWireBytes: total.wire, HTMLAuditNodes: total.nodes, AutomationAuditEventCount: int64(count), WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes, automationAuditGrant: g}
	parent.audits = g
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	g.close, err = a.admit(ctx, g.budget)
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		parent.audits = nil
		return nil, err
	}
	g.name = strings.Clone(g.name)
	g.digest = strings.Clone(g.digest)
	g.ip = strings.Clone(ip)
	g.ua = strings.Clone(ua)
	g.values = make([]recipients.Values, len(parent.values))
	for i, v := range parent.values {
		g.values[i] = v
		g.values[i].Email = strings.Clone(v.Email)
		g.values[i].Name = strings.Clone(v.Name)
		g.values[i].Role = strings.Clone(v.Role)
		g.values[i].Locale = ""
	}
	g.slots = make([]applicationAutomationAuditSlotV1, count)
	for i := range g.slots {
		purpose, shape, err := g.shapeV1(ctx, i)
		if err != nil {
			g.close()
			g.close = nil
			return nil, err
		}
		g.slots[i] = applicationAutomationAuditSlotV1{batch: g, index: i, purpose: purpose, shape: shape}
		g.slots[i].self = &g.slots[i]
	}
	return &ApplicationAutomationAuditsV1{state: g}, nil
}
func (g *applicationAutomationAuditBatchV1) validBudgetV1(ctx context.Context, work *WorkAdmissionV1, b ApplicationBudgetV1) bool {
	if g == nil || g.self != g || ctx == nil || g.callbackDone == nil || ctx.Done() != g.callbackDone || g.session == nil || g.session.state == nil || g.reader == nil || g.header == nil || g.header.self != g.header || g.header.reader != g.reader || g.header.session != g.session || g.header.admission != g.admission || g.header.closed.Load() || g.parent == nil || g.parent.audits != g || g.parent.session != g.session || g.parent.reader != g.reader || g.parent.doc == nil || g.parent.doc.ID != b.DocumentID || g.claim == nil || g.claim.request == nil || g.claim.request.ID != g.request || g.claim.replayed || g.source == nil || g.source.template != g.sourcePin || g.sourcePin == nil || g.sourcePin.ID != g.template || g.sourcePin.Version != g.version || g.budget != b || b.automationAuditGrant != g || b.AutomationAuditEventCount != int64(len(g.parent.values)+1) {
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
func (slot *applicationAutomationAuditSlotV1) acquireV1(ctx context.Context, h *ApplicationSessionV1, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, shape htmlAuditShapeV1) (func(), error) {
	if slot == nil || slot.self != slot || slot.batch == nil {
		return nil, ErrHTMLAuditEventV1
	}
	g := slot.batch
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.self != g || g.session != h || g.consumerClosed || g.released || g.close == nil || !slot.ready || slot.issued || slot.closed || slot.shape != shape || slot.purpose != purpose || slot.recipient != recipient || actor != (pgtype.UUID{Bytes: g.user, Valid: true}) || org != g.budget.OrgID || document != g.budget.DocumentID || kind != purpose.KindV1() || ip != g.ip || ua != g.ua || ctx.Done() != g.callbackDone || ctx.Value(applicationSessionCallbackKeyV1{}) != h.state {
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
			close := g.releaseIfCompleteV1()
			g.mu.Unlock()
			if close != nil {
				close()
			}
		})
	}, nil
}
func (g *applicationAutomationAuditBatchV1) releaseIfCompleteV1() func() {
	if !g.consumerClosed || g.opened != 0 || g.active != 0 || g.released {
		return nil
	}
	g.released = true
	close := g.close
	g.close = nil
	g.sourcePin = nil
	g.header = nil
	g.parent = nil
	g.claim = nil
	g.source = nil
	g.session = nil
	g.admission = nil
	g.reader = nil
	g.values = nil
	g.name = ""
	g.digest = ""
	g.ip = ""
	g.ua = ""
	return close
}
func (w *ApplicationAutomationAuditsV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	g := w.state
	g.mu.Lock()
	if g.consumerClosed {
		g.mu.Unlock()
		return
	}
	g.consumerClosed = true
	if g.active == 0 {
		g.sourcePin = nil
		g.claim = nil
		g.source = nil
		g.parent = nil
	}
	g.mu.Unlock()
	for i := range g.slots {
		g.mu.Lock()
		owner := g.slots[i].owner
		g.mu.Unlock()
		if owner != nil {
			owner.CloseConsumerV1()
		}
	}
	g.mu.Lock()
	close := g.releaseIfCompleteV1()
	g.mu.Unlock()
	if close != nil {
		close()
	}
}
func (w *ApplicationAutomationAuditsV1) NewNextAuditV1(ctx context.Context) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if w == nil || w.state == nil {
		return nil, ErrAutomationMaterializationV1
	}
	g := w.state
	g.mu.Lock()
	if g.consumerClosed || g.released || g.parent == nil || g.next >= len(g.slots) {
		g.mu.Unlock()
		return nil, ErrAutomationMaterializationV1
	}
	index := g.next
	parent := g.parent
	g.active++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.active--
		if g.consumerClosed && g.active == 0 {
			g.sourcePin = nil
			g.claim = nil
			g.source = nil
			g.parent = nil
		}
		close := g.releaseIfCompleteV1()
		g.mu.Unlock()
		if close != nil {
			close()
		}
	}()
	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.closed || parent.next != index {
		return nil, ErrAutomationMaterializationV1
	}
	recipient := pgtype.UUID{}
	var payload map[string]any
	if index == 0 {
		payload = map[string]any{"name": g.name, "source_kind": "blocks", "via": "automation", "automation_request_id": g.request, "template_id": g.template, "template_version": g.version, "template_content_sha256": g.digest}
	} else {
		if len(parent.rows) != 2*index {
			return nil, ErrAutomationMaterializationV1
		}
		row := parent.rows[2*index-1]
		v := g.values[index-1]
		if row == nil || row.ID == uuid.Nil || row.DocumentID != g.budget.DocumentID || row.Email != v.Email || row.Name != v.Name || row.Role != v.Role {
			return nil, ErrAutomationMaterializationV1
		}
		recipient = pgtype.UUID{Bytes: row.ID, Valid: true}
		payload = map[string]any{"email": v.Email, "name": v.Name, "role": v.Role, "via": "automation", "automation_request_id": g.request}
	}
	slot := &g.slots[index]
	g.mu.Lock()
	if g.consumerClosed || g.next != index {
		g.mu.Unlock()
		return nil, ErrAutomationMaterializationV1
	}
	slot.ready = true
	slot.recipient = recipient
	g.mu.Unlock()
	owner, err := g.session.newAutomationHTMLAuditEventV1(ctx, slot.purpose, g.budget.OrgID, g.budget.DocumentID, recipient, pgtype.UUID{Bytes: g.user, Valid: true}, slot.purpose.KindV1(), g.ip, g.ua, payload, slot)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	slot.owner = owner
	g.next++
	closed := g.consumerClosed
	g.mu.Unlock()
	if closed {
		owner.CloseConsumerV1()
		return nil, ErrAutomationMaterializationV1
	}
	return owner, nil
}
