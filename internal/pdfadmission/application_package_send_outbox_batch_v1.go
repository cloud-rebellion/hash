// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
)

// One actual private completion Work owns this collection. Each slot is derived
// from its immutable recipient and the original fixed invitation renderer; no
// caller count, message, token, row ID or byte declaration creates a reservation.
// The single native admission retains every original per-row return cost until
// this Work consumer and its original physical SQL fence have both retired.
type applicationPackageSendOutboxBatchV1 struct {
	self         *applicationPackageSendOutboxBatchV1
	parent       *ApplicationHTMLSendWorkV1
	plan         *applicationPackageSendRetentionPlanV1
	operation    *ApplicationHTMLSendOperationV1
	intent       *generated.SendSealingIntent
	observation  HTMLSendPackageAttemptObservationV1
	outputs      *htmlSendCompletionOutputsV1
	session      *ApplicationSessionV1
	header       *applicationHTMLAuthoringBodyHeaderV1
	admission    *ApplicationAdmissionV1
	callbackDone <-chan struct{}
	budget       ApplicationBudgetV1
	count, raw   int64
	slots        []applicationPackageSendOutboxSlotV1
	close        func()
}
type applicationPackageSendOutboxShapeV1 struct{ raw, subject, html, text int64 }

// The fixed renderer supplies conservative component bounds. Exact message
// identity and actual returned-row equality are checked separately at enqueue.
func (s applicationPackageSendOutboxShapeV1) coversV1(raw int64, msg dispatch.Message) bool {
	return s.raw >= 0 && s.subject >= 0 && s.html >= 0 && s.text >= 0 && raw >= 0 && raw <= s.raw && int64(len(msg.Subject)) <= s.subject && int64(len(msg.HTML)) <= s.html && int64(len(msg.Text)) <= s.text
}

type applicationPackageSendOutboxSlotV1 struct {
	self      *applicationPackageSendOutboxSlotV1
	batch     *applicationPackageSendOutboxBatchV1
	recipient *generated.Recipient
	index     int
	shape     applicationPackageSendOutboxShapeV1
	issued    bool
}

// This is the sum of the ORIGINAL per-row body reservations, including each
// row's fixed DB staging cost. Aggregating the loan does not amortize that cost.
// Typed collection storage is additive and allocated only after this grant.
func packageSendOutboxBatchResourcesV1(count, raw int64) (ApplicationRequestPayloadResourcesV1, error) {
	var empty ApplicationRequestPayloadResourcesV1
	if count < 1 || raw < 0 {
		return empty, ErrHTMLSendWorkV1
	}
	one, err := htmlAuthoringRetainedBodyResourcesV1(0, 2)
	if err != nil {
		return empty, err
	}
	parent, db := int64(0), int64(0)
	for _, part := range [][2]int64{{count, one.WorkingBytes}, {raw, 8}, {1, 8 * int64(unsafe.Sizeof(applicationPackageSendOutboxBatchV1{}))}, {count, 8 * int64(unsafe.Sizeof(applicationPackageSendOutboxSlotV1{}))}} {
		if err = htmlSendResolverAddV1(&parent, part[0], part[1]); err != nil {
			return empty, err
		}
	}
	if err = htmlSendResolverAddV1(&db, count, one.DBStagingBytes); err != nil {
		return empty, err
	}
	return ApplicationRequestPayloadResourcesV1{WorkingBytes: parent, DBStagingBytes: db}, nil
}

// Caller holds the same Work mutex. The placeholder has the exact original
// 43-character token alphabet/length and the same escaping as the generated token.
func (w *ApplicationHTMLSendWorkV1) packageSendOutboxShapeV1(outputs *htmlSendCompletionOutputsV1, index int) (applicationPackageSendOutboxShapeV1, error) {
	var empty applicationPackageSendOutboxShapeV1
	if outputs == nil || w.sourceDocument == nil || w.sourceIntent == nil || index < 0 || index >= len(w.sourceRecipients) || index >= len(outputs.recipients) {
		return empty, ErrHTMLSendWorkV1
	}
	r := w.sourceRecipients[index]
	if r == nil || r.ID == uuid.Nil || r.DocumentID != w.sourceDocument.ID || outputs.recipients[index].id != r.ID {
		return empty, ErrHTMLSendWorkV1
	}
	signURL := outputs.publicURL + "/sign/" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	beaconURL := outputs.publicURL + "/e/o/" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	subject, html, text, err := dispatch.InviteNotificationComponentsV1(dispatch.TemplateContext{DocumentName: w.sourceDocument.Name, SenderName: w.sourceIntent.ActorEmail, SenderEmail: w.sourceIntent.ActorEmail, RecipientName: r.Name, OrgName: outputs.orgName, Locale: r.Locale, SignURL: signURL, BeaconURL: beaconURL, Acknowledgement: !w.sourceDocument.RequiresSignature})
	if err != nil {
		return empty, err
	}
	raw, err := htmlAuthoringSumV1(int64(len(r.Email)), subject, html, text, int64(len(w.sourceIntent.ActorEmail)), int64(len(outputs.orgName)), int64(len("pending")))
	if err != nil {
		return empty, err
	}
	return applicationPackageSendOutboxShapeV1{raw: raw, subject: subject, html: html, text: text}, nil
}

// The fixed owner itself is prepaid by PrepareCompletionOutputsV1's initial
// native body loan. This constructor acquires the collection through the SAME
// native admission before creating any scalable slot storage.
func (w *ApplicationHTMLSendWorkV1) preparePackageSendOutboxBatchV1(call context.Context) error {
	if w.packageCompletion == nil || w.completionOutputs == nil || w.completionOutputs.packageOutbox != nil {
		return ErrHTMLSendWorkV1
	}
	plan, outputs := w.packageCompletion.plan, w.completionOutputs
	if !w.packageCompletionScopeV1(call, plan) || plan.completion == nil || outputs.publicURL != plan.completion.PublicURL || outputs.orgName != plan.completion.OrgName || len(outputs.recipients) != len(w.sourceRecipients) {
		return ErrHTMLSendWorkV1
	}
	count, raw := int64(len(w.sourceRecipients)), int64(0)
	for i := range w.sourceRecipients {
		if call.Err() != nil {
			return ErrHTMLSendWorkV1
		}
		shape, err := w.packageSendOutboxShapeV1(outputs, i)
		if err != nil {
			return err
		}
		if err = htmlSendResolverAddV1(&raw, 1, shape.raw); err != nil {
			return err
		}
	}
	resources, err := packageSendOutboxBatchResourcesV1(count, raw)
	if err != nil {
		return err
	}
	h := w.session
	s := h.state
	p := s.factory
	if p == nil || w.actor == nil {
		return ErrHTMLSendWorkV1
	}
	g := &applicationPackageSendOutboxBatchV1{parent: w, plan: plan, operation: w.stage.operation, intent: w.sourceIntent, observation: plan.current, outputs: outputs, session: h, header: w.actor.bodyHeader, callbackDone: call.Done(), count: count, raw: raw}
	g.self = g
	outputs.packageOutbox = g
	p.mu.Lock()
	s.mu.Lock()
	a := s.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || s.observer || s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) || a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone || !s.callbackActive || call.Value(applicationSessionCallbackKeyV1{}) != s || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	g.admission = a
	g.budget = ApplicationBudgetV1{Phase: "locked-package-send-outbox-returns", OrgID: s.org, DocumentID: s.document, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes, packageSendOutboxGrant: g}
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	g.close, err = a.admit(call, g.budget)
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	// Closing this consumer never releases the original admission's SQL fence.
	w.closes = append(w.closes, g.close)
	g.slots = make([]applicationPackageSendOutboxSlotV1, len(w.sourceRecipients))
	for i, r := range w.sourceRecipients {
		shape, e := w.packageSendOutboxShapeV1(outputs, i)
		if e != nil {
			return e
		}
		g.slots[i] = applicationPackageSendOutboxSlotV1{batch: g, recipient: r, index: i, shape: shape}
		g.slots[i].self = &g.slots[i]
	}
	return nil
}

// Admission inspects only this immutable private proof while its original Work,
// factory and session locks are held. Public budget fields cannot create it.
func (g *applicationPackageSendOutboxBatchV1) validBudgetV1(ctx context.Context, work *WorkAdmissionV1, b ApplicationBudgetV1) bool {
	if g == nil || g.self != g || g.parent == nil || g.plan == nil || g.outputs == nil || g.session == nil || g.session.state == nil || ctx == nil || ctx.Err() != nil || g.callbackDone == nil || ctx.Done() != g.callbackDone || g.budget != b || b.packageSendOutboxGrant != g || b.AdmissionID != uuid.Nil || g.parent.self != g.parent || g.parent.session != g.session || g.parent.stage == nil || g.parent.stage.purpose != HTMLSendCompletionV1 || g.parent.stage.operation != g.operation || g.operation == nil || g.operation.self != g.operation || g.plan.current != g.observation || g.parent.sourceIntent != g.intent || !packageCompletionIntentMatchesV1(g.intent, g.plan) || g.plan.completionControls == nil || g.plan.completionRecipientCount != len(g.parent.sourceRecipients) || g.parent.actor == nil || g.parent.actor.bodyHeader != g.header || g.parent.packageCompletion == nil || g.parent.packageCompletion.plan != g.plan || g.parent.completionOutputs != g.outputs || g.outputs.packageOutbox != g || g.count != int64(len(g.parent.sourceRecipients)) || g.count != int64(len(g.outputs.recipients)) || g.header == nil || g.header.self != g.header || g.header.reader != g.parent.actor || g.header.session != g.session || g.header.admission != g.admission || g.header.closed.Load() {
		return false
	}
	select {
	case <-g.callbackDone:
		return false
	default:
	}
	resources, err := packageSendOutboxBatchResourcesV1(g.count, g.raw)
	if err != nil || resources.WorkingBytes != b.WorkingBytes || resources.DBStagingBytes != b.DBStagingBytes {
		return false
	}
	s := g.session.state
	if s.factory == nil || s.factory.work != work || s.admission != g.admission || g.admission == nil || g.admission.fence != s.fence || g.header.fence != s.fence || g.header.loanClose == nil || ctx.Value(applicationSessionCallbackKeyV1{}) != s || s.org != b.OrgID || s.document != b.DocumentID || g.operation.factory == nil || g.operation.factory.state != s.factory || g.plan.batch == nil {
		return false
	}
	batch := g.plan.batch
	batch.mu.Lock()
	bound := batch.active && !batch.closed && !batch.released && batch.retention == g.plan && batch.operation == g.operation && batch.next > 0 && batch.next <= batch.count && batch.entries[batch.next-1] == g.plan.entry
	batch.mu.Unlock()
	if !bound {
		return false
	}
	for _, registered := range s.factory.packageRecoveryBatches {
		if registered == batch {
			return true
		}
	}
	return false
}

// Called only after the original exact generated-message comparison, under the
// same Work mutex. A slot authorizes one return for its actual recipient item.
func (g *applicationPackageSendOutboxBatchV1) consumeV1(call context.Context, w *ApplicationHTMLSendWorkV1, item *htmlSendCompletionRecipientV1, msg dispatch.Message, raw int64) error {
	if g == nil || w == nil || g.parent != w || w.session == nil || w.session.state == nil || w.session.state.factory == nil || g.outputs == nil || g.close == nil || len(g.slots) != len(g.outputs.recipients) {
		return ErrHTMLSendWorkV1
	}
	s := w.session.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	valid := g.validBudgetV1(call, p.work, g.budget)
	s.mu.Unlock()
	p.mu.Unlock()
	if !valid || !w.packageCompletionScopeV1(call, g.plan) {
		return ErrHTMLSendWorkV1
	}
	for i := range g.outputs.recipients {
		if &g.outputs.recipients[i] != item {
			continue
		}
		slot := &g.slots[i]
		r := slot.recipient
		if slot.self != slot || slot.batch != g || slot.index != i || slot.issued || r == nil || r != w.sourceRecipients[i] || r.ID != item.id || r.DocumentID != g.budget.DocumentID || !item.attempted || !item.rendered || !item.enqueued || item.outboxID != uuid.Nil || len(item.token) != 43 || !slot.shape.coversV1(raw, msg) || len(msg.Headers) != 0 || msg.To != r.Email || msg.ReplyTo != w.sourceIntent.ActorEmail || msg.FromName != g.outputs.orgName {
			return ErrHTMLSendWorkV1
		}
		slot.issued = true
		return nil
	}
	return ErrHTMLSendWorkV1
}
