// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This collection derives only the actual private completion Work's fixed
// package events. Its one native admission loan sums every original event cost;
// each event still owns its real append/publication consumer. Counts, JSON,
// actor authority and reported costs cannot be supplied through a public API.
type applicationPackageSendAuditBatchV1 struct {
	mu                                                                       sync.Mutex
	self                                                                     *applicationPackageSendAuditBatchV1
	work                                                                     *ApplicationHTMLSendWorkV1
	plan                                                                     *applicationPackageSendRetentionPlanV1
	operation                                                                *ApplicationHTMLSendOperationV1
	session                                                                  *ApplicationSessionV1
	admission                                                                *ApplicationAdmissionV1
	intent                                                                   *generated.SendSealingIntent
	callbackDone                                                             <-chan struct{}
	observation                                                              HTMLSendPackageAttemptObservationV1
	budget                                                                   ApplicationBudgetV1
	slots                                                                    []applicationPackageSendAuditSlotV1
	close                                                                    func()
	actor                                                                    pgtype.UUID
	ip, attemptText, packageText, revisionText, manifestText, commitmentText string
	basis, retainText, noticeText                                            string
	recipientCount, eventCount, next, opened, active                         int
	aborting, noInvite, opening, consumerClosed, released                    bool
}
type applicationPackageSendAuditSlotV1 struct {
	self                  *applicationPackageSendAuditSlotV1
	batch                 *applicationPackageSendAuditBatchV1
	index                 int
	purpose               HTMLAuditPurposeV1
	recipient             pgtype.UUID
	email, role           string
	shape                 htmlAuditShapeV1
	owner                 *ApplicationHTMLAuditEventConsumerV1
	ready, issued, closed bool
}

func packageSendAuditBatchResourcesV1(events, raw, wire, nodes int64) (ApplicationRequestPayloadResourcesV1, error) {
	var empty ApplicationRequestPayloadResourcesV1
	if events < 1 || events > math.MaxInt64/2 || raw < 0 || wire < 2*events || nodes < events {
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
	if !htmlInputAddV1(&parent, wire, 16) || !htmlInputAddV1(&parent, raw, 16) || !htmlInputAddV1(&parent, nodes, 256) || !htmlInputAddV1(&parent, 2, int64(unsafe.Sizeof(applicationPackageSendAuditBatchV1{}))) || !htmlInputAddV1(&parent, events, 2*int64(unsafe.Sizeof(applicationPackageSendAuditSlotV1{}))) {
		return empty, workguard.ErrUnavailableV1
	}
	return ApplicationRequestPayloadResourcesV1{WorkingBytes: parent, DBStagingBytes: db}, nil
}

// Fixed arrays let the first pass measure the actual schema without allocating
// recipient-sized maps, slots or payload copies before aggregate admission.
func (g *applicationPackageSendAuditBatchV1) fieldsV1(index int) (HTMLAuditPurposeV1, pgtype.UUID, [16]string, [16]any, int, error) {
	var keys [16]string
	var values [16]any
	if g == nil || index < 0 || index >= g.eventCount {
		return 0, pgtype.UUID{}, keys, values, 0, ErrHTMLAuditEventV1
	}
	keys = [16]string{"package_send_schema", "package_send_attempt_id", "package_id", "capture_revision", "manifest_sha256", "legal_commitment_sha256"}
	values = [16]any{"hash-package-send-v1", g.attemptText, g.packageText, g.revisionText, g.manifestText, g.commitmentText}
	n := 6
	purpose, recipient := HTMLAuditPackageDocumentSentV1, pgtype.UUID{}
	if g.aborting {
		purpose = HTMLAuditPackageSendAbortedV1
		keys[n], values[n] = "reason", "expiry_before_retention"
		n++
	} else if !g.noInvite && index < g.recipientCount {
		purpose = HTMLAuditPackageRecipientInvitedV1
		var email, role string
		if g.slots != nil {
			slot := &g.slots[index]
			recipient, email, role = slot.recipient, slot.email, slot.role
		} else {
			if g.work == nil || index >= len(g.work.sourceRecipients) || g.work.sourceRecipients[index] == nil {
				return 0, recipient, keys, values, 0, ErrHTMLAuditEventV1
			}
			row := g.work.sourceRecipients[index]
			recipient, email, role = pgtype.UUID{Bytes: row.ID, Valid: true}, row.Email, row.Role
		}
		keys[n], values[n] = "email", email
		keys[n+1], values[n+1] = "role", role
		n += 2
	} else if g.noInvite && index == 1 {
		purpose = HTMLAuditPackageDocumentExpiredV1
		keys[n], values[n] = "before_invite", true
		keys[n+1], values[n+1] = "irreversible_sealing_recovery", true
		n += 2
	} else {
		for _, pair := range [7]struct {
			key   string
			value any
		}{
			{"recipient_count", g.recipientCount}, {"evidence_retained", true}, {"lawful_basis", g.basis}, {"lawful_basis_confirmed", true}, {"retain_until", g.retainText}, {article13.AuditRequiredNoticeSchemaKey, "hash-a13-2026-08-31"}, {article13.AuditRequiredNoticeSentAtKey, g.noticeText},
		} {
			keys[n], values[n] = pair.key, pair.value
			n++
		}
		if g.noInvite {
			keys[n], values[n] = "expired_before_invite", true
			n++
		}
	}
	return purpose, recipient, keys, values, n, nil
}
func (g *applicationPackageSendAuditBatchV1) shapeV1(ctx context.Context, index int) (HTMLAuditPurposeV1, pgtype.UUID, htmlAuditShapeV1, error) {
	purpose, recipient, keys, values, n, err := g.fieldsV1(index)
	var shape htmlAuditShapeV1
	if err != nil {
		return 0, recipient, shape, err
	}
	if err = shape.add(0, 2, 1); err != nil {
		return 0, recipient, shape, err
	}
	for i := 0; i < n; i++ {
		if !htmlAuditRootKeyV1(purpose, keys[i]) {
			return 0, recipient, shape, ErrHTMLAuditEventV1
		}
		if err = shape.text(keys[i], true); err != nil {
			return 0, recipient, shape, err
		}
		if err = shape.add(0, 2, 1); err != nil {
			return 0, recipient, shape, err
		}
		if err = shape.value(ctx, values[i], 1); err != nil {
			return 0, recipient, shape, err
		}
	}
	for _, text := range [...]string{purpose.KindV1(), g.ip, ""} {
		if err = shape.text(text, false); err != nil {
			return 0, recipient, shape, err
		}
	}
	if err = shape.add(192, 4096, 16); err != nil {
		return 0, recipient, shape, err
	}
	return purpose, recipient, shape, nil
}

func (w *ApplicationHTMLSendWorkV1) newPackageSendAuditsV1(ctx context.Context, plan *applicationPackageSendRetentionPlanV1, aborting bool) (*applicationPackageSendAuditBatchV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.packageCompletionScopeV1(ctx, plan) || w.packageAudits != nil || plan.completionControls == nil || w.sourceIntent == nil || !packageCompletionIntentMatchesV1(w.sourceIntent, plan) {
		return nil, ErrHTMLSendWorkV1
	}
	noInvite := false
	if aborting {
		if !plan.current.RetentionStartedAt.IsZero() || ValidateSendExpiryV1(w.state.ExpiresAt, time.Now()) == nil {
			return nil, ErrHTMLSendWorkV1
		}
	} else {
		if w.packageCompletion == nil || w.packageCompletion.plan != plan || w.sourceDocument == nil || len(w.sourceRecipients) == 0 || plan.completionRecipientCount != len(w.sourceRecipients) {
			return nil, ErrHTMLSendWorkV1
		}
		expired, err := w.queries.IsSendSealingExpired(ctx, generated.IsSendSealingExpiredParams{ID: plan.entry.document, OrgID: plan.entry.org})
		if err != nil {
			return nil, err
		}
		noInvite = expired.Valid && expired.Bool
	}
	// This bounded typed constructor and its format strings are prepaid by the
	// plan's original completion-controls loan. The aggregate below precedes every
	// scalable slot allocation and every event payload map/copy.
	c := plan.current.Capture
	g := &applicationPackageSendAuditBatchV1{work: w, plan: plan, operation: w.stage.operation, session: w.session, intent: w.sourceIntent, callbackDone: ctx.Done(), observation: plan.current, actor: w.sourceIntent.ActorUserID, ip: w.sourceIntent.ActorIp, aborting: aborting, noInvite: noInvite,
		attemptText: plan.entry.attempt.String(), packageText: c.PackageID.String(), revisionText: strconv.FormatInt(c.Revision, 10), manifestText: hex.EncodeToString(c.CanonicalSHA256[:]), commitmentText: hex.EncodeToString(c.CommitmentSHA256[:]), retainText: plan.current.RetainUntil.UTC().Format(time.RFC3339), noticeText: plan.current.Article13NoticeEpochAt.UTC().Format(time.RFC3339Nano)}
	g.self = g
	if !aborting {
		g.basis = w.sourceDocument.LawfulBasis
	}
	g.eventCount = 1
	if !aborting && noInvite {
		g.eventCount = 2
	} else if !aborting {
		g.recipientCount = len(w.sourceRecipients)
		g.eventCount += g.recipientCount
	}
	var total htmlAuditShapeV1
	for i := 0; i < g.eventCount; i++ {
		_, _, shape, err := g.shapeV1(ctx, i)
		if err != nil {
			return nil, err
		}
		if err = total.add(shape.raw, shape.wire, shape.nodes); err != nil {
			return nil, err
		}
	}
	resources, err := packageSendAuditBatchResourcesV1(int64(g.eventCount), total.raw, total.wire, total.nodes)
	if err != nil {
		return nil, err
	}
	s := w.session.state
	p := s.factory
	if p == nil {
		return nil, ErrHTMLSendWorkV1
	}
	p.mu.Lock()
	s.mu.Lock()
	a := s.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || s.observer || s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed || s.org != plan.entry.org || s.document != plan.entry.document || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) || a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone || !s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	g.admission = a
	g.budget = ApplicationBudgetV1{Phase: "locked-package-send-fresh-events", OrgID: s.org, DocumentID: s.document, HTMLAuditRawBytes: total.raw, HTMLAuditWireBytes: total.wire, HTMLAuditNodes: total.nodes, PackageSendAuditEventCount: int64(g.eventCount), WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes, packageSendAuditGrant: g}
	w.packageAudits = g
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	g.close, err = a.admit(ctx, g.budget)
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		w.packageAudits = nil
		return nil, err
	}
	w.closes = append(w.closes, g.closeConsumerV1)
	g.ip, g.basis = strings.Clone(g.ip), strings.Clone(g.basis)
	g.slots = make([]applicationPackageSendAuditSlotV1, g.eventCount)
	for i := range g.slots {
		if !aborting && !noInvite && i < g.recipientCount {
			row := w.sourceRecipients[i]
			g.slots[i].recipient = pgtype.UUID{Bytes: row.ID, Valid: true}
			g.slots[i].email, g.slots[i].role = strings.Clone(row.Email), strings.Clone(row.Role)
		}
		purpose, recipient, shape, e := g.shapeV1(ctx, i)
		if e != nil {
			g.closeConsumerV1()
			return nil, e
		}
		slot := &g.slots[i]
		slot.self, slot.batch, slot.index, slot.purpose, slot.recipient, slot.shape = slot, g, i, purpose, recipient, shape
	}
	return g, nil
}

// Admission calls this under the genuine factory/session/Work locks. It may
// inspect those same private registrations without recursively reacquiring them.
func (g *applicationPackageSendAuditBatchV1) validBudgetV1(ctx context.Context, work *WorkAdmissionV1, b ApplicationBudgetV1) bool {
	if g == nil || g.self != g || ctx == nil || ctx.Err() != nil || g.callbackDone == nil || ctx.Done() != g.callbackDone || g.work == nil || g.work.self != g.work || g.work.packageAudits != g || g.work.session != g.session || g.work.stage == nil || g.work.stage.purpose != HTMLSendCompletionV1 || g.work.stage.operation != g.operation || g.operation == nil || g.operation.self != g.operation || g.plan == nil || g.plan.current != g.observation || g.work.sourceIntent != g.intent || !packageCompletionIntentMatchesV1(g.intent, g.plan) || g.session == nil || g.session.state == nil || g.budget != b || b.packageSendAuditGrant != g || b.PackageSendAuditEventCount != int64(g.eventCount) || g.eventCount < 1 || g.plan.completionControls == nil {
		return false
	}
	if g.aborting {
		if g.eventCount != 1 || g.recipientCount != 0 || !g.observation.RetentionStartedAt.IsZero() {
			return false
		}
	} else if g.work.packageCompletion == nil || g.work.packageCompletion.plan != g.plan || g.plan.completionRecipientCount != len(g.work.sourceRecipients) || (g.noInvite && (g.eventCount != 2 || g.recipientCount != 0)) || (!g.noInvite && (g.recipientCount != len(g.work.sourceRecipients) || g.eventCount != g.recipientCount+1)) {
		return false
	}
	s := g.session.state
	if s.factory == nil || s.factory.work != work || s.admission != g.admission || g.admission == nil || g.admission.fence != s.fence || ctx.Value(applicationSessionCallbackKeyV1{}) != s || s.org != b.OrgID || s.document != b.DocumentID || g.operation.factory == nil || g.operation.factory.state != s.factory || g.plan.batch == nil {
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
func (slot *applicationPackageSendAuditSlotV1) acquireV1(ctx context.Context, h *ApplicationSessionV1, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, shape htmlAuditShapeV1) (func(), error) {
	if slot == nil || slot.self != slot || slot.batch == nil || ctx == nil || h == nil || h.state == nil {
		return nil, ErrHTMLAuditEventV1
	}
	g := slot.batch
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.self != g || g.session != h || g.consumerClosed || g.released || g.close == nil || slot.index < 0 || slot.index >= len(g.slots) || &g.slots[slot.index] != slot || !g.opening || !slot.ready || slot.issued || slot.closed || slot.index != g.next || slot.shape != shape || slot.purpose != purpose || slot.recipient != recipient || actor != g.actor || org != g.budget.OrgID || document != g.budget.DocumentID || kind != purpose.KindV1() || ip != g.ip || ua != "" || ctx.Done() != g.callbackDone || ctx.Value(applicationSessionCallbackKeyV1{}) != h.state {
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
func (g *applicationPackageSendAuditBatchV1) clearInputsLockedV1() {
	if !g.consumerClosed || g.active != 0 {
		return
	}
	g.work, g.plan, g.operation, g.intent = nil, nil, nil, nil
	g.ip, g.basis, g.attemptText, g.packageText, g.revisionText, g.manifestText, g.commitmentText, g.retainText, g.noticeText = "", "", "", "", "", "", "", "", ""
	for i := range g.slots {
		g.slots[i].email, g.slots[i].role = "", ""
	}
}
func (g *applicationPackageSendAuditBatchV1) releaseIfCompleteV1() func() {
	g.clearInputsLockedV1()
	if !g.consumerClosed || g.opened != 0 || g.active != 0 || g.released {
		return nil
	}
	g.released = true
	close := g.close
	g.close = nil
	g.session, g.admission = nil, nil
	g.slots = nil
	g.budget = ApplicationBudgetV1{}
	return close
}
func (g *applicationPackageSendAuditBatchV1) closeConsumerV1() {
	if g == nil || g.self != g {
		return
	}
	g.mu.Lock()
	if g.consumerClosed {
		g.mu.Unlock()
		return
	}
	g.consumerClosed = true
	g.active++
	count := len(g.slots)
	g.mu.Unlock()
	for i := 0; i < count; i++ {
		g.mu.Lock()
		owner := g.slots[i].owner
		g.mu.Unlock()
		if owner != nil {
			owner.CloseConsumerV1()
		}
	}
	g.mu.Lock()
	g.active--
	close := g.releaseIfCompleteV1()
	g.mu.Unlock()
	if close != nil {
		close()
	}
}
func (g *applicationPackageSendAuditBatchV1) newNextV1(ctx context.Context, purpose HTMLAuditPurposeV1, recipient uuid.UUID) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if g == nil || g.self != g || ctx == nil || ctx.Err() != nil {
		return nil, ErrHTMLAuditEventV1
	}
	g.mu.Lock()
	if g.consumerClosed || g.released || g.opening || g.close == nil || g.next >= len(g.slots) || ctx.Done() != g.callbackDone || g.session == nil || ctx.Value(applicationSessionCallbackKeyV1{}) != g.session.state {
		g.mu.Unlock()
		return nil, ErrHTMLAuditEventV1
	}
	slot := &g.slots[g.next]
	rec := pgtype.UUID{Bytes: recipient, Valid: recipient != uuid.Nil}
	if slot.purpose != purpose || slot.recipient != rec || slot.ready || slot.issued || slot.closed {
		g.mu.Unlock()
		return nil, ErrHTMLAuditEventV1
	}
	g.active++
	g.opening = true
	slot.ready = true
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.active--
		g.opening = false
		close := g.releaseIfCompleteV1()
		g.mu.Unlock()
		if close != nil {
			close()
		}
	}()
	actual, actualRecipient, keys, values, n, err := g.fieldsV1(slot.index)
	if err != nil || actual != purpose || actualRecipient != rec {
		return nil, ErrHTMLAuditEventV1
	}
	payload := make(map[string]any, n)
	for i := 0; i < n; i++ {
		payload[keys[i]] = values[i]
	}
	// Only this fixed producer calls the common native core with a package slot.
	owner, err := g.session.newHTMLAuditEventCoreV1(ctx, purpose, g.budget.OrgID, g.budget.DocumentID, rec, g.actor, purpose.KindV1(), g.ip, "", payload, nil, nil, nil, slot)
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
		return nil, ErrHTMLAuditEventV1
	}
	return owner, nil
}
