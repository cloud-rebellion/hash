// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This private fixed token exists only after the SAME actual measured catalog
// header and row lock. It prices the unchanged full bool-feature policy before
// its parser; it grants no plan, subscription, quota or tenant authority.
type applicationHTMLSendPlanPolicyGrantV1 struct {
	self         *applicationHTMLSendPlanPolicyGrantV1
	owner        *ApplicationHTMLSendWorkV1
	reader       *htmlSendOrgSourceReadsV1
	session      *applicationOwnedSessionV1
	admission    *ApplicationAdmissionV1
	work         *WorkAdmissionV1
	bodyHeader   *applicationHTMLAuthoringBodyHeaderV1
	callbackDone <-chan struct{}
	plan         uuid.UUID
	created      pgtype.Timestamptz
	wire         int64
	server       int32
	parent       int64
}

func (g *applicationHTMLSendPlanPolicyGrantV1) validBudgetV1(ctx context.Context, a *WorkAdmissionV1, b ApplicationBudgetV1) bool {
	if g == nil || g.self != g || g.owner == nil || g.owner.self != g.owner || g.reader == nil || g.reader.work != g.owner || !g.reader.planPolicyStarted || g.reader.ctx != ctx || g.owner.session == nil || g.owner.session.state != g.session || g.session == nil || g.admission == nil || g.session.factory == nil || g.session.factory.work != a || g.work != a || g.admission.fence != g.session.fence || g.callbackDone == nil || ctx == nil || ctx.Done() != g.callbackDone || ctx.Value(applicationSessionCallbackKeyV1{}) != g.session || g.plan == uuid.Nil || g.wire < 0 || g.server <= 0 {
		return false
	}
	select {
	case <-g.callbackDone:
		return false
	default:
	}
	h := g.bodyHeader
	if h == nil || h.self != h || h.closed.Load() || h.reader == nil || h.reader.self != h.reader || h.reader.bodyHeader != h || h.session != g.owner.session || h.admission != g.admission || h.fence != g.session.fence || h.loanClose == nil {
		return false
	}
	parent, err := htmlSendPlanFeaturesLogicalV1(g.wire)
	if err != nil || parent != g.parent || parent <= 0 {
		return false
	}
	expected := ApplicationBudgetV1{Phase: "locked-html-send-plan-policy", OrgID: g.session.org, DocumentID: g.session.document, WorkingBytes: parent, htmlSendPlanPolicyGrant: g}
	return b == expected
}

// Called ONLY by readPlanV1 immediately after the genuine M95 header, before
// actual full-row expansion and the unchanged policy's JSON map validation.
func (w *ApplicationHTMLSendWorkV1) holdPlanPolicyV1(ctx context.Context, id uuid.UUID, created pgtype.Timestamptz, wire int64, server int32, reads *htmlSendOrgSourceReadsV1) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || id == uuid.Nil || wire < 0 || server <= 0 || reads == nil || reads.work != w || reads.ctx != ctx || reads.planPolicyStarted {
		return ErrHTMLSendWorkV1
	}
	// One original plan-policy invocation belongs to each genuine quota reader
	// or actual admitted org.plan binding fetch. A guessed Work-wide count must
	// not reject a second valid binding, nor permit repeated use of one reader.
	quota := reads.quota == w && w.quotaAttempted && w.stage != nil && w.stage.purpose == HTMLSendPreparationV1 && !w.sourceStarted && !w.recipientsAttempted && !w.bindingsAttempted
	source := reads.quota == nil && reads.planSource && reads.owner != nil && reads.owner == w.resolverOwner && reads.owner.work == w && reads.source != nil && reads.source == w.sourceState && reads.source.work == w && reads.source.owner == w.sourceOwner && reads.owner.source == reads.source && !reads.source.closeRequested.Load()
	if !quota && !source {
		return ErrHTMLSendWorkV1
	}
	reads.planPolicyStarted = true
	parent, err := htmlSendPlanFeaturesLogicalV1(wire)
	if err != nil {
		return err
	}
	s := w.session.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	a := s.admission
	if p.closing || p.work == nil || p.htmlAdmissions == nil || s.closed || s.unknown || s.ended || s.retired || s.observer || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) || a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone || !s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	g := &applicationHTMLSendPlanPolicyGrantV1{owner: w, reader: reads, session: s, admission: a, work: p.work, bodyHeader: w.actor.bodyHeader, callbackDone: ctx.Done(), plan: id, created: created, wire: wire, server: server, parent: parent}
	g.self = g
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	close, err := a.admit(ctx, ApplicationBudgetV1{Phase: "locked-html-send-plan-policy", OrgID: s.org, DocumentID: s.document, WorkingBytes: parent, htmlSendPlanPolicyGrant: g})
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, close)
	return nil
}
