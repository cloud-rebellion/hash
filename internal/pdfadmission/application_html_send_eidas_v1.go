// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/google/uuid"
	"time"
	"unsafe"
)

type applicationHTMLSendEIDASGrantV1 struct {
	self                 *applicationHTMLSendEIDASGrantV1
	owner                *ApplicationHTMLSendWorkV1
	session              *applicationOwnedSessionV1
	admission            *ApplicationAdmissionV1
	work                 *WorkAdmissionV1
	bodyHeader           *applicationHTMLAuthoringBodyHeaderV1
	actor                *ApplicationHTMLAuthoringReaderV1
	callbackDone         <-chan struct{}
	org, document        uuid.UUID
	header               generated.GetActiveEIDASRuleSetHeaderV1Row
	parentBytes, dbBytes int64
}

func htmlSendEIDASReadResourcesV1(h generated.GetActiveEIDASRuleSetHeaderV1Row) (int64, int64, error) {
	if h.OrgID == uuid.Nil || h.RuleCount < 0 || h.MeasuredRuleCount != h.RuleCount || h.RawTextBytes < 0 || h.PredicateWireBytes < 0 || h.ServerVersionNum <= 0 || h.MeasurementServerVersionNum != h.ServerVersionNum {
		return 0, 0, ErrHTMLSendWorkV1
	}
	r, err := htmlAuthoringRetainedBodyResourcesV1(h.RawTextBytes, h.PredicateWireBytes)
	if err != nil {
		return 0, 0, err
	}
	parent, db := r.WorkingBytes, r.DBStagingBytes
	if !htmlInputAddV1(&parent, h.RuleCount, 2*(int64(unsafe.Sizeof(generated.EidasRoutingRule{}))+int64(unsafe.Sizeof(generated.EidasRuleWireSizesV1{}))+16)) || !htmlInputAddV1(&db, h.RuleCount, 64) {
		return 0, 0, ErrHTMLSendWorkV1
	}
	return parent, db, nil
}
func (g *applicationHTMLSendEIDASGrantV1) validBudgetV1(ctx context.Context, a *WorkAdmissionV1, b ApplicationBudgetV1) bool {
	if g == nil || g.self != g || g.owner == nil || g.owner.self != g.owner || g.session == nil || g.owner.session == nil || g.owner.session.state != g.session || g.admission == nil || g.admission.fence != g.session.fence || g.work != a || g.session.factory == nil || g.session.factory.work != a || ctx == nil || g.callbackDone == nil || ctx.Done() != g.callbackDone || ctx.Value(applicationSessionCallbackKeyV1{}) != g.session {
		return false
	}
	select {
	case <-g.callbackDone:
		return false
	default:
	}
	h := g.bodyHeader
	if h == nil || h.self != h || h.reader != g.actor || h.reader == nil || h.reader.self != h.reader || h.reader.bodyHeader != h || h.session != g.owner.session || h.admission != g.admission || h.fence != g.session.fence || h.loanClose == nil || h.closed.Load() {
		return false
	}
	expected := ApplicationBudgetV1{Phase: "locked-html-send-eidas", OrgID: g.org, DocumentID: g.document, WorkingBytes: g.parentBytes, DBStagingBytes: g.dbBytes, htmlSendEIDASGrant: g}
	return b == expected && g.org != uuid.Nil && g.document != uuid.Nil && g.session.org == g.org && g.session.document == g.document && g.header.OrgID == g.org && g.parentBytes > 0 && g.dbBytes > 0
}

func (w *ApplicationHTMLSendWorkV1) holdEIDASBodyV1(ctx context.Context, h generated.GetActiveEIDASRuleSetHeaderV1Row) (func(), error) {
	parent, db, err := htmlSendEIDASReadResourcesV1(h)
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
	if p.closing || p.work == nil || p.htmlAdmissions == nil || s.observer || s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) || a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone || !s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	g := &applicationHTMLSendEIDASGrantV1{owner: w, session: s, admission: a, work: p.work, bodyHeader: w.actor.bodyHeader, actor: w.actor, callbackDone: ctx.Done(), org: s.org, document: s.document, header: h, parentBytes: parent, dbBytes: db}
	g.self = g
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	close, err := a.admit(ctx, ApplicationBudgetV1{Phase: "locked-html-send-eidas", OrgID: s.org, DocumentID: s.document, WorkingBytes: parent, DBStagingBytes: db, htmlSendEIDASGrant: g})
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	return close, nil
}

// Actual rules are read under header->loan->NOWAIT ordered pins->fresh header
// and ALL original ordered bodies. There is no row cap, truncated decision,
// missing-cache repair or inherited pool-backed rule reader.
func (w *ApplicationHTMLSendWorkV1) readEIDASRulesV1(call context.Context) ([]*generated.EidasRoutingRule, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.state == nil {
		return nil, ErrHTMLSendWorkV1
	}
	org := w.session.state.org
	h, err := w.queries.GetActiveEIDASRuleSetHeaderV1(call, org)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.holdEIDASBodyV1(call, *h)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeBody)
	pins, err := w.queries.LockActiveEIDASRuleSetPinsV1(call, org)
	if err != nil {
		return nil, err
	}
	if pins == nil || pins.OrgID != org || pins.RuleCount != h.RuleCount || pins.MeasuredRuleCount != h.RuleCount {
		return nil, ErrHTMLSendWorkV1
	}
	fresh, err := w.queries.GetActiveEIDASRuleSetHeaderV1(call, org)
	if err != nil {
		return nil, err
	}
	if fresh == nil || *fresh != *h {
		return nil, ErrHTMLSendWorkV1
	}
	rows, err := w.queries.ReadActiveEIDASRuleSetV1(call, generated.ReadActiveEIDASRuleSetV1Params{ExpectedRuleCount: h.RuleCount, ExpectedRawTextBytes: h.RawTextBytes, ExpectedPredicateWireBytes: h.PredicateWireBytes, ExpectedMeasurementServerVersionNum: h.MeasurementServerVersionNum, OrgID: org})
	if err != nil {
		return nil, fmt.Errorf("eidas: list rules: %w", err)
	}
	if int64(len(rows)) != h.RuleCount {
		return nil, ErrHTMLSendWorkV1
	}
	raw, wire := int64(0), int64(0)
	for _, r := range rows {
		if r == nil || r.OrgID != org || !r.Active || !htmlInputAddV1(&raw, int64(len(r.Name)+len(r.RequiredTier)+len(r.Reason)), 1) || !htmlInputAddV1(&wire, int64(len(r.PredicateJson)), 1) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if raw != h.RawTextBytes || wire != h.PredicateWireBytes {
		return nil, ErrHTMLSendWorkV1
	}
	return rows, nil
}

// EvaluateEIDASV1 runs the unchanged pure policy against this actual immutable
// source. Its new SQL stage belongs to the same original operation/context;
// actual source variables, complete rule bodies and outputs remain retained.
func (h *ApplicationHTMLSendSourceV1) EvaluateEIDASV1() (eidas.Decision, error) {
	var empty eidas.Decision
	if h == nil || h.state == nil {
		return empty, ErrHTMLSendWorkV1
	}
	s := h.state
	if !s.lockV1() {
		return empty, ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.eidasAttempted || !s.attempted || s.failure != nil || s.owner == nil || s.work == nil {
		return empty, ErrHTMLSendWorkV1
	}
	s.eidasAttempted = true
	owner := s.owner
	if err := owner.beginV1(); err != nil {
		return empty, err
	}
	defer owner.finishV1()
	doc := owner.snapshot.document
	inputBytes, err := htmlSendResolverParseDepthLogicalV1(int64(len(doc.VariablesJson)), 1, min(int64(len(doc.VariablesJson))+1, 10001))
	if err != nil {
		return empty, err
	}
	if !htmlInputAddV1(&inputBytes, int64(len(doc.VariablesJson)), 18+8) || !htmlInputAddV1(&inputBytes, 1, 2*8192) {
		return empty, ErrHTMLSendWorkV1
	}
	if err = owner.holdV1(htmlRevisionSourceStateV1, inputBytes, 0); err != nil {
		return empty, err
	}
	in, err := eidas.InputForDocumentV1(doc)
	if err != nil {
		return empty, htmlSendEIDASInputErrorV1{cause: err}
	}
	var rules []*generated.EidasRoutingRule
	s.work.mu.Lock()
	call := s.work.call
	sameCallback := s.work.valid(call)
	s.work.mu.Unlock()
	if sameCallback {
		rules, err = s.work.readEIDASRulesV1(call)
		if err != nil {
			return empty, err
		}
	} else {
		stage, err := s.work.stage.operation.OpenSQLV1(HTMLSendEIDASV1)
		if err != nil {
			return empty, err
		}
		session := stage.SessionV1()
		if session == nil {
			return empty, ErrHTMLSendWorkV1
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(owner.binding.ctx), 5*time.Second)
			defer stop()
			_ = session.CloseV1(cleanup)
		}()
		ctx := stage.ContextV1()
		if _, err = session.NewAdmissionV1(ctx); err != nil {
			return empty, err
		}
		err = stage.WithTxV1(func(call context.Context, _ generated.DBTX) error {
			work, e := session.NewHTMLSendWorkV1(call, stage)
			if e != nil {
				return e
			}
			if _, e = work.StateV1(call); e != nil {
				return e
			}
			rules, e = work.readEIDASRulesV1(call)
			return e
		})
		if err != nil {
			return empty, err
		}
		err = session.CommitV1(ctx)
		if err != nil {
			_ = session.CommitDispatchObservationV1()
			return empty, err
		}
	}
	scratch, retained, err := htmlSendEIDASPolicyLogicalV1(rules)
	if err != nil {
		return empty, err
	}
	if err = owner.holdV1(htmlRevisionSourceStateV1, scratch, retained); err != nil {
		return empty, err
	}
	return eidas.EvaluateRulesV1(rules, in)
}

// This fixed logical rule-call ledger preserves the original unbounded grammar.
// At most maxRaw+1 recursive node visits can retain at most maxRaw bytes each;
// ten JSON families per node cover validation+matching+typed/scalar fallbacks.
// Actual sequential rows share a continuous MAX scratch; ALL bodies/matches are
// separately retained. Swiss allocation, stack, fmt/pools/PG/GC/RSS remain
// measured runtime-capacity gates, not a deterministic heap multiplier claim.
func htmlSendEIDASPolicyLogicalV1(rules []*generated.EidasRoutingRule) (scratch, retained int64, err error) {
	maxRaw := int64(0)
	for _, r := range rules {
		if r == nil {
			return 0, 0, ErrHTMLSendWorkV1
		}
		maxRaw = max(maxRaw, int64(len(r.PredicateJson)))
		if !htmlInputAddV1(&retained, 1, int64(unsafe.Sizeof(eidas.MatchedRule{}))+36+16) || !htmlInputAddV1(&retained, int64(len(r.Name)+len(r.Reason)), 6) {
			return 0, 0, ErrHTMLSendWorkV1
		}
	}
	one, err := htmlSendResolverParseDepthLogicalV1(maxRaw, 10, min(maxRaw+1, 10001))
	if err != nil {
		return 0, 0, err
	}
	pathBytes := int64(0)
	if !htmlInputAddV1(&pathBytes, maxRaw, 32) || !htmlInputAddV1(&scratch, one, maxRaw+1) || !htmlInputAddV1(&scratch, maxRaw, pathBytes) || !htmlInputAddV1(&scratch, 1, 2*8192) {
		return 0, 0, ErrHTMLSendWorkV1
	}
	return scratch, retained, nil
}

var ErrHTMLSendEIDASInputV1 = errors.New("send eIDAS input is invalid")

type htmlSendEIDASInputErrorV1 struct{ cause error }

func (e htmlSendEIDASInputErrorV1) Error() string   { return e.cause.Error() }
func (e htmlSendEIDASInputErrorV1) Unwrap() []error { return []error{ErrHTMLSendEIDASInputV1, e.cause} }
