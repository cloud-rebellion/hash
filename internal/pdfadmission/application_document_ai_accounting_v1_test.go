// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
)

func TestDocumentAIAccountingActualQuoteAndOverflowV1(t *testing.T) {
	small, err := documentAIAccountingQuoteV1(7, 9, 21)
	large, err2 := documentAIAccountingQuoteV1(7, 8192, 21)
	if err != nil || err2 != nil || small.ParentBytes <= 0 || small.DBStagingBytes <= 0 || large.ParentBytes <= small.ParentBytes || large.DBStagingBytes <= small.DBStagingBytes || large.SQLSessions != 0 || large.ProviderStreams != 0 {
		t.Fatal("command staging quote lost actual dynamic/fixed work", small, large, err, err2)
	}
	for _, v := range [][3]int64{{-1, 1, 1}, {1, -1, 1}, {1, 1, -1}, {math.MaxInt64, 1, 1}, {1, math.MaxInt64, 1}, {1, 1, math.MaxInt64}} {
		if _, err := documentAIAccountingQuoteV1(v[0], v[1], v[2]); err == nil {
			t.Fatal("negative/overflow quote admitted", v)
		}
	}
}

// Synthetic already-open physical identity/control observations exercise REAL
// native Close/fence/coordinator bookkeeping. No socket/SQL/usage row/request
// receipt is fabricated as a successful producer; actual backend qualification
// remains in root's real PostgreSQL tests.
func TestDocumentAIAccountingBothPhysicalProofsBeforeRefundV1(t *testing.T) {
	fixture, session, c := applicationRequestLoanFixtureV1(t)
	p := session.state.factory
	factory := &ApplicationSessionFactoryV1{state: p}
	session.state.conn = nil
	session.state.tx = nil
	var observed atomic.Bool
	session.state.fence.observe = func(context.Context, applicationBackendIdentityV1) (bool, error) { return observed.Load(), nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sql, err := c.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{SQLSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	session.state.grant = sql.Close
	initial, err := c.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ParentBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	body, err := c.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ParentBytes: 256, DBStagingBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	s := &applicationDocumentAIAccountingStateV1{factory: factory, session: session, org: fixture.scope.OrgID, document: fixture.scope.DocumentID, lifetime: ctx, cancel: func() {}, initial: initial, body: body}
	owner := &ApplicationDocumentAIAccountingV1{state: s}
	s.self = owner
	p.documentAIAccountings[0] = s
	defer func() {
		if !applicationDoneV1(fixture.done) {
			close(fixture.done)
		}
		observed.Store(true)
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = owner.CloseV1(cleanup)
	}()
	before := c.SnapshotV1(fixture.scope.OrgID)
	for _, clientGone := range []bool{false, true} {
		if clientGone {
			close(fixture.done)
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Millisecond)
		err := owner.CloseV1(cleanup)
		stop()
		if err == nil || s.retired || c.SnapshotV1(fixture.scope.OrgID) != before || factory.PendingV1().DocumentAIAccountings != 1 {
			t.Fatal("Close/client completion refunded without original independent observer", clientGone, err, c.SnapshotV1(fixture.scope.OrgID))
		}
	}
	observed.Store(true)
	if err := owner.CloseV1(ctx); err != nil {
		t.Fatal("joined actual control observation did not retire", err)
	}
	if !s.retired || !session.RetiredV1() || c.SnapshotV1(fixture.scope.OrgID).Global != (workguard.VectorV1{}) || factory.PendingV1().DocumentAIAccountings != 0 {
		t.Fatal("physical+consumer retirement lost exact loan/registry", c.SnapshotV1(fixture.scope.OrgID), factory.PendingV1())
	}
	if err := owner.CloseV1(ctx); err != nil {
		t.Fatal("idempotent close failed", err)
	}
}

func TestDocumentAIUsageReceiptCloseJoinsActualBorrowV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	u := &ApplicationDocumentAIUsageReceiptV1{observed: true, persisted: true, active: 1, cost: ctx, cancel: cancel, params: generated.InsertAICompletionAuditParams{Model: "actual borrowed metadata"}}
	u.self = u
	u.CloseConsumerV1()
	u.CloseConsumerV1()
	if !errors.Is(ctx.Err(), context.Canceled) || u.retired || u.params.Model == "" {
		t.Fatal("Close lost actual active receipt borrower or private cancel")
	}
	u.finishV1()
	if !u.retiredV1() || u.params.Model != "" || u.cost != nil {
		t.Fatal("final actual usage borrower did not clear private refs before refund")
	}
	if err := u.beginV1(true); err == nil {
		t.Fatal("retired/closed opaque receipt reentered")
	}
}

func TestDocumentAIAccountingUnownedReceiptCannotGrantSQLV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, h := range []*ApplicationDocumentAIAccountingV1{nil, {}, {state: &applicationDocumentAIAccountingStateV1{}}} {
		if err := h.PrepareUsageV1(ctx, nil, nil, nil, "p", "m", "prompt", 1); err == nil {
			t.Fatal("unowned preparation acquired command authority")
		}
		if u, err := h.ObserveUsageV1(ctx, nil, nil, nil, &ai.CompletionObservationV1{}); err == nil || u != nil {
			t.Fatal("manufactured observation acquired usage authority", u, err)
		}
		if err := h.PersistUsageV1(nil); err == nil {
			t.Fatal("nil receipt granted command authority")
		}
	}
	for _, u := range []*ApplicationDocumentAIUsageReceiptV1{nil, {}, {observed: true, persisted: true}} {
		if err := u.beginV1(false); err == nil {
			t.Fatal("zero or copied-self usage receipt acquired a borrower")
		}
		if _, err := u.CostContextV1(); err == nil {
			t.Fatal("unowned receipt minted independent cost context")
		}
	}
}

// These are private context-gate witnesses only, not manufactured successful
// request/usage receipts or SQL evidence. The native producers still must prove
// real request commit, observation, usage INSERT and actual cost-row reread.
func TestDocumentAICostOriginalDeadlineAndObservationContextV1(t *testing.T) {
	origin, cancelOrigin := context.WithCancel(context.Background())
	cancelOrigin()
	live, stop := context.WithTimeout(context.WithoutCancel(origin), time.Second)
	defer stop()
	u := &ApplicationDocumentAIUsageReceiptV1{}
	u.cost = context.WithValue(live, applicationDocumentAICostContextKeyV1{}, u)
	callback := context.WithValue(u.cost, applicationSessionCallbackKeyV1{}, &applicationOwnedSessionV1{})
	if !u.costContextMatchesLockedV1(callback) {
		t.Fatal("actual derived cost context lost its independent incurred-cost lifetime")
	}
	if origin.Err() == nil || callback.Err() != nil {
		t.Fatal("canceled origin did not retain a live finite cost-only context")
	}
	for _, ctx := range []context.Context{nil, context.Background(), live, context.WithoutCancel(u.cost), context.WithValue(live, applicationDocumentAICostContextKeyV1{}, &ApplicationDocumentAIUsageReceiptV1{})} {
		if u.costContextMatchesLockedV1(ctx) {
			t.Fatal("unrelated, foreign-token or unbounded context resurrected cost authority")
		}
	}
	extended, stopExtended := context.WithDeadline(context.WithoutCancel(u.cost), time.Now().Add(2*time.Second))
	defer stopExtended()
	if u.costContextMatchesLockedV1(extended) {
		t.Fatal("replacement later deadline widened the original cost lifetime")
	}
	stop()
	later, stopLater := context.WithTimeout(context.Background(), time.Second)
	defer stopLater()
	later = context.WithValue(later, applicationDocumentAICostContextKeyV1{}, u)
	if u.costContextMatchesLockedV1(later) || u.costContextMatchesLockedV1(callback) {
		t.Fatal("expired original cost clock accepted a later live session context")
	}
}

func TestDocumentAICostCloseErasesPrivateAliasesBeforeRefundV1(t *testing.T) {
	c := &ApplicationDocumentAICostV1{row: &generated.AiCompletionAudit{Model: "actual variable metadata"}, source: &ApplicationHTMLAuthoringReaderV1{}, queries: generated.New(nil), usage: &ApplicationDocumentAIUsageReceiptV1{}, auditActive: 1}
	var refunds int
	check := func() {
		refunds++
		if !c.closed || c.row != nil || c.source != nil || c.queries != nil || c.usage != nil || c.closes != nil || c.releaseUsage != nil {
			t.Error("private cost data survived actual owner refund")
		}
	}
	c.closes = []func(){check}
	c.releaseUsage = check
	c.CloseConsumerV1()
	c.CloseConsumerV1()
	if refunds != 0 || c.closed || !c.closeRequested || c.row == nil {
		t.Fatal("Close erased/refunded metadata still in actual audit construction")
	}
	c.finishAuditV1()
	c.CloseConsumerV1()
	if refunds != 2 {
		t.Fatal("cost close lost or duplicated original consumer releases", refunds)
	}
}

func TestDocumentAIReadAndAuditCloseKeepsSourceUntilJoinV1(t *testing.T) {
	for _, mode := range []string{"audit-constructor", "source-read"} {
		t.Run(mode, func(t *testing.T) {
			s := &applicationDocumentAIStateV1{snapshot: &applicationHTMLRevisionSourceSnapshotV1{}}
			finish := s.finishAuditV1
			if mode == "audit-constructor" {
				s.auditActive = 1
			} else {
				s.readActive = 1
				finish = s.finishReadV1
			}
			w := &ApplicationDocumentAIWorkV1{state: s}
			s.self = w
			var refunds int
			s.closes = []func(){func() {
				refunds++
				if !s.closed || s.snapshot != nil || s.closes != nil {
					t.Error("work refunded before actual construction/read source aliases cleared")
				}
			}}
			w.CloseConsumerV1()
			if s.closed || s.snapshot == nil || !s.closeAfterProvider || refunds != 0 {
				t.Fatal("Close dropped original source during actual construction/read borrower")
			}
			finish()
			w.CloseConsumerV1()
			if !s.closed || s.snapshot != nil || refunds != 1 {
				t.Fatal("last actual construction/read borrower lost source cleanup")
			}
		})
	}
}
