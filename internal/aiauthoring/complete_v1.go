// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
// Package aiauthoring coordinates the fixed staff request/cost/result producers.
package aiauthoring

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DependenciesV1 struct {
	Pool     *pgxpool.Pool
	Sessions *pdfadmission.ApplicationSessionFactoryV1
	Audit    *audit.Logger
}
type RequestV1 = authoring.AIAppRequest

// This owner retains every native phase through actual response serialization.
// Private provider values are borrowable only while the original delivery is
// live. Copies share one registered lifecycle; Close cannot refund active use.
type ResultV1[T any] struct {
	body  *resultBodyV1[T]
	state *resultStateV1
}
type resultBodyV1[T any] struct{ value T }
type resultStateV1 struct {
	erase                             func()
	mu                                sync.Mutex
	original, workflow                context.Context
	cancel                            context.CancelFunc
	factory                           *pdfadmission.ApplicationSessionFactoryV1
	accounting                        *pdfadmission.ApplicationDocumentAIAccountingV1
	phases                            []*phaseV1
	usages                            []*pdfadmission.ApplicationDocumentAIUsageReceiptV1
	active                            int
	failed, closed, retiring, retired bool
}
type phaseV1 struct {
	session    *pdfadmission.ApplicationSessionV1
	admission  *pdfadmission.ApplicationAdmissionV1
	work       *pdfadmission.ApplicationDocumentAIWorkV1
	borrow     *pdfadmission.ApplicationDocumentAIWorkflowV1
	cost       *pdfadmission.ApplicationDocumentAICostV1
	event      *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	extraEvent *pdfadmission.ApplicationHTMLAuditEventConsumerV1
}

func (r *ResultV1[T]) WithValueV1(ctx context.Context, use func(T) error) error {
	if r == nil || r.state == nil || r.body == nil || use == nil || ctx == nil {
		return pdfadmission.ErrDocumentAIAuditV1
	}
	s := r.state
	s.mu.Lock()
	if s.closed || s.retired || s.failed || !reflect.TypeOf(ctx).Comparable() || ctx != s.original || ctx.Err() != nil || s.workflow == nil || s.workflow.Err() != nil {
		s.mu.Unlock()
		return pdfadmission.ErrDocumentAIAuditV1
	}
	s.active++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		finish := s.closed && s.active == 0 && !s.retiring
		if finish {
			s.retiring = true
		}
		s.mu.Unlock()
		if finish {
			s.retireV1()
		}
	}()
	if err := use(r.body.value); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.workflow.Err(); err != nil {
		return err
	}
	return nil
}
func (r *ResultV1[T]) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.mu.Lock()
	s.closed = true
	finish := s.active == 0 && !s.retiring
	if finish {
		s.retiring = true
	}
	s.mu.Unlock()
	if finish {
		s.retireV1()
	}
}
func (s *resultStateV1) retireV1() {
	s.mu.Lock()
	erase, cancel, phases, usages, accounting, factory := s.erase, s.cancel, s.phases, s.usages, s.accounting, s.factory
	s.erase, s.cancel, s.phases, s.usages, s.accounting, s.factory = nil, nil, nil, nil, nil, nil
	s.original, s.workflow = nil, nil
	s.mu.Unlock()
	if erase != nil {
		erase()
	}
	if cancel != nil {
		cancel()
	}
	for i := len(phases) - 1; i >= 0; i-- {
		p := phases[i]
		if p.event != nil {
			p.event.CloseConsumerV1()
		}
		if p.extraEvent != nil {
			p.extraEvent.CloseConsumerV1()
		}
		if p.cost != nil {
			p.cost.CloseConsumerV1()
		}
		if p.work != nil {
			p.work.CloseConsumerV1()
		}
		if p.borrow != nil {
			p.borrow.CloseConsumerV1()
		}
	}
	for _, u := range usages {
		u.CloseConsumerV1()
	}
	if accounting != nil {
		accounting.CloseConsumerV1()
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		_ = accounting.CloseV1(ctx)
		stop()
	}
	for i := len(phases) - 1; i >= 0; i-- {
		p := phases[i]
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		if p.session != nil {
			_ = p.session.CloseV1(ctx)
		}
		if p.admission != nil {
			_, _ = p.admission.ReconcileCleanupV1(ctx)
		}
		stop()
		*p = phaseV1{}
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	if factory != nil {
		_ = factory.ReconcileCleanupV1(ctx)
	}
	stop()
	s.mu.Lock()
	s.retired = true
	s.mu.Unlock()
}
func openPhaseV1(ctx context.Context, d DependenciesV1, r RequestV1, state *resultStateV1) (*phaseV1, error) {
	p := &phaseV1{}
	state.phases = append(state.phases, p)
	var err error
	p.session, err = d.Sessions.OpenV1(ctx, r.Actor.OrgID, r.DocumentID)
	if err != nil {
		return p, err
	}
	p.admission, err = p.session.NewAdmissionV1(ctx)
	return p, err
}

// The policy facade is constructed ONLY from this actual native callback.
// No arbitrary pooled tx/DBTX is promoted into native ownership.
func lockPhaseV1(ctx context.Context, p *phaseV1, r RequestV1, db generated.DBTX) (*generated.Document, *authoring.MemberGuard, error) {
	var err error
	p.work, err = p.session.NewDocumentAIWorkV1(ctx, r.Actor.UserID, r.Via, r.Action)
	if err != nil {
		return nil, nil, err
	}
	if err = p.work.LockScopeV1(ctx); err != nil {
		return nil, nil, err
	}
	tx := &nativeAIPolicyTxV1{DBTX: db}
	q := generated.New(tx)
	var member *authoring.MemberGuard
	doc, err := p.work.ReadDocumentWithActorV1(ctx, func(_ pdfadmission.HTMLRevisionReadAccessV1, user *generated.User) error {
		if user == nil || user.ID != r.Actor.UserID || user.OrgID != r.Actor.OrgID || (user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner)) {
			return auth.ErrMutationPermissionRevoked
		}
		var err error
		member, err = authoring.LockAuthor(ctx, tx, r.Actor)
		if err != nil {
			return err
		}
		fence, err := q.TryCollabArchivePrivacyFence(ctx, r.Actor.OrgID)
		if err != nil {
			return err
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		policy, err := p.work.PolicyV1(ctx)
		if err != nil {
			return err
		}
		check := func(id uuid.UUID, allowed, draft bool) error {
			if !allowed {
				return authoring.ErrAIAppDocumentClosed
			}
			if draft {
				retained, err := q.HasRetainedDraftSigningEvidence(ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: id, OrgID: r.Actor.OrgID})
				if err != nil {
					return err
				}
				if retained {
					return authoring.ErrDocumentHasEvidence
				}
			}
			pending, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: id, OrgID: r.Actor.OrgID})
			if err != nil {
				return err
			}
			if pending {
				return authoring.ErrPendingPrivacyReview
			}
			return ctx.Err()
		}
		if policy.RootDocumentID != r.DocumentID {
			if err = check(policy.RootDocumentID, policy.RootAllowed, policy.RootDraft); err != nil {
				return err
			}
		}
		return check(r.DocumentID, policy.DocumentAllowed, policy.DocumentDraft)
	})
	return doc, member, err
}

// Request commits before dispatch; genuine native usage autocommits before the
// separate M94 cost event. Result rollback/cancellation cannot undo usage. The
// reserved accounting connection has its own backend/observer retirement fence.
func CompleteDocumentAIV1[T any](parent context.Context, d DependenciesV1, r RequestV1, runtime *ai.Runtime, complete func(context.Context, *ai.Runtime, *generated.Document) (T, error), event func(T) audit.Entry) (result *ResultV1[T], failure error) {
	state := &resultStateV1{factory: d.Sessions, original: parent}
	result = &ResultV1[T]{state: state, body: &resultBodyV1[T]{}}
	state.erase = func() { var zero T; result.body.value = zero }
	fail := func(err error) (*ResultV1[T], error) {
		var zero T
		result.body.value = zero
		state.failed = true
		return result, err
	}
	if parent == nil || parent.Err() != nil || d.Sessions == nil || d.Audit == nil || runtime == nil || complete == nil || r.Actor.Authorize == nil || r.DocumentID == uuid.Nil {
		return fail(errors.New("AI completion dependencies unavailable"))
	}
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	state.workflow = ctx
	state.cancel = cancel
	// Native direct SQL ownership replaces the legacy pooled MaxConns gate here.
	// Legacy authoring.CompleteDocumentAI/ReserveAIAccounting remain unchanged.
	var err error
	state.accounting, err = d.Sessions.ReserveDocumentAIAccountingV1(ctx, r.Actor.OrgID, r.DocumentID)
	if err != nil {
		return fail(err)
	}
	requested, err := openPhaseV1(ctx, d, r, state)
	if err != nil {
		return fail(err)
	}
	var receipt *pdfadmission.ApplicationDocumentAIRequestReceiptV1
	var requestEvent audit.PendingEvent
	err = requested.session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		_, member, err := lockPhaseV1(call, requested, r, db)
		if err != nil {
			return err
		}
		requestEvent, requested.event, err = ownedaudit.LogDocumentAIRequestV1(d.Audit, call, requested.work, r.IP, r.UserAgent)
		if err != nil {
			return err
		}
		return member.Recheck(call)
	})
	if err != nil {
		return fail(err)
	}
	if err = requested.session.CommitV1(ctx); err != nil {
		return fail(err)
	}
	receipt, err = requested.work.CommittedRequestV1(requested.event)
	if err != nil {
		return fail(err)
	}
	if err = ownedaudit.PublishV1(d.Audit, requestEvent, requested.event); err != nil {
		return fail(err)
	}
	if err = requested.work.CloseCommittedRequestSourceV1(receipt); err != nil {
		return fail(err)
	}
	cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	err = requested.session.CloseV1(cleanup)
	stop()
	if err != nil {
		return fail(err)
	}
	dispatch, err := openPhaseV1(ctx, d, r, state)
	if err != nil {
		return fail(err)
	}
	var value T
	var resultEvent audit.PendingEvent
	err = dispatch.session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		doc, member, err := lockPhaseV1(call, dispatch, r, db)
		if err != nil {
			return err
		}
		observer := &usageObserverV1{dependencies: d, request: r, state: state, dispatch: dispatch, receipt: receipt}
		owner, err := dispatch.work.NewRuntimeV1(call, observer)
		if err != nil {
			return err
		}
		observer.owner = owner
		native := ai.WithNativeWorkflowV1(call, owner)
		dispatch.borrow, err = dispatch.work.BeginWorkflowV1(native)
		if err != nil {
			return err
		}
		scoped := runtime.ForAuditedRequest(generated.New(db), func(context.Context, generated.InsertAICompletionAuditParams) error {
			return errors.New("native AI observation required")
		})
		scoped = scoped.ForNativeWorkflowV1(owner)
		if err = member.Recheck(call); err != nil {
			return err
		}
		value, err = complete(native, scoped, doc)
		if err != nil {
			return err
		}
		if err = member.Recheck(call); err != nil {
			return err
		}
		id, user := r.DocumentID, r.Actor.UserID
		entry := audit.Entry{OrgID: r.Actor.OrgID, DocumentID: &id, ActorUserID: &user, Kind: "ai.result_ready", IP: r.IP, UserAgent: r.UserAgent, Payload: map[string]any{"via": r.Via, "tool": r.Action, "request_event_id": receipt.EventIDV1().String(), "provider_called": observer.observedV1()}}
		if event != nil {
			entry = event(value)
			if entry.Payload == nil {
				entry.Payload = map[string]any{}
			}
			entry.Payload["request_event_id"] = receipt.EventIDV1().String()
			entry.Payload["tool"] = r.Action
			entry.Payload["via"] = r.Via
		}
		if entry.OrgID != r.Actor.OrgID || entry.DocumentID == nil || *entry.DocumentID != id || entry.ActorUserID == nil || *entry.ActorUserID != user {
			return auth.ErrMutationPermissionRevoked
		}
		resultEvent, dispatch.event, err = ownedaudit.LogDocumentAIResultV1(d.Audit, call, dispatch.work, receipt, entry)
		if err != nil {
			return err
		}
		return member.Recheck(call)
	})
	if err != nil {
		return fail(err)
	}
	if err = dispatch.session.CommitV1(ctx); err != nil {
		return fail(err)
	}
	if err = ownedaudit.PublishV1(d.Audit, resultEvent, dispatch.event); err != nil {
		return fail(err)
	}
	result.body.value = value
	return result, nil
}

type usageObserverV1 struct {
	mu                 sync.Mutex
	dependencies       DependenciesV1
	request            RequestV1
	state              *resultStateV1
	dispatch           *phaseV1
	receipt            *pdfadmission.ApplicationDocumentAIRequestReceiptV1
	owner              *pdfadmission.ApplicationDocumentAIRuntimeV1
	prepared, observed bool
}

func (o *usageObserverV1) ReserveNativeUsageV1(origin context.Context, owner ai.NativeWorkflowV1, provider, model, prompt string, version int) error {
	o.mu.Lock()
	if o.prepared || o.owner == nil || owner != o.owner {
		o.mu.Unlock()
		return pdfadmission.ErrDocumentAIAuditV1
	}
	o.prepared = true
	o.mu.Unlock()
	return o.state.accounting.PrepareUsageV1(origin, o.dispatch.work, o.receipt, o.owner, provider, model, prompt, version)
}
func (o *usageObserverV1) ObserveNativeUsageV1(origin context.Context, owner ai.NativeWorkflowV1, observation *ai.CompletionObservationV1) error {
	o.mu.Lock()
	if !o.prepared || o.observed || o.owner == nil || owner != o.owner {
		o.mu.Unlock()
		return pdfadmission.ErrDocumentAIAuditV1
	}
	o.observed = true
	o.mu.Unlock()
	usage, err := o.state.accounting.ObserveUsageV1(origin, o.dispatch.work, o.receipt, o.owner, observation)
	if err != nil {
		return err
	}
	o.state.usages = append(o.state.usages, usage)
	if err = o.state.accounting.PersistUsageV1(usage); err != nil {
		slog.Error("AI usage persistence failed", "request_event_id", o.receipt.EventIDV1(), "org_id", o.request.Actor.OrgID, "tool", o.request.Action)
		return errors.New("AI usage persistence failed")
	}
	costCtx, err := usage.CostContextV1()
	if err != nil {
		return err
	}
	cost, err := openPhaseV1(costCtx, o.dependencies, o.request, o.state)
	if err != nil {
		return errors.New("AI completion event persistence failed")
	}
	var pending audit.PendingEvent
	err = cost.session.WithTxV1(costCtx, func(owned context.Context, _ generated.DBTX) error {
		var err error
		cost.cost, err = cost.session.NewDocumentAICostV1(owned, usage)
		if err != nil {
			return err
		}
		if err = cost.cost.ReadUsageV1(owned); err != nil {
			return err
		}
		pending, cost.event, err = ownedaudit.LogDocumentAICostV1(o.dependencies.Audit, owned, cost.cost)
		return err
	})
	if err == nil {
		err = cost.session.CommitV1(costCtx)
	}
	if err == nil {
		err = ownedaudit.PublishV1(o.dependencies.Audit, pending, cost.event)
	}
	if err != nil {
		slog.Error("AI completion event persistence failed", "request_event_id", o.receipt.EventIDV1(), "org_id", o.request.Actor.OrgID, "tool", o.request.Action)
		return errors.New("AI completion event persistence failed")
	}
	cleanup, stop := context.WithTimeout(context.WithoutCancel(costCtx), 5*time.Second)
	err = cost.session.CloseV1(cleanup)
	stop()
	return err
}
func (o *usageObserverV1) observedV1() bool { o.mu.Lock(); defer o.mu.Unlock(); return o.observed }
