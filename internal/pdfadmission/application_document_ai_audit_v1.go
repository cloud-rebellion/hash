// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrDocumentAIAuditV1 = errors.New("pdfadmission: owned document AI evidence unavailable")

type ApplicationDocumentAIWorkV1 struct{ state *applicationDocumentAIStateV1 }
type applicationDocumentAIStateV1 struct {
	mu                               sync.Mutex
	self                             *ApplicationDocumentAIWorkV1
	session                          *ApplicationSessionV1
	reader                           *ApplicationHTMLRevisionReaderV1
	queries                          *generated.Queries
	root, actor                      uuid.UUID
	signer                           *applicationSignerAIRequestV1
	signerRecipient                  *generated.Recipient
	clarifierRequested               bool
	via, action                      string
	snapshot                         *applicationHTMLRevisionSourceSnapshotV1
	release                          func()
	closes                           []func()
	policy                           *generated.GetDocumentAIPolicyV1Row
	requested, result, usageObserved bool
	providerActive                   int
	workflowActive                   int
	auditActive                      int
	readActive                       int
	runtimeOwner                     *ApplicationDocumentAIRuntimeV1
	closeAfterProvider               bool
	closed                           bool
}

// This capability has no public fields and cannot be made from event IDs,
// caller booleans, a pooled tx, old rows, or a manually manufactured usage row.
// The request owner remains alive until the workflow's actual final use.
type ApplicationDocumentAIRequestReceiptV1 struct {
	request *applicationDocumentAIStateV1
	event   *ApplicationHTMLAuditEventConsumerV1
	id      uuid.UUID
}
type ApplicationDocumentAIUsageReceiptV1 struct {
	mu                                   sync.Mutex
	self                                 *ApplicationDocumentAIUsageReceiptV1
	dispatch                             *applicationDocumentAIStateV1
	request                              *ApplicationDocumentAIRequestReceiptV1
	accounting                           *applicationDocumentAIAccountingStateV1
	params                               generated.InsertAICompletionAuditParams
	cost                                 context.Context
	cancel                               context.CancelFunc
	active                               int
	observed, persisted, closed, retired bool
	costClaimed                          bool
}
type ApplicationDocumentAICostV1 struct {
	mu                sync.Mutex
	session           *ApplicationSessionV1
	source            *ApplicationHTMLAuthoringReaderV1
	queries           *generated.Queries
	usage             *ApplicationDocumentAIUsageReceiptV1
	root              uuid.UUID
	row               *generated.AiCompletionAudit
	closes            []func()
	attempted, closed bool
	auditActive       int
	closeRequested    bool
	releaseUsage      func()
}
type applicationDocumentAIAuditKeyV1 struct{}
type applicationDocumentAICostContextKeyV1 struct{}
type applicationDocumentAIAuditScopeV1 struct {
	work    *applicationDocumentAIStateV1
	cost    *ApplicationDocumentAICostV1
	purpose HTMLAuditPurposeV1
	signer  *applicationSignerAIRequestV1
	actor   uuid.UUID
}

func documentAIAuditPurposeV1(p HTMLAuditPurposeV1) bool {
	switch p {
	case HTMLAuditAIRequestedV1, HTMLAuditAICompletedV1, HTMLAuditAIResultReadyV1, HTMLAuditAIBilingualCheckedV1, HTMLAuditAIRiskAnalyzedV1, HTMLAuditSignerAIRequestedV1, HTMLAuditSignerClarifierRequestedV1, HTMLAuditSignerAICompletedV1, HTMLAuditSignerClarifierAnsweredV1:
		return true
	}
	return false
}
func documentAIActionV1(via, action string) bool {
	if via != "rest" && via != "mcp" {
		return false
	}
	switch action {
	case "suggest_counter_clause", "check_bilingual_equivalence", "run_risk_analysis":
		return true
	case "clarify_clause":
		return via == "mcp"
	}
	return false
}
func (h *ApplicationSessionV1) NewDocumentAIWorkV1(ctx context.Context, actor uuid.UUID, via, action string) (*ApplicationDocumentAIWorkV1, error) {
	if h == nil || h.state == nil || actor == uuid.Nil || !documentAIActionV1(via, action) {
		return nil, ErrDocumentAIAuditV1
	}
	r, err := h.NewHTMLRevisionReaderV1(ctx)
	if err != nil {
		return nil, err
	}
	raw := 4*int64(unsafe.Sizeof(applicationDocumentAIStateV1{})) + 4*int64(unsafe.Sizeof(ApplicationDocumentAIRequestReceiptV1{})) + 4*int64(unsafe.Sizeof(ApplicationDocumentAIUsageReceiptV1{})) + 4*int64(unsafe.Sizeof(generated.GetDocumentAIPolicyV1Row{})) + 4096
	close, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		r.CloseConsumerV1()
		return nil, err
	}
	r.documentAIShared = true
	out := &ApplicationDocumentAIWorkV1{state: &applicationDocumentAIStateV1{session: h, reader: r, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), actor: actor, via: strings.Clone(via), action: strings.Clone(action), closes: []func(){close}}}
	out.state.self = out
	return out, nil
}
func (s *applicationDocumentAIStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.self != nil && s.self.state == s && s.session != nil && s.reader != nil && s.reader.documentAIShared && s.reader.valid(ctx)
}
func (s *applicationDocumentAIStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.authoring.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return errors.Join(ErrDocumentAIAuditV1, err)
	}
	s.closes = append(s.closes, close)
	return nil
}

// Root-first SHARE is essential for request and retained dispatch. A cost
// session never upgrades either actual family row while dispatch owns SHARE.
func (w *ApplicationDocumentAIWorkV1) LockScopeV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.root != uuid.Nil {
		return ErrDocumentAIAuditV1
	}
	p := s.session.state
	root, err := s.queries.GetDocumentAIRootV1(ctx, generated.GetDocumentAIRootV1Params{DocumentID: p.document, OrgID: p.org})
	if errors.Is(err, pgx.ErrNoRows) {
		return authoring.ErrDocumentNotFound
	}
	if err != nil {
		return err
	}
	row, err := s.queries.LockDocumentAIRootV1(ctx, generated.LockDocumentAIRootV1Params{RootDocumentID: root, OrgID: p.org})
	if errors.Is(err, pgx.ErrNoRows) {
		return authoring.ErrDocumentNotFound
	}
	if err != nil {
		return err
	}
	if row == nil || root == uuid.Nil || row.RootDocumentID != root || row.RootHasParent || (root != p.document && !row.IsEnvelope) {
		return authoring.ErrAIAppDocumentClosed
	}
	matches, err := s.queries.DocumentAIRootMatchesV1(ctx, generated.DocumentAIRootMatchesV1Params{RootDocumentID: root, DocumentID: p.document, OrgID: p.org})
	if err != nil {
		return err
	}
	if !matches {
		return authoring.ErrAIAppDocumentClosed
	}
	s.root = root
	return nil
}
func (w *ApplicationDocumentAIWorkV1) ReadDocumentWithActorV1(ctx context.Context, gate func(HTMLRevisionReadAccessV1, *generated.User) error) (*generated.Document, error) {
	if w == nil || w.state == nil || gate == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	if !s.validV1(ctx) || s.closeAfterProvider || s.readActive != 0 || s.root == uuid.Nil || s.snapshot != nil {
		s.mu.Unlock()
		return nil, ErrDocumentAIAuditV1
	}
	s.readActive++
	reader, actor, root, session := s.reader, s.actor, s.root, s.session
	s.mu.Unlock()
	// The actual reader retains its source while its original actor/privacy gate
	// calls PolicyV1. That method locks work normally; Close waits for this read.
	defer s.finishReadV1()
	models, err := reader.ReadDocumentWithActorV1(ctx, actor, func(a HTMLRevisionReadAccessV1) error {
		if a.DocumentID != session.state.document || a.OrgID != session.state.org {
			return authoring.ErrDocumentNotFound
		}
		matches, err := s.queries.DocumentAIRootMatchesV1(ctx, generated.DocumentAIRootMatchesV1Params{RootDocumentID: root, DocumentID: session.state.document, OrgID: session.state.org})
		if err != nil {
			return err
		}
		if !matches {
			return authoring.ErrAIAppDocumentClosed
		}
		return nil
	}, gate)
	if err != nil {
		return nil, err
	}
	snapshot, release, err := reader.borrowHTMLRevisionSourceV1(ctx)
	if err != nil {
		return nil, err
	}
	d := snapshot.document
	if d == nil || d.ID != session.state.document || d.OrgID != session.state.org || d.DeletedAt.Valid || (d.ParentEnvelopeID.Valid && uuid.UUID(d.ParentEnvelopeID.Bytes) != root) || (!d.ParentEnvelopeID.Valid && d.ID != root) {
		release()
		return nil, authoring.ErrAIAppDocumentClosed
	}
	s.mu.Lock()
	if !s.validV1(ctx) || s.closeAfterProvider || s.snapshot != nil {
		s.mu.Unlock()
		release()
		return nil, ErrDocumentAIAuditV1
	}
	s.snapshot, s.release = snapshot, release
	s.mu.Unlock()
	return models.Document, nil
}

// Call inside the actor gate AFTER the original member/credential and org
// privacy fence, before any full source body. This preserves refusal ordering.
func (w *ApplicationDocumentAIWorkV1) PolicyV1(ctx context.Context) (ManualNegotiationPolicyV1, error) {
	var out ManualNegotiationPolicyV1
	if w == nil || w.state == nil {
		return out, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.closeAfterProvider || s.readActive != 1 || s.root == uuid.Nil || s.policy != nil {
		return out, ErrDocumentAIAuditV1
	}
	p := s.session.state
	row, err := s.queries.GetDocumentAIPolicyV1(ctx, generated.GetDocumentAIPolicyV1Params{RootDocumentID: s.root, DocumentID: p.document, OrgID: p.org})
	if err != nil {
		return out, err
	}
	if row == nil || row.RootDocumentID != s.root || row.DocumentID != p.document {
		return out, ErrDocumentAIAuditV1
	}
	s.policy = row
	return ManualNegotiationPolicyV1{RootDocumentID: row.RootDocumentID, DocumentID: row.DocumentID, RootDraft: row.RootDraft, DocumentDraft: row.DocumentDraft, RootAllowed: row.RootAllowed, DocumentAllowed: row.DocumentAllowed}, nil
}
func (w *ApplicationDocumentAIWorkV1) NewRequestAuditV1(ctx context.Context, ip, ua string) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if w == nil || w.state == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	if !s.validV1(ctx) || s.signer != nil || s.snapshot == nil || s.policy == nil || s.requested || s.closeAfterProvider {
		s.mu.Unlock()
		return nil, ErrDocumentAIAuditV1
	}
	s.requested = true
	s.auditActive++
	scope := &applicationDocumentAIAuditScopeV1{work: s, purpose: HTMLAuditAIRequestedV1, actor: s.actor}
	payload := map[string]any{"via": s.via, "tool": s.action}
	s.mu.Unlock()
	defer s.finishAuditV1()
	return scope.newEventV1(ctx, ip, ua, payload)
}
func (w *ApplicationDocumentAIWorkV1) CommittedRequestV1(e *ApplicationHTMLAuditEventConsumerV1) (*ApplicationDocumentAIRequestReceiptV1, error) {
	if w == nil || w.state == nil || e == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := w.state
	e.mu.Lock()
	defer e.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.requested || e.self != e || e.documentAI == nil || e.documentAI.work != s || e.purpose != s.requestPurposeV1() || e.eventID == uuid.Nil || e.session != s.session || !e.attempted {
		return nil, ErrDocumentAIAuditV1
	}
	p := s.session.state
	p.mu.Lock()
	ack := p.commitAttempted && p.ended && !p.commitUnknown
	p.mu.Unlock()
	if !ack {
		return nil, ErrDocumentAIAuditV1
	}
	return &ApplicationDocumentAIRequestReceiptV1{request: s, event: e, id: e.eventID}, nil
}
func (r *ApplicationDocumentAIRequestReceiptV1) EventIDV1() uuid.UUID {
	if r == nil {
		return uuid.Nil
	}
	return r.id
}
func (r *ApplicationDocumentAIRequestReceiptV1) validV1() bool {
	if r == nil || r.request == nil || r.event == nil || r.id == uuid.Nil {
		return false
	}
	s := r.request
	// Audit preflight holds event.mu before validating its actual producer.
	// Receipt validation follows that same order; no requestWork→event inversion.
	r.event.mu.Lock()
	defer r.event.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.self == nil || s.self.state != s || !s.requested || s.session == nil {
		return false
	}
	p := s.session.state
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.commitAttempted && p.ended && !p.commitUnknown && r.event.eventID == r.id && r.event.session == s.session && r.event.documentAI != nil && r.event.documentAI.work == s
}
func (s *applicationDocumentAIStateV1) requestMatchesV1(r *ApplicationDocumentAIRequestReceiptV1) bool {
	return r != nil && r.request != s && r.validV1() && s.session.state.factory == r.request.session.state.factory && s.session.state.org == r.request.session.state.org && s.session.state.document == r.request.session.state.document && s.actor == r.request.actor && s.signer == r.request.signer && s.root == r.request.root && s.via == r.request.via && s.action == r.request.action
}

// The reserved native accounting owner alone creates usage receipts from the
// actual runtime observation. A caller params/row/verified bool cannot do so.
func (u *ApplicationDocumentAIUsageReceiptV1) beginV1(persisted bool) error {
	if u == nil {
		return ErrDocumentAIAuditV1
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.self != u || u.closed || u.retired || !u.observed || (persisted && !u.persisted) || u.cost == nil || u.cost.Err() != nil || u.dispatch == nil || u.accounting == nil || u.request == nil || !u.request.validV1() {
		return ErrDocumentAIAuditV1
	}
	u.active++
	return nil
}
func (u *ApplicationDocumentAIUsageReceiptV1) finishV1() {
	u.mu.Lock()
	u.active--
	u.retireLockedV1()
	u.mu.Unlock()
}
func (u *ApplicationDocumentAIUsageReceiptV1) retireLockedV1() {
	if u.closed && u.active == 0 && !u.retired {
		u.retired = true
		u.params = generated.InsertAICompletionAuditParams{}
		u.request = nil
		u.dispatch = nil
		u.accounting = nil
		u.cost = nil
		u.cancel = nil
	}
}
func (u *ApplicationDocumentAIUsageReceiptV1) retiredV1() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.retired
}

// A derived native session callback must retain this private observation token
// and its original finite deadline. A new unrelated live context, WithoutCancel
// or a longer replacement deadline cannot resurrect an incurred-cost receipt.
func (u *ApplicationDocumentAIUsageReceiptV1) costContextMatchesLockedV1(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil || u.cost == nil || u.cost.Err() != nil || ctx.Value(applicationDocumentAICostContextKeyV1{}) != u {
		return false
	}
	deadline, ok := ctx.Deadline()
	costDeadline, costOK := u.cost.Deadline()
	return ok && costOK && !deadline.After(costDeadline)
}
func (u *ApplicationDocumentAIUsageReceiptV1) beginCostV1(ctx context.Context) error {
	if u == nil {
		return ErrDocumentAIAuditV1
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.self != u || u.closed || u.retired || !u.observed || !u.persisted || u.costClaimed || u.dispatch == nil || u.accounting == nil || u.request == nil || !u.costContextMatchesLockedV1(ctx) || !u.request.validV1() {
		return ErrDocumentAIAuditV1
	}
	u.costClaimed = true
	u.active++
	return nil
}
func (u *ApplicationDocumentAIUsageReceiptV1) liveBorrowedV1(ctx context.Context) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.self == u && !u.closed && !u.retired && u.active > 0 && u.persisted && u.costClaimed && u.costContextMatchesLockedV1(ctx)
}

// This exact cost-only context starts at actual observation, never at request
// reservation. It does not grant dispatch, result or credential authority.
func (u *ApplicationDocumentAIUsageReceiptV1) CostContextV1() (context.Context, error) {
	if u == nil {
		return nil, ErrDocumentAIAuditV1
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.self != u || u.closed || u.retired || !u.persisted || u.cost == nil || u.cost.Err() != nil {
		return nil, ErrDocumentAIAuditV1
	}
	return u.cost, nil
}

// Called only after the original independently autocommitted usage INSERT.
// The native cost owner rereads the actual persisted row under a premeasure;
// returning a forged row/ID to the coordinator grants no append authority.
func (h *ApplicationSessionV1) NewDocumentAICostV1(ctx context.Context, u *ApplicationDocumentAIUsageReceiptV1) (*ApplicationDocumentAICostV1, error) {
	if h == nil || h.state == nil || u == nil {
		return nil, ErrDocumentAIAuditV1
	}
	if err := u.beginCostV1(ctx); err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			u.finishV1()
		}
	}()
	if h.state.factory != u.dispatch.session.state.factory || h.state.org != u.params.OrgID || h.state.document != u.dispatch.session.state.document {
		return nil, ErrDocumentAIAuditV1
	}
	r, err := h.NewHTMLAuthoringReaderV1(ctx)
	if err != nil {
		return nil, err
	}
	close, err := r.acquireOwnedRetainedBodyV1(ctx, 4*int64(unsafe.Sizeof(ApplicationDocumentAICostV1{}))+4*int64(unsafe.Sizeof(generated.AiCompletionAudit{}))+4096, 0)
	if err != nil {
		r.CloseConsumerV1()
		return nil, err
	}
	keep = true
	return &ApplicationDocumentAICostV1{session: h, source: r, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), usage: u, root: u.dispatch.root, closes: []func(){close}, releaseUsage: u.finishV1}, nil
}
func (c *ApplicationDocumentAICostV1) ReadUsageV1(ctx context.Context) error {
	if c == nil {
		return ErrDocumentAIAuditV1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.row != nil || c.source == nil || !c.source.valid(ctx) || c.usage == nil || !c.usage.liveBorrowedV1(ctx) || !c.usage.request.validV1() {
		return ErrDocumentAIAuditV1
	}
	u := c.usage
	p := c.session.state
	scope := &applicationDocumentAIAuditScopeV1{cost: c, purpose: u.dispatch.costPurposeV1(), actor: u.dispatch.actor, signer: u.dispatch.signer}
	if err := scope.lockScopeV1(ctx); err != nil {
		return err
	}
	fence, err := c.queries.TryCollabArchivePrivacyFence(ctx, p.org)
	if err != nil {
		return err
	}
	if !fence {
		return authoring.ErrPrivacyReviewChanging
	}
	for _, id := range []uuid.UUID{c.root, p.document} {
		pending, err := c.queries.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: id, OrgID: p.org})
		if err != nil {
			return err
		}
		if pending {
			return authoring.ErrPendingPrivacyReview
		}
		if id == p.document {
			break
		}
	}
	h, err := c.usageHeaderV1(ctx, u)
	if err != nil {
		return err
	}
	if h == nil || h.ID != u.request.id || h.OrgID != p.org || h.DocumentID != (pgtype.UUID{Bytes: p.document, Valid: true}) || h.ActorUserID != u.dispatch.auditActorV1() || h.RawTextBytes < 0 || !applicationStampV1(h.CreatedAt) {
		return ErrDocumentAIAuditV1
	}
	close, err := c.source.acquireOwnedRetainedBodyV1(ctx, h.RawTextBytes, 0)
	if err != nil {
		return err
	}
	c.closes = append(c.closes, close)
	row, err := c.usageBodyV1(ctx, u, h)
	if err != nil {
		return err
	}
	in := u.params
	if row == nil || row.ID != h.ID || row.OrgID != p.org || row.DocumentID != h.DocumentID || row.ActorUserID != h.ActorUserID || row.CreatedAt != h.CreatedAt || row.Provider != in.Provider || row.Model != in.Model || row.PromptName != in.PromptName || row.PromptVersion != in.PromptVersion || row.ShieldActive != in.ShieldActive || row.InputTokens != in.InputTokens || row.OutputTokens != in.OutputTokens || row.LatencyMs != in.LatencyMs || row.Success != in.Success || row.Error != in.Error || row.TransferJurisdiction != in.TransferJurisdiction {
		return ErrDocumentAIAuditV1
	}
	c.row = row
	return nil
}
func (c *ApplicationDocumentAICostV1) NewAuditV1(ctx context.Context) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if c == nil {
		return nil, ErrDocumentAIAuditV1
	}
	c.mu.Lock()
	if c.closed || c.closeRequested || c.attempted || c.row == nil || c.source == nil || !c.source.valid(ctx) || c.usage == nil || !c.usage.liveBorrowedV1(ctx) {
		c.mu.Unlock()
		return nil, ErrDocumentAIAuditV1
	}
	c.attempted = true
	c.auditActive++
	u, row := c.usage, c.row
	scope := &applicationDocumentAIAuditScopeV1{cost: c, purpose: u.dispatch.costPurposeV1(), actor: u.dispatch.actor, signer: u.dispatch.signer}
	payload := map[string]any{"via": u.dispatch.via, "tool": u.dispatch.action, "request_event_id": u.request.id.String(), "usage_id": row.ID.String(), "provider": row.Provider, "model": row.Model, "shield_active": row.ShieldActive, "input_tokens": row.InputTokens, "output_tokens": row.OutputTokens, "success": row.Success, "transfer_jurisdiction": row.TransferJurisdiction}
	if u.dispatch.signer != nil {
		if err := u.dispatch.signer.notice.BindAuditPayload(payload); err != nil {
			c.mu.Unlock()
			c.finishAuditV1()
			return nil, err
		}
	}
	c.mu.Unlock()
	defer c.finishAuditV1()
	return scope.newEventV1(ctx, "", "", payload)
}
func (w *ApplicationDocumentAIWorkV1) NewResultAuditV1(ctx context.Context, r *ApplicationDocumentAIRequestReceiptV1, kind, ip, ua string, payload map[string]any) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if w == nil || w.state == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := w.state
	scope, err := func() (*applicationDocumentAIAuditScopeV1, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.validV1(ctx) || s.signer != nil || s.requested || s.snapshot == nil || s.result || !s.requestMatchesV1(r) {
			return nil, ErrDocumentAIAuditV1
		}
		purpose := HTMLAuditAIResultReadyV1
		if s.action == "check_bilingual_equivalence" && s.via == "rest" {
			purpose = HTMLAuditAIBilingualCheckedV1
		}
		if s.action == "run_risk_analysis" {
			purpose = HTMLAuditAIRiskAnalyzedV1
		}
		if kind != purpose.KindV1() || payload["request_event_id"] != r.id.String() || payload["tool"] != s.action || payload["via"] != s.via {
			return nil, ErrDocumentAIAuditV1
		}
		switch purpose {
		case HTMLAuditAIResultReadyV1:
			if len(payload) != 4 {
				return nil, ErrDocumentAIAuditV1
			}
			if _, ok := payload["provider_called"].(bool); !ok {
				return nil, ErrDocumentAIAuditV1
			}
		case HTMLAuditAIBilingualCheckedV1:
			if len(payload) != 6 {
				return nil, ErrDocumentAIAuditV1
			}
			if _, ok := payload["equivalent"].(bool); !ok {
				return nil, ErrDocumentAIAuditV1
			}
			if _, ok := payload["shield_active"].(bool); !ok {
				return nil, ErrDocumentAIAuditV1
			}
			if _, ok := payload["confidence"].(float64); !ok {
				return nil, ErrDocumentAIAuditV1
			}
		case HTMLAuditAIRiskAnalyzedV1:
			fields := []string{"findings_count"}
			expected := 5
			if s.via == "rest" {
				fields = []string{"findings_count", "high", "medium", "low", "latency_ms"}
				expected = 9
			}
			if len(payload) != expected {
				return nil, ErrDocumentAIAuditV1
			}
			for _, key := range fields {
				if _, ok := payload[key].(int); !ok {
					return nil, ErrDocumentAIAuditV1
				}
			}
			if _, ok := payload["shield_active"].(bool); !ok {
				return nil, ErrDocumentAIAuditV1
			}
		}

		s.result = true
		s.auditActive++
		return &applicationDocumentAIAuditScopeV1{work: s, purpose: purpose, actor: s.actor}, nil
	}()
	if err != nil {
		return nil, err
	}
	defer s.finishAuditV1()
	return scope.newEventV1(ctx, ip, ua, payload)
}
func (s *applicationDocumentAIAuditScopeV1) newEventV1(ctx context.Context, ip, ua string, payload map[string]any) (*ApplicationHTMLAuditEventConsumerV1, error) {
	h := s.sessionV1()
	if h == nil {
		return nil, ErrDocumentAIAuditV1
	}
	own := context.WithValue(ctx, applicationDocumentAIAuditKeyV1{}, s)
	recipient, actor := s.attributionV1()
	return h.newHTMLAuditEventCoreV1(own, s.purpose, h.state.org, h.state.document, recipient, actor, s.purpose.KindV1(), ip, ua, payload, nil, nil, nil, nil)
}
func (s *applicationDocumentAIAuditScopeV1) sessionV1() *ApplicationSessionV1 {
	if s == nil {
		return nil
	}
	if s.work != nil {
		return s.work.session
	}
	if s.cost != nil {
		return s.cost.session
	}
	return nil
}
func (s *applicationDocumentAIAuditScopeV1) matchesV1(ctx context.Context, h *ApplicationSessionV1, p HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, payload map[string]any) bool {
	if s == nil || s.sessionV1() != h || h == nil || h.state == nil || !applicationContextV1(ctx) || s.purpose != p || !documentAIAuditPurposeV1(p) || org != h.state.org || document != h.state.document || kind != p.KindV1() {
		return false
	}
	expectedRecipient, expectedActor := s.attributionV1()
	if recipient != expectedRecipient || actor != expectedActor {
		return false
	}
	if s.work != nil {
		s.work.mu.Lock()
		defer s.work.mu.Unlock()
		return s.signerPayloadMatchesV1(p, payload) && s.cost == nil && !s.work.closeAfterProvider && s.work.validV1(ctx) && s.work.snapshot != nil && s.work.policy != nil && payload["via"] == s.work.via && payload["tool"] == s.work.action && (s.work.signer == nil || s.work.checkSignerV1(ctx) == nil)
	}
	if s.cost == nil {
		return false
	}
	s.cost.mu.Lock()
	defer s.cost.mu.Unlock()
	return s.signerPayloadMatchesV1(p, payload) && !s.cost.closed && !s.cost.closeRequested && s.cost.row != nil && s.cost.usage != nil && s.cost.usage.liveBorrowedV1(ctx) && s.cost.usage.request.validV1() && s.cost.source != nil && s.cost.source.valid(ctx) && p == s.cost.usage.dispatch.costPurposeV1() && ip == "" && ua == "" && payload["request_event_id"] == s.cost.usage.request.id.String() && payload["usage_id"] == s.cost.row.ID.String()
}
func (s *applicationDocumentAIAuditScopeV1) lockScopeV1(ctx context.Context) error {
	h := s.sessionV1()
	if h == nil || h.state == nil {
		return ErrDocumentAIAuditV1
	}
	p := h.state
	root := uuid.Nil
	if s.work != nil {
		root = s.work.root
	} else if s.cost != nil {
		root = s.cost.root
	}
	if root == uuid.Nil {
		return ErrDocumentAIAuditV1
	}
	q := generated.New(&applicationOwnedDBTXV1{session: p})
	r, err := q.LockDocumentAIRootV1(ctx, generated.LockDocumentAIRootV1Params{RootDocumentID: root, OrgID: p.org})
	if err != nil {
		return err
	}
	if r == nil || r.RootDocumentID != root || r.RootHasParent || (root != p.document && !r.IsEnvelope) {
		return authoring.ErrAIAppDocumentClosed
	}
	// Acquire the actual logical member after its root, even for cost-only work.
	var id, org uuid.UUID
	if err := (&applicationOwnedDBTXV1{session: p}).QueryRow(ctx, `SELECT d.id,d.org_id FROM documents d WHERE d.id=$1 AND d.org_id=$2 AND d.deleted_at IS NULL FOR SHARE OF d`, p.document, p.org).Scan(&id, &org); err != nil {
		return err
	}
	if id != p.document || org != p.org {
		return ErrDocumentAIAuditV1
	}
	matches, err := q.DocumentAIRootMatchesV1(ctx, generated.DocumentAIRootMatchesV1Params{RootDocumentID: root, DocumentID: p.document, OrgID: p.org})
	if err != nil {
		return err
	}
	if !matches {
		return authoring.ErrAIAppDocumentClosed
	}
	policy, err := q.GetDocumentAIPolicyV1(ctx, generated.GetDocumentAIPolicyV1Params{RootDocumentID: root, DocumentID: p.document, OrgID: p.org})
	if err != nil {
		return err
	}
	if policy == nil || !policy.RootAllowed || !policy.DocumentAllowed || (s.signerRequestV1() != nil && (policy.RootDraft || policy.DocumentDraft)) {
		return authoring.ErrAIAppDocumentClosed
	}
	return nil
}
func (w *ApplicationDocumentAIWorkV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if s.providerActive > 0 || s.workflowActive > 0 || s.auditActive > 0 || s.readActive > 0 {
		s.closeAfterProvider = true
		s.mu.Unlock()
		return
	}
	s.closed = true
	release, reader, closes, signer := s.release, s.reader, s.closes, s.signer
	s.snapshot = nil
	s.policy = nil
	s.runtimeOwner = nil
	s.signerRecipient = nil
	s.release = nil
	s.closes = nil
	s.mu.Unlock()
	if release != nil {
		release()
	}
	if reader != nil {
		reader.CloseConsumerV1()
	}
	for _, close := range closes {
		close()
	}
	if signer != nil {
		signer.finishV1()
	}
}
func (u *ApplicationDocumentAIUsageReceiptV1) CloseConsumerV1() {
	if u == nil {
		return
	}
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.closed = true
	cancel := u.cancel
	u.retireLockedV1()
	u.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func (c *ApplicationDocumentAICostV1) CloseConsumerV1() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if c.auditActive > 0 {
		c.closeRequested = true
		c.mu.Unlock()
		return
	}
	c.closed = true
	source, closes, releaseUsage := c.source, c.closes, c.releaseUsage
	c.row = nil
	c.usage = nil
	c.source = nil
	c.queries = nil
	c.closes = nil
	c.releaseUsage = nil
	c.mu.Unlock()
	if source != nil {
		source.CloseConsumerV1()
	}
	for _, close := range closes {
		close()
	}
	if releaseUsage != nil {
		releaseUsage()
	}
}

type DocumentAIAuditIdentityV1 struct{ OrgID, DocumentID, ActorID, RecipientID uuid.UUID }

func (w *ApplicationDocumentAIWorkV1) AuditIdentityV1() (DocumentAIAuditIdentityV1, error) {
	if w == nil || w.state == nil {
		return DocumentAIAuditIdentityV1{}, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.session == nil || s.snapshot == nil {
		return DocumentAIAuditIdentityV1{}, ErrDocumentAIAuditV1
	}
	return DocumentAIAuditIdentityV1{OrgID: s.session.state.org, DocumentID: s.session.state.document, ActorID: s.actor, RecipientID: s.recipientIDV1()}, nil
}
func (c *ApplicationDocumentAICostV1) AuditIdentityV1() (DocumentAIAuditIdentityV1, error) {
	if c == nil {
		return DocumentAIAuditIdentityV1{}, ErrDocumentAIAuditV1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.session == nil || c.row == nil || c.usage == nil {
		return DocumentAIAuditIdentityV1{}, ErrDocumentAIAuditV1
	}
	return DocumentAIAuditIdentityV1{OrgID: c.session.state.org, DocumentID: c.session.state.document, ActorID: c.usage.dispatch.actor, RecipientID: c.usage.dispatch.recipientIDV1()}, nil
}

// Only the already-committed request's source has ended here. Keep the private
// receipt/typed owner loan until actual workflow end; ending this borrower is
// not physical/backend/registry retirement or inferred garbage collection.
func (w *ApplicationDocumentAIWorkV1) CloseCommittedRequestSourceV1(r *ApplicationDocumentAIRequestReceiptV1) error {
	if w == nil || w.state == nil || r == nil || r.event == nil {
		return ErrDocumentAIAuditV1
	}
	s := w.state
	r.event.mu.Lock()
	defer r.event.mu.Unlock()
	s.mu.Lock()
	if s.closed || !s.requested || r.request != s || r.event == nil || r.id == uuid.Nil || r.event.documentAI == nil || r.event.documentAI.work != s || r.event.eventID != r.id {
		s.mu.Unlock()
		return ErrDocumentAIAuditV1
	}
	p := s.session.state
	p.mu.Lock()
	ack := p.commitAttempted && p.ended && !p.commitUnknown
	p.mu.Unlock()
	if !ack {
		s.mu.Unlock()
		return ErrDocumentAIAuditV1
	}
	release, reader := s.release, s.reader
	s.release = nil
	s.snapshot = nil
	s.mu.Unlock()
	if release != nil {
		release()
	}
	if reader != nil {
		reader.CloseConsumerV1()
	}
	return nil
}

// Fixed same-native-work lifetime through Shield/provider/usage/result and the
// actual HTTP/MCP serialization borrower, not only providerActive.
type ApplicationDocumentAIWorkflowV1 struct {
	state *applicationDocumentAIWorkflowStateV1
}
type applicationDocumentAIWorkflowStateV1 struct {
	once sync.Once
	work *ApplicationDocumentAIWorkV1
}

func (w *ApplicationDocumentAIWorkV1) BeginWorkflowV1(ctx context.Context) (*ApplicationDocumentAIWorkflowV1, error) {
	if w == nil || w.state == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.requested || s.snapshot == nil || s.policy == nil || s.runtimeOwner == nil || s.workflowActive != 0 || s.closeAfterProvider {
		return nil, ErrDocumentAIAuditV1
	}
	if err := s.holdV1(ctx, 4*int64(unsafe.Sizeof(applicationDocumentAIWorkflowStateV1{})), 0); err != nil {
		return nil, err
	}
	s.workflowActive++
	return &ApplicationDocumentAIWorkflowV1{state: &applicationDocumentAIWorkflowStateV1{work: w}}, nil
}
func (h *ApplicationDocumentAIWorkflowV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	h.state.once.Do(func() {
		w := h.state.work
		if w == nil || w.state == nil {
			return
		}
		s := w.state
		s.mu.Lock()
		s.workflowActive--
		closing := s.closeAfterProvider && s.workflowActive == 0 && s.providerActive == 0
		s.mu.Unlock()
		if closing {
			w.CloseConsumerV1()
		}
	})
}

func (s *applicationDocumentAIStateV1) finishAuditV1() {
	s.mu.Lock()
	s.auditActive--
	closing := s.closeAfterProvider && s.auditActive == 0 && s.providerActive == 0 && s.workflowActive == 0 && s.readActive == 0
	self := s.self
	s.mu.Unlock()
	if closing && self != nil {
		self.CloseConsumerV1()
	}
}
func (c *ApplicationDocumentAICostV1) finishAuditV1() {
	c.mu.Lock()
	c.auditActive--
	closing := c.closeRequested && c.auditActive == 0
	c.mu.Unlock()
	if closing {
		c.CloseConsumerV1()
	}
}

func (s *applicationDocumentAIStateV1) finishReadV1() {
	s.mu.Lock()
	s.readActive--
	closing := s.closeAfterProvider && s.readActive == 0 && s.auditActive == 0 && s.providerActive == 0 && s.workflowActive == 0
	self := s.self
	s.mu.Unlock()
	if closing && self != nil {
		self.CloseConsumerV1()
	}
}
