// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// One actual caller context is captured BEFORE a shorter SQL child exists.
// It is retained through pure source preparation, providers, sealing recovery,
// returned links and joined direct-mail use. It grants no child/family scope.
type ownedSendOperationV1 struct {
	mu                      sync.Mutex
	self                    *ownedSendOperationV1
	engine                  *Engine
	runtime                 *pdfadmission.WorkRuntimeV1
	factory                 *pdfadmission.ApplicationSessionFactoryV1
	native                  *pdfadmission.ApplicationHTMLSendOperationV1
	original                context.Context
	deadline                time.Time
	org, document           uuid.UUID
	works                   []*pdfadmission.ApplicationHTMLSendWorkV1
	closed, resourcesClosed bool
	initialStagesRetired    bool
	mailers                 int
}
type ownedSendPendingAuditV1 struct {
	event audit.PendingEvent
	owner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
}
type ownedSendPhaseV1 struct {
	operation *ownedSendOperationV1
	session   *pdfadmission.ApplicationSessionV1
	stage     *pdfadmission.ApplicationHTMLSendSQLStageV1
	admission *pdfadmission.ApplicationAdmissionV1
	work      *pdfadmission.ApplicationHTMLSendWorkV1
	pending   []ownedSendPendingAuditV1
}

func (e *Engine) newOwnedSendOperationV1(ctx context.Context, org, document uuid.UUID) (*ownedSendOperationV1, error) {
	if e == nil || e.Pool == nil || e.Queries == nil || e.Audit == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || org == uuid.Nil || document == uuid.Nil || ctx == nil || ctx.Err() != nil {
		return nil, pdfadmission.ErrHTMLSendWorkV1
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) {
		return nil, pdfadmission.ErrHTMLSendWorkV1
	}
	o := &ownedSendOperationV1{engine: e, runtime: e.WorkRuntime, factory: e.WorkRuntime.SessionsV1(), original: ctx, deadline: deadline, org: org, document: document}
	o.self = o
	if o.factory == nil {
		return nil, pdfadmission.ErrHTMLSendWorkV1
	}
	var err error
	o.native, err = o.factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return nil, err
	}
	return o, nil
}
func (o *ownedSendOperationV1) valid(ctx context.Context) bool {
	if o == nil || o.self != o || ctx == nil || o.original == nil || o.original.Err() != nil || ctx.Err() != nil || o.engine == nil || o.runtime == nil || o.engine.WorkRuntime != o.runtime || !o.runtime.MatchesPoolV1(o.engine.Pool) || o.factory != o.runtime.SessionsV1() {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && !deadline.After(o.deadline) && time.Now().Before(o.deadline)
}

// Private only: all callsites below are fixed Send stages. Actual row/source
// admission is made by the same session-owned work object BEFORE model SQL;
// this trusted fixed application callback is not a size/authority API.
func (o *ownedSendOperationV1) phaseV1(purpose pdfadmission.HTMLSendSQLPurposeV1, fn func(context.Context, *ownedSendPhaseV1, *generated.Queries, pgx.Tx) error) error {
	if !o.valid(o.original) || fn == nil || o.native == nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	o.mu.Lock()
	closed := o.closed
	o.mu.Unlock()
	if closed {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	p := &ownedSendPhaseV1{operation: o}
	var err error
	p.stage, err = o.native.OpenSQLV1(purpose)
	if err != nil {
		return err
	}
	ctx := p.stage.ContextV1()
	p.session = p.stage.SessionV1()
	if ctx == nil || p.session == nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = p.stage.CloseSQLV1()
		if p.admission != nil {
			_, _ = p.admission.ReconcileCleanupV1(cleanup)
		}
	}()
	defer func() {
		for _, pending := range p.pending {
			if pending.owner != nil {
				pending.owner.CloseConsumerV1()
			}
		}
	}()
	p.admission, err = p.session.NewAdmissionV1(ctx)
	if err != nil {
		return err
	}
	err = p.stage.WithTxV1(func(owned context.Context, db generated.DBTX) error {
		var e error
		p.work, e = p.session.NewHTMLSendWorkV1(owned, p.stage)
		if e != nil {
			return e
		}
		o.mu.Lock()
		if o.closed {
			o.mu.Unlock()
			p.work.CloseConsumerV1()
			return pdfadmission.ErrHTMLSendWorkV1
		}
		o.works = append(o.works, p.work)
		o.mu.Unlock()
		return fn(owned, p, generated.New(db), &sendOwnedPolicyTxV1{DBTX: db})
	})
	if err != nil {
		return err
	}
	err = p.session.CommitV1(ctx)
	if err != nil {
		// Inspect only after synchronous SAME-owner Commit. Both a dispatched
		// error and predispatch refusal return without publication/retry. Physical
		// retirement and original consumer conjunction alone govern debt release.
		_ = p.session.CommitDispatchObservationV1()
		return err
	}
	for i := range p.pending {
		pending := &p.pending[i]
		if err = ownedaudit.PublishV1(o.engine.Audit, pending.event, pending.owner); err != nil {
			return err
		}
		pending.owner = nil
	}
	return nil
}
func (p *ownedSendPhaseV1) appendAuditEntriesV1(ctx context.Context, entries []audit.Entry) error {
	if p == nil || p.operation == nil || p.session == nil {
		return pdfadmission.ErrHTMLAuditEventV1
	}
	for _, entry := range entries {
		var purpose pdfadmission.HTMLAuditPurposeV1
		switch entry.Kind {
		case audit.KindRecipientInvited:
			purpose = pdfadmission.HTMLAuditRecipientInvitedV1
		case audit.KindDocumentSent:
			purpose = pdfadmission.HTMLAuditDocumentSentV1
		case audit.KindDocumentExpired:
			purpose = pdfadmission.HTMLAuditDocumentExpiredV1
		case "crm.variables.observed":
			purpose = pdfadmission.HTMLAuditCRMObservedV1
		default:
			return pdfadmission.ErrHTMLAuditEventV1
		}
		if entry.DocumentID == nil || entry.OrgID != p.operation.org {
			return pdfadmission.ErrHTMLAuditEventV1
		}
		var event audit.PendingEvent
		var owner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
		var err error
		if *entry.DocumentID == p.operation.document {
			event, owner, err = ownedaudit.LogV1(p.operation.engine.Audit, ctx, p.session, purpose, entry)
		} else {
			member := p.work.EnvelopeMemberForAuditV1(ctx, *entry.DocumentID)
			if member == nil {
				return pdfadmission.ErrHTMLAuditEventV1
			}
			event, owner, err = ownedaudit.LogEnvelopeMemberV1(p.operation.engine.Audit, ctx, member, purpose, entry)
		}
		if err != nil {
			return err
		}
		p.pending = append(p.pending, ownedSendPendingAuditV1{event: event, owner: owner})
	}
	return nil
}
func (o *ownedSendOperationV1) retireConsumersLockedV1() []*pdfadmission.ApplicationHTMLSendWorkV1 {
	if !o.closed || o.resourcesClosed || o.mailers != 0 {
		return nil
	}
	o.resourcesClosed = true
	works := o.works
	o.works = nil
	return works
}
func (o *ownedSendOperationV1) closeConsumerV1() {
	if o == nil || o.self != o {
		return
	}
	o.mu.Lock()
	o.closed = true
	works := o.retireConsumersLockedV1()
	o.mu.Unlock()
	o.releaseWorksV1(works)
}
func (o *ownedSendOperationV1) releaseWorksV1(works []*pdfadmission.ApplicationHTMLSendWorkV1) {
	o.mu.Lock()
	retired := o.resourcesClosed
	o.mu.Unlock()
	if !retired {
		return
	}
	if o.native != nil {
		o.native.CloseConsumerV1()
	}
	for _, work := range works {
		if work != nil {
			work.CloseConsumerV1()
		}
	}
	if len(works) != 0 {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(o.original), 5*time.Second)
		defer cancel()
		_ = o.factory.ReconcileCleanupV1(cleanup)
	}
}
func (o *ownedSendOperationV1) sendEmailV1(kind, toEmail, toName, docName, senderEmail, signURL, beaconURL, locale string, requiresSignature bool) {
	e := o.engine
	if e.Mailer == nil {
		return
	}
	msg, err := e.renderEmail(kind, toEmail, toName, docName, senderEmail, signURL, beaconURL, locale, requiresSignature)
	if err != nil {
		slog.Warn("send: email template render failed", "kind", kind, "err", err)
		return
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.mailers++
	o.mu.Unlock()
	go func() {
		defer func() {
			msg = dispatch.Message{}
			o.mu.Lock()
			o.mailers--
			works := o.retireConsumersLockedV1()
			o.mu.Unlock()
			o.releaseWorksV1(works)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := e.Mailer.Send(ctx, msg); err != nil {
			slog.Warn("send: email send failed", "to", dispatch.MaskEmail(toEmail), "kind", kind, "err", dispatch.ScrubEmails(err.Error()))
		}
	}()
}

// CloseConsumerV1 ends this actual returned result's last-use consumer. All
// REST/MCP/automation/worker callers close after serialization or final use,
// including an error response whose typed policy error retains source strings.
// Active direct mailers keep the same owned work until their real calls join.
func (r *SendResult) CloseConsumerV1() {
	if r == nil {
		return
	}
	owner := r.owner
	r.owner = nil
	if owner != nil {
		owner.closeConsumerV1()
	}
}
func (e *Engine) Send(ctx context.Context, a Actor, docID uuid.UUID) (out SendResult, err error) {
	if err = requireActorAuthorization(a); err != nil {
		return out, err
	}
	operation, err := e.newOwnedSendOperationV1(ctx, a.OrgID, docID)
	if err != nil {
		return out, err
	}
	transferred := false
	defer func() {
		if !transferred {
			operation.closeConsumerV1()
		}
	}()
	if a.PackageSend.PresentV1() {
		if !a.PackageSend.ValidV1() {
			return out, pdfadmission.ErrPackageSendSelectionChangedV1
		}
		var found bool
		out, found, err = e.findOwnedPackageSendSelectionV1(ctx, operation, a)
		if err != nil || found {
			if err != nil {
				packageSendFailureDiagnosticV1("selection_lookup", err)
			}
			out.owner = operation
			transferred = true
			return out, err
		}
	}
	out, err = e.sendOwnedStagesV1(ctx, operation, a, docID)
	out.owner = operation
	transferred = true
	return out, err
}
func (e *Engine) ResumeSendSealing(ctx context.Context, docID, orgID uuid.UUID) (out SendResult, err error) {
	operation, err := e.newOwnedSendOperationV1(ctx, orgID, docID)
	if err != nil {
		return out, err
	}
	transferred := false
	defer func() {
		if !transferred {
			operation.closeConsumerV1()
		}
	}()
	// A new recovery operation has no preparation consumers. Record that fixed
	// empty boundary before opening its fresh snapshot stages.
	if err = operation.retireInitialStagesV1(); err != nil {
		return out, err
	}
	out, err = e.resumeOwnedSendSealingV1(ctx, operation, docID, orgID)
	out.owner = operation
	transferred = true
	return out, err
}

type ownedSendReadV1 struct {
	models       *pdfadmission.HTMLSendModelsV1
	work         *pdfadmission.ApplicationHTMLSendWorkV1
	source       *pdfadmission.ApplicationHTMLSendSourceV1
	resolution   *pdfadmission.ApplicationHTMLSendResolutionV1
	members      []*ownedSendFamilyMemberV1
	packageDraft *pdfadmission.ApplicationHTMLSendPackageDraftV1
}

func (e *Engine) readOwnedDraftForSendV1(ctx context.Context, o *ownedSendOperationV1, a Actor) (prepared *ownedSendPreparedV1, err error) {
	err = o.phaseV1(pdfadmission.HTMLSendPreparationV1, func(owned context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		state, err := p.work.StateV1(owned)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDocumentNotFound
		}
		if err != nil {
			return err
		}
		if state.BoundedStatus != "draft" {
			return ErrNotDraft
		}
		if err = ValidateExpiryForSend(state.ExpiresAt, e.now()); err != nil {
			return err
		}
		if state.ParentEnvelopeID.Valid {
			return ErrEnvelopeChildLifecycle
		}
		// Native standalone scope remains explicit. Family work requires its actual
		// family owner and may not silently use this document-only authority.
		if state.IsEnvelope && !state.RequiresSignature {
			return ErrEnvelopeRequiresSignature
		}
		if !state.RequiresSignature && !state.IsPdfSource {
			return ErrAcknowledgementNeedsPDF
		}
		actorUser, err := authorizeOwnedLifecycleActorV1(owned, p, tx, &a)
		if err != nil {
			return err
		}
		policy, err := p.work.ReadInitialPolicyV1(owned)
		if err != nil {
			return err
		}
		if !state.RequiresSignature && (!policy.PdfStorageKey.Valid || strings.TrimSpace(policy.PdfStorageKey.String) == "" || policy.PdfSha256Bytes != 32) {
			return ErrAcknowledgementNeedsPDF
		}
		if err = requireSupportedSignatureTier(eidas.Tier(policy.RoutingTier), eidas.TierSES); err != nil {
			return err
		}
		if err = ValidateLawfulBasis(a.LawfulBasis); err != nil {
			return err
		}
		if e.Billing != nil {
			if err = p.work.EnforceQuotaV1(owned, e.Billing); err != nil {
				return err
			}
		}
		models, err := p.work.ReadModelsV1(owned)
		if err != nil {
			return err
		}
		doc := models.Document
		if doc == nil || doc.ID != state.ID || doc.OrgID != state.OrgID || doc.UpdatedAt != state.UpdatedAt || doc.RoutingTier != policy.RoutingTier || doc.RequiresSignature != state.RequiresSignature {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		if err = requireLifecycleRoot(doc); err != nil {
			return err
		}
		if err = validateAcknowledgementSend(doc); err != nil {
			return err
		}
		if _, err = p.work.ReadRecipientsV1(owned); err != nil {
			return err
		}
		source, err := p.work.NewSourceV1(owned)
		if err != nil {
			return err
		}
		read := &ownedSendReadV1{models: models, work: p.work, source: source}
		if e.Resolver != nil && !doc.IsEnvelope {
			read.resolution, err = p.work.NewResolverV1(owned, source, e.Resolver)
			if err != nil {
				return err
			}
		}
		prepared, err = e.prepareOwnedSendV1(owned, read)
		if err != nil {
			return err
		}
		if err = p.work.CheckPackageSendSelectionV1(owned, a.PackageSend); err != nil {
			return err
		}
		if a.PackageSend.PresentV1() {
			if err = source.ValidateReviewedV1(); err != nil {
				return err
			}
			if err = source.ValidateCurrentV1(); err != nil {
				return err
			}
			read.packageDraft, err = p.work.ReadDocumentPackageDraftV1(owned, source, pdfadmission.DocumentPackageDraftExpectedV1{PackageID: a.PackageSend.PackageID, Generation: a.PackageSend.Generation})
			if err != nil {
				return err
			}
		}
		return reauthorizeLifecycleActor(owned, tx, a, actorUser)
	})
	return prepared, err
}

// Called only at the fixed successful intent-commit boundary, after the entry
// function has dropped every preparation/resolver/model view. All initial CPU,
// source and provider calls have synchronously joined and phaseV1's SQL Close
// has returned. Unknown physical debt remains in its actual native registry;
// signalling these real finished consumers never invents backend/GC credit.
func (o *ownedSendOperationV1) retireInitialStagesV1() error {
	if o == nil || o.self != o || o.factory == nil || o.original == nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	o.mu.Lock()
	if o.closed || o.initialStagesRetired || o.mailers != 0 {
		o.mu.Unlock()
		return pdfadmission.ErrHTMLSendWorkV1
	}
	if err := o.native.RetirePreparationResolversV1(); err != nil {
		o.mu.Unlock()
		return err
	}
	o.initialStagesRetired = true
	list := o.works
	o.works = nil
	o.mu.Unlock()
	for _, work := range list {
		work.CloseConsumerV1()
	}
	// Initial root/member model, resolver and source consumers just reached their
	// actual last use. Their Close notifications alone do not credit the native
	// coordinator. Reconcile the existing physical/consumer conjunction before
	// opening recovery phases; uncertain backend/observer debt remains charged.
	cleanup, stop := context.WithTimeout(context.WithoutCancel(o.original), 5*time.Second)
	defer stop()
	err := o.factory.ReconcileCleanupV1(cleanup)
	if err != nil && (!errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		return err
	}
	return nil
}

// Called only after the complete fields phase has committed and its callback
// has returned. Snapshot/evidence have replaced every old source view. Retire
// ONLY its exact two superseded Works; unrelated intent/marker models can still
// escape their callbacks and keep their original consumers until final use.
func (o *ownedSendOperationV1) retireSupersededSnapshotStagesV1(current, original, pinned *pdfadmission.ApplicationHTMLSendWorkV1) error {
	if o == nil || o.self != o || o.factory == nil || o.original == nil || current == nil || original == nil || pinned == nil || current == original || current == pinned || original == pinned {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	o.mu.Lock()
	if o.closed || !o.initialStagesRetired || o.mailers != 0 {
		o.mu.Unlock()
		return pdfadmission.ErrHTMLSendWorkV1
	}
	var foundCurrent, foundOriginal, foundPinned bool
	for _, work := range o.works {
		foundCurrent = foundCurrent || work == current
		foundOriginal = foundOriginal || work == original
		foundPinned = foundPinned || work == pinned
	}
	if !foundCurrent || !foundOriginal || !foundPinned {
		o.mu.Unlock()
		return pdfadmission.ErrHTMLSendWorkV1
	}
	retained := 0
	for _, work := range o.works {
		if work != original && work != pinned {
			o.works[retained] = work
			retained++
		}
	}
	clear(o.works[retained:])
	o.works = o.works[:retained]
	o.mu.Unlock()
	original.CloseConsumerV1()
	pinned.CloseConsumerV1()
	// Consumer notifications do not themselves release native debt. Ask the
	// existing factory to check the actual physical/consumer conjunction NOW,
	// before the next provider acquisition. Unknown observer/backend debt stays
	// charged; neither cancellation nor a cleanup deadline proves retirement.
	cleanup, stop := context.WithTimeout(context.WithoutCancel(o.original), 5*time.Second)
	defer stop()
	err := o.factory.ReconcileCleanupV1(cleanup)
	if err != nil && (!errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		return err
	}
	return nil
}

// End exactly one successful intent-only read after its real fixed scalar
// capture has replaced every row consumer. No other active or escaped model
// work is retired, and unknown physical/backend debt remains charged.
func (o *ownedSendOperationV1) retireIntentReadWorkV1(work *pdfadmission.ApplicationHTMLSendWorkV1) error {
	return o.retireFinishedOwnedWorkV1(work)
}

// Only the actual completed snapshot witness can reach this fixed boundary.
func (o *ownedSendOperationV1) retireSnapshotForCompletionV1(work *pdfadmission.ApplicationHTMLSendWorkV1, reference *pdfadmission.ApplicationHTMLSendCompletionReferenceV1) error {
	if o == nil || reference == nil || !reference.MatchesOperationV1(o.native) {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	return o.retireFinishedOwnedWorkV1(work)
}

// Private mechanism shared by the TWO fixed callsites above, after their
// genuine native projection/witness has replaced every escaped body consumer.
func (o *ownedSendOperationV1) retireFinishedOwnedWorkV1(work *pdfadmission.ApplicationHTMLSendWorkV1) error {
	if o == nil || o.self != o || work == nil || o.factory == nil || o.original == nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	o.mu.Lock()
	if o.closed || !o.initialStagesRetired || o.mailers != 0 {
		o.mu.Unlock()
		return pdfadmission.ErrHTMLSendWorkV1
	}
	index := -1
	for i, candidate := range o.works {
		if candidate == work {
			index = i
			break
		}
	}
	if index < 0 {
		o.mu.Unlock()
		return pdfadmission.ErrHTMLSendWorkV1
	}
	copy(o.works[index:], o.works[index+1:])
	o.works[len(o.works)-1] = nil
	o.works = o.works[:len(o.works)-1]
	o.mu.Unlock()
	work.CloseConsumerV1()
	cleanup, stop := context.WithTimeout(context.WithoutCancel(o.original), 5*time.Second)
	defer stop()
	err := o.factory.ReconcileCleanupV1(cleanup)
	if err != nil && (!errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return err
	}
	return nil
}
