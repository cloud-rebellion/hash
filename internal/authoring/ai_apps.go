// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package authoring

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// AIAppDeps contains the durable request, usage and result stores. All
// transports use the same authorization sequence, keeping incurred provider
// cost truthful even when the original credential expires before delivery.
type AIAppDeps struct {
	Pool    *pgxpool.Pool
	Queries *generated.Queries
	Audit   *audit.Logger
}

type AIAppRequest struct {
	Actor                      Actor
	DocumentID                 uuid.UUID
	Via, Action, IP, UserAgent string
}

type accountingAdmission struct {
	slot  chan struct{}
	users int
}

var accountingAdmissions = struct {
	sync.Mutex
	pools map[*pgxpool.Pool]*accountingAdmission
}{pools: make(map[*pgxpool.Pool]*accountingAdmission)}

// ReserveAIAccounting serializes durable AI requests per actual application
// pool and reserves cost-persistence capacity before any provider dispatch.
// Waiters hold no database connections. Registry entries disappear after the
// final request/waiter leaves, so short-lived pools do not accumulate globally.
// A one-connection pool cannot retain authority and independently preserve
// usage at the same time, so it is refused before provider processing.
func ReserveAIAccounting(ctx context.Context, pool *pgxpool.Pool) (*pgxpool.Conn, func(), error) {
	if pool == nil || pool.Config().MaxConns < 2 {
		return nil, nil, errors.New("AI accounting requires at least two database connections")
	}
	accountingAdmissions.Lock()
	gate := accountingAdmissions.pools[pool]
	if gate == nil {
		gate = &accountingAdmission{slot: make(chan struct{}, 1)}
		accountingAdmissions.pools[pool] = gate
	}
	gate.users++
	accountingAdmissions.Unlock()
	leaving := func() {
		accountingAdmissions.Lock()
		defer accountingAdmissions.Unlock()
		gate.users--
		if gate.users == 0 {
			delete(accountingAdmissions.pools, pool)
		}
	}
	select {
	case gate.slot <- struct{}{}:
	case <-ctx.Done():
		leaving()
		return nil, nil, ctx.Err()
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		<-gate.slot
		leaving()
		return nil, nil, err
	}
	var once sync.Once
	return conn, func() {
		once.Do(func() {
			conn.Release()
			<-gate.slot
			leaving()
		})
	}, nil
}

var (
	ErrAIAppDocumentClosed     = errors.New("document unavailable for AI or negotiation (must be draft or active)")
	ErrAIProposalNotFound      = errors.New("proposal not found in document")
	ErrAIProposalBlockMismatch = errors.New("parent proposal must refer to the same block")
	ErrAIBlockNotFound         = errors.New("block_id not in document tree")
)

type aiAppGuard struct {
	doc    *generated.Document
	member *MemberGuard
}

// Negotiation metadata may be added to an active frozen ceremony; it does not
// apply prose or change signed bytes. Parent-first locks serialize child tools
// with envelope send/finalization, while privacy holds exclude external AI use.
func lockAIApp(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID, shared bool) (*aiAppGuard, error) {
	q := generated.New(tx)
	initial, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: id, OrgID: actor.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDocumentNotFound
	}
	if err != nil {
		return nil, err
	}
	lock := func(id uuid.UUID) (*generated.Document, error) {
		if shared {
			return q.GetDocumentForShare(ctx, generated.GetDocumentForShareParams{ID: id, OrgID: actor.OrgID})
		}
		return q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: id, OrgID: actor.OrgID})
	}
	var family []*generated.Document
	if initial.ParentEnvelopeID.Valid {
		root, err := lock(uuid.UUID(initial.ParentEnvelopeID.Bytes))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrDocumentNotFound
			}
			return nil, err
		}
		if !root.IsEnvelope || root.ParentEnvelopeID.Valid {
			return nil, ErrAIAppDocumentClosed
		}
		family = append(family, root)
	}
	doc, err := lock(id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDocumentNotFound
	}
	if err != nil {
		return nil, err
	}
	if doc.ParentEnvelopeID != initial.ParentEnvelopeID {
		return nil, ErrAIAppDocumentClosed
	}
	family = append(family, doc)
	member, err := LockAuthor(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	fence, err := q.TryCollabArchivePrivacyFence(ctx, actor.OrgID)
	if err != nil {
		return nil, err
	}
	if !fence {
		return nil, ErrPrivacyReviewChanging
	}
	for _, parent := range family {
		switch parent.Status {
		case "draft", "sent", "in_progress", "changes_requested":
		default:
			return nil, ErrAIAppDocumentClosed
		}
		if parent.Status == "draft" {
			retained, err := q.HasRetainedDraftSigningEvidence(ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: parent.ID, OrgID: actor.OrgID})
			if err != nil {
				return nil, err
			}
			if retained {
				return nil, ErrDocumentHasEvidence
			}
		}
		pending, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: parent.ID, OrgID: actor.OrgID})
		if err != nil {
			return nil, err
		}
		if pending {
			return nil, ErrPendingPrivacyReview
		}
	}
	return &aiAppGuard{doc: doc, member: member}, nil
}

func AIAppBlock(doc *generated.Document, id string) (*blocks.Block, error) {
	tree, err := blocks.ParseTree(doc.BlocksJson)
	if err != nil {
		return nil, err
	}
	for i := range tree.Blocks {
		if tree.Blocks[i].ID == id {
			return &tree.Blocks[i], nil
		}
	}
	return nil, ErrAIBlockNotFound
}

func CommitNegotiationMutation[T any](parent context.Context, deps AIAppDeps, actor Actor, id uuid.UUID,
	mutate func(context.Context, *generated.Queries, *generated.Document) (T, error), event func(T) audit.Entry,
) (T, error) {
	var zero T
	if deps.Pool == nil || deps.Audit == nil || mutate == nil || event == nil {
		return zero, errors.New("AI mutation dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, MutationTimeout)
	defer cancel()
	tx, err := deps.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return zero, err
	}
	defer func() { _ = Rollback(ctx, tx) }()
	guard, err := lockAIApp(ctx, tx, actor, id, false)
	if err != nil {
		return zero, err
	}
	value, err := mutate(ctx, generated.New(tx), guard.doc)
	if err != nil {
		return zero, err
	}
	entry := event(value)
	if entry.OrgID != actor.OrgID || entry.DocumentID == nil || *entry.DocumentID != id || entry.ActorUserID == nil || *entry.ActorUserID != actor.UserID {
		return zero, auth.ErrMutationPermissionRevoked
	}
	pending, err := deps.Audit.LogTx(ctx, tx, entry)
	if err != nil {
		return zero, err
	}
	if err := guard.member.Recheck(ctx); err != nil {
		return zero, err
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, err
	}
	deps.Audit.Publish(pending)
	return value, nil
}

// Provider cost is a server observation of an already-authorized dispatch,
// rather than a user result mutation. Its receipt-bound insert survives expiry,
// cancellation and result-audit rollback. No generated provider text is logged.
func CompleteDocumentAI[T any](parent context.Context, deps AIAppDeps, request AIAppRequest, runtime *ai.Runtime,
	complete func(context.Context, *ai.Runtime, *generated.Document) (T, error), event func(T) audit.Entry,
) (T, error) {
	var zero T
	fail := func(err error) (T, error) { return zero, err }
	actor, id, tool := request.Actor, request.DocumentID, request.Action
	if deps.Pool == nil || deps.Audit == nil || deps.Queries == nil || runtime == nil || complete == nil || tool == "" || request.Via == "" {
		return fail(errors.New("AI completion dependencies unavailable"))
	}
	ctx, cancel := context.WithTimeout(parent, 35*time.Second)
	defer cancel()
	// Reserve accounting before acquiring the request/dispatch transaction.
	// It remains available even when all other pool slots are held by waiting
	// application traffic or the process's singleton worker lease.
	accounting, releaseAccounting, err := ReserveAIAccounting(ctx, deps.Pool)
	if err != nil {
		return fail(err)
	}
	defer releaseAccounting()
	requestTx, err := deps.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fail(err)
	}
	defer func() { _ = Rollback(ctx, requestTx) }()
	requested, err := lockAIApp(ctx, requestTx, actor, id, true)
	if err != nil {
		return fail(err)
	}
	receipt, err := deps.Audit.LogTx(ctx, requestTx, audit.Entry{OrgID: actor.OrgID, DocumentID: &id, ActorUserID: &actor.UserID, Kind: "ai.requested", IP: request.IP, UserAgent: request.UserAgent, Payload: map[string]any{"via": request.Via, "tool": tool}})
	if err != nil {
		return fail(err)
	}
	if err := requested.member.Recheck(ctx); err != nil {
		return fail(err)
	}
	if err := requestTx.Commit(ctx); err != nil {
		return fail(err)
	}
	deps.Audit.Publish(receipt)

	// Reacquire fresh authority after the durable request commits. Revocation
	// in this gap must prevent provider dispatch, including one-use tokens.
	tx, err := deps.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fail(err)
	}
	defer func() { _ = Rollback(ctx, tx) }()
	guard, err := lockAIApp(ctx, tx, actor, id, true)
	if err != nil {
		return fail(err)
	}
	observed := false
	scoped := runtime.ForAuditedRequest(generated.New(tx), func(_ context.Context, params generated.InsertAICompletionAuditParams) error {
		if observed || params.OrgID != actor.OrgID || !params.DocumentID.Valid || uuid.UUID(params.DocumentID.Bytes) != id || !params.ActorUserID.Valid || uuid.UUID(params.ActorUserID.Bytes) != actor.UserID {
			return errors.New("AI usage receipt mismatch")
		}
		observed = true
		costCtx, costCancel := context.WithTimeout(context.WithoutCancel(parent), MutationTimeout)
		defer costCancel()
		usage, err := generated.New(accounting).InsertRequestedAICompletionAudit(costCtx, generated.InsertRequestedAICompletionAuditParams{
			RequestEventID: receipt.ID, OrgID: actor.OrgID, DocumentID: id, ActorUserID: actor.UserID,
			Provider: params.Provider, Model: params.Model, PromptName: params.PromptName, PromptVersion: params.PromptVersion, ShieldActive: params.ShieldActive,
			InputTokens: params.InputTokens, OutputTokens: params.OutputTokens, LatencyMs: params.LatencyMs, Success: params.Success, Error: params.Error, TransferJurisdiction: params.TransferJurisdiction,
		})
		if err != nil {
			slog.Error("AI usage persistence failed", "request_event_id", receipt.ID, "org_id", actor.OrgID, "tool", tool)
			return errors.New("AI usage persistence failed")
		}
		costTx, err := accounting.BeginTx(costCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return errors.New("AI completion event persistence failed")
		}
		defer func() { _ = Rollback(costCtx, costTx) }()
		costEvent, err := deps.Audit.LogTx(costCtx, costTx, audit.Entry{OrgID: actor.OrgID, DocumentID: &id, ActorUserID: &actor.UserID, Kind: "ai.completed", Payload: map[string]any{
			"via": request.Via, "tool": tool, "request_event_id": receipt.ID.String(), "usage_id": usage.ID.String(), "provider": params.Provider, "model": params.Model,
			"shield_active": params.ShieldActive, "input_tokens": params.InputTokens, "output_tokens": params.OutputTokens, "success": params.Success, "transfer_jurisdiction": params.TransferJurisdiction,
		}})
		if err != nil {
			slog.Error("AI completion event persistence failed", "request_event_id", receipt.ID, "org_id", actor.OrgID, "tool", tool)
			return errors.New("AI completion event persistence failed")
		}
		if err := costTx.Commit(costCtx); err != nil {
			return errors.New("AI completion event persistence failed")
		}
		deps.Audit.Publish(costEvent)
		return nil
	})
	if err := guard.member.Recheck(ctx); err != nil {
		return fail(err)
	}
	value, err := complete(ctx, scoped, guard.doc)
	if err != nil {
		return fail(err)
	}
	if err := guard.member.Recheck(ctx); err != nil {
		return fail(err)
	}
	entry := audit.Entry{OrgID: actor.OrgID, DocumentID: &id, ActorUserID: &actor.UserID, Kind: "ai.result_ready", IP: request.IP, UserAgent: request.UserAgent, Payload: map[string]any{"via": request.Via, "tool": tool, "request_event_id": receipt.ID.String(), "provider_called": observed}}
	if event != nil {
		entry = event(value)
		if entry.Payload == nil {
			entry.Payload = map[string]any{}
		}
		entry.Payload["request_event_id"] = receipt.ID.String()
		entry.Payload["tool"] = tool
		entry.Payload["via"] = request.Via
	}
	if entry.OrgID != actor.OrgID || entry.DocumentID == nil || *entry.DocumentID != id || entry.ActorUserID == nil || *entry.ActorUserID != actor.UserID {
		return fail(auth.ErrMutationPermissionRevoked)
	}
	pending, err := deps.Audit.LogTx(ctx, tx, entry)
	if err != nil {
		return fail(err)
	}
	if err := guard.member.Recheck(ctx); err != nil {
		return fail(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fail(err)
	}
	deps.Audit.Publish(pending)
	return value, nil
}
