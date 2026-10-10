// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Engine struct {
	pool     *pgxpool.Pool
	logger   audit.TxAppender
	receipts *auth.SignedCookie
}

func NewEngine(pool *pgxpool.Pool, logger audit.TxAppender, receipts *auth.SignedCookie) *Engine {
	return &Engine{pool: pool, logger: logger, receipts: receipts}
}

type transactionState struct {
	ctx   context.Context
	tx    pgx.Tx
	q     *generated.Queries
	actor SessionActor
	user  *generated.User
	final func() error
	event *audit.Entry
}

func clock(s *transactionState) (time.Time, error) {
	now, err := s.q.GetPresignClock(s.ctx)
	if err != nil {
		return time.Time{}, err
	}
	if !now.Valid {
		return time.Time{}, ErrUnavailable
	}
	return now.Time.UTC().Truncate(time.Microsecond), nil
}
func timestamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
func unhex(v string) []byte                    { raw, _ := hex.DecodeString(v); return raw }
func eligible(u *generated.User) bool          { return u != nil && (u.Role == "owner" || u.Role == "sender") }
func witness(a SessionActor, org, user, request uuid.UUID) error {
	if a.authorize == nil || a.orgID == uuid.Nil || a.userID == uuid.Nil || org != a.orgID || user != a.userID || request == uuid.Nil {
		return auth.ErrMutationPermissionRevoked
	}
	return nil
}
func lookupError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (e *Engine) transaction(ctx context.Context, a SessionActor, fn func(*transactionState) error) error {
	if e == nil || e.pool == nil || a.authorize == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, MutationTimeout)
	defer cancel()
	tx, err := e.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := generated.New(tx)
	if _, err := q.GetOrgForOwnerMutation(ctx, a.orgID); err != nil {
		return lookupError(err)
	}
	u, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: a.userID, OrgID: a.orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return err
	}
	if err := a.authorize(ctx, tx, u); err != nil {
		return err
	}
	s := &transactionState{ctx: ctx, tx: tx, q: q, actor: a, user: u}
	if err := fn(s); err != nil {
		return err
	}
	var pending audit.PendingEvent
	if s.event != nil {
		if e.logger == nil {
			return ErrUnavailable
		}
		pending, err = e.logger.LogTx(ctx, tx, *s.event)
		if err != nil {
			return errors.Join(ErrAudit, err)
		}
	}
	if s.final != nil {
		if err := s.final(); err != nil {
			return err
		}
	}
	if err := a.authorize(ctx, tx, u); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if s.event != nil {
		e.logger.Publish(pending)
	}
	return nil
}

func commandDigest(operation string, value any) (string, error) {
	raw, err := canonical(value)
	if err != nil {
		return "", err
	}
	return domainSHA("hash:presign-command:v1:"+operation, raw), nil
}

func requestOutcome(row *generated.PresignMutationRequest) (Outcome, error) {
	var out Outcome
	if row == nil || strictDecode(row.OutcomeJson, &out, 8192) != nil || out.OrgID != row.OrgID || out.UserID != row.ActorUserID || out.RequestID != row.RequestID || out.State != row.State || out.Operation != row.Operation || !row.OccurredAt.Valid || !out.OccurredAt.Equal(row.OccurredAt.Time) {
		return out, ErrUnavailable
	}
	if row.State == "closed" {
		if out.Operation != OperationCloseRequest || out.Reference != (presign.Reference{}) || out.ResourceKind != "" || out.CommandSHA256 != "" {
			return out, ErrUnavailable
		}
	} else if row.State != "committed" || out.CommandSHA256 != hex.EncodeToString(row.CommandSha256) || !validSHA(out.CommandSHA256) || !row.ResourceID.Valid || !row.ResourceRevision.Valid || !row.ResourceKind.Valid || out.Reference.ID != uuid.UUID(row.ResourceID.Bytes) || out.Reference.Revision != row.ResourceRevision.Int64 || out.Reference.SHA256 != hex.EncodeToString(row.ResourceSha256) || out.ResourceKind != row.ResourceKind.String {
		return out, ErrUnavailable
	}
	return out, nil
}

func priorRequest(s *transactionState, id uuid.UUID, op, digest string) (*Outcome, error) {
	r, err := s.q.GetOwnPresignMutationRequest(s.ctx, generated.GetOwnPresignMutationRequestParams{OrgID: s.actor.orgID, ActorUserID: s.actor.userID, RequestID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out, err := requestOutcome(r)
	if err != nil {
		return nil, err
	}
	if op != "" && (out.State != "committed" || out.Operation != op || out.CommandSHA256 != digest) {
		return nil, ErrConflict
	}
	return &out, nil
}

func finishMutation(s *transactionState, id uuid.UUID, op, digest, kind string, ref presign.Reference) (Outcome, error) {
	now, err := clock(s)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{OrgID: s.actor.orgID, UserID: s.actor.userID, RequestID: id, State: "committed", Operation: op, CommandSHA256: digest, ResourceKind: kind, Reference: ref, OccurredAt: now}
	if err := insertOutcome(s, out); err != nil {
		return Outcome{}, err
	}
	s.event = &audit.Entry{OrgID: s.actor.orgID, ActorUserID: &s.actor.userID, Kind: "presign." + op, Payload: map[string]any{"request_id": id.String(), "resource_kind": kind, "resource_id": ref.ID.String(), "revision": ref.Revision, "sha256": ref.SHA256, "command_sha256": digest}}
	return out, nil
}

func insertOutcome(s *transactionState, out Outcome) error {
	raw, err := canonical(out)
	if err != nil {
		return err
	}
	params := generated.InsertPresignMutationRequestParams{OrgID: out.OrgID, ActorUserID: out.UserID, RequestID: out.RequestID, State: out.State, Operation: out.Operation, OutcomeJson: raw, OccurredAt: timestamp(out.OccurredAt)}
	if out.State == "committed" {
		params.CommandSha256 = unhex(out.CommandSHA256)
		params.ResourceKind = pgtype.Text{String: out.ResourceKind, Valid: true}
		params.ResourceID = pgtype.UUID{Bytes: out.Reference.ID, Valid: true}
		params.ResourceRevision = pgtype.Int8{Int64: out.Reference.Revision, Valid: true}
		params.ResourceSha256 = unhex(out.Reference.SHA256)
	}
	_, err = s.q.InsertPresignMutationRequest(s.ctx, params)
	return err
}

type confirmation struct {
	Version        int       `json:"version"`
	OrgID          uuid.UUID `json:"org_id"`
	UserID         uuid.UUID `json:"actor_user_id"`
	RequestID      uuid.UUID `json:"request_id"`
	Digest         string    `json:"digest"`
	IdentitySHA256 string    `json:"identity_sha256"`
	SessionSHA256  string    `json:"session_sha256"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (e *Engine) mint(s *transactionState, purpose string, id uuid.UUID, digest, identity string) (string, time.Time, error) {
	if e.receipts == nil {
		return "", time.Time{}, ErrUnavailable
	}
	now, err := clock(s)
	if err != nil {
		return "", time.Time{}, err
	}
	expiry := now.Add(PreviewTTL)
	body, _ := canonical(confirmation{Version: 1, OrgID: s.actor.orgID, UserID: s.actor.userID, RequestID: id, Digest: digest, IdentitySHA256: identity, SessionSHA256: s.actor.credentialSHA256, ExpiresAt: expiry})
	token, err := e.receipts.MintPurpose(purpose, body, PreviewTTL)
	return token, expiry, err
}

func (e *Engine) verify(s *transactionState, purpose, token string, id uuid.UUID, digest, identity string) error {
	if e.receipts == nil {
		return ErrUnavailable
	}
	raw, err := e.receipts.VerifyPurpose(purpose, token)
	if err != nil {
		return ErrConflict
	}
	var c confirmation
	if strictDecode(raw, &c, 4096) != nil || c.Version != 1 || c.OrgID != s.actor.orgID || c.UserID != s.actor.userID || c.RequestID != id || c.Digest != digest || c.IdentitySHA256 != identity || c.SessionSHA256 != s.actor.credentialSHA256 {
		return ErrConflict
	}
	now, err := clock(s)
	if err != nil {
		return err
	}
	if !now.Before(c.ExpiresAt) {
		return ErrConflict
	}
	return nil
}

func (e *Engine) GetOwnRequest(ctx context.Context, a SessionActor, id uuid.UUID) (Outcome, error) {
	var out Outcome
	err := e.transaction(ctx, a, func(s *transactionState) error {
		prior, err := priorRequest(s, id, "", "")
		if err != nil {
			return err
		}
		if prior == nil {
			return ErrNotFound
		}
		out = *prior
		return nil
	})
	return out, err
}

func (e *Engine) CloseOwnRequest(ctx context.Context, a SessionActor, in CloseRequestInput) (Outcome, error) {
	var out Outcome
	if err := witness(a, in.ExpectedOrgID, in.ExpectedUserID, in.RequestID); err != nil {
		return out, err
	}
	if !in.Confirmed {
		return out, invalid("explicit close confirmation")
	}
	err := e.transaction(ctx, a, func(s *transactionState) error {
		prior, err := priorRequest(s, in.RequestID, "", "")
		if err != nil {
			return err
		}
		if prior != nil {
			out = *prior
			return nil
		}
		now, err := clock(s)
		if err != nil {
			return err
		}
		out = Outcome{OrgID: a.orgID, UserID: a.userID, RequestID: in.RequestID, State: "closed", Operation: OperationCloseRequest, OccurredAt: now}
		if err := insertOutcome(s, out); err != nil {
			return err
		}
		s.event = &audit.Entry{OrgID: a.orgID, ActorUserID: &a.userID, Kind: "presign.request.closed", Payload: map[string]any{"request_id": in.RequestID.String()}}
		return nil
	})
	return out, err
}
