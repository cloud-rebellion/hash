// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"context"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ExecutionActorV1 struct {
	session  SessionActor
	identity presign.ExecutorIdentity
}

func NewSessionExecutionActorV1(a SessionActor) (ExecutionActorV1, error) {
	if a.authorize == nil || a.orgID == uuid.Nil || a.userID == uuid.Nil || !validSHA(a.credentialSHA256) {
		return ExecutionActorV1{}, auth.ErrMutationPermissionRevoked
	}
	return ExecutionActorV1{session: a, identity: presign.ExecutorIdentity{Kind: presign.ExecutorMember, UserID: a.userID}}, nil
}

func NewAPIExecutionActorV1(a auth.PreSignAPIAdmissionV1) (ExecutionActorV1, error) {
	if a.OrgID() == uuid.Nil || a.UserID() == uuid.Nil || a.CredentialID() == uuid.Nil || !validSHA(a.Commitment()) {
		return ExecutionActorV1{}, auth.ErrMutationPermissionRevoked
	}
	s := SessionActor{orgID: a.OrgID(), userID: a.UserID(), credentialSHA256: a.Commitment(), authorize: a.AuthorizeV1}
	return ExecutionActorV1{session: s, identity: presign.ExecutorIdentity{Kind: presign.ExecutorAPIKey, UserID: a.UserID(), CredentialID: a.CredentialID()}}, nil
}

func (a ExecutionActorV1) OrgID() uuid.UUID                   { return a.session.orgID }
func (a ExecutionActorV1) UserID() uuid.UUID                  { return a.session.userID }
func (a ExecutionActorV1) Identity() presign.ExecutorIdentity { return a.identity }
func (a ExecutionActorV1) CredentialCommitment() string       { return a.session.credentialSHA256 }

// Recovery keeps the original credential and live membership checks, without
// requiring a new send grant or silently adopting a replacement credential.
func (a ExecutionActorV1) AuthorizeRecoveryV1(ctx context.Context, tx pgx.Tx, u *generated.User) error {
	if tx == nil || a.session.authorize == nil || u == nil || u.OrgID != a.OrgID() || u.ID != a.UserID() || a.identity.UserID != u.ID {
		return auth.ErrMutationPermissionRevoked
	}
	return a.session.authorize(ctx, tx, u)
}

// AuthorizeV1 checks the SAME originally captured interactive/API capability;
// a live replacement token/user/credential never adopts a pending request.
func (a ExecutionActorV1) AuthorizeV1(ctx context.Context, tx pgx.Tx, u *generated.User) error {
	if tx == nil || a.session.authorize == nil || u == nil || u.OrgID != a.OrgID() || u.ID != a.UserID() || !eligible(u) ||
		a.identity.UserID != u.ID || !validSHA(a.CredentialCommitment()) {
		return auth.ErrMutationPermissionRevoked
	}
	return a.session.authorize(ctx, tx, u)
}

type ExecutionAuthorityV1 struct {
	actor           ExecutionActorV1
	definition      WorkflowDefinition
	policy          presign.Policy
	grant           presign.Grant
	member, grantor generated.User
	consumed        int64
	observed        time.Time
}

func (a ExecutionAuthorityV1) Definition() WorkflowDefinition {
	raw, _, _, err := CanonicalDefinition(a.definition)
	if err != nil {
		return WorkflowDefinition{}
	}
	d, err := DecodeDefinition(raw)
	if err != nil {
		return WorkflowDefinition{}
	}
	return d
}
func (a ExecutionAuthorityV1) Policy() presign.Policy           { return a.policy }
func (a ExecutionAuthorityV1) Grant() presign.Grant             { return a.grant }
func (a ExecutionAuthorityV1) ConsumedUses() int64              { return a.consumed }
func (a ExecutionAuthorityV1) ObservedAt() time.Time            { return a.observed }
func (a ExecutionAuthorityV1) Actor() presign.MemberObservation { return memberObservationV1(a.member) }
func (a ExecutionAuthorityV1) Grantor() presign.MemberObservation {
	return memberObservationV1(a.grantor)
}
func (a ExecutionAuthorityV1) CredentialCommitmentV1() string { return a.actor.CredentialCommitment() }
func memberObservationV1(u generated.User) presign.MemberObservation {
	return presign.MemberObservation{OrgID: u.OrgID, UserID: u.ID, Name: u.Name, Email: u.Email, Role: u.Role, Active: eligible(&u)}
}

// LockExecutionAuthorityV1 runs only after the caller's fixed native body loan.
// The org fence freezes membership/grant mutations; live users precede grant
// FOR UPDATE, and the exact ledger revision supplies the next use. No provider
// work runs in this transaction. Historical readback uses LoadOutcome instead.
func LockExecutionAuthorityV1(ctx context.Context, tx pgx.Tx, a ExecutionActorV1, policy, grant presign.Reference) (ExecutionAuthorityV1, error) {
	var out ExecutionAuthorityV1
	if ctx == nil || ctx.Err() != nil || tx == nil || a.session.authorize == nil || a.OrgID() == uuid.Nil || a.UserID() == uuid.Nil ||
		policy.ID == uuid.Nil || policy.Revision < 1 || policy.Revision > presign.MaxRevision || !validSHA(policy.SHA256) ||
		grant.ID == uuid.Nil || grant.Revision < 1 || grant.Revision > presign.MaxRevision || !validSHA(grant.SHA256) {
		return out, ErrInvalid
	}
	q := generated.New(tx)
	if _, err := q.GetOrgForOwnerMutation(ctx, a.OrgID()); err != nil {
		return out, lookupError(err)
	}
	u, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: a.UserID(), OrgID: a.OrgID()})
	if err != nil {
		return out, lookupError(err)
	}
	if err = a.AuthorizeV1(ctx, tx, u); err != nil {
		return out, err
	}
	// Scalar discovery grants no authority. Recheck its identity under the
	// actual head lock after the original member/representative SHARE locks.
	var grantorID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT grantor_user_id FROM presign_grants WHERE org_id=$1 AND id=$2`, a.OrgID(), grant.ID).Scan(&grantorID); err != nil {
		return out, lookupError(err)
	}
	guser, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: grantorID, OrgID: a.OrgID()})
	if err != nil || !eligible(guser) {
		return out, auth.ErrMutationPermissionRevoked
	}
	h, err := q.GetPresignGrantHeadForUpdate(ctx, generated.GetPresignGrantHeadForUpdateParams{OrgID: a.OrgID(), ID: grant.ID})
	if err != nil {
		return out, lookupError(err)
	}
	if h.RevokedAt.Valid {
		return out, auth.ErrMutationPermissionRevoked
	}
	if h.GrantorUserID != grantorID || h.CurrentRevision != grant.Revision {
		return out, ErrConflict
	}
	r, err := q.GetPresignGrantRevisionForShare(ctx, generated.GetPresignGrantRevisionForShareParams{OrgID: a.OrgID(), GrantID: grant.ID, Revision: grant.Revision})
	if err != nil {
		return out, lookupError(err)
	}
	g, err := decodeGrant(r, h)
	if err != nil {
		return out, err
	}
	if g.Reference() != grant || g.Snapshot().Policy != policy || g.Snapshot().Grantor.Name != guser.Name || g.Snapshot().Grantor.Email != guser.Email {
		return out, ErrConflict
	}
	s := &transactionState{ctx: ctx, tx: tx, q: q, actor: a.session, user: u}
	d, p, err := activePolicy(s, policy)
	if err != nil {
		return out, err
	}
	if p.Snapshot().Executor != a.identity || p.Snapshot().Operation != presign.OperationPreSignAndSend {
		return out, auth.ErrMutationPermissionRevoked
	}
	nextRow, err := q.NextPresignExecutionUse(ctx, generated.NextPresignExecutionUseParams{OrgID: a.OrgID(), GrantID: grant.ID, GrantRevision: grant.Revision})
	if err != nil {
		return out, err
	}
	next := int64(nextRow)
	now, err := clock(s)
	if err != nil {
		return out, err
	}
	if next < 1 || next > g.Snapshot().MaxUses || now.Before(g.Snapshot().NotBefore) || !now.Before(g.Snapshot().ExpiresAt) {
		return out, ErrConflict
	}
	if err = a.AuthorizeV1(ctx, tx, u); err != nil {
		return out, err
	}
	return ExecutionAuthorityV1{actor: a, definition: d, policy: p, grant: g, member: *u, grantor: *guser, consumed: next - 1, observed: now}, nil
}
