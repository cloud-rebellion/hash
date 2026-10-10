// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const grantPurpose = "presign.self-grant.confirm.v1"

func normalizedGrant(in GrantIntent) (GrantIntent, error) {
	if in.GrantID == uuid.Nil || in.ExpectedRevision < 0 || in.ExpectedRevision >= presign.MaxRevision || in.Policy.ID == uuid.Nil || in.Policy.Revision < 1 || in.Policy.Revision > presign.MaxRevision || !validSHA(in.Policy.SHA256) || !visible(in.CompanyName, 200) || !visible(in.CompanyID, 100) || !visible(in.AuthorityBasis, 500) || in.MaxUses < 1 || in.MaxUses > presign.MaxRecordedUses || in.ExpiresAt.IsZero() {
		return in, invalid("named finite self-grant intent")
	}
	if _, err := render.SignatureFontSHA256(in.Font); err != nil {
		return in, invalid("supported signature style")
	}
	in.ExpiresAt = in.ExpiresAt.UTC().Truncate(time.Microsecond)
	if !in.NotBefore.IsZero() {
		in.NotBefore = in.NotBefore.UTC().Truncate(time.Microsecond)
	}
	return in, nil
}

func namedGrantor(s *transactionState, in GrantIntent) presign.NamedRepresentative {
	return presign.NamedRepresentative{UserID: s.user.ID, Name: s.user.Name, Email: s.user.Email, CompanyName: in.CompanyName, CompanyID: in.CompanyID, AuthorityBasis: in.AuthorityBasis}
}
func grantReviewHash(s *transactionState, in GrantIntent) (string, error) {
	fontHash, err := render.SignatureFontSHA256(in.Font)
	if err != nil {
		return "", err
	}
	copy := Disclosure()
	raw, err := canonical(struct {
		Grantor    presign.NamedRepresentative `json:"grantor"`
		Signature  presign.SignatureStyle      `json:"signature"`
		Disclosure presign.CopyPin             `json:"disclosure"`
	}{namedGrantor(s, in), presign.SignatureStyle{Font: in.Font, FontSHA256: fontHash}, presign.CopyPin{Version: copy.Version, SHA256: copy.SHA256}})
	if err != nil {
		return "", err
	}
	return domainSHA("hash:presign-grant-review:v1", raw), nil
}

func activePolicy(s *transactionState, ref presign.Reference) (WorkflowDefinition, presign.Policy, error) {
	r, err := s.q.GetPresignPolicyRevisionForShare(s.ctx, generated.GetPresignPolicyRevisionForShareParams{OrgID: s.actor.orgID, PolicyID: ref.ID, Revision: ref.Revision})
	if err != nil {
		return WorkflowDefinition{}, presign.Policy{}, lookupError(err)
	}
	d, p, err := decodeWorkflow(r)
	if err != nil {
		return d, p, err
	}
	if p.Reference() != ref {
		return d, p, ErrConflict
	}
	if err := validateLiveDefinition(s, d); err != nil {
		return d, p, err
	}
	h, err := s.q.GetPresignWorkflowHeadForShare(s.ctx, generated.GetPresignWorkflowHeadForShareParams{OrgID: s.actor.orgID, ID: r.WorkflowID})
	if err != nil {
		return d, p, err
	}
	retired, err := s.q.IsPresignWorkflowRetired(s.ctx, generated.IsPresignWorkflowRetiredParams{OrgID: s.actor.orgID, WorkflowID: r.WorkflowID, Revision: r.Revision})
	if err != nil {
		return d, p, err
	}
	if h.ArchivedAt.Valid || retired {
		return d, p, ErrConflict
	}
	return d, p, nil
}

func validateGrantIntent(s *transactionState, in GrantIntent, d WorkflowDefinition, p presign.Policy) error {
	if !eligible(s.user) {
		return auth.ErrMutationPermissionRevoked
	}
	r := d.RecipientRules
	if in.CompanyName != r.ProviderCompanyName || in.CompanyID != r.ProviderCompanyID || in.AuthorityBasis != r.ProviderAuthorityBasis {
		return invalid("approved provider company/authority declarations")
	}
	now, err := clock(s)
	if err != nil {
		return err
	}
	if !now.Before(in.ExpiresAt) {
		return auth.ErrMutationCredentialExpired
	}
	if in.MaxUses > p.Snapshot().MaxUses || in.ExpiresAt.After(now.Add(time.Duration(p.Snapshot().MaxGrantDurationSeconds)*time.Second)) {
		return invalid("grant exceeds finite policy allowance")
	}
	if !in.NotBefore.IsZero() && (!in.NotBefore.Before(in.ExpiresAt)) {
		return invalid("absolute grant start/deadline")
	}
	return nil
}

func validateGrantHead(s *transactionState, in GrantIntent) error {
	h, err := s.q.GetPresignGrantHeadForUpdate(s.ctx, generated.GetPresignGrantHeadForUpdateParams{OrgID: s.actor.orgID, ID: in.GrantID})
	if in.ExpectedRevision == 0 {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return ErrConflict
	}
	if err != nil {
		return lookupError(err)
	}
	if h.GrantorUserID != s.actor.userID || h.RevokedAt.Valid || h.CurrentRevision != in.ExpectedRevision {
		return ErrConflict
	}
	r, err := s.q.GetPresignGrantRevisionForShare(s.ctx, generated.GetPresignGrantRevisionForShareParams{OrgID: s.actor.orgID, GrantID: h.ID, Revision: h.CurrentRevision})
	if err != nil {
		return err
	}
	g, err := decodeGrant(r, h)
	if err != nil {
		return err
	}
	if g.Snapshot().Grantor.Name != s.user.Name || g.Snapshot().Grantor.Email != s.user.Email {
		return ErrConflict
	}
	return nil
}

func decodeGrant(r *generated.PresignGrantRevision, h *generated.PresignGrant) (presign.Grant, error) {
	var g presign.Grant
	if r == nil || h == nil {
		return g, ErrUnavailable
	}
	g, err := presign.DecodeGrant(r.CanonicalGrant)
	if err != nil {
		return g, ErrUnavailable
	}
	v := g.Snapshot()
	if !bytes.Equal(g.CanonicalJSON(), r.CanonicalGrant) || g.Commitment() != hex.EncodeToString(r.GrantSha256) || v.OrgID != r.OrgID || v.ID != r.GrantID || v.Revision != r.Revision || v.Grantor.UserID != h.GrantorUserID || v.Policy.ID != r.PolicyID || v.Policy.Revision != r.PolicyRevision || v.Policy.SHA256 != hex.EncodeToString(r.PolicySha256) || !r.GrantedAt.Valid || !r.NotBefore.Valid || !r.ExpiresAt.Valid || !v.GrantedAt.Equal(r.GrantedAt.Time) || !v.NotBefore.Equal(r.NotBefore.Time) || !v.ExpiresAt.Equal(r.ExpiresAt.Time) || v.MaxUses != r.MaxUses || r.ConsumedUses != 0 {
		return g, ErrUnavailable
	}
	return g, nil
}

func (e *Engine) PreviewSelfGrant(ctx context.Context, a SessionActor, in GrantIntent) (GrantPreview, error) {
	var out GrantPreview
	if err := witness(a, in.ExpectedOrgID, in.ExpectedUserID, in.RequestID); err != nil {
		return out, err
	}
	in, err := normalizedGrant(in)
	if err != nil {
		return out, err
	}
	op := OperationCreateGrant
	if in.ExpectedRevision > 0 {
		op = OperationReviseGrant
	}
	digest, _ := commandDigest(op, in)
	err = e.transaction(ctx, a, func(s *transactionState) error {
		d, p, err := activePolicy(s, in.Policy)
		if err != nil {
			return err
		}
		if err := validateGrantIntent(s, in, d, p); err != nil {
			return err
		}
		if err := validateGrantHead(s, in); err != nil {
			return err
		}
		fontHash, err := render.SignatureFontSHA256(in.Font)
		if err != nil {
			return err
		}
		copy := Disclosure()
		reviewHash, err := grantReviewHash(s, in)
		if err != nil {
			return err
		}
		token, expiry, err := e.mint(s, grantPurpose, in.RequestID, digest, reviewHash)
		if err != nil {
			return err
		}
		out = GrantPreview{OrgID: a.orgID, UserID: a.userID, Intent: in, Grantor: namedGrantor(s, in), Signature: presign.SignatureStyle{Font: in.Font, FontSHA256: fontHash}, Disclosure: presign.CopyPin{Version: copy.Version, SHA256: copy.SHA256}, Receipt: token, ExpiresAt: expiry}
		return nil
	})
	return out, err
}

func (e *Engine) grantConfirmation(ctx context.Context, a SessionActor, input ConfirmGrantInput, revise bool) (Outcome, error) {
	var out Outcome
	in := input.Intent
	if err := witness(a, in.ExpectedOrgID, in.ExpectedUserID, in.RequestID); err != nil {
		return out, err
	}
	if !input.Confirmed || (in.ExpectedRevision > 0) != revise {
		return out, invalid("explicit self consent and revision")
	}
	in, err := normalizedGrant(in)
	if err != nil {
		return out, err
	}
	op := OperationCreateGrant
	if revise {
		op = OperationReviseGrant
	}
	digest, _ := commandDigest(op, in)
	err = e.transaction(ctx, a, func(s *transactionState) error {
		prior, err := priorRequest(s, in.RequestID, op, digest)
		if err != nil {
			return err
		}
		if prior != nil {
			out = *prior
			return nil
		}
		reviewHash, err := grantReviewHash(s, in)
		if err != nil {
			return err
		}
		if err := e.verify(s, grantPurpose, input.Receipt, in.RequestID, digest, reviewHash); err != nil {
			return err
		}
		d, p, err := activePolicy(s, in.Policy)
		if err != nil {
			return err
		}
		if err := validateGrantIntent(s, in, d, p); err != nil {
			return err
		}
		if err := validateGrantHead(s, in); err != nil {
			return err
		}
		now, err := clock(s)
		if err != nil {
			return err
		}
		start := in.NotBefore
		if start.IsZero() || start.Before(now) {
			start = now
		}
		fontHash, err := render.SignatureFontSHA256(in.Font)
		if err != nil {
			return err
		}
		copy := Disclosure()
		g, err := presign.NewGrant(presign.GrantSnapshot{SchemaVersion: 1, ID: in.GrantID, OrgID: a.orgID, Revision: in.ExpectedRevision + 1, Policy: in.Policy, Grantor: namedGrantor(s, in), Signature: presign.SignatureStyle{Font: in.Font, FontSHA256: fontHash}, Disclosure: presign.CopyPin{Version: copy.Version, SHA256: copy.SHA256}, GrantedAt: now, NotBefore: start, ExpiresAt: in.ExpiresAt, MaxUses: in.MaxUses})
		if err != nil {
			return invalid("confirmed named grant snapshot")
		}
		if revise {
			n, err := s.q.AdvanceOwnPresignGrantHead(s.ctx, generated.AdvanceOwnPresignGrantHeadParams{OrgID: a.orgID, ID: in.GrantID, GrantorUserID: a.userID, CurrentRevision: in.ExpectedRevision})
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrConflict
			}
		} else {
			if _, err := s.q.InsertPresignGrantHead(s.ctx, generated.InsertPresignGrantHeadParams{OrgID: a.orgID, ID: in.GrantID, GrantorUserID: a.userID}); err != nil {
				return err
			}
		}
		_, err = s.q.InsertPresignGrantRevision(s.ctx, generated.InsertPresignGrantRevisionParams{OrgID: a.orgID, GrantID: in.GrantID, Revision: in.ExpectedRevision + 1, CanonicalGrant: g.CanonicalJSON(), GrantSha256: unhex(g.Commitment()), PolicyID: in.Policy.ID, PolicyRevision: in.Policy.Revision, PolicySha256: unhex(in.Policy.SHA256), GrantedAt: timestamp(now), NotBefore: timestamp(start), ExpiresAt: timestamp(in.ExpiresAt), MaxUses: in.MaxUses})
		if err != nil {
			return err
		}
		out, err = finishMutation(s, in.RequestID, op, digest, "grant", g.Reference())
		s.final = func() error {
			if _, _, err := activePolicy(s, in.Policy); err != nil {
				return err
			}
			currentReview, err := grantReviewHash(s, in)
			if err != nil {
				return err
			}
			if err := e.verify(s, grantPurpose, input.Receipt, in.RequestID, digest, currentReview); err != nil {
				return err
			}
			at, err := clock(s)
			if err != nil {
				return err
			}
			if !at.Before(in.ExpiresAt) {
				return auth.ErrMutationCredentialExpired
			}
			return nil
		}
		return err
	})
	return out, err
}

func (e *Engine) CreateSelfGrant(ctx context.Context, a SessionActor, in ConfirmGrantInput) (Outcome, error) {
	return e.grantConfirmation(ctx, a, in, false)
}
func (e *Engine) ReviseSelfGrant(ctx context.Context, a SessionActor, in ConfirmGrantInput) (Outcome, error) {
	return e.grantConfirmation(ctx, a, in, true)
}

func (e *Engine) revoke(ctx context.Context, a SessionActor, in ResourceMutationInput, owner bool) (Outcome, error) {
	var out Outcome
	if err := witness(a, in.ExpectedOrgID, in.ExpectedUserID, in.RequestID); err != nil {
		return out, err
	}
	if !in.Confirmed || in.Reference.ID == uuid.Nil || in.Reference.Revision < 1 || !validSHA(in.Reference.SHA256) {
		return out, invalid("exact confirmed grant reference")
	}
	op := OperationSelfRevoke
	reason := "self_revoked"
	if owner {
		op = OperationOwnerRevoke
		reason = "owner_revoked"
	}
	digest, _ := commandDigest(op, in)
	err := e.transaction(ctx, a, func(s *transactionState) error {
		prior, err := priorRequest(s, in.RequestID, op, digest)
		if err != nil {
			return err
		}
		if prior != nil {
			out = *prior
			return nil
		}
		if owner && s.user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		// Read only to discover the named user, then retain that user before the
		// grant UPDATE lock. User-transition triggers acquire locks in this order.
		grantor, err := s.q.GetPresignGrantorIdentity(s.ctx, generated.GetPresignGrantorIdentityParams{OrgID: a.orgID, ID: in.Reference.ID})
		if err != nil {
			return lookupError(err)
		}
		if !owner && grantor != a.userID {
			return ErrNotFound
		}
		if grantor != a.userID {
			if _, err := s.q.GetUserForShare(s.ctx, generated.GetUserForShareParams{ID: grantor, OrgID: a.orgID}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		h, err := s.q.GetPresignGrantHeadForUpdate(s.ctx, generated.GetPresignGrantHeadForUpdateParams{OrgID: a.orgID, ID: in.Reference.ID})
		if err != nil {
			return lookupError(err)
		}
		if h.GrantorUserID != grantor || h.CurrentRevision != in.Reference.Revision || h.RevokedAt.Valid {
			return ErrConflict
		}
		r, err := s.q.GetPresignGrantRevisionForShare(s.ctx, generated.GetPresignGrantRevisionForShareParams{OrgID: a.orgID, GrantID: h.ID, Revision: h.CurrentRevision})
		if err != nil {
			return err
		}
		g, err := decodeGrant(r, h)
		if err != nil {
			return err
		}
		if g.Reference() != in.Reference {
			return ErrConflict
		}
		now, err := clock(s)
		if err != nil {
			return err
		}
		n, err := s.q.RevokePresignGrant(s.ctx, generated.RevokePresignGrantParams{OrgID: a.orgID, ID: h.ID, CurrentRevision: h.CurrentRevision, RevokedAt: timestamp(now), RevokedReason: pgtype.Text{String: reason, Valid: true}})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrConflict
		}
		if err := s.q.InsertPresignGrantRevocation(s.ctx, generated.InsertPresignGrantRevocationParams{OrgID: a.orgID, GrantID: h.ID, RevokedAt: timestamp(now), Reason: reason, ActorUserID: pgtype.UUID{Bytes: a.userID, Valid: true}}); err != nil {
			return err
		}
		out, err = finishMutation(s, in.RequestID, op, digest, "grant", in.Reference)
		return err
	})
	return out, err
}

func (e *Engine) RevokeOwnGrant(ctx context.Context, a SessionActor, in ResourceMutationInput) (Outcome, error) {
	return e.revoke(ctx, a, in, false)
}
func (e *Engine) RevokeGrantAsOwner(ctx context.Context, a SessionActor, in ResourceMutationInput) (Outcome, error) {
	return e.revoke(ctx, a, in, true)
}
