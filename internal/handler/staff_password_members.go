// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
)

// An owner creates a member only in their own organization. A pending member
// chooses their own password through mailbox proof; owners never select one.
func (s *Server) handleCreateStaffMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	session, cookie, ok := s.transactionSession(w, r, actor)
	if !ok {
		return
	}
	var in struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	}
	if !decodeStaffAuthJSON(w, r, &in) {
		return
	}
	email, name, err := normalizeOIDCIdentity(in.Email, strings.TrimSpace(in.Name))
	if err != nil || !validStaffText(name, true) || !validRole(in.Role) {
		writeError(w, http.StatusBadRequest, "valid email, name and member role required")
		return
	}
	if !s.staffAuthReady(w) || !s.staffAuthAccountAllowed(w, "invitation", email, 5) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sessionTransactionTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	defer rollbackSessionTransaction(ctx, tx)
	q := s.Queries.WithTx(tx)
	// Recovery takes the same email fence before locking its target user.
	// Acquire it before the actor SHARE lock too, including self-invitations.
	if err := q.LockStaffPasswordEmail(ctx, email); err != nil {
		staffAuthUnavailable(w)
		return
	}
	// Share the existing owner-mutation organization fence and live cookie/
	// generation/role recheck. The request cannot choose its organization.
	if _, err := q.GetOrgForOwnerMutation(ctx, actor.OrgID); err != nil {
		staffAuthUnavailable(w)
		return
	}
	if !s.authorizeTransactionSession(w, r, tx, actor, session, cookie, auth.RoleOwner) {
		return
	}
	member, err := q.LockStaffPasswordUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		staffAuthUnavailable(w)
		return
	}
	created := errors.Is(err, pgx.ErrNoRows)
	if created {
		member, err = q.CreateUser(ctx, generated.CreateUserParams{OrgID: actor.OrgID, Email: email, Name: name, Role: in.Role})
		if err != nil {
			staffAuthUnavailable(w)
			return
		}
	} else if member.OrgID != actor.OrgID {
		// Do not reveal or move somebody else's existing organization.
		staffAuthAccepted(w)
		return
	}
	if _, err := q.GetStaffPasswordCredentialForUser(ctx, member.ID); err == nil {
		staffAuthAccepted(w)
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		staffAuthUnavailable(w)
		return
	}
	if err := s.issueStaffAuthEmail(ctx, q, member, email, member.Name, "", "setup", ""); err != nil {
		staffAuthUnavailable(w)
		return
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID,
		Kind: audit.KindMemberCreated, IP: clientIP(r),
		Payload: map[string]any{"member_id": member.ID.String(), "role": member.Role, "invitation": true, "created": created}})
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	if !s.transactionSessionFresh(w, cookie) {
		return
	}
	if err := tx.Commit(ctx); err != nil {
		staffAuthUnavailable(w)
		return
	}
	s.Audit.Publish(pending)
	staffAuthAccepted(w)
}
