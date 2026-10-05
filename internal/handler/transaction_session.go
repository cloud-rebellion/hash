// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/jackc/pgx/v5"
)

const sessionTransactionTimeout = 10 * time.Second

func (s *Server) sessionMutationAuthorization(w http.ResponseWriter, r *http.Request, u auth.SessionUser) (auth.TransactionAuthorization, bool) {
	session, cookie, ok := s.transactionSession(w, r, u)
	if !ok {
		return nil, false
	}
	return auth.SessionTransactionAuthorization(s.Cookies, cookie, session, u.OrgID), true
}

// Middleware identifies the caller at request admission. A write that waits
// on database locks must authorize that same signed session again inside its
// transaction, then retain the user lock through commit.
func (s *Server) transactionSession(w http.ResponseWriter, r *http.Request, u auth.SessionUser) (auth.SessionPayload, string, bool) {
	var session auth.SessionPayload
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || s.Cookies == nil {
		writeError(w, http.StatusUnauthorized, "session required")
		return session, "", false
	}
	payload, err := s.Cookies.Verify(cookie.Value)
	if err != nil || json.Unmarshal(payload, &session) != nil || session.UserID != u.UserID {
		writeError(w, http.StatusUnauthorized, "session invalid")
		return session, "", false
	}
	return session, cookie.Value, true
}

func (s *Server) authorizeTransactionSession(w http.ResponseWriter, r *http.Request, tx pgx.Tx, u auth.SessionUser, session auth.SessionPayload, cookie string, minimum auth.Role) bool {
	var role string
	var generation int64
	err := tx.QueryRow(r.Context(), `SELECT role,session_generation FROM users WHERE id=$1 AND org_id=$2 FOR SHARE`, u.UserID, u.OrgID).Scan(&role, &generation)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeInternalErrorMsg(w, "load transaction authorization", err)
		return false
	}
	allowed := role == string(auth.RoleOwner) || (minimum == auth.RoleSender && role == string(auth.RoleSender))
	if err != nil || !allowed || generation != session.Generation {
		writeError(w, http.StatusForbidden, "permission or session revoked")
		return false
	}
	return s.transactionSessionFresh(w, cookie)
}

func (s *Server) transactionSessionFresh(w http.ResponseWriter, cookie string) bool {
	if s.Cookies == nil {
		writeError(w, http.StatusUnauthorized, "session required")
		return false
	}
	if _, err := s.Cookies.Verify(cookie); err != nil {
		writeError(w, http.StatusUnauthorized, "session expired before transaction committed")
		return false
	}
	return true
}

func rollbackSessionTransaction(ctx context.Context, tx pgx.Tx) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(rollbackCtx)
}
