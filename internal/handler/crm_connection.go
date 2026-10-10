// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
)

const crmEnrollmentMaxAge = time.Minute

var errCRMConnectionChanged = errors.New("CRM connection changed; refresh and review")

type crmConnectionDTO struct {
	ID         uuid.UUID `json:"id"`
	Generation string    `json:"generation"`
	Status     string    `json:"status"`
	CRMTeamID  string    `json:"crm_team_id"`
	CRMUserID  string    `json:"crm_user_id"`
	VerifiedAt *string   `json:"verified_at"`
	UpdatedAt  string    `json:"updated_at"`
}
type crmConnectionResponse struct {
	OrgID                   uuid.UUID         `json:"org_id"`
	UserID                  uuid.UUID         `json:"user_id"`
	RequiresReconfiguration bool              `json:"requires_reconfiguration"`
	Available               bool              `json:"available"`
	Configured              bool              `json:"configured"`
	Origin                  string            `json:"origin"`
	Connection              *crmConnectionDTO `json:"connection"`
}
type crmConnectionInput struct {
	ExpectedOrgID      uuid.UUID `json:"expected_org_id"`
	ExpectedUserID     uuid.UUID `json:"expected_user_id"`
	ExpectedGeneration string    `json:"expected_generation"`
	Token              string    `json:"token"`
}
type crmConnectionEnableInput struct {
	ExpectedOrgID      uuid.UUID `json:"expected_org_id"`
	ExpectedUserID     uuid.UUID `json:"expected_user_id"`
	ExpectedGeneration string    `json:"expected_generation"`
	CRMTeamID          string    `json:"crm_team_id"`
	CRMUserID          string    `json:"crm_user_id"`
}

func crmGeneration(raw string, allowZero bool) (int64, error) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 || (!allowZero && n == 0) || strconv.FormatInt(n, 10) != raw || n == math.MaxInt64 {
		return 0, errOwnerMutationInput
	}
	return n, nil
}

func crmIdentity(row *generated.CrmConnection) crmconnection.Identity {
	return crmconnection.Identity{ID: row.ID, OrgID: row.OrgID, Generation: row.Generation,
		Origin: row.Origin, CRMTeamID: row.CrmTeamID, CRMUserID: row.CrmUserID}
}

func (s *Server) crmResponse(row *generated.CrmConnection, u auth.SessionUser) crmConnectionResponse {
	out := crmConnectionResponse{OrgID: u.OrgID, UserID: u.UserID, Available: s.CRMClient != nil && s.CRMKeys != nil, Origin: s.CRMOrigin}
	if row != nil {
		out.RequiresReconfiguration = row.Origin != s.CRMOrigin
		at := row.VerifiedAt.Time.UTC().Format(time.RFC3339Nano)
		out.Configured = true
		out.Connection = &crmConnectionDTO{ID: row.ID, Generation: strconv.FormatInt(row.Generation, 10),
			Status: row.Status, CRMTeamID: row.CrmTeamID, CRMUserID: row.CrmUserID,
			VerifiedAt: &at, UpdatedAt: row.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)}
	}
	return out
}

func (s *Server) writeCRMConnectionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		writeError(w, http.StatusUnauthorized, "original session expired")
	case errors.Is(err, errOwnerMutationInput):
		writeError(w, http.StatusBadRequest, "invalid CRM connection input")
	case errors.Is(err, errCRMConnectionChanged), errors.Is(err, crmconnection.ErrIdentity):
		writeError(w, http.StatusConflict, errCRMConnectionChanged.Error())
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		writeError(w, http.StatusForbidden, "organization owner permission or original credential unavailable")
	default:
		// Upstream response bodies, bearer values and arbitrary network errors
		// must never become org-readable diagnostics or telemetry.
		writeError(w, http.StatusServiceUnavailable, "CRM connection temporarily unavailable")
	}
}

func (s *Server) readCRMConnection(ctx context.Context, actor authoring.Actor) (*generated.CrmConnection, error) {
	if s.Pool == nil {
		return nil, crmconnection.ErrNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockOwner(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	row, err := generated.New(tx).GetCRMConnectionByOrgForShare(ctx, actor.OrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		row, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = guard.Recheck(ctx); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Server) commitCRMConnection(ctx context.Context, actor authoring.Actor,
	mutate func(context.Context, *generated.Queries) (*generated.CrmConnection, error),
	entry audit.Entry, observedAt time.Time) (*generated.CrmConnection, error) {
	if s.Pool == nil || s.Audit == nil {
		return nil, crmconnection.ErrNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockOwner(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	row, err := mutate(ctx, generated.New(tx))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errCRMConnectionChanged
	}
	if err != nil {
		return nil, err
	}
	if row == nil || row.OrgID != actor.OrgID || entry.OrgID != actor.OrgID || entry.ActorUserID == nil || *entry.ActorUserID != actor.UserID {
		return nil, errCRMConnectionChanged
	}
	payload := entry.Payload
	if payload == nil {
		return nil, errCRMConnectionChanged
	}
	payload["connection_id"], payload["generation"] = row.ID, strconv.FormatInt(row.Generation, 10)
	payload["origin"], payload["crm_team_id"], payload["crm_user_id"] = row.Origin, row.CrmTeamID, row.CrmUserID
	pending, err := s.Audit.LogTx(ctx, tx, entry)
	if err != nil {
		return nil, err
	}
	if err = guard.Recheck(ctx); err != nil {
		return nil, err
	}
	if !observedAt.IsZero() && (!observedAt.Before(time.Now().Add(time.Second)) || time.Since(observedAt) > crmEnrollmentMaxAge) {
		return nil, errCRMConnectionChanged
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.Audit.Publish(pending)
	return row, nil
}

func (s *Server) handleGetCRMConnection(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	actor, err := s.sessionOwnerActor(r, u)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	row, err := s.readCRMConnection(r.Context(), actor)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.crmResponse(row, u))
}

func (s *Server) handleSetCRMConnection(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in crmConnectionInput
	if decodeJSON(r, &in) != nil || crmconnection.ValidateToken(in.Token) != nil {
		s.writeCRMConnectionError(w, errOwnerMutationInput)
		return
	}
	if in.ExpectedOrgID != u.OrgID || in.ExpectedUserID != u.UserID {
		s.writeCRMConnectionError(w, errCRMConnectionChanged)
		return
	}
	generation, err := crmGeneration(in.ExpectedGeneration, true)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	if generation >= math.MaxInt64-2 {
		s.writeCRMConnectionError(w, errCRMConnectionChanged)
		return
	}
	actor, err := s.sessionOwnerActor(r, u)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	if s.CRMClient == nil || s.CRMKeys == nil || s.Queries == nil {
		s.writeCRMConnectionError(w, crmconnection.ErrNotConfigured)
		return
	}
	before, err := s.readCRMConnection(r.Context(), actor)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	id := uuid.New()
	if before != nil {
		id = before.ID
	}
	if (before == nil && generation != 0) || (before != nil && before.Generation != generation) {
		s.writeCRMConnectionError(w, errCRMConnectionChanged)
		return
	}
	identity := crmconnection.Identity{ID: id, OrgID: u.OrgID, Generation: generation + 1, Origin: s.CRMOrigin}
	observation, err := s.CRMClient.VerifyCredential(r.Context(), identity, in.Token)
	if err != nil {
		in.Token = ""
		s.writeCRMConnectionError(w, err)
		return
	}
	identity.CRMTeamID, identity.CRMUserID = observation.CRMTeamID, observation.CRMUserID
	ciphertext, err := s.CRMKeys.Seal(identity, in.Token)
	in.Token = ""
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	row, err := s.commitCRMConnection(r.Context(), actor, func(ctx context.Context, q *generated.Queries) (*generated.CrmConnection, error) {
		return q.SaveCRMConnectionCandidate(ctx, generated.SaveCRMConnectionCandidateParams{OrgID: u.OrgID, ID: id,
			Generation: identity.Generation, ExpectedGeneration: generation, Origin: identity.Origin,
			CrmTeamID: identity.CRMTeamID, CrmUserID: identity.CRMUserID, CredentialCiphertext: ciphertext,
			VerifiedAt: pgtype.Timestamptz{Time: observation.ObservedAt, Valid: true}})
	}, audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, IP: clientIP(r), Kind: "crm.connection.candidate",
		Payload: map[string]any{"connection_id": id, "generation": strconv.FormatInt(identity.Generation, 10), "origin": identity.Origin,
			"crm_team_id": identity.CRMTeamID, "crm_user_id": identity.CRMUserID}}, observation.ObservedAt)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.crmResponse(row, u))
}

func (s *Server) handleEnableCRMConnection(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in crmConnectionEnableInput
	if decodeJSON(r, &in) != nil {
		s.writeCRMConnectionError(w, errOwnerMutationInput)
		return
	}
	if in.ExpectedOrgID != u.OrgID || in.ExpectedUserID != u.UserID {
		s.writeCRMConnectionError(w, errCRMConnectionChanged)
		return
	}
	generation, err := crmGeneration(in.ExpectedGeneration, false)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	if generation >= math.MaxInt64-1 {
		s.writeCRMConnectionError(w, errCRMConnectionChanged)
		return
	}
	actor, err := s.sessionOwnerActor(r, u)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	if s.CRMClient == nil || s.CRMKeys == nil {
		s.writeCRMConnectionError(w, crmconnection.ErrNotConfigured)
		return
	}
	before, err := s.readCRMConnection(r.Context(), actor)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	if before == nil || before.Status != "candidate" || before.Generation != generation || before.Origin != s.CRMOrigin || before.CrmTeamID != in.CRMTeamID || before.CrmUserID != in.CRMUserID {
		s.writeCRMConnectionError(w, errCRMConnectionChanged)
		return
	}
	identity := crmIdentity(before)
	token, _, err := s.CRMKeys.Open(identity, before.CredentialCiphertext)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	observation, err := s.CRMClient.VerifyCredential(r.Context(), identity, token)
	if err != nil {
		token = ""
		s.writeCRMConnectionError(w, err)
		return
	}
	identity.Generation++
	ciphertext, err := s.CRMKeys.Seal(identity, token)
	token = ""
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	row, err := s.commitCRMConnection(r.Context(), actor, func(ctx context.Context, q *generated.Queries) (*generated.CrmConnection, error) {
		return q.EnableCRMConnection(ctx, generated.EnableCRMConnectionParams{OrgID: u.OrgID, ID: identity.ID,
			Generation: identity.Generation, ExpectedGeneration: generation, Origin: identity.Origin,
			CrmTeamID: identity.CRMTeamID, CrmUserID: identity.CRMUserID, CredentialCiphertext: ciphertext,
			VerifiedAt: pgtype.Timestamptz{Time: observation.ObservedAt, Valid: true}})
	}, audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, IP: clientIP(r), Kind: "crm.connection.enabled",
		Payload: map[string]any{"connection_id": identity.ID, "generation": strconv.FormatInt(identity.Generation, 10), "origin": identity.Origin,
			"crm_team_id": identity.CRMTeamID, "crm_user_id": identity.CRMUserID}}, observation.ObservedAt)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.crmResponse(row, u))
}

func (s *Server) handleRevokeCRMConnection(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in struct {
		ExpectedGeneration string    `json:"expected_generation"`
		ExpectedOrgID      uuid.UUID `json:"expected_org_id"`
		ExpectedUserID     uuid.UUID `json:"expected_user_id"`
	}
	if decodeJSON(r, &in) != nil {
		s.writeCRMConnectionError(w, errOwnerMutationInput)
		return
	}
	if in.ExpectedOrgID != u.OrgID || in.ExpectedUserID != u.UserID {
		s.writeCRMConnectionError(w, errCRMConnectionChanged)
		return
	}
	generation, err := crmGeneration(in.ExpectedGeneration, false)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	actor, err := s.sessionOwnerActor(r, u)
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	row, err := s.commitCRMConnection(r.Context(), actor, func(ctx context.Context, q *generated.Queries) (*generated.CrmConnection, error) {
		return q.RevokeCRMConnection(ctx, generated.RevokeCRMConnectionParams{OrgID: u.OrgID, ExpectedGeneration: generation})
	}, audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, IP: clientIP(r), Kind: "crm.connection.revoked",
		Payload: map[string]any{"previous_generation": in.ExpectedGeneration}}, time.Time{})
	if err != nil {
		s.writeCRMConnectionError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.crmResponse(row, u))
}
