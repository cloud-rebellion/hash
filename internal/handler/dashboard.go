// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// handleDashboard returns the KPI block the sender app's home page renders.
// All metrics are org-scoped, computed on the fly (no caching for v1; the
// queries are cheap and the data set is small per-org).
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	ctx := r.Context()

	statusRows, err := s.Queries.CountDocumentsByStatus(ctx, u.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	byStatus := make(map[string]int64, len(statusRows))
	for _, r := range statusRows {
		byStatus[r.Status] = r.N
	}

	since24h := pgtype.Timestamptz{Time: time.Now().Add(-24 * time.Hour), Valid: true}
	sentToday, err := s.Queries.CountSentSince(ctx, generated.CountSentSinceParams{OrgID: u.OrgID, SentAt: since24h})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	completed30d, err := s.Queries.CountCompletedSince(ctx, generated.CountCompletedSinceParams{
		OrgID:       u.OrgID,
		CompletedAt: pgtype.Timestamptz{Time: time.Now().Add(-30 * 24 * time.Hour), Valid: true},
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	awaiting, err := s.Queries.CountAwaitingSig(ctx, u.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	expiring, err := s.Queries.CountExpiringSoon(ctx, u.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	timeToSign, err := s.Queries.TimeToSignP50Seconds(ctx, u.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	split, err := s.Queries.AgentVsHumanDocumentSplit(ctx, u.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	out := map[string]any{
		"by_status":            byStatus,
		"sent_24h":             sentToday,
		"completed_30d":        completed30d,
		"awaiting_signature":   awaiting,
		"expiring_within_7d":   expiring,
		"time_to_sign_p50_sec": timeToSign,
		"agent_authored_30d":   split.Agent,
		"human_authored_30d":   split.Human,
	}
	writeJSON(w, http.StatusOK, out)
}
