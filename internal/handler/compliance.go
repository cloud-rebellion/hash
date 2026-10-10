// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
)

var errComplianceFlagNotFound = errors.New("flag not found")

// zeroTime is the lower-bound passed to feed Fetch when we want every
// item. Used by the on-demand flag-run endpoint.
func zeroTime() time.Time { return time.Time{} }

// Phase 12 REST surface. Seed the baseline kit, list flags, transition
// flag status, fetch the baseline row.

// POST /api/v1/compliance/seed
//
// Body: { "business_type": "law_firm" | "saas" | ..., "jurisdiction": "SE" }
func (s *Server) handleSeedCompliance(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Environment == "production" {
		writeError(w, http.StatusServiceUnavailable, "built-in compliance legal drafts are unavailable pending counsel approval")
		return
	}
	if s.Compliance == nil {
		writeError(w, http.StatusServiceUnavailable, "compliance seeder not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var in struct {
		BusinessType string `json:"business_type"`
		Jurisdiction string `json:"jurisdiction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	bt := compliance.BusinessType(in.BusinessType)
	if !bt.Valid() {
		writeError(w, http.StatusBadRequest, "business_type must be law_firm | saas | consulting | healthcare | fintech | other")
		return
	}
	jurisdiction, err := compliance.NormalizeJurisdiction(in.Jurisdiction)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor, err := s.sessionOwnerActor(r, sess)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize compliance baseline", err)
		return
	}
	res, err := authoring.CommitOwnerMutation(r.Context(), s.Pool, s.Audit, actor,
		func(ctx context.Context, q *generated.Queries) (*compliance.SeedResult, error) {
			return compliance.New(q, eidas.New(q)).Seed(ctx, compliance.SeedInput{
				OrgID: sess.OrgID, UserID: sess.UserID, BusinessType: bt, Jurisdiction: jurisdiction,
			})
		},
		func(res *compliance.SeedResult) audit.Entry {
			return audit.Entry{
				OrgID:       sess.OrgID,
				ActorUserID: &sess.UserID,
				Kind:        "compliance.baseline_seeded",
				IP:          firstIPFromHeader(r),
				UserAgent:   r.UserAgent(),
				Payload: map[string]any{
					"business_type":      bt,
					"jurisdiction":       jurisdiction,
					"eidas_rules_seeded": res.EIDASRulesSeeded,
				},
			}
		},
	)
	if err != nil {
		s.writeDraftAuthoringError(w, "seed compliance baseline failed", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// GET /api/v1/compliance/baseline
func (s *Server) handleGetComplianceBaseline(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	row, err := s.Queries.GetComplianceBaseline(r.Context(), sess.OrgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusOK, map[string]any{"baseline": nil})
			return
		}
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"baseline": baselineToDTO(row)})
}

// GET /api/v1/compliance/flags?status=open
func (s *Server) handleListComplianceFlags(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	status := r.URL.Query().Get("status")
	rows, err := s.Queries.ListComplianceFlags(r.Context(), generated.ListComplianceFlagsParams{
		OrgID:   sess.OrgID,
		Column2: status,
		Limit:   500,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		out = append(out, flagToDTO(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"flags": out, "count": len(out)})
}

// PATCH /api/v1/compliance/flags/{id}
//
// Body: { "status": "acknowledged" | "resolved" | "dismissed" | "open" }
func (s *Server) handleSetComplianceFlagStatus(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	idRaw := chiURLParam(r, "id")
	id, err := uuid.Parse(idRaw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	switch in.Status {
	case "open", "acknowledged", "resolved", "dismissed":
	default:
		writeError(w, http.StatusBadRequest, "status must be open|acknowledged|resolved|dismissed")
		return
	}
	actor, err := s.sessionOwnerActor(r, sess)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize compliance flag update", err)
		return
	}
	row, err := authoring.CommitOwnerMutation(r.Context(), s.Pool, s.Audit, actor,
		func(ctx context.Context, q *generated.Queries) (*generated.ComplianceFlag, error) {
			row, err := q.SetComplianceFlagStatus(ctx, generated.SetComplianceFlagStatusParams{
				ID:     id,
				OrgID:  sess.OrgID,
				Status: in.Status,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errComplianceFlagNotFound
			}
			return row, err
		},
		func(*generated.ComplianceFlag) audit.Entry {
			return audit.Entry{
				OrgID: sess.OrgID, ActorUserID: &sess.UserID,
				Kind:    "compliance.flag_status_changed",
				Payload: map[string]any{"via": "rest", "flag_id": id.String(), "status": in.Status},
			}
		},
	)
	if errors.Is(err, errComplianceFlagNotFound) {
		writeError(w, http.StatusNotFound, errComplianceFlagNotFound.Error())
		return
	}
	if err != nil {
		s.writeDraftAuthoringError(w, "update compliance flag failed", err)
		return
	}
	writeJSON(w, http.StatusOK, flagToDTO(row))
}

// POST /api/v1/compliance/flag-run
//
// Manual trigger for the EDPB-flag sweep. Useful for demo + for
// admins who want to refresh without waiting for the worker tick.
func (s *Server) handleComplianceFlagRun(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.ComplianceFlagger == nil || s.ComplianceFeed == nil {
		writeError(w, http.StatusServiceUnavailable, "flagger not configured")
		return
	}
	actor, err := s.sessionOwnerActor(r, sess)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize compliance refresh", err)
		return
	}
	type refreshResult struct{ itemsProcessed, flagsRaised int }
	result, err := authoring.CommitOwnerMutation(r.Context(), s.Pool, s.Audit, actor,
		func(ctx context.Context, q *generated.Queries) (refreshResult, error) {
			items, err := s.ComplianceFeed.Fetch(ctx, zeroTime())
			if err != nil {
				return refreshResult{}, err
			}
			raised, err := compliance.NewFlagger(q).FlagRunForOrg(ctx, sess.OrgID, items)
			return refreshResult{len(items), raised}, err
		},
		func(result refreshResult) audit.Entry {
			return audit.Entry{
				OrgID: sess.OrgID, ActorUserID: &sess.UserID,
				Kind:    "compliance.flag_run",
				Payload: map[string]any{"via": "rest", "items_processed": result.itemsProcessed, "flags_raised": result.flagsRaised},
			}
		},
	)
	if err != nil {
		s.writeDraftAuthoringError(w, "refresh compliance flags failed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items_processed": result.itemsProcessed, "flags_raised": result.flagsRaised})
}

func baselineToDTO(b *generated.ComplianceBaseline) map[string]any {
	out := map[string]any{
		"org_id":         b.OrgID.String(),
		"business_type":  b.BusinessType,
		"jurisdiction":   b.Jurisdiction,
		"schema_version": b.SchemaVersion,
		"seeded_at":      b.SeededAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"updated_at":     b.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if b.DpaTemplateID.Valid {
		out["dpa_template_id"] = uuid.UUID(b.DpaTemplateID.Bytes).String()
	}
	if b.RecordsDocID.Valid {
		out["records_doc_id"] = uuid.UUID(b.RecordsDocID.Bytes).String()
	}
	if b.PrivacyNoticeID.Valid {
		out["privacy_notice_id"] = uuid.UUID(b.PrivacyNoticeID.Bytes).String()
	}
	return out
}

func flagToDTO(f *generated.ComplianceFlag) map[string]any {
	out := map[string]any{
		"id":               f.ID.String(),
		"org_id":           f.OrgID.String(),
		"update_ref":       f.UpdateRef,
		"update_title":     f.UpdateTitle,
		"affected_topic":   f.AffectedTopic,
		"block_id":         f.BlockID,
		"severity":         f.Severity,
		"suggested_action": f.SuggestedAction,
		"status":           f.Status,
		"raised_at":        f.RaisedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if f.DocumentID.Valid {
		out["document_id"] = uuid.UUID(f.DocumentID.Bytes).String()
	}
	if f.TemplateID.Valid {
		out["template_id"] = uuid.UUID(f.TemplateID.Bytes).String()
	}
	if f.ResolvedAt.Valid {
		out["resolved_at"] = f.ResolvedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return out
}
