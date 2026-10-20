// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/catalogrules"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

var errEIDASRuleNotFound = errors.New("rule not found")

type eidasRuleInputError struct {
	status  int
	message string
}

func (e *eidasRuleInputError) Error() string { return e.message }

func (s *Server) writeEIDASMutationError(w http.ResponseWriter, err error) {
	if errors.Is(err, pdfadmission.ErrCatalogRuleInputV1) || errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
		writeError(w, http.StatusServiceUnavailable, "eIDAS policy is temporarily unavailable")
		return
	}
	var input *eidasRuleInputError
	if errors.As(err, &input) {
		writeError(w, input.status, input.message)
		return
	}
	if errors.Is(err, errEIDASRuleNotFound) {
		writeError(w, http.StatusNotFound, errEIDASRuleNotFound.Error())
		return
	}
	s.writeDraftAuthoringError(w, "update eIDAS policy failed", err)
}

// Phase 9.2 eIDAS REST surface. CRUD over org_id-scoped routing rules,
// a "preview" endpoint that runs the engine against a hypothetical
// input so the rule-builder UI can show "this rule would trigger AES",
// a "seed Swedish defaults" button, and a per-document tier setter.

// ruleDTO is the wire shape for REST + MCP.
type ruleDTO struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Priority     int32           `json:"priority"`
	Predicate    json.RawMessage `json:"predicate_json"`
	RequiredTier string          `json:"required_tier"`
	Reason       string          `json:"reason"`
	Active       bool            `json:"active"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
}

func toRuleDTO(r *generated.EidasRoutingRule) ruleDTO {
	return ruleDTO{
		ID:           r.ID.String(),
		Name:         r.Name,
		Priority:     r.Priority,
		Predicate:    r.PredicateJson,
		RequiredTier: r.RequiredTier,
		Reason:       r.Reason,
		Active:       r.Active,
		CreatedAt:    r.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		UpdatedAt:    r.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

// GET /api/v1/eidas-rules
func (s *Server) handleListEIDASRules(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	rules, err := s.Queries.ListEIDASRules(r.Context(), sess.OrgID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]ruleDTO, 0, len(rules))
	for _, r := range rules {
		out = append(out, toRuleDTO(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out, "count": len(out)})
}

// POST /api/v1/eidas-rules
//
// Body: { name, priority, predicate_json, required_tier, reason, active }
func (s *Server) handleCreateEIDASRule(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	input, err := s.HTMLCreationSessions.NewCatalogRuleHTTPInputV1(r.Context(), sess.OrgID)
	if err != nil {
		s.writeEIDASMutationError(w, err)
		return
	}
	defer input.CloseConsumerV1()
	in, err := input.DecodeCreateV1(r.Context(), w, r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if !eidas.Tier(in.RequiredTier).Valid() {
		writeError(w, http.StatusBadRequest, "required_tier must be SES, AES, or QES")
		return
	}
	if len(in.Predicate) == 0 {
		writeError(w, http.StatusBadRequest, "predicate_json required")
		return
	}
	if err := input.ValidateRuleV1(r.Context(), in.Predicate, eidas.Tier(in.RequiredTier)); err != nil {
		if errors.Is(err, pdfadmission.ErrCatalogRuleInputV1) {
			s.writeEIDASMutationError(w, err)
			return
		}
		writeError(w, http.StatusBadRequest, "invalid eIDAS rule: "+err.Error())
		return
	}
	active := true
	if in.Active != nil {
		active = *in.Active
	}
	if err := eidas.ValidateRuleActivation(eidas.Tier(in.RequiredTier), active); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	actor, err := s.sessionOwnerActor(r, sess)
	if err != nil {
		s.writeEIDASMutationError(w, err)
		return
	}
	row, release, err := catalogrules.CommitCatalogOwnerMutationV1(r.Context(), s.HTMLCreationSessions, s.Audit, actor, uuid.New(),
		func(ctx context.Context, q *generated.Queries, reader *pdfadmission.ApplicationHTMLAuthoringReaderV1) (*generated.EidasRoutingRule, error) {
			return reader.CreateCatalogRuleV1(ctx, generated.InsertEIDASRuleParams{
				OrgID:         sess.OrgID,
				Name:          in.Name,
				Priority:      in.Priority,
				PredicateJson: in.Predicate,
				RequiredTier:  in.RequiredTier,
				Reason:        in.Reason,
				Active:        active,
			})
		},
		func(row *generated.EidasRoutingRule) audit.Entry {
			return audit.Entry{
				OrgID: sess.OrgID, ActorUserID: &sess.UserID,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "rest", "tool": "create_eidas_rule", "rule_id": row.ID.String()},
			}
		},
	)
	if err != nil {
		s.writeEIDASMutationError(w, err)
		return
	}
	defer release()
	writeJSON(w, http.StatusCreated, toRuleDTO(row))
}

// PATCH /api/v1/eidas-rules/{id}
func (s *Server) handleUpdateEIDASRule(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	input, err := s.HTMLCreationSessions.NewCatalogRuleHTTPInputV1(r.Context(), sess.OrgID)
	if err != nil {
		s.writeEIDASMutationError(w, err)
		return
	}
	defer input.CloseConsumerV1()
	in, err := input.DecodePatchV1(r.Context(), w, r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	actor, err := s.sessionOwnerActor(r, sess)
	if err != nil {
		s.writeEIDASMutationError(w, err)
		return
	}
	row, release, err := catalogrules.CommitCatalogOwnerMutationV1(r.Context(), s.HTMLCreationSessions, s.Audit, actor, id,
		func(ctx context.Context, q *generated.Queries, reader *pdfadmission.ApplicationHTMLAuthoringReaderV1) (*generated.EidasRoutingRule, error) {
			// All active policy writers serialize through the organization lock.
			// Resolve omitted values from the row read after that lock was acquired.
			existing, err := reader.ReadCatalogRuleV1(ctx, id)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errEIDASRuleNotFound
			}
			if err != nil {
				return nil, err
			}
			name := existing.Name
			if in.Name != nil {
				name = *in.Name
			}
			priority := existing.Priority
			if in.Priority != nil {
				priority = *in.Priority
			}
			predicate := existing.PredicateJson
			if in.Predicate != nil && len(*in.Predicate) > 0 {
				predicate = *in.Predicate
			}
			tier := existing.RequiredTier
			if in.RequiredTier != nil {
				if !eidas.Tier(*in.RequiredTier).Valid() {
					return nil, &eidasRuleInputError{http.StatusBadRequest, "required_tier must be SES, AES, or QES"}
				}
				tier = *in.RequiredTier
			}
			reason := existing.Reason
			if in.Reason != nil {
				reason = *in.Reason
			}
			active := existing.Active
			if in.Active != nil {
				active = *in.Active
			}
			if err := input.ValidateRuleV1(ctx, predicate, eidas.Tier(tier)); err != nil {
				if errors.Is(err, pdfadmission.ErrCatalogRuleInputV1) {
					return nil, err
				}
				return nil, &eidasRuleInputError{http.StatusBadRequest, "invalid eIDAS rule: " + err.Error()}
			}
			if err := eidas.ValidateRuleActivation(eidas.Tier(tier), active); err != nil {
				return nil, &eidasRuleInputError{http.StatusConflict, err.Error()}
			}
			updated, err := reader.UpdateCatalogRuleV1(ctx, generated.UpdateEIDASRuleParams{
				ID:            id,
				OrgID:         sess.OrgID,
				Name:          name,
				Priority:      priority,
				PredicateJson: predicate,
				RequiredTier:  tier,
				Reason:        reason,
				Active:        active,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errEIDASRuleNotFound
			}
			return updated, err
		},
		func(*generated.EidasRoutingRule) audit.Entry {
			return audit.Entry{
				OrgID: sess.OrgID, ActorUserID: &sess.UserID,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "rest", "tool": "update_eidas_rule", "rule_id": id.String()},
			}
		},
	)
	if err != nil {
		s.writeEIDASMutationError(w, err)
		return
	}
	defer release()
	writeJSON(w, http.StatusOK, toRuleDTO(row))
}

// DELETE /api/v1/eidas-rules/{id}
func (s *Server) handleDeleteEIDASRule(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	actor, err := s.sessionOwnerActor(r, sess)
	if err != nil {
		s.writeEIDASMutationError(w, err)
		return
	}
	_, release, err := catalogrules.CommitCatalogOwnerMutationV1(r.Context(), s.HTMLCreationSessions, s.Audit, actor, id,
		func(ctx context.Context, q *generated.Queries, reader *pdfadmission.ApplicationHTMLAuthoringReaderV1) (uuid.UUID, error) {
			if err := reader.DeleteCatalogRuleV1(ctx, id); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return uuid.Nil, errEIDASRuleNotFound
				}
				return uuid.Nil, err
			}
			return id, nil
		},
		func(uuid.UUID) audit.Entry {
			return audit.Entry{
				OrgID: sess.OrgID, ActorUserID: &sess.UserID,
				Kind:    audit.KindDocumentUpdated,
				Payload: map[string]any{"via": "rest", "tool": "delete_eidas_rule", "rule_id": id.String()},
			}
		},
	)
	if err != nil {
		s.writeEIDASMutationError(w, err)
		return
	}
	defer release()
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/v1/eidas-rules/seed-sweden
//
// Idempotent. Adds the default Swedish rules an org should start with;
// existing rules with the same names are left untouched.
func (s *Server) handleSeedSwedishEIDASRules(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if err := eidas.ValidateRuleActivation(eidas.TierAES, true); err != nil {
		writeError(w, http.StatusConflict, "Swedish defaults are unavailable: "+err.Error())
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if err := eidas.New(s.Queries.WithTx(tx)).SeedSwedishDefaults(r.Context(), sess.OrgID); err != nil {
		writeInternalError(w, err)
		return
	}
	pending, err := s.Audit.LogTx(r.Context(), tx, audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID,
		Kind:    audit.KindDocumentUpdated,
		Payload: map[string]any{"via": "rest", "tool": "seed_swedish_eidas_defaults"},
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pending)
	rules, _ := s.Queries.ListEIDASRules(r.Context(), sess.OrgID)
	out := make([]ruleDTO, 0, len(rules))
	for _, r := range rules {
		out = append(out, toRuleDTO(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out, "count": len(out)})
}

// POST /api/v1/eidas-rules/preview
//
// Body: { amount, country, document_type, variables, current_tier? }
// Runs the engine against the supplied hypothetical input. Useful for
// the rule-builder UI to show "if this contract had amount=200000, AES
// would be required" without committing a send.
func (s *Server) handlePreviewEIDASRules(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var in struct {
		Amount       float64           `json:"amount"`
		Country      string            `json:"country"`
		DocumentType string            `json:"document_type"`
		Variables    map[string]string `json:"variables"`
		CurrentTier  string            `json:"current_tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Variables == nil {
		in.Variables = map[string]string{}
	}
	decision, err := s.EIDAS.Evaluate(r.Context(), sess.OrgID, eidas.EvaluateInput{
		Amount:       in.Amount,
		Country:      in.Country,
		DocumentType: in.DocumentType,
		Variables:    in.Variables,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := map[string]any{
		"required_tier":   decision.RequiredTier,
		"matched_rules":   decision.MatchedRules,
		"evaluated_count": decision.EvaluatedCount,
	}
	if in.CurrentTier != "" {
		out["would_block"] = eidas.Tier(in.CurrentTier).Cmp(decision.RequiredTier) < 0
	}
	writeJSON(w, http.StatusOK, out)
}

// PATCH /api/v1/documents/{id}/routing-tier
//
// Body: { "routing_tier": "AES" }
func (s *Server) handleSetDocumentRoutingTier(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var in struct {
		RoutingTier string `json:"routing_tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	tier, err := writableRoutingTier(in.RoutingTier)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, sess.OrgID, sess.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize routing tier update", err)
		return
	}
	if s.Pool == nil || s.Audit == nil {
		writeInternalError(w, errors.New("routing tier mutation dependencies unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockDraft(ctx, tx,
		authoring.Actor{OrgID: sess.OrgID, UserID: sess.UserID, Authorize: authorize}, docID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize routing tier update", err)
		return
	}
	q := generated.New(tx)
	rows, err := q.SetDocumentRoutingTier(ctx, generated.SetDocumentRoutingTierParams{
		ID: docID, OrgID: sess.OrgID, RoutingTier: tier,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if rows != 1 {
		writeError(w, http.StatusConflict, "routing tier can only be set to SES while the document is draft")
		return
	}
	pendingAudit, err := s.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &docID,
		Kind:    audit.KindDocumentUpdated,
		Payload: map[string]any{"via": "rest", "tool": "set_routing_tier", "routing_tier": tier},
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if err := guard.Recheck(ctx); err != nil {
		s.writeDraftAuthoringError(w, "authorize routing tier commit", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeInternalError(w, err)
		return
	}
	s.Audit.Publish(pendingAudit)
	writeJSON(w, http.StatusOK, map[string]any{"routing_tier": tier})
}

func writableRoutingTier(raw string) (string, error) {
	if strings.EqualFold(strings.TrimSpace(raw), string(eidas.TierSES)) {
		return string(eidas.TierSES), nil
	}
	return "", errors.New("AES and QES are unavailable until identity proofs are cryptographically bound to the ceremony; routing_tier must be SES")
}
