// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
)

const signerClarifierTimeout = 35 * time.Second

// Phase 11 wires the three AI-backed features:
//
//   11.1  POST /sign/{token}/clarify        signer-side, magic-token authed
//   11.2  /api/v1/documents/{id}/proposals  sender-side, session authed
//   11.3  /api/v1/documents/{id}/bilingual  sender-side, session authed
//
// Each handler keeps the AI heavy lifting in internal/aiapps so the
// HTTP shell stays small + the audit + Shield-tokenized path is shared.

// POST /sign/{token}/clarify
//
// Body: { "block_id": "...", "selection_text": "...", "question": "...", "locale": "sv-SE" }
//
// Locale is optional; defaults to 'sv-SE'. We pull surrounding context
// from the signer's document view (the same block tree the rest of
// /sign/{token}/* serves), so the explanation is grounded in the
// clause's neighbours.
func (s *Server) handleSignerClarify(w http.ResponseWriter, r *http.Request) {
	if s.Clarifier == nil {
		writeError(w, http.StatusServiceUnavailable, "clarifier not configured")
		return
	}
	rc, ok := s.lookupTokenOrError(w, r)
	if !ok {
		return
	}
	noticeEvidence, ok := s.requireSignerNoticeAcknowledgement(w, r, rc)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var in signerClarifierInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.SelectionText == "" && in.BlockID == "" {
		writeError(w, http.StatusBadRequest, "selection_text or block_id required")
		return
	}

	res, err := s.completeSignerClarifier(r, rc, noticeEvidence, in)
	if err != nil {
		s.writeSignerClarifierError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// lookupBlockWithNeighbours walks the top-level block list + finds the
// target by ID. Returns the block plus the rendered text of the
// previous and next blocks (joined for the "surrounding context" slot
// in the prompt).
func lookupBlockWithNeighbours(tree *blocks.Tree, id string) (*blocks.Block, string, string) {
	if tree == nil || len(tree.Blocks) == 0 {
		return nil, "", ""
	}
	idx := -1
	for i := range tree.Blocks {
		if tree.Blocks[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, "", ""
	}
	before, after := "", ""
	if idx > 0 {
		before = tree.Blocks[idx-1].Text
	}
	if idx+1 < len(tree.Blocks) {
		after = tree.Blocks[idx+1].Text
	}
	return &tree.Blocks[idx], before, after
}

// POST /api/v1/documents/{id}/proposals
//
// Body: { "block_id", "proposal_kind", "proposed_text", "rationale",
//
//	"ai_assisted": false, "parent_id": "..." }
func (s *Server) handleCreateProposal(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var in struct {
		BlockID      string `json:"block_id"`
		ProposalKind string `json:"proposal_kind"`
		ProposedText string `json:"proposed_text"`
		Rationale    string `json:"rationale"`
		AIAssisted   bool   `json:"ai_assisted"`
		ParentID     string `json:"parent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.BlockID == "" {
		writeError(w, http.StatusBadRequest, "block_id required")
		return
	}
	switch in.ProposalKind {
	case "edit", "reject", "counter", "block_lock":
	default:
		writeError(w, http.StatusBadRequest, "proposal_kind must be edit|reject|counter|block_lock")
		return
	}
	parent := pgtype.UUID{}
	if in.ParentID != "" {
		id, err := uuid.Parse(in.ParentID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "parent_id must be a uuid")
			return
		}
		parent = pgtype.UUID{Bytes: id, Valid: true}
	}
	actor, err := s.sessionAIAppActor(r, sess)
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	row, err := authoring.CommitNegotiationMutation(r.Context(), s.aiAppDependencies(), actor, docID,
		func(ctx context.Context, q *generated.Queries, doc *generated.Document) (*generated.DocumentProposal, error) {
			if _, err := authoring.AIAppBlock(doc, in.BlockID); err != nil {
				return nil, err
			}
			if parent.Valid {
				row, err := q.GetProposalForUpdate(ctx, generated.GetProposalForUpdateParams{ID: uuid.UUID(parent.Bytes), OrgID: sess.OrgID, DocumentID: doc.ID})
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, authoring.ErrAIProposalNotFound
				}
				if err != nil {
					return nil, err
				}
				if row.BlockID != in.BlockID {
					return nil, authoring.ErrAIProposalBlockMismatch
				}
			}
			return q.InsertProposal(ctx, generated.InsertProposalParams{
				DocumentID:   doc.ID,
				OrgID:        sess.OrgID,
				ProposedBy:   pgtype.UUID{Bytes: sess.UserID, Valid: true},
				BlockID:      in.BlockID,
				ProposalKind: in.ProposalKind,
				ProposedText: in.ProposedText,
				Rationale:    in.Rationale,
				DiffJson:     []byte("{}"),
				AiAssisted:   in.AIAssisted,
				ParentID:     parent,
			})
		},
		func(row *generated.DocumentProposal) audit.Entry {
			return audit.Entry{
				OrgID:       sess.OrgID,
				ActorUserID: &sess.UserID,
				DocumentID:  &docID,
				Kind:        "negotiation.proposed",
				IP:          firstIPFromHeader(r),
				UserAgent:   r.UserAgent(),
				Payload: map[string]any{
					"via":         "rest",
					"proposal_id": row.ID.String(),
					"block_id":    in.BlockID,
					"kind":        in.ProposalKind,
					"ai_assisted": in.AIAssisted,
				},
			}
		},
	)
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, proposalToDTO(row))
}

// GET /api/v1/documents/{id}/proposals
func (s *Server) handleListProposals(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: sess.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	rows, err := s.Queries.ListProposalsByDocument(r.Context(), generated.ListProposalsByDocumentParams{
		DocumentID: docID,
		Limit:      200,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		out = append(out, proposalToDTO(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposals": out, "count": len(out)})
}

// PATCH /api/v1/proposals/{id}/status
//
// Body: { "status": "accepted" | "rejected" | "superseded" }
func (s *Server) handleSetProposalStatus(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var in struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	switch in.Status {
	case "accepted", "rejected", "superseded", "pending":
	default:
		writeError(w, http.StatusBadRequest, "status must be accepted|rejected|superseded|pending")
		return
	}
	ownerDoc, err := s.Queries.GetProposalOwnerDoc(r.Context(), generated.GetProposalOwnerDocParams{ID: id, OrgID: sess.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		s.writeAIAppMutationError(w, authoring.ErrAIProposalNotFound)
		return
	}
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	actor, err := s.sessionAIAppActor(r, sess)
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	row, err := authoring.CommitNegotiationMutation(r.Context(), s.aiAppDependencies(), actor, ownerDoc,
		func(ctx context.Context, q *generated.Queries, doc *generated.Document) (*generated.DocumentProposal, error) {
			row, err := q.GetProposalForUpdate(ctx, generated.GetProposalForUpdateParams{ID: id, OrgID: sess.OrgID, DocumentID: doc.ID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, authoring.ErrAIProposalNotFound
			}
			if err != nil {
				return nil, err
			}
			if _, err := authoring.AIAppBlock(doc, row.BlockID); err != nil {
				return nil, err
			}
			return q.SetProposalStatus(ctx, generated.SetProposalStatusParams{
				ID:     id,
				OrgID:  sess.OrgID,
				Status: in.Status,
			})
		},
		func(row *generated.DocumentProposal) audit.Entry {
			return audit.Entry{
				OrgID:       sess.OrgID,
				ActorUserID: &sess.UserID,
				DocumentID:  &row.DocumentID,
				Kind:        "negotiation.status_changed",
				IP:          firstIPFromHeader(r),
				UserAgent:   r.UserAgent(),
				Payload:     map[string]any{"via": "rest", "proposal_id": id.String(), "status": in.Status},
			}
		},
	)
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proposalToDTO(row))
}

// POST /api/v1/documents/{id}/proposals/suggest
//
// Body: { "block_id", "concern", "red_lines": ["..."] }
// Returns an AI-drafted counter without persisting; caller can then
// POST /proposals with ai_assisted=true to commit.
func (s *Server) handleSuggestCounter(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Negotiator == nil {
		writeError(w, http.StatusServiceUnavailable, "negotiator not configured")
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var in struct {
		BlockID  string   `json:"block_id"`
		Concern  string   `json:"concern"`
		RedLines []string `json:"red_lines"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	res, err := runStaffAICompletion(r, s, sess, docID, "suggest_counter_clause", s.Negotiator.Runtime,
		func(ctx context.Context, runtime *ai.Runtime, doc *generated.Document) (aiapps.CounterResult, error) {
			block, err := authoring.AIAppBlock(doc, in.BlockID)
			if err != nil {
				return aiapps.CounterResult{}, err
			}
			return (&aiapps.Negotiator{Runtime: runtime}).SuggestCounter(ctx, aiapps.CounterInput{
				OrgID: sess.OrgID, DocumentID: doc.ID, UserID: &sess.UserID,
				OriginalClause: block.Text, Concern: in.Concern, RedLines: in.RedLines,
			})
		}, nil)
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// POST /api/v1/documents/{id}/bilingual/equivalence
//
// Body: { "block_id" OR "clause_a"+"clause_b", "lang_a", "lang_b" }
func (s *Server) handleBilingualEquivalence(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.Bilingual == nil {
		writeError(w, http.StatusServiceUnavailable, "bilingual checker not configured")
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var in struct {
		LangA   string `json:"lang_a"`
		LangB   string `json:"lang_b"`
		ClauseA string `json:"clause_a"`
		ClauseB string `json:"clause_b"`
		BlockID string `json:"block_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	res, err := runStaffAICompletion(r, s, sess, docID, "check_bilingual_equivalence", s.Bilingual.Runtime,
		func(ctx context.Context, runtime *ai.Runtime, doc *generated.Document) (aiapps.EquivalenceResult, error) {
			clauseA := in.ClauseA
			if in.BlockID != "" {
				block, err := authoring.AIAppBlock(doc, in.BlockID)
				if err != nil {
					return aiapps.EquivalenceResult{}, err
				}
				if clauseA == "" {
					clauseA = block.Text
				}
			}
			if clauseA == "" || in.ClauseB == "" {
				return aiapps.EquivalenceResult{}, errAIAppInput
			}
			return (&aiapps.Bilingual{Runtime: runtime}).Check(ctx, aiapps.EquivalenceInput{
				OrgID: sess.OrgID, DocumentID: doc.ID, UserID: &sess.UserID,
				LangA: in.LangA, ClauseA: clauseA, LangB: in.LangB, ClauseB: in.ClauseB,
			})
		}, func(res aiapps.EquivalenceResult) audit.Entry {
			return audit.Entry{OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &docID, Kind: "bilingual.checked",
				IP: firstIPFromHeader(r), UserAgent: r.UserAgent(), Payload: map[string]any{
					"equivalent": res.Equivalent, "confidence": res.Confidence, "shield_active": res.ShieldActive,
				},
			}
		})
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// PATCH /api/v1/documents/{id}/negotiation-enabled
//
// Body: { "enabled": true }
func (s *Server) handleSetNegotiationEnabled(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	actor, err := s.sessionAIAppActor(r, sess)
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	_, err = authoring.CommitNegotiationMutation(r.Context(), s.aiAppDependencies(), actor, docID,
		func(ctx context.Context, q *generated.Queries, doc *generated.Document) (bool, error) {
			return true, q.SetDocumentNegotiationEnabled(ctx, generated.SetDocumentNegotiationEnabledParams{ID: doc.ID, OrgID: sess.OrgID, NegotiationEnabled: in.Enabled})
		}, func(bool) audit.Entry {
			return audit.Entry{OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &docID, Kind: "negotiation.setting_changed",
				IP: firstIPFromHeader(r), UserAgent: r.UserAgent(), Payload: map[string]any{"via": "rest", "enabled": in.Enabled},
			}
		})
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"negotiation_enabled": in.Enabled})
}

// PATCH /api/v1/documents/{id}/bilingual-target
//
// Body: { "lang": "en-GB" }
func (s *Server) handleSetBilingualTarget(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		Lang string `json:"lang"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	actor, err := s.sessionAIAppActor(r, sess)
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	_, err = authoring.CommitNegotiationMutation(r.Context(), s.aiAppDependencies(), actor, docID,
		func(ctx context.Context, q *generated.Queries, doc *generated.Document) (bool, error) {
			return true, q.SetDocumentBilingualTarget(ctx, generated.SetDocumentBilingualTargetParams{ID: doc.ID, OrgID: sess.OrgID, BilingualTargetLang: in.Lang})
		}, func(bool) audit.Entry {
			return audit.Entry{OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &docID, Kind: "bilingual.target_changed",
				IP: firstIPFromHeader(r), UserAgent: r.UserAgent(), Payload: map[string]any{"via": "rest", "lang": in.Lang},
			}
		})
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bilingual_target_lang": in.Lang})
}

// POST /api/v1/documents/{id}/risk-analysis
//
// Body: { "locale": "sv-SE", "sender_context": "B2B SaaS, EU customers, no auto-renewal" }
//
// Both fields are optional. Runs the risk_analyzer prompt against the
// document's current block tree (skipping signature placeholders and
// empty blocks). Findings are NOT persisted ,  callers re-run when the
// draft changes.
func (s *Server) handleRunRiskAnalysis(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if s.RiskAnalyzer == nil {
		writeError(w, http.StatusServiceUnavailable, "risk analyzer not configured")
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var in struct {
		Locale        string `json:"locale"`
		SenderContext string `json:"sender_context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	res, err := runStaffAICompletion(r, s, sess, docID, "run_risk_analysis", s.RiskAnalyzer.Runtime,
		func(ctx context.Context, runtime *ai.Runtime, doc *generated.Document) (aiapps.AnalyzeResult, error) {
			tree, err := blocks.ParseTree(doc.BlocksJson)
			if err != nil {
				return aiapps.AnalyzeResult{}, err
			}
			return (&aiapps.RiskAnalyzer{Runtime: runtime}).Analyze(ctx, aiapps.AnalyzeInput{
				OrgID: sess.OrgID, DocumentID: doc.ID, UserID: &sess.UserID,
				Locale: in.Locale, Blocks: tree.Blocks, SenderContext: in.SenderContext,
			})
		}, func(res aiapps.AnalyzeResult) audit.Entry {
			return audit.Entry{OrgID: sess.OrgID, ActorUserID: &sess.UserID, DocumentID: &docID, Kind: "risk.analyzed", IP: firstIPFromHeader(r), UserAgent: r.UserAgent(),
				Payload: map[string]any{"findings_count": len(res.Findings), "high": countSeverity(res.Findings, aiapps.SeverityHigh),
					"medium": countSeverity(res.Findings, aiapps.SeverityMedium), "low": countSeverity(res.Findings, aiapps.SeverityLow),
					"shield_active": res.ShieldActive, "latency_ms": res.LatencyMs},
			}
		})
	if err != nil {
		s.writeAIAppMutationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func countSeverity(fs []aiapps.Finding, sev string) int {
	n := 0
	for _, f := range fs {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func proposalToDTO(p *generated.DocumentProposal) map[string]any {
	out := map[string]any{
		"id":            p.ID.String(),
		"document_id":   p.DocumentID.String(),
		"org_id":        p.OrgID.String(),
		"block_id":      p.BlockID,
		"proposal_kind": p.ProposalKind,
		"proposed_text": p.ProposedText,
		"rationale":     p.Rationale,
		"status":        p.Status,
		"ai_assisted":   p.AiAssisted,
		"diff_json":     json.RawMessage(p.DiffJson),
		"created_at":    p.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"updated_at":    p.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if p.ProposedBy.Valid {
		out["proposed_by"] = uuid.UUID(p.ProposedBy.Bytes).String()
	}
	if p.RecipientID.Valid {
		out["recipient_id"] = uuid.UUID(p.RecipientID.Bytes).String()
	}
	if p.ParentID.Valid {
		out["parent_id"] = uuid.UUID(p.ParentID.Bytes).String()
	}
	return out
}

// guard imports + helpers
var _ = strings.ToLower

var errAIAppInput = errors.New("clause_a and clause_b required (or block_id resolving to clause_a)")

func (s *Server) aiAppDependencies() authoring.AIAppDeps {
	return authoring.AIAppDeps{Pool: s.Pool, Queries: s.Queries, Audit: s.Audit}
}

func (s *Server) sessionAIAppActor(r *http.Request, user auth.SessionUser) (authoring.Actor, error) {
	authorize, err := s.sessionDraftAuthorization(r, user.OrgID, user.UserID)
	if err != nil {
		return authoring.Actor{}, err
	}
	return authoring.Actor{OrgID: user.OrgID, UserID: user.UserID, Authorize: authorize}, nil
}

func runStaffAICompletion[T any](r *http.Request, s *Server, user auth.SessionUser, id uuid.UUID, action string, runtime *ai.Runtime,
	complete func(context.Context, *ai.Runtime, *generated.Document) (T, error), event func(T) audit.Entry,
) (T, error) {
	var zero T
	actor, err := s.sessionAIAppActor(r, user)
	if err != nil {
		return zero, err
	}
	return authoring.CompleteDocumentAI(r.Context(), s.aiAppDependencies(), authoring.AIAppRequest{
		Actor: actor, DocumentID: id, Via: "rest", Action: action, IP: firstIPFromHeader(r), UserAgent: r.UserAgent(),
	}, runtime, complete, event)
}

func (s *Server) writeAIAppMutationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authoring.ErrAIAppDocumentClosed):
		writeError(w, http.StatusConflict, authoring.ErrAIAppDocumentClosed.Error())
	case errors.Is(err, authoring.ErrAIProposalNotFound), errors.Is(err, authoring.ErrAIBlockNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, authoring.ErrAIProposalBlockMismatch), errors.Is(err, errAIAppInput):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.writeDraftAuthoringError(w, "AI or negotiation operation failed", err)
	}
}
