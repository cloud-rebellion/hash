// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/aiauthoring"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/negotiationauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// registerAIAppsTools mounts the Phase 11 AI moats: clarifier (11.1),
// negotiation copilot (11.2), bilingual equivalence (11.3).
func registerAIAppsTools(s *Server, d Deps) {
	if d.Clarifier != nil {
		s.RegisterTool(ToolDef{
			Name:        "clarify_clause",
			Write:       true,
			Description: "Return a plain-language explanation of a clause for a signer. Grounded in the supplied clause text + surrounding context + legal references; locale shapes the response language (sv-SE default). Shield-tokenizes PII before crossing to the model.",
			InputSchema: schemaObject(map[string]any{
				"document_id":         stringSchema("document uuid"),
				"clause_text":         stringSchema("the clause to explain"),
				"surrounding_context": stringSchema("optional neighbour clauses for grounding"),
				"legal_context":       stringSchema("optional legal references"),
				"question":            stringSchema("optional signer question; empty = 'explain this'"),
				"locale":              stringSchema("RFC 5646 tag; default sv-SE"),
			}, []string{"document_id", "clause_text"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID         string `json:"document_id"`
					ClauseText         string `json:"clause_text"`
					SurroundingContext string `json:"surrounding_context"`
					LegalContext       string `json:"legal_context"`
					Question           string `json:"question"`
					Locale             string `json:"locale"`
				}
				if err := MustParseArgs(args, &p); err != nil {
					return nil, err
				}
				id, err := uuid.Parse(p.DocumentID)
				if err != nil {
					return nil, errors.New("document_id must be a uuid")
				}
				if err := auth.EnforceDocScope(r.Context(), id); err != nil {
					return nil, err
				}
				return runAIAppCompletion(r.Context(), d, id, "clarify_clause", d.Clarifier.Runtime,
					func(ctx context.Context, runtime *ai.Runtime, _ *generated.Document) (aiapps.ClarifyResult, error) {
						return (&aiapps.Clarifier{Runtime: runtime}).Clarify(ctx, aiapps.ClarifyInput{
							OrgID: u.OrgID, DocumentID: id, UserID: &u.UserID, Locale: p.Locale, ClauseText: p.ClauseText,
							SurroundingContext: p.SurroundingContext, LegalContext: p.LegalContext, Question: p.Question,
						})
					}, nil,
				)
			},
		})
	}

	if d.Negotiator != nil {
		s.RegisterTool(ToolDef{
			Name:        "suggest_counter_clause",
			Write:       true,
			Description: "Draft a counter-clause for a flagged block. Returns revised text + rationale. The output is a suggestion only; pass it to propose_counter_clause to actually persist a proposal.",
			InputSchema: schemaObject(map[string]any{
				"document_id": stringSchema("document uuid"),
				"block_id":    stringSchema("block uuid to redraft"),
				"concern":     stringSchema("recipient concern / context"),
				"red_lines": map[string]any{
					"type":  "array",
					"items": map[string]any{"type": "string"},
				},
			}, []string{"document_id", "block_id"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID string   `json:"document_id"`
					BlockID    string   `json:"block_id"`
					Concern    string   `json:"concern"`
					RedLines   []string `json:"red_lines"`
				}
				if err := MustParseArgs(args, &p); err != nil {
					return nil, err
				}
				id, err := uuid.Parse(p.DocumentID)
				if err != nil {
					return nil, errors.New("document_id must be a uuid")
				}
				if err := auth.EnforceDocScope(r.Context(), id); err != nil {
					return nil, err
				}
				return runAIAppCompletion(r.Context(), d, id, "suggest_counter_clause", d.Negotiator.Runtime,
					func(ctx context.Context, runtime *ai.Runtime, doc *generated.Document) (aiapps.CounterResult, error) {
						target, err := authoring.AIAppBlockContextV1(ctx, doc, p.BlockID)
						if err != nil {
							return aiapps.CounterResult{}, err
						}
						return (&aiapps.Negotiator{Runtime: runtime}).SuggestCounter(ctx, aiapps.CounterInput{
							OrgID: u.OrgID, DocumentID: id, UserID: &u.UserID, OriginalClause: target.Text, Concern: p.Concern, RedLines: p.RedLines,
						})
					}, nil,
				)
			},
		})

		s.RegisterTool(ToolDef{
			Name:        "propose_counter_clause",
			Write:       true,
			Description: "Persist a proposal against a block. proposal_kind is edit | reject | counter | block_lock. Set ai_assisted=true when the proposed_text came from suggest_counter_clause.",
			InputSchema: schemaObject(map[string]any{
				"document_id":   stringSchema("document uuid"),
				"block_id":      stringSchema("block uuid"),
				"proposal_kind": stringSchema("edit | reject | counter | block_lock"),
				"proposed_text": stringSchema("the proposed clause body"),
				"rationale":     stringSchema("one-line explanation"),
				"ai_assisted":   map[string]any{"type": "boolean"},
				"parent_id":     stringSchema("optional parent proposal in a counter-counter chain"),
			}, []string{"document_id", "block_id", "proposal_kind"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				return withManualNegotiationArgumentsV1(r, d, args, func(r *http.Request, args json.RawMessage) (any, error) {
					var p struct {
						DocumentID   string `json:"document_id"`
						BlockID      string `json:"block_id"`
						ProposalKind string `json:"proposal_kind"`
						ProposedText string `json:"proposed_text"`
						Rationale    string `json:"rationale"`
						AIAssisted   bool   `json:"ai_assisted"`
						ParentID     string `json:"parent_id"`
					}
					if err := MustParseArgs(args, &p); err != nil {
						return nil, err
					}
					id, err := uuid.Parse(p.DocumentID)
					if err != nil {
						return nil, errors.New("document_id must be a uuid")
					}
					if err := auth.EnforceDocScope(r.Context(), id); err != nil {
						return nil, err
					}
					switch p.ProposalKind {
					case "edit", "reject", "counter", "block_lock":
					default:
						return nil, errors.New("proposal_kind must be edit | reject | counter | block_lock")
					}
					parent := pgtype.UUID{}
					if p.ParentID != "" {
						pid, err := uuid.Parse(p.ParentID)
						if err != nil {
							return nil, errors.New("parent_id must be a uuid")
						}
						parent = pgtype.UUID{Bytes: pid, Valid: true}
					}
					result, err := runManualNegotiationV1(r, d, id, negotiationauthoring.InputV1{Operation: pdfadmission.ManualProposalCreateV1, BlockID: p.BlockID, ProposalKind: p.ProposalKind, ProposedText: p.ProposedText, Rationale: p.Rationale, AIAssisted: p.AIAssisted, ParentID: parent})
					owned := &ownedManualNegotiationResultV1{owner: result}
					if err != nil {
						return owned, aiAppMutationError(err)
					}
					owned.value = proposalRow(result.Proposal)
					return owned, nil
				})
			},
		})

		s.RegisterTool(ToolDef{
			Name:        "set_proposal_status",
			Write:       true,
			Description: "Move a proposal between pending / accepted / rejected / superseded as the authorized sender or owner. The audit captures the original actor; accepting a proposal does not apply contract text.",
			InputSchema: schemaObject(map[string]any{
				"proposal_id": stringSchema("proposal uuid"),
				"status":      stringSchema("pending | accepted | rejected | superseded"),
			}, []string{"proposal_id", "status"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				return withManualNegotiationArgumentsV1(r, d, args, func(r *http.Request, args json.RawMessage) (any, error) {
					u, _ := auth.FromContext(r.Context())
					var p struct {
						ProposalID string `json:"proposal_id"`
						Status     string `json:"status"`
					}
					if err := MustParseArgs(args, &p); err != nil {
						return nil, err
					}
					id, err := uuid.Parse(p.ProposalID)
					if err != nil {
						return nil, errors.New("proposal_id must be a uuid")
					}
					// Confine a doc-scoped agent token: it must not flip a proposal on
					// a sibling document. Resolve the owning doc (org-scoped) first.
					ownerDoc, err := d.Queries.GetProposalOwnerDoc(r.Context(), generated.GetProposalOwnerDocParams{ID: id, OrgID: u.OrgID})
					if errors.Is(err, pgx.ErrNoRows) {
						return nil, errors.New("proposal not found")
					}
					if err != nil {
						return nil, err
					}
					if err := auth.EnforceDocScope(r.Context(), ownerDoc); err != nil {
						return nil, err
					}
					switch p.Status {
					case "pending", "accepted", "rejected", "superseded":
					default:
						return nil, errors.New("status must be pending | accepted | rejected | superseded")
					}
					result, err := runManualNegotiationV1(r, d, ownerDoc, negotiationauthoring.InputV1{Operation: pdfadmission.ManualProposalStatusV1, ProposalID: id, Status: p.Status})
					owned := &ownedManualNegotiationResultV1{owner: result}
					if err != nil {
						return owned, aiAppMutationError(err)
					}
					owned.value = proposalRow(result.Proposal)
					return owned, nil
				})
			},
		})

		s.RegisterTool(ToolDef{
			Name:        "list_proposals",
			Description: "Return up to 200 proposals against a document, newest-first.",
			InputSchema: schemaObject(map[string]any{
				"document_id": stringSchema("document uuid"),
			}, []string{"document_id"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID string `json:"document_id"`
				}
				if err := MustParseArgs(args, &p); err != nil {
					return nil, err
				}
				id, err := uuid.Parse(p.DocumentID)
				if err != nil {
					return nil, errors.New("document_id must be a uuid")
				}
				if err := auth.EnforceDocScope(r.Context(), id); err != nil {
					return nil, err
				}
				if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID}); err != nil {
					if errors.Is(err, pgx.ErrNoRows) {
						return nil, errors.New("document not found")
					}
					return nil, err
				}
				rows, err := d.Queries.ListProposalsByDocument(r.Context(), generated.ListProposalsByDocumentParams{
					DocumentID: id, Limit: 200,
				})
				if err != nil {
					return nil, err
				}
				out := make([]map[string]any, 0, len(rows))
				for _, p := range rows {
					out = append(out, proposalRow(p))
				}
				return map[string]any{"proposals": out, "count": len(out)}, nil
			},
		})
	}

	if d.RiskAnalyzer != nil {
		s.RegisterTool(ToolDef{
			Name:        "run_risk_analysis",
			Write:       true,
			Description: "Read the document's draft block tree and return a deterministic list of findings flagging elevated-risk clauses (liability, IP, auto_renewal, jurisdiction, payment_terms, termination, indemnification, confidentiality, data_protection, warranty). Each finding has block_id, category, severity (low|medium|high), summary, suggestion. Use this before sending high-value contracts to surface risks the sender may have missed.",
			InputSchema: schemaObject(map[string]any{
				"document_id":    stringSchema("document uuid"),
				"locale":         stringSchema("RFC 5646 tag, default sv-SE"),
				"sender_context": stringSchema("optional notes about sender redlines / industry"),
			}, []string{"document_id"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID    string `json:"document_id"`
					Locale        string `json:"locale"`
					SenderContext string `json:"sender_context"`
				}
				if err := MustParseArgs(args, &p); err != nil {
					return nil, err
				}
				id, err := uuid.Parse(p.DocumentID)
				if err != nil {
					return nil, errors.New("document_id must be a uuid")
				}
				if err := auth.EnforceDocScope(r.Context(), id); err != nil {
					return nil, err
				}
				return runAIAppCompletion(r.Context(), d, id, "run_risk_analysis", d.RiskAnalyzer.Runtime,
					func(ctx context.Context, runtime *ai.Runtime, doc *generated.Document) (aiapps.AnalyzeResult, error) {
						tree, err := ai.ParseTreeV1(ctx, doc.BlocksJson)
						if err != nil {
							return aiapps.AnalyzeResult{}, err
						}
						return (&aiapps.RiskAnalyzer{Runtime: runtime}).Analyze(ctx, aiapps.AnalyzeInput{
							OrgID: u.OrgID, DocumentID: id, UserID: &u.UserID, Locale: p.Locale, Blocks: tree.Blocks, SenderContext: p.SenderContext,
						})
					},
					func(res aiapps.AnalyzeResult) audit.Entry {
						return audit.Entry{
							OrgID: u.OrgID, DocumentID: &id, ActorUserID: &u.UserID, Kind: "risk.analyzed",
							Payload: map[string]any{"findings_count": len(res.Findings), "shield_active": res.ShieldActive, "via": "mcp"},
						}
					},
				)
			},
		})
	}

	if d.Bilingual != nil {
		s.RegisterTool(ToolDef{
			Name:        "check_bilingual_equivalence",
			Write:       true,
			Description: "Compare two clauses in different languages and return {equivalent, drift, confidence}. Use this to verify a translation hasn't dropped or weakened obligations across languages.",
			InputSchema: schemaObject(map[string]any{
				"document_id": stringSchema("document uuid"),
				"lang_a":      stringSchema("RFC 5646 tag, default sv-SE"),
				"clause_a":    stringSchema("clause body in lang_a"),
				"lang_b":      stringSchema("RFC 5646 tag, default en-GB"),
				"clause_b":    stringSchema("clause body in lang_b"),
			}, []string{"document_id", "clause_a", "clause_b"}),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				u, _ := auth.FromContext(r.Context())
				var p struct {
					DocumentID string `json:"document_id"`
					LangA      string `json:"lang_a"`
					ClauseA    string `json:"clause_a"`
					LangB      string `json:"lang_b"`
					ClauseB    string `json:"clause_b"`
				}
				if err := MustParseArgs(args, &p); err != nil {
					return nil, err
				}
				id, err := uuid.Parse(p.DocumentID)
				if err != nil {
					return nil, errors.New("document_id must be a uuid")
				}
				if err := auth.EnforceDocScope(r.Context(), id); err != nil {
					return nil, err
				}
				return runAIAppCompletion(r.Context(), d, id, "check_bilingual_equivalence", d.Bilingual.Runtime,
					func(ctx context.Context, runtime *ai.Runtime, _ *generated.Document) (aiapps.EquivalenceResult, error) {
						return (&aiapps.Bilingual{Runtime: runtime}).Check(ctx, aiapps.EquivalenceInput{
							OrgID: u.OrgID, DocumentID: id, UserID: &u.UserID, LangA: p.LangA, ClauseA: p.ClauseA, LangB: p.LangB, ClauseB: p.ClauseB,
						})
					}, nil,
				)
			},
		})
	}
	for _, name := range []string{"clarify_clause", "suggest_counter_clause", "run_risk_analysis", "check_bilingual_equivalence"} {
		tool, ok := s.tools[name]
		if !ok {
			continue
		}
		original := tool.Handler
		tool.Handler = func(r *http.Request, args json.RawMessage) (any, error) {
			return withAIArgumentsV1(r, d, args, original)
		}
		s.tools[name] = tool
	}
}

func proposalRow(p *generated.DocumentProposal) map[string]any {
	out := map[string]any{
		"id":            p.ID.String(),
		"document_id":   p.DocumentID.String(),
		"block_id":      p.BlockID,
		"proposal_kind": p.ProposalKind,
		"proposed_text": p.ProposedText,
		"rationale":     p.Rationale,
		"status":        p.Status,
		"ai_assisted":   p.AiAssisted,
		"created_at":    p.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"updated_at":    p.UpdatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if p.ProposedBy.Valid {
		out["proposed_by"] = uuid.UUID(p.ProposedBy.Bytes).String()
	}
	if p.ParentID.Valid {
		out["parent_id"] = uuid.UUID(p.ParentID.Bytes).String()
	}
	return out
}

func runManualNegotiationV1(r *http.Request, d Deps, id uuid.UUID, in negotiationauthoring.InputV1) (*negotiationauthoring.ResultV1, error) {
	actor, err := aiAppActor(r.Context(), id)
	if err != nil {
		return nil, err
	}
	// Original manual MCP entries have no IP or UserAgent fields.
	return negotiationauthoring.MutateV1(r.Context(), negotiationauthoring.DependenciesV1{Sessions: d.PDFCreationSessions, Audit: d.Audit}, negotiationauthoring.ActorV1{OrgID: actor.OrgID, UserID: actor.UserID, Authorize: actor.Authorize, Via: "mcp"}, id, in)
}

type ownedManualNegotiationResultV1 struct {
	value any
	owner *negotiationauthoring.ResultV1
}

func (r *ownedManualNegotiationResultV1) MarshalJSON() ([]byte, error) { return json.Marshal(r.value) }
func (r *ownedManualNegotiationResultV1) CloseConsumerV1() {
	if r != nil && r.owner != nil {
		r.owner.CloseConsumerV1()
	}
}
func withManualNegotiationArgumentsV1(r *http.Request, d Deps, args json.RawMessage, run func(*http.Request, json.RawMessage) (any, error)) (result any, failure error) {
	// Validation-only compatibility cannot enter the producer or synthesize proof.
	if d.PDFCreationSessions == nil {
		return run(r, args)
	}
	u, _ := auth.FromContext(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(ctx, u.OrgID, args)
	if err != nil {
		return nil, err
	}
	defer func() { result = newOwnedBlockToolResultV1(result, input) }()
	failure = input.WithArgumentsV1(ctx, func(raw []byte) error { result, failure = run(r, json.RawMessage(raw)); return failure })
	return result, failure
}

func runAIAppCompletion[T any](ctx context.Context, d Deps, id uuid.UUID, tool string, runtime *ai.Runtime,
	complete func(context.Context, *ai.Runtime, *generated.Document) (T, error), event func(T) audit.Entry,
) (any, error) {
	actor, err := aiAppActor(ctx, id)
	if err != nil {
		return nil, aiAppMutationError(err)
	}
	result, err := aiauthoring.CompleteDocumentAIV1(ctx, aiauthoring.DependenciesV1{Pool: d.Pool, Sessions: d.PDFCreationSessions, Audit: d.Audit}, authoring.AIAppRequest{Actor: actor, DocumentID: id, Via: "mcp", Action: tool}, runtime, complete, event)
	owned := &ownedAIResultV1[T]{ctx: ctx, owner: result}
	if err != nil {
		return owned, aiAppMutationError(err)
	}
	return owned, nil
}

func aiAppDependencies(d Deps) authoring.AIAppDeps {
	return authoring.AIAppDeps{Pool: d.Pool, Queries: d.Queries, Audit: d.Audit}
}

func aiAppActor(ctx context.Context, id uuid.UUID) (authoring.Actor, error) {
	authorize, err := auth.APIKeyTransactionAuthorization(ctx, id, mcpScopeWriteAuthoring)
	if err != nil {
		return authoring.Actor{}, err
	}
	u, ok := auth.FromContext(ctx)
	if !ok {
		return authoring.Actor{}, auth.ErrMutationPermissionRevoked
	}
	return authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, nil
}

func aiAppMutationError(err error) error {
	for _, safe := range []error{auth.ErrMutationCredentialExpired, auth.ErrMutationPermissionRevoked, authoring.ErrDocumentNotFound,
		authoring.ErrDocumentHasEvidence, authoring.ErrPrivacyReviewChanging, authoring.ErrPendingPrivacyReview,
		authoring.ErrAIAppDocumentClosed, authoring.ErrAIProposalNotFound, authoring.ErrAIProposalBlockMismatch, authoring.ErrAIBlockNotFound} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return errors.New("AI or negotiation operation failed")
}
