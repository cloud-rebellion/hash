// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
)

// registerEnvelopeTools mounts the Phase 8.6 envelope surface for agents.
// PandaDoc-style: an envelope is a document that holds other documents;
// one signature ceremony covers every child, the audit cert manifest
// binds them together cryptographically.
func registerEnvelopeTools(s *Server, d Deps) {
	if d.Envelopes == nil {
		return
	}

	s.RegisterTool(ToolDef{
		Name:        "create_envelope",
		Write:       true,
		Description: "Create a new envelope from existing draft documents. A fresh empty envelope shell is created and all child_ids attach in the supplied order. Returns the envelope document.",
		InputSchema: schemaObject(map[string]any{
			"name": stringSchema("envelope title shown on the cert + signer page"),
			"child_ids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Existing draft document UUIDs to bundle, in the order signers should see them.",
			},
		}, []string{"name", "child_ids"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				Name     string   `json:"name"`
				ChildIDs []string `json:"child_ids"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			if p.Name == "" {
				return nil, errors.New("name required")
			}
			if len(p.ChildIDs) == 0 {
				return nil, errors.New("at least one child_id required")
			}
			ids := make([]uuid.UUID, 0, len(p.ChildIDs))
			for _, raw := range p.ChildIDs {
				id, err := uuid.Parse(raw)
				if err != nil {
					return nil, errors.New("child_ids must be uuids")
				}
				ids = append(ids, id)
			}
			if err := validateEnvelopeIDs(ids); err != nil {
				return nil, err
			}
			envDoc, err := commitEnvelopeMutation(r.Context(), d, uuid.Nil, ids,
				func(ctx context.Context, q *generated.Queries, _ map[uuid.UUID]*generated.Document) (*generated.Document, error) {
					if err := d.Billing.LockDocumentQuotaMutation(ctx, q, u.OrgID); err != nil {
						return nil, err
					}
					env, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
						OrgID: u.OrgID, Name: p.Name, BlocksJson: []byte(`{"version":1,"blocks":[]}`), VariablesJson: []byte(`{}`), SenderID: u.UserID,
					})
					if err != nil {
						return nil, err
					}
					if err := d.Billing.EnforceDocumentQuotaMutation(ctx, q, u.OrgID); err != nil {
						return nil, err
					}
					engine := envelopes.New(q)
					envDoc, err := engine.PromoteToEnvelope(ctx, env.ID, u.OrgID)
					if err != nil {
						return nil, envelopeTargetError(err)
					}
					for i, cid := range ids {
						if _, err := engine.Attach(ctx, envDoc.ID, cid, u.OrgID, int32(i+1)); err != nil {
							return nil, envelopeTargetError(err)
						}
					}
					return envDoc, nil
				},
				func(row *generated.Document) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &row.ID, Kind: audit.KindDocumentUpdated,
						Payload: map[string]any{"via": "mcp", "tool": "create_envelope", "child_count": len(ids)},
					}
				},
			)
			if err != nil {
				return nil, envelopeMutationError(err)
			}
			return envelopeRow(envDoc), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "promote_to_envelope",
		Write:       true,
		Description: "Mark an existing draft document as an envelope so it can host child documents. The document must be draft + blocks-source + not already a child.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid to promote"),
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
			row, err := commitEnvelopeMutation(r.Context(), d, id, nil,
				func(ctx context.Context, q *generated.Queries, _ map[uuid.UUID]*generated.Document) (*generated.Document, error) {
					row, err := envelopes.New(q).PromoteToEnvelope(ctx, id, u.OrgID)
					return row, envelopeTargetError(err)
				},
				func(*generated.Document) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &id, Kind: audit.KindDocumentUpdated,
						Payload: map[string]any{"via": "mcp", "tool": "promote_to_envelope"},
					}
				},
			)
			if err != nil {
				return nil, envelopeMutationError(err)
			}
			return envelopeRow(row), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "attach_to_envelope",
		Write:       true,
		Description: "Attach a child document to an envelope at the given position (1-indexed; <=0 appends to end). The envelope must already be promoted. Children inherit the envelope's status after send.",
		InputSchema: schemaObject(map[string]any{
			"envelope_id": stringSchema("envelope uuid"),
			"child_id":    stringSchema("child document uuid"),
			"position":    intSchema("1-indexed position; omit to append", 0, 1000, 0),
		}, []string{"envelope_id", "child_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				EnvelopeID string `json:"envelope_id"`
				ChildID    string `json:"child_id"`
				Position   int32  `json:"position"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			envID, err := uuid.Parse(p.EnvelopeID)
			if err != nil {
				return nil, errors.New("envelope_id must be a uuid")
			}
			childID, err := uuid.Parse(p.ChildID)
			if err != nil {
				return nil, errors.New("child_id must be a uuid")
			}
			// A doc-scoped agent token must not attach/detach documents outside
			// its sandbox: both the envelope and the child are documents.
			if err := auth.EnforceDocScope(r.Context(), envID); err != nil {
				return nil, err
			}
			if err := auth.EnforceDocScope(r.Context(), childID); err != nil {
				return nil, err
			}
			row, err := commitEnvelopeMutation(r.Context(), d, envID, []uuid.UUID{childID},
				func(ctx context.Context, q *generated.Queries, _ map[uuid.UUID]*generated.Document) (*generated.Document, error) {
					row, err := envelopes.New(q).Attach(ctx, envID, childID, u.OrgID, p.Position)
					return row, envelopeTargetError(err)
				},
				func(*generated.Document) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &envID, Kind: audit.KindDocumentUpdated,
						Payload: map[string]any{"via": "mcp", "tool": "attach_to_envelope", "child_id": childID.String()},
					}
				},
			)
			if err != nil {
				return nil, envelopeMutationError(err)
			}
			return envelopeRow(row), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "detach_from_envelope",
		Write:       true,
		Description: "Remove a child document from its envelope. The child becomes standalone again.",
		InputSchema: schemaObject(map[string]any{
			"child_id": stringSchema("child document uuid"),
		}, []string{"child_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				ChildID string `json:"child_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.ChildID)
			if err != nil {
				return nil, errors.New("child_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			child, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, authoring.ErrDocumentNotFound
			}
			if err != nil {
				return nil, envelopeMutationError(err)
			}
			if !child.ParentEnvelopeID.Valid {
				return nil, errEnvelopeTargetIneligible
			}
			envID := uuid.UUID(child.ParentEnvelopeID.Bytes)
			// Detaching changes the parent's instrument membership too. A token
			// bound only to a child cannot authorize its sibling envelope.
			if err := auth.EnforceDocScope(r.Context(), envID); err != nil {
				return nil, err
			}
			row, err := commitEnvelopeMutation(r.Context(), d, envID, []uuid.UUID{id},
				func(ctx context.Context, q *generated.Queries, docs map[uuid.UUID]*generated.Document) (*generated.Document, error) {
					current := docs[id]
					if current == nil || !current.ParentEnvelopeID.Valid || uuid.UUID(current.ParentEnvelopeID.Bytes) != envID {
						return nil, errEnvelopeTargetIneligible
					}
					row, err := envelopes.New(q).Detach(ctx, id, u.OrgID)
					return row, envelopeTargetError(err)
				},
				func(*generated.Document) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &envID, Kind: audit.KindDocumentUpdated,
						Payload: map[string]any{"via": "mcp", "tool": "detach_from_envelope", "child_id": id.String()},
					}
				},
			)
			if err != nil {
				return nil, envelopeMutationError(err)
			}
			return envelopeRow(row), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "reorder_envelope_children",
		Write:       true,
		Description: "Set the order of an envelope's children. child_id_order is the desired final order; missing children keep their existing position.",
		InputSchema: schemaObject(map[string]any{
			"envelope_id": stringSchema("envelope uuid"),
			"child_id_order": map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "string"},
			},
		}, []string{"envelope_id", "child_id_order"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				EnvelopeID   string   `json:"envelope_id"`
				ChildIDOrder []string `json:"child_id_order"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			envID, err := uuid.Parse(p.EnvelopeID)
			if err != nil {
				return nil, errors.New("envelope_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), envID); err != nil {
				return nil, err
			}
			ids := make([]uuid.UUID, 0, len(p.ChildIDOrder))
			for _, raw := range p.ChildIDOrder {
				id, err := uuid.Parse(raw)
				if err != nil {
					return nil, errors.New("child_id_order must be uuids")
				}
				ids = append(ids, id)
			}
			if err := validateEnvelopeIDs(ids); err != nil {
				return nil, err
			}
			kids, err := commitEnvelopeMutation(r.Context(), d, envID, ids,
				func(ctx context.Context, q *generated.Queries, docs map[uuid.UUID]*generated.Document) ([]*generated.Document, error) {
					if !docs[envID].IsEnvelope || docs[envID].ParentEnvelopeID.Valid {
						return nil, errEnvelopeTargetIneligible
					}
					for _, id := range ids {
						child := docs[id]
						if child == nil || !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != envID {
							return nil, errEnvelopeTargetIneligible
						}
					}
					engine := envelopes.New(q)
					if err := engine.Reorder(ctx, envID, u.OrgID, ids); err != nil {
						return nil, envelopeTargetError(err)
					}
					return engine.Children(ctx, envID, u.OrgID)
				},
				func([]*generated.Document) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID, DocumentID: &envID, Kind: audit.KindDocumentUpdated,
						Payload: map[string]any{"via": "mcp", "tool": "reorder_envelope_children", "count": len(ids)},
					}
				},
			)
			if err != nil {
				return nil, envelopeMutationError(err)
			}
			out := make([]map[string]any, 0, len(kids))
			for _, c := range kids {
				out = append(out, envelopeRow(c))
			}
			return map[string]any{"children": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "list_envelope_children",
		Description: "Return an envelope's children in position order with their status + final PDF metadata.",
		InputSchema: schemaObject(map[string]any{
			"envelope_id": stringSchema("envelope uuid"),
		}, []string{"envelope_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				EnvelopeID string `json:"envelope_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			envID, err := uuid.Parse(p.EnvelopeID)
			if err != nil {
				return nil, errors.New("envelope_id must be a uuid")
			}
			// Confine a per-document agent token to its bound envelope (the sibling
			// write tools already do this; these two reads skipped it and leaked
			// child metadata + final-PDF hashes for any envelope in the org).
			if err := auth.EnforceDocScope(r.Context(), envID); err != nil {
				return nil, err
			}
			kids, err := d.Envelopes.Children(r.Context(), envID, u.OrgID)
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(kids))
			for _, c := range kids {
				out = append(out, envelopeRow(c))
			}
			return map[string]any{"children": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "get_envelope_manifest",
		Description: "Return the audit-cert manifest for an envelope: ordered children with deterministic SHA-256 commitments to each frozen content snapshot, plus a canonical manifest hash. Same shape that is rendered inside the signed cert; final-PDF self-hashes are deliberately not claimed.",
		InputSchema: schemaObject(map[string]any{
			"envelope_id": stringSchema("envelope uuid"),
		}, []string{"envelope_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				EnvelopeID string `json:"envelope_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			envID, err := uuid.Parse(p.EnvelopeID)
			if err != nil {
				return nil, errors.New("envelope_id must be a uuid")
			}
			// Confine a per-document agent token to its bound envelope before
			// returning the frozen-child commitments + manifest hash.
			if err := auth.EnforceDocScope(r.Context(), envID); err != nil {
				return nil, err
			}
			env, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: envID, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("envelope not found")
			}
			if err != nil {
				return nil, err
			}
			if !env.IsEnvelope {
				return nil, errors.New("document is not an envelope")
			}
			m, err := d.Envelopes.BuildManifest(r.Context(), env)
			if err != nil {
				return nil, err
			}
			return m, nil
		},
	})
}

// envelopeRow shapes a document for MCP responses. Keeps the envelope-
// aware fields explicit so agents can spot is_envelope + parent linkage.
func envelopeRow(d *generated.Document) map[string]any {
	out := map[string]any{
		"id":          d.ID.String(),
		"name":        d.Name,
		"status":      d.Status,
		"source_kind": d.SourceKind,
		"is_envelope": d.IsEnvelope,
		"created_at":  d.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if d.ParentEnvelopeID.Valid {
		out["parent_envelope_id"] = uuid.UUID(d.ParentEnvelopeID.Bytes).String()
	}
	if d.EnvelopePosition.Valid {
		out["envelope_position"] = d.EnvelopePosition.Int32
	}
	// Final-PDF metadata so an agent can tell in one call whether a child is
	// finished + ready to download (matches the list_envelope_children description).
	if d.FinalPdfKey.Valid {
		out["final_pdf_ready"] = true
		out["final_pdf_sha256"] = fmt.Sprintf("%x", d.FinalPdfSha)
	}
	if d.CompletedAt.Valid {
		out["completed_at"] = d.CompletedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return out
}

// guard against the import dropping if the file briefly looks empty.
var _ = envelopes.Engine{}

var errEnvelopeTargetIneligible = errors.New("document not eligible for envelope mutation")

func validateEnvelopeIDs(ids []uuid.UUID) error {
	seen := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		if id == uuid.Nil || seen[id] {
			return errors.New("child IDs must be distinct nonzero UUIDs")
		}
		seen[id] = true
	}
	return nil
}

// Translate only the target statement's no-row result. An audit no-row result
// must remain a failed transaction, never become a missing document response.
func envelopeTargetError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return errEnvelopeTargetIneligible
	}
	return err
}

// Envelope membership is authoring of the whole instrument. Lock its root
// before its children, as send does, then validate every affected draft's
// evidence/privacy state. The original key and member remain locked until the
// audit and last authorization check commit together.
func commitEnvelopeMutation[T any](parent context.Context, d Deps, root uuid.UUID, requested []uuid.UUID,
	mutate func(context.Context, *generated.Queries, map[uuid.UUID]*generated.Document) (T, error), event func(T) audit.Entry,
) (T, error) {
	var zero T
	if d.Pool == nil || d.Audit == nil {
		return zero, errors.New("atomic audit dependencies unavailable")
	}
	authorize, err := auth.APIKeyTransactionAuthorization(parent, root, mcpScopeWriteAuthoring)
	if err != nil {
		return zero, err
	}
	u, ok := auth.FromContext(parent)
	if !ok {
		return zero, auth.ErrMutationPermissionRevoked
	}
	ctx, cancel := context.WithTimeout(parent, authoring.MutationTimeout)
	defer cancel()
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return zero, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := generated.New(tx)
	actor := authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}
	docs := make(map[uuid.UUID]*generated.Document)
	guards := []*authoring.DraftGuard{}
	ids := append([]uuid.UUID(nil), requested...)
	if root != uuid.Nil {
		guard, err := authoring.LockDraft(ctx, tx, actor, root)
		if err != nil {
			return zero, err
		}
		docs[root], guards = guard.Document, append(guards, guard)
		if guard.Document.IsEnvelope {
			kids, err := envelopes.New(q).Children(ctx, root, u.OrgID)
			if err != nil {
				return zero, err
			}
			for _, child := range kids {
				ids = append(ids, child.ID)
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	for _, id := range ids {
		if _, locked := docs[id]; locked {
			continue
		}
		guard, err := authoring.LockDraft(ctx, tx, actor, id)
		if err != nil {
			return zero, err
		}
		docs[id], guards = guard.Document, append(guards, guard)
	}
	var member *authoring.MemberGuard
	if root == uuid.Nil {
		member, err = authoring.LockAuthor(ctx, tx, actor)
		if err != nil {
			return zero, err
		}
	}
	value, err := mutate(ctx, q, docs)
	if err != nil {
		return zero, err
	}
	entry := event(value)
	if entry.OrgID != u.OrgID || entry.ActorUserID == nil || *entry.ActorUserID != u.UserID {
		return zero, auth.ErrMutationPermissionRevoked
	}
	pending, err := d.Audit.LogTx(ctx, tx, entry)
	if err != nil {
		return zero, err
	}
	for _, guard := range guards {
		if err := guard.Recheck(ctx); err != nil {
			return zero, err
		}
	}
	if member != nil {
		if err := member.Recheck(ctx); err != nil {
			return zero, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return zero, err
	}
	d.Audit.Publish(pending)
	return value, nil
}

func envelopeMutationError(err error) error {
	for _, safe := range []error{auth.ErrMutationCredentialExpired, auth.ErrMutationPermissionRevoked,
		authoring.ErrDocumentNotFound, authoring.ErrDocumentNotDraft, authoring.ErrDocumentHasEvidence,
		authoring.ErrPrivacyReviewChanging, authoring.ErrPendingPrivacyReview, errEnvelopeTargetIneligible} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return errors.New("envelope mutation failed")
}
