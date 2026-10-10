// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/send"
)

// registerWorkflowTools mounts the MCP write tools that drive a document
// through its lifecycle. These were deferred from week 2 (Phase 2) and
// land here in week 7 so an agent can author, send, follow up, and close
// out a document end-to-end without ever touching the REST surface.
//
// Every workflow write fires the same audit + webhook fan-out the REST
// handlers do, with `via=mcp` + tool-name in the payload so reviewers can
// filter agent-driven workflow actions.
func registerWorkflowTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "send_document",
		Write:       true,
		Description: "Transition a draft document to sent. Mints a fresh magic link per signer and queues invite emails + a document.sent webhook. Returns one signing URL per recipient.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid (must be in draft state)"),
			"lawful_basis": map[string]any{
				"type":        "string",
				"enum":        []string{"contract"},
				"description": "Controller confirmation that GDPR Article 6(1)(b), contract or requested pre-contractual steps, applies to this document",
			},
		}, []string{"document_id", "lawful_basis"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string `json:"document_id"`
				LawfulBasis string `json:"lawful_basis"`
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
			if err := send.ValidateLawfulBasis(p.LawfulBasis); err != nil {
				return nil, err
			}
			// Route through the lifecycle engine so the agent send path
			// enforces the SAME quota gate, variable freeze, eIDAS guard, and
			// magic-token expiry as the REST surface. The raw UPDATE this
			// replaced left magic_token_expires_at NULL (fail-open).
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), id, mcpScopeWriteWorkflow)
			if err != nil {
				return nil, err
			}
			res, err := d.Send.Send(r.Context(), send.Actor{
				UserID: &u.UserID, OrgID: u.OrgID, Email: u.Email,
				IP: clientIP(r), Via: "mcp", Tool: "send_document",
				LawfulBasis: p.LawfulBasis, Authorize: authorize,
			}, id)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"document_id": id,
				"status":      res.Status,
				"links":       res.Links,
			}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "void_document",
		Write:       true,
		Description: "Move a sent or in-progress document to voided. Cancels the reminder schedule and fires a document.voided webhook. Cannot void a completed document.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"reason":      stringSchema("optional human-readable reason"),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				Reason     string `json:"reason"`
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
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), id, mcpScopeWriteWorkflow)
			if err != nil {
				return nil, err
			}
			if err := d.Send.Void(r.Context(), send.Actor{
				UserID: &u.UserID, OrgID: u.OrgID, Email: u.Email,
				IP: clientIP(r), Via: "mcp", Tool: "void_document",
				Authorize: authorize,
			}, id, p.Reason); err != nil {
				return nil, err
			}
			return map[string]any{"document_id": id, "status": "voided"}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "remind_recipient",
		Write:       true,
		Description: "Re-issue magic links and send reminder emails to recipients still pending on a sent / in-progress document. Resets the auto-reminder schedule to +3 days.",
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
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), id, mcpScopeWriteWorkflow)
			if err != nil {
				return nil, err
			}
			sent, err := d.Send.Remind(r.Context(), send.Actor{
				UserID: &u.UserID, OrgID: u.OrgID, Email: u.Email,
				IP: clientIP(r), Via: "mcp", Tool: "remind_recipient",
				Authorize: authorize,
			}, id, false)
			if err != nil {
				return nil, err
			}
			return map[string]any{"document_id": id, "reminded": sent}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "set_expiry",
		Write:       true,
		Description: "Set or clear expires_at on an editable draft. After sending, the document expires at that frozen time (worker hourly tick). Retained signing evidence and open privacy reviews prevent editing.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"expires_at":  stringSchema("RFC3339 timestamp; pass empty string to clear"),
		}, []string{"document_id", "expires_at"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				ExpiresAt  string `json:"expires_at"`
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
			var expiresArg pgtype.Timestamptz
			if p.ExpiresAt != "" {
				t, perr := time.Parse(time.RFC3339, p.ExpiresAt)
				if perr != nil {
					return nil, errors.New("expires_at must be RFC3339")
				}
				if t.Before(time.Now()) {
					return nil, errors.New("expires_at must be in the future")
				}
				expiresArg = pgtype.Timestamptz{Time: t, Valid: true}
			}
			return mutateDraftDocumentMetadata(r, d, u, id, mcpScopeWriteWorkflow,
				map[string]any{"via": "mcp", "tool": "set_expiry", "expires_at": p.ExpiresAt},
				func(locked *generated.Document) (generated.UpdateDocumentMetadataParams, error) {
					// A timestamp that was valid at admission can expire during a
					// parent/member lock wait. Validate the freshly locked edit too.
					if expiresArg.Valid && !expiresArg.Time.After(time.Now()) {
						return generated.UpdateDocumentMetadataParams{}, errors.New("expires_at must be in the future")
					}
					return generated.UpdateDocumentMetadataParams{ID: id, OrgID: u.OrgID, Name: locked.Name, ExpiresAt: expiresArg, Metadata: locked.Metadata}, nil
				})
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "attach_metadata",
		Write:       true,
		Description: "Merge a key/value pair into an editable draft's metadata JSONB. External systems use this to correlate Hash documents with their own ids. Existing keys are overwritten; retained signing evidence and open privacy reviews prevent editing.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"key":         stringSchema("metadata key"),
			"value":       stringSchema("metadata value (string)"),
		}, []string{"document_id", "key", "value"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				Key        string `json:"key"`
				Value      string `json:"value"`
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
			if p.Key == "" {
				return nil, errors.New("key required")
			}
			return mutateDraftDocumentMetadata(r, d, u, id, mcpScopeWriteAuthoring,
				map[string]any{"via": "mcp", "tool": "attach_metadata", "key": p.Key, "value": p.Value},
				func(locked *generated.Document) (generated.UpdateDocumentMetadataParams, error) {
					meta := map[string]any{}
					if len(locked.Metadata) > 0 {
						if err := json.Unmarshal(locked.Metadata, &meta); err != nil {
							return generated.UpdateDocumentMetadataParams{}, fmt.Errorf("stored metadata invalid: %w", err)
						}
					}
					if meta == nil {
						return generated.UpdateDocumentMetadataParams{}, errors.New("stored metadata must be an object")
					}
					meta[p.Key] = p.Value
					raw, err := json.Marshal(meta)
					if err != nil {
						return generated.UpdateDocumentMetadataParams{}, err
					}
					return generated.UpdateDocumentMetadataParams{ID: id, OrgID: u.OrgID, Name: locked.Name, ExpiresAt: locked.ExpiresAt, Metadata: raw}, nil
				})
		},
	})
}

// Both metadata tools retain the original admitted key, the live sender/owner,
// and draft/evidence/privacy locks through mutation and audit. No second token
// use is claimed. Publication follows the final receipt check and commit.
func mutateDraftDocumentMetadata(r *http.Request, d Deps, u auth.SessionUser, id uuid.UUID, scope string, payload map[string]any,
	input func(*generated.Document) (generated.UpdateDocumentMetadataParams, error),
) (*generated.Document, error) {
	if d.Pool == nil || d.Queries == nil || d.Audit == nil {
		return nil, errors.New("atomic metadata dependencies unavailable")
	}
	authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), id, scope)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
	defer cancel()
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockDraft(ctx, tx, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
	if err != nil {
		return nil, err
	}
	params, err := input(guard.Document)
	if err != nil {
		return nil, err
	}
	doc, err := d.Queries.WithTx(tx).UpdateDocumentMetadata(ctx, params)
	if err != nil {
		return nil, err
	}
	actorID := guard.UserID()
	pending, err := d.Audit.LogTx(ctx, tx, audit.Entry{
		OrgID: u.OrgID, ActorUserID: &actorID, DocumentID: &id, Kind: audit.KindDocumentUpdated, Payload: payload,
	})
	if err != nil {
		return nil, err
	}
	if err := guard.Recheck(ctx); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	d.Audit.Publish(pending)
	return doc, nil
}

// senderFromDoc loads the sender's identity for the email templates. Best
// effort; falls back to the document's sender_id as a string when the user
// row can't be loaded (shouldn't happen, but the email path is non-fatal).
func senderFromDoc(ctx context.Context, d Deps, doc *generated.Document) string {
	user, err := d.Queries.GetUser(ctx, doc.SenderID)
	if err != nil || user == nil {
		return doc.SenderID.String()
	}
	return user.Email
}

// guards: keep the imports flexible for future evolution.
var (
	_ = path.Join
	_ = sha256.Sum256
)
