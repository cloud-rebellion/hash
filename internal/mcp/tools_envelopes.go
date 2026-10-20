// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blockauthoring"
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
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				Name     string   `json:"name"`
				ChildIDs []string `json:"child_ids"`
			}
			if err := input.WithArgumentsV1(r.Context(), func(raw []byte) error { return MustParseArgs(raw, &p) }); err != nil {
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
			owned, err := commitOwnedEnvelopeV1(r, d, "create_envelope", blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopeCreateV1, Children: ids, Name: p.Name})
			if err != nil {
				return owned, envelopeMutationError(err)
			}
			return newOwnedEnvelopeToolResultV1(envelopeRow(owned.Document), owned), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "promote_to_envelope",
		Write:       true,
		Description: "Mark an existing draft document as an envelope so it can host child documents. The document must be draft + blocks-source + not already a child.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid to promote"),
		}, []string{"document_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				DocumentID string `json:"document_id"`
			}
			if err := input.WithArgumentsV1(r.Context(), func(raw []byte) error { return MustParseArgs(raw, &p) }); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			owned, err := commitOwnedEnvelopeV1(r, d, "promote_to_envelope", blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopePromoteV1, Root: id})
			if err != nil {
				return owned, envelopeMutationError(err)
			}
			return newOwnedEnvelopeToolResultV1(envelopeRow(owned.Document), owned), nil
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
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				EnvelopeID string `json:"envelope_id"`
				ChildID    string `json:"child_id"`
				Position   int32  `json:"position"`
			}
			if err := input.WithArgumentsV1(r.Context(), func(raw []byte) error { return MustParseArgs(raw, &p) }); err != nil {
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
			owned, err := commitOwnedEnvelopeV1(r, d, "attach_to_envelope", blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopeAttachV1, Root: envID, Children: []uuid.UUID{childID}, Position: p.Position})
			if err != nil {
				return owned, envelopeMutationError(err)
			}
			return newOwnedEnvelopeToolResultV1(envelopeRow(owned.Document), owned), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "detach_from_envelope",
		Write:       true,
		Description: "Remove a child document from its envelope. The child becomes standalone again.",
		InputSchema: schemaObject(map[string]any{
			"child_id": stringSchema("child document uuid"),
		}, []string{"child_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				ChildID string `json:"child_id"`
			}
			if err := input.WithArgumentsV1(r.Context(), func(raw []byte) error { return MustParseArgs(raw, &p) }); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.ChildID)
			if err != nil {
				return nil, errors.New("child_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			child, err := d.Queries.GetEnvelopeTopologyChildParentV1(r.Context(), generated.GetEnvelopeTopologyChildParentV1Params{ID: id, OrgID: u.OrgID})
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
			owned, err := commitOwnedEnvelopeV1(r, d, "detach_from_envelope", blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopeDetachV1, Root: envID, Children: []uuid.UUID{id}})
			if err != nil {
				return owned, envelopeMutationError(err)
			}
			return newOwnedEnvelopeToolResultV1(envelopeRow(owned.Document), owned), nil
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
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				EnvelopeID   string   `json:"envelope_id"`
				ChildIDOrder []string `json:"child_id_order"`
			}
			if err := input.WithArgumentsV1(r.Context(), func(raw []byte) error { return MustParseArgs(raw, &p) }); err != nil {
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
			owned, err := commitOwnedEnvelopeV1(r, d, "reorder_envelope_children", blockauthoring.EnvelopeInputV1{Operation: blockauthoring.EnvelopeReorderV1, Root: envID, Children: ids})
			if err != nil {
				return owned, envelopeMutationError(err)
			}
			out := make([]map[string]any, 0, len(owned.Children))
			for _, child := range owned.Children {
				out = append(out, envelopeMetadataRow(child))
			}
			return newOwnedEnvelopeToolResultV1(map[string]any{"children": out, "count": len(out)}, owned), nil
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
			kids, err := d.Envelopes.Q.ListEnvelopeChildMetadataForRead(r.Context(), generated.ListEnvelopeChildMetadataForReadParams{
				ParentEnvelopeID: pgtype.UUID{Bytes: envID, Valid: true}, OrgID: u.OrgID,
			})
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(kids))
			for _, c := range kids {
				out = append(out, envelopeMetadataRow(c))
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
