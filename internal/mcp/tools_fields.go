// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/fields"
)

// registerFieldTools exposes the v1.2 fillable-field surface over MCP.
// Senders (or agents) can add fillable fields and PDF signature overlays.
// Block-source signatures remain derived from the block tree.
func registerFieldTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:  "add_document_field",
		Write: true,
		Description: "Add a field overlay to a draft document. Type is one of text|date|checkbox|dropdown|initial, or 'signature' on a pdf-source document (signature requires recipient_id). " +
			"MCP coordinates are integer basis points of the rendered page: 2500 means 25 percent. Omitted width/height default to 1500/400 (15/4 percent); explicit zero dimensions are invalid. recipient_id is optional for fillable fields; empty = any recipient may fill. Dropdown requires options.choices.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid"),
			"recipient_id": stringSchema("optional recipient uuid; empty = any signer"),
			"type":         stringSchema("text|date|checkbox|dropdown|initial|signature; signature is PDF-only and requires recipient_id"),
			"page":         intSchema("1-indexed PDF page", 1, 1000, 1),
			"x_pct":        intSchema("left edge as 0..10000 (basis points of page width)", 0, 10000, 0),
			"y_pct":        intSchema("top edge as 0..10000", 0, 10000, 0),
			"w_pct":        intSchema("width as 0..10000", 0, 10000, 1500),
			"h_pct":        intSchema("height as 0..10000", 0, 10000, 400),
			"required":     stringSchema("'true' or 'false' (default true)"),
			"label":        stringSchema("display label shown above the input"),
			"options": map[string]any{"type": "object", "description": "dropdown configuration; choices must contain the permitted signer values", "properties": map[string]any{
				"choices": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			}},
		}, []string{"document_id", "type"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string          `json:"document_id"`
				RecipientID string          `json:"recipient_id"`
				Type        string          `json:"type"`
				Page        *int            `json:"page"`
				XPct        *int            `json:"x_pct"`
				YPct        *int            `json:"y_pct"`
				WPct        *int            `json:"w_pct"`
				HPct        *int            `json:"h_pct"`
				Required    string          `json:"required"`
				Label       string          `json:"label"`
				Options     json.RawMessage `json:"options"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			docID, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
				return nil, err
			}
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), docID, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			var recipientID *uuid.UUID
			if p.RecipientID != "" {
				rid, err := uuid.Parse(p.RecipientID)
				if err != nil {
					return nil, errors.New("recipient_id must be a uuid")
				}
				recipientID = &rid
			}
			if p.Required != "" && p.Required != "true" && p.Required != "false" {
				return nil, errors.New("required must be 'true' or 'false'")
			}
			required := p.Required != "false"
			page := 1
			if p.Page != nil {
				if *p.Page < 1 || *p.Page > 1000 {
					return nil, &fields.ValidationError{Field: "page", Reason: "must be between 1 and 1000"}
				}
				page = *p.Page
			}
			engine := fields.MutationEngine{Pool: d.Pool, Audit: d.Audit}
			actor := fields.Actor{
				OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "add_document_field",
				IP: clientIP(r), UserAgent: r.UserAgent(),
			}
			row, err := engine.Create(r.Context(), actor, docID, fields.CreateInput{
				RecipientID: recipientID, Type: p.Type, Page: page,
				XPct: optionalFieldBasisPoints(p.XPct, 0), YPct: optionalFieldBasisPoints(p.YPct, 0),
				WPct: optionalFieldBasisPoints(p.WPct, 1500), HPct: optionalFieldBasisPoints(p.HPct, 400),
				Required: required, Label: p.Label, Options: p.Options,
			})
			if err != nil {
				return nil, err
			}
			return fieldRowToMCP(row), nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "list_document_fields",
		Description: "List the fillable fields attached to a document (both signature and non-signature). Use this before sending to confirm every recipient has the required fields assigned.",
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
			docID, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
				return nil, err
			}
			if _, err := d.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, errors.New("document not found")
				}
				return nil, err
			}
			rows, err := d.Queries.ListFieldsByDocument(r.Context(), docID)
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, f := range rows {
				out = append(out, fieldRowToMCP(f))
			}
			return map[string]any{"fields": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "delete_document_field",
		Write:       true,
		Description: "Remove an unfilled field from an editable draft document. Retained signing evidence and open privacy reviews prevent field authoring.",
		InputSchema: schemaObject(map[string]any{
			"field_id": stringSchema("uuid of the field to delete"),
		}, []string{"field_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				FieldID string `json:"field_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.FieldID)
			if err != nil {
				return nil, errors.New("field_id must be a uuid")
			}
			// Confine a doc-scoped agent token: resolve the field's owning doc
			// (org-scoped) and enforce scope before deleting.
			ownerDoc, err := d.Queries.GetFieldOwnerDoc(r.Context(), generated.GetFieldOwnerDocParams{ID: id, OrgID: u.OrgID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, fields.ErrFieldNotFound
			}
			if err != nil {
				return nil, err
			}
			if err := auth.EnforceDocScope(r.Context(), ownerDoc); err != nil {
				return nil, err
			}
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), ownerDoc, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			engine := fields.MutationEngine{Pool: d.Pool, Audit: d.Audit}
			actor := fields.Actor{
				OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "delete_document_field",
				IP: clientIP(r), UserAgent: r.UserAgent(),
			}
			deleted, err := engine.Delete(r.Context(), actor, ownerDoc, id)
			if err != nil {
				return nil, err
			}
			return map[string]any{"deleted": deleted.ID.String()}, nil
		},
	})
}

// MCP uses integer basis points; the shared authoring boundary uses percent.
func optionalFieldBasisPoints(value *int, fallback int) float64 {
	if value == nil {
		return float64(fallback) / 100
	}
	return float64(*value) / 100
}

func fieldNumericPercent(value pgtype.Numeric) float64 {
	f, err := value.Float64Value()
	if err != nil || !f.Valid {
		return 0
	}
	return f.Float64
}

func fieldRowToMCP(f *generated.DocumentField) map[string]any {
	out := map[string]any{
		"id":          f.ID.String(),
		"document_id": f.DocumentID.String(),
		"type":        f.Type,
		"page":        f.Page,
		"x_pct":       fieldNumericPercent(f.XPct),
		"y_pct":       fieldNumericPercent(f.YPct),
		"w_pct":       fieldNumericPercent(f.WPct),
		"h_pct":       fieldNumericPercent(f.HPct),
		"required":    f.Required,
	}
	if f.RecipientID.Valid {
		out["recipient_id"] = uuid.UUID(f.RecipientID.Bytes).String()
	}
	if f.Label.Valid {
		out["label"] = f.Label.String
	}
	if f.Value.Valid {
		out["value"] = f.Value.String
	}
	if f.CompletedAt.Valid {
		out["completed_at"] = f.CompletedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if len(f.OptionsJson) > 0 {
		out["options"] = json.RawMessage(f.OptionsJson)
	}
	return out
}
