// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/docintake"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/pdftemplateauthoring"
	"github.com/bright-interaction/hash/internal/recipientauthoring"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/requestmeta"
	"github.com/bright-interaction/hash/internal/versions"
)

var (
	errMCPRecipientDocumentNotFound = recipients.ErrDocumentNotFound
	errMCPRecipientNotFound         = recipients.ErrRecipientNotFound
	errMCPRecipientNotDraft         = recipients.ErrDocumentNotDraft
)

// pgtypeUUID lifts a uuid.UUID into pgx's nullable form.
func pgtypeUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// registerAuthoringTools mounts the agent-facing write tools. Every tool
// emits an audit event with `via=mcp` and the tool name so we can tell
// agent-authored vs human-authored documents apart.
func registerAuthoringTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "create_document",
		Write:       true,
		Description: "Create a new draft document. Use source_kind=blocks for the agent authoring path; source_kind=pdf with template_id for stamping flows.",
		InputSchema: schemaObject(map[string]any{
			"name":                      stringSchema("human-readable document name"),
			"source_kind":               map[string]any{"type": "string", "enum": []string{"blocks", "pdf"}, "description": "blocks (agent) or pdf (uploaded template)"},
			"template_id":               stringSchema("optional template uuid to instantiate from"),
			"expected_template_version": map[string]any{"type": "integer", "minimum": 1, "description": "reviewed current PDF layout template version"},
			"parties":                   map[string]any{"type": "array", "maxItems": pdflayout.MaxParties, "items": schemaObject(map[string]any{"role": stringSchema("declared party role"), "name": stringSchema("fresh party name"), "email": stringSchema("fresh party email"), "locale": stringSchema("ceremony language")}, []string{"role", "name", "email"})},
			"variables_json":            map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "string variable values keyed by name (eg. {\"recipient.name\":\"Tom\"})"},
			"blocks_json":               map[string]any{"type": "object", "description": "initial block tree {version:1,blocks:[...]} when source_kind=blocks"},
		}, []string{"name", "source_kind"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				Name                    string              `json:"name"`
				SourceKind              string              `json:"source_kind"`
				TemplateID              string              `json:"template_id"`
				BlocksJSON              json.RawMessage     `json:"blocks_json"`
				VariablesJSON           json.RawMessage     `json:"variables_json"`
				ExpectedTemplateVersion *int32              `json:"expected_template_version"`
				Parties                 []pdflayout.Binding `json:"parties"`
			}
			if err := input.WithArgumentsV1(r.Context(), func(raw []byte) error { return MustParseArgs(raw, &p) }); err != nil {
				return nil, err
			}
			if p.Name == "" {
				return nil, errors.New("name required")
			}
			if p.SourceKind != "blocks" && p.SourceKind != "pdf" {
				return nil, errors.New("source_kind must be 'blocks' or 'pdf'")
			}
			if p.SourceKind != "pdf" && (len(p.Parties) > 0 || p.ExpectedTemplateVersion != nil) {
				return nil, errors.New("party bindings require a PDF template")
			}

			var tmplID pgtype.UUID
			if p.TemplateID != "" {
				id, err := uuid.Parse(p.TemplateID)
				if err != nil {
					return nil, errors.New("template_id must be a uuid")
				}
				tmplID = pgtypeUUID(id)
			}

			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), uuid.Nil, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			if d.Pool == nil || d.Audit == nil {
				return nil, errors.New("document creation dependencies unavailable")
			}
			if p.SourceKind == "blocks" {
				return blockauthoring.CreateV1(r.Context(), blockauthoring.DependenciesV1{Sessions: d.PDFCreationSessions, Billing: d.Billing, Audit: d.Audit, SnapshotCreation: d.Versions != nil},
					blockauthoring.ActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "create_document"}, blockauthoring.CreateInputV1{Name: p.Name, TemplateID: tmplID, BlocksJSON: p.BlocksJSON, VariablesJSON: p.VariablesJSON})
			}
			return pdftemplateauthoring.CreateV1(r.Context(), pdftemplateauthoring.CreateDependenciesV1{Sessions: d.PDFCreationSessions, Billing: d.Billing, Audit: d.Audit},
				pdftemplateauthoring.CreateActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "create_document"}, pdftemplateauthoring.CreateInputV1{TemplateID: tmplID, Source: pdfadmission.PDFTemplateDocumentInputV1{Name: p.Name, TemplateText: p.TemplateID, Variables: p.VariablesJSON, ExpectedTemplateVersion: p.ExpectedTemplateVersion, Parties: p.Parties}})
		},
	})

	s.RegisterTool(ToolDef{
		Name:  "create_pdf_document",
		Write: true,
		Description: "Create a signable pdf-source document in ONE step from a designed proposal, skipping the template detour. " +
			"Supply EITHER pdf_base64 (a base64-encoded PDF) OR html (a designed HTML page rendered to PDF with its own CSS/@page preserved). " +
			"Returns a draft pdf-source document; then add_recipient + add_document_field (type=signature) + send_document.",
		InputSchema: schemaObject(map[string]any{
			"name":               stringSchema("human-readable document name"),
			"pdf_base64":         stringSchema("base64-encoded PDF bytes (mutually exclusive with html)"),
			"html":               stringSchema("designed HTML to render to PDF (mutually exclusive with pdf_base64)"),
			"landscape":          map[string]any{"type": "boolean", "default": false, "description": "landscape fallback when the HTML sets no @page size"},
			"requires_signature": map[string]any{"type": "boolean", "default": true, "description": "false = acknowledgement mode (recipients view + accept, no signature)"},
		}, []string{"name"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			release, err := importguard.Shared.Acquire(u.OrgID)
			if err != nil {
				return nil, err
			}
			defer release()

			var p struct {
				Name              string `json:"name"`
				PDFBase64         string `json:"pdf_base64"`
				HTML              string `json:"html"`
				Landscape         bool   `json:"landscape"`
				RequiresSignature *bool  `json:"requires_signature"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			if p.Name == "" {
				return nil, errors.New("name required")
			}
			if (p.PDFBase64 == "") == (p.HTML == "") {
				return nil, errors.New("supply exactly one of pdf_base64 or html")
			}
			var data []byte
			if p.PDFBase64 != "" {
				raw, derr := base64.StdEncoding.DecodeString(p.PDFBase64)
				if derr != nil {
					return nil, errors.New("pdf_base64 is not valid base64")
				}
				data = raw
			} else {
				if d.PDF == nil {
					return nil, errors.New("pdf renderer unavailable")
				}
				opts := render.PDFOptions{PreferCSSPageSize: true, WaitDelay: "1000ms"}
				if p.Landscape {
					opts.PaperWidth, opts.PaperHeight = 11.69, 8.27
				}
				if err := render.ValidateDesignedHTMLSize(p.HTML); err != nil {
					return nil, err
				}
				if err := malwarescan.ScanActive(r.Context(), []byte(p.HTML)); err != nil {
					return nil, err
				}
				safe, serr := render.SanitizeForRenderBoundedV1(p.HTML)
				if serr != nil {
					return nil, serr
				}
				rendered, rerr := d.PDF.HTMLToPDF(r.Context(), safe, opts)
				if rerr != nil {
					return nil, fmt.Errorf("render html to pdf: %w", rerr)
				}
				data = rendered
			}
			if d.Pool == nil || d.Audit == nil {
				return nil, errors.New("atomic audit dependencies unavailable")
			}
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), uuid.Nil, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(r.Context(), authoring.MutationTimeout)
			defer cancel()
			r = r.WithContext(ctx)
			result, err := docintake.CreateOwnedPDFSourceDocumentV1(ctx, docintake.OwnedPDFDependenciesV1{Sessions: d.PDFCreationSessions, Billing: d.Billing, Audit: d.Audit, Store: d.Storage}, docintake.OwnedPDFActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "create_pdf_document"}, p.Name, data, p.RequiresSignature)
			// The central MCP transport closes this concrete owner after both
			// success and error serialization; returning from SQL is not last use.
			return result, err
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "set_document_blocks",
		Write:       true,
		Description: "Replace the entire block tree of a draft document. Validates against the canonical schema.",
		InputSchema: schemaObject(map[string]any{
			"document_id":         stringSchema("document uuid"),
			"expected_updated_at": stringSchema("updated_at from the observed document; stale replacements are rejected"),
			"blocks_json":         map[string]any{"type": "object", "description": "{version:1, blocks:[...]}"},
		}, []string{"expected_updated_at", "document_id", "blocks_json"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				ExpectedUpdatedAt string          `json:"expected_updated_at"`
				DocumentID        string          `json:"document_id"`
				BlocksJSON        json.RawMessage `json:"blocks_json"`
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
			tree, err := input.ParseTreeV1(r.Context(), p.BlocksJSON)
			if err != nil {
				return nil, fmt.Errorf("invalid blocks_json: %w", err)
			}
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "set_document_blocks", func(current *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
				*current = *tree
				return nil
			}, p.ExpectedUpdatedAt)
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "import_html",
		Write:       true,
		Description: "Replace a draft document's block tree by parsing an HTML fragment into canonical blocks.",
		InputSchema: schemaObject(map[string]any{
			"document_id":         stringSchema("document uuid"),
			"expected_updated_at": stringSchema("updated_at from the observed document; stale replacements are rejected"),
			"html":                stringSchema("HTML fragment to parse into blocks"),
		}, []string{"expected_updated_at", "document_id", "html"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			release, err := importguard.Shared.Acquire(u.OrgID)
			if err != nil {
				return nil, err
			}
			defer release()
			var p struct {
				ExpectedUpdatedAt string `json:"expected_updated_at"`
				DocumentID        string `json:"document_id"`
				HTML              string `json:"html"`
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
			if err := malwarescan.ScanActive(r.Context(), []byte(p.HTML)); err != nil {
				return nil, err
			}
			tree, err := input.ParseMCPHTMLImportV1(r.Context(), p.HTML)
			if err != nil {
				return nil, err
			}
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaImport, "import_html", func(current *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
				*current = *tree
				return nil
			}, p.ExpectedUpdatedAt)
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "import_markdown",
		Write:       true,
		Description: "Replace a draft document's block tree by parsing a markdown body into canonical blocks.",
		InputSchema: schemaObject(map[string]any{
			"document_id":         stringSchema("document uuid"),
			"expected_updated_at": stringSchema("updated_at from the observed document; stale replacements are rejected"),
			"markdown":            stringSchema("markdown source"),
		}, []string{"expected_updated_at", "document_id", "markdown"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			release, err := importguard.Shared.Acquire(u.OrgID)
			if err != nil {
				return nil, err
			}
			defer release()
			var p struct {
				ExpectedUpdatedAt string `json:"expected_updated_at"`
				DocumentID        string `json:"document_id"`
				Markdown          string `json:"markdown"`
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
			if err := malwarescan.ScanActive(r.Context(), []byte(p.Markdown)); err != nil {
				return nil, err
			}
			tree, err := input.ParseMCPMarkdownImportV1(r.Context(), p.Markdown)
			if err != nil {
				return nil, err
			}
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaImport, "import_markdown", func(current *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
				*current = *tree
				return nil
			}, p.ExpectedUpdatedAt)
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "append_block",
		Write:       true,
		Description: "Append a block to the end of a draft document's block tree.",
		InputSchema: schemaObject(map[string]any{
			"expected_updated_at": stringSchema("updated_at from the observed document"),
			"document_id":         stringSchema("document uuid"),
			"block":               map[string]any{"type": "object", "description": "canonical block; see hash://schema/blocks"},
		}, []string{"expected_updated_at", "document_id", "block"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				ExpectedUpdatedAt string          `json:"expected_updated_at"`
				DocumentID        string          `json:"document_id"`
				Block             json.RawMessage `json:"block"`
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
			var blk blocks.Block
			if err := json.Unmarshal(p.Block, &blk); err != nil {
				return nil, fmt.Errorf("invalid block: %w", err)
			}
			doc, err := mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "append_block",
				func(t *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
					t.Blocks = append(t.Blocks, blk)
					return blocks.ValidateForSendV1(t, admission)
				}, p.ExpectedUpdatedAt)
			return doc, err
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "update_block",
		Write:       true,
		Description: "Replace a top-level block by id on a draft document. The replacement keeps the requested block_id.",
		InputSchema: schemaObject(map[string]any{
			"document_id":         stringSchema("document uuid"),
			"expected_updated_at": stringSchema("updated_at from the observed document"),
			"block_id":            stringSchema("id of the top-level block to replace"),
			"block":               map[string]any{"type": "object", "description": "replacement canonical block; see hash://schema/blocks"},
		}, []string{"document_id", "block_id", "block", "expected_updated_at"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				ExpectedUpdatedAt string          `json:"expected_updated_at"`
				DocumentID        string          `json:"document_id"`
				BlockID           string          `json:"block_id"`
				Block             json.RawMessage `json:"block"`
			}
			if err := input.WithArgumentsV1(r.Context(), func(raw []byte) error { return MustParseArgs(raw, &p) }); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if p.BlockID == "" {
				return nil, errors.New("block_id required")
			}
			if err := auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			var replacement blocks.Block
			if err := json.Unmarshal(p.Block, &replacement); err != nil {
				return nil, fmt.Errorf("invalid block: %w", err)
			}
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "update_block",
				func(t *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
					return updateTopLevelBlockWithAdmissionV1(t, p.BlockID, replacement, admission)
				}, p.ExpectedUpdatedAt)
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "delete_block",
		Write:       true,
		Description: "Remove a block by id from a draft document.",
		InputSchema: schemaObject(map[string]any{
			"expected_updated_at": stringSchema("updated_at from the observed document"),
			"document_id":         stringSchema("document uuid"),
			"block_id":            stringSchema("id of the block to remove"),
		}, []string{"expected_updated_at", "document_id", "block_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				ExpectedUpdatedAt string `json:"expected_updated_at"`
				DocumentID        string `json:"document_id"`
				BlockID           string `json:"block_id"`
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
			doc, err := mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "delete_block",
				func(t *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
					filtered := make([]blocks.Block, 0, len(t.Blocks))
					removed := false
					for _, b := range t.Blocks {
						if b.ID == p.BlockID {
							removed = true
							continue
						}
						filtered = append(filtered, b)
					}
					if !removed {
						return errors.New("block_id not found at top level")
					}
					t.Blocks = filtered
					return nil
				}, p.ExpectedUpdatedAt)
			return doc, err
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "reorder_blocks",
		Write:       true,
		Description: "Rearrange the top-level blocks of a draft document. block_ids must be a permutation of the existing ids.",
		InputSchema: schemaObject(map[string]any{
			"expected_updated_at": stringSchema("updated_at from the observed document"),
			"document_id":         stringSchema("document uuid"),
			"block_ids":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, []string{"expected_updated_at", "document_id", "block_ids"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				ExpectedUpdatedAt string   `json:"expected_updated_at"`
				DocumentID        string   `json:"document_id"`
				BlockIDs          []string `json:"block_ids"`
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
			doc, err := mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "reorder_blocks",
				func(t *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
					byID := map[string]blocks.Block{}
					for _, b := range t.Blocks {
						byID[b.ID] = b
					}
					if len(p.BlockIDs) != len(t.Blocks) {
						return errors.New("block_ids length must equal top-level block count")
					}
					reordered := make([]blocks.Block, 0, len(p.BlockIDs))
					seen := map[string]bool{}
					for _, bid := range p.BlockIDs {
						b, ok := byID[bid]
						if !ok || seen[bid] {
							return fmt.Errorf("unknown or duplicate block_id: %s", bid)
						}
						seen[bid] = true
						reordered = append(reordered, b)
					}
					t.Blocks = reordered
					return nil
				}, p.ExpectedUpdatedAt)
			return doc, err
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "add_signature_field",
		Write:       true,
		Description: "Convenience: append a signature_field block bound to a recipient role.",
		InputSchema: schemaObject(map[string]any{
			"expected_updated_at": stringSchema("updated_at from the observed document"),
			"document_id":         stringSchema("document uuid"),
			"recipient_role":      stringSchema("role label, must match a recipient on the document (eg 'client', 'provider')"),
			"label":               stringSchema("optional human label, eg 'Client signature'"),
			"required":            map[string]any{"type": "boolean", "const": true, "default": true, "description": "signature fields are always required"},
		}, []string{"expected_updated_at", "document_id", "recipient_role"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				ExpectedUpdatedAt string `json:"expected_updated_at"`
				DocumentID        string `json:"document_id"`
				RecipientRole     string `json:"recipient_role"`
				Label             string `json:"label"`
				Required          *bool  `json:"required"`
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
			required := true
			if p.Required != nil {
				required = *p.Required
			}
			block := blocks.Block{
				Type: blocks.TypeSignatureField,
				Attrs: map[string]any{
					"recipient_role": p.RecipientRole,
					"label":          p.Label,
					"required":       required,
				},
			}
			return mutateDocumentTree(r, d, u.OrgID, u.UserID, id, versions.ViaMCP, "add_signature_field",
				func(t *blocks.Tree, admission blocks.ConditionalSendAdmissionV1) error {
					t.Blocks = append(t.Blocks, block)
					return blocks.ValidateForSendV1(t, admission)
				}, p.ExpectedUpdatedAt)
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "set_variables",
		Write:       true,
		Description: "Replace a draft document's variable values.",
		InputSchema: schemaObject(map[string]any{
			"document_id":         stringSchema("document uuid"),
			"expected_updated_at": stringSchema("updated_at from the observed document"),
			"variables":           map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "name → string value map"},
		}, []string{"document_id", "variables", "expected_updated_at"}),
		Handler: func(r *http.Request, args json.RawMessage) (result any, failure error) {
			u, _ := auth.FromContext(r.Context())
			input, err := d.PDFCreationSessions.NewBlocksArgumentsV1(r.Context(), u.OrgID, args)
			if err != nil {
				return nil, err
			}
			defer func() { result = newOwnedBlockToolResultV1(result, input) }()
			var p struct {
				ExpectedUpdatedAt string          `json:"expected_updated_at"`
				DocumentID        string          `json:"document_id"`
				Variables         json.RawMessage `json:"variables"`
			}
			if err := input.WithArgumentsV1(r.Context(), func(raw []byte) error { return MustParseArgs(raw, &p) }); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			if err = auth.EnforceDocScope(r.Context(), id); err != nil {
				return nil, err
			}
			vars := p.Variables
			if len(vars) == 0 {
				vars = json.RawMessage(`{}`)
			}
			if _, err = blocks.ParseVariableValues(vars); err != nil {
				return nil, fmt.Errorf("invalid variables: %w", err)
			}
			if d.Pool == nil || d.Audit == nil {
				return nil, errors.New("atomic audit dependencies unavailable")
			}
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), id, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			updated, err := blockauthoring.MutatePlainDraftV1(r.Context(), blockauthoring.DependenciesV1{Sessions: d.PDFCreationSessions, Audit: d.Audit, SnapshotMutation: d.Versions != nil}, blockauthoring.ActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "set_variables"}, id, versions.ViaMCP, p.ExpectedUpdatedAt, checkDocumentObservation, blockauthoring.PlainDraftMutationInputV1{VariablesOnly: true, Variables: vars})
			return updated, canonicalBlockMutationErrorV1(err)

		},
	})

	s.RegisterTool(ToolDef{
		Name:        "add_recipient",
		Write:       true,
		Description: "Add a signer, approver, or custom signature-role participant to a draft document. Informational cc/viewer delivery is unavailable in this release.",
		InputSchema: schemaObject(map[string]any{
			"document_id": stringSchema("document uuid"),
			"role":        map[string]any{"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$", "default": "signer", "description": "signer, approver, or a custom role matching a signature field; cc/viewer are unavailable"},
			"email":       stringSchema("recipient email"),
			"name":        stringSchema("recipient display name"),
			"order_index": intSchema("ordering for sequential routing; 0 for parallel", 0, 1000, 0),
			"locale":      stringSchema("signing language code (e.g. sv, en); defaults to the document's default_locale"),
		}, []string{"document_id", "email", "name"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID string `json:"document_id"`
				Role       string `json:"role"`
				Email      string `json:"email"`
				Name       string `json:"name"`
				OrderIndex int32  `json:"order_index"`
				Locale     string `json:"locale"`
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
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), id, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			engine := recipientauthoring.MutationEngine{Pool: d.Pool, Audit: d.Audit, Billing: d.Billing}
			actor := recipients.MutationActor{
				OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "add_recipient",
				IP: clientIP(r), UserAgent: r.UserAgent(),
			}
			role := p.Role
			if role == "" {
				role = "signer"
			}
			return engine.CreateOwnedV1(r.Context(), d.PDFCreationSessions, d.Queries, actor, id, recipients.Values{
				Email: p.Email, Name: p.Name, Role: role, OrderIndex: p.OrderIndex, Locale: p.Locale,
			})
		},
	})

	// update_recipient / delete_recipient: let an agent self-correct a mistyped
	// email or a wrongly-added signer BEFORE send, without a REST/UI fallback.
	// Draft-only so a link is never already out; only supplied fields change.
	s.RegisterTool(ToolDef{
		Name:        "update_recipient",
		Write:       true,
		Description: "Update a response participant on a DRAFT document (fix email/name/signature role/order/locale). Only supplied fields change; cc/viewer delivery is unavailable.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid (must be draft)"),
			"recipient_id": stringSchema("recipient uuid"),
			"email":        stringSchema("optional new email"),
			"name":         stringSchema("optional new name"),
			"role":         map[string]any{"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$", "description": "optional signer, approver, or custom signature role; cc/viewer are unavailable"},
			"order_index":  intSchema("optional new signing order", 0, 1000, 0),
			"locale":       stringSchema("optional new signer-ceremony locale"),
		}, []string{"document_id", "recipient_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string  `json:"document_id"`
				RecipientID string  `json:"recipient_id"`
				Email       *string `json:"email"`
				Name        *string `json:"name"`
				Role        *string `json:"role"`
				OrderIndex  *int32  `json:"order_index"`
				Locale      *string `json:"locale"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			docID, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			rid, err := uuid.Parse(p.RecipientID)
			if err != nil {
				return nil, errors.New("recipient_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
				return nil, err
			}
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), docID, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			engine := recipientauthoring.MutationEngine{Pool: d.Pool, Audit: d.Audit, Billing: d.Billing}
			actor := recipients.MutationActor{
				OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "update_recipient",
				IP: clientIP(r), UserAgent: r.UserAgent(),
			}
			return engine.UpdateOwnedV1(r.Context(), d.PDFCreationSessions, d.Queries, actor, docID, rid, recipients.Patch{
				Email: p.Email, Name: p.Name, Role: p.Role, OrderIndex: p.OrderIndex, Locale: p.Locale,
			})
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "delete_recipient",
		Write:       true,
		Description: "Remove a recipient from a DRAFT document (e.g. a mistakenly-added signer). Draft-only.",
		InputSchema: schemaObject(map[string]any{
			"document_id":  stringSchema("document uuid (must be draft)"),
			"recipient_id": stringSchema("recipient uuid"),
		}, []string{"document_id", "recipient_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				DocumentID  string `json:"document_id"`
				RecipientID string `json:"recipient_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			docID, err := uuid.Parse(p.DocumentID)
			if err != nil {
				return nil, errors.New("document_id must be a uuid")
			}
			rid, err := uuid.Parse(p.RecipientID)
			if err != nil {
				return nil, errors.New("recipient_id must be a uuid")
			}
			if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
				return nil, err
			}
			authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), docID, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			engine := recipientauthoring.MutationEngine{Pool: d.Pool, Audit: d.Audit, Billing: d.Billing}
			actor := recipients.MutationActor{
				OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "mcp", Tool: "delete_recipient",
				IP: clientIP(r), UserAgent: r.UserAgent(),
			}
			deleted, err := engine.DeleteOwnedV1(r.Context(), d.PDFCreationSessions, d.Queries, actor, docID, rid)
			if err != nil {
				return deleted, err
			}
			return &ownedRecipientDeletedToolResultV1{owner: deleted}, nil
		},
	})
}

func normalizeMCPRecipientUpdate(existing *generated.Recipient, email, name, role *string, orderIndex *int32, locale *string) (recipients.Values, error) {
	return recipients.NormalizePatch(existing, recipients.Patch{
		Email: email, Name: name, Role: role, OrderIndex: orderIndex, Locale: locale,
	})
}

// mutateDocumentTree applies fn to the document's block tree under a draft +
// blocks-source guard, persists the result, and emits the audit event.
func mutateDocumentTree(r *http.Request, d Deps, orgID, userID uuid.UUID, docID uuid.UUID, via versions.Via, toolName string, fn pdfadmission.BlocksEditV1, expected string) (any, error) {
	if d.Pool == nil || d.Audit == nil {
		return nil, errors.New("atomic audit dependencies unavailable")
	}
	authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), docID, mcpScopeWriteAuthoring)
	if err != nil {
		return nil, err
	}
	result, err := blockauthoring.MutateTreeV1(r.Context(), blockauthoring.DependenciesV1{Sessions: d.PDFCreationSessions, Audit: d.Audit, SnapshotMutation: d.Versions != nil}, blockauthoring.ActorV1{OrgID: orgID, UserID: userID, Authorize: authorize, Via: "mcp", Tool: toolName}, docID, via, expected, checkDocumentObservation, fn)
	return result, canonicalBlockMutationErrorV1(err)
}

func updateTopLevelBlock(tree *blocks.Tree, blockID string, replacement blocks.Block) error {
	return updateTopLevelBlockWithAdmissionV1(tree, blockID, replacement, nil)
}
func updateTopLevelBlockWithAdmissionV1(tree *blocks.Tree, blockID string, replacement blocks.Block, admission blocks.ConditionalSendAdmissionV1) error {
	if tree == nil {
		return errors.New("block tree is nil")
	}
	for i := range tree.Blocks {
		if tree.Blocks[i].ID == blockID {
			// A block's identity comes from the path argument, matching the REST
			// endpoint and preventing an update from silently becoming a rename.
			replacement.ID = blockID
			tree.Blocks[i] = replacement
			return blocks.ValidateForSendV1(tree, admission)
		}
	}
	return errors.New("block_id not found at top level")
}

func clientIP(r *http.Request) string {
	// chi.middleware.RealIP has already put the client IP into r.RemoteAddr.
	return requestmeta.ClientIP(r.RemoteAddr)
}

func cleanupMCPImportedPDF(parent context.Context, d Deps, doc *generated.Document) error {
	if d.Storage == nil || doc == nil || !doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" ||
		!doc.EvidenceVersionPinsRequired || !doc.PdfStorageVersionID.Valid ||
		strings.TrimSpace(doc.PdfStorageVersionID.String) == "" || len(doc.PdfSha256) != sha256.Size {
		return errors.New("document import cleanup unavailable")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
	defer cancel()
	return d.Storage.DeleteVersion(ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
}

// Called only after authoritative document row lock acquisition.
func checkDocumentObservation(doc *generated.Document, expected string) error {
	if expected == "" {
		return errors.New("expected_updated_at is required")
	}
	observed, err := time.Parse(time.RFC3339Nano, expected)
	if err != nil {
		return errors.New("expected_updated_at must be RFC3339")
	}
	if doc == nil || !doc.UpdatedAt.Valid || !doc.UpdatedAt.Time.Equal(observed) {
		return errors.New("document changed since observation; fetch and review before replacing content")
	}
	return nil
}
