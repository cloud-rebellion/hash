// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
)

type designToolArgsV1 struct {
	TemplateID            string                  `json:"template_id,omitempty"`
	DocumentID            string                  `json:"document_id,omitempty"`
	Input                 json.RawMessage         `json:"input,omitempty"`
	BrandProfile          json.RawMessage         `json:"brand_profile,omitempty"`
	Purpose               documentpurpose.Purpose `json:"purpose,omitempty"`
	Version               int32                   `json:"version,omitempty"`
	ExpectedContentSHA256 string                  `json:"expected_content_sha256,omitempty"`
	VisuallyReviewed      bool                    `json:"visually_reviewed,omitempty"`
	ReviewedPages         []int                   `json:"reviewed_pages,omitempty"`
}

func designDecodeV1(raw []byte, value any) error {
	if sourcejson.Validate(raw) != nil {
		return errors.New("invalid or ambiguous design JSON")
	}
	if err := validateJSONUnicode(raw); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return errors.New("JSON object required")
	}
	for _, key := range []string{"values", "sections"} {
		if v, ok := object[key]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return errors.New("values and sections must be objects of strings")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("one JSON object required")
	}
	return nil
}

func designObjectShapeV1(raw []byte, properties map[string]any, required []string) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return errors.New("JSON object required")
	}
	for key := range object {
		if _, ok := properties[key]; !ok {
			return errors.New("unexpected design argument")
		}
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return errors.New("required design argument missing")
		}
	}
	return nil
}
func designActorV1(ctx context.Context, id uuid.UUID, write bool) (DesignActorV1, error) {
	key, user, org, err := auth.DesignCredentialIdentityV1(ctx)
	if err != nil {
		return DesignActorV1{}, err
	}
	scope := mcpScopeRead
	if write {
		scope = mcpScopeWriteAuthoring
	}
	authorize, err := auth.APIKeyTransactionAuthorization(ctx, id, scope)
	if err != nil {
		return DesignActorV1{}, err
	}
	return DesignActorV1{Actor: authoring.Actor{OrgID: org, UserID: user, Authorize: authorize}, KeyID: key}, nil
}

func registerDesignToolsV1(s *Server, d Deps) {
	// Each fixed operation selects its own native input profile. The caller
	// cannot select a tenant, grant, cost, actor or native-work profile.
	type def struct {
		name, description             string
		write, owner, document, input bool
		profile                       pdfadmission.HTMLAuthoringInputProfileV1
	}
	defs := []def{
		{"create_design_template", "Save a new editable, versioned HTML design. Read hash://guides/designed-documents first. This does not visually review, approve, create recipients or send anything.", true, false, false, true, pdfadmission.HTMLTemplateMasterInputV1},
		{"get_design_template", "Read current editable HTML source, or the exact immutable version pinned by a document. For historical source supply version AND expected_content_sha256. Result separates current_parent_version/name from selected version/master/defaults/approval.", false, false, false, false, 0},
		{"update_design_template", "Save a new HTML layout/assets/defaults version using expected_version. Existing documents keep their frozen design; instantiate the reviewed new version to use its layout.", true, false, false, true, pdfadmission.HTMLTemplateMasterInputV1},
		{"preview_design_template", "Render the saved exact design to a PDF. Returns bytes, SHA, page count and an API-key-bound expiring preview receipt. Inspect EVERY page; rendering/readback is not visual review.", false, false, false, true, pdfadmission.HTMLTemplatePreviewInputV1},
		{"approve_design_template", "Explicit OWNER approval of the exact design preview after inspecting every page. Supply visually_reviewed=true and reviewed_pages=1..N. This is a caller attestation, not contract approval or Send.", true, true, false, true, pdfadmission.HTMLTemplateApprovalInputV1},
		{"create_document_from_design", "Create an internal draft from an exact approved design version. Supply purpose document/presentation/signing explicitly and a unique request_id. Retains master, declared text and exact PDF history. Does not add recipients or send.", true, false, false, true, pdfadmission.HTMLDocumentCreationInputV1},
		{"get_document_design_source", "Read current declared source/PDF commitments and the frozen editable-template origin. Layout/assets remain frozen; text revisions do not replace a layout. Returns retained brand provenance when present.", false, false, true, false, 0},
		{"get_document_design_history", "Read retained HTML materialization revisions and exact source/PDF/page-count pins.", false, false, true, false, 0},
		{"download_document_pdf", "Download an exact saved PDF for visual inspection. Supply current updated_at/PDF SHA and HTML source commitment; revision selects retained HTML history. No approval or Send occurs.", false, false, true, true, 0},
		{"revise_document_design_values", "Revise declared plain-text values/sections using current source/updated_at pins. Preserves the frozen master/assets and retained PDF history; new PDF requires fresh visual review and field placement.", true, false, true, true, pdfadmission.HTMLDocumentRevisionInputV1},
		{"review_document_design", "Explicitly acknowledge the exact current HTML PDF after inspecting EVERY page. Supply visually_reviewed=true and reviewed_pages=1..N. Save, download and successful rendering are insufficient. Does not approve contractual terms or Send.", true, false, true, true, 0},
	}
	for _, item := range defs {
		item := item
		props := map[string]any{}
		required := []string{}
		if item.name != "create_design_template" {
			key := "template_id"
			if item.document {
				key = "document_id"
			}
			props[key] = stringSchema("UUID in the caller's organization")
			required = append(required, key)
		}
		if item.input {
			props["input"] = designInputSchemaV1(item.name)
			required = append(required, "input")
		}
		if item.name == "get_design_template" {
			props["version"] = map[string]any{"type": "integer", "minimum": 1}
			props["expected_content_sha256"] = stringSchema("required exact frozen content commitment when version is provided")
		}
		if item.name == "create_design_template" || item.name == "update_design_template" {
			props["brand_profile"] = map[string]any{"type": "object", "description": "Optional exact profile_id, revision, content_sha256 and selected asset_slots. Server resolves safe PNG bytes, rejects client-name collisions, admits the expanded master and binds provenance atomically. Reference hash-asset:brand_<slot> without copying binary bytes through the model."}
		}
		if item.name == "create_document_from_design" {
			props["purpose"] = documentPurposeSchemaV1()
			required = append(required, "purpose")
		}
		if item.owner || item.name == "review_document_design" {
			props["visually_reviewed"] = map[string]any{"type": "boolean", "description": "Explicit attestation that you inspected every page of this exact PDF"}
			props["reviewed_pages"] = map[string]any{"type": "array", "minItems": 1, "maxItems": 500, "items": map[string]any{"type": "integer", "minimum": 1, "maximum": 500}}
			required = append(required, "visually_reviewed", "reviewed_pages")
		}
		tool := ToolDef{Name: item.name, Description: item.description, Write: item.write, InputSchema: schemaObject(props, required)}
		tool.InputSchema["additionalProperties"] = false
		if item.owner {
			tool.MinRole = auth.RoleOwner
		}
		tool.Handler = func(r *http.Request, raw json.RawMessage) (result any, failure error) {
			if d.Design == nil {
				return nil, errors.New("native design authoring unavailable")
			}
			var args designToolArgsV1
			if err := designObjectShapeV1(raw, props, required); err != nil {
				return nil, err
			}
			if err := designDecodeV1(raw, &args); err != nil {
				return nil, err
			}
			if item.name == "get_design_template" {
				var selection map[string]json.RawMessage
				_ = json.Unmarshal(raw, &selection) // The strict object decoder above succeeded.
				_, hasVersion := selection["version"]
				_, hasSHA := selection["expected_content_sha256"]
				if hasVersion != hasSHA || (hasVersion && (args.Version < 1 || len(args.ExpectedContentSHA256) != 64)) {
					return nil, errors.New("historical source requires version and exact content SHA-256 together")
				}
				if args.Version > 0 {
					sha, err := hex.DecodeString(args.ExpectedContentSHA256)
					if err != nil || hex.EncodeToString(sha) != args.ExpectedContentSHA256 {
						return nil, errors.New("historical source requires a lowercase SHA-256 commitment")
					}
				}
			}
			id := uuid.Nil
			if item.name != "create_design_template" {
				value := args.TemplateID
				if item.document {
					value = args.DocumentID
				}
				var err error
				id, err = uuid.Parse(value)
				if err != nil || id == uuid.Nil {
					return nil, errors.New("valid document_id or template_id required")
				}
			}
			authDoc := uuid.Nil
			if item.document {
				authDoc = id
			}
			actor, err := designActorV1(r.Context(), authDoc, item.write)
			if err != nil {
				return nil, err
			}
			if (item.owner || item.name == "review_document_design") && !args.VisuallyReviewed {
				return nil, errors.New("visual review remains pending; inspect every page before explicitly acknowledging it")
			}
			var input *pdfadmission.ApplicationHTMLAuthoringInputV1
			owned := &designOwnedResultV1{state: &designOwnedStateV1{}}
			defer func() { result = owned }()
			if item.profile != 0 {
				if d.PDFCreationSessions == nil {
					return nil, errors.New("native HTML input admission unavailable")
				}
				input, err = d.PDFCreationSessions.NewHTMLAuthoringInputV1(r.Context(), actor.OrgID, item.profile)
				if err != nil {
					return nil, err
				}
				owned.state.input = input
				args.Input, err = input.ReadBodyV1(r.Context(), io.NopCloser(bytes.NewReader(args.Input)))
				if err != nil {
					return nil, err
				}
			}
			var value DesignResultV1
			switch item.name {
			case "get_design_template":
				value, err = d.Design.ReadTemplateV1(r.Context(), actor, id, DesignTemplateReadInputV1{Version: args.Version, ExpectedContentSHA256: args.ExpectedContentSHA256})
			case "create_design_template", "update_design_template":
				var p DesignTemplateInputV1
				if err = designDecodeV1(args.Input, &p); err == nil {
					value, err = d.Design.WriteTemplateV1(r.Context(), actor, id, p, input, args.BrandProfile)
				}
			case "preview_design_template":
				var p DesignPreviewInputV1
				if err = designDecodeV1(args.Input, &p); err == nil {
					value, err = d.Design.PreviewTemplateV1(r.Context(), actor, id, p)
				}
			case "approve_design_template":
				var p DesignApprovalInputV1
				if err = designDecodeV1(args.Input, &p); err == nil {
					value, err = d.Design.ApproveTemplateV1(r.Context(), actor, id, p, args.ReviewedPages)
				}
			case "create_document_from_design":
				var p DesignCreationInputV1
				if err = designDecodeV1(args.Input, &p); err == nil {
					if args.Purpose == "" || documentpurpose.Validate(args.Purpose) != nil {
						err = documentpurpose.ErrInvalid
					} else {
						p.Purpose = args.Purpose
						value, err = d.Design.CreateDocumentV1(r.Context(), actor, id, p)
					}
				}
			case "get_document_design_source":
				value, err = d.Design.DocumentSourceV1(r.Context(), actor, id)
			case "get_document_design_history":
				value, err = d.Design.DocumentHistoryV1(r.Context(), actor, id)
			case "download_document_pdf":
				var p DesignPDFInputV1
				if err = designDecodeV1(args.Input, &p); err == nil {
					value, err = d.Design.DocumentPDFV1(r.Context(), actor, id, p)
				}
			case "revise_document_design_values":
				var p DesignRevisionInputV1
				if err = designDecodeV1(args.Input, &p); err == nil {
					value, err = d.Design.ReviseDocumentV1(r.Context(), actor, id, p, input)
				}
			case "review_document_design":
				var p DesignReviewInputV1
				if err = designDecodeV1(args.Input, &p); err == nil {
					value, err = d.Design.ReviewDocumentV1(r.Context(), actor, id, p, args.ReviewedPages)
				}
			}
			owned.state.value, owned.state.release = value.Value, value.Release
			return owned, err
		}
		s.RegisterTool(tool)
	}
}

func designInputSchemaV1(name string) map[string]any {
	fields := map[string]any{}
	required := []string{}
	strings := func(names ...string) {
		for _, n := range names {
			fields[n] = stringSchema(n)
			required = append(required, n)
		}
	}
	maps := func() {
		fields["values"] = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}
		fields["sections"] = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}
	}
	switch name {
	case "create_design_template", "update_design_template":
		strings("name")
		fields["html_master_json"] = map[string]any{"type": "object", "description": "Strict hash://schema/html-master object; self-contained inert HTML/CSS and exact embedded assets"}
		fields["variables_json"] = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}
		required = append(required, "html_master_json", "variables_json")
		if name == "update_design_template" {
			fields["expected_version"] = intSchema("current template version", 1, 2147483647, 1)
			required = append(required, "expected_version")
		}
	case "preview_design_template", "approve_design_template":
		fields["expected_version"] = intSchema("current template version", 1, 2147483647, 1)
		required = append(required, "expected_version")
		strings("expected_content_sha256")
		if name == "preview_design_template" {
			maps()
		} else {
			strings("preview_receipt", "expected_preview_pdf_sha256")
		}
	case "create_document_from_design":
		strings("name", "expected_template_content_sha256", "request_id")
		fields["expected_template_version"] = intSchema("approved exact design version", 1, 2147483647, 1)
		required = append(required, "expected_template_version")
		maps()
	case "revise_document_design_values":
		strings("expected_updated_at", "expected_html_source_commitment")
		maps()
		fields["summary"] = stringSchema("plain-text change summary, at most 500 characters")
	case "download_document_pdf":
		strings("expected_updated_at", "expected_pdf_sha256")
		fields["expected_html_source_commitment"] = stringSchema("required for retained HTML designs")
		fields["revision"] = intSchema("optional retained HTML materialization revision", 1, 2147483647, 1)
	case "review_document_design":
		strings("expected_updated_at", "expected_pdf_sha256", "expected_html_source_commitment")
	}
	return schemaObject(fields, required)
}
