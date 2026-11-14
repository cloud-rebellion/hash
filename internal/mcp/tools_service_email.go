// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// The transport delegates validation, CAS, rendering and transactional owner
// checks to the same service as REST. This private interface permits transport
// tests without substituting the production credential authorization boundary.
type serviceEmailSettings interface {
	List(context.Context, authoring.Actor) ([]emailtemplates.Template, error)
	Preview(context.Context, authoring.Actor, string, emailtemplates.Input) (emailtemplates.Preview, error)
	Save(context.Context, authoring.Actor, string, emailtemplates.Input) (emailtemplates.Template, error)
}

func registerServiceEmailTools(s *Server, d Deps) {
	var work *pdfadmission.WorkAdmissionV1
	if d.Send != nil && d.Send.WorkRuntime != nil && d.Send.WorkRuntime.MatchesPoolV1(d.Pool) && d.Send.WorkRuntime.SessionsV1() == d.PDFCreationSessions {
		work = d.Send.WorkRuntime.WorkV1()
	}
	service := emailtemplates.Service{Pool: d.Pool, Audit: d.Audit, Work: work, Runtime: d.AIRuntime}
	registerServiceEmailToolsWithService(s, service)
	registerWorkspaceEmailPreferencesV1(s, service)
}

type serviceEmailProposalSettings interface {
	Propose(context.Context, authoring.Actor, string, emailtemplates.ProposalInput) (emailtemplates.Proposal, error)
}

func registerServiceEmailToolsWithService(s *Server, service serviceEmailSettings) {
	s.RegisterTool(ToolDef{
		Name: "propose_service_email_design", MinRole: auth.RoleOwner, Write: true,
		Description: "Propose a branded email candidate and synthetic preview through the workspace's existing enabled AI provider. Owner and organization-wide write:authoring key required; document tokens denied. Supply the observed expected_revision, all three source strings and a bounded prompt. Optional preview_locale (en/sv) selects only the synthetic native preview, never the provider prompt or saved wording. Omission preserves English except quota samples use saved workspace language. Optional design_json follows the preview contract. Logo bytes remain local. This incurs configured AI usage and records usage; it does not save, send or configure a provider. Human review and a separate exact-CAS save remain required.",
		InputSchema: serviceEmailProposalInputSchemaV1(),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			values, err := exactServiceEmailFieldsV1(args, false, true, true)
			if err != nil {
				return nil, err
			}
			var kind string
			var in emailtemplates.ProposalInput
			if json.Unmarshal(values[0], &kind) != nil || json.Unmarshal(values[1], &in.ExpectedRevision) != nil ||
				json.Unmarshal(values[2], &in.SubjectTemplate) != nil || json.Unmarshal(values[3], &in.HTMLTemplate) != nil ||
				json.Unmarshal(values[4], &in.TextTemplate) != nil || json.Unmarshal(values[6], &in.Prompt) != nil {
				return nil, errServiceEmailArguments
			}
			if values[5] != nil {
				var design string
				if json.Unmarshal(values[5], &design) != nil {
					return nil, errServiceEmailArguments
				}
				in.DesignJSON = &design
			}
			in.PreviewLocale, err = emailtemplates.DecodeSyntheticPreviewLocaleV1(values[7])
			if err != nil {
				return nil, errServiceEmailArguments
			}
			actor, err := serviceEmailActor(r, mcpScopeWriteAuthoring)
			if err != nil {
				return nil, err
			}
			proposalService, ok := service.(serviceEmailProposalSettings)
			if !ok {
				return nil, emailtemplates.ErrWorkspaceAIUnavailable
			}
			return proposalService.Propose(r.Context(), actor, kind, in)
		},
	})
	s.RegisterTool(ToolDef{
		Name: "list_service_email_templates", MinRole: auth.RoleOwner,
		Description: "List organization service email subjects and introductory content, revisions, editable capabilities and byte limits. Owner and organization-wide read key required; document tokens denied. This does not send email or configure SMTP, sender identity, tracking, AI generation or tracking. Full design is a canonical bounded design_json edition with protected native content, never raw resources.",
		InputSchema: serviceEmailInputSchema(true),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			if _, err := exactServiceEmailArguments(args, true); err != nil {
				return nil, err
			}
			actor, err := serviceEmailActor(r, mcpScopeRead)
			if err != nil {
				return nil, err
			}
			rows, err := service.List(r.Context(), actor)
			if err != nil {
				return nil, err
			}
			return &ownedServiceEmailListV1{rows: rows}, nil
		},
	})
	for _, save := range []bool{false, true} {
		name, scope := "preview_service_email_template", mcpScopeRead
		description := "Preview service email subject and introductory content using synthetic data only; no save, send or AI provider call. Optional preview_locale (en/sv) selects native preview copy only, never translates custom wording. Omission preserves English except quota samples use saved workspace language. Hash appends its protected action/security/legal content. Owner and organization-wide read key required; document tokens denied. Supply the observed expected_revision and all three source strings. Built-in-only kinds permit only revision zero with three empty strings. HTML supports safe formatting, no links/images/attributes/CSS; byte limits come from List. Optional design_json is the canonical full layout/palette/logo edition: exactly one {{native_content}} slot, validated embedded PNG/JPEG only; no remote resources or concealed native actions. Omit it to preserve the saved design, or use empty string to clear it."
		if save {
			name, scope = "save_service_email_template", mcpScopeWriteAuthoring
			description = "Save organization service email subject and introductory content through the owner settings transaction with exact expected_revision CAS. Only the eight editable kinds reported by List can be saved. Supply all three strings; all empty resets built-in content at a new revision. Hash retains protected action/security/legal content and its safe HTML/byte limits. A conflict requires reload and review. Owner and organization-wide write:authoring key required; document tokens denied. Affects future eligible messages, not frozen messages; no email send, SMTP, sender/tracking configuration, AI generation or implicit sending. Optional canonical design_json uses the same immutable revision; omission preserves the current design, empty explicitly clears it."
		}
		s.RegisterTool(ToolDef{
			Name: name, Description: description, MinRole: auth.RoleOwner, Write: save,
			InputSchema: serviceEmailInputSchema(false, !save),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				values, err := exactServiceEmailFieldsV1(args, false, false, !save)
				if err != nil {
					return nil, err
				}
				var kind string
				var in emailtemplates.Input
				if json.Unmarshal(values[0], &kind) != nil || json.Unmarshal(values[1], &in.ExpectedRevision) != nil ||
					json.Unmarshal(values[2], &in.SubjectTemplate) != nil || json.Unmarshal(values[3], &in.HTMLTemplate) != nil ||
					json.Unmarshal(values[4], &in.TextTemplate) != nil {
					return nil, errServiceEmailArguments
				}
				if values[5] != nil {
					var design string
					if json.Unmarshal(values[5], &design) != nil {
						return nil, errServiceEmailArguments
					}
					in.DesignJSON = &design
				}
				in.PreviewLocale, err = emailtemplates.DecodeSyntheticPreviewLocaleV1(values[7])
				if err != nil {
					return nil, errServiceEmailArguments
				}
				actor, err := serviceEmailActor(r, scope)
				if err != nil {
					return nil, err
				}
				if save {
					return service.Save(r.Context(), actor, kind, in)
				}
				return service.Preview(r.Context(), actor, kind, in)
			},
		})
	}
}

func serviceEmailActor(r *http.Request, scope string) (authoring.Actor, error) {
	u, ok := auth.FromContext(r.Context())
	if !ok || u.OrgID == uuid.Nil || u.Role != string(auth.RoleOwner) {
		return authoring.Actor{}, auth.ErrMutationPermissionRevoked
	}
	if _, documentScoped := auth.DocumentScopeFromContext(r.Context()); documentScoped {
		return authoring.Actor{}, auth.ErrMutationPermissionRevoked
	}
	// The private receipt exists only after RequireAPIKey verifies the actual
	// key and claims its use. The service retains this closure across row waits,
	// rechecking the same key, scopes, expiry and live owner before commit.
	authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), uuid.Nil, scope)
	if err != nil {
		return authoring.Actor{}, err
	}
	return authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, nil
}

var errServiceEmailArguments = errors.New("invalid service email arguments; supply exactly kind, expected_revision and all three source strings (List takes an empty object)")

// Closed flat contract: five required legacy fields plus optional design_json.
// Escaped source is bounded before typed decoding; omission preserves design. Exact key equality
// precedes typed decoding, refusing duplicates, aliases, nulls and trailing JSON.
// Content validation stays in emailtemplates.Service, shared with REST.
func exactServiceEmailArguments(raw []byte, list bool) ([6]json.RawMessage, error) {
	var values [6]json.RawMessage
	decoded, err := exactServiceEmailFieldsV1(raw, list, false)
	copy(values[:], decoded[:6])
	return values, err
}

func exactServiceEmailFieldsV1(raw []byte, list, proposal bool, preview ...bool) ([8]json.RawMessage, error) {
	var values [8]json.RawMessage
	if len(raw) < 2 || len(raw) > (160<<10)+6*dispatch.ServiceEmailDesignSourceBytesV1 || validateJSONUnicode(raw) != nil {
		return values, errServiceEmailArguments
	}
	fields := []string{"kind", "expected_revision", "subject_template", "html_template", "text_template", "design_json"}
	if proposal {
		fields = append(fields, "prompt")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return values, errServiceEmailArguments
	}
	for d.More() {
		tok, err = d.Token()
		key, ok := tok.(string)
		if err != nil || !ok || list {
			return values, errServiceEmailArguments
		}
		index := -1
		for i, field := range fields {
			if key == field {
				index = i
				break
			}
		}
		if len(preview) == 1 && preview[0] && key == "preview_locale" {
			index = 7
		}
		if index < 0 || values[index] != nil || d.Decode(&values[index]) != nil || bytes.Equal(bytes.TrimSpace(values[index]), []byte("null")) {
			return values, errServiceEmailArguments
		}
	}
	if tok, err = d.Token(); err != nil || tok != json.Delim('}') {
		return values, errServiceEmailArguments
	}
	if _, err = d.Token(); err != io.EOF {
		return values, errServiceEmailArguments
	}
	if !list {
		for _, value := range values[:5] {
			if value == nil {
				return values, errServiceEmailArguments
			}
		}
	}
	if proposal && values[6] == nil {
		return values, errServiceEmailArguments
	}
	return values, nil
}

func serviceEmailInputSchema(list bool, preview ...bool) map[string]any {
	properties := map[string]any{}
	var required []string
	if !list {
		properties = map[string]any{
			"kind":              map[string]any{"type": "string", "enum": dispatch.ServiceEmailKindsV1()},
			"expected_revision": map[string]any{"type": "integer", "minimum": 0, "description": "Exact revision observed by List; stale revisions refuse without overwriting."},
			"subject_template":  stringSchema("Subject override; at most 256 UTF-8 bytes. Empty uses built-in subject."),
			"html_template":     stringSchema("Introductory safe HTML only; at most 16384 UTF-8 bytes. No links, images, attributes or CSS."),
			"text_template":     stringSchema("Introductory plain text only; at most 8192 UTF-8 bytes."),
			"design_json":       stringSchema("Optional canonical v1 full email design JSON string; at most131072 UTF-8 bytes. One protected native_content slot; validated embedded logo only. Omitted preserves current design; empty string explicitly clears it."),
		}
		if len(preview) == 1 && preview[0] {
			properties["preview_locale"] = map[string]any{"type": "string", "enum": []string{"en", "sv"}, "description": "Optional synthetic native preview language only; omission preserves English except quota uses saved workspace language. Does not translate or save custom wording."}
		}
		required = []string{"kind", "expected_revision", "subject_template", "html_template", "text_template"}
	}
	schema := schemaObject(properties, required)
	schema["additionalProperties"] = false
	return schema
}

func serviceEmailProposalInputSchemaV1() map[string]any {
	schema := serviceEmailInputSchema(false, true)
	properties := schema["properties"].(map[string]any)
	properties["prompt"] = stringSchema("Design instruction; 1..4096 UTF-8 bytes. Existing configured workspace AI only; no credentials, remote resources or implicit save/send.")
	schema["required"] = append(schema["required"].([]string), "prompt")
	return schema
}

// The central MCP serializer retains the actual process owner across all rows.
type ownedServiceEmailListV1 struct{ rows []emailtemplates.Template }

func (o *ownedServiceEmailListV1) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{"schema_version": 1, "templates": o.rows, "limits": map[string]int{"subject_bytes": dispatch.ServiceEmailSubjectSourceBytesV1, "html_bytes": dispatch.ServiceEmailHTMLSourceBytesV1, "text_bytes": dispatch.ServiceEmailTextSourceBytesV1, "design_bytes": dispatch.ServiceEmailDesignSourceBytesV1}, "preview_synthetic": true})
}
func (o *ownedServiceEmailListV1) CloseConsumerV1() {
	if o != nil {
		for _, r := range o.rows {
			r.CloseConsumerV1()
		}
	}
}
