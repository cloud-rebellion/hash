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
	registerServiceEmailToolsWithService(s, emailtemplates.Service{Pool: d.Pool, Audit: d.Audit})
}

func registerServiceEmailToolsWithService(s *Server, service serviceEmailSettings) {
	s.RegisterTool(ToolDef{
		Name: "list_service_email_templates", MinRole: auth.RoleOwner,
		Description: "List organization service email subjects and introductory content, revisions, editable capabilities and byte limits. Owner and organization-wide read key required; document tokens denied. This does not send email or configure SMTP, sender identity, tracking, AI generation or full email layout.",
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
			return map[string]any{"schema_version": 1, "templates": rows, "limits": map[string]int{
				"subject_bytes": dispatch.ServiceEmailSubjectSourceBytesV1,
				"html_bytes":    dispatch.ServiceEmailHTMLSourceBytesV1,
				"text_bytes":    dispatch.ServiceEmailTextSourceBytesV1,
			}, "preview_synthetic": true}, nil
		},
	})
	for _, save := range []bool{false, true} {
		name, scope := "preview_service_email_template", mcpScopeRead
		description := "Preview service email subject and introductory content using synthetic data only; no save, send or AI provider call. Hash appends its protected action/security/legal content. Owner and organization-wide read key required; document tokens denied. Supply the observed expected_revision and all three source strings. Built-in-only kinds permit only revision zero with three empty strings. HTML supports safe formatting, no links/images/attributes/CSS; byte limits come from List. This is not a full-layout editor."
		if save {
			name, scope = "save_service_email_template", mcpScopeWriteAuthoring
			description = "Save organization service email subject and introductory content through the owner settings transaction with exact expected_revision CAS. Only the six editable kinds reported by List can be saved. Supply all three strings; all empty resets built-in content at a new revision. Hash retains protected action/security/legal content and its safe HTML/byte limits. A conflict requires reload and review. Owner and organization-wide write:authoring key required; document tokens denied. Affects future eligible messages, not frozen messages; no email send, SMTP, sender/tracking configuration, AI generation or full-layout design."
		}
		s.RegisterTool(ToolDef{
			Name: name, Description: description, MinRole: auth.RoleOwner, Write: save,
			InputSchema: serviceEmailInputSchema(false),
			Handler: func(r *http.Request, args json.RawMessage) (any, error) {
				values, err := exactServiceEmailArguments(args, false)
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

// Closed flat contract: at most five fields and 160KiB. Exact key equality
// precedes typed decoding, refusing duplicates, aliases, nulls and trailing JSON.
// Content validation stays in emailtemplates.Service, shared with REST.
func exactServiceEmailArguments(raw []byte, list bool) ([5]json.RawMessage, error) {
	var values [5]json.RawMessage
	if len(raw) < 2 || len(raw) > 160<<10 || validateJSONUnicode(raw) != nil {
		return values, errServiceEmailArguments
	}
	fields := []string{"kind", "expected_revision", "subject_template", "html_template", "text_template"}
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
		for _, value := range values {
			if value == nil {
				return values, errServiceEmailArguments
			}
		}
	}
	return values, nil
}

func serviceEmailInputSchema(list bool) map[string]any {
	properties := map[string]any{}
	var required []string
	if !list {
		properties = map[string]any{
			"kind":              map[string]any{"type": "string", "enum": dispatch.ServiceEmailKindsV1()},
			"expected_revision": map[string]any{"type": "integer", "minimum": 0, "description": "Exact revision observed by List; stale revisions refuse without overwriting."},
			"subject_template":  stringSchema("Subject override; at most 256 UTF-8 bytes. Empty uses built-in subject."),
			"html_template":     stringSchema("Introductory safe HTML only; at most 16384 UTF-8 bytes. No links, images, attributes or CSS."),
			"text_template":     stringSchema("Introductory plain text only; at most 8192 UTF-8 bytes."),
		}
		required = []string{"kind", "expected_revision", "subject_template", "html_template", "text_template"}
	}
	schema := schemaObject(properties, required)
	schema["additionalProperties"] = false
	return schema
}
