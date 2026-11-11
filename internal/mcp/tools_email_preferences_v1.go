// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
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
	"github.com/bright-interaction/hash/internal/emailtemplates"
)

type workspaceEmailPreferencesV1 interface {
	PreferencesV1(context.Context, authoring.Actor) (emailtemplates.PreferencesV1, error)
	SavePreferencesV1(context.Context, authoring.Actor, emailtemplates.PreferencesInputV1) (emailtemplates.PreferencesV1, error)
}

var errWorkspaceEmailPreferencesArgumentsV1 = errors.New("supply only the observed expected_revision and an English or Swedish workspace email locale; reads take no arguments")

func registerWorkspaceEmailPreferencesV1(s *Server, service workspaceEmailPreferencesV1) {
	for _, save := range []bool{false, true} {
		name, scope := "get_workspace_email_preferences", mcpScopeRead
		description := "Read the saved workspace email language and CAS revision. Owner and organization-wide read key required; document keys denied. It selects future scheduled staff/quota builtin copy, independently of browser UI and document/recipient languages. No send or SMTP configuration."
		properties, required := map[string]any{}, []string{}
		if save {
			name, scope = "save_workspace_email_preferences", mcpScopeWriteAuthoring
			description = "Save the workspace's English or Swedish scheduled staff/quota email language with exact expected_revision CAS. Owner and organization-wide write:authoring key required; document keys denied. Every save advances revision. Custom prose stays literal; queued messages, recipients, triggers, timing and document/recipient language stay unchanged. Stale or uncertain saves require readback before retry."
			properties = map[string]any{
				"expected_revision": map[string]any{"type": "integer", "minimum": 0, "maximum": emailtemplates.PreferencesMaxRevisionV1 - 1},
				"locale":            map[string]any{"type": "string", "enum": []string{"en", "sv"}},
			}
			required = []string{"expected_revision", "locale"}
		}
		schema := schemaObject(properties, required)
		schema["additionalProperties"] = false
		s.RegisterTool(ToolDef{Name: name, MinRole: auth.RoleOwner, Write: save, Description: description, InputSchema: schema,
			Handler: func(r *http.Request, raw json.RawMessage) (any, error) {
				in, err := workspaceEmailPreferencesArgumentsV1(raw, save)
				if err != nil {
					return nil, err
				}
				actor, err := serviceEmailActor(r, scope)
				if err != nil {
					return nil, err
				}
				if save {
					return service.SavePreferencesV1(r.Context(), actor, in)
				}
				return service.PreferencesV1(r.Context(), actor)
			}})
	}
}

func workspaceEmailPreferencesArgumentsV1(raw []byte, save bool) (emailtemplates.PreferencesInputV1, error) {
	var out emailtemplates.PreferencesInputV1
	if len(raw) < 2 || len(raw) > 2048 || validateJSONUnicode(raw) != nil {
		return out, errWorkspaceEmailPreferencesArgumentsV1
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return out, errWorkspaceEmailPreferencesArgumentsV1
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		tok, err = d.Token()
		key, ok := tok.(string)
		if err != nil || !ok || !save || (key != "locale" && key != "expected_revision") || fields[key] != nil {
			return out, errWorkspaceEmailPreferencesArgumentsV1
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return out, errWorkspaceEmailPreferencesArgumentsV1
		}
		fields[key] = value
	}
	if tok, err = d.Token(); err != nil || tok != json.Delim('}') {
		return out, errWorkspaceEmailPreferencesArgumentsV1
	}
	if _, err = d.Token(); err != io.EOF {
		return out, errWorkspaceEmailPreferencesArgumentsV1
	}
	if save {
		if len(fields) != 2 || json.Unmarshal(fields["expected_revision"], &out.ExpectedRevision) != nil ||
			json.Unmarshal(fields["locale"], &out.Locale) != nil || out.ExpectedRevision < 0 || out.ExpectedRevision >= emailtemplates.PreferencesMaxRevisionV1 ||
			(out.Locale != "en" && out.Locale != "sv") {
			return out, errWorkspaceEmailPreferencesArgumentsV1
		}
	}
	return out, nil
}
