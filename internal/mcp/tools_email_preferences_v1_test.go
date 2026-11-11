// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/google/uuid"
)

type emailPreferences128Fixture struct {
	base  *serviceEmailDelegationFixture
	input emailtemplates.PreferencesInputV1
}

func (f *emailPreferences128Fixture) PreferencesV1(ctx context.Context, actor authoring.Actor) (emailtemplates.PreferencesV1, error) {
	err := f.base.authorize(ctx, actor, "preferences-read")
	return emailtemplates.PreferencesV1{SchemaVersion: 1, OrgID: actor.OrgID, Locale: "en"}, err
}
func (f *emailPreferences128Fixture) SavePreferencesV1(ctx context.Context, actor authoring.Actor, in emailtemplates.PreferencesInputV1) (emailtemplates.PreferencesV1, error) {
	f.input = in
	err := f.base.authorize(ctx, actor, "preferences-save")
	now := time.Now()
	return emailtemplates.PreferencesV1{SchemaVersion: 1, OrgID: actor.OrgID, Revision: in.ExpectedRevision + 1, Locale: in.Locale, UpdatedAt: &now}, err
}

func TestWorkspaceEmail128MCPHasExplicitOrgOnlyScopePolicy(t *testing.T) {
	s := New(Deps{})
	for _, tc := range []struct {
		name, scope string
		write       bool
	}{{"get_workspace_email_preferences", mcpScopeRead, false}, {"save_workspace_email_preferences", mcpScopeWriteAuthoring, true}} {
		tool, ok := s.tools[tc.name]
		if !ok || tool.MinRole != auth.RoleOwner || tool.Write != tc.write || mcpToolRequiredScopes[tc.name] != tc.scope || tool.InputSchema["additionalProperties"] != false || docScopeSafeTools[tc.name] {
			t.Fatal("workspace preference scope boundary changed", tc.name)
		}
	}
}

func TestWorkspaceEmail128MCPClosedArguments(t *testing.T) {
	for _, raw := range []string{`{"expected_revision":0,"locale":"sv"}`, `{"locale":"en","expected_revision":12}`} {
		if _, err := workspaceEmailPreferencesArgumentsV1([]byte(raw), true); err != nil {
			t.Fatal("valid preference rejected", err)
		}
	}
	for _, raw := range []string{
		`{}`, `{"expected_revision":0}`, `{"expected_revision":null,"locale":"en"}`,
		`{"expected_revision":0,"locale":null}`, `{"expected_revision":0,"locale":"sv-SE"}`,
		`{"expected_revision":0,"locale":"sv","locale":"en"}`,
		`{"expected_revision":0,"locale":"en","org_id":"foreign"}`,
		`{"expected_revision":0.5,"locale":"en"}`, `{"expected_revision":-1,"locale":"en"}`,
		`{"expected_revision":9223372036854775807,"locale":"en"}`,
		`{"expected_revision":9007199254740991,"locale":"en"}`,
		`{"expected_revision":9007199254740992,"locale":"en"}`,
		`{"expected_revision":0,"locale":"en"}{}`,
	} {
		if _, err := workspaceEmailPreferencesArgumentsV1([]byte(raw), true); err == nil {
			t.Fatal("ambiguous or invalid input accepted", raw)
		}
	}
	if _, err := workspaceEmailPreferencesArgumentsV1([]byte(`{"locale":"en"}`), false); err == nil {
		t.Fatal("read accepted caller settings")
	}
}

func TestWorkspaceEmail128MCPRetainsOriginalCredential(t *testing.T) {
	for _, save := range []bool{false, true} {
		for _, mode := range []string{"valid", "viewer", "sender", "document", "wrong-scope", "revoked", "expired"} {
			t.Run(mode, func(t *testing.T) {
				server, key, base := serviceEmailFixture(t)
				fixture := &emailPreferences128Fixture{base: base}
				registerWorkspaceEmailPreferencesV1(server, fixture)
				switch mode {
				case "viewer", "sender":
					key.role = mode
				case "document":
					key.document = uuid.New()
				case "wrong-scope":
					key.scopes = []string{"write:workflow"}
				case "revoked":
					base.tx.missing = true
				case "expired":
					base.tx.expired = true
				}
				name, args := "get_workspace_email_preferences", "{}"
				if save {
					name, args = "save_workspace_email_preferences", `{"expected_revision":7,"locale":"sv"}`
				}
				response := serviceEmailCall(t, server, key, name, args)
				if mode == "valid" {
					if response.Error != nil || decodedToolResult(t, response).IsError || len(base.calls) != 1 {
						t.Fatal("native admitted credential lost", response.Error)
					}
					if save && (fixture.input.ExpectedRevision != 7 || fixture.input.Locale != "sv") {
						t.Fatal("preference input changed")
					}
				} else if (response.Error == nil && !decodedToolResult(t, response).IsError) || len(base.calls) != 0 {
					t.Fatal("refused credential reached settings")
				}
			})
		}
	}
}
