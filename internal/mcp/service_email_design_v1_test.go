// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/google/uuid"
)

type serviceEmailProposalFixture760 struct {
	*serviceEmailDelegationFixture
	prompt string
}

func (f *serviceEmailProposalFixture760) Propose(ctx context.Context, actor authoring.Actor, kind string, in emailtemplates.ProposalInput) (emailtemplates.Proposal, error) {
	f.kind, f.input, f.prompt = kind, in.Input, in.Prompt
	if err := f.authorize(ctx, actor, "propose"); err != nil {
		return emailtemplates.Proposal{}, err
	}
	return emailtemplates.Proposal{SchemaVersion: 1, Kind: kind, ExpectedRevision: in.ExpectedRevision, Input: in.Input, Preview: emailtemplates.Preview{SchemaVersion: 1, Synthetic: true, Revision: in.ExpectedRevision, MandatoryContentPreserved: true}, Saved: false}, nil
}

const serviceEmailProposalArgs760 = `{"kind":"email.invite","expected_revision":7,"subject_template":"Hello {{recipient_name}}","html_template":"<p>Intro</p>","text_template":"Intro","design_json":"","prompt":"Use our current workspace brand"}`

func TestServiceEmailDesign760MCPProposalRequiresOriginalOwnerAuthoringCredential(t *testing.T) {
	for _, mode := range []string{"owner", "read-only", "workflow-only", "document", "viewer", "revoked-current-key", "changed-current-scope"} {
		t.Run(mode, func(t *testing.T) {
			_, credential, base := serviceEmailFixture(t)
			fixture := &serviceEmailProposalFixture760{serviceEmailDelegationFixture: base}
			server := NewServer()
			registerServiceEmailToolsWithService(server, fixture)
			tool := server.tools["propose_service_email_design"]
			if tool.MinRole != auth.RoleOwner || !tool.Write || mcpToolRequiredScopes[tool.Name] != mcpScopeWriteAuthoring || tool.InputSchema["additionalProperties"] != false {
				t.Fatal("proposal scope/role/closed input classification changed")
			}
			if _, safe := docScopeSafeTools[tool.Name]; safe {
				t.Fatal("proposal exposed to document token")
			}
			switch mode {
			case "read-only":
				credential.scopes = []string{"read"}
			case "workflow-only":
				credential.scopes = []string{"write:workflow"}
			case "document":
				credential.document = uuid.New()
			case "viewer":
				credential.role = "viewer"
			case "revoked-current-key":
				base.tx.missing = true
			case "changed-current-scope":
				base.tx.scopes = []string{"read"}
			}
			response := serviceEmailCall(t, server, credential, tool.Name, serviceEmailProposalArgs760)
			if mode != "owner" {
				if response.Error == nil && !decodedToolResult(t, response).IsError {
					t.Fatal("proposal accepted unauthorized credential")
				}
				if len(base.calls) != 0 {
					t.Fatal("refused credential reached configured provider service")
				}
				return
			}
			if response.Error != nil {
				t.Fatal(response.Error)
			}
			result := decodedToolResult(t, response)
			if result.IsError || len(base.calls) != 1 || base.calls[0] != "propose" || base.tx.queries != 1 || fixture.prompt != "Use our current workspace brand" || fixture.input.DesignJSON == nil || *fixture.input.DesignJSON != "" || !strings.Contains(result.Content[0].Text, `"saved":false`) || !strings.Contains(result.Content[0].Text, `"synthetic":true`) {
				t.Fatal("proposal skipped native credential, changed input or implicitly saved", result)
			}
		})
	}
}

func TestServiceEmailDesign760MCPProposalRefusesAmbiguousFields(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(serviceEmailProposalArgs760, `,"prompt":"Use our current workspace brand"`, "", 1),
		strings.Replace(serviceEmailProposalArgs760, `"prompt":"Use our current workspace brand"`, `"prompt":null`, 1),
		strings.TrimSuffix(serviceEmailProposalArgs760, "}") + `,"prompt":"second"}`,
		strings.TrimSuffix(serviceEmailProposalArgs760, "}") + `,"provider_key":"forbidden"}`,
		serviceEmailProposalArgs760 + ` {}`,
	} {
		if _, err := exactServiceEmailFieldsV1([]byte(raw), false, true); err == nil {
			t.Fatal("ambiguous proposal fields accepted")
		}
	}
	if _, err := exactServiceEmailArguments([]byte(serviceEmailProposalArgs760), false); err == nil {
		t.Fatal("proposal prompt smuggled into ordinary save")
	}
}

func TestServiceEmailMCPProposalLocaleDoesNotChangePromptV1(t *testing.T) {
	_, v, base := serviceEmailFixture(t)
	fixture := &serviceEmailProposalFixture760{serviceEmailDelegationFixture: base}
	server := NewServer()
	registerServiceEmailToolsWithService(server, fixture)
	args := strings.TrimSuffix(serviceEmailProposalArgs760, "}") + `,"preview_locale":"sv"}`
	result := serviceEmailCall(t, server, v, "propose_service_email_design", args)
	if result.Error != nil || decodedToolResult(t, result).IsError || fixture.input.PreviewLocale == nil || *fixture.input.PreviewLocale != "sv" || fixture.prompt != "Use our current workspace brand" || len(base.calls) != 1 || base.calls[0] != "propose" {
		t.Fatal("proposal synthetic locale changed prompt, authority or operation")
	}
}
