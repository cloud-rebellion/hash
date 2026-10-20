// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ai

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This normal-test owner exercises actual logical grants and the real pure
// producers only. It provides no SQL, durable event, M94 or application authority.
type workflowBudget295 struct {
	grant       *workguard.GrantV1
	coordinator *workguard.CoordinatorV1
	org         uuid.UUID
}

func newWorkflowBudget295(t *testing.T, limit int64) (context.Context, *workflowBudget295) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	org := uuid.New()
	c, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: limit}, Organisation: workguard.VectorV1{ParentBytes: limit}, MaxGrants: 2, MaxOrganisationGrants: 2})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	owner := &workflowBudget295{grant: grant, coordinator: c, org: org}
	t.Cleanup(grant.Close)
	return WithNativeWorkflowV1(ctx, owner), owner
}
func (o *workflowBudget295) RetainV1(ctx context.Context, n int64) error {
	return o.grant.TryGrowParentV1(ctx, n)
}
func (o *workflowBudget295) ParseTreeV1(_ context.Context, raw []byte) (*blocks.Tree, error) {
	return blocks.ParseTree(raw)
}
func (o *workflowBudget295) ReadRecipientNamesV1(context.Context, uuid.UUID) ([]string, error) {
	return nil, ErrNativeWorkflowV1
}
func (o *workflowBudget295) ReadOrganizationProviderV1(context.Context, uuid.UUID) (*generated.OrgAiSetting, error) {
	return nil, ErrNativeWorkflowV1
}
func (o *workflowBudget295) WrapProviderV1(context.Context, Provider) (Provider, error) {
	return nil, ErrNativeWorkflowV1
}
func (o *workflowBudget295) PrepareUsageV1(context.Context, string, string, string, int) error {
	return ErrNativeWorkflowV1
}
func (o *workflowBudget295) ObserveUsageV1(context.Context, *CompletionObservationV1) error {
	return ErrNativeWorkflowV1
}

func TestNativeBuiltinPromptUsesActualOriginalTemplate295(t *testing.T) {
	ctx, owner := newWorkflowBudget295(t, 64<<20)
	registry := NewPromptRegistry()
	input := map[string]string{"Locale": "sv-SE", "ClauseText": "Payment € ö", "SurroundingContext": "other", "LegalContext": "references", "Question": "why?", "OriginalClause": "A&B <text>", "Concern": "due date", "RedLines": "- retain date", "LangA": "sv", "LangB": "en", "ClauseA": "A", "ClauseB": "B", "BlocksJSON": "{\"id\":\"body\",\"text\":\"Ä\"}", "SenderContext": "SaaS"}
	for _, name := range []string{"signer_clarifier", "negotiation_counter", "bilingual_equivalence", "risk_analyzer"} {
		prompt, err := registry.Get(name, 0)
		if err != nil {
			t.Fatal(err)
		}
		original, err := prompt.Render(input)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := RenderPromptV1(ctx, prompt, input)
		if err != nil || !reflect.DeepEqual(actual, original) {
			t.Fatal(name, "original prompt wire changed", err)
		}
	}
	if owner.coordinator.SnapshotV1(owner.org).Global.ParentBytes <= 4096 {
		t.Fatal("actual prompt expansions were uncharged")
	}
	owner.grant.Close()
	if owner.coordinator.SnapshotV1(owner.org).GlobalGrants != 0 {
		t.Fatal("prompt consumer did not retire")
	}
}
func TestNativeShieldMatchesOriginalSequentialProducers295(t *testing.T) {
	ctx, owner := newWorkflowBudget295(t, 128<<20)
	raw, err := NewLocalShield(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	shield := raw.(*LocalShield)
	in := "Jane Andersson sends jane@example.test with IBAN SE4550000000058398257466 and +46 70 123 45 67; personnummer 850101-1234; Åsa."
	known := []string{"Jane", "Jane Andersson", "Åsa", "email", "shield", "name", "Jane"}
	old, oldHandle, err := shield.Tokenize(ctx, in, known...)
	if err != nil {
		t.Fatal(err)
	}
	actual, handle, err := tokenizeForNativeV1(ctx, shield, in, known...)
	if err != nil || actual != old {
		t.Fatal("original sequential tokenization changed", err)
	}
	if !reflect.DeepEqual(handle.(*localHandle).ids, oldHandle.(*localHandle).ids) || !reflect.DeepEqual(handle.(*localHandle).plain, oldHandle.(*localHandle).plain) {
		t.Fatal("original token table/ordering changed")
	}
	response := strings.Repeat(actual+" ", 3)
	want, err := shield.Untokenize(ctx, response, oldHandle)
	if err != nil {
		t.Fatal(err)
	}
	got, err := untokenizeForNativeV1(ctx, shield, response, handle)
	if err != nil || got != want {
		t.Fatal("sequential restoration changed", err)
	}
	owner.grant.Close()
	if owner.coordinator.SnapshotV1(owner.org).GlobalGrants != 0 {
		t.Fatal("Shield consumer did not retire")
	}
}
func TestNativeRestorationRefusesActualExpansionBeforeReplacement295(t *testing.T) {
	ctx, owner := newWorkflowBudget295(t, 16<<20)
	raw, _ := NewLocalShield(make([]byte, 32))
	shield := raw.(*LocalShield)
	plain := strings.Repeat("J", 1024)
	tokenized, handle, err := tokenizeForNativeV1(ctx, shield, plain, plain)
	if err != nil {
		t.Fatal(err)
	}
	if tokenized == plain {
		t.Fatal("actual original known-name token absent")
	}
	response := strings.Repeat(tokenized, 10000)
	old, err := shield.Untokenize(ctx, response, handle)
	if err != nil || len(old) <= len(response) {
		t.Fatal("fixture did not exercise actual restoration amplification", err)
	}
	before := owner.coordinator.SnapshotV1(owner.org).Global.ParentBytes
	got, err := untokenizeForNativeV1(ctx, shield, response, handle)
	if err == nil || got != "" || !errors.Is(err, workguard.ErrUnavailableV1) {
		t.Fatal("uncharged restored output was produced", err)
	}
	if owner.coordinator.SnapshotV1(owner.org).Global.ParentBytes != before {
		t.Fatal("denied expansion changed retained debt")
	}
}
func TestCompletionObservationRejectsForeignOwnerOrOrigin295(t *testing.T) {
	ctx, owner := newWorkflowBudget295(t, 1<<20)
	other, foreign := newWorkflowBudget295(t, 1<<20)
	params := generated.InsertAICompletionAuditParams{OrgID: owner.org, Provider: "mistral", Model: "actual", InputTokens: 23, OutputTokens: 11, Success: true}
	observation := newCompletionObservationV1(ctx, owner, params)
	params.Model = "changed caller shell"
	actual, err := observation.ParamsForV1(owner, ctx)
	if err != nil || actual.Model != "actual" || actual.InputTokens != 23 || actual.OutputTokens != 11 {
		t.Fatal("opaque actual observation changed", err)
	}
	if _, err = observation.ParamsForV1(foreign, other); err == nil {
		t.Fatal("foreign owner adopted observation")
	}
	detached := context.WithoutCancel(ctx)
	if _, err = observation.ParamsForV1(owner, detached); err == nil {
		t.Fatal("detached caller invented observation origin")
	}
}

func TestNativePromptUnsupportedProgramKeepsLegacyRenderButRefusesNative295(t *testing.T) {
	ctx, owner := newWorkflowBudget295(t, 1<<20)
	registry := NewPromptRegistry()
	if err := registry.Register("program", 1, "", "constant", `{{printf "%1000s" .Value}}`, 1); err != nil {
		t.Fatal(err)
	}
	prompt, err := registry.Get("program", 1)
	if err != nil {
		t.Fatal(err)
	}
	original, err := prompt.Render(map[string]string{"Value": "x"})
	if err != nil || len(original.User) != 1000 {
		t.Fatal("original custom renderer changed", err)
	}
	before := owner.coordinator.SnapshotV1(owner.org).Global.ParentBytes
	actual, err := RenderPromptV1(ctx, prompt, map[string]string{"Value": "x"})
	if !errors.Is(err, ErrNativeWorkflowV1) || actual.User != "" {
		t.Fatal("unsupported executable template entered native producer", err)
	}
	if owner.coordinator.SnapshotV1(owner.org).Global.ParentBytes != before {
		t.Fatal("unsupported profile changed parent debt")
	}
}

func TestNativeCompletionObservationChecksActualIntegerBeforeNarrowing295(t *testing.T) {
	request := Request{PromptVersion: 1}
	if err := nativeCompletionValuesV1(request, Response{InputTokens: 2147483647, OutputTokens: 2147483647}, 2147483647); err != nil {
		t.Fatal("supported exact boundary refused", err)
	}
	for _, value := range []int64{-1, 2147483648, 4294967319} {
		actual := int(value)
		if err := nativeCompletionValuesV1(request, Response{InputTokens: actual}, 0); !errors.Is(err, ErrCompletionAudit) {
			t.Fatal("actual input usage narrowed before validation", value, err)
		}
		if err := nativeCompletionValuesV1(request, Response{OutputTokens: actual}, 0); !errors.Is(err, ErrCompletionAudit) {
			t.Fatal("actual output usage narrowed before validation", value, err)
		}
	}
	if err := nativeCompletionValuesV1(request, Response{}, -1); !errors.Is(err, ErrCompletionAudit) {
		t.Fatal("negative actual latency accepted", err)
	}
}
