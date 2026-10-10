// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

type frozenBindings struct {
	bindings []*generated.DocumentVariableBinding
	writes   int
}

func (s *frozenBindings) ListVariableBindings(context.Context, uuid.UUID) ([]*generated.DocumentVariableBinding, error) {
	return s.bindings, nil
}
func (s *frozenBindings) StageVariableBindingError(context.Context, generated.UpdateVariableBindingErrorParams) error {
	s.writes++
	return nil
}
func (s *frozenBindings) StageVariableBindingResolved(context.Context, generated.UpdateVariableBindingResolvedParams) error {
	s.writes++
	return nil
}

type forbiddenFrozenSource struct{ t *testing.T }

func (s forbiddenFrozenSource) Kind() SourceKind { return SourceKind("crm.deal") }
func (s forbiddenFrozenSource) Fetch(context.Context, Ref) (string, error) {
	s.t.Fatal("frozen render fetched live source")
	return "", nil
}

func TestFrozenResolutionUsesSnapshotInsteadOfMutableBindingValues(t *testing.T) {
	store := &frozenBindings{bindings: []*generated.DocumentVariableBinding{
		{VariableName: "amount", SourceKind: "crm.deal", LastValue: "999", Fallback: "fallback"},
		{VariableName: "empty", SourceKind: "crm.deal", LastValue: "changed", Fallback: "fallback"},
		{VariableName: "unset", SourceKind: "crm.deal", LastValue: "new", Fallback: "fallback"},
	}}
	r := New(nil, forbiddenFrozenSource{t})
	r.Q = store
	doc := &generated.Document{ID: uuid.New(), VariablesJson: json.RawMessage(`{"amount":"100","empty":"","static":"unchanged"}`)}
	for _, binding := range store.bindings {
		binding.DocumentID = doc.ID
	}
	values, report, err := r.Resolve(context.Background(), doc, ResolveOptions{FreezeMode: true})
	if err != nil {
		t.Fatal(err)
	}
	if values["amount"] != "100" || values["empty"] != "" || values["static"] != "unchanged" {
		t.Fatalf("snapshot changed: %v", values)
	}
	if _, present := values["empty"]; !present {
		t.Fatal("empty frozen value lost")
	}
	if _, present := values["unset"]; present {
		t.Fatal("mutable fallback introduced value absent at freeze")
	}
	if store.writes != 0 {
		t.Fatal("frozen render wrote binding")
	}
	if len(report) != 3 || report[0].Value != "100" {
		t.Fatalf("report=%v", report)
	}
	for _, entry := range report {
		if entry.ResolvedFrom != "frozen" {
			t.Fatalf("report source=%s", entry.ResolvedFrom)
		}
	}
}

func TestFrozenResolutionRejectsAgentOverride(t *testing.T) {
	r := New(nil)
	r.Q = &frozenBindings{}
	values, _, err := r.Resolve(context.Background(), &generated.Document{VariablesJson: json.RawMessage(`{"amount":"100"}`)}, ResolveOptions{FreezeMode: true, AgentOverrides: map[string]string{"amount": "999"}})
	if err == nil || values != nil {
		t.Fatal("frozen override accepted")
	}
}
