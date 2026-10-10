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

type emptyValueSource struct{ calls int }

func (s *emptyValueSource) Kind() SourceKind                           { return SourceKind("crm.deal") }
func (s *emptyValueSource) Fetch(context.Context, Ref) (string, error) { s.calls++; return "", nil }

func TestResolverPreservesSuccessfulEmptySourceAndCacheValue(t *testing.T) {
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), VariablesJson: json.RawMessage(`{"contact":"old contact"}`)}
	store := &frozenBindings{bindings: []*generated.DocumentVariableBinding{{DocumentID: doc.ID, VariableName: "contact", SourceKind: "crm.deal", Fallback: "fallback contact"}}}
	source := &emptyValueSource{}
	r := New(nil, source)
	r.Q = store
	for _, expectedSource := range []string{"source", "cached"} {
		values, report, err := r.Resolve(context.Background(), doc, ResolveOptions{})
		if err != nil {
			t.Fatal(err)
		}
		value, present := values["contact"]
		if !present || value != "" || len(report) != 1 || report[0].ResolvedFrom != expectedSource {
			t.Fatalf("values=%v report=%v", values, report)
		}
	}
	if source.calls != 1 || store.writes != 0 {
		t.Fatalf("fetches=%d writes=%d", source.calls, store.writes)
	}
	frozen, _, err := r.FreezeForSend(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]string
	if err = json.Unmarshal(frozen, &values); err != nil {
		t.Fatal(err)
	}
	if value, present := values["contact"]; !present || value != "" {
		t.Fatalf("frozen=%s", frozen)
	}
}
