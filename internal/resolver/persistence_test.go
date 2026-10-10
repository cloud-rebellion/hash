// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

type failingObservationStore struct{ frozenBindings }

func (s *failingObservationStore) StageVariableBindingError(context.Context, generated.UpdateVariableBindingErrorParams) error {
	return errors.New("private database diagnostic")
}
func (s *failingObservationStore) StageVariableBindingResolved(context.Context, generated.UpdateVariableBindingResolvedParams) error {
	return errors.New("private database diagnostic")
}

type observationSource struct{ failure bool }

func (s observationSource) Kind() SourceKind { return SourceKind("crm.deal") }
func (s observationSource) Fetch(context.Context, Ref) (string, error) {
	if s.failure {
		return "", ErrNotFound
	}
	return "current CRM value", nil
}

func TestPreviewDoesNotRequireStagingAndFreezeRefusesUnstagedObservations(t *testing.T) {
	for _, mode := range []string{"source", "cached", "source-error", "unregistered"} {
		t.Run(mode, func(t *testing.T) {
			doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New()}
			binding := &generated.DocumentVariableBinding{DocumentID: doc.ID, VariableName: "amount", SourceKind: "crm.deal", SourceRef: "42", SourcePath: "amount", Fallback: "fallback"}
			r := New(nil, observationSource{failure: mode == "source-error"})
			r.Q = &failingObservationStore{frozenBindings{bindings: []*generated.DocumentVariableBinding{binding}}}
			if mode == "unregistered" {
				binding.SourceKind = "missing"
			}
			key := sourceCacheKey(doc.OrgID, binding.SourceKind, binding.SourceRef, binding.SourcePath)
			if mode == "cached" {
				r.Cache.put(key, "cached value")
			}
			values, report, err := r.Resolve(context.Background(), doc, ResolveOptions{})
			if err != nil || values == nil || len(report) != 1 {
				t.Fatalf("resolution returned values=%v report=%v err=%v", values, report, err)
			}
			frozen, _, err := r.FreezeForSend(context.Background(), doc)
			if !errors.Is(err, ErrBindingPersistence) || frozen != nil {
				t.Fatal("send freeze accepted unpersisted observation")
			}
		})
	}
}

func TestPreviewSourceFailureUsesFallbackWithoutRecording(t *testing.T) {
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New()}
	store := &frozenBindings{bindings: []*generated.DocumentVariableBinding{{DocumentID: doc.ID, VariableName: "amount", SourceKind: "crm.deal", Fallback: "agreed fallback"}}}
	r := New(nil, observationSource{failure: true})
	r.Q = store
	values, report, err := r.Resolve(context.Background(), doc, ResolveOptions{})
	if err != nil || values["amount"] != "agreed fallback" || report[0].ResolvedFrom != "fallback" || store.writes != 0 {
		t.Fatalf("values=%v report=%v writes=%d err=%v", values, report, store.writes, err)
	}
}

// An ordinary database reader deliberately lacks the staging contract.
type readOnlyBindings struct {
	bindings []*generated.DocumentVariableBinding
}

func (s readOnlyBindings) ListVariableBindings(context.Context, uuid.UUID) ([]*generated.DocumentVariableBinding, error) {
	return s.bindings, nil
}

func TestFreezeRequiresExplicitStagingAdapterAndFreshCRM(t *testing.T) {
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New()}
	binding := &generated.DocumentVariableBinding{DocumentID: doc.ID, VariableName: "amount", SourceKind: "crm.deal", SourceRef: "42", SourcePath: "amount", Fallback: "old amount"}
	r := New(nil, observationSource{})
	r.Q = readOnlyBindings{bindings: []*generated.DocumentVariableBinding{binding}}
	if values, _, err := r.Resolve(context.Background(), doc, ResolveOptions{}); err != nil || values["amount"] != "current CRM value" {
		t.Fatalf("read preview values=%v err=%v", values, err)
	}
	if frozen, _, err := r.FreezeForSend(context.Background(), doc); !errors.Is(err, ErrBindingPersistence) || frozen != nil {
		t.Fatalf("unstaged freeze accepted: %s err=%v", frozen, err)
	}
	if _, ok := any((*generated.Queries)(nil)).(ObservationStager); ok {
		t.Fatal("ordinary DB queries can accidentally stage/persist resolver observations")
	}
	r.Q = &frozenBindings{bindings: []*generated.DocumentVariableBinding{binding}}
	r.Sources[SourceCRMDeal] = observationSource{failure: true}
	if frozen, _, err := r.FreezeForSend(context.Background(), doc); !errors.Is(err, ErrSourceFreshness) || frozen != nil {
		t.Fatalf("cached CRM/fallback accepted for send: %s err=%v", frozen, err)
	}
}
