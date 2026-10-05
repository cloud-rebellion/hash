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

func (s *failingObservationStore) UpdateVariableBindingError(context.Context, generated.UpdateVariableBindingErrorParams) error {
	return errors.New("private database diagnostic")
}
func (s *failingObservationStore) UpdateVariableBindingResolved(context.Context, generated.UpdateVariableBindingResolvedParams) error {
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

func TestResolverRefusesUnpersistedObservations(t *testing.T) {
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
			if !errors.Is(err, ErrBindingPersistence) || values != nil || report != nil {
				t.Fatalf("resolution returned values=%v report=%v err=%v", values, report, err)
			}
			if mode != "cached" {
				if _, hit := r.Cache.get(key); hit {
					t.Fatal("unpersisted value cached")
				}
			}
			frozen, _, err := r.FreezeForSend(context.Background(), doc)
			if !errors.Is(err, ErrBindingPersistence) || frozen != nil {
				t.Fatal("send freeze accepted unpersisted observation")
			}
		})
	}
}

func TestResolverSourceFailureKeepsRecordedFallback(t *testing.T) {
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New()}
	store := &frozenBindings{bindings: []*generated.DocumentVariableBinding{{DocumentID: doc.ID, VariableName: "amount", SourceKind: "crm.deal", Fallback: "agreed fallback"}}}
	r := New(nil, observationSource{failure: true})
	r.Q = store
	values, report, err := r.Resolve(context.Background(), doc, ResolveOptions{})
	if err != nil || values["amount"] != "agreed fallback" || report[0].ResolvedFrom != "fallback" || store.writes != 1 {
		t.Fatalf("values=%v report=%v writes=%d err=%v", values, report, store.writes, err)
	}
}
