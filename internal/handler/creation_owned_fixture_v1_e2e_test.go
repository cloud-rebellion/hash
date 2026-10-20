//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// This is explicit preparation of the one existing legacy pro catalog source
// in this disposable fixture. The actual controlled native M95 owner admits
// its stored/uncompressed source before expansion and returns an acknowledged
// intrinsic receipt only after its own physical native backend retires. It is
// neither a target-route fallback nor SQL cache insertion/read repair.
func ownedCreationPrepareProPlanV1(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	var plan uuid.UUID
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT id FROM billing_plans WHERE slug='pro'").Scan(&plan); err != nil || plan == uuid.Nil {
		t.Fatal("scalar actual operator plan identity unavailable", err)
	} //nolint:rawsql -- fixed scalar fixture identity only, no body/cache expansion
	owner, err := q.runtime.SessionsV1().ControlledMeasurePlanSourceV1(q.f.ctx, plan)
	if owner != nil {
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := owner.CloseV1(cleanup); err != nil {
				t.Error("actual M95 preparation cleanup", err)
			}
		})
	}
	if err != nil || owner == nil {
		t.Fatal("explicit actual M95 source preparation failed", err)
	}
	receipt, err := owner.ReceiptV1()
	if err != nil || receipt.Kind != "plan" || receipt.SourceID != plan || receipt.OrgID != uuid.Nil || receipt.WireBytes <= 0 || receipt.ServerVersionNum != 160015 || !receipt.CreatedAt.Valid || !receipt.MeasuredAt.Valid {
		t.Fatal("genuine M95 preparation lacks exact acknowledged receipt", err)
	}
	owner.CloseConsumerV1()
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := owner.CloseV1(cleanup); err != nil {
		t.Fatal("actual M95 source owner did not close", err)
	}
	if err := owner.CloseV1(cleanup); err != nil {
		t.Fatal("actual M95 source close not idempotent", err)
	}
	// Template/creation work had one tenant observer. Explicit process catalog
	// maintenance genuinely starts the distinct process observer: exactly two.
	ownedCreationAssertDrainedV1(t, q, 2)
}

// Exact creation-fixture recipe, separate from the existing public-signer
// helper. Native tenant authoring starts one real tenant observer. Explicit
// process catalog preparation or signer lookup starts its second observer.
// Counts below are expectations from those operations, never learned from a
// failing Pending snapshot or used as a fabricated backend retirement proof.
func ownedCreationAssertDrainedV1(t *testing.T, q *ownedPublicReadFixtureV1, observers int) {
	t.Helper()
	if observers != 1 && observers != 2 {
		t.Fatal("unsupported exact owned creation observer recipe")
	}
	q.reconcileV1(t)
	p := q.runtime.SessionsV1().PendingV1()
	if p.WorkSessions != 0 || p.UnknownStarts != 0 || p.HTMLAdmissions != 0 || p.HTMLInputProducers != 0 || p.HTMLCanonicalConsumers != 0 || p.SignerScopes != 0 || p.SignerReaders != 0 || p.CatalogMaintenance != 0 || p.DocumentPackageOperations != 0 || p.ObserverSessions != observers || p.Closing {
		t.Fatalf("actual creation work remains or exact observer recipe differs: %+v wantObservers=%d", p, observers)
	}
	s, err := q.runtime.SnapshotV1(q.f.org)
	expectedGlobal := workguard.VectorV1{SQLSessions: int64(observers)}
	expectedOrg := workguard.VectorV1{SQLSessions: 1}
	if err != nil || s.Global != expectedGlobal || s.GlobalGrants != int64(observers) || s.Organisation != expectedOrg || s.OrganisationGrants != 1 {
		t.Fatalf("actual creation observer-only vector differs: %+v err=%v wantObservers=%d", s, err, observers)
	}
	global, err := q.runtime.SnapshotV1(uuid.Nil)
	if err != nil || global.Global != s.Global || global.GlobalGrants != s.GlobalGrants || global.Organisation != (workguard.VectorV1{}) || global.OrganisationGrants != 0 || global.ActiveOrganisations != s.ActiveOrganisations {
		t.Fatal("creation global observation invented tenant or coordinator", global, err)
	}
	// Reconciliation repeats only the original physical cleanup; it cannot
	// manufacture another consumer last use or credit an unrelated transaction.
	q.reconcileV1(t)
	again, err := q.runtime.SnapshotV1(q.f.org)
	if err != nil || again != s {
		t.Fatal("repeated actual creation cleanup changed observer-only debt", again, err)
	}
}
