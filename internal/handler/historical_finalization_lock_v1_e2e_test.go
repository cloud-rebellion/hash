//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"errors"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"testing"
)

func TestHistoricalFinalizationNativeSerializationV1E2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	factory := q.runtime.SessionsV1()
	before, err := q.runtime.SnapshotV1(f.org)
	if err != nil {
		t.Fatal(err)
	}
	pendingBefore := factory.PendingV1()
	first, err := factory.NewHistoricalFinalizationLockV1(f.ctx, f.org, f.doc.ID)
	if err != nil {
		t.Fatal("actual native advisory lock", err)
	}
	defer func() {
		if err := first.CloseV1(f.ctx); err != nil {
			t.Error(err)
		}
	}()
	if err = first.VerifyV1(f.ctx); err != nil {
		t.Fatal("same dedicated backend verification", err)
	}
	held, err := q.runtime.SnapshotV1(f.org)
	if err != nil {
		t.Fatal(err)
	}
	pendingHeld := factory.PendingV1()
	if held.Global.SQLSessions != before.Global.SQLSessions+1 || held.Organisation.SQLSessions != before.Organisation.SQLSessions+1 || held.Global.ParentBytes <= before.Global.ParentBytes || pendingHeld.WorkSessions != pendingBefore.WorkSessions+1 {
		t.Fatal("actual lock connection/body is not charged to same runtime/organization")
	}
	second, err := factory.NewHistoricalFinalizationLockV1(f.ctx, f.org, f.doc.ID)
	if second != nil || !errors.Is(err, pdfadmission.ErrHistoricalFinalizationBusyV1) {
		t.Fatalf("concurrent same-document finalizer acquired serialization: owner=%v err=%v", second != nil, err)
	}
	afterBusy, err := q.runtime.SnapshotV1(f.org)
	if err != nil {
		t.Fatal(err)
	}
	if held.Global != afterBusy.Global || held.Organisation != afterBusy.Organisation || held.GlobalGrants != afterBusy.GlobalGrants || held.OrganisationGrants != afterBusy.OrganisationGrants || pendingHeld != factory.PendingV1() {
		t.Fatal("refused real advisory contender leaked native SQL/body ownership")
	}
	copy := *first
	if err = copy.CloseV1(f.ctx); err != nil {
		t.Fatal("joined physical lock close", err)
	}
	if err = first.VerifyV1(f.ctx); !errors.Is(err, pdfadmission.ErrHistoricalFinalizationLockV1) {
		t.Fatal("copied closed shell retained lock authority", err)
	}
	afterClose, err := q.runtime.SnapshotV1(f.org)
	if err != nil {
		t.Fatal(err)
	}
	if before.Global != afterClose.Global || before.Organisation != afterClose.Organisation || before.GlobalGrants != afterClose.GlobalGrants || before.OrganisationGrants != afterClose.OrganisationGrants || pendingBefore != factory.PendingV1() {
		t.Fatal("lock retirement did not return to actual original vector/pending baseline")
	}
	retry, err := factory.NewHistoricalFinalizationLockV1(f.ctx, f.org, f.doc.ID)
	if err != nil {
		t.Fatal("actual same-document retry remains locked after real close", err)
	}
	if err = retry.VerifyV1(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err = retry.CloseV1(f.ctx); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
}
