// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package importguard

import (
	"errors"
	"github.com/google/uuid"
	"sync"
	"testing"
)

func TestGlobalAndTenantAdmission(t *testing.T) {
	a := New(2)
	org := uuid.New()
	release, err := a.Acquire(org)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Acquire(org); !errors.Is(err, ErrBusy) {
		t.Fatal("tenant admitted concurrently")
	}
	other, err := a.Acquire(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Acquire(uuid.New()); !errors.Is(err, ErrBusy) {
		t.Fatal("global limit bypassed")
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); release() }()
	}
	wg.Wait()
	again, err := a.Acquire(org)
	if err != nil {
		t.Fatal(err)
	}
	again()
	other()
	if a.active != 0 || len(a.orgs) != 0 {
		t.Fatal("lease leaked")
	}
}

func TestAnonymousSharesBudgetAndLeavesAuthoringCapacity(t *testing.T) {
	a := New(2)
	public, err := a.AcquireAnonymous()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AcquireAnonymous(); !errors.Is(err, ErrBusy) {
		t.Fatal("public concurrency exceeded")
	}
	author, err := a.Acquire(uuid.New())
	if err != nil {
		t.Fatal("public admission consumed authoring capacity", err)
	}
	if _, err := a.Acquire(uuid.New()); !errors.Is(err, ErrBusy) {
		t.Fatal("shared budget exceeded")
	}
	public()
	public()
	replacement, err := a.AcquireAnonymous()
	if err != nil {
		t.Fatal(err)
	}
	replacement()
	author()
	if a.active != 0 || a.anonymous {
		t.Fatal("lease leaked")
	}
}
