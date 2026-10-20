// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// These constructor/identity checks perform no SQL and establish no business
// authority. Actual session/body retirement is tested by the genuine PG route.
func TestHTMLSendScopedCloseRequiresOriginalOwnerAndBoundedContextV1(t *testing.T) {
	coordinator, work := applicationSessionResourcesTestV1(t, 2)
	factory, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	op, err := factory.NewHTMLSendOperationV1(ctx, org, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if err := (*ApplicationHTMLSendOperationV1)(nil).CloseV1(ctx); err != nil {
		t.Fatal("nil close is not idempotent", err)
	}
	if err := (&ApplicationHTMLSendOperationV1{}).CloseV1(ctx); !errors.Is(err, ErrHTMLSendWorkV1) {
		t.Fatal("zero shell gained close authority")
	}
	// A shell referencing the real identity cannot close the real owner.
	shell := &ApplicationHTMLSendOperationV1{self: op}
	if err := shell.CloseV1(ctx); !errors.Is(err, ErrHTMLSendWorkV1) || op.closed {
		t.Fatal("foreign shell closed the original operation")
	}
	for _, invalid := range []context.Context{nil, context.Background()} {
		if err := op.CloseV1(invalid); !errors.Is(err, ErrHTMLSendWorkV1) || op.closed {
			t.Fatal("unbounded close changed original ownership")
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := op.CloseV1(canceled); !errors.Is(err, ErrHTMLSendWorkV1) || op.closed {
		t.Fatal("canceled close changed original ownership")
	}
	if err := op.CloseV1(ctx); err != nil || !op.closed {
		t.Fatal("unused actual constructor owner did not close", err)
	}
	if err := op.CloseV1(ctx); err != nil {
		t.Fatal("same-owner cleanup retry replayed or failed", err)
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 || factory.PendingV1().WorkSessions != 0 {
		t.Fatal("metadata-only close created resource or SQL authority", got)
	}
}

// Ending the logical consumer must not need a fresh cleanup deadline, grant
// physical retirement, or let a shell end another operation. This constructor
// test performs no SQL; actual JSON/backend debt is covered by the PG route.
func TestHTMLSendEndConsumerBeforeExpiredPhysicalCleanupV1(t *testing.T) {
	coordinator, work := applicationSessionResourcesTestV1(t, 2)
	factory, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	op, err := factory.NewHTMLSendOperationV1(ctx, org, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	(*ApplicationHTMLSendOperationV1)(nil).EndConsumerV1()
	(&ApplicationHTMLSendOperationV1{}).EndConsumerV1()
	(&ApplicationHTMLSendOperationV1{self: op}).EndConsumerV1()
	if op.closed {
		t.Fatal("foreign shell ended the actual consumer")
	}
	expired, stop := context.WithCancel(ctx)
	stop()
	op.EndConsumerV1()
	op.EndConsumerV1()
	if err := op.CloseV1(expired); !errors.Is(err, ErrHTMLSendWorkV1) || !op.closed || ctx.Err() != nil {
		t.Fatal("expired physical cleanup lost logical closure or canceled the original request", err)
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 || factory.PendingV1().WorkSessions != 0 {
		t.Fatal("logical closure created resource or physical SQL authority", got)
	}
}
