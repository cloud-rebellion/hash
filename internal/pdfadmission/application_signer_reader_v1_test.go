// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"reflect"
	"testing"
	"time"
)

// These tests exercise actual shared coordinator accounting, not physical SQL
// retirement or authority. Public owner shells must remain unusable.
func TestSignerReadBodyAndGlobalProbeShareActualCapacityV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := htmlAuthoringResourcesV1(123, 456)
	if err != nil {
		t.Fatal(err)
	}
	limit := workguard.VectorV1{ParentBytes: r.WorkingBytes, DBStagingBytes: r.DBStagingBytes, SQLSessions: 2}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	work, err := NewWorkAdmissionV1(c)
	if err != nil {
		t.Fatal(err)
	}
	global, err := work.signerProcessHeaderV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer global()
	org := uuid.New()
	b := ApplicationBudgetV1{Phase: "locked-signer-read-body", OrgID: org, DocumentID: uuid.New(), HTMLAuthoringRawBytes: 123, HTMLAuthoringWireBytes: 456, WorkingBytes: r.WorkingBytes, DBStagingBytes: r.DBStagingBytes}
	if close, err := work.ApplicationV1(ctx, b); err == nil || close != nil {
		if close != nil {
			close()
		}
		t.Fatal("reader bypassed held global probe bytes")
	}
	global()
	close, err := work.ApplicationV1(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	if got := c.SnapshotV1(org); got.Global.ParentBytes != r.WorkingBytes || got.Organisation.ParentBytes != r.WorkingBytes || got.ActiveOrganisations != 1 {
		t.Fatal("reader not charged to same authentic tenant/global vector")
	}
	if next, err := work.signerProcessHeaderV1(ctx); err == nil || next != nil {
		if next != nil {
			next()
		}
		t.Fatal("global probe bypassed retained reader body")
	}
	close()
	if got := c.SnapshotV1(org); got.GlobalGrants != 0 || got.ActiveOrganisations != 0 {
		t.Fatal("pure accounting fixture retained work")
	}
}
func TestSignerReadFixedPhaseCannotUnderpriceOrBorrowForeignFieldsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, _ := htmlAuthoringResourcesV1(10, 20)
	limit := workguard.VectorV1{ParentBytes: r.WorkingBytes, DBStagingBytes: r.DBStagingBytes}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	w, _ := NewWorkAdmissionV1(c)
	b := ApplicationBudgetV1{Phase: "locked-signer-read-body", OrgID: uuid.New(), DocumentID: uuid.New(), HTMLAuthoringRawBytes: 10, HTMLAuthoringWireBytes: 20, WorkingBytes: r.WorkingBytes, DBStagingBytes: r.DBStagingBytes}
	for _, bad := range []ApplicationBudgetV1{func() ApplicationBudgetV1 { x := b; x.WorkingBytes--; return x }(), func() ApplicationBudgetV1 { x := b; x.DBStagingBytes--; return x }(), func() ApplicationBudgetV1 { x := b; x.RecipientID = uuid.New(); return x }(), func() ApplicationBudgetV1 { x := b; x.HTMLInputRawBytes = 1; return x }(), func() ApplicationBudgetV1 { x := b; x.Phase = "locked-signer-read-header"; return x }()} {
		if close, err := w.ApplicationV1(ctx, bad); err == nil || close != nil {
			if close != nil {
				close()
			}
			t.Fatal("changed fixed signer loan accepted")
		}
	}
}
func TestSignerReaderRequiresActualFactoryScopeAndOwnerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, f := range []*ApplicationSessionFactoryV1{nil, {}} {
		if scope, err := f.ProbeSignerScopeV1(ctx, make([]byte, 32)); err == nil || scope != nil {
			t.Fatal("factory shell dispatched unscoped SQL")
		}
		if reader, err := f.NewSignerReaderV1(ctx, &ApplicationSignerScopeV1{}, SignerReadActiveV1); err == nil || reader != nil {
			t.Fatal("scope shell created tenant reader")
		}
	}
	var reader *ApplicationSignerReaderV1
	if err := reader.WithModelsV1(ctx, func(ApplicationSignerReadAccessV1) error { return nil }, func(context.Context, *ApplicationSignerReadModelsV1) error { return nil }); err == nil {
		t.Fatal("nil reader supplied models")
	}
	reader.CloseConsumerV1()
	if err := (&ApplicationSignerReaderV1{}).CloseV1(ctx); err == nil {
		t.Fatal("empty reader shell fabricated actual cleanup")
	}
}

func TestCopiedSignerReaderCannotCloseOriginalConsumersV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	closed := 0
	// Bookkeeping-only, explicitly NOT a native session/admission fixture. This
	// reproduces copying an exported opaque reader before any mutex use without
	// authorizing actual SQL, retirement, or work release.
	original := &ApplicationSignerReaderV1{consumers: []func(){func() { closed++ }}}
	original.self = original
	copied := &ApplicationSignerReaderV1{}
	reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(original).Elem())
	copied.CloseConsumerV1()
	if closed != 0 || original.consumerClosed {
		t.Fatal("copied handle ended original live result consumers")
	}
	if err := copied.CloseV1(ctx); err == nil {
		t.Fatal("copied handle fabricated physical cleanup")
	}
	if err := copied.CommitReadV1(ctx); err == nil {
		t.Fatal("copied handle dispatched read commit")
	}
}
