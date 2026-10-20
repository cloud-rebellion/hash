// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"sync"
	"testing"
	"time"
)

// This test exercises the actual Parent grant/borrower/Close protocol only.
// The source shells are deliberately invalid SQL authority; production input
// is available solely through a genuine Source24 SDK callback. The original
// actual manual PDF journey qualifies the isolated worker and native rows.
func TestHistoricalManualOriginalAliasAndCopiedCloseJoinV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 1024}, Organisation: workguard.VectorV1{ParentBytes: 1024}, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	input := &ApplicationHistoricalManualPDFSourceV1{raw: []byte("actual original alias"), active: true}
	input.self = input
	m := &ApplicationHistoricalFinalizationManualPDFV1{input: input, originalAlias: true, pdf: input.raw, coordinator: coordinator, ctx: ctx, org: org}
	m.self = m
	input.result = m
	if err = m.acquireV1(0, 64); err != nil {
		t.Fatal(err)
	}
	if err = m.acquireV1(6, 128); err != nil {
		t.Fatal(err)
	}
	entered, finish, returned := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		returned <- m.WithPDFV1(func(raw []byte) error {
			if string(raw) != "actual original alias" {
				t.Error("original alias changed")
			}
			close(entered)
			<-finish
			return nil
		})
	}()
	<-entered
	copied := m
	copied.CloseConsumerV1()
	m.CloseConsumerV1()
	snapshot := coordinator.SnapshotV1(org)
	if snapshot.Global.ParentBytes != 192 || snapshot.GlobalGrants != 2 {
		t.Fatal("live actual PDF consumer lost Parent debt", snapshot)
	}
	sourceStarted, sourceJoined := make(chan struct{}), make(chan struct{})
	go func() { close(sourceStarted); input.finishSourceCallbackV1(); close(sourceJoined) }()
	<-sourceStarted
	select {
	case <-sourceJoined:
		t.Fatal("SDK callback retired before original PDF borrower joined")
	default:
	}
	close(finish)
	if err = <-returned; err != nil {
		t.Fatal(err)
	}
	<-sourceJoined
	snapshot = coordinator.SnapshotV1(org)
	if snapshot.Global.ParentBytes != 0 || snapshot.GlobalGrants != 0 {
		t.Fatal("actual borrower/Close did not drain", snapshot)
	}
	if err = m.WithPDFV1(func([]byte) error { t.Fatal("closed original input reused"); return nil }); err == nil {
		t.Fatal("expired input accepted")
	}
}
func TestHistoricalManualConcurrentRefusalAndCloseDrainV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 1024}, Organisation: workguard.VectorV1{ParentBytes: 1024}, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		input := &ApplicationHistoricalManualPDFSourceV1{active: false}
		input.self = input
		m := &ApplicationHistoricalFinalizationManualPDFV1{input: input, originalAlias: true, coordinator: coordinator, ctx: ctx, org: org}
		m.self = m
		input.result = m
		if err = m.acquireV1(0, 64); err != nil {
			t.Fatal(err)
		}
		var joined sync.WaitGroup
		joined.Add(3)
		go func() {
			defer joined.Done()
			_ = m.WithPDFV1(func([]byte) error { t.Error("expired source produced PDF"); return nil })
		}()
		go func() { defer joined.Done(); m.CloseConsumerV1() }()
		go func() { defer joined.Done(); input.finishSourceCallbackV1() }()
		joined.Wait()
		snapshot := coordinator.SnapshotV1(org)
		if snapshot.Global.ParentBytes != 0 || snapshot.GlobalGrants != 0 {
			t.Fatalf("iteration%d pending actual Parent: %+v", i, snapshot)
		}
	}
}
