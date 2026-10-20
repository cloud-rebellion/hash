// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func TestPackageRecoveryFactoryWaitsForActualGrantRetirementV1(t *testing.T) {
	c, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 4096, DBStagingBytes: 4096, SQLSessions: 1}, Organisation: workguard.VectorV1{ParentBytes: 4096, DBStagingBytes: 4096, SQLSessions: 1}, MaxGrants: 4, MaxOrganisationGrants: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	g, err := c.TryAcquireProcessV1(ctx, workguard.VectorV1{ParentBytes: 1024, DBStagingBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	done := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	p := &applicationSessionFactoryStateV1{}
	f := &ApplicationSessionFactoryV1{state: p}
	s := &applicationPackageSendRecoveryBatchStateV1{factory: f, closed: true, release: func() {
		close(entered)
		<-release
		g.Close()
	}}
	p.packageRecoveryBatches[0] = s
	go func() {
		defer close(done)
		joined <- f.ReconcileCleanupV1(ctx)
	}()
	defer func() {
		unblock()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("grant-release test producer did not join cleanup")
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("real process grant retirement did not enter")
	}
	if err := f.ReconcileCleanupV1(ctx); !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatal("factory acknowledged a release that has not joined", err)
	}
	if snapshot := c.SnapshotV1(uuid.Nil); snapshot.Global.ParentBytes != 1024 || snapshot.GlobalGrants != 1 {
		t.Fatal("unfinished release credited the actual process grant", snapshot)
	}
	p.mu.Lock()
	registered := p.packageRecoveryBatches[0] == s
	p.mu.Unlock()
	if !registered {
		t.Fatal("unfinished release lost its cleanup registration")
	}
	unblock()
	select {
	case err := <-joined:
		if err != nil {
			t.Fatal("joined release remained unknown", err)
		}
	case <-ctx.Done():
		t.Fatal("actual process grant retirement did not join")
	}
	if err := f.ReconcileCleanupV1(ctx); err != nil {
		t.Fatal("retired batch retained cleanup debt", err)
	}
	if snapshot := c.SnapshotV1(uuid.Nil); snapshot.GlobalGrants != 0 || snapshot.Global.ParentBytes != 0 {
		t.Fatal("actual grant did not retire", snapshot)
	}
}
