//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Use the same real process/session boundary as the HTTP application. Merely
// constructing an Engine and RecipientContext no longer admits a mutation.
func signingWorkRuntimeE2E(t *testing.T, pool *pgxpool.Pool) *pdfadmission.WorkRuntimeV1 {
	t.Helper()
	limits := workguard.LimitsV1{
		Global:       workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 2},
		Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 2},
		MaxGrants:    128, MaxOrganisationGrants: 64,
	}
	runtime, err := pdfadmission.NewWorkRuntimeV1(pool, limits, int64(pool.Config().MaxConns)+8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		observers := runtime.SessionsV1().PendingV1().ObserverSessions
		err := runtime.CloseV1(ctx)
		pending := runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.SignerScopes != 0 || pending.SignerReaders != 0 || pending.DocumentPackageOperations != 0 || pending.ObserverSessions != observers {
			t.Errorf("signing fixture retained non-observer work: %+v", pending)
		}
		if observers > 0 && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Errorf("signing fixture observer cleanup debt falsely resolved: %v", err)
		} else if observers == 0 && err != nil {
			t.Error("close actual signing fixture runtime", err)
		}
		// An unused synthetic scope observes the complete global allocation;
		// it never grants SQL or document authority to this fixture.
		snapshot, snapshotErr := runtime.SnapshotV1(uuid.New())
		if snapshotErr != nil || snapshot.Global != (workguard.VectorV1{SQLSessions: int64(observers)}) || snapshot.GlobalGrants != int64(observers) {
			t.Errorf("signing fixture leaked work or lost observer debt: %+v error=%v", snapshot, snapshotErr)
		}
	})
	return runtime
}

func bindSigningWorkRuntimeE2E(t *testing.T, engine *Engine) {
	t.Helper()
	if engine.WorkRuntime == nil {
		engine.WorkRuntime = signingWorkRuntimeE2E(t, engine.Pool)
	}
	if err := engine.InitializeWorkRuntimeV1(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := engine.CloseWorkRuntimeRequestsV1(ctx); err != nil {
			t.Error("close actual signing request journal", err)
		}
	})
}

func lookupSigningViewE2E(t *testing.T, ctx context.Context, engine *Engine, tokenHash []byte) *RecipientContext {
	t.Helper()
	rc, err := engine.LookupSignerViewByTokenV1(ctx, tokenHash)
	if err != nil {
		t.Fatal("look up actual owned signing view", err)
	}
	t.Cleanup(func() {
		if err := rc.CloseReadV1(); err != nil {
			t.Error("close actual signing fixture view", err)
		}
	})
	return rc
}
