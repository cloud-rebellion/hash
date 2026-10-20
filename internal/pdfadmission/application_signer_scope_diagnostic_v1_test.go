// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

type signerScopeObservationHandlerV1 struct {
	slog.Handler
	onRefusal func()
}

func (h signerScopeObservationHandlerV1) Handle(ctx context.Context, row slog.Record) error {
	if row.Message == "owned signer scope refused" {
		h.onRefusal()
	}
	return h.Handler.Handle(ctx, row)
}

func TestSignerScopeRealObserverDenialLogsBeforeActualControlReleaseV1(t *testing.T) {
	v := workguard.VectorV1{ParentBytes: 8 << 20, DBStagingBytes: 8 << 20, SQLSessions: 1}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	work, err := NewWorkAdmissionV1(c)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := work.signerProcessSQLV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	before := c.SnapshotV1(uuid.Nil)
	var output bytes.Buffer
	original := slog.Default()
	observedLoan := false
	slog.SetDefault(slog.New(signerScopeObservationHandlerV1{Handler: slog.NewJSONHandler(&output, nil), onRefusal: func() {
		observedLoan = true
		got := c.SnapshotV1(uuid.Nil)
		if got.Global != v || got.GlobalGrants != 2 || got.ActiveOrganisations != 0 {
			t.Error("actual scope header was released before the synchronous log consumer", got)
		}
	}}))
	defer slog.SetDefault(original)
	scope, err := f.ProbeSignerScopeForRouteV1(ctx, make([]byte, 32), SignerReadDiagnosticCommentsV1)
	if scope == nil || !errors.Is(err, workguard.ErrUnavailableV1) {
		t.Fatal("actual probe did not refuse before observer dispatch", err)
	}
	var row map[string]any
	if err := json.Unmarshal(output.Bytes(), &row); err != nil {
		t.Fatal("funded original scope did not log", err)
	}
	if row["msg"] != "owned signer scope refused" || row["route"] != float64(SignerReadDiagnosticCommentsV1) || row["probe_phase"] != float64(signerScopeObserverV1) || row["error_class"] != float64(5) || row["atomic_decision"] != false || row["reason"] != float64(0) {
		t.Fatal("incorrect phase or invented atomic observer decision", row)
	}
	if !observedLoan {
		t.Fatal("original synchronous consumer was not observed")
	}
	if f.PendingV1() != (ApplicationSessionPendingV1{}) || c.SnapshotV1(uuid.Nil) != before {
		t.Fatal("probe retained owner or refunded held SQL", f.PendingV1(), c.SnapshotV1(uuid.Nil))
	}
	f.state.mu.Lock()
	control := f.state.signerControl
	f.state.mu.Unlock()
	if control == nil || control.observer != nil {
		t.Fatal("denied observer dispatched")
	}
	output.Reset()
	scope.LogReaderConstructionRefusalV1(ctx, SignerReadDiagnosticCommentsV1, SignerReadDiagnosticLookupV1, err)
	if output.Len() != 0 {
		t.Fatal("released scope emitted a diagnostic")
	}
	release()
	if got := c.SnapshotV1(uuid.Nil); got.GlobalGrants != 0 || got.Global != (workguard.VectorV1{}) || got.ActiveOrganisations != 0 {
		t.Fatal("actual grants not retired", got)
	}
}

func TestSignerScopePreHeaderDenialDoesNotInventFundedDiagnosticV1(t *testing.T) {
	_, work := applicationSessionResourcesTestV1(t, 1)
	f, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var output bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(original)
	scope, err := f.ProbeSignerScopeForRouteV1(ctx, make([]byte, 32), SignerReadDiagnosticPDFV1)
	if scope != nil || !errors.Is(err, workguard.ErrUnavailableV1) || output.Len() != 0 || f.PendingV1() != (ApplicationSessionPendingV1{}) {
		t.Fatal("pre-header refusal allocated or invented an owned frame", err)
	}
}
