// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type signerFailurePrivateErrorV1 struct{}

func (signerFailurePrivateErrorV1) Error() string { panic("private error must never be formatted") }

type signerFailureContextV1 struct {
	context.Context
	err                     error
	hasDeadline             bool
	errReads, deadlineReads int
}

func (c *signerFailureContextV1) Err() error { c.errReads++; return c.err }
func (c *signerFailureContextV1) Deadline() (time.Time, bool) {
	c.deadlineReads++
	return time.Now().Add(time.Minute), c.hasDeadline
}

func TestSignerReaderDiagnosticConstructorKeepsOriginalErrorContractV1(t *testing.T) {
	cases := []struct {
		name          string
		ctx           *signerFailureContextV1
		mode          SignerReadModeV1
		cause         uint8
		deadlineReads int
	}{
		{"no-deadline", &signerFailureContextV1{Context: context.Background()}, SignerReadActiveV1, 2, 1},
		{"canceled", &signerFailureContextV1{Context: context.Background(), err: context.Canceled}, SignerReadActiveV1, 3, 0},
		{"expired", &signerFailureContextV1{Context: context.Background(), err: context.DeadlineExceeded}, SignerReadActiveV1, 4, 0},
		{"private-context-error", &signerFailureContextV1{Context: context.Background(), err: signerFailurePrivateErrorV1{}}, SignerReadActiveV1, 5, 0},
		{"invalid-mode", &signerFailureContextV1{Context: context.Background(), hasDeadline: true}, SignerReadModeV1("invalid"), 6, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var factory *ApplicationSessionFactoryV1
			reader, err := factory.NewSignerReaderV1(tc.ctx, nil, tc.mode)
			if reader != nil || !errors.Is(err, ErrSignerReadV1) || err.Error() != ErrSignerReadV1.Error() ||
				errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
				signerReaderConstructorCauseV1(errors.Join(ErrApplicationSessionV1, err)) != tc.cause {
				t.Fatal("constructor changed original rejection semantics")
			}
			if tc.ctx.errReads != 1 || tc.ctx.deadlineReads != tc.deadlineReads {
				t.Fatal("input cause was not captured at the original single context check")
			}
		})
	}
	var factory *ApplicationSessionFactoryV1
	if reader, err := factory.NewSignerReaderV1(nil, nil, SignerReadActiveV1); reader != nil || signerReaderConstructorCauseV1(err) != 1 {
		t.Fatal("nil context rejection changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, mode := range []SignerReadModeV1{SignerReadActiveV1, SignerReadCompletedV1, SignerReadActiveRecheckV1, SignerReadActiveResponseV1} {
		reader, err := factory.NewSignerReaderV1(ctx, nil, mode)
		if reader != nil || !errors.Is(err, ErrApplicationSessionV1) || signerReaderConstructorCauseV1(err) != 0 {
			t.Fatal("valid input no longer reaches the original missing-factory guard")
		}
	}
}

func TestSignerReaderDiagnosticRegistryGuardsDoNotBorrowScopeV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	full := make(map[*ApplicationSignerReaderV1]struct{}, applicationSessionMaxWorkV1)
	for range applicationSessionMaxWorkV1 {
		full[&ApplicationSignerReaderV1{}] = struct{}{}
	}
	for _, tc := range []struct {
		name  string
		state *applicationSessionFactoryStateV1
		cause uint8
	}{
		{"closing-before-missing", &applicationSessionFactoryStateV1{closing: true}, 7},
		{"missing", &applicationSessionFactoryStateV1{}, 8},
		{"full", &applicationSessionFactoryStateV1{signerReaders: full}, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &ApplicationSessionFactoryV1{state: tc.state}
			before := len(tc.state.signerReaders)
			reader, err := f.NewSignerReaderV1(ctx, nil, SignerReadActiveRecheckV1)
			if reader != nil || !errors.Is(err, ErrSignerReadV1) || signerReaderConstructorCauseV1(err) != tc.cause ||
				err.Error() != ErrSignerReadV1.Error() || len(tc.state.signerReaders) != before {
				t.Fatal("rejected constructor allocated or changed guard priority/error")
			}
		})
	}
}

func TestSignerReaderDiagnosticCausesAreConcurrentImmutableValuesV1(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 256 {
		wg.Go(func() {
			cause := uint8(1 + i%9)
			err := errors.Join(ErrApplicationSessionV1, &signerReaderConstructorRefusalsV1[cause])
			for range 128 {
				if signerReaderConstructorCauseV1(err) != cause || !errors.Is(err, ErrSignerReadV1) {
					t.Error("another constructor changed this call's cause")
					return
				}
			}
		})
	}
	wg.Wait()
	if applicationSignerReadDiagnosticControlBytesV1 > 8<<20 {
		t.Fatal("diagnostics no longer fit the original process control class")
	}
}

func TestSignerReaderDiagnosticConcreteNestedErrorsPrecedeGenericSessionV1(t *testing.T) {
	for _, tc := range []struct {
		err   error
		class uint8
	}{
		{context.DeadlineExceeded, 1}, {context.Canceled, 2}, {pgx.ErrNoRows, 3},
		{pgx.ErrTxClosed, 4}, {pgx.ErrTxCommitRollback, 5}, {io.EOF, 6}, {io.ErrUnexpectedEOF, 7},
		{pgx.ScanArgError{Err: signerFailurePrivateErrorV1{}}, 8},
		{&pgconn.PgError{Code: "40001", Message: "PRIVATE-CANARY", Detail: "PRIVATE-CANARY"}, 9},
		{&pgconn.PgError{Code: "40P01"}, 10}, {&pgconn.PgError{Code: "57014"}, 11},
		{&pgconn.PgError{Code: "55P03"}, 12}, {&pgconn.PgError{Code: "57P01"}, 13},
		{&pgconn.PgError{Code: "42P01"}, 14}, {&pgconn.PgError{Code: "PRIVATE-CANARY"}, 15},
	} {
		err := errors.Join(ErrApplicationSessionV1, tc.err)
		if got := signerReadFailureClassV1(err); got != tc.class {
			t.Fatalf("nested class %d masked by session sentinel: %d", tc.class, got)
		}
	}
	if signerReadFailureClassV1(signerFailurePrivateErrorV1{}) != 22 {
		t.Fatal("unknown private error was formatted or misclassified")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	contracted := applicationErrorV1(ctx, workguard.ErrUnavailableV1)
	if !errors.Is(contracted, ErrApplicationAdmissionV1) || errors.Is(contracted, workguard.ErrUnavailableV1) || contracted.Error() != ErrApplicationAdmissionV1.Error() {
		t.Fatal("original admission wrapper error contract changed")
	}
	wrapped := errors.Join(ErrApplicationSessionV1, ErrHTMLAuthoringReadV1, contracted)
	if signerReadFailureClassV1(wrapped) != 23 || signerReadFailureClassV1(errors.Join(wrapped, workguard.ErrUnavailableV1)) != 16 || signerReadFailureClassV1(errors.Join(wrapped, context.Canceled)) != 2 || signerReadFailureClassV1(ErrHTMLAuthoringReadV1) != 22 {
		t.Fatal("contracted admission classification inferred a hidden cause or masked a concrete one")
	}
	if signerReadFailureContextV1(ctx) != 2 {
		t.Fatal("live callback misclassified")
	}
	r := &ApplicationSignerReaderV1{}
	r.recordModelFailureDiagnosticV1(ctx, context.Canceled)
	cancel()
	if r.diagnostic.errorClass != 2 || r.diagnostic.contextState != 2 || signerReadFailureContextV1(ctx) != 3 {
		t.Fatal("retained scalar snapshot followed later callback cancellation")
	}
}

func TestSignerReaderDiagnosticRetainsOriginalStartupObservationV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	first := applicationSessionStartErrorV1(ctx, ErrApplicationSessionUnknownV1, io.EOF, 2)
	cancel()
	r := &ApplicationSignerReaderV1{}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recordModelFailureDiagnosticV1(ctx, applicationSessionErrorV1(ctx, nil, first))
	assertStartup := func() {
		t.Helper()
		if r.diagnostic.startPhase != 2 || r.diagnostic.startErrorClass != 6 || r.diagnostic.startContextState != 2 {
			t.Fatal("original startup observation was lost or sampled during later cleanup")
		}
	}
	assertStartup()
	if r.diagnostic.errorClass != 2 || r.diagnostic.contextState != 3 {
		t.Fatal("startup snapshot changed the existing model failure classification")
	}
	r.recordModelFailureDiagnosticV1(context.Background(), context.DeadlineExceeded)
	assertStartup()
	if r.diagnostic.errorClass != 1 || r.diagnostic.contextState != 2 {
		t.Fatal("retained startup observation prevented model failure updates")
	}
	r.recordModelFailureDiagnosticV1(ctx, applicationSessionStartErrorV1(ctx, ErrApplicationSessionUnknownV1, context.DeadlineExceeded, 6))
	assertStartup()
	if r.diagnostic.errorClass != 1 || r.diagnostic.contextState != 3 {
		t.Fatal("later captured startup changed original model classification")
	}
	for _, err := range []error{nil, ErrSignerReadV1, ErrApplicationSessionUnknownV1, io.EOF, errors.Join(ErrApplicationSessionV1, ErrSignerReadV1)} {
		uncaptured := &ApplicationSignerReaderV1{}
		uncaptured.mu.Lock()
		uncaptured.recordModelFailureDiagnosticV1(ctx, err)
		if uncaptured.diagnostic.startPhase != 0 || uncaptured.diagnostic.startErrorClass != 0 || uncaptured.diagnostic.startContextState != 0 {
			t.Fatal("uncaptured failure invented startup evidence")
		}
		uncaptured.mu.Unlock()
	}
}
