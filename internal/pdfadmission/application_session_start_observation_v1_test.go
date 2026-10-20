// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type cyclicStartObservationErrorV1 struct{}

func (*cyclicStartObservationErrorV1) Error() string   { return "cycle" }
func (e *cyclicStartObservationErrorV1) Unwrap() error { return e }

type multipleStartObservationErrorV1 struct{ children []error }

func (*multipleStartObservationErrorV1) Error() string     { return "multiple" }
func (e *multipleStartObservationErrorV1) Unwrap() []error { return e.children }

func TestApplicationSessionStartObservationPreservesCauseContractV1(t *testing.T) {
	for phase := uint8(1); phase <= 6; phase++ {
		t.Run(fmt.Sprint(phase), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			private := &pgconn.PgError{Code: "40001", Message: "private statement and credential detail"}
			cause := errors.Join(io.EOF, private)
			original := applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, cause)
			observedError := applicationSessionStartErrorV1(ctx, ErrApplicationSessionUnknownV1, cause, phase)
			oldCauses := original.(*applicationSessionFailureV1).Unwrap()
			newCauses := observedError.(*applicationSessionFailureV1).Unwrap()
			if len(oldCauses) != len(newCauses) || observedError.Error() != original.Error() {
				t.Fatal("startup observation changed error text or cause count")
			}
			for i := range oldCauses {
				if oldCauses[i] != newCauses[i] {
					t.Fatal("startup observation changed cause identity or order")
				}
			}
			var server *pgconn.PgError
			if !errors.Is(observedError, io.EOF) || !errors.Is(observedError, ErrApplicationSessionUnknownV1) || !errors.As(observedError, &server) || server != private {
				t.Fatal("startup observation changed SQL decision contract")
			}
			want := ApplicationSessionStartObservationV1{Phase: phase, ErrorClass: 6, ContextState: 2}
			cancel() // Startup and later cleanup must not rewrite the observation.
			wrapped := applicationSessionErrorV1(ctx, nil, errors.Join(errors.New("other"), fmt.Errorf("outer: %w", observedError)))
			got, ok := ApplicationSessionStartObservationForV1(wrapped)
			if !ok || got != want || errors.Is(observedError, context.Canceled) {
				t.Fatal("original live startup observation changed after cancellation")
			}
			newCauses[0] = nil
			if !errors.Is(observedError, ErrApplicationSessionV1) {
				t.Fatal("Unwrap lost its defensive copy")
			}
		})
	}
}

func TestApplicationSessionStartObservationContextScopesV1(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	for _, tc := range []struct {
		name         string
		ctx          context.Context
		cause        error
		state, class uint8
	}{
		{"nil", nil, nil, 1, 0},
		{"live", context.Background(), nil, 2, 0},
		{"canceled", canceled, nil, 3, 2},
		{"expired", expired, nil, 4, 1},
		// pgx's connect timeout may expire while the outer startup context lives.
		{"inner-deadline", context.Background(), context.DeadlineExceeded, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := applicationSessionStartErrorV1(tc.ctx, ErrApplicationSessionUnknownV1, tc.cause, 2)
			got, ok := ApplicationSessionStartObservationForV1(err)
			if !ok || got != (ApplicationSessionStartObservationV1{Phase: 2, ErrorClass: tc.class, ContextState: tc.state}) {
				t.Fatalf("wrong closed startup observation: %+v", got)
			}
			original := applicationSessionErrorV1(tc.ctx, ErrApplicationSessionUnknownV1, tc.cause).(*applicationSessionFailureV1)
			actual := err.(*applicationSessionFailureV1)
			if len(original.causes) != len(actual.causes) {
				t.Fatal("startup context changed original cause count")
			}
			for i := range original.causes {
				if original.causes[i] != actual.causes[i] {
					t.Fatal("startup context changed original cause order")
				}
			}
		})
	}
	for _, err := range []error{nil, ErrApplicationSessionV1, applicationSessionErrorV1(nil, nil, nil), &cyclicStartObservationErrorV1{}} {
		if got, ok := ApplicationSessionStartObservationForV1(err); ok || got != (ApplicationSessionStartObservationV1{}) {
			t.Fatal("uncaptured or cyclic error invented a startup observation")
		}
	}
	var typedNil *applicationSessionFailureV1
	if _, ok := ApplicationSessionStartObservationForV1(typedNil); ok {
		t.Fatal("typed nil error invented a startup observation")
	}
	// Nil child slots must consume traversal budget too. The observation after
	// the first 32 slots must remain unseen, without scanning the entire slice.
	children := make([]error, 64)
	children[63] = applicationSessionStartErrorV1(context.Background(), nil, io.EOF, 2)
	if _, ok := ApplicationSessionStartObservationForV1(&multipleStartObservationErrorV1{children: children}); ok {
		t.Fatal("sparse multi-error bypassed the traversal bound")
	}
}
