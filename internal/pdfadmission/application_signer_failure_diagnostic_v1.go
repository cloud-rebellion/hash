// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"io"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These immutable static companions preserve the original sentinel, text and
// errors.Is contract. No rejected constructor allocates a reader or observation
// frame. The private cause is data only, never admission or retry authority.
type signerReaderConstructorRefusalV1 struct{ cause uint8 }

var signerReaderConstructorRefusalsV1 = [...]signerReaderConstructorRefusalV1{
	{}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9},
}

func (*signerReaderConstructorRefusalV1) Error() string { return ErrSignerReadV1.Error() }
func (*signerReaderConstructorRefusalV1) Unwrap() error { return ErrSignerReadV1 }

func signerReaderConstructorCauseV1(err error) uint8 {
	var refusal *signerReaderConstructorRefusalV1
	if errors.As(err, &refusal) && refusal != nil {
		return refusal.cause
	}
	return 0
}

// Same ordered input checks as applicationContextV1 followed by the original
// mode predicate. Snapshot Err exactly once at the actual rejection branch.
// Causes: nil context, missing deadline, canceled, expired, other context error,
// invalid mode; registry closing/missing/full are captured under the factory lock.
func signerReaderInputRefusalV1(ctx context.Context, mode SignerReadModeV1) error {
	if ctx == nil {
		return &signerReaderConstructorRefusalsV1[1]
	}
	if err := ctx.Err(); err != nil {
		switch err {
		case context.Canceled:
			return &signerReaderConstructorRefusalsV1[3]
		case context.DeadlineExceeded:
			return &signerReaderConstructorRefusalsV1[4]
		default:
			return &signerReaderConstructorRefusalsV1[5]
		}
	}
	if _, ok := ctx.Deadline(); !ok {
		return &signerReaderConstructorRefusalsV1[2]
	}
	if mode != SignerReadActiveV1 && mode != SignerReadCompletedV1 && mode != SignerReadActiveRecheckV1 && mode != SignerReadActiveResponseV1 {
		return &signerReaderConstructorRefusalsV1[6]
	}
	return nil
}

// Fixed context state only. Do not retain the context or its error. A callback
// context must be sampled before WithTx returns and cancels it unconditionally.
func signerReadFailureContextV1(ctx context.Context) uint8 {
	if ctx == nil {
		return 1
	}
	switch err := ctx.Err(); err {
	case nil:
		return 2
	case context.Canceled:
		return 3
	case context.DeadlineExceeded:
		return 4
	default:
		return 5
	}
}

// Inspect concrete nested causes before generic session/reader sentinels: the
// native SQL facade wraps query failures with ErrApplicationSessionV1. Never
// format/log an error, SQLSTATE, server detail, statement, identity or address.
func signerReadFailureClassV1(err error) uint8 {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, context.DeadlineExceeded):
		return 1
	case errors.Is(err, context.Canceled):
		return 2
	case errors.Is(err, pgx.ErrNoRows):
		return 3
	case errors.Is(err, pgx.ErrTxClosed):
		return 4
	case errors.Is(err, pgx.ErrTxCommitRollback):
		return 5
	case errors.Is(err, io.EOF):
		return 6
	case errors.Is(err, io.ErrUnexpectedEOF):
		return 7
	}
	var scan pgx.ScanArgError
	if errors.As(err, &scan) {
		return 8
	}
	var server *pgconn.PgError
	if errors.As(err, &server) && server != nil {
		switch server.Code {
		case "40001":
			return 9
		case "40P01":
			return 10
		case "57014":
			return 11
		case "55P03":
			return 12
		case "57P01", "57P02", "57P03":
			return 13
		case "42P01", "42703":
			return 14
		default:
			return 15
		}
	}
	switch {
	case errors.Is(err, workguard.ErrUnavailableV1):
		return 16
	case errors.Is(err, ErrApplicationAdmissionV1):
		// This wrapper deliberately contracts its inner cause. The separate
		// atomic frame, when present, proves an actual capacity refusal.
		return 23
	case errors.Is(err, ErrApplicationSessionUnknownV1):
		return 17
	case errors.Is(err, ErrApplicationSessionV1):
		return 18
	case errors.Is(err, ErrSignerReadCredentialV1):
		return 19
	case errors.Is(err, ErrSignerReadLawfulBasisV1):
		return 20
	case errors.Is(err, ErrSignerReadV1):
		return 21
	default:
		return 22
	}
}

// Caller holds the actual reader mutex and its existing control loan. Scalars
// are copied synchronously; no private error/context survives the call.
func (r *ApplicationSignerReaderV1) recordModelFailureDiagnosticV1(ctx context.Context, err error) {
	r.diagnostic.errorClass = signerReadFailureClassV1(err)
	r.diagnostic.contextState = signerReadFailureContextV1(ctx)
	if r.diagnostic.startPhase == 0 {
		if observed, captured := ApplicationSessionStartObservationForV1(err); captured {
			r.diagnostic.startPhase = observed.Phase
			r.diagnostic.startErrorClass = observed.ErrorClass
			r.diagnostic.startContextState = observed.ContextState
		}
	}
}
