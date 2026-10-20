// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type applicationInternalWritePhaseV1 uint8

const (
	applicationAuditIdentityWriteV1 applicationInternalWritePhaseV1 = iota + 1
	applicationCeremonyReopenWriteV1
)

// The private immutable tag describes only a known completed failure at one
// fixed mutation statement. It grants no work, SQL, retry, commit or retirement
// authority, and never drops the native session wrapper or original cause.
type applicationInternalWriteFailureV1 struct {
	phase applicationInternalWritePhaseV1
	cause error
}

func (*applicationInternalWriteFailureV1) Error() string {
	return "pdfadmission: internal document write failed"
}
func (e *applicationInternalWriteFailureV1) Unwrap() error { return e.cause }

func applicationInternalWriteErrorV1(ctx context.Context, phase applicationInternalWritePhaseV1, cause error) error {
	if ctx == nil || ctx.Err() != nil || !applicationInternalWritePhaseValidV1(phase) || !applicationCompletedInternalSQLFailureV1(cause) {
		return cause
	}
	return &applicationInternalWriteFailureV1{phase: phase, cause: cause}
}

func applicationInternalWritePhaseValidV1(phase applicationInternalWritePhaseV1) bool {
	return phase == applicationAuditIdentityWriteV1 || phase == applicationCeremonyReopenWriteV1
}

// IsInternalApplicationWriteFailureV1 recognizes only the private phase tag.
// Untagged PgError/NoRows, pre-dispatch refusal, M94 measurement and native
// uncertainty remain availability/semantic errors at their original boundary.
func IsInternalApplicationWriteFailureV1(err error) bool {
	var failure *applicationInternalWriteFailureV1
	return errors.As(err, &failure) && failure != nil && applicationInternalWritePhaseValidV1(failure.phase) && applicationCompletedInternalSQLFailureV1(err)
}

func applicationCompletedInternalSQLFailureV1(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrApplicationSessionUnknownV1) || errors.Is(err, ErrApplicationSessionCommitUnknownV1) ||
		errors.Is(err, ErrHTMLAuditEventV1) || errors.Is(err, ErrHTMLCeremonyWorkflowV1) ||
		errors.Is(err, ErrHTMLRevisionReadV1) || errors.Is(err, ErrHTMLRevisionSourceV1) ||
		errors.Is(err, ErrHTMLRevisionCollectionsV1) || errors.Is(err, ErrHTMLAuthoringReadV1) || errors.Is(err, ErrBlocksWriterV1) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	var network net.Error
	if errors.As(err, &network) {
		return false
	}
	// Inspect every cause, rather than allowing the first known server error
	// or NoRows to conceal an independent retry/unknown cause in a join.
	known, nodes := false, 0
	var inspect func(error) bool
	inspect = func(cause error) bool {
		nodes++
		if cause == nil || nodes > 64 {
			return false
		}
		if cause == ErrApplicationSessionV1 {
			return true
		}
		// A real Scan no-row result is known only at the private fixed writes.
		if cause == pgx.ErrNoRows {
			known = true
			return true
		}
		if server, ok := cause.(*pgconn.PgError); ok {
			if server == nil || !applicationInternalSQLStateV1(server.Code) {
				return false
			}
			known = true
			return true
		}
		switch wrapped := cause.(type) {
		case interface{ Unwrap() []error }:
			causes := wrapped.Unwrap()
			if len(causes) == 0 {
				return false
			}
			for _, inner := range causes {
				if !inspect(inner) {
					return false
				}
			}
			return true
		case interface{ Unwrap() error }:
			return inspect(wrapped.Unwrap())
		default:
			return false
		}
	}
	return inspect(err) && known
}

func applicationInternalSQLStateV1(code string) bool {
	if len(code) != 5 {
		return false
	}
	// Conservative known nonretry server-fault classes. Serialization/deadlock
	// (40), connection (08), resources/limits/locks (53/54/55), cancellation or
	// shutdown (57), system I/O (58), and unknown classes deliberately stay out.
	switch code[:2] {
	case "20", "21", "22", "23", "27", "2F", "34", "3D", "3F", "42", "44", "P0", "XX":
		return true
	default:
		return false
	}
}
