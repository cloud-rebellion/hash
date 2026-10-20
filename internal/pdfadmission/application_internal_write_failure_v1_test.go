// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These guards distinguish exact observed write faults from availability and
// unknown outcomes. Actual mutation, rollback and HTTP fidelity are exercised
// by the existing original500 and freshM94 PostgreSQL journeys.
func TestInternalWriteFailurePreservesNativeAvailabilityV1(t *testing.T) {
	server := func(code string) error { return &pgconn.PgError{Code: code, Message: "private driver detail"} }
	for _, phase := range []applicationInternalWritePhaseV1{applicationAuditIdentityWriteV1, applicationCeremonyReopenWriteV1} {
		for _, tc := range []struct {
			name     string
			cause    error
			internal bool
		}{
			{"trigger exception", server("P0001"), true},
			{"constraint", server("23514"), true},
			{"syntax", server("42601"), true},
			{"data exception", server("22003"), true},
			{"no returned mutation row", pgx.ErrNoRows, true},
			{"cancel", context.Canceled, false},
			{"deadline", context.DeadlineExceeded, false},
			{"unknown session", ErrApplicationSessionUnknownV1, false},
			{"unknown commit", ErrApplicationSessionCommitUnknownV1, false},
			{"fresh measurement no row", errors.Join(ErrHTMLAuditEventV1, pgx.ErrNoRows), false},
			{"missing document body cache", ErrHTMLRevisionReadV1, false},
			{"serialization", server("40001"), false},
			{"deadlock", server("40P01"), false},
			{"server cancel", server("57014"), false},
			{"server shutdown", server("57P01"), false},
			{"lock", server("55P03"), false},
			{"resource", server("53300"), false},
			{"program limit", server("54000"), false},
			{"connection", server("08006"), false},
			{"system IO", server("58030"), false},
			{"network", &net.OpError{Op: "read", Net: "tcp", Err: io.EOF}, false},
			{"EOF", io.EOF, false},
			{"unknown SQLSTATE", server("ZZ999"), false},
			{"invalid SQLSTATE", server("23"), false},
			{"unknown cause", errors.New("unknown operation result"), false},
			{"no rows cannot conceal serialization", errors.Join(pgx.ErrNoRows, server("40001")), false},
			{"first server cause cannot conceal retry", errors.Join(server("23514"), server("40001")), false},
			{"no rows cannot conceal unknown", errors.Join(pgx.ErrNoRows, errors.New("unknown operation result")), false},
		} {
			t.Run(fmt.Sprintf("%d/%s", phase, tc.name), func(t *testing.T) {
				ctx := context.Background()
				original := applicationSessionErrorV1(ctx, nil, tc.cause)
				fault := applicationInternalWriteErrorV1(ctx, phase, original)
				if IsInternalApplicationWriteFailureV1(fault) != tc.internal {
					t.Fatal("fixed write classification lost native/internal distinction")
				}
				if !errors.Is(fault, original) || !errors.Is(fault, tc.cause) || !errors.Is(fault, ErrApplicationSessionV1) {
					t.Fatal("write classification discarded original native causes")
				}
				if IsInternalApplicationWriteFailureV1(original) {
					t.Fatal("untagged SQL or no-row acquired an internal-write phase")
				}
				if tc.internal {
					if strings.Contains(fault.Error(), "private driver detail") {
						t.Fatal("fixed write error exposed driver detail")
					}
					for _, extra := range []error{context.Canceled, context.DeadlineExceeded, ErrApplicationSessionUnknownV1, ErrApplicationSessionCommitUnknownV1, ErrHTMLAuditEventV1, server("55P03")} {
						if IsInternalApplicationWriteFailureV1(errors.Join(fault, extra)) {
							t.Fatal("tagged write concealed joined availability or measurement failure")
						}
					}
				}
			})
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	original := applicationSessionErrorV1(context.Background(), nil, pgx.ErrNoRows)
	if IsInternalApplicationWriteFailureV1(applicationInternalWriteErrorV1(ctx, applicationCeremonyReopenWriteV1, original)) || IsInternalApplicationWriteFailureV1(applicationInternalWriteErrorV1(context.Background(), 0, original)) {
		t.Fatal("cancelled context or unknown phase acquired an internal-write result")
	}
}
