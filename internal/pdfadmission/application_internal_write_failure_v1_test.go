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
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These guards distinguish exact observed write faults from availability and
// unknown outcomes. Actual mutation, rollback and HTTP fidelity are exercised
// by the existing original500 and freshM94 PostgreSQL journeys.
func TestInternalWriteFailurePreservesNativeAvailabilityV1(t *testing.T) {
	server := func(code string) error { return &pgconn.PgError{Code: code, Message: "private driver detail"} }
	for _, phase := range []applicationInternalWritePhaseV1{applicationAuditIdentityWriteV1, applicationCeremonyReopenWriteV1, applicationBlocksMutationWriteV1, applicationBlocksVersionWriteV1} {
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

type internalWriteFaultRowV1 struct{ err error }

func (r internalWriteFaultRowV1) Scan(...any) error { return r.err }

// Drive the real generated methods through the native QueryRow/Scan seam.
// A named read or a fresh-measurement failure cannot acquire write provenance.
func TestNativeFixedBlockWritesClassifyOnlyCompletedResponsesV1(t *testing.T) {
	for _, operation := range []struct {
		name  string
		write bool
		run   func(context.Context, *generated.Queries) error
	}{
		{"block mutation", true, func(ctx context.Context, q *generated.Queries) error {
			_, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{})
			return err
		}},
		{"version snapshot", true, func(ctx context.Context, q *generated.Queries) error {
			_, err := q.InsertDocumentVersion(ctx, generated.InsertDocumentVersionParams{})
			return err
		}},
		{"document read", false, func(ctx context.Context, q *generated.Queries) error {
			_, err := q.GetDocument(ctx, generated.GetDocumentParams{})
			return err
		}},
		{"fresh measurement", false, func(ctx context.Context, q *generated.Queries) error {
			_, err := q.MeasureNativeBlocksResponseV1(ctx, generated.MeasureNativeBlocksResponseV1Params{})
			return err
		}},
	} {
		for _, fault := range []struct {
			name      string
			err       error
			completed bool
		}{
			{"exception", &pgconn.PgError{Code: "P0001", Message: "private test SQL detail"}, true},
			{"no row", pgx.ErrNoRows, true},
			{"retry", &pgconn.PgError{Code: "40001"}, false},
			{"cancel", context.Canceled, false},
			{"unknown", ErrApplicationSessionUnknownV1, false},
		} {
			t.Run(operation.name+"/"+fault.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				tx := &applicationSessionTxTestV1{row: internalWriteFaultRowV1{fault.err}}
				h := &ApplicationSessionV1{state: &applicationOwnedSessionV1{tx: tx, changed: make(chan struct{})}}
				err := h.WithTxV1(ctx, func(owned context.Context, db generated.DBTX) error { return operation.run(owned, generated.New(db)) })
				if got, want := IsInternalApplicationWriteFailureV1(err), operation.write && fault.completed; got != want {
					t.Fatalf("native response classification=%t want%t", got, want)
				}
				if !errors.Is(err, fault.err) || !errors.Is(err, ErrApplicationSessionV1) {
					t.Fatal("native response lost original error causes")
				}
				if strings.Contains(err.Error(), "private test SQL detail") {
					t.Fatal("native response exposed SQL detail")
				}
			})
		}
	}
}
