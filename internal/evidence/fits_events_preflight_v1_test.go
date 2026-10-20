// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These fixtures establish only this in-process producer size boundary. They
// are not retained/live event, database, renderer or memory-isolation proof.
func fitsEventsSizeRowV1() *generated.Event {
	return &generated.Event{
		ID:          uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		OrgID:       uuid.MustParse("10000000-0000-4000-8000-000000000002"),
		DocumentID:  pgtype.UUID{Bytes: uuid.MustParse("10000000-0000-4000-8000-000000000003"), Valid: true},
		RecipientID: pgtype.UUID{Bytes: uuid.MustParse("10000000-0000-4000-8000-000000000004"), Valid: true},
		ActorUserID: pgtype.UUID{Bytes: uuid.MustParse("10000000-0000-4000-8000-000000000005"), Valid: true},
		Kind:        "document.viewed",
		Ua:          pgtype.Text{String: "Browser/1", Valid: true},
		CreatedAt:   pgtype.Timestamptz{Time: time.Date(2026, 10, 12, 1, 2, 3, 456789123, time.UTC), Valid: true},
		PayloadJson: json.RawMessage("{}"), PayloadHashed: []byte("{}"),
		PrevHash: bytes.Repeat([]byte{1}, 32), RowHash: bytes.Repeat([]byte{2}, 32),
	}
}

func fitsEventsActualWireV1(t *testing.T, rows []*generated.Event) []byte {
	t.Helper()
	canonical := make([]CanonicalCeremonyEvent, len(rows))
	for i, row := range rows {
		canonical[i] = canonicalCeremonyEvent(row)
	}
	raw, err := json.MarshalIndent(CeremonyEventsFile{
		SchemaVersion: ceremonyEventsSchemaV2,
		DocumentID:    uuid.UUID(rows[0].DocumentID.Bytes).String(), OrgID: rows[0].OrgID.String(),
		CommitmentDomain: ceremonyEventsCommitmentDomain,
		CommitmentSHA256: strings.Repeat("a", 64), Count: len(rows), Events: canonical,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFitsEventsPreflightBoundsActualEncodedWire(t *testing.T) {
	for _, name := range []string{"ordinary", "html-and-controls", "nested-raw-json", "invalid-utf8", "nullable-ua", "scoped-ip", "large-admitted-string"} {
		t.Run(name, func(t *testing.T) {
			row := fitsEventsSizeRowV1()
			switch name {
			case "html-and-controls":
				row.Ua.String = "\"\\\b\f\n\r\t\x00\x01<>&\u2028\u2029🙂"
				row.Kind = "kind:<>&"
				row.PayloadJson = json.RawMessage("{\"k\":\"<>&\u2028\u2029\",\"nested\":[[],{},[1,2]]}")
				row.PayloadHashed = append([]byte(nil), row.PayloadJson...)
			case "nested-raw-json":
				row.PayloadJson = json.RawMessage(strings.Repeat("[", 60) + "0" + strings.Repeat("]", 60))
				row.PayloadHashed = append([]byte(nil), row.PayloadJson...)
			case "invalid-utf8":
				row.Ua.String = string([]byte{0xff, 0xc0, 0x80})
				row.PayloadJson = json.RawMessage([]byte{'"', 0xff, '"'})
				row.PayloadHashed = append([]byte(nil), row.PayloadJson...)
			case "nullable-ua":
				row.Ua = pgtype.Text{String: strings.Repeat("<", 1000000), Valid: false}
				row.RecipientID.Valid = false
				row.ActorUserID.Valid = false
			case "scoped-ip":
				address := netip.MustParseAddr("fe80::1").WithZone(strings.Repeat("<>&", 1000))
				row.Ip = &address
			case "large-admitted-string":
				row.Ua.String = strings.Repeat("a", 3<<20)
			}
			rows := []*generated.Event{row}
			bound, err := fitsEventsJSONBoundV1(context.Background(), rows)
			if err != nil {
				t.Fatalf("admitted fixture rejected: %v", err)
			}
			actual := fitsEventsActualWireV1(t, rows)
			if int64(len(actual)) > bound || bound > manualfit.MaxEventsJSONBytesV1 {
				t.Fatalf("actual encoded length %d exceeds admitted bound %d", len(actual), bound)
			}
		})
	}
}

func TestFitsEventsPreflightRejectsEncodingExpansionBeforeCanonicalValidation(t *testing.T) {
	for _, name := range []string{"ua-html", "kind-control", "payload-html", "base64", "nested-indentation", "per-row-metadata", "hex"} {
		t.Run(name, func(t *testing.T) {
			row := fitsEventsSizeRowV1()
			rows := []*generated.Event{row}
			switch name {
			case "ua-html":
				row.Ua.String = strings.Repeat("&", 700000)
			case "kind-control":
				row.Kind = strings.Repeat("\x01", 700000)
			case "payload-html":
				row.PayloadJson = json.RawMessage("{\"k\":\"" + strings.Repeat("<", 600000) + "\"}")
				row.PayloadHashed = append([]byte(nil), row.PayloadJson...)
			case "base64":
				row.PayloadJson = json.RawMessage("null")
				row.PayloadHashed = []byte("null" + strings.Repeat(" ", 3200000))
			case "nested-indentation":
				row.PayloadJson = json.RawMessage(strings.Repeat("[", 2000) + "0" + strings.Repeat("]", 2000))
				row.PayloadHashed = append([]byte(nil), row.PayloadJson...)
			case "per-row-metadata":
				rows = make([]*generated.Event, maxEvidenceEvents)
				for i := range rows {
					rows[i] = row
				}
			case "hex":
				row.PrevHash = bytes.Repeat([]byte{1}, 2100000)
			}
			var oldRawCapBytes int64
			for _, event := range rows {
				oldRawCapBytes += int64(len(event.PayloadJson)) + int64(len(event.PayloadHashed)) + int64(len(event.Ua.String)) + int64(len(event.Kind))
			}
			if oldRawCapBytes > manualfit.MaxEventsJSONBytesV1 {
				t.Fatal("fixture does not expose the old raw-size admission gap")
			}
			actual := fitsEventsActualWireV1(t, rows)
			if int64(len(actual)) <= manualfit.MaxEventsJSONBytesV1 {
				t.Fatal("fixture does not expand beyond the actual producer cap")
			}
			// RowHash is intentionally invalid (and metadata repeats event IDs).
			// A size error proves admission runs before canonical row validation,
			// payload copies and base64/hex/whole-file serialization.
			raw, commitment, count, err := buildSchema4CeremonyEventsJSONV1(context.Background(), uuid.UUID(row.DocumentID.Bytes), rows)
			if !errors.Is(err, ErrEvidenceTooLarge) || raw != nil || commitment != "" || count != 0 {
				t.Fatalf("oversized wire reached canonical builder: %v", err)
			}
		})
	}
}

func TestFitsEventsSchema4KeepsHistoricalCanonicalBytes(t *testing.T) {
	org, document := uuid.New(), uuid.New()
	row := ceremonyTestEventAt(t, org, document, pgtype.UUID{}, "document.viewed", []byte("{\"layout\":[1,{\"text\":\"<>&\"}]}"), time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC))
	row.Ua = pgtype.Text{String: "Agent \"one\" <>&", Valid: true}
	var err error
	row.RowHash, err = audit.RecomputeEventRowHash(row)
	if err != nil {
		t.Fatal(err)
	}
	rows := []*generated.Event{row}
	historical, digest, count, err := BuildCeremonyEventsJSON(document, rows)
	if err != nil {
		t.Fatal(err)
	}
	fitted, fittedDigest, fittedCount, err := buildSchema4CeremonyEventsJSONV1(context.Background(), document, rows)
	if err != nil || !bytes.Equal(fitted, historical) || fittedDigest != digest || fittedCount != count {
		t.Fatal("schema4 changed the canonical historical event bytes/commitment")
	}
	if err := VerifyCeremonyEventsJSON(fitted, document.String(), org.String(), digest, count); err != nil {
		t.Fatal(err)
	}
	// The legacy builder still has its historical behavior. Only the schema4
	// wrapper gains this producer cap; schema2/3 callers must remain untouched.
	row.Ua.String = strings.Repeat("&", 700000)
	row.RowHash, err = audit.RecomputeEventRowHash(row)
	if err != nil {
		t.Fatal(err)
	}
	legacyLarge, _, _, err := BuildCeremonyEventsJSON(document, rows)
	if err != nil || int64(len(legacyLarge)) <= manualfit.MaxEventsJSONBytesV1 {
		t.Fatal("historical builder changed its serialization/admission behavior")
	}
	if _, _, _, err := buildSchema4CeremonyEventsJSONV1(context.Background(), document, rows); !errors.Is(err, ErrEvidenceTooLarge) {
		t.Fatal("schema4 admitted oversized historical output")
	}
}

func TestBuildSchema4EventAdmissionBeforeCommitmentAndLaterWork(t *testing.T) {
	document, builder, _, _ := fittedBuildFixtureV1(t)
	queries := builder.Q.(*evidenceQueriesStub)
	queries.events[0].Ua = pgtype.Text{String: strings.Repeat("&", 700000), Valid: true}
	versions := builder.Versions.(*evidenceVersionsStub)
	result, err := builder.Build(context.Background(), document)
	if !errors.Is(err, ErrEvidenceTooLarge) || result != nil || versions.historyLimit != 0 || queries.qesWasCalled {
		t.Fatalf("schema4 producer passed oversized events into later work: %v", err)
	}
}

func TestFitsEventsPreflightBudgetOverflowAndInvalidInputs(t *testing.T) {
	for _, item := range []struct {
		name           string
		used, addition int64
	}{
		{name: "negative-addition", addition: -1},
		{name: "negative-total", used: -1, addition: 1},
		{name: "over-limit-total", used: manualfit.MaxEventsJSONBytesV1 + 1, addition: 1},
		{name: "max-int-addition", addition: int64(^uint64(0) >> 1)},
		{name: "max-int-total", used: int64(^uint64(0) >> 1), addition: 1},
		{name: "remaining-byte", used: manualfit.MaxEventsJSONBytesV1, addition: 1},
	} {
		t.Run(item.name, func(t *testing.T) {
			budget := fitsEventsJSONBudgetV1{used: item.used}
			if !errors.Is(budget.add(item.addition), ErrEvidenceTooLarge) || budget.used != item.used {
				t.Fatal("overflow/invalid budget was accepted or modified")
			}
		})
	}
	for _, name := range []string{"empty", "nil", "too-many", "invalid-json"} {
		t.Run(name, func(t *testing.T) {
			rows := []*generated.Event{fitsEventsSizeRowV1()}
			switch name {
			case "empty":
				rows = nil
			case "nil":
				rows[0] = nil
			case "too-many":
				rows = make([]*generated.Event, maxEvidenceEvents+1)
			case "invalid-json":
				rows[0].PayloadJson = json.RawMessage("{\"broken\":")
			}
			if _, err := fitsEventsJSONBoundV1(context.Background(), rows); !errors.Is(err, ErrArtifactIntegrity) {
				t.Fatalf("invalid preflight input accepted: %v", err)
			}
		})
	}
}

func TestFitsEventsPreflightPreservesPrivateCancellationCause(t *testing.T) {
	privateCause := errors.New("private-event-cancellation-cause")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(privateCause)
	raw, _, _, err := buildSchema4CeremonyEventsJSONV1(ctx, uuid.New(), []*generated.Event{fitsEventsSizeRowV1()})
	if raw != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, privateCause) || strings.Contains(err.Error(), privateCause.Error()) {
		t.Fatal("cancellation cause lost or private text disclosed")
	}
}
