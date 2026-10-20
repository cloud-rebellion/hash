// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitselect

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
)

func TestArchiveBudgetV1ActualSchema4MembersAndStoreZIP(t *testing.T) {
	_, _, sql, _ := setupSelectionV1(t)
	state := cloneStateV1(sql.state)
	entries := testEntriesV1(state)
	proof, err := AdmitArchiveBudgetV1(state, entries)
	if err != nil {
		t.Fatal(err)
	}
	// Execute the actual archive writer, including descriptors and central/end
	// records, instead of asserting an implementation's hand-computed framing.
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, e := range entries {
		f, e1 := w.CreateHeader(&zip.FileHeader{Name: e.Name, Method: zip.Store})
		if e1 != nil {
			t.Fatal(e1)
		}
		if _, e1 = io.CopyN(f, bytes.NewReader(make([]byte, e.Bytes)), e.Bytes); e1 != nil {
			t.Fatal(e1)
		}
	}
	for _, r := range state.Inventory {
		var name string
		switch r.Kind.String {
		case "manifest":
			name = manualfit.ManifestArchiveNameV1(r.PreparationID)
		case "span":
			name = manualfit.SpanArchiveNameV1(r.PreparationID)
		case "page":
			name = manualfit.PageArchiveNameV1(r.PreparationID, int(r.Page.Int32))
		default:
			t.Fatal("fixture lacks actual fit member")
		}
		f, e1 := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if e1 != nil {
			t.Fatal(e1)
		}
		if _, e1 = io.CopyN(f, bytes.NewReader(make([]byte, r.Bytes.Int64)), r.Bytes.Int64); e1 != nil {
			t.Fatal(e1)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(out.Len()) > proof.UpperBoundBytes() {
		t.Fatal("actual schema4 ZIP exceeds locked reservation")
	}
	for _, tc := range []struct {
		name   string
		change func([]ArchiveEntryLimitV1) []ArchiveEntryLimitV1
	}{
		{"old names", func(x []ArchiveEntryLimitV1) []ArchiveEntryLimitV1 { x[1].Name = "final.pdf"; return x }},
		{"missing events", func(x []ArchiveEntryLimitV1) []ArchiveEntryLimitV1 { return append(x[:6], x[7:]...) }},
		{"missing historical issuer", func(x []ArchiveEntryLimitV1) []ArchiveEntryLimitV1 { return x[:len(x)-1] }},
		{"arbitrary filename", func(x []ArchiveEntryLimitV1) []ArchiveEntryLimitV1 {
			return append(x, ArchiveEntryLimitV1{"unreviewed.json", 1})
		}},
		{"event member cap", func(x []ArchiveEntryLimitV1) []ArchiveEntryLimitV1 {
			x[6].Bytes = manualfit.MaxEventsJSONBytesV1 + 1
			return x
		}},
		{"certificate signature cap", func(x []ArchiveEntryLimitV1) []ArchiveEntryLimitV1 {
			x[4].Bytes = manualfit.MaxCertificateSignatureBytesV1 + 1
			return x
		}},
		{"fit double charge", func(x []ArchiveEntryLimitV1) []ArchiveEntryLimitV1 {
			return append(x, ArchiveEntryLimitV1{manualfit.SpanArchiveNameV1(uuid.New()), 1})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := AdmitArchiveBudgetV1(state, tc.change(testEntriesV1(state))); e == nil {
				t.Fatal("incoherent schema4 reservation admitted")
			}
		})
	}
}

func TestArchiveBudgetV1KnownObjectCountsAndProducerEntryCap(t *testing.T) {
	_, _, sql, _ := setupSelectionV1(t)
	state := cloneStateV1(sql.state)
	// Known three-member operations must not be charged as500-page operations.
	// This is an archive budget test, not a100-party signing acceptance claim.
	for i := 1; i < 100; i++ {
		state.Inventory = append(state.Inventory, &generated.ListSignatureFitInventoryRow{PreparationID: uuid.New(), RecipientID: uuid.New(), Status: "staging", ExpectedObjects: 3, ReservedBytes: 3})
		state.Document.SignatureFitReservedBytes += 3
	}
	if _, err := AdmitArchiveBudgetV1(state, testEntriesV1(state)); err != nil {
		t.Fatal("known small operations falsely exceed producer entry cap", err)
	}
	state = cloneStateV1(sql.state)
	for _, r := range state.Inventory {
		r.ExpectedObjects = 502
	}
	state.Preparation.ExpectedObjects = 502
	for i := 1; i < 20; i++ {
		state.Inventory = append(state.Inventory, &generated.ListSignatureFitInventoryRow{PreparationID: uuid.New(), RecipientID: uuid.New(), Status: "staging", ExpectedObjects: 502, ReservedBytes: 3})
		state.Document.SignatureFitReservedBytes += 3
	}
	if _, err := AdmitArchiveBudgetV1(state, testEntriesV1(state)); err == nil {
		t.Fatal("10000-entry producer cap escaped through65535 ZIP threshold")
	}
}

func TestArchiveBudgetV1RejectsMissingConflictingOrUnchargedInventory(t *testing.T) {
	_, _, sql, _ := setupSelectionV1(t)
	for _, mode := range []string{"missing rows", "missing expected count", "conflicting count", "conflicting reservation", "uncharged live debt", "invalid status", "negative reservation", "cleaned debt still charged", "current preparation omitted", "current preparation count mismatch"} {
		t.Run(mode, func(t *testing.T) {
			state := cloneStateV1(sql.state)
			switch mode {
			case "current preparation omitted":
				state.Preparation.ID = uuid.New()
			case "current preparation count mismatch":
				state.Preparation.ExpectedObjects++
			case "missing rows":
				state.Inventory = nil
			case "missing expected count":
				for _, r := range state.Inventory {
					r.ExpectedObjects = 0
				}
			case "conflicting count":
				state.Inventory[1].ExpectedObjects++
			case "conflicting reservation":
				state.Inventory[1].ReservedBytes++
			case "uncharged live debt":
				state.Document.SignatureFitReservedBytes--
			case "invalid status":
				state.Inventory[0].Status = "unknown invented status"
			case "negative reservation":
				state.Inventory[0].ReservedBytes = -1
			case "cleaned debt still charged":
				for _, r := range state.Inventory {
					r.Status = "cleaned"
				}
			}
			if _, err := AdmitArchiveBudgetV1(state, testEntriesV1(state)); err == nil {
				t.Fatal("incomplete locked reservation inventory admitted")
			}
		})
	}
	state := cloneStateV1(sql.state)
	for _, r := range state.Inventory {
		r.Status = "cleaned"
	}
	state.Preparation.Status = "cleaned"
	state.Document.SignatureFitReservedBytes = 0
	if _, err := AdmitArchiveBudgetV1(state, testEntriesV1(state)); err != nil {
		t.Fatal("durable cleaned privacy history treated as live debt", err)
	}
}
