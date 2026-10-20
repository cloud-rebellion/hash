// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func manualSignatureTargetFixture() (*generated.Document, uuid.UUID, []*generated.DocumentField) {
	sum := sha256.Sum256([]byte("retained source"))
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), SourceKind: "pdf", Status: "sent",
		PdfStorageKey: pgtype.Text{String: "source.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "source-version", Valid: true},
		PdfSha256: append([]byte(nil), sum[:]...), EvidenceVersionPinsRequired: true}
	rec := uuid.New()
	rows := make([]*generated.DocumentField, 2)
	for i := range rows {
		rows[i] = &generated.DocumentField{ID: uuid.New(), DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: rec, Valid: true}, Type: "signature", Required: true, Page: int32(i + 1),
			XPct: pgtype.Numeric{Int: big.NewInt(10), Valid: true}, YPct: pgtype.Numeric{Int: big.NewInt(70), Valid: true},
			WPct: pgtype.Numeric{Int: big.NewInt(30), Valid: true}, HPct: pgtype.Numeric{Int: big.NewInt(8), Valid: true}}
	}
	return doc, rec, rows
}

func TestManualSignatureTargetsBindEveryFieldAndCopyInputs(t *testing.T) {
	doc, rec, rows := manualSignatureTargetFixture()
	p, err := captureManualSignatureTargets(doc, rec, rows)
	if err != nil || len(p.fields) != 2 {
		t.Fatalf("capture=%+v error=%v", p, err)
	}
	// Query ordering, another party's status transition, and label changes do
	// not invalidate the exact source/target geometry prepared for this signer.
	rows[0], rows[1] = rows[1], rows[0]
	doc.Status = "in_progress"
	rows[0].Label = pgtype.Text{String: "changed label", Valid: true}
	f, err := validateLockedManualSignatureTargets(p, doc, rec, rows)
	if err != nil || f.ID != p.fields[0].id {
		t.Fatalf("stable target representative=%v error=%v", f, err)
	}
	// Mutating a numeric's shared big.Int or the digest backing slice must not
	// mutate preparation and hide source/placement drift.
	rows[1].XPct.Int.SetInt64(11)
	if _, err := validateLockedManualSignatureTargets(p, doc, rec, rows); !errors.Is(err, ErrSignaturePreparationChanged) {
		t.Fatalf("aliased coordinate mutation error=%v", err)
	}
	rows[1].XPct.Int.SetInt64(10)
	doc.PdfSha256[0] ^= 1
	if _, err := validateLockedManualSignatureTargets(p, doc, rec, rows); !errors.Is(err, ErrSignaturePreparationChanged) {
		t.Fatalf("aliased digest mutation error=%v", err)
	}
}

func TestManualSignatureTargetsRejectSourceAndSecondFieldDrift(t *testing.T) {
	mutations := map[string]func(*generated.Document, []*generated.DocumentField){
		"source key":     func(d *generated.Document, _ []*generated.DocumentField) { d.PdfStorageKey.String += "-new" },
		"source version": func(d *generated.Document, _ []*generated.DocumentField) { d.PdfStorageVersionID.String += "-new" },
		"source hash":    func(d *generated.Document, _ []*generated.DocumentField) { d.PdfSha256[0] ^= 1 },
		"pin policy":     func(d *generated.Document, _ []*generated.DocumentField) { d.EvidenceVersionPinsRequired = false },
		"source kind":    func(d *generated.Document, _ []*generated.DocumentField) { d.SourceKind = "blocks" },
		"envelope":       func(d *generated.Document, _ []*generated.DocumentField) { d.IsEnvelope = true },
		"org":            func(d *generated.Document, _ []*generated.DocumentField) { d.OrgID = uuid.New() },
		"second id":      func(_ *generated.Document, r []*generated.DocumentField) { r[1].ID = uuid.New() },
		"second page":    func(_ *generated.Document, r []*generated.DocumentField) { r[1].Page++ },
		"second x": func(_ *generated.Document, r []*generated.DocumentField) {
			r[1].XPct.Int.Add(r[1].XPct.Int, big.NewInt(1))
		},
		"second y": func(_ *generated.Document, r []*generated.DocumentField) {
			r[1].YPct.Int.Add(r[1].YPct.Int, big.NewInt(1))
		},
		"second w": func(_ *generated.Document, r []*generated.DocumentField) {
			r[1].WPct.Int.Add(r[1].WPct.Int, big.NewInt(1))
		},
		"second h": func(_ *generated.Document, r []*generated.DocumentField) {
			r[1].HPct.Int.Add(r[1].HPct.Int, big.NewInt(1))
		},
		"second owner":    func(_ *generated.Document, r []*generated.DocumentField) { r[1].RecipientID.Bytes = uuid.New() },
		"second type":     func(_ *generated.Document, r []*generated.DocumentField) { r[1].Type = "text" },
		"second required": func(_ *generated.Document, r []*generated.DocumentField) { r[1].Required = false },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			doc, rec, rows := manualSignatureTargetFixture()
			p, err := captureManualSignatureTargets(doc, rec, rows)
			if err != nil {
				t.Fatal(err)
			}
			mutate(doc, rows)
			if _, err := validateLockedManualSignatureTargets(p, doc, rec, rows); !errors.Is(err, ErrSignaturePreparationChanged) {
				t.Fatalf("drift error=%v", err)
			}
		})
	}
	for _, action := range []string{"remove second", "add third"} {
		t.Run(action, func(t *testing.T) {
			doc, rec, rows := manualSignatureTargetFixture()
			p, err := captureManualSignatureTargets(doc, rec, rows)
			if err != nil {
				t.Fatal(err)
			}
			if action == "remove second" {
				rows = rows[:1]
			} else {
				extra := *rows[1]
				extra.ID = uuid.New()
				rows = append(rows, &extra)
			}
			if _, err := validateLockedManualSignatureTargets(p, doc, rec, rows); !errors.Is(err, ErrSignaturePreparationChanged) {
				t.Fatalf("changed target count error=%v", err)
			}
		})
	}
}

func TestManualSignatureTargetsRefuseInvalidPreflight(t *testing.T) {
	mutations := map[string]func(*generated.Document, []*generated.DocumentField){
		"missing source key":     func(d *generated.Document, _ []*generated.DocumentField) { d.PdfStorageKey.Valid = false },
		"missing source version": func(d *generated.Document, _ []*generated.DocumentField) { d.PdfStorageVersionID.Valid = false },
		"invalid source hash":    func(d *generated.Document, _ []*generated.DocumentField) { d.PdfSha256 = d.PdfSha256[:31] },
		"duplicate id":           func(_ *generated.Document, r []*generated.DocumentField) { r[1].ID = r[0].ID },
		"foreign field":          func(_ *generated.Document, r []*generated.DocumentField) { r[1].DocumentID = uuid.New() },
		"nil field":              func(_ *generated.Document, r []*generated.DocumentField) { r[1] = nil },
		"null x":                 func(_ *generated.Document, r []*generated.DocumentField) { r[1].XPct.Valid = false },
		"NaN x":                  func(_ *generated.Document, r []*generated.DocumentField) { r[1].XPct.NaN = true },
		"infinite x": func(_ *generated.Document, r []*generated.DocumentField) {
			r[1].XPct.InfinityModifier = pgtype.Infinity
		},
		"zero width":        func(_ *generated.Document, r []*generated.DocumentField) { r[1].WPct.Int.SetInt64(0) },
		"outside viewport":  func(_ *generated.Document, r []*generated.DocumentField) { r[1].XPct.Int.SetInt64(90) },
		"zero page":         func(_ *generated.Document, r []*generated.DocumentField) { r[1].Page = 0 },
		"unbounded decimal": func(_ *generated.Document, r []*generated.DocumentField) { r[1].XPct.Exp = -1000000 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			doc, rec, rows := manualSignatureTargetFixture()
			mutate(doc, rows)
			if _, err := captureManualSignatureTargets(doc, rec, rows); err == nil {
				t.Fatal("invalid preflight admitted")
			}
		})
	}
	doc, rec, rows := manualSignatureTargetFixture()
	if _, err := captureManualSignatureTargets(doc, uuid.New(), rows); err == nil {
		t.Fatal("no assigned signatures admitted")
	}
	if _, err := validateLockedManualSignatureTargets(nil, doc, rec, rows); !errors.Is(err, ErrSignaturePreparationChanged) {
		t.Fatal(err)
	}
	// Legacy source rows remain admissible under their existing digest-bound,
	// read-only version-resolution policy; preparation never invents a pin.
	doc.EvidenceVersionPinsRequired = false
	doc.PdfStorageVersionID = pgtype.Text{}
	if _, err := captureManualSignatureTargets(doc, rec, rows); err != nil {
		t.Fatal(err)
	}
}
