// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"math/big"
	"testing"
)

func historicalPDFTargetFixtureV1() (*generated.Document, uuid.UUID, []*generated.DocumentField) {
	id, org, recipient := uuid.New(), uuid.New(), uuid.New()
	n := func(value int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(value), Exp: -4, Valid: true} }
	doc := &generated.Document{ID: id, OrgID: org, SourceKind: "pdf", PdfStorageKey: pgtype.Text{String: "org/source.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "opaque:source:v1", Valid: true}, PdfSha256: bytes.Repeat([]byte{7}, 32), EvidenceVersionPinsRequired: true}
	rows := []*generated.DocumentField{{ID: uuid.MustParse("10000000-0000-0000-0000-000000000001"), DocumentID: id, RecipientID: pgtype.UUID{Bytes: recipient, Valid: true}, Type: "signature", Page: 1, Required: true, XPct: n(100000), YPct: n(200000), WPct: n(500000), HPct: n(100000)}, {ID: uuid.MustParse("20000000-0000-0000-0000-000000000002"), DocumentID: id, RecipientID: pgtype.UUID{Bytes: recipient, Valid: true}, Type: "signature", Page: 2, Required: true, XPct: n(100000), YPct: n(200000), WPct: n(500000), HPct: n(100000)}}
	return doc, recipient, rows
}
func TestHistoricalPDFNativeTargetsBindAllPlacementsAndSourceV1(t *testing.T) {
	doc, recipient, rows := historicalPDFTargetFixtureV1()
	target, err := captureHistoricalPDFTargetsV1(doc, recipient, rows)
	if err != nil {
		t.Fatal(err)
	}
	doc.Status = "in_progress"
	rows[0], rows[1] = rows[1], rows[0]
	representative, err := validateHistoricalPDFTargetsV1(target, doc, recipient, rows)
	if err != nil || representative.ID != target.fields[0].id {
		t.Fatalf("stable source with reordered rows must retain deterministic field: %v %v", representative, err)
	}
	cases := map[string]func(*generated.Document, []*generated.DocumentField){
		"second placement": func(_ *generated.Document, f []*generated.DocumentField) { f[0].XPct.Int = big.NewInt(110000) },
		"source version": func(d *generated.Document, _ []*generated.DocumentField) {
			d.PdfStorageVersionID.String = "opaque:source:v2"
		},
		"source digest":        func(d *generated.Document, _ []*generated.DocumentField) { d.PdfSha256[31] ^= 1 },
		"pins required":        func(d *generated.Document, _ []*generated.DocumentField) { d.EvidenceVersionPinsRequired = false },
		"recipient assignment": func(_ *generated.Document, f []*generated.DocumentField) { f[0].RecipientID.Bytes = uuid.New() },
		"hidden placement":     func(_ *generated.Document, f []*generated.DocumentField) { f[0].WPct.Int = big.NewInt(0) },
		"unbounded representation": func(_ *generated.Document, f []*generated.DocumentField) {
			f[0].XPct.Int = new(big.Int).Lsh(big.NewInt(1), 257)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := htmlSendCloneDocumentV1(doc)
			f := []*generated.DocumentField{htmlSendCloneFieldV1(rows[0]), htmlSendCloneFieldV1(rows[1])}
			mutate(d, f)
			if _, err := validateHistoricalPDFTargetsV1(target, d, recipient, f); !errors.Is(err, ErrHistoricalPDFSignaturePreparationChangedV1) {
				t.Fatalf("changed target accepted: %v", err)
			}
		})
	}
}
func TestHistoricalPDFNativeTargetCaptureRejectsPlaceholderAndForeignV1(t *testing.T) {
	doc, recipient, rows := historicalPDFTargetFixtureV1()
	for name, mutate := range map[string]func([]*generated.DocumentField){"placeholder": func(f []*generated.DocumentField) { f[0].WPct.Int = big.NewInt(0) }, "duplicate": func(f []*generated.DocumentField) { f[1].ID = f[0].ID }, "foreign": func(f []*generated.DocumentField) { f[1].DocumentID = uuid.New() }, "optional": func(f []*generated.DocumentField) { f[1].Required = false }} {
		t.Run(name, func(t *testing.T) {
			f := []*generated.DocumentField{htmlSendCloneFieldV1(rows[0]), htmlSendCloneFieldV1(rows[1])}
			mutate(f)
			if _, err := captureHistoricalPDFTargetsV1(doc, recipient, f); err == nil {
				t.Fatal("invalid placed target accepted")
			}
		})
	}
}
