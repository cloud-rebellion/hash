// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestSignerFieldListCostsMeasureTextOptionsAndOverflowV1(t *testing.T) {
	a, b, u, err := signerFieldListCostsV1(2, 10, 20)
	if err != nil || a <= 0 || b <= 0 || u < 6*30+2*1024 {
		t.Fatal("actual JSON/control bound absent", err)
	}
	for _, input := range [][3]int64{{2, 1000, 20}, {2, 10, 1000}, {3, 10, 20}} {
		x, y, z, err := signerFieldListCostsV1(input[0], input[1], input[2])
		if err != nil || x <= a || y <= b || z <= u {
			t.Fatal("field count/text/options did not increase paid live costs", err)
		}
	}
	for _, input := range [][3]int64{{-1, 0, 0}, {0, -1, 0}, {0, 0, -1}, {math.MaxInt64, 0, 0}, {1, math.MaxInt64, 0}, {1, 0, math.MaxInt64}, {1, math.MaxInt64 / 4, math.MaxInt64 / 4}} {
		if _, _, _, err := signerFieldListCostsV1(input[0], input[1], input[2]); err == nil {
			t.Fatal("invalid/overflowing resource or JSON cost admitted")
		}
	}
}

func TestDocumentFieldResponsePreservesWireSemanticsV1(t *testing.T) {
	id := uuid.MustParse("18200000-0000-4000-8000-000000000001")
	doc := uuid.MustParse("18200000-0000-4000-8000-000000000002")
	party := uuid.MustParse("18200000-0000-4000-8000-000000000003")
	coordinate := pgtype.Numeric{Int: big.NewInt(123456), Exp: -4, Valid: true}
	f := &generated.DocumentField{ID: id, DocumentID: doc, RecipientID: pgtype.UUID{Bytes: party, Valid: true}, Type: "signature", Page: 2, XPct: coordinate, YPct: coordinate, WPct: coordinate, HPct: coordinate, Required: true, Label: pgtype.Text{Valid: true}, Value: pgtype.Text{String: "Å<&\u2028", Valid: true}, OptionsJson: json.RawMessage(`{"example":"<&\u2028"}`), CompletedAt: pgtype.Timestamptz{Time: time.Date(2026, 10, 17, 1, 2, 3, 456789000, time.FixedZone("fixture", 3600)), Valid: true}}
	got, err := json.Marshal(DocumentFieldDTOV1(f))
	want := `{"completed_at":"2026-10-17T00:02:03.456Z","document_id":"18200000-0000-4000-8000-000000000002","h_pct":12.345600000000001,"id":"18200000-0000-4000-8000-000000000001","label":"","options":{"example":"\u003c\u0026\u2028"},"page":2,"recipient_id":"18200000-0000-4000-8000-000000000003","required":true,"type":"signature","value":"Å\u003c\u0026\u2028","w_pct":12.345600000000001,"x_pct":12.345600000000001,"y_pct":12.345600000000001}`
	if err != nil || string(got) != want {
		t.Fatalf("original numeric/optional/escaping/signature projection changed: %s (%v)", got, err)
	}
	f.RecipientID = pgtype.UUID{}
	f.Label = pgtype.Text{}
	f.Value = pgtype.Text{}
	f.CompletedAt = pgtype.Timestamptz{}
	f.OptionsJson = nil
	value := DocumentFieldDTOV1(f)
	for _, key := range []string{"recipient_id", "label", "value", "completed_at", "options"} {
		if _, exists := value[key]; exists {
			t.Fatal("SQL NULL changed to present empty value", key)
		}
	}
	if fieldCoordinateV1(pgtype.Numeric{}) != 0 {
		t.Fatal("invalid numeric lost original zero behavior")
	}
}

func TestSignerFieldListRejectsUnownedReadersAndOperationsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, _ := htmlInputFactoryTestV1(t, 64<<20)
	for _, r := range []*ApplicationSignerReaderV1{nil, {}, {factory: f}} {
		if h, err := f.NewSignerFieldListInputV1(ctx, r); err == nil || h != nil {
			t.Fatal("unowned reader supplied field scope")
		}
	}
	for _, h := range []*ApplicationSignerFieldListInputV1{nil, {}, {factory: f}} {
		if op, finish, err := f.NewSignerFieldListOperationV1(h); err == nil || op != nil || finish != nil {
			t.Fatal("unregistered input constructed field operation")
		}
	}
	if h, err := f.NewHTMLAuthoringInputV1(ctx, uuid.New(), signerFieldListInputProfileV1); err == nil || h != nil {
		t.Fatal("ordinary body profile fabricated field-read authority")
	}
}
