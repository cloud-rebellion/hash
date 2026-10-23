// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Pure descriptor selection only. The immutable comparison fixture supplies no
// native SQL, storage, publication or actual-PDF proof to these tests.
func delegatedRowsFixtureV1(t *testing.T) (presign.Execution, []*generated.DocumentField, []*generated.Signature) {
	t.Helper()
	raw, err := os.ReadFile("../presignexecute/testdata/execution-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	e, err := presign.DecodeExecution(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := e.Snapshot()
	numeric := func(n int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(n), Exp: -4, Valid: true} }
	fields := make([]*generated.DocumentField, 0, 2)
	for _, f := range s.Document.Fields {
		fields = append(fields, &generated.DocumentField{ID: f.ID, DocumentID: s.Document.ID, RecipientID: pgtype.UUID{Bytes: f.RecipientID, Valid: true}, Type: f.Type, Required: f.Required, Page: int32(f.Page), XPct: numeric(f.X), YPct: numeric(f.Y), WPct: numeric(f.W), HPct: numeric(f.H)})
	}
	digest, err := hex.DecodeString(s.Signature.Image.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	provider := &generated.Signature{ID: s.Signature.ID, DocumentID: s.Document.ID, RecipientID: s.Signature.RecipientID, FieldID: s.Signature.FieldID,
		SignatureKind: "delegated_grant_v1", PresignExecutionID: pgtype.UUID{Bytes: s.ID, Valid: true}, TypedName: s.Signature.TypedName, Font: s.Signature.Style.Font,
		ImageStorageKey: s.Signature.Image.StorageKey, ImageSha256: digest, ImageVersionPinRequired: true, ImageVersionID: pgtype.Text{String: s.Signature.Image.VersionID, Valid: true}, SignedAt: pgtype.Timestamptz{Time: s.ExecutedAt, Valid: true}}
	customer := &generated.Signature{ID: uuid.New(), DocumentID: s.Document.ID, RecipientID: s.Document.Parties[0].ID, FieldID: s.Document.Fields[0].ID, SignatureKind: "manual", SignedAt: pgtype.Timestamptz{Time: s.ExecutedAt.Add(time.Second), Valid: true}}
	return e, fields, []*generated.Signature{customer, provider}
}

func TestDelegatedFinalizationSelectsOnlyExactAlreadyPaintedProviderV1(t *testing.T) {
	e, fields, rows := delegatedRowsFixtureV1(t)
	provider, err := delegatedProviderRecipientForExecutionV1(e, fields, rows)
	if err != nil || provider != e.Snapshot().Signature.RecipientID || provider == rows[0].RecipientID {
		t.Fatal("exact provider not selected", err)
	}
	for name, change := range map[string]func([]*generated.DocumentField, []*generated.Signature){
		"wrong execution": func(_ []*generated.DocumentField, s []*generated.Signature) {
			s[1].PresignExecutionID.Bytes = uuid.New()
		},
		"missing version":  func(_ []*generated.DocumentField, s []*generated.Signature) { s[1].ImageVersionID.Valid = false },
		"changed version":  func(_ []*generated.DocumentField, s []*generated.Signature) { s[1].ImageVersionID.String += "-changed" },
		"changed name":     func(_ []*generated.DocumentField, s []*generated.Signature) { s[1].TypedName = "other" },
		"manual provider":  func(_ []*generated.DocumentField, s []*generated.Signature) { s[1].SignatureKind = "manual" },
		"fitted customer":  func(_ []*generated.DocumentField, s []*generated.Signature) { s[0].SignatureKind = "manual_pdf_fit_v1" },
		"foreign customer": func(_ []*generated.DocumentField, s []*generated.Signature) { s[0].RecipientID = uuid.New() },
		"moved field": func(f []*generated.DocumentField, _ []*generated.Signature) {
			f[1].XPct.Int.Add(f[1].XPct.Int, big.NewInt(1))
		},
		"field required": func(f []*generated.DocumentField, _ []*generated.Signature) { f[0].Required = false },
		"wrong page":     func(f []*generated.DocumentField, _ []*generated.Signature) { f[1].Page++ },
	} {
		t.Run(name, func(t *testing.T) {
			execution, f, s := delegatedRowsFixtureV1(t)
			change(f, s)
			if _, err := delegatedProviderRecipientForExecutionV1(execution, f, s); err == nil {
				t.Fatal("unproved provider skip accepted")
			}
		})
	}
	if _, err := delegatedProviderRecipientForExecutionV1(e, fields, rows[:1]); err == nil {
		t.Fatal("missing party accepted")
	}
}

func TestSignerPresignBodyBorrowerRetainsActualParentGrantV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	org := uuid.New()
	c, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 128}, Organisation: workguard.VectorV1{ParentBytes: 128}, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	r := &ApplicationSignerReaderV1{presignBorrowers: 1, models: &ApplicationSignerReadModelsV1{}, consumers: []func(){g.Close}}
	r.self = r
	r.CloseConsumerV1()
	if c.SnapshotV1(org).Global.ParentBytes != 64 || r.models == nil {
		t.Fatal("active derivative consumer lost actual Parent ownership")
	}
	if next, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 65}); err == nil || next != nil {
		if next != nil {
			next.Close()
		}
		t.Fatal("active derivative body did not block overlapping capacity")
	}
	r.mu.Lock()
	r.presignBorrowers--
	closes := r.retireBlockSigningReadConsumersV1()
	r.mu.Unlock()
	for _, close := range closes {
		close()
	}
	if c.SnapshotV1(org).Global.ParentBytes != 0 || r.models != nil {
		t.Fatal("joined derivative did not retire exact original owner")
	}
	next, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 65})
	if err != nil {
		t.Fatal("joined derivative did not restore original capacity", err)
	}
	next.Close()
}

func TestDelegatedManualGeometryRequiresExactPagesAndVisibleCommitmentV1(t *testing.T) {
	page := sanitize.PDFManualPage{UserUnit: 1}
	for i := range page.Boxes {
		page.Boxes[i] = [4]float64{0, 0, 612, 792}
	}
	original := sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: "base", SourceBytes: 10, GeometrySHA256: "geometry", Pages: []sanitize.PDFManualPage{page}}
	visible := original
	visible.SourceSHA256 = "visible"
	visible.SourceBytes = 20
	pin := presign.ArtifactPin{SHA256: "visible", Bytes: 20}
	if !sameDelegatedManualGeometryV1(visible, original, pin) {
		t.Fatal("identical actual geometry rejected solely because committed source differs")
	}
	for name, change := range map[string]func(*sanitize.PDFManualGeometry){
		"source digest":   func(g *sanitize.PDFManualGeometry) { g.SourceSHA256 = "other" },
		"source count":    func(g *sanitize.PDFManualGeometry) { g.SourceBytes++ },
		"geometry digest": func(g *sanitize.PDFManualGeometry) { g.GeometrySHA256 = "other" },
		"crop":            func(g *sanitize.PDFManualGeometry) { g.Pages[0].Boxes[1][2]-- },
		"rotation":        func(g *sanitize.PDFManualGeometry) { g.Pages[0].Rotation = 90 },
		"user unit":       func(g *sanitize.PDFManualGeometry) { g.Pages[0].UserUnit = 2 },
		"page count":      func(g *sanitize.PDFManualGeometry) { g.Pages = append(g.Pages, page) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := visible
			copy.Pages = append([]sanitize.PDFManualPage(nil), visible.Pages...)
			change(&copy)
			if sameDelegatedManualGeometryV1(copy, original, pin) {
				t.Fatal("changed actual geometry or visible commitment accepted")
			}
		})
	}
}
