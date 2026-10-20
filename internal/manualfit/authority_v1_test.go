// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
)

func authorityFixtureV1(t *testing.T) (AuthorityInputV1, sanitize.PDFManualGeometry) {
	t.Helper()
	org := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	doc := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	recipient := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	first := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	second := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	third := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	source := SourceTupleV1{Key: "opaque/source.pdf", VersionID: "opaque+/exact=version", SHA256: strings.Repeat("a", 64), Bytes: 100}
	in := AuthorityInputV1{OrgID: org, DocumentID: doc, RecipientID: recipient,
		CeremonyEpoch: time.Date(2026, 10, 11, 12, 30, 1, 123456000, time.UTC), Source: source,
		TypedName: "Åsa María Example", Font: "Caveat", SpanSHA256: strings.Repeat("b", 64),
		ExpectedTargetIDs: []uuid.UUID{third, first, second},
		Targets: []TargetV1{
			{ID: third, OrgID: org, DocumentID: doc, RecipientID: recipient, Page: 3, Required: true, X: "12.3400", Y: "25.0000", W: "50.0000", H: "10.0000"},
			{ID: second, OrgID: org, DocumentID: doc, RecipientID: recipient, Page: 1, Required: true, X: "0.0000", Y: "0.0000", W: "40.0000", H: "10.0000"},
			{ID: first, OrgID: org, DocumentID: doc, RecipientID: recipient, Page: 3, Required: true, X: "0.0001", Y: "60.0000", W: "75.0000", H: "10.0000"},
		}}
	page := sanitize.PDFManualPage{Rotation: 90, UserUnit: 2}
	for i := range page.Boxes {
		page.Boxes[i] = [4]float64{-20, 10, 180, 410}
	}
	page.Boxes[1] = [4]float64{0, 30, 160, 390}
	g := sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: source.SHA256, SourceBytes: source.Bytes,
		Pages: []sanitize.PDFManualPage{page, page, page}}
	authorityGeometryHashV1(t, &g)
	return in, g
}

func authorityGeometryHashV1(t *testing.T, g *sanitize.PDFManualGeometry) {
	t.Helper()
	raw, err := json.Marshal(g.Pages)
	if err != nil {
		t.Fatal(err)
	}
	g.GeometrySHA256 = authoritySHA256V1(raw)
}

func TestAuthorityV1AllPagesAndExactPercentages(t *testing.T) {
	in, g := authorityFixtureV1(t)
	a, err := BuildAuthorityV1(in, g)
	if err != nil {
		t.Fatal(err)
	}
	pages := a.Pages()
	if len(pages) != 2 || pages[0].Plan.Page != 1 || pages[1].Plan.Page != 3 {
		t.Fatalf("wrong assigned page set: %+v", pages)
	}
	for _, page := range pages {
		if page.Plan.WidthPoints != "720" || page.Plan.HeightPoints != "320" {
			t.Fatalf("rotation/UserUnit/CropBox lost: %+v", page.Plan)
		}
		if page.Plan.SourceSHA256 != in.Source.SHA256 || page.Plan.GeometrySHA256 != g.GeometrySHA256 || page.Plan.SpanSHA256 != in.SpanSHA256 {
			t.Fatal("lost source/geometry/span binding")
		}
		wantSHA, err := signaturefit.InputSHA(page.Plan)
		if err != nil || page.InputSHA256 != wantSHA {
			t.Fatalf("wrong request SHA: %s %v", page.InputSHA256, err)
		}
	}
	if len(pages[0].Plan.Targets) != 1 || len(pages[1].Plan.Targets) != 2 {
		t.Fatal("target coverage changed")
	}
	if pages[1].Plan.Targets[0].ID != "00000000-0000-0000-0000-000000000001" ||
		pages[1].Plan.Targets[0].X != "0.000001" || pages[1].Plan.Targets[1].X != "0.1234" {
		t.Fatalf("targets not sorted or exact: %+v", pages[1].Plan.Targets)
	}
	if a.Input().Targets[2].X != "12.3400" {
		t.Fatal("raw database decimal was rewritten")
	}
	if len(a.Geometry().Pages) != 3 {
		t.Fatal("unassigned source page omitted from geometry authority")
	}
	if a.SHA256() != authoritySHA256V1(a.CanonicalJSON()) {
		t.Fatal("wrong authority digest")
	}
	if a.FontInfo().SHA256 == "" {
		t.Fatal("frozen font pin absent")
	}
	// Input order and timezone presentation cannot change an otherwise exact
	// authority. Original decimal spelling remains a separate commitment.
	in.Targets[0], in.Targets[2] = in.Targets[2], in.Targets[0]
	in.ExpectedTargetIDs[0], in.ExpectedTargetIDs[2] = in.ExpectedTargetIDs[2], in.ExpectedTargetIDs[0]
	in.CeremonyEpoch = in.CeremonyEpoch.In(time.FixedZone("fixture", 2*60*60))
	b, err := BuildAuthorityV1(in, g)
	if err != nil || !bytes.Equal(a.CanonicalJSON(), b.CanonicalJSON()) {
		t.Fatalf("noncanonical order or epoch: %v", err)
	}
}

func TestAuthorityV1CopiesInputsAndOutputs(t *testing.T) {
	in, g := authorityFixtureV1(t)
	a, err := BuildAuthorityV1(in, g)
	if err != nil {
		t.Fatal(err)
	}
	before := a.CanonicalJSON()
	beforeInput := a.Input()
	beforePages := a.Pages()
	in.ExpectedTargetIDs[0] = uuid.Nil
	in.Targets[0].X = "99"
	g.Pages[0].Boxes[0][0] = 999
	copyInput := a.Input()
	copyInput.ExpectedTargetIDs[0] = uuid.Nil
	copyInput.Targets[0].X = "99"
	copyGeometry := a.Geometry()
	copyGeometry.Pages[0].Boxes[0][0] = 999
	copyPages := a.Pages()
	copyPages[0].Plan.Targets[0].X = "0.99"
	copyCanonical := a.CanonicalJSON()
	copyCanonical[0] = 'x'
	if !bytes.Equal(before, a.CanonicalJSON()) || a.Input().Targets[0] != beforeInput.Targets[0] ||
		a.Input().ExpectedTargetIDs[0] != beforeInput.ExpectedTargetIDs[0] || a.Pages()[0].Plan.Targets[0] != beforePages[0].Plan.Targets[0] ||
		a.Geometry().Pages[0].Boxes[0][0] != -20 {
		t.Fatal("authority aliases mutable input or output")
	}
}

func TestAuthorityV1WorkerViewportVariants(t *testing.T) {
	for _, tc := range []struct {
		name          string
		rotation      int
		userUnit      float64
		disjointCrop  bool
		width, height string
	}{
		{"unrotated nonzero origin", 0, 1, false, "160", "360"},
		{"quarter turn scaled", 90, 2, false, "720", "320"},
		{"half turn", 180, 1, false, "160", "360"},
		{"negative quarter turn", -90, 1, false, "360", "160"},
		{"disjoint CropBox MediaBox fallback", 270, 2, true, "800", "400"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, g := authorityFixtureV1(t)
			for i := range g.Pages {
				g.Pages[i].Rotation = tc.rotation
				g.Pages[i].UserUnit = tc.userUnit
				if tc.disjointCrop {
					g.Pages[i].Boxes[1] = [4]float64{500, 600, 700, 800}
				}
			}
			authorityGeometryHashV1(t, &g)
			a, err := BuildAuthorityV1(in, g)
			if err != nil {
				t.Fatal(err)
			}
			for _, page := range a.Pages() {
				if page.Plan.WidthPoints != tc.width || page.Plan.HeightPoints != tc.height {
					t.Fatalf("worker viewport changed: %+v", page.Plan)
				}
			}
			if a.Geometry().Pages[0] != g.Pages[0] {
				t.Fatal("original boxes/rotation/UserUnit mutated")
			}
		})
	}
}

func TestAuthorityV1RejectsIncompleteForeignAndStaleInputs(t *testing.T) {
	changes := map[string]func(*AuthorityInputV1, *sanitize.PDFManualGeometry){
		"missing all targets": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.Targets = nil
			in.ExpectedTargetIDs = nil
		},
		"missing expected ID": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.ExpectedTargetIDs = in.ExpectedTargetIDs[:2]
		},
		"missing target": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets = in.Targets[:2] },
		"extra target": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.Targets = append(in.Targets, in.Targets[0])
		},
		"unexpected target": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].ID[15] = 9 },
		"duplicate target":  func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0] = in.Targets[1] },
		"duplicate expected ID": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.ExpectedTargetIDs[0] = in.ExpectedTargetIDs[1]
		},
		"absent target ID": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.Targets[0].ID = uuid.Nil
			in.ExpectedTargetIDs[0] = uuid.Nil
		},
		"foreign org":         func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].OrgID = in.DocumentID },
		"foreign document":    func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].DocumentID = in.OrgID },
		"cross-party":         func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].RecipientID = in.OrgID },
		"not required":        func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].Required = false },
		"missing source page": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].Page = 4 },
		"zero page":           func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].Page = 0 },
		"zero width":          func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].W = "0" },
		"negative x":          func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].X = "-0.0001" },
		"exact edge overflow": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.Targets[0].X = "99.9999"
			in.Targets[0].W = "0.0002"
		},
		"decimal control":            func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].X = "1\x00" },
		"decimal exponent":           func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].X = "1e1" },
		"absent source key":          func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.Key = "" },
		"invalid key UTF8":           func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.Key = string([]byte{0xff}) },
		"absent source version":      func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.VersionID = " " },
		"source version control":     func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.VersionID = "v\x00x" },
		"source version newline":     func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.VersionID = "v\nx" },
		"source key carriage return": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.Key = "source\r.pdf" },
		"development source version": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.Source.VersionID = "hash:unversioned-development"
		},
		"unbounded source version": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.Source.VersionID = strings.Repeat("x", 1025)
		},
		"source digest case": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.Source.SHA256 = strings.ToUpper(in.Source.SHA256)
		},
		"zero source digest": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.SHA256 = strings.Repeat("0", 64) },
		"source too large":   func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.Bytes = sanitize.MaxPDFBytes + 1 },
		"stale source SHA":   func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.SourceSHA256 = strings.Repeat("c", 64) },
		"stale source bytes": func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.SourceBytes++ },
		"missing geometry":   func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.Pages = nil },
		"too many source pages": func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) {
			for len(g.Pages) <= sanitize.MaxPDFPages {
				g.Pages = append(g.Pages, g.Pages[0])
			}
		},
		"wrong geometry schema":       func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.SchemaVersion = 2 },
		"stale geometry SHA":          func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.GeometrySHA256 = strings.Repeat("c", 64) },
		"changed unassigned geometry": func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.Pages[1].Rotation = 180 },
		"unsupported rotation":        func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.Pages[0].Rotation = 45 },
		"bad UserUnit":                func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.Pages[0].UserUnit = 0 },
		"nonfinite box":               func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.Pages[0].Boxes[0][0] = math.NaN() },
		"unsupported viewport":        func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) { g.Pages[0].UserUnit = 75000 },
		"missing epoch":               func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.CeremonyEpoch = time.Time{} },
		"missing identity":            func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.RecipientID = uuid.Nil },
		"invalid font":                func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Font = "fallback" },
		"invalid span digest":         func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.SpanSHA256 = "" },
		"blank name":                  func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.TypedName = "  " },
		"too long name":               func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.TypedName = strings.Repeat("Å", 201) },
		"invalid name UTF8":           func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.TypedName = string([]byte{0xff}) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			in, g := authorityFixtureV1(t)
			change(&in, &g)
			if _, err := BuildAuthorityV1(in, g); err == nil {
				t.Fatal("invalid authority accepted")
			}
		})
	}
}

func TestAuthorityV1ChangesCommitments(t *testing.T) {
	changes := map[string]func(*AuthorityInputV1, *sanitize.PDFManualGeometry){
		"source key":           func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.Key += "/changed" },
		"source exact version": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Source.VersionID += "+changed" },
		"ceremony epoch": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) {
			in.CeremonyEpoch = in.CeremonyEpoch.Add(time.Microsecond)
		},
		"name":                 func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.TypedName += " Junior" },
		"font":                 func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Font = "Sacramento" },
		"span":                 func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.SpanSHA256 = strings.Repeat("c", 64) },
		"last target":          func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].X = "12.3401" },
		"raw decimal spelling": func(in *AuthorityInputV1, _ *sanitize.PDFManualGeometry) { in.Targets[0].X = "12.34" },
		"unassigned page geometry": func(_ *AuthorityInputV1, g *sanitize.PDFManualGeometry) {
			g.Pages[1].Rotation = 180
			authorityGeometryHashV1(t, g)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			in, g := authorityFixtureV1(t)
			before, err := BuildAuthorityV1(in, g)
			if err != nil {
				t.Fatal(err)
			}
			change(&in, &g)
			after, err := BuildAuthorityV1(in, g)
			if err != nil {
				t.Fatal(err)
			}
			if before.SHA256() == after.SHA256() {
				t.Fatal("changed authority commitment was ignored")
			}
		})
	}
}

func TestAuthorityV1TargetBudgetsAndFiveFonts(t *testing.T) {
	in, g := authorityFixtureV1(t)
	in.Targets = nil
	in.ExpectedTargetIDs = nil
	for i := 0; i < MaxAuthorityTargetsV1; i++ {
		id := uuid.UUID{14: byte((i + 1) >> 8), 15: byte(i + 1)}
		in.ExpectedTargetIDs = append(in.ExpectedTargetIDs, id)
		in.Targets = append(in.Targets, TargetV1{ID: id, OrgID: in.OrgID, DocumentID: in.DocumentID, RecipientID: in.RecipientID,
			Page: i/MaxAuthorityTargetsPerPageV1 + 1, Required: true, X: "0", Y: "0", W: "50", H: "10"})
	}
	for len(g.Pages) < 8 {
		g.Pages = append(g.Pages, g.Pages[0])
	}
	authorityGeometryHashV1(t, &g)
	in.TypedName = strings.Repeat("Å", 200)
	for _, font := range []string{"Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple"} {
		in.Font = font
		a, err := BuildAuthorityV1(in, g)
		if err != nil {
			t.Fatalf("all-target/font boundary refused %s: %v", font, err)
		}
		count := 0
		for _, page := range a.Pages() {
			count += len(page.Plan.Targets)
		}
		if count != MaxAuthorityTargetsV1 || len(a.Pages()) != 8 {
			t.Fatalf("all-target coverage lost: %d", count)
		}
	}
	tooMany := in
	tooMany.Targets = append(append([]TargetV1(nil), in.Targets...), in.Targets[0])
	tooMany.ExpectedTargetIDs = append(append([]uuid.UUID(nil), in.ExpectedTargetIDs...), in.ExpectedTargetIDs[0])
	if _, err := BuildAuthorityV1(tooMany, g); err == nil {
		t.Fatal("total target cap ignored")
	}
	tooManyOnPage := in
	tooManyOnPage.Targets = append([]TargetV1(nil), in.Targets[:129]...)
	tooManyOnPage.ExpectedTargetIDs = append([]uuid.UUID(nil), in.ExpectedTargetIDs[:129]...)
	for i := range tooManyOnPage.Targets {
		tooManyOnPage.Targets[i].Page = 1
	}
	if _, err := BuildAuthorityV1(tooManyOnPage, g); err == nil {
		t.Fatal("per-page target cap ignored")
	}
}

func TestPercentToFractionV1ExactBaseTen(t *testing.T) {
	for raw, want := range map[string]string{"0": "0", "-0.0000": "0", "+100.0000": "1", "12.3400": "0.1234", "000.0100": "0.0001", ".0001": "0.000001", "99.9999": "0.999999", "1.": "0.01"} {
		got, err := PercentToFractionV1(raw)
		if err != nil || got != want {
			t.Fatalf("%q -> %q, want %q: %v", raw, got, want, err)
		}
	}
	for _, raw := range []string{"", ".", "+", "-1", "100.0001", "NaN", "Inf", "1/2", "1e1", " 1", "1 ", "1\n", "1\x00", "1..0", strings.Repeat("0", 129), "0." + strings.Repeat("0", 33)} {
		if _, err := PercentToFractionV1(raw); err == nil {
			t.Fatalf("invalid decimal %q accepted", raw)
		}
	}
}
