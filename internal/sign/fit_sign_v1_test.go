// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are snapshot/authority tests, not rendered PDF or legal acceptance.
func fittedSignAuthorityFixtureV1(t *testing.T) (*generated.Document, uuid.UUID, []*generated.DocumentField, SignInput, []byte, sanitize.PDFManualGeometry) {
	t.Helper()
	doc, recipient, fields := manualSignatureTargetFixture()
	epoch := time.Date(2026, 10, 12, 12, 30, 0, 123456000, time.UTC)
	doc.SentAt = pgtype.Timestamptz{Time: epoch, Valid: true}
	doc.Article13NoticeEpochAt = doc.SentAt
	doc.Article13NoticeEpochV61Committed = true
	input := SignInput{TypedName: strings.Repeat("Å", 200), Font: "Caveat"}
	span, err := render.RenderSignatureSpan(input.TypedName, input.Font)
	if err != nil {
		t.Fatal(err)
	}
	page := sanitize.PDFManualPage{UserUnit: 1}
	for i := range page.Boxes {
		page.Boxes[i] = [4]float64{-20, 10, 980, 610}
	}
	page.Boxes[1] = [4]float64{10, 20, 910, 560}
	geometry := sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: hex.EncodeToString(doc.PdfSha256), SourceBytes: 100,
		Pages: []sanitize.PDFManualPage{page, page, page}}
	raw, err := json.Marshal(geometry.Pages)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	geometry.GeometrySHA256 = hex.EncodeToString(digest[:])
	return doc, recipient, fields, input, []byte(span), geometry
}

func TestCaptureFittedAuthorityV1PreservesWholeNameSourceAllPagesAndExactTargets(t *testing.T) {
	doc, recipient, fields, input, span, geometry := fittedSignAuthorityFixtureV1(t)
	authority, err := captureFittedAuthorityV1(doc, recipient, fields, input, span, geometry)
	if err != nil {
		t.Fatal(err)
	}
	captured := authority.Input()
	if captured.TypedName != input.TypedName || captured.Source.VersionID != doc.PdfStorageVersionID.String ||
		!captured.CeremonyEpoch.Equal(doc.SentAt.Time) || len(captured.Targets) != 2 || len(authority.Geometry().Pages) != 3 {
		t.Fatal("name, exact source, epoch, all targets or untouched-page geometry lost")
	}
	for _, target := range captured.Targets {
		if target.X != "10" || target.Y != "70" || target.W != "30" || target.H != "8" {
			t.Fatal("database percentages changed")
		}
	}
	for _, page := range authority.Pages() {
		for _, target := range page.Plan.Targets {
			if target.X != "0.1" || target.Y != "0.7" || target.W != "0.3" || target.H != "0.08" {
				t.Fatal("renderer did not receive exact fractional coordinates")
			}
		}
	}
	pin := authority.SHA256()
	fields[0].XPct.Int.SetInt64(11)
	geometry.Pages[2].UserUnit = 3
	doc.PdfSha256[0] ^= 1
	span[0] ^= 1
	if authority.SHA256() != pin || authority.Input().Targets[0].X != "10" {
		t.Fatal("mutable query/provider inputs altered captured authority")
	}
}

func TestCaptureFittedAuthorityV1RefusesUncommittedEpochSourceGeometryAndUnsafeSpan(t *testing.T) {
	cases := map[string]func(*generated.Document, []*generated.DocumentField, *SignInput, *[]byte, *sanitize.PDFManualGeometry){
		"notice uncommitted": func(d *generated.Document, _ []*generated.DocumentField, _ *SignInput, _ *[]byte, _ *sanitize.PDFManualGeometry) {
			d.Article13NoticeEpochV61Committed = false
		},
		"notice epoch changed": func(d *generated.Document, _ []*generated.DocumentField, _ *SignInput, _ *[]byte, _ *sanitize.PDFManualGeometry) {
			d.Article13NoticeEpochAt.Time = d.SentAt.Time.Add(time.Microsecond)
		},
		"required source version missing": func(d *generated.Document, _ []*generated.DocumentField, _ *SignInput, _ *[]byte, _ *sanitize.PDFManualGeometry) {
			d.PdfStorageVersionID.Valid = false
		},
		"legacy unpinned source": func(d *generated.Document, _ []*generated.DocumentField, _ *SignInput, _ *[]byte, _ *sanitize.PDFManualGeometry) {
			d.EvidenceVersionPinsRequired = false
		},
		"envelope child": func(d *generated.Document, _ []*generated.DocumentField, _ *SignInput, _ *[]byte, _ *sanitize.PDFManualGeometry) {
			d.ParentEnvelopeID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		},
		"wrong source geometry": func(_ *generated.Document, _ []*generated.DocumentField, _ *SignInput, _ *[]byte, g *sanitize.PDFManualGeometry) {
			g.SourceSHA256 = strings.Repeat("0", 64)
		},
		"oversized source": func(_ *generated.Document, _ []*generated.DocumentField, _ *SignInput, _ *[]byte, g *sanitize.PDFManualGeometry) {
			g.SourceBytes = sanitize.MaxPDFBytes + 1
		},
		"changed name": func(_ *generated.Document, _ []*generated.DocumentField, i *SignInput, _ *[]byte, _ *sanitize.PDFManualGeometry) {
			i.TypedName = "another name"
		},
		"changed font": func(_ *generated.Document, _ []*generated.DocumentField, i *SignInput, _ *[]byte, _ *sanitize.PDFManualGeometry) {
			i.Font = "Sacramento"
		},
		"active markup": func(_ *generated.Document, _ []*generated.DocumentField, _ *SignInput, s *[]byte, _ *sanitize.PDFManualGeometry) {
			*s = append(*s, []byte("<script>alert(1)</script>")...)
		},
		"second target outside pages": func(_ *generated.Document, f []*generated.DocumentField, _ *SignInput, _ *[]byte, _ *sanitize.PDFManualGeometry) {
			f[1].Page = 4
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc, recipient, fields, input, span, geometry := fittedSignAuthorityFixtureV1(t)
			mutate(doc, fields, &input, &span, &geometry)
			if a, err := captureFittedAuthorityV1(doc, recipient, fields, input, span, geometry); a != nil || !errors.Is(err, ErrSignaturePreparationChanged) {
				t.Fatalf("unsafe capture returned authority=%v error=%v", a != nil, err)
			}
		})
	}
}
