// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
)

func manifestFixtureV1(t *testing.T) (*ManifestV1, ObjectPinV1, []PageArtifactV1) {
	t.Helper()
	in, g := authorityFixtureV1(t)
	span := []byte(`<span class="hash-signature" data-font="Caveat">Åsa María Example</span>`)
	in.SpanSHA256 = authoritySHA256V1(span)
	a, err := BuildAuthorityV1(in, g)
	if err != nil {
		t.Fatal(err)
	}
	op := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	prefix := ObjectPrefixV1(op, in.OrgID, in.DocumentID)
	spanPin := ObjectPinV1{prefix + "span.html", " exact+/opaque=version ", in.SpanSHA256, int64(len(span)), "text/html"}
	pages := make([]PageArtifactV1, 0)
	for _, p := range a.Pages() {
		pages = append(pages, PageArtifactV1{p.Plan.Page, p.InputSHA256,
			ObjectPinV1{prefix + "page-" + itoaTestV1(p.Plan.Page) + ".fit", "page-version+/=", strings.Repeat("c", 64), 400, signaturefit.MediaType},
			strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64), a.FontInfo().SHA256, strings.Repeat("a", 64)})
	}
	m, err := NewManifestV1(op, a, spanPin, pages)
	if err != nil {
		t.Fatal(err)
	}
	return m, spanPin, pages
}
func itoaTestV1(page int) string {
	if page == 1 {
		return "1"
	}
	if page == 3 {
		return "3"
	}
	return "unsupported"
}

func TestManifestV1CompleteBindingAndImmutability(t *testing.T) {
	m, span, pages := manifestFixtureV1(t)
	before := m.CanonicalJSON()
	if m.AggregateBytes() != int64(len(before))+span.Bytes+pages[0].Package.Bytes+pages[1].Package.Bytes {
		t.Fatal("aggregate omitted evidence bytes")
	}
	if m.Binding().AuthoritySHA256 != m.Authority().SHA256() || m.SHA256() != authoritySHA256V1(before) {
		t.Fatal("commitment mismatch")
	}
	binding := m.Binding()
	binding.CeremonyEpoch = binding.CeremonyEpoch.In(time.FixedZone("fixture", 3600))
	decoded, err := DecodeManifestV1(before, binding)
	if err != nil || !bytes.Equal(decoded.CanonicalJSON(), before) || decoded.Span().VersionID != span.VersionID {
		t.Fatalf("opaque identity not preserved: %v", err)
	}
	reverse := append([]PageArtifactV1(nil), pages...)
	reverse[0], reverse[1] = reverse[1], reverse[0]
	reordered, err := NewManifestV1(m.Binding().OperationID, m.Authority(), span, reverse)
	if err != nil || !bytes.Equal(reordered.CanonicalJSON(), before) {
		t.Fatal("constructor ordering is not stable")
	}
	pages[0].Page = 99
	reverse[0].Package.Key = "foreign"
	before[0] = 'x'
	got := m.Pages()
	got[0].Package.VersionID = "changed"
	a := m.Authority()
	canonical := a.CanonicalJSON()
	canonical[0] = 'x'
	targets := a.Input()
	targets.Targets[0].X = "90"
	raw := m.CanonicalJSON()
	if raw[0] != '{' || m.Pages()[0].Page != 1 || m.Pages()[0].Package.VersionID != "page-version+/=" || m.Authority().Input().Targets[0].X == "90" {
		t.Fatal("mutable accessor aliases manifest")
	}
}

func TestManifestV1RejectsChangedAuthorityAndPins(t *testing.T) {
	m, span, pages := manifestFixtureV1(t)
	cases := []struct {
		name string
		edit func(*ObjectPinV1, []PageArtifactV1)
	}{
		{"foreign operation span", func(s *ObjectPinV1, p []PageArtifactV1) { s.Key = strings.Replace(s.Key, "44444444", "55555555", 1) }},
		{"wrong span hash", func(s *ObjectPinV1, p []PageArtifactV1) { s.SHA256 = strings.Repeat("a", 64) }},
		{"empty version", func(s *ObjectPinV1, p []PageArtifactV1) { s.VersionID = "" }},
		{"control version", func(s *ObjectPinV1, p []PageArtifactV1) { s.VersionID = "opaque\nversion" }},
		{"development version", func(s *ObjectPinV1, p []PageArtifactV1) { s.VersionID = "hash:unversioned-development" }},
		{"unbounded version", func(s *ObjectPinV1, p []PageArtifactV1) { s.VersionID = strings.Repeat("v", 1025) }},
		{"wrong span mime", func(s *ObjectPinV1, p []PageArtifactV1) { s.ContentType = "application/pdf" }},
		{"oversized span", func(s *ObjectPinV1, p []PageArtifactV1) { s.Bytes = MaxSpanBytesV1 + 1 }},
		{"foreign package", func(s *ObjectPinV1, p []PageArtifactV1) { p[0].Package.Key = p[1].Package.Key }},
		{"wrong page", func(s *ObjectPinV1, p []PageArtifactV1) { p[0].Page = 2 }},
		{"wrong input hash", func(s *ObjectPinV1, p []PageArtifactV1) { p[0].InputSHA256 = strings.Repeat("a", 64) }},
		{"wrong frozen font", func(s *ObjectPinV1, p []PageArtifactV1) { p[0].FontSHA256 = strings.Repeat("a", 64) }},
		{"oversized package", func(s *ObjectPinV1, p []PageArtifactV1) { p[0].Package.Bytes = int64(signaturefit.MaxPackageBytes) + 1 }},
		{"wrong package mime", func(s *ObjectPinV1, p []PageArtifactV1) { p[0].Package.ContentType = "application/pdf" }},
		{"noncanonical digest", func(s *ObjectPinV1, p []PageArtifactV1) { p[0].PDFSHA256 = strings.Repeat("D", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := span
			p := append([]PageArtifactV1(nil), pages...)
			tc.edit(&s, p)
			if _, err := NewManifestV1(m.Binding().OperationID, m.Authority(), s, p); err == nil {
				t.Fatal("accepted changed identity or cap")
			}
		})
	}
	for _, p := range [][]PageArtifactV1{nil, pages[:1], append(append([]PageArtifactV1(nil), pages...), pages[0])} {
		if _, err := NewManifestV1(m.Binding().OperationID, m.Authority(), span, p); err == nil {
			t.Fatal("accepted omitted or duplicate pages")
		}
	}
	if _, err := NewManifestV1(uuid.Nil, m.Authority(), span, pages); err == nil {
		t.Fatal("accepted nil operation")
	}
	for _, field := range []string{"operation", "org", "document", "recipient", "epoch", "authority"} {
		t.Run("binding "+field, func(t *testing.T) {
			b := m.Binding()
			switch field {
			case "operation":
				b.OperationID = uuid.New()
			case "org":
				b.OrgID = uuid.New()
			case "document":
				b.DocumentID = uuid.New()
			case "recipient":
				b.RecipientID = uuid.New()
			case "epoch":
				b.CeremonyEpoch = b.CeremonyEpoch.Add(time.Microsecond)
			case "authority":
				b.AuthoritySHA256 = strings.Repeat("a", 64)
			}
			if _, err := DecodeManifestV1(m.CanonicalJSON(), b); err == nil {
				t.Fatal("accepted foreign binding")
			}
		})
	}
}

func TestManifestV1ClosedCanonicalDecoding(t *testing.T) {
	m, _, _ := manifestFixtureV1(t)
	raw := m.CanonicalJSON()
	changed := [][]byte{
		append(append([]byte(nil), raw...), byte(' ')),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"hash-manual-signature-fit-manifest-v1","schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"SCHEMA":`), 1),
		bytes.Replace(raw, []byte(`"pages":[`), []byte(`"pages":null,"unused":[`), 1),
		bytes.Replace(raw, []byte(`"page":1`), []byte(`"page":1.0`), 1),
		bytes.Replace(raw, []byte(`"recipe_sha256":"`+signaturefit.RecipeSHA256V1+`"`), []byte(`"recipe_sha256":"`+strings.Repeat("a", 64)+`"`), 1),
		[]byte("{}"), nil, bytes.Repeat([]byte{' '}, MaxManifestBytesV1+1),
	}
	for i, b := range changed {
		if _, err := DecodeManifestV1(b, m.Binding()); err == nil {
			t.Fatalf("accepted nonclosed form %d", i)
		}
	}
	var wire manifestWireV1
	if json.Unmarshal(raw, &wire) != nil {
		t.Fatal("fixture")
	}
	wire.Pages[0], wire.Pages[1] = wire.Pages[1], wire.Pages[0]
	b, _ := json.Marshal(wire)
	if _, err := DecodeManifestV1(b, m.Binding()); err == nil {
		t.Fatal("decoder normalized reversed pages")
	}
}

func TestArchivedAuthorityV1ClosedIndependentGeometry(t *testing.T) {
	in, g := authorityFixtureV1(t)
	a, err := BuildAuthorityV1(in, g)
	if err != nil {
		t.Fatal(err)
	}
	archived, err := DecodeAuthorityV1(a.CanonicalJSON())
	if err != nil || archived.SHA256() != a.SHA256() {
		t.Fatalf("archived authority: %v", err)
	}
	for _, edit := range []func(*authorityCanonicalV1){
		func(s *authorityCanonicalV1) { s.FontInfo.SHA256 = strings.Repeat("a", 64) },
		func(s *authorityCanonicalV1) { s.Pages = s.Pages[:1] },
		func(s *authorityCanonicalV1) { s.Targets[0].X = "1.0000" },
		func(s *authorityCanonicalV1) { s.ExpectedTargetIDs[0] = uuid.Nil },
		func(s *authorityCanonicalV1) { s.Geometry.Pages[1].Rotation = 45 },
		func(s *authorityCanonicalV1) { s.Pages[0].Plan.Text = "Different name" },
		func(s *authorityCanonicalV1) { s.CeremonyEpoch = "2026-10-11T13:30:01.123456+01:00" },
	} {
		var wire authorityCanonicalV1
		if json.Unmarshal(a.CanonicalJSON(), &wire) != nil {
			t.Fatal("fixture")
		}
		edit(&wire)
		raw, _ := json.Marshal(wire)
		if _, err := DecodeAuthorityV1(raw); err == nil {
			t.Fatal("accepted changed archived authority")
		}
	}
	for _, raw := range [][]byte{bytes.Replace(a.CanonicalJSON(), []byte(`"schema":`), []byte(`"schema":"manual_pdf_fit_v1","schema":`), 1), []byte("null"), append(a.CanonicalJSON(), ' ')} {
		if _, err := DecodeAuthorityV1(raw); err == nil {
			t.Fatal("accepted nonclosed authority")
		}
	}
}

func TestManifestV1AggregateBoundary(t *testing.T) {
	span := ObjectPinV1{Bytes: 100}
	pages := []PageArtifactV1{{Package: ObjectPinV1{Bytes: MaxEvidenceBytesV1 - 300}}}
	if total, err := aggregateBytesV1(200, span, pages); err != nil || total != MaxEvidenceBytesV1 {
		t.Fatalf("exact aggregate boundary: %d %v", total, err)
	}
	pages[0].Package.Bytes++
	if _, err := aggregateBytesV1(200, span, pages); err == nil {
		t.Fatal("accepted aggregate overflow")
	}
	pages[0].Package.Bytes = 1 << 62
	if _, err := aggregateBytesV1(200, span, pages); err == nil {
		t.Fatal("accepted overflowing arithmetic")
	}
}

func TestManifestV1AllPageBudgetAdmission(t *testing.T) {
	base, span, _ := manifestFixtureV1(t)
	in, g := authorityFixtureV1(t)
	in.SpanSHA256 = span.SHA256
	for len(g.Pages) < 10 {
		g.Pages = append(g.Pages, g.Pages[0])
	}
	in.Targets = nil
	in.ExpectedTargetIDs = nil
	for i := 1; i <= 10; i++ {
		id := uuid.UUID{15: byte(i)}
		in.ExpectedTargetIDs = append(in.ExpectedTargetIDs, id)
		in.Targets = append(in.Targets, TargetV1{id, in.OrgID, in.DocumentID, in.RecipientID, i, true, "0", "0", "50", "50"})
	}
	authorityGeometryHashV1(t, &g)
	a, err := BuildAuthorityV1(in, g)
	if err != nil {
		t.Fatal(err)
	}
	prefix := ObjectPrefixV1(base.Binding().OperationID, in.OrgID, in.DocumentID)
	artifacts := make([]PageArtifactV1, 0, 10)
	for _, p := range a.Pages() {
		artifacts = append(artifacts, PageArtifactV1{p.Plan.Page, p.InputSHA256,
			ObjectPinV1{prefix + "page-" + strconv.Itoa(p.Plan.Page) + ".fit", "exact-version", strings.Repeat("c", 64), int64(signaturefit.MaxPackageBytes), signaturefit.MediaType},
			strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64), a.FontInfo().SHA256, strings.Repeat("a", 64)})
	}
	if _, err := NewManifestV1(base.Binding().OperationID, a, span, artifacts); err == nil {
		t.Fatal("accepted ten maximum packages beyond 160 MiB")
	}
	// Shrinking an actual declared package, instead of dropping any assigned page,
	// allows the complete same authority to fit within the cumulative budget.
	artifacts[9].Package.Bytes = 1
	if m, err := NewManifestV1(base.Binding().OperationID, a, span, artifacts); err != nil || len(m.Pages()) != 10 {
		t.Fatalf("complete bounded page set refused: %v", err)
	}
	if _, err := NewManifestV1(base.Binding().OperationID, a, span, artifacts[:9]); err == nil {
		t.Fatal("omitted page accepted to evade budget")
	}
}

func TestVersionV1SourceArtifactsAndReadBoundaryAgree(t *testing.T) {
	m, span, pages := manifestFixtureV1(t)
	rejected := []string{"null", " null ", " null ", "hash:unversioned-development", " hash:unversioned-development ", "opaque" + string(rune(10)) + "version", "   "}
	for _, version := range rejected {
		t.Run("reject "+version, func(t *testing.T) {
			input := m.Authority().Input()
			input.Source.VersionID = version
			if _, err := BuildAuthorityV1(input, m.Authority().Geometry()); err == nil {
				t.Fatal("constructor accepted reserved source version")
			}
			var wire authorityCanonicalV1
			if json.Unmarshal(m.Authority().CanonicalJSON(), &wire) != nil {
				t.Fatal("authority fixture")
			}
			wire.Source.VersionID = version
			raw, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeAuthorityV1(raw); err == nil {
				t.Fatal("reserved source version accepted")
			}
			changedSpan := span
			changedSpan.VersionID = version
			if _, err := NewManifestV1(m.Binding().OperationID, m.Authority(), changedSpan, pages); err == nil {
				t.Fatal("reserved span version accepted")
			}
			changedPages := append([]PageArtifactV1(nil), pages...)
			changedPages[0].Package.VersionID = version
			if _, err := NewManifestV1(m.Binding().OperationID, m.Authority(), span, changedPages); err == nil {
				t.Fatal("reserved package version accepted")
			}
			var mw manifestWireV1
			if json.Unmarshal(m.CanonicalJSON(), &mw) != nil {
				t.Fatal("manifest fixture")
			}
			mw.Pages[0].Package.VersionID = version
			encoded, _ := json.Marshal(mw)
			if _, err := DecodeManifestV1(encoded, m.Binding()); err == nil {
				t.Fatal("decoder accepted reserved package version")
			}
			pin := ObjectPinV1{m.ManifestKey(), version, m.SHA256(), int64(len(m.CanonicalJSON())), "application/json"}
			store := &fitStoreTestV1{blobs: map[string]fitBlobTestV1{}}
			if _, err := VerifyRetainedV1(context.Background(), store, pin, m.Binding()); err == nil || len(store.reads) != 0 {
				t.Fatal("reserved manifest version reached storage")
			}
		})
	}
	// Invalid UTF-8 cannot be faithfully represented by json.Marshal; inject it
	// into a valid raw archive instead of testing the replacement Rune it emits.
	var badAuthority authorityCanonicalV1
	if json.Unmarshal(m.Authority().CanonicalJSON(), &badAuthority) != nil {
		t.Fatal("authority fixture")
	}
	badAuthority.Source.VersionID = "invalid-version-marker"
	encodedBad, _ := json.Marshal(badAuthority)
	encodedBad = bytes.Replace(encodedBad, []byte("invalid-version-marker"), []byte{0xff}, 1)
	if _, err := DecodeAuthorityV1(encodedBad); err == nil {
		t.Fatal("invalid UTF-8 source version accepted")
	}
	invalidInput := m.Authority().Input()
	invalidInput.Source.VersionID = string([]byte{0xff})
	if _, err := BuildAuthorityV1(invalidInput, m.Authority().Geometry()); err == nil {
		t.Fatal("constructor accepted invalid UTF-8 source version")
	}
	badSpan := span
	badSpan.VersionID = string([]byte{0xff})
	if _, err := NewManifestV1(m.Binding().OperationID, m.Authority(), badSpan, pages); err == nil {
		t.Fatal("invalid UTF-8 artifact version accepted")
	}
	for _, version := range []string{" exact opaque version ", " Åsa/+/= ", "version null suffix", "NULL"} {
		t.Run("preserve "+version, func(t *testing.T) {
			input := m.Authority().Input()
			input.Source.VersionID = version
			built, err := BuildAuthorityV1(input, m.Authority().Geometry())
			if err != nil || built.Input().Source.VersionID != version {
				t.Fatalf("constructor changed opaque source: %v", err)
			}
			var wire authorityCanonicalV1
			if json.Unmarshal(m.Authority().CanonicalJSON(), &wire) != nil {
				t.Fatal("authority fixture")
			}
			wire.Source.VersionID = version
			raw, _ := json.Marshal(wire)
			authority, err := DecodeAuthorityV1(raw)
			if err != nil || authority.Input().Source.VersionID != version {
				t.Fatalf("opaque source changed: %v", err)
			}
			copiedSpan := span
			copiedSpan.VersionID = version
			copiedPages := append([]PageArtifactV1(nil), pages...)
			copiedPages[0].Package.VersionID = version
			created, err := NewManifestV1(m.Binding().OperationID, authority, copiedSpan, copiedPages)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeManifestV1(created.CanonicalJSON(), created.Binding())
			if err != nil || decoded.Authority().Input().Source.VersionID != version || decoded.Span().VersionID != version || decoded.Pages()[0].Package.VersionID != version {
				t.Fatalf("opaque artifact version changed: %v", err)
			}
		})
	}
}
