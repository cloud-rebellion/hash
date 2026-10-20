// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package documentpackage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func fixtureV1() InputV1 {
	org := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	root := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	return InputV1{
		Binding: BindingV1{org, root, uuid.MustParse("33333333-3333-4333-a333-333333333333"), 1},
		Main: MemberV1{DocumentID: root, Title: "Main agreement", Category: "Agreement",
			PDF:    PDFPinV1{"org/" + org.String() + "/documents/44444444-4444-4444-8444-444444444444.pdf", " version+/= ", strings.Repeat("a", 64), 1000, 2},
			Source: SourcePinV1{Kind: SourcePDFImportV1}},
	}
}

func mixedFixtureV1() InputV1 {
	in := fixtureV1()
	in.Main.Source = SourcePinV1{SourceHTMLRevisionV1, strings.Repeat("b", 64), strings.Repeat("c", 64),
		&MaterializationPinV1{uuid.MustParse("55555555-5555-4555-b555-555555555555"), 2}}
	for i, title := range []string{"Data processing agreement", "Nondisclosure agreement"} {
		annex := cloneMemberV1(in.Main)
		annex.DocumentID = uuid.UUID{15: byte(i + 20)}
		annex.Title, annex.Category = title, []string{"DPA", "NDA"}[i]
		annex.PDF.Key = "org/" + in.Binding.OrgID.String() + "/documents/annex-" + strconv.Itoa(i) + ".pdf"
		annex.PDF.VersionID = "annex+/=" + strconv.Itoa(i)
		annex.Source = SourcePinV1{Kind: SourcePDFImportV1}
		if i == 1 {
			annex.Source = SourcePinV1{Kind: SourceHTMLOriginV1, CommitmentSHA256: strings.Repeat("d", 64), OriginCommitmentSHA256: strings.Repeat("d", 64)}
		}
		in.Annexes = append(in.Annexes, annex)
	}
	return in
}

func mustManifestV1(t *testing.T, in InputV1) *ManifestV1 {
	t.Helper()
	m, err := NewManifestV1(in)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// This independent expression deliberately does not call the implementation's
// commitment helper or use its exported domain constant.
func legalHashTestV1(raw []byte) string {
	sum := sha256.Sum256(append([]byte("hash:legal-package-manifest:v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func expectedV1(m *ManifestV1) ExpectedV1 { return ExpectedV1{m.Binding(), m.CommitmentSHA256()} }

func TestManifestV1LiteralCanonicalVectorAndHashDomains(t *testing.T) {
	in := fixtureV1()
	in.Binding.Revision = 9007199254740993 // above JavaScript's exact integer range
	m := mustManifestV1(t, in)
	const canonical = `{"schema":"hash-legal-package-manifest-v1","binding":{"org_id":"11111111-1111-4111-8111-111111111111","document_id":"22222222-2222-4222-8222-222222222222","package_id":"33333333-3333-4333-a333-333333333333","revision":"9007199254740993"},"main":{"document_id":"22222222-2222-4222-8222-222222222222","title":"Main agreement","category":"Agreement","pdf":{"key":"org/11111111-1111-4111-8111-111111111111/documents/44444444-4444-4444-8444-444444444444.pdf","version_id":" version+/= ","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":1000,"pages":2},"source":{"kind":"pdf-import","commitment_sha256":"","origin_commitment_sha256":"","materialization":null}},"annexes":[]}`
	if string(m.CanonicalJSON()) != canonical {
		t.Fatal("canonical format changed")
	}
	// Calculated independently with Node crypto from the literal 703-byte vector.
	if m.CanonicalSHA256() != "f4bb7f4da27f4b1b0424db4ea70788ac83c7bb2dc76508ceebd432ffc3dd7997" ||
		m.CommitmentSHA256() != "237f931c7d048387c19c4273860d82486c1653d77691ec62491b5b5242dfdca6" {
		t.Fatal("published digest vector changed")
	}
	plain := sha256.Sum256([]byte(canonical))
	if m.CanonicalSHA256() != hex.EncodeToString(plain[:]) || m.CommitmentSHA256() != legalHashTestV1([]byte(canonical)) || m.CommitmentSHA256() == m.CanonicalSHA256() {
		t.Fatal("legal commitment and stored-object hash were conflated")
	}
	decoded, err := DecodeManifestV1([]byte(canonical), expectedV1(m))
	if err != nil || decoded.Binding().Revision != in.Binding.Revision || decoded.Main().PDF.VersionID != in.Main.PDF.VersionID {
		t.Fatal("identity or opaque version changed", err)
	}
	if _, err := DecodeManifestV1(m.CanonicalJSON(), ExpectedV1{m.Binding(), m.CanonicalSHA256()}); !errors.Is(err, ErrManifestV1) {
		t.Fatal("object hash accepted as legal commitment")
	}
	// The imported source and reviewed PDF are one tuple, not twice the input.
	if m.AggregatePDFBytes() != 1000 || m.AggregatePDFPages() != 2 {
		t.Fatal("source tuple double charged")
	}
}

func TestManifestV1OrderAndEveryClaimAreCommitted(t *testing.T) {
	base := mustManifestV1(t, mixedFixtureV1())
	cases := []struct {
		name string
		edit func(*InputV1)
	}{
		{"package", func(in *InputV1) { in.Binding.PackageID[15]++ }},
		{"revision", func(in *InputV1) { in.Binding.Revision++ }},
		{"root", func(in *InputV1) { in.Binding.DocumentID[15]++; in.Main.DocumentID = in.Binding.DocumentID }},
		{"title", func(in *InputV1) { in.Main.Title = "Näringsliv – agreement" }},
		{"category", func(in *InputV1) { in.Main.Category = "Custom business document" }},
		{"key", func(in *InputV1) { in.Main.PDF.Key += ".new" }},
		{"version", func(in *InputV1) { in.Main.PDF.VersionID += "new" }},
		{"PDF hash", func(in *InputV1) { in.Main.PDF.SHA256 = strings.Repeat("f", 64) }},
		{"PDF bytes", func(in *InputV1) { in.Main.PDF.Bytes++ }},
		{"PDF pages", func(in *InputV1) { in.Main.PDF.Pages++ }},
		{"source commitment", func(in *InputV1) { in.Main.Source.CommitmentSHA256 = strings.Repeat("e", 64) }},
		{"origin commitment", func(in *InputV1) { in.Main.Source.OriginCommitmentSHA256 = strings.Repeat("e", 64) }},
		{"materialization ID", func(in *InputV1) { in.Main.Source.Materialization.ID[15]++ }},
		{"materialization sequence", func(in *InputV1) { in.Main.Source.Materialization.Sequence++ }},
		{"annex ID", func(in *InputV1) { in.Annexes[0].DocumentID[15] += 10 }},
		{"annex title", func(in *InputV1) { in.Annexes[0].Title += " revised" }},
		{"annex order", func(in *InputV1) { in.Annexes[0], in.Annexes[1] = in.Annexes[1], in.Annexes[0] }},
		{"annex removal", func(in *InputV1) { in.Annexes = in.Annexes[:1] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base.Input()
			tc.edit(&in)
			changed := mustManifestV1(t, in)
			if changed.CommitmentSHA256() == base.CommitmentSHA256() || bytes.Equal(changed.CanonicalJSON(), base.CanonicalJSON()) {
				t.Fatal("changed claim lost")
			}
			if _, err := DecodeManifestV1(changed.CanonicalJSON(), expectedV1(base)); !errors.Is(err, ErrManifestV1) {
				t.Fatal("changed valid manifest accepted against old freeze")
			}
		})
	}
}

func TestManifestV1DeepImmutabilityAndMainOnlyEquivalence(t *testing.T) {
	in := mixedFixtureV1()
	in.Annexes[0].Source = cloneMemberV1(in.Main).Source
	m := mustManifestV1(t, in)
	raw, digest, object := m.CanonicalJSON(), m.CommitmentSHA256(), m.CanonicalSHA256()
	in.Main.Source.Materialization.Sequence = 99
	in.Annexes[0].Source.Materialization.Sequence = 96
	in.Annexes[0].Title = "changed caller"
	main, annexes, copy := m.Main(), m.Annexes(), m.Input()
	main.Source.Materialization.Sequence = 98
	annexes[0].Title = "changed getter"
	annexes[0].Source.Materialization.Sequence = 95
	copy.Main.Source.Materialization.Sequence = 97
	copy.Annexes[0].Title = "changed input"
	copy.Annexes[0].Source.Materialization.Sequence = 94
	returned := m.CanonicalJSON()
	returned[0] = 'x'
	if !bytes.Equal(m.CanonicalJSON(), raw) || m.Main().Source.Materialization.Sequence != 2 || m.Annexes()[0].Title != "Data processing agreement" || m.Annexes()[0].Source.Materialization.Sequence != 2 || m.CommitmentSHA256() != digest || m.CanonicalSHA256() != object {
		t.Fatal("mutable alias escaped")
	}
	decoded, err := DecodeManifestV1(raw, expectedV1(m))
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'x'
	if decoded.CanonicalJSON()[0] != '{' {
		t.Fatal("decoder retained caller bytes")
	}
	nilAnnex := mustManifestV1(t, fixtureV1())
	empty := fixtureV1()
	empty.Annexes = []MemberV1{}
	emptyAnnex := mustManifestV1(t, empty)
	if !bytes.Equal(nilAnnex.CanonicalJSON(), emptyAnnex.CanonicalJSON()) || !bytes.HasSuffix(nilAnnex.CanonicalJSON(), []byte(`"annexes":[]}`)) {
		t.Fatal("main-only ambiguity")
	}
}

func TestManifestV1MixedSourceShapes(t *testing.T) {
	base := fixtureV1()
	for _, source := range []SourcePinV1{
		{Kind: SourcePDFImportV1},
		{Kind: SourceHTMLOriginV1, CommitmentSHA256: strings.Repeat("b", 64), OriginCommitmentSHA256: strings.Repeat("b", 64)},
		{SourceHTMLRevisionV1, strings.Repeat("b", 64), strings.Repeat("b", 64), &MaterializationPinV1{base.Binding.PackageID, 1}},
		{SourceHTMLRevisionV1, strings.Repeat("b", 64), strings.Repeat("c", 64), &MaterializationPinV1{base.Binding.PackageID, 2}},
	} {
		in := base
		in.Main.Source = source
		m := mustManifestV1(t, in)
		if _, err := DecodeManifestV1(m.CanonicalJSON(), expectedV1(m)); err != nil {
			t.Fatal(err)
		}
	}
	invalid := []SourcePinV1{
		{}, {Kind: "blocks"},
		{Kind: SourcePDFImportV1, CommitmentSHA256: strings.Repeat("a", 64)},
		{Kind: SourcePDFImportV1, OriginCommitmentSHA256: strings.Repeat("a", 64)},
		{Kind: SourcePDFImportV1, Materialization: &MaterializationPinV1{base.Binding.PackageID, 1}},
		{Kind: SourceHTMLOriginV1, CommitmentSHA256: strings.Repeat("b", 64)},
		{Kind: SourceHTMLOriginV1, CommitmentSHA256: strings.Repeat("b", 64), OriginCommitmentSHA256: strings.Repeat("c", 64)},
		{SourceHTMLOriginV1, strings.Repeat("b", 64), strings.Repeat("b", 64), &MaterializationPinV1{base.Binding.PackageID, 1}},
		{Kind: SourceHTMLRevisionV1, CommitmentSHA256: strings.Repeat("b", 64), OriginCommitmentSHA256: strings.Repeat("b", 64)},
		{SourceHTMLRevisionV1, strings.Repeat("b", 64), strings.Repeat("c", 64), &MaterializationPinV1{base.Binding.PackageID, 1}},
		{SourceHTMLRevisionV1, strings.Repeat("b", 64), strings.Repeat("c", 64), &MaterializationPinV1{uuid.Nil, 2}},
		{SourceHTMLRevisionV1, strings.Repeat("b", 64), strings.Repeat("c", 64), &MaterializationPinV1{base.Binding.PackageID, 0}},
	}
	for i, source := range invalid {
		in := base
		in.Main.Source = source
		if _, err := NewManifestV1(in); !errors.Is(err, ErrManifestV1) {
			t.Fatalf("invalid source %d accepted", i)
		}
	}
}

func TestManifestV1OwnershipDuplicatesAndOpaqueVersions(t *testing.T) {
	base := mixedFixtureV1()
	cases := []struct {
		name string
		edit func(*InputV1)
	}{
		{"zero org", func(in *InputV1) { in.Binding.OrgID = uuid.Nil }},
		{"zero root", func(in *InputV1) { in.Binding.DocumentID = uuid.Nil }},
		{"zero package", func(in *InputV1) { in.Binding.PackageID = uuid.Nil }},
		{"zero revision", func(in *InputV1) { in.Binding.Revision = 0 }},
		{"negative revision", func(in *InputV1) { in.Binding.Revision = -1 }},
		{"wrong main", func(in *InputV1) { in.Main.DocumentID = in.Binding.PackageID }},
		{"zero annex", func(in *InputV1) { in.Annexes[0].DocumentID = uuid.Nil }},
		{"duplicate document", func(in *InputV1) { in.Annexes[0].DocumentID = in.Main.DocumentID }},
		{"duplicate object", func(in *InputV1) { in.Annexes[0].PDF = in.Main.PDF }},
		{"contradictory duplicate object", func(in *InputV1) { in.Annexes[0].PDF = in.Main.PDF; in.Annexes[0].PDF.SHA256 = strings.Repeat("e", 64) }},
		{"foreign org", func(in *InputV1) { in.Main.PDF.Key = "org/" + in.Binding.PackageID.String() + "/doc.pdf" }},
		{"prefix lookalike", func(in *InputV1) { in.Main.PDF.Key = "org/" + in.Binding.OrgID.String() + "-foreign/doc.pdf" }},
		{"traversal", func(in *InputV1) { in.Main.PDF.Key += "/../foreign.pdf" }},
		{"empty segment", func(in *InputV1) { in.Main.PDF.Key += "//other.pdf" }},
		{"backslash", func(in *InputV1) { in.Main.PDF.Key += "\\other.pdf" }},
		{"key trailing space", func(in *InputV1) { in.Main.PDF.Key += " " }},
		{"key trailing Unicode space", func(in *InputV1) { in.Main.PDF.Key += "\u00a0" }},
		{"zero digest", func(in *InputV1) { in.Main.PDF.SHA256 = strings.Repeat("0", 64) }},
		{"uppercase digest", func(in *InputV1) { in.Main.PDF.SHA256 = strings.Repeat("A", 64) }},
		{"invalid digest", func(in *InputV1) { in.Main.PDF.SHA256 = strings.Repeat("g", 64) }},
		{"empty title", func(in *InputV1) { in.Main.Title = "" }},
		{"title boundary space", func(in *InputV1) { in.Main.Title = " Leading" }},
		{"title control", func(in *InputV1) { in.Main.Title = "A\nB" }},
		{"title line separator", func(in *InputV1) { in.Main.Title = "A\u2028B" }},
		{"invalid title UTF8", func(in *InputV1) { in.Main.Title = string([]byte{0xff}) }},
		{"title byte cap", func(in *InputV1) { in.Main.Title = strings.Repeat("å", MaxTitleBytesV1/2+1) }},
		{"category cap", func(in *InputV1) { in.Main.Category = strings.Repeat("c", MaxCategoryBytesV1+1) }},
		{"key cap", func(in *InputV1) { in.Main.PDF.Key += strings.Repeat("k", MaxObjectTextBytesV1) }},
		{"key control", func(in *InputV1) { in.Main.PDF.Key += "\x00" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := cloneInputV1(base)
			tc.edit(&in)
			if _, err := NewManifestV1(in); !errors.Is(err, ErrManifestV1) {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
	for _, version := range []string{"", " ", "\u2003", "null", " null ", "\u2003hash:unversioned-development\u2003", "bad\nversion", string([]byte{0xff}), strings.Repeat("v", 1025)} {
		in := cloneInputV1(base)
		in.Main.PDF.VersionID = version
		if _, err := NewManifestV1(in); !errors.Is(err, ErrManifestV1) {
			t.Fatal("invalid version accepted")
		}
	}
	for _, version := range []string{" opaque+/=version ", "\u2003v+/=\u2003", "NULL", "%2F+a=", "version with spaces", strings.Repeat("v", 1024)} {
		in := cloneInputV1(base)
		in.Main.PDF.VersionID = version
		m := mustManifestV1(t, in)
		decoded, err := DecodeManifestV1(m.CanonicalJSON(), expectedV1(m))
		if err != nil || decoded.Main().PDF.VersionID != version {
			t.Fatal("opaque provider bytes changed", err)
		}
	}
	// Distinct object versions and distinct objects with equal content remain distinct.
	in := cloneInputV1(base)
	in.Annexes[0].PDF.Key = in.Main.PDF.Key
	in.Annexes[0].PDF.VersionID = "another-version"
	in.Annexes[0].PDF.SHA256 = in.Main.PDF.SHA256
	mustManifestV1(t, in)
	in.Annexes[0].PDF.Key += ".copy"
	in.Annexes[0].PDF.VersionID = in.Main.PDF.VersionID
	mustManifestV1(t, in)
}

func TestManifestV1AggregateAndMetadataBoundaries(t *testing.T) {
	in := fixtureV1()
	in.Main.PDF.Bytes = MaxPDFBytesV1
	in.Main.PDF.Pages = MaxPDFPagesV1
	m := mustManifestV1(t, in)
	if m.AggregatePDFBytes() != MaxPDFBytesV1 || m.AggregatePDFPages() != MaxPDFPagesV1 {
		t.Fatal("single tuple double charged")
	}
	in = mixedFixtureV1()
	in.Annexes = in.Annexes[:1]
	in.Main.PDF.Bytes = MaxPDFBytesV1 / 2
	in.Annexes[0].PDF.Bytes = MaxPDFBytesV1 / 2
	in.Main.PDF.Pages = 250
	in.Annexes[0].PDF.Pages = 250
	mustManifestV1(t, in)
	for _, edit := range []func(*InputV1){func(v *InputV1) { v.Annexes[0].PDF.Bytes++ }, func(v *InputV1) { v.Annexes[0].PDF.Pages++ }, func(v *InputV1) { v.Main.PDF.Bytes = math.MaxInt64 }, func(v *InputV1) { v.Main.PDF.Bytes = 0 }, func(v *InputV1) { v.Main.PDF.Bytes = -1 }, func(v *InputV1) { v.Main.PDF.Pages = math.MaxInt32 }, func(v *InputV1) { v.Main.PDF.Pages = -1 }} {
		changed := cloneInputV1(in)
		edit(&changed)
		if _, err := NewManifestV1(changed); !errors.Is(err, ErrManifestV1) {
			t.Fatal("aggregate/overflow bound bypassed")
		}
	}
	in = fixtureV1()
	in.Main.Title = strings.Repeat("t", MaxTitleBytesV1)
	in.Main.Category = strings.Repeat("c", MaxCategoryBytesV1)
	for i := 0; i < MaxAnnexesV1; i++ {
		member := cloneMemberV1(in.Main)
		member.DocumentID = uuid.UUID{15: byte(i + 30)}
		member.PDF.Key = "org/" + in.Binding.OrgID.String() + "/annex-" + strconv.Itoa(i)
		in.Annexes = append(in.Annexes, member)
	}
	mustManifestV1(t, in)
	extra := cloneMemberV1(in.Main)
	extra.DocumentID = uuid.UUID{15: 99}
	extra.PDF.Key += ".extra"
	in.Annexes = append(in.Annexes, extra)
	if _, err := NewManifestV1(in); !errors.Is(err, ErrManifestV1) {
		t.Fatal("annex limit bypassed")
	}
}

func TestManifestV1ExactCanonicalByteLimit(t *testing.T) {
	in := fixtureV1()
	fill := func(member *MemberV1, index int) {
		member.Title = strings.Repeat("t", 512)
		member.Category = strings.Repeat("c", 128)
		prefix := "org/" + in.Binding.OrgID.String() + "/part-" + strconv.Itoa(index) + "/"
		member.PDF.Key = prefix + strings.Repeat("k", 1024-len(prefix))
		member.PDF.VersionID = strings.Repeat("v", 1024)
	}
	fill(&in.Main, 0)
	in.Main.PDF.VersionID = in.Main.PDF.VersionID[:1023] // one legal byte reserved for the +1 test
	for i := 0; i < 16; i++ {
		member := cloneMemberV1(in.Main)
		member.DocumentID = uuid.UUID{15: byte(i + 40)}
		fill(&member, i+1)
		in.Annexes = append(in.Annexes, member)
	}
	base := mustManifestV1(t, in)
	needed := MaxManifestBytesV1 - len(base.CanonicalJSON())
	if needed <= 0 {
		t.Fatal("boundary fixture too large")
	}
	if remainder := needed % 5; remainder != 0 {
		trim := 5 - remainder
		in.Main.Category = in.Main.Category[:len(in.Main.Category)-trim]
		needed += trim
	}
	// Go's fixed canonical encoder spells '&' as six ASCII bytes. Each
	// replacement increases the wire length by five without changing text caps.
	amps := needed / 5
	for i := -1; i < len(in.Annexes) && amps > 0; i++ {
		member := &in.Main
		if i >= 0 {
			member = &in.Annexes[i]
		}
		n := min(amps, len(member.PDF.VersionID))
		member.PDF.VersionID = strings.Repeat("&", n) + member.PDF.VersionID[n:]
		amps -= n
	}
	if amps != 0 {
		t.Fatal("insufficient metadata room")
	}
	m := mustManifestV1(t, in)
	if len(m.CanonicalJSON()) != MaxManifestBytesV1 {
		t.Fatal("did not hit exact byte boundary")
	}
	if _, err := DecodeManifestV1(m.CanonicalJSON(), expectedV1(m)); err != nil {
		t.Fatal("exact boundary refused", err)
	}
	in.Main.PDF.VersionID += "v"
	if _, err := NewManifestV1(in); !errors.Is(err, ErrManifestV1) {
		t.Fatal("one byte over canonical cap accepted")
	}
}

func TestManifestV1TrustedDecodeBinding(t *testing.T) {
	m := mustManifestV1(t, mixedFixtureV1())
	for _, edit := range []func(*ExpectedV1){func(e *ExpectedV1) { e.Binding.OrgID[15]++ }, func(e *ExpectedV1) { e.Binding.DocumentID[15]++ }, func(e *ExpectedV1) { e.Binding.PackageID[15]++ }, func(e *ExpectedV1) { e.Binding.Revision++ }, func(e *ExpectedV1) { e.CommitmentSHA256 = "" }, func(e *ExpectedV1) { e.CommitmentSHA256 = strings.Repeat("0", 64) }, func(e *ExpectedV1) { e.CommitmentSHA256 = strings.ToUpper(e.CommitmentSHA256) }} {
		expected := expectedV1(m)
		edit(&expected)
		if _, err := DecodeManifestV1(m.CanonicalJSON(), expected); !errors.Is(err, ErrManifestV1) {
			t.Fatal("foreign/stale expectation accepted")
		}
	}
	in := m.Input()
	in.Binding.Revision = math.MaxInt64
	max := mustManifestV1(t, in)
	decoded, err := DecodeManifestV1(max.CanonicalJSON(), expectedV1(max))
	if err != nil || decoded.Binding().Revision != math.MaxInt64 {
		t.Fatal("bigint precision lost", err)
	}
}

func TestManifestV1ClosedCanonicalDecode(t *testing.T) {
	m := mustManifestV1(t, fixtureV1())
	raw := m.CanonicalJSON()
	cases := map[string][]byte{
		"empty": nil, "null": []byte("null"), "trailing whitespace": append(bytes.Clone(raw), ' '), "trailing object": append(bytes.Clone(raw), []byte("{}")...),
		"unknown":                   bytes.Replace(raw, []byte(`"schema":`), []byte(`"extra":0,"schema":`), 1),
		"duplicate":                 bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"hash-legal-package-manifest-v1","schema":`), 1),
		"escaped duplicate":         bytes.Replace(raw, []byte(`"schema":`), []byte(`"\u0073chema":"hash-legal-package-manifest-v1","schema":`), 1),
		"case alias":                bytes.Replace(raw, []byte(`"schema":`), []byte(`"SCHEMA":`), 1),
		"unsupported schema":        bytes.Replace(raw, []byte(ManifestSchemaV1), []byte("hash-legal-package-manifest-v2"), 1),
		"UUID alias":                bytes.Replace(raw, []byte("4333-a333"), []byte("4333-A333"), 1),
		"revision number":           bytes.Replace(raw, []byte(`"revision":"1"`), []byte(`"revision":1`), 1),
		"revision leading zero":     bytes.Replace(raw, []byte(`"revision":"1"`), []byte(`"revision":"01"`), 1),
		"revision exponent":         bytes.Replace(raw, []byte(`"revision":"1"`), []byte(`"revision":"1e0"`), 1),
		"float integer":             bytes.Replace(raw, []byte(`"bytes":1000`), []byte(`"bytes":1000.0`), 1),
		"exponent integer":          bytes.Replace(raw, []byte(`"bytes":1000`), []byte(`"bytes":1e3`), 1),
		"null annexes":              bytes.Replace(raw, []byte(`"annexes":[]`), []byte(`"annexes":null`), 1),
		"omitted optional category": bytes.Replace(raw, []byte(`"category":"Agreement",`), nil, 1),
		"null category":             bytes.Replace(raw, []byte(`"category":"Agreement"`), []byte(`"category":null`), 1),
		"null main":                 bytes.Replace(raw, []byte(`"main":{`), []byte(`"main":null,"unknown":{`), 1),
		"lone surrogate":            bytes.Replace(raw, []byte(`"Main agreement"`), []byte(`"\ud800"`), 1),
		"invalid UTF8":              bytes.Replace(raw, []byte("Main agreement"), []byte{0xff}, 1),
		"over bytes":                bytes.Repeat([]byte{' '}, MaxManifestBytesV1+1),
		"over depth":                []byte(`{"unknown":` + strings.Repeat("[", 10) + "0" + strings.Repeat("]", 10) + "}"),
		"too many annexes":          bytes.Replace(raw, []byte(`"annexes":[]`), []byte(`"annexes":[`+strings.TrimSuffix(strings.Repeat("{},", 17), ",")+`]`), 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			expected := ExpectedV1{m.Binding(), legalHashTestV1(value)}
			if _, err := DecodeManifestV1(value, expected); !errors.Is(err, ErrManifestV1) {
				t.Fatal("noncanonical input accepted")
			}
		})
	}
}

func TestManifestV1PreflightWorkBudget(t *testing.T) {
	value := "0"
	for i := 0; i < 3; i++ {
		value = "[" + strings.TrimSuffix(strings.Repeat(value+",", 16), ",") + "]"
	}
	d := json.NewDecoder(strings.NewReader(value))
	d.UseNumber()
	budget := 2048
	if err := closedTokensV1(d, 0, &budget); !errors.Is(err, ErrManifestV1) || budget >= 0 {
		t.Fatal("token work limit not enforced")
	}
}

func FuzzDecodeManifestV1(f *testing.F) {
	in := fixtureV1()
	m, err := NewManifestV1(in)
	if err != nil {
		f.Fatal(err)
	}
	for _, raw := range [][]byte{m.CanonicalJSON(), nil, []byte("null"), []byte("{}"), []byte{0xff}, []byte(`{"annexes":[{},{}]}`)} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeManifestV1(raw, ExpectedV1{in.Binding, legalHashTestV1(raw)})
		if err != nil {
			if !errors.Is(err, ErrManifestV1) {
				t.Fatal("unexpected error")
			}
			return
		}
		plain := sha256.Sum256(raw)
		if !bytes.Equal(decoded.CanonicalJSON(), raw) || decoded.CommitmentSHA256() != legalHashTestV1(raw) || decoded.CanonicalSHA256() != hex.EncodeToString(plain[:]) {
			t.Fatal("decoder normalized input or corrupted commitment")
		}
	})
}

func TestManifestV1UnicodeLabelsPreserveExactAcceptedBytes(t *testing.T) {
	var previous string
	for _, label := range []string{"Caf\u00e9", "Cafe\u0301"} {
		in := fixtureV1()
		in.Main.Title, in.Main.Category = label, "F\u00f6retagsvillkor"
		m := mustManifestV1(t, in)
		decoded, err := DecodeManifestV1(m.CanonicalJSON(), expectedV1(m))
		if err != nil || decoded.Main().Title != label || decoded.Main().Category != in.Main.Category {
			t.Fatal("Unicode label bytes changed", err)
		}
		if m.CommitmentSHA256() == previous {
			t.Fatal("different accepted Unicode forms collapsed")
		}
		previous = m.CommitmentSHA256()
	}
}
