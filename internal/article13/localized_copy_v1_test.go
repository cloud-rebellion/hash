// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package article13

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func localizedSnapshotTestV1(t *testing.T, locale string) Snapshot {
	t.Helper()
	in := validInput()
	material, err := LocalizedNoticeV1("Customer agreement", "contract", locale)
	if err != nil {
		t.Fatal(err)
	}
	in.PurposeSummary, in.LegalBasisDisclosure, in.Copy = material.PurposeSummary, material.LegalBasisDisclosure, material.Copy
	snapshot, err := NewSnapshot(in)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestLocalizedNoticeV1PreservesExactEnglishAndUnknownFallback(t *testing.T) {
	legal, err := LegalBasisDisclosureV1("contract")
	if err != nil {
		t.Fatal(err)
	}
	for _, locale := range []string{"en", "", "de", "SV", "sv-SE", " sv "} {
		material, err := LocalizedNoticeV1("Customer agreement", "contract", locale)
		if err != nil || material.CopyLocale != "en" || material.PurposeSummary != PurposeSummaryV1("Customer agreement") ||
			material.LegalBasisDisclosure != legal || material.Copy != RenderedCopyV1("Customer agreement") {
			t.Fatalf("locale %q changed the exact legacy English material: %v", locale, err)
		}
		actual, err := localizedSnapshotTestV1(t, locale).CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		want, _ := localizedSnapshotTestV1(t, "en").CanonicalJSON()
		if !bytes.Equal(actual, want) {
			t.Fatal("English fallback changed canonical bytes")
		}
	}
	// Retained pre-localization evidence remains byte-for-byte verifiable.
	historical := validSnapshot(t)
	canonical, err := historical.CanonicalJSON()
	if err != nil || string(canonical) != goldenCanonicalJSON {
		t.Fatal("historical English canonical fixture changed", err)
	}
	digest, err := historical.Digest()
	if err != nil || digest != goldenDigest {
		t.Fatal("historical English digest changed", err)
	}
}

func TestLocalizedNoticeV1SwedishHashesAllActualCopyWithoutNewSnapshotFields(t *testing.T) {
	en, sv := localizedSnapshotTestV1(t, "en"), localizedSnapshotTestV1(t, "sv")
	if sv.Schema != SchemaV1 || sv.RetentionYears != 7 || sv.DSRCapability != en.DSRCapability || sv.PolicyURL != en.PolicyURL ||
		sv.Controller != en.Controller || sv.Processor != en.Processor || sv.SupervisoryAuthority != en.SupervisoryAuthority {
		t.Fatal("translation changed schema, policy or configured identity")
	}
	if !strings.Contains(sv.PurposeSummary, "Customer agreement") || !strings.Contains(sv.LegalBasisDisclosure, "GDPR artikel 6.1 b") ||
		!strings.Contains(sv.Copy.RetentionValue, "7 år") {
		t.Fatal("missing translated purpose, existing legal basis or retention")
	}
	before, after := reflect.ValueOf(en.Copy), reflect.ValueOf(sv.Copy)
	for i := 0; i < after.NumField(); i++ {
		if after.Field(i).String() == "" || before.Field(i).String() == after.Field(i).String() {
			t.Fatalf("fixed notice field %s was not translated", after.Type().Field(i).Name)
		}
	}
	canonical, err := sv.CanonicalJSON()
	if err != nil || bytes.Contains(canonical, []byte(`"copy_locale"`)) || bytes.Contains(canonical, []byte(`"locale"`)) {
		t.Fatal("localization added a canonical wire field", err)
	}
	var readback Snapshot
	if err := json.Unmarshal(canonical, &readback); err != nil || readback != sv {
		t.Fatal("canonical snapshot lost actual translated material", err)
	}
	enEvidence, err := NewEvidence(en)
	if err != nil {
		t.Fatal(err)
	}
	svEvidence, err := NewEvidence(sv)
	if err != nil || svEvidence.Digest == enEvidence.Digest {
		t.Fatal("Swedish material did not require a distinct commitment", err)
	}
	if err := enEvidence.Validate(); err != nil {
		t.Fatal("historical English evidence no longer validates", err)
	}
	for i := 0; i < after.NumField(); i++ {
		changed := sv
		reflect.ValueOf(&changed.Copy).Elem().Field(i).SetString(after.Field(i).String() + " ändrat")
		digest, err := changed.Digest()
		if err != nil || digest == svEvidence.Digest {
			t.Fatalf("actual translated field %s is not digest-bound", after.Type().Field(i).Name)
		}
	}
}

func TestLocalizedNoticeV1DoesNotIntroduceAnotherLawfulBasis(t *testing.T) {
	for _, locale := range []string{"en", "sv", "unknown"} {
		for _, basis := range []string{"consent", "legitimate_interests", "", "contract-extra"} {
			if _, err := LocalizedNoticeV1("Document", basis, locale); !errors.Is(err, ErrUnsupportedLegalBasis) {
				t.Fatalf("locale %q admitted unimplemented basis %q", locale, basis)
			}
		}
	}
}
