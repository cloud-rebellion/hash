// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package i18n

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/documentpackage"
)

func TestT_FallbackAndParams(t *testing.T) {
	// Known Swedish key resolves to a non-empty, non-key value.
	if got := T("sv", "email.invite.cta", nil); got == "" || got == "email.invite.cta" {
		t.Errorf("sv cta unresolved: %q", got)
	}
	// Unknown key passes through.
	if got := T("sv", "no.such.key", nil); got != "no.such.key" {
		t.Errorf("want key passthrough, got %q", got)
	}
	// Unknown locale falls back to English per key.
	if got, want := T("zz", "email.invite.cta", nil), T("en", "email.invite.cta", nil); got != want {
		t.Errorf("unknown locale should fall back to en: got %q want %q", got, want)
	}
	// Placeholder substitution.
	if got := T("en", "email.invite.subject", map[string]string{"sender": "Jane", "document": "NDA"}); got != "Jane sent you NDA for signature" {
		t.Errorf("substitution: %q", got)
	}
}

func TestTSubstitutesInOneDeterministicPass(t *testing.T) {
	params := map[string]string{
		"sender":   "{document}",
		"document": "must-not-be-cascaded",
	}
	for i := 0; i < 100; i++ {
		got := T("en", "email.invite.subject", params)
		if got != "{document} sent you must-not-be-cascaded for signature" {
			t.Fatalf("substitution cascaded or varied: %q", got)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{"": "en", "zz": "en", "sv": "sv", "de": "de"}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryLocaleHasInviteSubject(t *testing.T) {
	// Spot-check coverage: every shipped locale has the invite subject and it
	// keeps both placeholders.
	for code := range messages {
		s := T(code, "email.invite.subject", map[string]string{"sender": "S", "document": "D"})
		if s == "" || s == "email.invite.subject" {
			t.Errorf("%s: invite subject unresolved", code)
		}
		if !contains(s, "S") || !contains(s, "D") {
			t.Errorf("%s: invite subject dropped a placeholder value: %q", code, s)
		}
	}
}

func TestEveryLocaleUsesNeutralInvitationFooter(t *testing.T) {
	for code, catalog := range messages {
		invite := catalog["email.invite.footer"]
		common := catalog["email.common.footer"]
		if invite == "" || common == "" {
			t.Errorf("%s: invitation or common footer is missing", code)
			continue
		}
		if invite != common {
			t.Errorf("%s: invitation footer must reuse neutral common footer: invite=%q common=%q", code, invite, common)
		}
	}
}

func TestEveryLocaleUsesNeutralDocumentSpecificPrivacyPurpose(t *testing.T) {
	const document = "Customer agreement"
	for code := range messages {
		purpose := T(code, "privacy.purpose", map[string]string{"document": document})
		lower := strings.ToLower(purpose)
		if !strings.Contains(purpose, document) {
			t.Errorf("%s: purpose is not document-specific: %q", code, purpose)
		}
		for _, forbidden := range []string{"legally-binding", "legally binding", "legal obligation", "statutory"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s: purpose contains unsupported claim %q: %q", code, forbidden, purpose)
			}
		}
		if !strings.Contains(lower, "does not determine legal effect for the document") {
			t.Errorf("%s: purpose lacks neutral legal-effect qualification: %q", code, purpose)
		}
		if !strings.Contains(lower, "fixed seven-year evidence policy") {
			t.Errorf("%s: purpose contradicts the implemented fixed retention policy: %q", code, purpose)
		}
	}
}

func TestFrontendA13CatalogDisclosesImplementedRetentionAndRequestTimingInEveryLocale(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "frontend", "src", "lib", "i18n.a13.ts"))
	if err != nil {
		t.Fatal(err)
	}
	const retentionMarker = "fixed {years}-year evidence-retention policy to independently owned source or rendered PDF versions when a document is sent, completed final PDFs and audit certificates"
	const abandonedCeremonyMarker = "signature artifacts captured before a signing ceremony later ends without completion"
	const fineprintMarker = "does not change the fixed Hash evidence-retention period; deletion remains subject to immutable retention"
	const requestMarker = "applicable GDPR deadline; identity checks or a lawful extension may affect timing"
	retentionCount := 0
	fineprintCount := 0
	requestCount := 0
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.Contains(line, `"a13.retentionValue"`):
			retentionCount++
			if !strings.Contains(line, retentionMarker) || !strings.Contains(line, abandonedCeremonyMarker) {
				t.Errorf("unsafe frontend retention copy: %s", line)
			}
		case strings.Contains(line, `"a13.fineprint"`):
			fineprintCount++
			if !strings.Contains(line, fineprintMarker) {
				t.Errorf("unsafe frontend fine print: %s", line)
			}
		case strings.Contains(line, `"a13.requestReceived"`):
			requestCount++
			if !strings.Contains(line, requestMarker) {
				t.Errorf("unsafe frontend request-timing copy: %s", line)
			}
		}
	}
	if retentionCount != len(messages) || fineprintCount != len(messages) || requestCount != len(messages) {
		t.Fatalf("frontend A13 legal copy covers retention=%d fineprint=%d requests=%d; backend locale count is %d", retentionCount, fineprintCount, requestCount, len(messages))
	}
}

func TestSignerCeremonyUsesOnlyServerSelectedEnglishAndSwedish(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "frontend", "src", "routes", "sign", "[token]", "+page.svelte"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	// Fresh contexts reset without persisting, then only the validated server
	// recipient may select one of the two reviewed interface catalogs. Neither
	// a saved browser preference nor the other email catalogs select legal copy.
	calls := regexp.MustCompile(`(?m)^\s*preferLocale\(([^\n]+)\);$`).FindAllStringSubmatch(source, -1)
	resets, selections := 0, 0
	for _, call := range calls {
		switch call[1] {
		case "'en', { force: true }":
			resets++
		case "loaded.recipient.locale === 'sv' ? 'sv' : 'en', { force: true }":
			selections++
		default:
			t.Fatalf("signer ceremony uses an unreviewed locale source: %s", call[0])
		}
	}
	if resets != 3 || selections != 1 || strings.Count(source, "preferLocale(") != len(calls) {
		t.Fatalf("signer locale boundary changed: resets=%d server selections=%d", resets, selections)
	}
	for _, forbidden := range []string{"setLocale(", "class=\"lang-select\"", "{#each LOCALES", "navigator.language", "localStorage.getItem("} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("signer ceremony exposes a browser-selected or unreviewed catalog via %q", forbidden)
		}
	}
	for _, required := range []string{
		"loaded.privacy.copy_locale !== undefined && loaded.privacy.copy_locale !== 'en' && loaded.privacy.copy_locale !== 'sv'",
		"{#if ctx.privacy.copy_locale === 'sv'}",
		"{#if packageReview.canonicalLocale === 'sv'}",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("signer ceremony no longer checks or labels actual canonical copy: missing %q", required)
		}
	}
}

func TestSignerLegalCatalogPreservesExactEnglishAndSwedishVersionedCopy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "frontend", "src", "lib", "signerPackageIncorporation.ts"))
	if err != nil {
		t.Fatal(err)
	}
	_, catalog, ok := strings.Cut(string(raw), "export const signerPackageIncorporations = {")
	if !ok {
		t.Fatal("closed signer legal catalog is missing")
	}
	catalog, _, ok = strings.Cut(catalog, "} as const;")
	if !ok {
		t.Fatal("closed signer legal catalog has no end")
	}
	entryPattern := regexp.MustCompile(`(?m)^  '([^']+)': \{\n    locale: '([^']+)',\n    sha256: '([^']+)',\n    text: '([^']+)',\n  \},$`)
	entries := entryPattern.FindAllStringSubmatch(catalog, -1)
	if len(entries) != 2 || strings.TrimSpace(entryPattern.ReplaceAllString(catalog, "")) != "" {
		t.Fatal("signer legal catalog must contain only the two explicit reviewed version/copy/digest pairs")
	}
	want := map[string]struct{ locale, digest string }{
		"hash-package-incorporation-v1":    {"en", "ed7e8d4a4b7e03bb600f94ccd6328e4f457528eb165f18fd0ca6ccfecb972670"},
		"hash-package-incorporation-sv-v1": {"sv", "24cfae89a52f479cbce33b71f99faec557ebd573279a9e5184bb51b17505a6de"},
	}
	for _, entry := range entries {
		version, locale, digest, text := entry[1], entry[2], entry[3], entry[4]
		expected, ok := want[version]
		if !ok {
			t.Fatalf("unreviewed or duplicate legal version %q", version)
		}
		delete(want, version)
		canonical, err := documentpackage.IncorporationCopyForVersionV1(version)
		if err != nil || locale != expected.locale || digest != expected.digest || canonical.SHA256 != digest || canonical.Text != text ||
			fmt.Sprintf("%x", sha256.Sum256([]byte(text))) != digest || canonical.ValidateV1() != nil {
			t.Fatalf("%s: frontend legal text, language or digest differs from the exact server statement: %v", version, err)
		}
		if selected := documentpackage.IncorporationCopyForLocaleV1(locale); selected != canonical {
			t.Fatalf("%s: new Send locale selects a different canonical statement", version)
		}
	}
	legacy := documentpackage.IncorporationCopyV1()
	if legacy.Version != "hash-package-incorporation-v1" || legacy.SHA256 != "ed7e8d4a4b7e03bb600f94ccd6328e4f457528eb165f18fd0ca6ccfecb972670" {
		t.Fatal("legacy English statement was relabeled or its retained digest changed")
	}
	for _, locale := range []string{"en", "", "de", "SV", "sv-SE", " sv "} {
		if got := documentpackage.IncorporationCopyForLocaleV1(locale); got != legacy {
			t.Fatalf("locale %q no longer falls back to exact retained English", locale)
		}
	}
	if _, err := documentpackage.IncorporationCopyForVersionV1("hash-package-incorporation-v2"); err == nil {
		t.Fatal("unreviewed future legal version was accepted")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
