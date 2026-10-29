// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSkippedAcceptanceRemainsPendingWithoutExposingTestOutput(t *testing.T) {
	t.Setenv("HASH_BROWSER_E2E", "")
	events := `{"Action":"output","Package":"example/first","Output":"private-configuration-sentinel"}
{"Action":"pass","Package":"example/first","Test":"TestOrdinary"}
{"Action":"pass","Package":"example/first"}
{"Action":"skip","Package":"github.com/bright-interaction/hash/internal/handler","Test":"TestOwnedRealRenderedSignerFourArtifactsWithExternalBrowserE2E"}
{"Action":"pass","Package":"github.com/bright-interaction/hash/internal/handler"}`
	other := hashModule + "internal/handler"
	summary, err := summarizeEvents("ordinary", 0, strings.NewReader("example/first\n"+other+"\n"), strings.NewReader(events), map[string]bool{"example/first": true, other: true})
	if err != nil || summary.Result != "pending" || summary.PassedTests != 1 || summary.PassedPackages != 2 || len(summary.SkippedTests) != 1 || len(summary.SeparateProfiles) != 1 || summary.SeparateProfiles[0].State != "separate profile not run" {
		t.Fatal("a skipped acceptance test was promoted to a passing test")
	}
	raw, err := json.Marshal(summary)
	if err != nil || strings.Contains(string(raw), "private-configuration-sentinel") {
		t.Fatal("accounting summary retained raw test output")
	}
}

func TestEventAccountingRefusesMissingDuplicateAndUnexpectedPackages(t *testing.T) {
	for _, test := range []struct{ name, events string }{
		{"missing", `{"Action":"pass","Package":"example/first"}`},
		{"duplicate", `{"Action":"pass","Package":"example/first"}
{"Action":"pass","Package":"example/first"}
{"Action":"pass","Package":"example/second"}`},
		{"unexpected", `{"Action":"pass","Package":"example/third"}`},
		{"truncated", `{"Action":"pass","Package":"example/first"}
{"Action":`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := summarizeEvents("ordinary", 0, strings.NewReader("example/first\nexample/second\n"), strings.NewReader(test.events), map[string]bool{"example/first": true, "example/second": true}); err == nil {
				t.Fatal("incomplete or duplicate execution could qualify the package partition")
			}
		})
	}
}

func TestNativeGoFailureCannotBeOverruledByPassingEvents(t *testing.T) {
	summary, err := summarizeEvents("ordinary", 1, strings.NewReader("example/only\n"), strings.NewReader(`{"Action":"pass","Package":"example/only","Test":"TestActual"}
{"Action":"pass","Package":"example/only"}`), map[string]bool{"example/only": true})
	if err != nil || summary.Result != "failed" || summary.GoExitCode != 1 {
		t.Fatal("accounting overruled the native Go failure")
	}
}

func TestOnlySourcePackagesWithoutTestsMayHavePackageSkipEvents(t *testing.T) {
	input := `{"Action":"skip","Package":"example/only"}`
	summary, err := summarizeEvents("ordinary", 0, strings.NewReader("example/only\n"), strings.NewReader(input), map[string]bool{"example/only": false})
	if err != nil || summary.Result != "passed" || len(summary.CompiledNoTests) != 1 || len(summary.SkippedTests) != 0 {
		t.Fatal("a package with no test files was misclassified as acceptance pending")
	}
	if _, err := summarizeEvents("ordinary", 0, strings.NewReader("example/only\n"), strings.NewReader(input), map[string]bool{"example/only": true}); err == nil {
		t.Fatal("a package with test files could disappear behind a package skip")
	}
}

func TestUncataloguedCoreSkipFailsEvenWithNativeSuccess(t *testing.T) {
	input := `{"Action":"skip","Package":"github.com/bright-interaction/hash/internal/e2e","Test":"TestSendSignStampE2E"}
{"Action":"pass","Package":"github.com/bright-interaction/hash/internal/e2e"}`
	name := hashModule + "internal/e2e"
	summary, err := summarizeEvents("ordinary", 0, strings.NewReader(name+"\n"), strings.NewReader(input), map[string]bool{name: true})
	if err != nil || summary.Result != "failed" || len(summary.UnexpectedSkips) != 1 || len(summary.SkippedTests) != 0 {
		t.Fatal("an uncatalogued core acceptance skip was accepted")
	}
}

func TestOptionalSkipRequiresExactIDAndAnUnsetOwnerFlag(t *testing.T) {
	id := testID{Package: hashModule + "internal/handler", Test: "TestOwnedRealRenderedSignerFourArtifactsWithExternalBrowserE2E"}
	if _, ok := optionalSkip(id, func(string) string { return "1" }); ok {
		t.Fatal("an enabled profile's test may not skip")
	}
	id.Test += "/unexpected-child"
	if _, ok := optionalSkip(id, func(string) string { return "" }); ok {
		t.Fatal("the optional catalog matched a broader test-name prefix")
	}
}

func TestOptionalSubtestSkipDoesNotPromoteItsNativePassingParent(t *testing.T) {
	t.Setenv("HASH_E2E_FITTED_OUTPUT_OWNED_PG", "")
	name := hashModule + "internal/sign"
	parent := "TestFittedOutputJournalPositivePinSurvivesLateProviderFailureE2E"
	events := `{"Action":"skip","Package":"` + name + `","Test":"` + parent + `/late_error"}
{"Action":"pass","Package":"` + name + `","Test":"` + parent + `"}
{"Action":"pass","Package":"` + name + `"}`
	summary, err := summarizeEvents("ordinary", 0, strings.NewReader(name+"\n"), strings.NewReader(events), map[string]bool{name: true})
	if err != nil || summary.Result != "pending" || summary.PassedTests != 0 || len(summary.PendingParents) != 1 || len(summary.SkippedTests) != 1 {
		t.Fatal("native parent PASS promoted a skipped acceptance case")
	}
}
