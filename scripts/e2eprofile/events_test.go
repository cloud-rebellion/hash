// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"encoding/json"
	"fmt"
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

func appendDiagnosticEvent(out *strings.Builder, action, pkg, test, output string) {
	raw, _ := json.Marshal(map[string]string{"Action": action, "Package": pkg, "Test": test, "Output": output})
	out.Write(raw)
	out.WriteByte('\n')
}

func TestFailedAssertionDiagnosticsRedactCredentialsBeforeJournalOutput(t *testing.T) {
	var input strings.Builder
	pkg := "example/failure"
	appendDiagnosticEvent(&input, "run", pkg, "TestFailure", "")
	for _, line := range []string{
		"fixture_test.go:41: database failed postgres://private-user:private-password@localhost/test?access_token=query-secret\n",
		"fixture_test.go:42: Authorization: Bearer auth-secret\n",
		"  Cookie: session=cookie-secret; refresh=refresh-secret\n",
		`  {\"credentials\": {` + "\n",
		`    "arbitrary": "json-secret"` + "\n",
		"fixture_test.go:43: api_key=key-secret\n",
		"fixture_test.go:44: expected SQLSTATE 23514\n",
	} {
		appendDiagnosticEvent(&input, "output", pkg, "TestFailure", line)
	}
	appendDiagnosticEvent(&input, "fail", pkg, "TestFailure", "")
	appendDiagnosticEvent(&input, "fail", pkg, "", "")
	summary, err := summarizeEvents("ordinary", 1, strings.NewReader(pkg+"\n"), strings.NewReader(input.String()), map[string]bool{pkg: true})
	if err != nil || summary.Result != "failed" || len(summary.FailedTests) != 1 {
		t.Fatal("diagnostics changed failure accounting", err)
	}
	raw, _ := json.Marshal(summary)
	for _, secret := range []string{"private-user", "private-password", "query-secret", "auth-secret", "cookie-secret", "refresh-secret", "json-secret", "key-secret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("credential escaped bounded journal diagnostics", secret)
		}
	}
	if !strings.Contains(string(raw), "expected SQLSTATE 23514") || !strings.Contains(string(raw), "fixture_test.go:44") {
		t.Fatal("safe source assertion was lost")
	}
}

func TestPackageTimeoutRetainsPanicHeaderAndUnfinishedTests(t *testing.T) {
	var input strings.Builder
	pkg := "example/timeout"
	appendDiagnosticEvent(&input, "run", pkg, "TestWaiting/recipient", "")
	appendDiagnosticEvent(&input, "output", pkg, "", "panic: test timed out after 3m0s\n")
	for i := 0; i < 100; i++ {
		appendDiagnosticEvent(&input, "output", pkg, "", fmt.Sprintf("worker.go:%d +0x1234\n", i))
	}
	appendDiagnosticEvent(&input, "fail", pkg, "", "")
	summary, err := summarizeEvents("ordinary", 1, strings.NewReader(pkg+"\n"), strings.NewReader(input.String()), map[string]bool{pkg: true})
	if err == nil || summary.Result != "failed" || summary.FailedPackages != 1 || len(summary.UnfinishedTests) != 1 || summary.UnfinishedTests[0].Test != "TestWaiting/recipient" {
		t.Fatal("timeout was not retained as failed unfinished execution", err)
	}
	if len(summary.Diagnostics) == 0 || len(summary.Diagnostics[0].Header) != 1 || !strings.Contains(summary.Diagnostics[0].Header[0], "test timed out") || len(summary.Diagnostics[0].Tail) > diagnosticTailRows {
		t.Fatal("bounded package panic context missing")
	}
}

func TestMalformedStreamKeepsObservedFailureAndPendingDiagnostics(t *testing.T) {
	var input strings.Builder
	pkg := "example/incomplete"
	appendDiagnosticEvent(&input, "pass", pkg, "TestAlreadyPassed", "")
	appendDiagnosticEvent(&input, "run", pkg, "TestWaiting", "")
	appendDiagnosticEvent(&input, "output", pkg, "TestWaiting", "wait_test.go:77: expected parent lock\n")
	input.WriteString(`{"Action":`)
	summary, err := summarizeEvents("ordinary", 1, strings.NewReader(pkg+"\n"), strings.NewReader(input.String()), map[string]bool{pkg: true})
	if err == nil || summary.Result != "failed" || summary.PassedTests != 1 || len(summary.UnfinishedTests) != 1 || len(summary.Diagnostics) != 1 || summary.AccountingError == "" {
		t.Fatal("malformed stream discarded observed context or qualified", err)
	}
	if summary.Diagnostics[0].State != "unfinished" || !strings.Contains(summary.Diagnostics[0].Tail[0], "expected parent lock") {
		t.Fatal("unfinished assertion context missing")
	}
}

func TestFailureDiagnosticCapsCannotOverruleLargeNativeFailureCohort(t *testing.T) {
	var input strings.Builder
	pkg := "example/cohort"
	for i := 0; i < 8431; i++ {
		appendDiagnosticEvent(&input, "pass", pkg, fmt.Sprintf("TestPass%d", i), "")
	}
	for i := 0; i < 68; i++ {
		name := fmt.Sprintf("TestFailure%03d", i)
		appendDiagnosticEvent(&input, "run", pkg, name, "")
		for j := 0; j < 20; j++ {
			appendDiagnosticEvent(&input, "output", pkg, name, fmt.Sprintf("cohort_test.go:%d: %s\n", j, strings.Repeat("synthetic", 100)))
		}
		appendDiagnosticEvent(&input, "fail", pkg, name, "")
	}
	appendDiagnosticEvent(&input, "fail", pkg, "", "")
	summary, err := summarizeEvents("ordinary", 1, strings.NewReader(pkg+"\n"), strings.NewReader(input.String()), map[string]bool{pkg: true})
	if err != nil || summary.Result != "failed" || summary.PassedTests != 8431 || len(summary.FailedTests) != 68 || !summary.DiagnosticsTruncated || len(summary.Diagnostics) > diagnosticMaxRecords {
		t.Fatal("diagnostic cap changed native counts/outcome", err)
	}
	count := 0
	for _, d := range summary.Diagnostics {
		count += len(d.Package) + len(d.Test) + len(d.State)
		if len(d.Header) > diagnosticHeadRows || len(d.Tail) > diagnosticTailRows {
			t.Fatal("diagnostic row cap exceeded")
		}
		for _, rows := range [][]string{d.Header, d.Tail} {
			for _, row := range rows {
				if len(row) > diagnosticMaxLine {
					t.Fatal("line cap exceeded")
				}
				count += len(row)
			}
		}
	}
	if count > diagnosticMaxBytes {
		t.Fatal("diagnostic byte cap exceeded")
	}
}

func TestSourceAssertionSurvivesVerboseFailureAndReportedIDsAreRedacted(t *testing.T) {
	var input strings.Builder
	pkg := "example/verbose"
	name := "TestCase/access_token=subtest-secret"
	appendDiagnosticEvent(&input, "run", pkg, name, "")
	appendDiagnosticEvent(&input, "output", pkg, name, "important_test.go:123: expected authoritative parent lock\n")
	for i := 0; i < 50; i++ {
		appendDiagnosticEvent(&input, "output", pkg, name, fmt.Sprintf("debug output row%d\n", i))
	}
	appendDiagnosticEvent(&input, "fail", pkg, name, "")
	appendDiagnosticEvent(&input, "fail", pkg, "", "")
	summary, err := summarizeEvents("ordinary", 1, strings.NewReader(pkg+"\n"), strings.NewReader(input.String()), map[string]bool{pkg: true})
	if err != nil || len(summary.FailedTests) != 1 || summary.Result != "failed" {
		t.Fatal("reported identifier sanitization changed accounting", err)
	}
	raw, _ := json.Marshal(summary)
	if strings.Contains(string(raw), "subtest-secret") || !strings.Contains(string(raw), "expected authoritative parent lock") || !summary.DiagnosticsTruncated {
		t.Fatal("source assertion/redaction/truncation report lost")
	}
}

func TestTruncatedPanicBeforePackageTerminalStillPublishesHeader(t *testing.T) {
	var input strings.Builder
	pkg := "example/truncated-panic"
	appendDiagnosticEvent(&input, "run", pkg, "TestWait", "")
	appendDiagnosticEvent(&input, "output", pkg, "", "panic: timeout before package result\n")
	summary, err := summarizeEvents("ordinary", 1, strings.NewReader(pkg+"\n"), strings.NewReader(input.String()), map[string]bool{pkg: true})
	if err == nil || summary.Result != "failed" || len(summary.UnfinishedTests) != 1 || len(summary.Diagnostics) != 1 || len(summary.Diagnostics[0].Header) != 1 {
		t.Fatal("truncated panic discarded package header", err)
	}
}

func TestDiagnosticRedactionKeepsSafeURLContextAndCoversConfigurationKeys(t *testing.T) {
	blocked := false
	safe := diagnosticRedact("source_test.go:17: http://synthetic-user:synthetic-password@localhost:8080/check?token=url-token#fragment-secret", &blocked)
	if !strings.Contains(safe, "localhost:8080/check") || strings.Contains(safe, "synthetic-user") || strings.Contains(safe, "synthetic-password") || strings.Contains(safe, "url-token") || strings.Contains(safe, "fragment-secret") {
		t.Fatal("URL diagnostic context/redaction failed")
	}
	for _, line := range []string{`source_test.go:18: HASH_SESSION_KEY=configuration-secret`, `source_test.go:19: {"apiToken":"configuration-secret"}`, `source_test.go:20: X-Api-Key: configuration-secret`, `source_test.go:21: authentication: configuration-secret`, `source_test.go:22: Basic configuration-secret`} {
		blocked = false
		safe := diagnosticRedact(line, &blocked)
		if strings.Contains(safe, "configuration-secret") {
			t.Fatal("configuration/authentication secret escaped redaction")
		}
	}
}

func TestPrivateKeyPEMContinuationsStayPrivateUntilEndBoundary(t *testing.T) {
	for _, kind := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"} {
		t.Run(kind, func(t *testing.T) {
			var input strings.Builder
			pkg := "example/pem"
			name := "TestPrivateMaterial"
			appendDiagnosticEvent(&input, "run", pkg, name, "")
			for _, line := range []string{
				"key_test.go:51: -----BEGIN " + kind + "-----\n",
				"synthetic-base64-private-material\n",
				"pretend_test.go:999: synthetic-source-looking-private-material\n",
				"=== RUN synthetic-control-looking-private-material\n",
				"synthetic-post-control-private-material\n",
				"-----END " + kind + "-----\n",
				"after-end-marker public diagnostic context\n",
				"key_test.go:52: http://localhost:8080/safe-context expected completion\n",
			} {
				appendDiagnosticEvent(&input, "output", pkg, name, line)
			}
			appendDiagnosticEvent(&input, "fail", pkg, name, "")
			appendDiagnosticEvent(&input, "fail", pkg, "", "")
			summary, err := summarizeEvents("ordinary", 1, strings.NewReader(pkg+"\n"), strings.NewReader(input.String()), map[string]bool{pkg: true})
			if err != nil || summary.Result != "failed" || len(summary.FailedTests) != 1 {
				t.Fatal("PEM suppression changed native accounting", err)
			}
			raw, _ := json.Marshal(summary)
			for _, secret := range []string{"synthetic-base64-private-material", "synthetic-source-looking-private-material", "synthetic-control-looking-private-material", "synthetic-post-control-private-material", "-----BEGIN", "-----END"} {
				if strings.Contains(string(raw), secret) {
					t.Fatal("private PEM boundary/body escaped")
				}
			}
			if !strings.Contains(string(raw), "key_test.go:51:") || !strings.Contains(string(raw), "key_test.go:52:") || !strings.Contains(string(raw), "localhost:8080/safe-context") || !strings.Contains(string(raw), "after-end-marker public diagnostic context") {
				t.Fatal("PEM source location or END boundary reset was lost")
			}
		})
	}
}

func TestAWSAndSpacedCredentialFieldsSuppressContinuationsAndResetAtSource(t *testing.T) {
	for _, field := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "private key", "api key"} {
		t.Run(field, func(t *testing.T) {
			stream := &diagnosticStream{}
			stream.add("config_test.go:61: " + field + ": synthetic-field-secret\n")
			stream.add("synthetic-field-continuation\n")
			stream.add("config_test.go:62: expected safe assertion context\n")
			raw, _ := json.Marshal(stream.tail)
			if strings.Contains(string(raw), "synthetic-field-secret") || strings.Contains(string(raw), "synthetic-field-continuation") || !strings.Contains(string(raw), "config_test.go:61:") || !strings.Contains(string(raw), "expected safe assertion context") {
				t.Fatal("credential field boundary/redaction failed")
			}
		})
	}
}
