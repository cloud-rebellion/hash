// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHandlerCatalogPlanIsStableCompleteAndAnchored(t *testing.T) {
	var names []string
	for i := 0; i < 35; i++ {
		names = append(names, fmt.Sprintf("TestActual%02d", i))
	}
	names = append(names, "Example", "FuzzSeeds")
	forward, err := planHandlerCohorts(strings.NewReader(strings.Join(names, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
		names[i], names[j] = names[j], names[i]
	}
	reverse, err := planHandlerCohorts(strings.NewReader(strings.Join(names, "\n") + "\n"))
	if err != nil || !reflect.DeepEqual(forward, reverse) {
		t.Fatal("catalog order changed deterministic cohorts", err)
	}
	seen := map[string]bool{}
	for _, c := range forward {
		if len(c.Roots) == 0 || len(c.Roots) > 16 {
			t.Fatal("cohort is empty or over bounded root count")
		}
		r := regexp.MustCompile(c.Pattern)
		for _, name := range c.Roots {
			if seen[name] || !r.MatchString(name) || r.MatchString(name+"Extra") || r.MatchString("Prefix"+name) {
				t.Fatal("cohort omitted, duplicated or overselected a root")
			}
			seen[name] = true
		}
	}
	if len(seen) != len(names) {
		t.Fatal("catalog union lost roots")
	}
}

func TestCohortLeaderExitCannotHidePipeHoldingChild(t *testing.T) {
	root := t.TempDir()
	pidfile, release := filepath.Join(root, "pid"), filepath.Join(root, "release")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	leader := exec.Command("sh", "-c", `printf '%s' "$$" > "$1"; while [ ! -f "$2" ]; do sleep 0.01; done`, "cohort-leader", pidfile, release)
	leader.Stdout, leader.Stderr = writer, writer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan cohortProcessOutcome, 1)
	go func() { done <- runCohortProcess(ctx, leader) }()
	var pid int
	deadline := time.Now().Add(2 * time.Second)
	for {
		raw, _ := os.ReadFile(pidfile)
		pid, _ = strconv.Atoi(string(raw))
		if pid > 1 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("native leader did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	worker := exec.Command("sleep", "30")
	worker.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: pid}
	worker.Stdout, worker.Stderr = writer, writer
	if err := worker.Start(); err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	workerDone := make(chan error, 1)
	go func() { workerDone <- worker.Wait() }()
	defer func() {
		_ = worker.Process.Kill()
		select {
		case <-workerDone:
		default:
		}
	}()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, []byte("exit"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-done:
		if !outcome.Joined || !outcome.Residual || outcome.ExitCode != 0 {
			t.Fatal("leader exit hid native descendant debt", outcome)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("pipe-holder process group did not settle")
	}
	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("pipe-holder direct child was not reaped")
	}
	var one [1]byte
	if n, err := reader.Read(one[:]); n != 0 || err != io.EOF {
		t.Fatal("native worker kept inherited stdout open after group join", n, err)
	}
}

func TestFatalCohortExitStopsDedicatedProfileDispatch(t *testing.T) {
	script, err := os.ReadFile("../test-e2e-profiles.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"70", "143", "1"} {
		t.Run(code, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source")
			bin := filepath.Join(root, "bin")
			tmp := filepath.Join(root, "tmp")
			for _, path := range []string{filepath.Join(source, "scripts"), bin, tmp} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(source, "scripts", "test-e2e-profiles.sh"), script, 0700); err != nil {
				t.Fatal(err)
			}
			fakeGo := `#!/bin/sh
set -eu
case "$1" in
build|test)
  output=
  previous=
  for arg in "$@"; do [ "$previous" != -o ] || output=$arg; previous=$arg; done
  if [ -n "$output" ]; then
    cat > "$output" <<'HELPER'
#!/bin/sh
case "$1" in ordinary-cohorts) exit "$COHORT_FATAL_TEST_CODE";; audit) exit 0;; *) printf '%064d\n' 0;; esac
HELPER
    chmod 700 "$output"
  else printf 'dedicated\n' >> "$COHORT_FATAL_TEST_LOG"; fi;;
list)
  if [ "$2" = -m ]; then printf 'github.com/bright-interaction/hash\n'; else
    with_tests=0
    for arg in "$@"; do case "$arg" in *TestGoFiles*) with_tests=1;; esac; done
    for package in internal/handler other cmd/worker internal/db internal/fitprepare internal/fitselect; do
      if [ "$with_tests" = 1 ]; then printf 'github.com/bright-interaction/hash/%s tests\n' "$package"; else printf 'github.com/bright-interaction/hash/%s\n' "$package"; fi
    done
  fi;;
run) :;;
*) exit 91;;
esac
`
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte(fakeGo), 0700); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(root, "dispatch")
			env := append([]string{}, os.Environ()...)
			for _, setting := range []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"), "TMPDIR=" + tmp, "HASH_E2E_EVIDENCE_DIR=" + filepath.Join(root, "evidence"), "HASH_BROWSER_E2E=0", "COHORT_FATAL_TEST_CODE=" + code, "COHORT_FATAL_TEST_LOG=" + log} {
				env = append(env, setting)
			}
			for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_BACKLOG_DB_URL", "HASH_E2E_RECIPIENT_LOCK_DB_URL", "HASH_E2E_EXPECT_MIGRATIONS_SHA256", "HASH_E2E_S3_ENDPOINT", "HASH_E2E_S3_ACCESS_KEY", "HASH_E2E_S3_SECRET_KEY", "HASH_E2E_GOTENBERG_URL", "HASH_E2E_RENDERER_URL"} {
				env = append(env, name+"=synthetic")
			}
			cmd := exec.Command("sh", filepath.Join(source, "scripts", "test-e2e-profiles.sh"))
			cmd.Env = env
			raw, runErr := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(runErr, &exit) {
				t.Fatalf("finite profile script did not fail: %v %s", runErr, raw)
			}
			want, _ := strconv.Atoi(code)
			if exit.ExitCode() != want {
				t.Fatalf("profile failure exit=%d want%d: %s", exit.ExitCode(), want, raw)
			}
			calls, _ := os.ReadFile(log)
			if code == "1" && strings.Count(string(calls), "dedicated") != 4 || code != "1" && len(calls) != 0 {
				t.Fatalf("unknown ownership dispatched later profiles or ordinary failure suppressed them: %s", calls)
			}
		})
	}
	if cohortErrorExitCode(fmt.Errorf("wrapped: %w", &unsettledCohortError{})) != 70 || cohortErrorExitCode(fmt.Errorf("known test failure")) != 1 {
		t.Fatal("fatal ownership and known test failures share an exit")
	}
}

func TestUnsettledCohortCannotBeDemotedByFinalEvidenceFailure(t *testing.T) {
	for _, phase := range []string{"binary identity", "event close", "stderr close", "summary write", "skip inventory", "stdout report"} {
		late := fmt.Errorf("%s failed", phase)
		if got := cohortReturnError(context.Background(), &unsettledCohortError{}, late); cohortErrorExitCode(got) != 70 {
			t.Fatal("late evidence failure demoted unsettled ownership", phase)
		}
		if got := cohortReturnError(context.Background(), nil, late); got != late || cohortErrorExitCode(got) != 1 {
			t.Fatal("known evidence failure acquired fatal ownership", phase)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if cohortErrorExitCode(cohortReturnError(ctx, nil, late)) != 70 {
			t.Fatal("overall cancellation lost fatal status", phase)
		}
	}
}

// A real source-built tiny Go suite exercises catalog/list init, native
// test2json output, relative fixture reads, fuzz seeds and ordinary aggregation.
// It uses no service, network, source checkout copy or application configuration.
func TestOrdinaryCohortsNativeMiniSuitePreservesWorkingDirectoryAndFailure(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOENV", "off")
	handler := filepath.Join(root, "internal", "handler")
	other := filepath.Join(root, "other")
	for _, dir := range []string{handler, other} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module "+strings.TrimSuffix(hashModule, "/")+"\ngo 1.26.10\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(handler, "relative.fixture"), []byte("owned"), 0600); err != nil {
		t.Fatal(err)
	}
	source := `package handler
import("testing";"os";"fmt")
func init(){if raw,err:=os.ReadFile("relative.fixture");err!=nil||string(raw)!="owned"{panic("handler cwd lost")}}
func Example(){fmt.Println("owned")
// Output: owned
}
func FuzzSeeds(f *testing.F){f.Add("seed");f.Fuzz(func(t *testing.T,s string){if s!="seed"{t.Fatal("seed changed")}})}
`
	for i := 0; i < 18; i++ {
		source += fmt.Sprintf("func TestActual%02d(t *testing.T){if %d==0&&os.Getenv(\"HASH_COHORT_UNIT_FAIL\")==\"1\"{t.Fatal(\"deliberate native failure\")}}\n", i, i)
	}
	if err := os.WriteFile(filepath.Join(handler, "handler_test.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "other_test.go"), []byte("package other\nimport \"testing\"\nfunc TestOther(t *testing.T){}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "handler.test")
	build := exec.Command("go", "test", "-c", "-tags=e2e", "-p=2", "-o", binary, "./internal/handler")
	if raw, err := build.CombinedOutput(); err != nil {
		t.Fatalf("native mini-suite build failed: %v %s", err, raw)
	}
	packages := filepath.Join(root, "packages")
	inventory := filepath.Join(root, "inventory")
	if err := os.WriteFile(packages, []byte(handlerPackage+"\n"+hashModule+"other\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventory, []byte(handlerPackage+" tests\n"+hashModule+"other tests\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, fail := range []bool{false, true} {
		t.Setenv("HASH_COHORT_UNIT_FAIL", fmt.Sprint(map[bool]int{false: 0, true: 1}[fail]))
		evidence := filepath.Join(root, fmt.Sprintf("evidence-%t", fail))
		if err := os.Mkdir(evidence, 0700); err != nil {
			t.Fatal(err)
		}
		err := ordinaryCohortsRun([]string{evidence, binary, packages, inventory})
		if (err != nil) != fail {
			t.Fatalf("native failure was lost or success refused: fail=%t err=%v", fail, err)
		}
		raw, readErr := os.ReadFile(filepath.Join(evidence, "ordinary.summary.json"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		var summary cohortProfileSummary
		if err := json.Unmarshal(raw, &summary); err != nil {
			t.Fatal(err)
		}
		if !summary.CoverageVerified || summary.HandlerRoots != 20 || summary.ExpectedPackages != 2 || len(summary.Invocations) != 3 || summary.PassedTests+len(summary.FailedTests) != 22 {
			t.Fatal("native catalog union/root/fuzz/package accounting differs", string(raw))
		}
		if fail && summary.FailedPackages != 1 || !fail && summary.PassedPackages != 2 {
			t.Fatal("handler package count was duplicated or native failure concealed")
		}
		failedInvocations := 0
		for _, receipt := range summary.Invocations {
			if !receipt.ProcessJoined {
				t.Fatal("native process group did not settle")
			}
			if receipt.ID != "ordinary-other" && receipt.WorkingDirectory != handler {
				t.Fatal("handler did not retain package working directory")
			}
			if receipt.NativeExit != 0 {
				failedInvocations++
			}
		}
		if fail && failedInvocations != 1 || !fail && failedInvocations != 0 {
			t.Fatal("actual native exit receipt changed")
		}
	}
}

func TestCohortCancellationJoinsNativeChildGroup(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := filepath.Join(t.TempDir(), "ready")
	// The leader reaps its worker on TERM; the whole owned group is fenced.
	cmd := exec.Command("sh", "-c", `trap 'wait; exit 143' TERM; sleep 30 & printf ready > "$1"; wait`, "cohort-fixture", ready)
	done := make(chan cohortProcessOutcome, 1)
	go func() { done <- runCohortProcess(ctx, cmd) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("finite native cancellation fixture did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case result := <-done:
		if !result.Cancelled || !result.Joined || result.ExitCode == 0 {
			t.Fatal("cancelled native child group was credited as success or left unjoined", result)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("native cancellation did not settle within cleanup bound")
	}
}

func TestHandlerCatalogRefusesMalformedDuplicateAndBenchmarkRoots(t *testing.T) {
	for _, catalog := range []string{"", "TestActual\n\n", "TestActual\nTestActual\n", "BenchmarkCost\n", "TestActual/subcase\n", "PASS\n", "TestActual :one\n", "TestActual\x00\n"} {
		if _, err := planHandlerCohorts(strings.NewReader(catalog)); err == nil {
			t.Fatal("invalid test catalog accepted", catalog)
		}
	}
}

func TestCohortDiagnosticBudgetDoesNotLoseFailureAccounting(t *testing.T) {
	total := profileSummary{Result: "passed"}
	for i := 0; i < 100; i++ {
		part := profileSummary{Result: "failed", FailedTests: []testID{{handlerPackage, fmt.Sprintf("TestFailure%d", i)}}, Diagnostics: []failureDiagnostic{{Package: handlerPackage, Test: fmt.Sprintf("TestFailure%d", i), State: "failed", Header: []string{strings.Repeat("h", 256)}, Tail: []string{strings.Repeat("x", 256), strings.Repeat("x", 256)}}}, UnfinishedTests: []testID{{handlerPackage, fmt.Sprintf("TestUnfinished%d", i)}}}
		mergeInvocation(&total, part, true)
	}
	bytes := 0
	for _, id := range total.UnfinishedTests {
		bytes += len(id.Package) + len(id.Test)
	}
	for _, d := range total.Diagnostics {
		bytes += len(d.Package) + len(d.Test) + len(d.State)
		for _, line := range append(append([]string{}, d.Header...), d.Tail...) {
			bytes += len(line)
		}
	}
	if bytes > diagnosticMaxBytes || len(total.Diagnostics) > diagnosticMaxRecords || len(total.UnfinishedTests) > diagnosticMaxPending || !total.DiagnosticsTruncated || len(total.FailedTests) != 100 || total.Result != "failed" {
		t.Fatal("aggregate diagnostic limits changed authoritative failure accounting")
	}
}

func cohortEvent(action, name string) string {
	raw, _ := json.Marshal(map[string]string{"Action": action, "Package": handlerPackage, "Test": name})
	return string(raw) + "\n"
}
func TestHandlerCohortRequiresEverySelectedRunAndTerminal(t *testing.T) {
	valid := cohortEvent("run", "TestA") + cohortEvent("run", "TestA/child") + cohortEvent("pass", "TestA/child") + cohortEvent("pass", "TestA") + cohortEvent("run", "FuzzSeed") + cohortEvent("run", "FuzzSeed/seed#0") + cohortEvent("pass", "FuzzSeed/seed#0") + cohortEvent("pass", "FuzzSeed") + cohortEvent("run", "Example") + cohortEvent("pass", "Example")
	selected := []string{"TestA", "FuzzSeed", "Example"}
	if err := auditCohortCoverage(selected, strings.NewReader(valid)); err != nil {
		t.Fatal("actual root/subtest/fuzz/example shape refused", err)
	}
	for name, events := range map[string]string{
		"missing root":         strings.ReplaceAll(valid, cohortEvent("run", "Example")+cohortEvent("pass", "Example"), ""),
		"missing terminal":     strings.ReplaceAll(valid, cohortEvent("pass", "Example"), ""),
		"duplicate run":        valid + cohortEvent("run", "TestA"),
		"duplicate terminal":   valid + cohortEvent("pass", "Example"),
		"unexpected root":      valid + cohortEvent("run", "TestOther"),
		"unexpected child":     valid + cohortEvent("run", "TestOther/child"),
		"terminal without run": strings.ReplaceAll(valid, cohortEvent("run", "Example"), ""),
		"malformed":            valid + `{"Action":`,
		"other package":        valid + `{"Action":"pass","Package":"unexpected","Test":"TestA"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if auditCohortCoverage(selected, strings.NewReader(events)) == nil {
				t.Fatal("incomplete or duplicate selected execution qualified")
			}
		})
	}
}

func TestHandlerUnionRefusesMissingDuplicateAndSubstitutedReceipts(t *testing.T) {
	cohorts, _ := planHandlerCohorts(strings.NewReader("TestA\nTestB\n"))
	valid := []invocationReceipt{{ID: "ordinary-other"}, {ID: cohorts[0].ID, Roots: append([]string(nil), cohorts[0].Roots...)}}
	if err := auditCohortUnion(cohorts, valid); err != nil {
		t.Fatal(err)
	}
	for _, test := range []string{"missing", "duplicate", "substitute", "coverage failed"} {
		receipts := append([]invocationReceipt(nil), valid...)
		receipts[1].Roots = append([]string(nil), receipts[1].Roots...)
		switch test {
		case "missing":
			receipts = receipts[:1]
		case "duplicate":
			receipts[1].Roots[1] = receipts[1].Roots[0]
		case "substitute":
			receipts[1].Roots[0] = "TestOther"
		case "coverage failed":
			receipts[1].AccountingError = "selected root missing"
		}
		if auditCohortUnion(cohorts, receipts) == nil {
			t.Fatal("invalid union accepted", test)
		}
	}
}

func TestCohortAggregationRetainsNativeFailureAndOptionalPending(t *testing.T) {
	other := profileSummary{Result: "passed", PassedPackages: 2, PassedTests: 3}
	total := profileSummary{Result: "passed"}
	mergeInvocation(&total, other, false)
	for _, result := range []string{"pending", "failed", "passed"} {
		mergeInvocation(&total, profileSummary{Result: result, PassedPackages: 1, PassedTests: 1}, true)
	}
	if total.Result != "failed" || total.GoExitCode != 1 || total.PassedPackages != 2 || total.PassedTests != 6 {
		t.Fatal("native handler failure or unique package accounting was overwritten")
	}
	pending := profileSummary{Result: "passed"}
	mergeInvocation(&pending, profileSummary{Result: "pending", SkippedTests: []testID{{handlerPackage, "TestOptional"}}, SeparateProfiles: []separateProfileCoverage{{Profile: "external-browser", State: "separate profile not run"}}}, true)
	if pending.Result != "pending" || len(pending.SkippedTests) != 1 || len(pending.SeparateProfiles) != 1 {
		t.Fatal("optional acceptance skip became a success")
	}
}

func TestInvocationEnvelopePreservesNativeFailureWithoutSyntheticPass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events")
	raw := cohortEvent("run", "TestA") + cohortEvent("fail", "TestA") + `{"Action":`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := appendInvocationEvidence(&out, path, "handler-000", invocationReceipt{ID: "handler-000", NativeExit: 1, Result: "failed"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `"Action":"pass"`) || !strings.Contains(out.String(), "invalid_native_fragment_base64") || !strings.Contains(out.String(), `"native_exit_code":1`) {
		t.Fatal("raw failure/malformed evidence was lost or replaced with success")
	}
	dec := json.NewDecoder(&out)
	for dec.More() {
		var envelope map[string]json.RawMessage
		if err := dec.Decode(&envelope); err != nil {
			t.Fatal(err)
		}
		if envelope["Action"] != nil || envelope["Package"] != nil {
			t.Fatal("invocation evidence masquerades as a native package event")
		}
	}
}
