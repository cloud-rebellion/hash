// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const handlerCohortRoots = 16
const handlerPackage = hashModule + "internal/handler"

type handlerCohort struct {
	ID      string   `json:"id"`
	Roots   []string `json:"roots"`
	Pattern string   `json:"pattern"`
}
type invocationReceipt struct {
	ID               string   `json:"id"`
	Roots            []string `json:"selected_roots,omitempty"`
	NativeExit       int      `json:"native_exit_code"`
	EventSHA256      string   `json:"event_sha256"`
	Result           string   `json:"result"`
	AccountingError  string   `json:"accounting_error,omitempty"`
	ElapsedSeconds   float64  `json:"elapsed_seconds"`
	WorkingDirectory string   `json:"working_directory"`
	ProcessJoined    bool     `json:"process_group_joined"`
	Cancelled        bool     `json:"cancelled,omitempty"`
}
type cohortProfileSummary struct {
	profileSummary
	Execution          string              `json:"execution"`
	CatalogSHA256      string              `json:"handler_catalog_sha256"`
	BinarySHA256       string              `json:"handler_binary_sha256"`
	HandlerRoots       int                 `json:"handler_catalog_roots"`
	CoverageVerified   bool                `json:"handler_root_coverage_verified"`
	NotDispatchedRoots []string            `json:"handler_not_dispatched_roots,omitempty"`
	Invocations        []invocationReceipt `json:"invocations"`
}

const cohortFatalExitCode = 70

type unsettledCohortError struct{}

func (*unsettledCohortError) Error() string {
	return "native cohort ownership cancelled or unsettled; further dispatch forbidden"
}
func cohortErrorExitCode(err error) int {
	var fatal *unsettledCohortError
	if errors.As(err, &fatal) {
		return cohortFatalExitCode
	}
	return 1
}

func cohortReturnError(owner context.Context, dispatchErr, resultErr error) error {
	if owner.Err() != nil || cohortErrorExitCode(dispatchErr) == cohortFatalExitCode {
		return &unsettledCohortError{}
	}
	return resultErr
}

// The catalog comes from this same prebuilt tagged binary's -test.list output.
// Benchmarks have no role in mandatory Test/Example/Fuzz-seed qualification.
func planHandlerCohorts(input io.Reader) ([]handlerCohort, error) {
	scanner := bufio.NewScanner(input)
	seen := map[string]bool{}
	var roots []string
	for scanner.Scan() {
		name := scanner.Text()
		if !validCohortRoot(name) || seen[name] || len(roots) >= 4096 {
			return nil, fmt.Errorf("handler catalog has an invalid, duplicate or excessive root")
		}
		seen[name] = true
		roots = append(roots, name)
	}
	if scanner.Err() != nil || len(roots) == 0 {
		return nil, fmt.Errorf("handler catalog is empty or malformed")
	}
	sort.Strings(roots)
	var result []handlerCohort
	for start := 0; start < len(roots); start += handlerCohortRoots {
		end := min(start+handlerCohortRoots, len(roots))
		names := append([]string(nil), roots[start:end]...)
		quoted := make([]string, len(names))
		for i, name := range names {
			quoted[i] = regexp.QuoteMeta(name)
		}
		result = append(result, handlerCohort{fmt.Sprintf("handler-%03d", len(result)), names, "^(" + strings.Join(quoted, "|") + ")$"})
	}
	return result, nil
}
func validCohortRoot(name string) bool {
	if len(name) > 512 || !(strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Example") || strings.HasPrefix(name, "Fuzz")) {
		return false
	}
	for _, r := range name {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func auditCohortUnion(cohorts []handlerCohort, receipts []invocationReceipt) error {
	if len(cohorts) == 0 || len(receipts) != len(cohorts)+1 || receipts[0].ID != "ordinary-other" || len(receipts[0].Roots) != 0 {
		return fmt.Errorf("ordinary invocation union is incomplete")
	}
	seen := map[string]bool{}
	for i, c := range cohorts {
		r := receipts[i+1]
		if r.ID != c.ID || len(r.Roots) != len(c.Roots) || r.AccountingError != "" {
			return fmt.Errorf("handler cohort receipt is missing or failed coverage accounting")
		}
		for j, name := range c.Roots {
			if r.Roots[j] != name || seen[name] {
				return fmt.Errorf("handler root union duplicated, omitted or substituted a root")
			}
			seen[name] = true
		}
	}
	return nil
}

// Every selected root must start and terminate exactly once. Every subtest's
// parent must belong to this cohort; duplicate test runs/terminals are refused.
func auditCohortCoverage(roots []string, input io.Reader) error {
	selected := map[string]bool{}
	for _, name := range roots {
		if !validCohortRoot(name) || selected[name] {
			return fmt.Errorf("invalid selected handler roots")
		}
		selected[name] = true
	}
	if len(selected) == 0 {
		return fmt.Errorf("empty selected handler cohort")
	}
	runs, terminals := map[string]bool{}, map[string]bool{}
	dec := json.NewDecoder(input)
	for {
		var e struct{ Action, Package, Test string }
		if err := dec.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("handler cohort events malformed")
		}
		if e.Package != "" && e.Package != handlerPackage {
			return fmt.Errorf("handler cohort emitted an unexpected package")
		}
		if e.Test == "" {
			continue
		}
		root, _, _ := strings.Cut(e.Test, "/")
		if !selected[root] {
			return fmt.Errorf("handler cohort executed an unselected root or subtest")
		}
		switch e.Action {
		case "run":
			if runs[e.Test] || terminals[e.Test] {
				return fmt.Errorf("handler cohort duplicated or reordered a test run")
			}
			runs[e.Test] = true
		case "pass", "fail", "skip":
			if !runs[e.Test] || terminals[e.Test] {
				return fmt.Errorf("handler cohort terminal lacks one unique run")
			}
			terminals[e.Test] = true
		}
	}
	for name := range selected {
		if !runs[name] || !terminals[name] {
			return fmt.Errorf("handler cohort omitted a selected root or terminal")
		}
	}
	for name := range runs {
		if !terminals[name] {
			return fmt.Errorf("handler cohort left a test without a terminal")
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Explicit aggregation retains native invocation outcomes; it never invents a
// native Go package PASS event. A handler package passes only when every
// independently audited native cohort and the complete root catalog pass.
func mergeInvocation(total *profileSummary, part profileSummary, handler bool) {
	if !handler {
		total.PassedPackages += part.PassedPackages
		total.FailedPackages += part.FailedPackages
		total.CompiledNoTests = append(total.CompiledNoTests, part.CompiledNoTests...)
	}
	total.PassedTests += part.PassedTests
	total.FailedTests = append(total.FailedTests, part.FailedTests...)
	total.SkippedTests = append(total.SkippedTests, part.SkippedTests...)
	total.PendingParents = append(total.PendingParents, part.PendingParents...)
	total.UnexpectedSkips = append(total.UnexpectedSkips, part.UnexpectedSkips...)
	total.UnfinishedTests = append(total.UnfinishedTests, part.UnfinishedTests...)
	for _, d := range part.Diagnostics {
		if len(total.Diagnostics) < diagnosticMaxRecords {
			total.Diagnostics = append(total.Diagnostics, d)
		} else {
			total.DiagnosticsTruncated = true
		}
	}
	total.DiagnosticsTruncated = total.DiagnosticsTruncated || part.DiagnosticsTruncated
	for _, group := range part.SeparateProfiles {
		found := false
		for i := range total.SeparateProfiles {
			if total.SeparateProfiles[i].Profile == group.Profile {
				total.SeparateProfiles[i].Tests = append(total.SeparateProfiles[i].Tests, group.Tests...)
				found = true
				break
			}
		}
		if !found {
			total.SeparateProfiles = append(total.SeparateProfiles, group)
		}
	}
	if part.Result == "failed" {
		total.Result = "failed"
		total.GoExitCode = 1
	} else if part.Result == "pending" && total.Result != "failed" {
		total.Result = "pending"
	}
	if part.AccountingError != "" {
		total.AccountingError = "one or more native invocations failed accounting"
	}
	boundCohortDiagnostics(total)
}

func boundCohortDiagnostics(summary *profileSummary) {
	remaining, pendingBytes := diagnosticMaxBytes, 0
	kept := summary.UnfinishedTests[:0]
	for _, id := range summary.UnfinishedTests {
		cost := len(id.Package) + len(id.Test)
		if len(kept) >= diagnosticMaxPending || pendingBytes+cost > 4096 {
			summary.DiagnosticsTruncated = true
			break
		}
		kept = append(kept, id)
		pendingBytes += cost
		remaining -= cost
	}
	summary.UnfinishedTests = kept
	records := summary.Diagnostics[:0]
	for _, record := range summary.Diagnostics {
		cost := len(record.Package) + len(record.Test) + len(record.State)
		for _, rows := range [][]string{record.Header, record.Tail} {
			for _, line := range rows {
				cost += len(line)
			}
		}
		if len(records) >= diagnosticMaxRecords || cost > remaining {
			summary.DiagnosticsTruncated = true
			break
		}
		records = append(records, record)
		remaining -= cost
	}
	summary.Diagnostics = records
}

func ordinaryCohortsRun(args []string) (resultErr error) {
	if len(args) != 4 {
		return fmt.Errorf("ordinary cohorts require evidence, tagged handler binary, package inventory and source test inventory")
	}
	evidence, binary := args[0], args[1]
	binary, err := filepath.Abs(binary)
	if err != nil {
		return fmt.Errorf("cannot resolve source-built handler binary")
	}
	module, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot resolve module working directory")
	}
	owner, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var dispatchErr error
	defer func() {
		resultErr = cohortReturnError(owner, dispatchErr, resultErr)
	}()
	raw, err := os.ReadFile(args[2])
	if err != nil {
		return fmt.Errorf("cannot read ordinary package inventory")
	}
	var other []string
	seen := map[string]bool{}
	for _, name := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if name == "" || seen[name] {
			return fmt.Errorf("invalid ordinary package inventory")
		}
		seen[name] = true
		if name != handlerPackage {
			other = append(other, name)
		}
	}
	if !seen[handlerPackage] || len(other) == 0 {
		return fmt.Errorf("ordinary partition requires handler and other packages")
	}
	inventory, err := os.Open(args[3])
	if err != nil {
		return fmt.Errorf("cannot read same-tag source inventory")
	}
	withTests, err := readTestInventory(inventory)
	inventory.Close()
	if err != nil {
		return err
	}
	for name := range seen {
		if _, ok := withTests[name]; !ok {
			return fmt.Errorf("ordinary package absent from same-tag source inventory")
		}
	}
	if !withTests[handlerPackage] {
		return fmt.Errorf("handler source inventory must contain tests")
	}
	binarySHA, err := fileSHA256(binary)
	if err != nil {
		return fmt.Errorf("cannot pin source-built handler binary")
	}
	ctx, cancel := context.WithTimeout(owner, 30*time.Second)
	var listing bytes.Buffer
	listCmd := handlerCatalogCommand(module, binary)
	listCmd.Stdout = &limitedCatalogWriter{out: &listing, remaining: 1 << 20}
	listCmd.Stderr = io.Discard
	listed := runCohortProcess(ctx, listCmd)
	cancel()
	if !listed.Joined || listed.Cancelled {
		return &unsettledCohortError{}
	}
	if listed.ExitCode != 0 || listed.Residual {
		return fmt.Errorf("tagged handler test catalog failed")
	}
	cohorts, err := planHandlerCohorts(bytes.NewReader(listing.Bytes()))
	if err != nil {
		return err
	}
	catalogRaw, _ := json.Marshal(cohorts)
	catalogDigest := sha256.Sum256(catalogRaw)
	work, err := os.MkdirTemp("", "hash-handler-cohorts-")
	if err != nil {
		return fmt.Errorf("cannot create bounded cohort work directory")
	}
	defer os.RemoveAll(work)
	eventOut, err := os.OpenFile(filepath.Join(evidence, "ordinary.events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot create ordinary invocation evidence")
	}
	defer eventOut.Close()
	stderrOut, err := os.OpenFile(filepath.Join(evidence, "ordinary.stderr"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot create ordinary stderr evidence")
	}
	defer stderrOut.Close()
	if os.WriteFile(filepath.Join(evidence, "ordinary.packages"), raw, 0600) != nil {
		return fmt.Errorf("cannot retain ordinary package inventory")
	}
	total := cohortProfileSummary{profileSummary: profileSummary{Schema: "hash.e2e-cohort-profile.v1", Profile: "ordinary", Result: "passed", ExpectedPackages: len(seen), SkippedPackages: []string{}, FailedTests: []testID{}, SkippedTests: []testID{}, UnexpectedSkips: []testID{}, CompiledNoTests: []string{}, SeparateProfiles: []separateProfileCoverage{}}, Execution: "native-invocations-with-exact-handler-root-coverage", CatalogSHA256: hex.EncodeToString(catalogDigest[:]), BinarySHA256: binarySHA}
	for _, c := range cohorts {
		total.HandlerRoots += len(c.Roots)
	}
	handlerFailed := false
	run := func(id string, packages, roots []string, cmd *exec.Cmd) (runFailure error) {
		fmt.Printf("e2e ordinary invocation: %s (%d packages, %d selected roots)\n", id, len(packages), len(roots))
		eventPath, stderrPath := filepath.Join(work, "events"), filepath.Join(work, "stderr")
		out, err := os.Create(eventPath)
		if err != nil {
			return fmt.Errorf("cannot open native event evidence")
		}
		stderr, err := os.Create(stderrPath)
		if err != nil {
			out.Close()
			return fmt.Errorf("cannot open native stderr evidence")
		}
		start := time.Now()
		cmd.Stdout = out
		cmd.Stderr = stderr
		call := owner
		cancelCall := func() {}
		if len(roots) > 0 {
			call, cancelCall = context.WithTimeout(owner, 180*time.Second)
		}
		outcome := runCohortProcess(call, cmd)
		cancelCall()
		defer func() {
			if !outcome.Joined {
				runFailure = &unsettledCohortError{}
			}
		}()
		elapsed := time.Since(start).Seconds()
		closeErr := out.Close()
		stderrErr := stderr.Close()
		code := outcome.ExitCode
		if closeErr != nil || stderrErr != nil {
			return fmt.Errorf("native evidence could not settle")
		}
		events, err := os.Open(eventPath)
		if err != nil {
			return fmt.Errorf("native events unavailable")
		}
		part, auditErr := summarizeEvents("ordinary", max(0, code), strings.NewReader(strings.Join(packages, "\n")+"\n"), events, withTests)
		events.Close()
		if len(roots) > 0 {
			events, err = os.Open(eventPath)
			if err != nil {
				return fmt.Errorf("cohort events unavailable")
			}
			coverageErr := auditCohortCoverage(roots, events)
			events.Close()
			if coverageErr != nil {
				auditErr = coverageErr
			}
		}
		if code != 0 || auditErr != nil {
			part.Result = "failed"
		}
		if !outcome.Joined || outcome.Residual || outcome.Cancelled {
			auditErr = fmt.Errorf("native invocation cancelled or left process-group debt")
			part.Result = "failed"
		}
		if auditErr != nil {
			part.AccountingError = auditErr.Error()
		}
		eventSHA, err := fileSHA256(eventPath)
		if err != nil {
			return fmt.Errorf("native events could not be pinned")
		}
		receipt := invocationReceipt{ID: id, Roots: roots, NativeExit: code, EventSHA256: eventSHA, Result: part.Result, AccountingError: part.AccountingError, ElapsedSeconds: elapsed, WorkingDirectory: cmd.Dir, ProcessJoined: outcome.Joined, Cancelled: outcome.Cancelled}
		if err := appendInvocationEvidence(eventOut, eventPath, id, receipt); err != nil {
			return err
		}
		stderr, err = os.Open(stderrPath)
		if err != nil {
			return fmt.Errorf("native stderr unavailable")
		}
		_, copyErr := io.Copy(stderrOut, stderr)
		stderr.Close()
		if copyErr != nil {
			return fmt.Errorf("cannot retain native stderr")
		}
		total.Invocations = append(total.Invocations, receipt)
		mergeInvocation(&total.profileSummary, part, len(roots) > 0)
		if len(roots) > 0 && part.Result == "failed" {
			handlerFailed = true
		}
		if !outcome.Joined {
			return &unsettledCohortError{}
		}
		return nil
	}
	command := append([]string{"go", "test", "-json", "-tags=e2e", "-count=1", "-timeout=180s", "-p=2", "-parallel=2"}, other...)
	otherCommand := exec.Command(command[0], command[1:]...)
	otherCommand.Dir = module
	dispatchErr = run("ordinary-other", other, nil, otherCommand)
	for _, cohort := range cohorts {
		if dispatchErr != nil {
			break
		}
		if owner.Err() != nil {
			handlerFailed = true
			total.Result = "failed"
			total.GoExitCode = 1
			break
		}
		dispatchErr = run(cohort.ID, []string{handlerPackage}, cohort.Roots, handlerTestCommand(module, binary, cohort.Pattern))
	}
	if dispatchErr != nil {
		handlerFailed = true
		total.Result = "failed"
		total.GoExitCode = 1
		total.AccountingError = "native invocation dispatch or settlement failed"
	}
	dispatched := map[string]bool{}
	for _, receipt := range total.Invocations {
		for _, root := range receipt.Roots {
			dispatched[root] = true
		}
	}
	for _, cohort := range cohorts {
		for _, root := range cohort.Roots {
			if !dispatched[root] {
				total.NotDispatchedRoots = append(total.NotDispatchedRoots, root)
			}
		}
	}
	currentSHA, err := fileSHA256(binary)
	if err != nil || currentSHA != binarySHA {
		return fmt.Errorf("handler test binary changed after catalog execution")
	}
	if handlerFailed {
		total.FailedPackages++
	} else {
		total.PassedPackages++
	}
	if err := auditCohortUnion(cohorts, total.Invocations); err != nil {
		total.Result = "failed"
		total.AccountingError = err.Error()
	} else {
		total.CoverageVerified = true
	}
	if total.PassedPackages+total.FailedPackages+len(total.CompiledNoTests) != len(seen) {
		total.Result = "failed"
		total.AccountingError = "ordinary aggregate did not account for every distinct package"
	}
	if err := eventOut.Close(); err != nil {
		return fmt.Errorf("ordinary event evidence did not settle")
	}
	if err := stderrOut.Close(); err != nil {
		return fmt.Errorf("ordinary stderr evidence did not settle")
	}
	sort.Slice(total.SeparateProfiles, func(i, j int) bool { return total.SeparateProfiles[i].Profile < total.SeparateProfiles[j].Profile })
	encoded, err := json.MarshalIndent(total, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(evidence, "ordinary.summary.json"), append(encoded, '\n'), 0600) != nil {
		return fmt.Errorf("cannot retain aggregate ordinary summary")
	}
	var skipped strings.Builder
	for _, id := range total.SkippedTests {
		fmt.Fprintf(&skipped, "%s\t%s\n", id.Package, id.Test)
	}
	for _, id := range total.UnexpectedSkips {
		fmt.Fprintf(&skipped, "%s\t%s\tunexpected\n", id.Package, id.Test)
	}
	if os.WriteFile(filepath.Join(evidence, "ordinary.skipped-tests.txt"), []byte(skipped.String()), 0600) != nil {
		return fmt.Errorf("cannot retain aggregate skip inventory")
	}
	if err := json.NewEncoder(os.Stdout).Encode(total); err != nil {
		return fmt.Errorf("cannot report ordinary aggregate")
	}
	if owner.Err() != nil {
		return &unsettledCohortError{}
	}
	if dispatchErr != nil && cohortErrorExitCode(dispatchErr) == cohortFatalExitCode {
		return dispatchErr
	}
	if total.Result == "failed" {
		return fmt.Errorf("ordinary invocation or exact root coverage failed")
	}
	return nil
}

func handlerCatalogCommand(module, binary string) *exec.Cmd {
	cmd := exec.Command(binary, "-test.list=^(Test|Example|Fuzz)")
	cmd.Dir = filepath.Join(module, "internal", "handler")
	return cmd
}
func handlerTestCommand(module, binary, pattern string) *exec.Cmd {
	cmd := exec.Command("go", "tool", "test2json", "-t", "-p", handlerPackage, binary, "-test.v=test2json", "-test.count=1", "-test.timeout=180s", "-test.parallel=2", "-test.run="+pattern)
	cmd.Dir = filepath.Join(module, "internal", "handler")
	return cmd
}

type cohortProcessOutcome struct {
	ExitCode                    int
	Joined, Cancelled, Residual bool
}

// Every native invocation owns one process group, including its test binary
// and PDF children. Cancellation and unexpected descendant debt are settled
// before another cohort is dispatched; an unresolved group always fails.
func runCohortProcess(ctx context.Context, cmd *exec.Cmd) cohortProcessOutcome {
	result := cohortProcessOutcome{ExitCode: -1, Joined: true}
	if ctx.Err() != nil {
		result.Cancelled = true
		return result
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	if cmd.Start() != nil {
		return result
	}
	result.Joined = false
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waited := false
	select {
	case <-done:
		waited = true
	case <-ctx.Done():
		result.Cancelled = true
	}
	absent := func() bool { return syscall.Kill(-cmd.Process.Pid, 0) == syscall.ESRCH }
	settle := func(until time.Time) bool {
		for {
			if !waited {
				select {
				case <-done:
					waited = true
				default:
				}
			}
			if waited && absent() {
				return true
			}
			if time.Now().After(until) {
				return false
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if waited && absent() {
		result.Joined = true
	} else {
		result.Residual = !result.Cancelled
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		if settle(time.Now().Add(2 * time.Second)) {
			result.Joined = true
		} else {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			result.Joined = settle(time.Now().Add(3 * time.Second))
		}
	}
	if waited && cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	return result
}

type limitedCatalogWriter struct {
	out       io.Writer
	remaining int
}

func (w *limitedCatalogWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, fmt.Errorf("handler catalog exceeds bound")
	}
	n, err := w.out.Write(p)
	w.remaining -= n
	return n, err
}

func appendInvocationEvidence(out io.Writer, path, id string, receipt invocationReceipt) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read invocation evidence")
	}
	defer f.Close()
	reader, enc := bufio.NewReader(f), json.NewEncoder(out)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			if json.Valid(line) {
				if err := enc.Encode(struct {
					Schema     string          `json:"schema"`
					Invocation string          `json:"invocation"`
					Event      json.RawMessage `json:"event"`
				}{"hash.e2e-native-event.v1", id, line}); err != nil {
					return fmt.Errorf("cannot retain invocation envelope")
				}
			} else if err := enc.Encode(struct {
				Schema     string `json:"schema"`
				Invocation string `json:"invocation"`
				Fragment   []byte `json:"invalid_native_fragment_base64"`
			}{"hash.e2e-native-invalid.v1", id, line}); err != nil {
				return fmt.Errorf("cannot retain malformed native evidence")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("cannot read native invocation evidence")
		}
	}
	if err := enc.Encode(struct {
		Schema  string            `json:"schema"`
		Receipt invocationReceipt `json:"receipt"`
	}{"hash.e2e-native-receipt.v1", receipt}); err != nil {
		return fmt.Errorf("cannot retain native exit receipt")
	}
	return nil
}
