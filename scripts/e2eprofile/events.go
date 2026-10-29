// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

type testID struct {
	Package string `json:"package"`
	Test    string `json:"test"`
}

type profileSummary struct {
	Schema           string                    `json:"schema"`
	Profile          string                    `json:"profile"`
	Result           string                    `json:"result"`
	GoExitCode       int                       `json:"go_exit_code"`
	AccountingError  string                    `json:"accounting_error,omitempty"`
	ExpectedPackages int                       `json:"expected_packages"`
	PassedPackages   int                       `json:"passed_packages"`
	FailedPackages   int                       `json:"failed_packages"`
	SkippedPackages  []string                  `json:"skipped_packages"`
	PassedTests      int                       `json:"passed_tests"`
	FailedTests      []testID                  `json:"failed_tests"`
	SkippedTests     []testID                  `json:"skipped_tests_pending"`
	PendingParents   []testID                  `json:"parent_tests_with_skipped_cases"`
	UnexpectedSkips  []testID                  `json:"unexpected_skipped_tests"`
	CompiledNoTests  []string                  `json:"compiled_packages_without_tests"`
	SeparateProfiles []separateProfileCoverage `json:"separate_profile_coverage"`
}

type separateProfileCoverage struct {
	Profile string   `json:"profile"`
	State   string   `json:"state"`
	Tests   []testID `json:"tests"`
}

// auditRun only emits bounded identities/counts. Event Output fields, which can
// contain ordinary test diagnostics, remain in the caller's private JSON file.
func auditRun(args []string) error {
	if len(args) != 7 {
		return fmt.Errorf("audit requires profile, package inventory, event file, summary, skip inventory, Go exit code and source test inventory")
	}
	code, err := strconv.Atoi(args[5])
	if err != nil || code < 0 || code > 255 {
		return fmt.Errorf("invalid captured Go exit code")
	}
	inventory, err := os.Open(args[1])
	if err != nil {
		return fmt.Errorf("cannot read expected package inventory")
	}
	defer inventory.Close()
	events, err := os.Open(args[2])
	if err != nil {
		return fmt.Errorf("cannot read Go JSON events")
	}
	defer events.Close()
	testFile, err := os.Open(args[6])
	if err != nil {
		return fmt.Errorf("cannot read source test inventory")
	}
	defer testFile.Close()
	withTests, err := readTestInventory(testFile)
	if err != nil {
		return err
	}
	summary, err := summarizeEvents(args[0], code, inventory, events, withTests)
	if err != nil {
		summary.Result = "failed"
		summary.AccountingError = err.Error()
	}
	raw, err := json.MarshalIndent(summary, "", "  ")
	if err != nil || os.WriteFile(args[3], append(raw, '\n'), 0600) != nil {
		return fmt.Errorf("cannot retain profile summary")
	}
	var skipped strings.Builder
	for _, id := range summary.SkippedTests {
		fmt.Fprintf(&skipped, "%s\t%s\n", id.Package, id.Test)
	}
	for _, id := range summary.UnexpectedSkips {
		fmt.Fprintf(&skipped, "%s\t%s\tunexpected\n", id.Package, id.Test)
	}
	for _, name := range summary.SkippedPackages {
		fmt.Fprintf(&skipped, "%s\t[package skipped]\n", name)
	}
	if err := os.WriteFile(args[4], []byte(skipped.String()), 0600); err != nil {
		return fmt.Errorf("cannot retain pending skip inventory")
	}
	if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		return fmt.Errorf("cannot report profile summary")
	}
	if summary.Result == "failed" {
		return fmt.Errorf("profile failed; inspect its retained Go events")
	}
	return nil
}

func summarizeEvents(profile string, code int, inventory, input io.Reader, withTests map[string]bool) (profileSummary, error) {
	summary := profileSummary{Schema: "hash.e2e-profile.v1", Profile: profile, Result: "passed", GoExitCode: code,
		SkippedPackages: []string{}, FailedTests: []testID{}, SkippedTests: []testID{}, UnexpectedSkips: []testID{}, CompiledNoTests: []string{}, SeparateProfiles: []separateProfileCoverage{}}
	expected := make(map[string]bool)
	scanner := bufio.NewScanner(inventory)
	for scanner.Scan() {
		name := scanner.Text()
		if name == "" || expected[name] {
			return summary, fmt.Errorf("empty or duplicate expected package")
		}
		expected[name] = true
	}
	if scanner.Err() != nil || len(expected) == 0 {
		return summary, fmt.Errorf("expected package inventory is unavailable")
	}
	summary.ExpectedPackages = len(expected)
	packages := make(map[string]string)
	tests := make(map[testID]string)
	decoder := json.NewDecoder(input)
	for {
		var event struct{ Action, Package, Test string }
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			return summary, fmt.Errorf("Go JSON event stream is incomplete or malformed")
		}
		if event.Action != "pass" && event.Action != "fail" && event.Action != "skip" {
			continue
		}
		if !expected[event.Package] {
			return summary, fmt.Errorf("Go events escaped the expected package partition")
		}
		if event.Test == "" {
			if packages[event.Package] != "" {
				return summary, fmt.Errorf("package executed more than once")
			}
			packages[event.Package] = event.Action
		} else {
			id := testID{Package: event.Package, Test: event.Test}
			if tests[id] != "" {
				return summary, fmt.Errorf("test terminal event appeared more than once")
			}
			tests[id] = event.Action
		}
	}
	if len(packages) != len(expected) {
		return summary, fmt.Errorf("Go events did not account for every expected package")
	}
	testCounts := make(map[string]int)
	for id := range tests {
		testCounts[id.Package]++
	}
	for name, action := range packages {
		hasTests, known := withTests[name]
		if !known {
			return summary, fmt.Errorf("package missing from same-tag source test inventory")
		}
		if hasTests && (action == "skip" || testCounts[name] == 0) {
			return summary, fmt.Errorf("a package with test files skipped or emitted no test terminal events")
		}
		switch action {
		case "pass":
			summary.PassedPackages++
		case "fail":
			summary.FailedPackages++
		case "skip":
			summary.CompiledNoTests = append(summary.CompiledNoTests, name)
		}
	}
	separate := make(map[string][]testID)
	pendingParents := make(map[testID]bool)
	for id, action := range tests {
		if action != "skip" {
			continue
		}
		parent := id.Test
		for {
			end := strings.LastIndexByte(parent, '/')
			if end < 0 {
				break
			}
			parent = parent[:end]
			parentID := testID{Package: id.Package, Test: parent}
			if tests[parentID] == "pass" {
				pendingParents[parentID] = true
			}
		}
	}
	for id, action := range tests {
		switch action {
		case "pass":
			if pendingParents[id] {
				summary.PendingParents = append(summary.PendingParents, id)
			} else {
				summary.PassedTests++
			}
		case "fail":
			summary.FailedTests = append(summary.FailedTests, id)
		case "skip":
			if owner, allowed := optionalSkip(id, os.Getenv); allowed {
				summary.SkippedTests = append(summary.SkippedTests, id)
				separate[owner] = append(separate[owner], id)
			} else {
				summary.UnexpectedSkips = append(summary.UnexpectedSkips, id)
			}
		}
	}
	sort.Strings(summary.SkippedPackages)
	less := func(a, b testID) bool {
		if a.Package == b.Package {
			return a.Test < b.Test
		}
		return a.Package < b.Package
	}
	sort.Slice(summary.FailedTests, func(i, j int) bool { return less(summary.FailedTests[i], summary.FailedTests[j]) })
	sort.Slice(summary.SkippedTests, func(i, j int) bool { return less(summary.SkippedTests[i], summary.SkippedTests[j]) })
	sort.Slice(summary.UnexpectedSkips, func(i, j int) bool { return less(summary.UnexpectedSkips[i], summary.UnexpectedSkips[j]) })
	sort.Slice(summary.PendingParents, func(i, j int) bool { return less(summary.PendingParents[i], summary.PendingParents[j]) })
	sort.Strings(summary.CompiledNoTests)
	for owner, ids := range separate {
		sort.Slice(ids, func(i, j int) bool { return less(ids[i], ids[j]) })
		summary.SeparateProfiles = append(summary.SeparateProfiles, separateProfileCoverage{Profile: owner, State: "separate profile not run", Tests: ids})
	}
	sort.Slice(summary.SeparateProfiles, func(i, j int) bool { return summary.SeparateProfiles[i].Profile < summary.SeparateProfiles[j].Profile })
	if len(summary.SkippedPackages) != 0 || len(summary.SkippedTests) != 0 {
		summary.Result = "pending"
	}
	if code != 0 || summary.FailedPackages != 0 || len(summary.FailedTests) != 0 || len(summary.UnexpectedSkips) != 0 {
		summary.Result = "failed"
	}
	return summary, nil
}

func readTestInventory(input io.Reader) (map[string]bool, error) {
	result := make(map[string]bool)
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid source test inventory")
		}
		if _, duplicate := result[fields[0]]; duplicate {
			return nil, fmt.Errorf("duplicate source test inventory")
		}
		switch fields[1] {
		case "tests":
			result[fields[0]] = true
		case "no-tests":
			result[fields[0]] = false
		default:
			return nil, fmt.Errorf("invalid source test inventory state")
		}
	}
	if scanner.Err() != nil || len(result) == 0 {
		return nil, fmt.Errorf("source test inventory unavailable")
	}
	return result, nil
}
