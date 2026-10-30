// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	diagnosticMaxStreams = 160
	diagnosticMaxRunning = 1024
	diagnosticMaxRecords = 24
	diagnosticMaxPending = 128
	diagnosticMaxBytes   = 16 << 10
	diagnosticMaxLine    = 256
	diagnosticHeadRows   = 2
	diagnosticTailRows   = 6
)

type failureDiagnostic struct {
	Package string   `json:"package"`
	Test    string   `json:"test,omitempty"`
	State   string   `json:"state"`
	Header  []string `json:"header,omitempty"`
	Tail    []string `json:"tail,omitempty"`
}

type diagnosticStream struct {
	header, tail, assertions []string
	truncated                bool
	blocked                  bool
	pem                      bool
}
type eventDiagnostics struct {
	streams   map[testID]*diagnosticStream
	running   map[testID]bool
	truncated bool
}

var (
	diagnosticANSI       = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	diagnosticURL        = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	diagnosticUserInfo   = regexp.MustCompile(`://[^/?#\s]+@`)
	diagnosticQuery      = regexp.MustCompile(`[?&][^\s"'<>]+`)
	diagnosticCredential = regexp.MustCompile(`(?i)\b(?:[a-z0-9]+[-_])*(?:authorization|authentication|proxy[-_]?authorization|cookie|set[-_]?cookie|password|passwd|pwd|client[-_]?secret|secret|credentials?|api[-_ ]?key|api[-_]?token|x[-_]?api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|token|session[-_]?key|session[-_]?token|signing[-_]?key|jwt|private[-_ ]?key|secret[-_]?access[-_]?key|access[-_]?key[-_]?id)\b["']?\s*[:=]`)
	diagnosticPEMBegin   = regexp.MustCompile(`(?i)-----BEGIN(?:[ \t]+[A-Z0-9]+)*[ \t]+PRIVATE[ \t]+KEY-----`)
	diagnosticPEMEnd     = regexp.MustCompile(`(?i)-----END(?:[ \t]+[A-Z0-9]+)*[ \t]+PRIVATE[ \t]+KEY-----`)
	diagnosticAuth       = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[^\s,;"']+`)
	diagnosticAssertion  = regexp.MustCompile(`^\s*[A-Za-z0-9_./-]+\.go:[0-9]+(?::[0-9]+)?:\s`)
)

func diagnosticBound(s string, size int) string {
	if len(s) <= size {
		return s
	}
	s = s[:size-3]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "..."
}

// Credential-shaped lines are withheld in full, including following multiline
// values until another source assertion/control boundary. Redaction happens
// before truncation, so a short tail cannot expose a credential prefix.
func diagnosticRedact(line string, blocked *bool) string {
	pem := false // Single-line identifiers; event streams retain their own PEM state.
	return diagnosticRedactWithPEM(line, blocked, &pem)
}
func diagnosticSensitive(line, marker string) string {
	if at := diagnosticAssertion.FindString(line); at != "" {
		return diagnosticBound(strings.TrimSpace(at)+" "+marker, diagnosticMaxLine)
	}
	if diagnosticPanic(line) {
		return "panic: " + marker
	}
	return marker
}
func diagnosticRedactWithPEM(line string, blocked, pem *bool) string {
	line = diagnosticANSI.ReplaceAllString(line, "")
	line = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' {
			return -1
		}
		return r
	}, line)
	line = strings.ReplaceAll(strings.ReplaceAll(line, `\"`, `"`), `\'`, `'`)
	// A source-looking line inside key material is still private. Only the
	// actual END marker releases this state; assertion boundaries cannot do so.
	if diagnosticPEMBegin.MatchString(line) {
		*pem = true
		*blocked = true
		if diagnosticPEMEnd.MatchString(line) {
			*pem = false
			*blocked = false
		}
		return diagnosticSensitive(line, "[private key redacted]")
	}
	if *pem {
		if diagnosticPEMEnd.MatchString(line) {
			*pem = false
			*blocked = false
		}
		if diagnosticPanic(line) {
			return "panic: [private key continuation redacted]"
		}
		return "[private key continuation redacted]"
	}
	if diagnosticPEMEnd.MatchString(line) {
		return diagnosticSensitive(line, "[private key boundary redacted]")
	}
	if diagnosticAssertion.MatchString(line) {
		*blocked = false
	}
	line = diagnosticURL.ReplaceAllStringFunc(line, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return diagnosticUserInfo.ReplaceAllString(raw, "://[redacted]@")
		}
		if u.User != nil {
			u.User = url.User("redacted")
		}
		if u.RawQuery != "" {
			u.RawQuery = "redacted"
		}
		if u.Fragment != "" {
			u.Fragment = "redacted"
		}
		return u.String()
	})
	line = diagnosticUserInfo.ReplaceAllString(line, "://[redacted]@")
	line = diagnosticAuth.ReplaceAllString(line, "[authentication redacted]")
	line = diagnosticQuery.ReplaceAllString(line, "?[redacted]")
	if diagnosticCredential.MatchString(line) {
		*blocked = true
		return diagnosticSensitive(line, "[sensitive diagnostic redacted]")
	}
	if *blocked {
		return "[sensitive continuation redacted]"
	}
	return diagnosticBound(strings.TrimSpace(line), diagnosticMaxLine)
}

func diagnosticPanic(line string) bool {
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, "panic:") || strings.HasPrefix(line, "fatal error:") || strings.Contains(line, "test timed out after") || strings.HasPrefix(line, "SIGSEGV:") || strings.HasPrefix(line, "SIGABRT:")
}
func (s *diagnosticStream) add(raw string) {
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "=== ") || strings.HasPrefix(trimmed, "--- PASS:") || strings.HasPrefix(trimmed, "--- FAIL:") || strings.HasPrefix(trimmed, "--- SKIP:") {
			s.blocked = false
			continue
		}
		safe := diagnosticRedactWithPEM(line, &s.blocked, &s.pem)
		if safe == "" {
			continue
		}
		if diagnosticPanic(safe) {
			if len(s.header) < diagnosticHeadRows {
				s.header = append(s.header, safe)
			} else {
				s.truncated = true
			}
		}
		if len(safe) == diagnosticMaxLine && strings.HasSuffix(safe, "...") {
			s.truncated = true
		}
		if diagnosticAssertion.MatchString(safe) {
			s.assertions = append(s.assertions, safe)
			if len(s.assertions) > 4 {
				s.assertions = s.assertions[1:]
				s.truncated = true
			}
		}
		if len(s.tail) > 0 && s.tail[len(s.tail)-1] == safe {
			continue
		}
		s.tail = append(s.tail, safe)
		if len(s.tail) > diagnosticTailRows {
			s.tail = s.tail[1:]
			s.truncated = true
		}
	}
}
func (d *eventDiagnostics) observe(action, pkg, test, output string) {
	if d.streams == nil {
		d.streams = make(map[testID]*diagnosticStream)
		d.running = make(map[testID]bool)
	}
	id := testID{Package: pkg, Test: test}
	if action == "run" && test != "" {
		if len(d.running) < diagnosticMaxRunning || d.running[id] {
			d.running[id] = true
		} else {
			d.truncated = true
		}
	}
	if action == "pass" || action == "skip" || action == "fail" {
		delete(d.running, id)
	}
	if action == "pass" || action == "skip" {
		delete(d.streams, id)
	}
	if output == "" {
		return
	}
	ids := []testID{id}
	if test != "" {
		ids = append(ids, testID{Package: pkg})
	}
	for _, key := range ids {
		s := d.streams[key]
		if s == nil {
			if len(d.streams) >= diagnosticMaxStreams {
				d.truncated = true
				continue
			}
			s = &diagnosticStream{}
			d.streams[key] = s
		}
		s.add(output)
	}
}
func diagnosticIDLess(a, b testID) bool {
	if a.Package == b.Package {
		return a.Test < b.Test
	}
	return a.Package < b.Package
}
func (d *eventDiagnostics) attach(summary *profileSummary, tests map[testID]string, packages map[string]string) {
	ids := make([]testID, 0)
	for id := range d.running {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return diagnosticIDLess(ids[i], ids[j]) })
	remaining := diagnosticMaxBytes
	pendingBytes := 0
	for i, id := range ids {
		if i >= diagnosticMaxPending {
			d.truncated = true
			break
		}
		safe := diagnosticReportedID(id)
		cost := len(safe.Package) + len(safe.Test)
		if pendingBytes+cost > 4096 {
			d.truncated = true
			break
		}
		summary.UnfinishedTests = append(summary.UnfinishedTests, safe)
		remaining -= cost
		pendingBytes += cost
	}
	ids = ids[:0]
	for id, action := range tests {
		if action == "fail" {
			ids = append(ids, id)
		}
	}
	for id := range d.running {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return diagnosticIDLess(ids[i], ids[j]) })
	packageIDs := make([]testID, 0)
	testOutput := make(map[string]bool)
	for id, stream := range d.streams {
		if id.Test != "" && (tests[id] == "fail" || d.running[id]) && len(stream.header)+len(stream.tail) > 0 {
			testOutput[id.Package] = true
		}
	}
	for id, stream := range d.streams {
		if id.Test != "" || packages[id.Package] == "pass" || packages[id.Package] == "skip" {
			continue
		}
		if len(stream.header) > 0 || summary.GoExitCode != 0 && !testOutput[id.Package] {
			packageIDs = append(packageIDs, id)
		}
	}
	sort.Slice(packageIDs, func(i, j int) bool { return diagnosticIDLess(packageIDs[i], packageIDs[j]) })
	// Package panic context precedes test tails so a panic/timeout header survives
	// a long failing test list. Per-test assertion tails then receive remaining budget.
	ids = append(packageIDs, ids...)
	for _, id := range ids {
		s := d.streams[id]
		if s == nil || len(s.header)+len(s.tail) == 0 {
			continue
		}
		if len(summary.Diagnostics) >= diagnosticMaxRecords {
			d.truncated = true
			break
		}
		safe := diagnosticReportedID(id)
		record := failureDiagnostic{Package: diagnosticBound(safe.Package, 200), Test: diagnosticBound(safe.Test, 200), State: "failed"}
		if d.running[id] {
			record.State = "unfinished"
		}
		cost := len(record.Package) + len(record.Test) + len(record.State)
		if cost >= remaining {
			d.truncated = true
			break
		}
		remaining -= cost
		tail := s.tail
		if id.Test != "" && len(s.assertions) > 0 {
			tail = append([]string(nil), s.assertions...)
			last := s.tail
			if len(last) > 2 {
				last = last[len(last)-2:]
			}
			for _, row := range last {
				exists := false
				for _, saved := range tail {
					if row == saved {
						exists = true
						break
					}
				}
				if !exists {
					tail = append(tail, row)
				}
			}
		}
		if s.truncated {
			d.truncated = true
		}
		for index, rows := range [][]string{s.header, tail} {
			for _, row := range rows {
				if len(row) > remaining {
					d.truncated = true
					break
				}
				if index == 0 {
					record.Header = append(record.Header, row)
				} else {
					record.Tail = append(record.Tail, row)
				}
				remaining -= len(row)
			}
		}
		summary.Diagnostics = append(summary.Diagnostics, record)
	}
	summary.DiagnosticsTruncated = d.truncated
}

// Source IDs make accounting decisions unchanged. Only their reported strings
// are redacted/bounded, so a data-derived subtest name cannot bypass output
// redaction. Cardinality, skip classification and native failure stay intact.
func diagnosticReportedID(id testID) testID {
	blocked := false
	id.Package = diagnosticRedact(id.Package, &blocked)
	blocked = false
	id.Test = diagnosticRedact(id.Test, &blocked)
	return id
}
func diagnosticReportedSummary(summary *profileSummary) {
	for _, ids := range [][]testID{summary.FailedTests, summary.SkippedTests, summary.PendingParents, summary.UnexpectedSkips, summary.UnfinishedTests} {
		for i := range ids {
			ids[i] = diagnosticReportedID(ids[i])
		}
	}
	for i := range summary.SeparateProfiles {
		for j := range summary.SeparateProfiles[i].Tests {
			summary.SeparateProfiles[i].Tests[j] = diagnosticReportedID(summary.SeparateProfiles[i].Tests[j])
		}
	}
	for i := range summary.Diagnostics {
		id := diagnosticReportedID(testID{Package: summary.Diagnostics[i].Package, Test: summary.Diagnostics[i].Test})
		summary.Diagnostics[i].Package = id.Package
		summary.Diagnostics[i].Test = id.Test
	}
}
