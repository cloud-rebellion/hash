// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package sourceguard holds AST checks over the whole module. Each check pins a
// defect class found in the PR 5 audits so it cannot come back unnoticed. They
// run with the plain unit suite (go test ./...), so scripts/ci.sh enforces them.
package sourceguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type parsedFile struct {
	rel  string
	fset *token.FileSet
	file *ast.File
}

// moduleFiles parses every non-generated .go file under internal/ and cmd/.
// Build constraints are ignored on purpose: the e2e-tagged files are checked too.
func moduleFiles(t *testing.T) []parsedFile {
	t.Helper()
	var out []parsedFile
	for _, top := range []string{"internal", "cmd"} {
		root := filepath.Join("..", "..", top)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "generated" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(filepath.Join("..", ".."), path)
			out = append(out, parsedFile{rel: filepath.ToSlash(rel), fset: fset, file: f})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) < 100 {
		t.Fatalf("parsed only %d files; the module root moved, the guards would pass vacuously", len(out))
	}
	return out
}

func calleeName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

func isIdentNamed(e ast.Expr, name string) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name == name
	case *ast.Ident:
		return v.Name == name
	}
	return false
}

// funcs yields every function declaration with its qualified name.
func funcs(pf parsedFile, visit func(name string, fn *ast.FuncDecl)) {
	for _, d := range pf.file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
			visit(fn.Name.Name, fn)
		}
	}
}

// ---------------------------------------------------------------------------
// (a) The audit logger measures every event that names a document.
//
// html_snapshot_event_payload_sizes_v1 must hold a row for every event on an
// HTML document, or the revision collections reader fails and the document can
// never be revised (N1, R2, C1: a permanent 503). Asking each of the dozens of
// Audit.LogTx call sites to measure its own event failed twice: five writers
// (rename, field delete, reminder policy, routing tier REST and MCP) shipped
// unmeasured. The measurement now lives in the one place that inserts events,
// audit.Logger.append, and this guard pins that chokepoint instead of the call
// sites: the insert has exactly one caller, the measurement follows it
// unconditionally for a DocumentID, and no other writer can add an event row
// without being named here.
// ---------------------------------------------------------------------------

const (
	auditLogFile        = "internal/audit/log.go"
	auditMeasureHelper  = "measureDocumentEventV1"
	auditMeasureQuery   = "MeasureHTMLSnapshotEventPayloadV1"
	auditInsertQuery    = "InsertEvent"
	ownedInsertQuery    = "InsertEventIdentityV1"
	auditAppendFunction = "append"
)

// ownedEventWriterDirs may call InsertEventIdentityV1. These are the owned
// writers; each measures the event inside its own proof (see
// pdfadmission/application_html_audit_event_v1.go). Prefix match on the path.
var ownedEventWriterDirs = []string{"internal/pdfadmission/", "internal/ownedaudit/"}

func callsAny(fn *ast.FuncDecl, names map[string]bool) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && names[calleeName(c)] {
			found = true
		}
		return !found
	})
	return found
}

func hasCallTo(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if c, ok := x.(*ast.CallExpr); ok && calleeName(c) == name {
			found = true
		}
		return !found
	})
	return found
}

func condIsDocumentIDNotNil(e ast.Expr) bool {
	b, ok := e.(*ast.BinaryExpr)
	if !ok || b.Op != token.NEQ {
		return false
	}
	nilSide, other := b.Y, b.X
	if id, ok := b.X.(*ast.Ident); ok && id.Name == "nil" {
		nilSide, other = b.X, b.Y
	}
	id, ok := nilSide.(*ast.Ident)
	if !ok || id.Name != "nil" {
		return false
	}
	sel, ok := other.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "DocumentID"
}

func TestAuditLoggerMeasuresEveryDocumentEvent(t *testing.T) {
	files := moduleFiles(t)
	var appendFn, helperFn *ast.FuncDecl
	for _, pf := range files {
		if pf.rel != auditLogFile {
			continue
		}
		funcs(pf, func(name string, fn *ast.FuncDecl) {
			switch name {
			case auditAppendFunction:
				appendFn = fn
			case auditMeasureHelper:
				helperFn = fn
			}
		})
	}
	if appendFn == nil || helperFn == nil {
		t.Fatalf("%s must define %s and %s; the audit chokepoint moved and this guard would pass vacuously", auditLogFile, auditAppendFunction, auditMeasureHelper)
	}
	if !hasCallTo(helperFn, auditMeasureQuery) {
		t.Errorf("%s no longer calls %s", auditMeasureHelper, auditMeasureQuery)
	}
	// The measurement is a top-level statement of append, after the insert and
	// guarded only by DocumentID != nil, so no early return, nested branch or
	// second event can slip past it.
	inserted, measured := -1, false
	for i, stmt := range appendFn.Body.List {
		if hasCallTo(stmt, auditInsertQuery) && inserted < 0 {
			inserted = i
		}
		if ifs, ok := stmt.(*ast.IfStmt); ok && inserted >= 0 && i > inserted && condIsDocumentIDNotNil(ifs.Cond) && ifs.Else == nil {
			for _, inner := range ifs.Body.List {
				if hasCallTo(inner, auditMeasureHelper) {
					measured = true
				}
			}
		}
	}
	if inserted < 0 {
		t.Errorf("%s.%s no longer calls %s", auditLogFile, auditAppendFunction, auditInsertQuery)
	} else if !measured {
		t.Errorf("%s.%s must measure the event right after %s with a top-level `if e.DocumentID != nil { %s(...) }`; an unmeasured document event makes an HTML draft permanently unrevisable (503)", auditLogFile, auditAppendFunction, auditInsertQuery, auditMeasureHelper)
	}

	for _, pf := range files {
		if strings.HasSuffix(pf.rel, "_test.go") {
			continue
		}
		funcs(pf, func(name string, fn *ast.FuncDecl) {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.SelectorExpr:
					// Selectors, not calls: a method value (f := q.InsertEvent) is a bypass too.
					switch v.Sel.Name {
					case auditInsertQuery:
						if pf.rel != auditLogFile || name != auditAppendFunction {
							t.Errorf("%s:%s (%s) uses %s. Events are inserted only by audit.Logger.append, which measures them (C1)", pf.rel, name, pf.fset.Position(v.Pos()), auditInsertQuery)
						}
					case ownedInsertQuery:
						allowed := false
						for _, dir := range ownedEventWriterDirs {
							allowed = allowed || strings.HasPrefix(pf.rel, dir)
						}
						if !allowed {
							t.Errorf("%s:%s (%s) uses %s outside the owned event writers %v, which measure their own events", pf.rel, name, pf.fset.Position(v.Pos()), ownedInsertQuery, ownedEventWriterDirs)
						}
					case auditAppendFunction:
						if x, ok := v.X.(*ast.Ident); ok && x.Name == "l" && strings.HasPrefix(pf.rel, "internal/audit/") && name != "Log" && name != "LogTx" {
							t.Errorf("%s:%s (%s) calls Logger.append directly; only Log and LogTx may, so every path is measured", pf.rel, name, pf.fset.Position(v.Pos()))
						}
					}
				case *ast.BasicLit:
					if v.Kind == token.STRING && strings.Contains(strings.ToLower(v.Value), "into events") {
						t.Errorf("%s:%s (%s) holds raw SQL that inserts into events; only the audit logger and the owned writers may", pf.rel, name, pf.fset.Position(v.Pos()))
					}
				}
				return true
			})
		})
	}

	// A new sqlc statement that inserts into events is a new unmeasured writer.
	queries, err := filepath.Glob(filepath.Join("..", "db", "queries", "*.sql"))
	if err != nil || len(queries) == 0 {
		t.Fatalf("no sqlc query files found (%v); the guard would pass vacuously", err)
	}
	for _, path := range queries {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, block := range strings.Split(string(raw), "-- name: ")[1:] {
			name := strings.Fields(block)[0]
			if strings.Contains(strings.ToLower(block), "insert into events") && name != auditInsertQuery && name != ownedInsertQuery {
				t.Errorf("%s: sqlc statement %s inserts into events. Use audit.Logger, or extend this guard with the reason the new writer measures its own events", filepath.Base(path), name)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// (b) The review-gate classifier runs before the availability branch.
//
// The application session wraps in-transaction errors with
// ErrApplicationSessionV1 and keeps the cause, so a 23514 review-gate refusal
// also matches errors.Is(err, ErrApplicationSessionV1). An error mapping that
// tests the session first answers a permanent refusal with "503 retry later"
// (N2, R4). In any function that contains both, the classifier must come first
// in source order.
// ---------------------------------------------------------------------------

var gateClassifiers = map[string]bool{"Message": false, "sendReviewGateMessageV1": true, "writePDFRevisionDBRefusalV1": true}

func firstGateClassifier(fn *ast.FuncDecl) token.Pos {
	var first token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		hit := false
		if s, ok := c.Fun.(*ast.SelectorExpr); ok {
			if x, ok := s.X.(*ast.Ident); ok && x.Name == "reviewgate" && s.Sel.Name == "Message" {
				hit = true
			}
		}
		if id, ok := c.Fun.(*ast.Ident); ok && gateClassifiers[id.Name] {
			hit = true
		}
		if hit && (first == 0 || c.Pos() < first) {
			first = c.Pos()
		}
		return true
	})
	return first
}

func firstSessionCheck(fn *ast.FuncDecl) token.Pos {
	var first token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || calleeName(c) != "Is" || len(c.Args) != 2 || !isIdentNamed(c.Args[1], "ErrApplicationSessionV1") {
			return true
		}
		if first == 0 || c.Pos() < first {
			first = c.Pos()
		}
		return true
	})
	return first
}

// sessionCheckWithoutGateClassifier lists the functions that test
// ErrApplicationSessionV1 and have no review-gate classifier at all (C4). That
// is the original R4 shape: the gate refusal rides inside the session wrapper
// and is answered "503 retry later". The order check below skips such
// functions, so this list pins the set. A new mapper must classify the gate
// first; do not add to this list. The R4 completion (one reviewgate check
// inside packageauthoring.PublicErrorV1 and mcp.sanitizeToolError) empties it.
var sessionCheckWithoutGateClassifier = map[string]string{
	"internal/handler/blocks.go:mapMutationStatus":                                               unclassifiedMapper,
	"internal/handler/documents.go:handleCreateDocument":                                         unclassifiedMapper,
	"internal/handler/documents_import.go:finishPDFDocumentWithLocaleV1":                         unclassifiedMapper,
	"internal/handler/html_review_owned_v1.go:writeOwnedHTMLReviewErrorV1":                       unclassifiedMapper,
	"internal/handler/pdf_template_owned_lifecycle_v1.go:finishOwnedPDFTemplateFieldsV1":         unclassifiedMapper,
	"internal/handler/recipients.go:writeRecipientMutationError":                                 unclassifiedMapper,
	"internal/pdfadmission/application_signer_failure_diagnostic_v1.go:signerReadFailureClassV1": unclassifiedMapper,
	"internal/pdfadmission/application_signer_scope_diagnostic_v1.go:signerScopeErrorClassV1":    unclassifiedMapper,
	"internal/pdftemplateauthoring/create_v1.go:ordinaryPDFCreateStatementV1":                    unclassifiedMapper,
	"internal/sign/html_ceremony_request_v1.go:htmlCeremonyAdmissionErrorV1":                     unclassifiedMapper,
	"internal/sign/owned_signer_read_v1.go:signerReadErrorV1":                                    unclassifiedMapper,
}

// unclassifiedMapper is the shared reason: the set was pinned by the C4 audit
// finding, and whether the review gate can reach each mapper was not audited.
// Classify the gate first or prove it unreachable, then delete the entry.
const unclassifiedMapper = "pinned by audit finding C4 (2026-11-08); review-gate reachability through this mapper is not audited. Classify the gate before the session check, or prove it unreachable, then delete the entry"

func TestEverySessionCheckMapperClassifiesTheReviewGate(t *testing.T) {
	used := map[string]bool{}
	for _, pf := range moduleFiles(t) {
		if strings.HasSuffix(pf.rel, "_test.go") {
			continue
		}
		funcs(pf, func(name string, fn *ast.FuncDecl) {
			if firstSessionCheck(fn) == 0 || firstGateClassifier(fn) != 0 {
				return
			}
			key := pf.rel + ":" + name
			if reason, ok := sessionCheckWithoutGateClassifier[key]; ok {
				if strings.TrimSpace(reason) == "" {
					t.Errorf("%s: allowlist entry has no reason", key)
				}
				used[key] = true
				return
			}
			t.Errorf("%s tests ErrApplicationSessionV1 but never classifies the review gate (reviewgate.Message, sendReviewGateMessageV1, writePDFRevisionDBRefusalV1); a permanent 409 gate refusal would be answered 503 retry later", key)
		})
	}
	for key := range sessionCheckWithoutGateClassifier {
		if !used[key] {
			t.Errorf("stale allowlist entry %s: remove it", key)
		}
	}
}

func TestReviewGateClassifierPrecedesSessionCheck(t *testing.T) {
	checked := 0
	for _, pf := range moduleFiles(t) {
		if strings.HasSuffix(pf.rel, "_test.go") {
			continue
		}
		funcs(pf, func(name string, fn *ast.FuncDecl) {
			gate, session := firstGateClassifier(fn), firstSessionCheck(fn)
			if gate == 0 || session == 0 {
				return
			}
			checked++
			if session < gate {
				t.Errorf("%s:%s (%s) tests ErrApplicationSessionV1 before the review-gate classifier; a gate refusal would map to 503. Classify the gate first",
					pf.rel, name, pf.fset.Position(session))
			}
		})
	}
	if checked == 0 {
		t.Fatal("no function combines the gate classifier with a session check; the guard no longer sees the real mappings")
	}
}

// ---------------------------------------------------------------------------
// (c) HTML reviews in e2e fixtures go through the human-review helper.
//
// MarkDocumentHTMLReviewed records no document_review_kinds_v1 row, which the
// signing gate (M124) refuses, so a fixture that wants a passing review must
// use markHTMLReviewedHumanE2E (R1: two e2e tests went red). A test that calls
// it directly must be on the list with the reason it needs the bare review.
// ---------------------------------------------------------------------------

const humanReviewHelper = "markHTMLReviewedHumanE2E"

// Keys are "path:Function".
var bareReviewAllowlist = map[string]string{
	"internal/handler/html_template_move_db_e2e_test.go:TestReviewKindGatesSigningSendE2E":                                   "tests the reviewer-kind gate itself, so it inserts the kind rows by hand",
	"internal/handler/html_materialization_foundation_e2e_test.go:TestHTMLMaterializationAppendOnlyCurrentPinsAndHistoryE2E": "grandfathered: materialization history test, never attaches the document under a signing root",
	"internal/handler/html_template_authorization_e2e_test.go:TestHTMLTemplateSchemaImmutabilityAndDocumentReviewE2E":        "grandfathered: exercises review preconditions directly, never attaches the document under a signing root",
	"internal/handler/pdf_member_review_gate_e2e_test.go:TestAgentReviewedHTMLMemberRefusedThroughAttachE2E":                 "tests the member gate itself, so it records an agent kind row by hand and must not get the human one",
}

func TestMarkDocumentHTMLReviewedOnlyInHumanReviewHelper(t *testing.T) {
	used := map[string]bool{}
	for _, pf := range moduleFiles(t) {
		if !strings.HasSuffix(pf.rel, "_e2e_test.go") {
			continue
		}
		funcs(pf, func(name string, fn *ast.FuncDecl) {
			if name == humanReviewHelper || !callsAny(fn, map[string]bool{"MarkDocumentHTMLReviewed": true}) {
				return
			}
			key := pf.rel + ":" + name
			if reason, ok := bareReviewAllowlist[key]; ok {
				if strings.TrimSpace(reason) == "" {
					t.Errorf("%s: allowlist entry has no reason", key)
				}
				used[key] = true
				return
			}
			t.Errorf("%s calls MarkDocumentHTMLReviewed directly. Use %s, which also records the human reviewer kind, or add the test to bareReviewAllowlist with the reason it needs a review without a kind row", key, humanReviewHelper)
		})
	}
	for key := range bareReviewAllowlist {
		if !used[key] {
			t.Errorf("stale allowlist entry %s: remove it", key)
		}
	}
}

// ---------------------------------------------------------------------------
// (d) The DSR transition path has one mapping from a database error to a client
// answer, and nothing writes the retryable 503 or the privacy-contention 409
// around it.
//
// The N2, N3 and R2 audit findings were one defect three times: a call site that
// tested 55P03 (or nothing) by itself missed the deadline and deadlock arms, so
// a lock wait past the transaction deadline answered 409, 500 or a false "not
// found". classifyDSRDBErrorV1 is the one mapping; the two writers it is built
// from are only called from it. A new call site goes through the classifier (or
// authorizeTransactionSessionClassified for a role lock), or, at a COMMIT,
// classifyDSRCommitErrorV1, which itself goes through the classifier.
// ---------------------------------------------------------------------------

const dsrClassifier = "classifyDSRDBErrorV1"

var dsrRawWriters = map[string]bool{"writeDSRRetryableV1": true, "writeDSRPrivacyContentionV1": true}

func TestDSRRetryWritersAreOnlyCalledFromTheClassifier(t *testing.T) {
	classifierCalls := map[string]bool{}
	for _, pf := range moduleFiles(t) {
		if strings.HasSuffix(pf.rel, "_test.go") {
			continue
		}
		funcs(pf, func(name string, fn *ast.FuncDecl) {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok || !dsrRawWriters[calleeName(c)] {
					return true
				}
				if name == dsrClassifier {
					classifierCalls[calleeName(c)] = true
					return true
				}
				t.Errorf("%s:%s calls %s directly. Map the error with %s so the deadline, deadlock and 55P03 arms stay in one place", pf.rel, name, calleeName(c), dsrClassifier)
				return true
			})
		})
	}
	for writer := range dsrRawWriters {
		if !classifierCalls[writer] {
			t.Errorf("%s no longer calls %s; the guard would pass vacuously, update it with the refactor", dsrClassifier, writer)
		}
	}
}

// The classifier above is pinned only where it is called from. A COMMIT has its
// own mapping, because a failed COMMIT may have been applied. handleTransitionDSR
// must map every failed tx.Commit through classifyDSRCommitErrorV1 and never
// through its `fail` closure, which ends in classifyDSRDBErrorV1 and would give a
// retry hint for a deadline after COMMIT was sent (R1). `fail` reaches only the
// shared classifier, never a raw writer, so the guard above cannot see that
// revert. The sibling create and export handlers in the same file keep their own
// unclassified commit handling and are outside rule 4; they must still never
// call `fail`.
const (
	dsrCommitFile       = "internal/handler/dsr.go"
	dsrCommitClassifier = "classifyDSRCommitErrorV1"
	dsrTransitionFunc   = "handleTransitionDSR"
)

func TestDSRTransitionCommitUsesTheCommitClassifier(t *testing.T) {
	branches := 0
	seenFile := false
	for _, pf := range moduleFiles(t) {
		if pf.rel != dsrCommitFile {
			continue
		}
		seenFile = true
		funcs(pf, func(name string, fn *ast.FuncDecl) {
			commitCalls, branchCommits := 0, 0
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.CallExpr:
					if calleeName(v) == "Commit" {
						commitCalls++
					}
				case *ast.IfStmt:
					as, ok := v.Init.(*ast.AssignStmt)
					if !ok || len(as.Rhs) != 1 {
						return true
					}
					c, ok := as.Rhs[0].(*ast.CallExpr)
					if !ok || calleeName(c) != "Commit" {
						return true
					}
					branchCommits++
					calls := map[string]bool{}
					ast.Inspect(v.Body, func(m ast.Node) bool {
						if mc, ok := m.(*ast.CallExpr); ok {
							calls[calleeName(mc)] = true
						}
						return true
					})
					if calls["fail"] || calls[dsrClassifier] {
						t.Errorf("%s:%s maps a failed Commit through fail or %s. A failed COMMIT may have been applied: use %s, which gives a retry hint only when the commit was never sent or the server rolled it back", pf.rel, name, dsrClassifier, dsrCommitClassifier)
					}
					if name == dsrTransitionFunc {
						branches++
						if !calls[dsrCommitClassifier] {
							t.Errorf("%s:%s: the error branch of a Commit does not call %s", pf.rel, name, dsrCommitClassifier)
						}
					}
				}
				return true
			})
			if name == dsrTransitionFunc && commitCalls != branchCommits {
				t.Errorf("%s:%s has %d Commit calls but %d are an `if err := ...Commit(...); err != nil` branch; write each commit in that shape so the guard can see its error branch", pf.rel, name, commitCalls, branchCommits)
			}
		})
	}
	if !seenFile {
		t.Fatalf("%s not found; the guard would pass vacuously, update it with the move", dsrCommitFile)
	}
	if branches == 0 {
		t.Errorf("%s has no Commit error branch; the guard would pass vacuously, update it with the refactor", dsrTransitionFunc)
	}
}
