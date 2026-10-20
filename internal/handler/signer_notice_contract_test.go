// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// This contract test keeps every magic-link mutation that is visually behind
// the Article 13 gate from silently losing the server-side precondition when a
// handler is refactored. The DSR endpoint is intentionally excluded: exercising
// data-subject rights is available inside the notice before acknowledgement.
func TestSignerMutationHandlersEnforceCurrentNotice(t *testing.T) {
	files := map[string][]string{
		"sign.go": {
			"handleSignerView", "handleSignerSign", "handleSignerAccept",
			"handleSignerDecline", "handleSignerRequestChanges", "handleSignerCreateComment",
		},
		"signer_fields_owned_v1.go": {"handleSignerSubmitFieldsOwnedV1"},
		"ai_apps.go":                {"handleSignerClarify"},
	}
	for filename, functions := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, function := range functions {
			decl := findFunction(parsed, function)
			if decl == nil {
				t.Fatalf("%s: missing %s", filename, function)
			}
			if !callsFunction(decl.Body, "requireSignerNoticeAcknowledgement") {
				t.Errorf("%s: %s does not enforce the current Article 13 notice", filename, function)
			}
		}
	}
}

func TestSignerClarifierAuditsBeforeExternalProcessingAndChecksResultAudit(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	handler := read("ai_apps.go")
	start := strings.Index(handler, "func (s *Server) handleSignerClarify")
	end := strings.Index(handler, "func lookupBlockWithNeighbours")
	if start < 0 || end <= start {
		t.Fatal("missing signer clarification endpoint")
	}
	handler = handler[start:end]
	ordered := func(source string, names ...string) bool {
		offset := 0
		for _, name := range names {
			index := strings.Index(source[offset:], name)
			if index < 0 {
				return false
			}
			offset += index + len(name)
		}
		return true
	}
	if !ordered(handler, "requireSignerNoticeAcknowledgement(", "NewSignerAIRequestV1(", "owned.WithBodyV1(", "decodeSignerJSON(", "owned.CaptureInputV1(", "s.completeSignerClarifier(", "res.WithValueV1(") {
		t.Fatal("clarifier bypasses recipient Article13 admission")
	}
	bridge := read("../sign/ai_request_owned_v1.go")
	if !ordered(bridge, "borrowOriginalV1(", "validateNoticeEvidence(", "originalLiveV1(", "NewSignerAIRequestV1(") || !ordered(bridge, "ValidateLockedRecipientCredential(", "ValidateLockedNoticeEvidence(") {
		t.Fatal("clarifier lacks parent-first retained recipient credential and notice guard")
	}
	source := read("../aiauthoring/signer_clarifier_v1.go")
	if !ordered(source, "ReserveDocumentAIAccountingV1(", "lockSignerPhaseV1(call, requested", "LogSignerAIRequestV1(d.Audit, call, requested.work, true)", "LogSignerAIRequestV1(d.Audit, call, requested.work, false)", "requested.session.CommitV1(", "CommittedRequestV1(", "lockSignerPhaseV1(call, dispatch", "NewRuntimeV1(", "BeginWorkflowV1(", "}).Clarify(", "request.RecheckV1(owned", "LogSignerAIAnswerV1(", "CheckSignerCredentialV1(owned)", "dispatch.session.CommitV1(") {
		t.Fatal("clarifier durable-request/dispatch/result order unsafe")
	}
	helper := read("signer_ai.go")
	if !strings.Contains(handler, "context.WithTimeout(r.Context(), signerClarifierTimeout)") || !strings.Contains(helper, "aiauthoring.CompleteSignerClarifierV1(") || strings.Contains(helper, "Audit.LogTx(") {
		t.Fatal("clarifier lacks bounded processing or required reserved accounting")
	}
	cost := read("../pdfadmission/application_document_ai_accounting_v1.go")
	if !strings.Contains(cost, "PersistSignerAIUsageV1(") || !ordered(source, "accounting.ObserveUsageV1(", "accounting.PersistUsageV1(", "CostContextV1(", "NewDocumentAICostV1(", "ReadUsageV1(", "LogSignerAICostV1(", "cost.session.CommitV1(") {
		t.Fatal("clarifier lacks bounded processing or required reserved accounting")
	}
}

func TestSignerFieldSubmissionRevalidatesNoticeAfterDocumentLock(t *testing.T) {
	readFunction := func(path, name string) *ast.FuncDecl {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		fn := findFunction(file, name)
		if fn == nil {
			t.Fatalf("missing real field policy function %s:%s", path, name)
		}
		return fn
	}
	wrapper := readFunction("fields.go", "handleSignerSubmitFields")
	if len(wrapper.Body.List) != 1 || !callsFunction(wrapper.Body, "handleSignerSubmitFieldsOwnedV1") {
		t.Fatal("public field route no longer delegates to the guarded native handler")
	}
	handler := readFunction("signer_fields_owned_v1.go", "handleSignerSubmitFieldsOwnedV1")
	if !signerContractCallsInOrderV1(handler, "requireSignerNoticeAcknowledgement", "NewSignerFieldsRequestV1", "decodeSignerJSON", "WithSignerFieldsMutationV1", "ValidateLockedNoticeEvidence", "UpdateSignerFieldValueV1") {
		t.Fatal("field notice/capture/locked-revalidation/write order is unsafe")
	}
	callback := signerContractDirectCallbackV1(handler.Body, "WithSignerFieldsMutationV1")
	if !signerContractNoticeGuardBeforeWriteV1(callback, "ValidateLockedNoticeEvidence", "signerFieldsResponseV1", "UpdateSignerFieldValueV1") {
		t.Fatal("actual field mutation callback must return the locked notice failure before any update")
	}
	native := readFunction("../sign/fields_owned_v1.go", "WithSignerFieldsMutationV1")
	if !signerContractCallsInOrderV1(native, "WithTxV1", "StateV1", "ReadModelsV1", "BeginSignerFieldsMutationV1", "mutate", "SignerFieldsWritesCompleteV1", "CommitV1") {
		t.Fatal("native field callback can precede its actual parent lock or commit before complete writes")
	}
	state := readFunction("../pdfadmission/application_html_send_work_v1.go", "StateV1")
	if !callsFunction(state.Body, "GetHTMLSendDocumentStateHeaderV1") {
		t.Fatal("native State no longer obtains its real scoped parent header lock")
	}
	raw, err := os.ReadFile("../db/queries/html_send_read_sizes.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	start := strings.Index(sql, "-- name: GetHTMLSendDocumentStateHeaderV1 :one")
	if start < 0 {
		t.Fatal("native parent-lock query missing")
	}
	query := sql[start:]
	if end := strings.Index(query[1:], "-- name:"); end >= 0 {
		query = query[:end+1]
	}
	if !strings.Contains(query, "d.id=sqlc.arg(document_id)::uuid") || !strings.Contains(query, "d.org_id=sqlc.arg(org_id)::uuid") || !strings.Contains(query, "FOR UPDATE OF d") {
		t.Fatal("native field parent lock lost exact document/org/update scope")
	}
	mutation := readFunction("../pdfadmission/application_signer_fields_results_v1.go", "UpdateSignerFieldValueV1")
	if !callsFunction(mutation.Body, "UpdateFieldValue") {
		t.Fatal("owned field mutation no longer reaches the guarded actual SQL writer")
	}
}

func signerContractDirectCallbackV1(body *ast.BlockStmt, method string) *ast.BlockStmt {
	var result *ast.BlockStmt
	for _, stmt := range body.List {
		assignment, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assignment.Rhs) != 1 {
			continue
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok || !signerContractNamedCallV1(call, method) {
			continue
		}
		for _, arg := range call.Args {
			if callback, ok := arg.(*ast.FuncLit); ok {
				if result != nil {
					return nil
				}
				result = callback.Body
			}
		}
	}
	return result
}

func signerContractNamedCallV1(call *ast.CallExpr, name string) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == name
	case *ast.SelectorExpr:
		return fn.Sel.Name == name
	}
	return false
}

func signerContractNoticeGuardBeforeWriteV1(body *ast.BlockStmt, noticeName, denyName, writeName string) bool {
	if body == nil {
		return false
	}
	guardIndex, writeIndex := -1, -1
	for i, stmt := range body.List {
		// Calls in an unrelated function literal do not execute at this point.
		ast.Inspect(stmt, func(node ast.Node) bool {
			if _, ok := node.(*ast.FuncLit); ok {
				return false
			}
			if call, ok := node.(*ast.CallExpr); ok && signerContractNamedCallV1(call, writeName) && writeIndex < 0 {
				writeIndex = i
			}
			return true
		})
		guard, ok := stmt.(*ast.IfStmt)
		if !ok || guard.Else != nil || len(guard.Body.List) != 1 {
			continue
		}
		assignment, ok := guard.Init.(*ast.AssignStmt)
		condition, conditionOK := guard.Cond.(*ast.BinaryExpr)
		returned, returnOK := guard.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || !conditionOK || condition.Op != token.NEQ || !returnOK || len(returned.Results) != 1 {
			continue
		}
		bound, boundOK := assignment.Lhs[0].(*ast.Ident)
		call, callOK := assignment.Rhs[0].(*ast.CallExpr)
		left, leftOK := condition.X.(*ast.Ident)
		right, rightOK := condition.Y.(*ast.Ident)
		denial, denialOK := returned.Results[0].(*ast.CallExpr)
		if boundOK && callOK && leftOK && rightOK && denialOK && bound.Name == "err" && left.Name == "err" && right.Name == "nil" && signerContractNamedCallV1(call, noticeName) && signerContractNamedCallV1(denial, denyName) {
			guardIndex = i
		}
	}
	return guardIndex >= 0 && writeIndex > guardIndex
}

func signerContractCallsInOrderV1(fn *ast.FuncDecl, names ...string) bool {
	previous := token.NoPos
	for _, name := range names {
		position := token.NoPos
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			match := false
			switch f := call.Fun.(type) {
			case *ast.Ident:
				match = f.Name == name
			case *ast.SelectorExpr:
				match = f.Sel.Name == name
			}
			if match && (position == token.NoPos || call.Pos() < position) {
				position = call.Pos()
			}
			return true
		})
		if position == token.NoPos || position <= previous {
			return false
		}
		previous = position
	}
	return true
}

func TestSignerNativePolicyOrderOracleRejectsMissingAndReorderedGatesV1(t *testing.T) {
	for _, body := range []string{"lock();notice();write()", "notice();lock();write()", "lock();write();notice()", "lock();write()"} {
		file, err := parser.ParseFile(token.NewFileSet(), "negative.go", "package p;func f(){"+body+"}", 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := signerContractCallsInOrderV1(findFunction(file, "f"), "lock", "notice", "write"); got != (body == "lock();notice();write()") {
			t.Fatal("native policy-order oracle accepted a missing/reordered gate", body)
		}
	}
	valid := "if err:=notice();err!=nil{return deny()};for range values {write()}"
	for _, body := range []string{
		valid,
		strings.Replace(valid, "return deny()", "", 1),
		strings.Replace(valid, "return deny()", "return nil", 1),
		strings.Replace(valid, "err!=nil", "err==nil", 1),
		"if false {if err:=notice();err!=nil{return deny()}};for range values {write()}",
		"for range values {write()};if err:=notice();err!=nil{return deny()}",
		"unused:=func(){if err:=notice();err!=nil{return deny()}};for range values {write()}",
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "negative.go", "package p;func f(){"+body+"}", 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := signerContractNoticeGuardBeforeWriteV1(findFunction(file, "f").Body, "notice", "deny", "write"); got != (body == valid) {
			t.Fatal("native notice oracle accepted an unchecked, unreachable or late guard", body)
		}
	}
}

func findFunction(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

func callsFunction(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			found = found || fun.Name == name
		case *ast.SelectorExpr:
			found = found || fun.Sel.Name == name
		}
		return !found
	})
	return found
}
