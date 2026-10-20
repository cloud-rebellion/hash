// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Every participant mutation authenticates once before beginning its
// transaction, then must rebind that evidence to the row-locked sent_at before
// its first state write. This contract test prevents a future refactor from
// silently reopening the lookup-to-lock resend race on one entrypoint.
func TestParticipantMutationsRevalidateNoticeAfterDocumentLock(t *testing.T) {
	raw, err := os.ReadFile("flow.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	tests := []struct {
		method        string
		firstMutation string
		sourceFile    string
		lockRead      string
		delegate      string
	}{
		{method: "Sign", firstMutation: "q.SetRecipientStatus("},
		{method: "Accept", firstMutation: "w.MarkAcknowledgementAcceptedV1(", sourceFile: "acknowledgement_owned_v1.go", lockRead: "w.StateV1(", delegate: "acceptAcknowledgementOwnedV1"},
		{method: "Decline", firstMutation: "q.SetRecipientStatus("},
		{method: "requestChangesLegacyV1", firstMutation: "q.CreateChangeRequest(", lockRead: "q.GetDocumentForUpdate("},
		{method: "RequestChanges", firstMutation: "work.CreateParticipantChangeV1(", sourceFile: "html_ceremony_request_v1.go", lockRead: "work.ReadAccessV1("},
		{method: "mutateCommentOwnedV1", firstMutation: "w.CreateCommentV1(", sourceFile: "comments_owned_v1.go", lockRead: "w.StateV1("},
		{method: "MarkViewed"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if tt.method == "MarkViewed" {
				assertNativeViewedNoticeContractV1(t, source)
				return
			}
			methodSource := source
			if tt.sourceFile != "" {
				actual, err := os.ReadFile(tt.sourceFile)
				if err != nil {
					t.Fatal(err)
				}
				methodSource = string(actual)
			}
			method := tt.method
			if tt.delegate != "" {
				entry := engineMethodSource(t, source, tt.method)
				notice := strings.Index(entry, "validateNoticeEvidence(")
				dispatch := strings.Index(entry, "return e."+tt.delegate+"(")
				if notice < 0 || dispatch <= notice || strings.Contains(entry, "Pool.Begin(") {
					t.Fatal("public participant entry must validate original notice then delegate to the native mutation without pooled fallback")
				}
				method = tt.delegate
			}
			body := engineMethodSource(t, methodSource, method)
			lockRead := tt.lockRead
			if lockRead == "" {
				lockRead = "GetDocumentForUpdate("
			}
			lock := strings.Index(body, lockRead)
			revalidate := strings.Index(body, "ValidateLockedNoticeEvidence(")
			mutation := strings.Index(body, tt.firstMutation)
			if lock < 0 || revalidate <= lock || mutation <= revalidate {
				t.Fatalf("lock/revalidation/mutation order is unsafe: lock=%d revalidate=%d mutation=%d", lock, revalidate, mutation)
			}
		})
	}
}

func assertNativeViewedNoticeContractV1(t *testing.T, source string) {
	t.Helper()
	entry, err := parser.ParseFile(token.NewFileSet(), "entry.go", "package sign\n"+engineMethodSource(t, source, "MarkViewed"), 0)
	if err != nil {
		t.Fatal(err)
	}
	fn := entry.Decls[0].(*ast.FuncDecl)
	if len(fn.Body.List) != 1 {
		t.Fatal("view entry must delegate only to the native operation")
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		t.Fatal("view entry must return its native result")
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok || viewedNoticeCallNameV1(call) != "markViewedOwnedV1" || len(call.Args) != 3 {
		t.Fatal("view entry must retain the native view delegate")
	}
	raw, err := os.ReadFile("view_owned_v1.go")
	if err != nil {
		t.Fatal(err)
	}
	owned := engineMethodSource(t, string(raw), "markViewedOwnedV1")
	if notice, operation := strings.Index(owned, "validateNoticeEvidence("), strings.Index(owned, "NewHTMLSendOperationV1("); notice < 0 || operation <= notice || strings.Contains(owned, "Pool.Begin(") {
		t.Fatal("native view must validate original notice before opening its actual operation")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "owned.go", "package sign\n"+owned, 0)
	if err != nil {
		t.Fatal(err)
	}
	native := file.Decls[0].(*ast.FuncDecl)
	var callback *ast.BlockStmt
	for _, stmt := range native.Body.List {
		assignment, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assignment.Rhs) != 1 {
			continue
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok || viewedNoticeCallNameV1(call) != "WithTxV1" || len(call.Args) != 1 {
			continue
		}
		literal, ok := call.Args[0].(*ast.FuncLit)
		if !ok || callback != nil {
			t.Fatal("view must use one actual native transaction callback")
		}
		callback = literal.Body
	}
	if !viewedNoticeGuardBeforeWriteV1(callback) {
		t.Fatal("native view must lock, load and return a failed locked notice before its actual write")
	}
}

func viewedNoticeCallNameV1(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// Inspect direct callback statements, so an unreachable/nested marker cannot
// satisfy the notice guard that must dominate the actual mutation.
func viewedNoticeGuardBeforeWriteV1(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	lock, models, notice, write := -1, -1, -1, -1
	for i, stmt := range body.List {
		var rhs ast.Expr
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 {
				rhs = s.Rhs[0]
			}
		case *ast.IfStmt:
			if assignment, ok := s.Init.(*ast.AssignStmt); ok && len(assignment.Rhs) == 1 {
				rhs = assignment.Rhs[0]
			}
		}
		call, ok := rhs.(*ast.CallExpr)
		if !ok {
			continue
		}
		switch viewedNoticeCallNameV1(call) {
		case "StateV1":
			lock = i
		case "ReadModelsV1":
			models = i
		case "MarkSignerViewedV1":
			write = i
		case "ValidateLockedNoticeEvidence":
			guard, ok := stmt.(*ast.IfStmt)
			if !ok || guard.Else != nil || len(guard.Body.List) != 1 {
				continue
			}
			assignment, ok := guard.Init.(*ast.AssignStmt)
			condition, conditionOK := guard.Cond.(*ast.BinaryExpr)
			returned, returnOK := guard.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(assignment.Lhs) != 1 || !conditionOK || condition.Op != token.NEQ || !returnOK || len(returned.Results) != 1 {
				continue
			}
			bound, boundOK := assignment.Lhs[0].(*ast.Ident)
			left, leftOK := condition.X.(*ast.Ident)
			right, rightOK := condition.Y.(*ast.Ident)
			result, resultOK := returned.Results[0].(*ast.Ident)
			if boundOK && leftOK && rightOK && resultOK && bound.Name == "err" && left.Name == "err" && right.Name == "nil" && result.Name == "err" {
				notice = i
			}
		}
	}
	return lock >= 0 && models > lock && notice > models && write > notice
}

func TestNativeViewedNoticeOracleRejectsInertAndUncheckedGuardsV1(t *testing.T) {
	valid := "if _,err=StateV1();err!=nil{return err};models,err:=ReadModelsV1();if err=ValidateLockedNoticeEvidence();err!=nil{return err};if err=MarkSignerViewedV1();err!=nil{return err}"
	for _, body := range []string{
		valid,
		strings.Replace(valid, "{return err};if err=Mark", "{};if err=Mark", 1),
		strings.Replace(valid, "Evidence();err!=nil{return err}", "Evidence();err!=nil{return nil}", 1),
		strings.Replace(valid, "Evidence();err!=nil", "Evidence();err==nil", 1),
		strings.Replace(valid, "if err=ValidateLockedNoticeEvidence();err!=nil{return err}", "if false {if err=ValidateLockedNoticeEvidence();err!=nil{return err}}", 1),
		strings.Replace(valid, "if err=ValidateLockedNoticeEvidence();err!=nil{return err}", "ValidateLockedNoticeEvidence()", 1),
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "negative.go", "package p;func f(){"+body+"}", 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := viewedNoticeGuardBeforeWriteV1(file.Decls[0].(*ast.FuncDecl).Body); got != (body == valid) {
			t.Fatal("view notice oracle accepted an inert or unchecked guard", body)
		}
	}
}

func engineMethodSource(t *testing.T, source, method string) string {
	t.Helper()
	startMarker := "func (e *Engine) " + method + "("
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("missing Engine.%s", method)
	}
	rest := source[start+len(startMarker):]
	end := strings.Index(rest, "\nfunc ")
	if end < 0 {
		return source[start:]
	}
	return source[start : start+len(startMarker)+end]
}

func TestNativeCommentNoticeBeforeOperationAndFinalCommitV1(t *testing.T) {
	raw, err := os.ReadFile("comments_owned_v1.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	body := engineMethodSource(t, source, "mutateCommentOwnedV1")
	notice, operation := strings.Index(body, "validateNoticeEvidence("), strings.Index(body, "NewOperationV1(")
	audit, final, commit := strings.Index(body, "ownedaudit.LogV1("), strings.LastIndex(body, "ValidateLockedNoticeEvidence("), strings.Index(body, "session.CommitV1(")
	if notice < 0 || operation <= notice || audit < 0 || final <= audit || commit <= final || strings.Contains(body, "Pool.Begin(") || strings.Contains(body, "Audit.LogTx(") {
		t.Fatal("native comment notice/measurement/final-commit gates changed")
	}
	entry := engineMethodSource(t, source, "SignerCommentOwnedV1")
	if !strings.Contains(entry, "borrowOriginalV1(") || !strings.Contains(entry, "NewSignerCommentRequestV1(") || !strings.Contains(entry, "mutateCommentOwnedV1(") {
		t.Fatal("public comments lost genuine original-reader/request lineage")
	}
}
