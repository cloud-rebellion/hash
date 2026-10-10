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
		"fields.go":  {"handleSignerSubmitFields"},
		"ai_apps.go": {"handleSignerClarify"},
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
	handlerRaw, err := os.ReadFile("ai_apps.go")
	if err != nil {
		t.Fatal(err)
	}
	helperRaw, err := os.ReadFile("signer_ai.go")
	if err != nil {
		t.Fatal(err)
	}
	handler := string(handlerRaw)
	handlerStart := strings.Index(handler, "func (s *Server) handleSignerClarify")
	handlerEnd := strings.Index(handler, "func lookupBlockWithNeighbours")
	if handlerStart < 0 || handlerEnd <= handlerStart {
		t.Fatal("missing signer clarification endpoint")
	}
	handler = handler[handlerStart:handlerEnd]
	notice := strings.Index(handler, "requireSignerNoticeAcknowledgement(")
	guardedCall := strings.Index(handler, "s.completeSignerClarifier(")
	if notice < 0 || guardedCall <= notice {
		t.Fatal("clarifier bypasses recipient Article13 admission")
	}
	helper := string(helperRaw)
	guardLock := strings.Index(helper, "GetDocumentForShare(")
	recipientLock := strings.Index(helper, "GetRecipientForShare(")
	originalCredential := strings.Index(helper, "sign.ValidateLockedRecipientCredential(")
	lockedNotice := strings.Index(helper, "sign.ValidateLockedNoticeEvidence(")
	if guardLock < 0 || recipientLock <= guardLock || originalCredential < 0 || lockedNotice <= originalCredential {
		t.Fatal("clarifier lacks parent-first retained recipient credential and notice guard")
	}
	start := strings.Index(helper, "func (s *Server) completeSignerClarifier(")
	if start < 0 {
		t.Fatal("missing guarded signer provider protocol")
	}
	source := helper[start:]
	requestGuard := strings.Index(source, "lockSignerClarifier(ctx, requestTx,")
	requestAudit := strings.Index(source, `Kind: "ai.requested"`)
	requestCommit := strings.Index(source, "requestTx.Commit(ctx)")
	dispatchGuard := strings.Index(source, "lockSignerClarifier(ctx, tx,")
	externalCall := strings.Index(source, "}).Clarify(ctx,")
	answerAudit := strings.Index(source, `Kind: "clarifier.answered"`)
	finalCheck := strings.LastIndex(source, "guard.recheck(ctx)")
	finalCommit := strings.Index(source, "tx.Commit(ctx)")
	if requestGuard < 0 || requestAudit <= requestGuard || requestCommit <= requestAudit ||
		dispatchGuard <= requestCommit || externalCall <= dispatchGuard || answerAudit <= externalCall ||
		finalCheck <= answerAudit || finalCommit <= finalCheck {
		t.Fatalf("clarifier durable-request/dispatch/result order unsafe: %d/%d/%d/%d/%d/%d/%d/%d", requestGuard, requestAudit, requestCommit, dispatchGuard, externalCall, answerAudit, finalCheck, finalCommit)
	}
	if !strings.Contains(source, "context.WithTimeout(r.Context(), signerClarifierTimeout)") ||
		!strings.Contains(source, "authoring.ReserveAIAccounting(") ||
		!strings.Contains(source, "InsertRequestedSignerAICompletionAudit(") ||
		strings.Contains(source, "_, _ = s.Audit.Log") {
		t.Fatal("clarifier lacks bounded processing or required reserved accounting")
	}
}

func TestSignerFieldSubmissionRevalidatesNoticeAfterDocumentLock(t *testing.T) {
	raw, err := os.ReadFile("fields.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "func (s *Server) handleSignerSubmitFields")
	end := strings.Index(source, "func recipientCanFillFields")
	if start < 0 || end <= start {
		t.Fatal("could not isolate handleSignerSubmitFields source")
	}
	body := source[start:end]
	rowLock := strings.Index(body, "GetDocumentForUpdate(")
	revalidate := strings.Index(body, "sign.ValidateLockedNoticeEvidence(")
	mutation := strings.Index(body, "q.UpdateFieldValue(")
	if rowLock < 0 || revalidate <= rowLock || mutation <= revalidate {
		t.Fatalf("field lock/revalidation/mutation order is unsafe: lock=%d revalidate=%d mutation=%d", rowLock, revalidate, mutation)
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
