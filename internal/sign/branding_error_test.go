// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestRenderForSignerFailsClosedOnBrandingLookupFailure(t *testing.T) {
	sentinel := errors.New("frozen branding lookup failed")
	calls := 0
	engine := &Engine{BrandingCSS: func(context.Context, *generated.Document) (string, error) {
		calls++
		return "", sentinel
	}}
	rc := &RecipientContext{
		Document: &generated.Document{
			ID:            uuid.New(),
			SourceKind:    "blocks",
			BlocksJson:    []byte(`{"version":1,"blocks":[]}`),
			VariablesJson: []byte(`{}`),
		},
		Recipient: &generated.GetRecipientByTokenHashRow{Locale: "en"},
	}

	html, err := engine.RenderForSigner(context.Background(), rc)
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "resolve branding") {
		t.Fatalf("RenderForSigner error = %v, want wrapped branding failure", err)
	}
	if html != "" {
		t.Fatalf("RenderForSigner returned HTML after branding failure: %q", html)
	}
	if calls != 1 {
		t.Fatalf("branding resolver calls = %d, want 1", calls)
	}
}

func TestFinalizationResolvesBrandingBeforeRenderingOrStorage(t *testing.T) {
	raw, err := os.ReadFile("flow.go")
	if err != nil {
		t.Fatal(err)
	}
	assertBrandingGateBefore(t, string(raw), "completeAcknowledgedDocument",
		"e.prepareOrdinaryHistoricalFinalizationV1",
	)
	assertBrandingGateBefore(t, string(raw), "finalize",
		"sourceOwner.ensureEnvelopeChildrenEvidenceVersionsV1", "sourceOwner.terminalManifestV1",
		"e.prepareOrdinaryHistoricalFinalizationV1",
	)
}

func assertBrandingGateBefore(t *testing.T, source, function string, requiredEffects ...string) {
	t.Helper()
	if err := checkFinalizationBrandingGateForTestV1(source, function, requiredEffects...); err != nil {
		t.Fatal(err)
	}
}

// This is a syntax/order assertion only. It grants no SQL or rendering authority.
// M109 freezes the exact HTML before provider effects. New/pre-freeze work must
// resolve actual native frozen branding and return its failure; recovery after
// that durable freeze must use the original HTML without resolving new CSS.
// Actual PostgreSQL/native preparation recovery remains a separate E2E check.
func checkFinalizationBrandingGateForTestV1(source, function string, requiredEffects ...string) error {
	message := "finalize acknowledgement: resolve branding: %w"
	if function == "finalize" {
		message = "finalize document: resolve branding: %w"
	} else if function != "completeAcknowledgedDocument" {
		return fmt.Errorf("unexpected finalization function %q", function)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "flow.go", source, 0)
	if err != nil {
		return err
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		candidate, ok := decl.(*ast.FuncDecl)
		if !ok || candidate.Name.Name != function || candidate.Recv == nil || len(candidate.Recv.List) != 1 {
			continue
		}
		pointer, ok := candidate.Recv.List[0].Type.(*ast.StarExpr)
		if !ok || brandingGateCallNameForTestV1(pointer.X) != "Engine" {
			continue
		}
		if fn != nil {
			return fmt.Errorf("duplicate Engine.%s", function)
		}
		fn = candidate
	}
	if fn == nil || fn.Body == nil {
		return fmt.Errorf("missing Engine.%s", function)
	}
	lookupIndex, gateIndex := -1, -1
	var gate *ast.IfStmt
	for i, stmt := range fn.Body.List {
		if assignment, ok := stmt.(*ast.AssignStmt); ok && len(assignment.Rhs) == 1 {
			call, ok := assignment.Rhs[0].(*ast.CallExpr)
			if ok && brandingGateCallNameForTestV1(call.Fun) == "e.ordinaryCertificateInputFrozenV1" {
				if lookupIndex != -1 || len(assignment.Lhs) != 2 || brandingGateCallNameForTestV1(assignment.Lhs[0]) != "frozenCertificate" || brandingGateCallNameForTestV1(assignment.Lhs[1]) != "err" {
					return fmt.Errorf("ambiguous frozen input lookup in %s", function)
				}
				lookupIndex = i
			}
		}
		candidate, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		condition, ok := candidate.Cond.(*ast.UnaryExpr)
		if !ok || condition.Op != token.NOT || brandingGateCallNameForTestV1(condition.X) != "frozenCertificate" {
			continue
		}
		if gate != nil || candidate.Init != nil || candidate.Else != nil || len(candidate.Body.List) != 2 {
			return fmt.Errorf("ambiguous fresh branding gate in %s", function)
		}
		gateIndex, gate = i, candidate
	}
	if lookupIndex < 0 || lookupIndex+2 != gateIndex || gate == nil {
		return fmt.Errorf("missing frozen-input lookup/error gate before fresh branding in %s", function)
	}
	if err := checkBrandingErrorReturnForTestV1(fn.Body.List[lookupIndex+1], "", function); err != nil {
		return err
	}
	assignment, ok := gate.Body.List[0].(*ast.AssignStmt)
	if !ok || len(assignment.Rhs) != 1 || len(assignment.Lhs) != 2 || brandingGateCallNameForTestV1(assignment.Lhs[1]) != "err" {
		return fmt.Errorf("missing fresh branding assignment in %s", function)
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok || brandingGateCallNameForTestV1(call.Fun) != "e.resolveBrandingCSSForFinalizationOwnedV1" {
		return fmt.Errorf("missing native fresh branding resolver in %s", function)
	}
	if err := checkBrandingErrorReturnForTestV1(gate.Body.List[1], message, function); err != nil {
		return err
	}
	seen := make(map[string]bool, len(requiredEffects)+16)
	for _, effect := range requiredEffects {
		seen[effect] = false
	}
	// The common adapter now owns these former flow-local effects. If any direct
	// effect reappears, it must still follow the complete fresh branding gate.
	for _, effect := range []string{
		"sourceOwner.source.WithAcknowledgementFinalPDFV1", "final.CalculateSHA256V1", "final.StoreFinalV1",
		"e.loadHistoricalCertificateSnapshotOwnedV1", "certificateData.snapshot.PrepareClaimsV1",
		"sourceOwner.prepareAuditCertificateV1", "certificate.RenderAndStoreV1",
		"sourceOwner.renderFinalBlocksPDFV1", "sourceOwner.stampManualPDFV1",
		"e.Storage.PutEvidenceVersioned", "e.PDF.HTMLToPDF",
	} {
		seen[effect] = false
	}
	lookupCalls, resolverCalls, preparationCalls := 0, 0, 0
	var orderError error
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := brandingGateCallNameForTestV1(call.Fun)
		switch name {
		case "e.ordinaryCertificateInputFrozenV1":
			lookupCalls++
		case "e.resolveBrandingCSSForFinalizationOwnedV1":
			resolverCalls++
		case "e.prepareOrdinaryHistoricalFinalizationV1":
			preparationCalls++
		}
		if _, tracked := seen[name]; tracked {
			seen[name] = true
			if call.Pos() < gate.End() {
				orderError = fmt.Errorf("fresh branding gate must precede %q in %s", name, function)
			}
		}
		return true
	})
	if orderError != nil {
		return orderError
	}
	if lookupCalls != 1 || resolverCalls != 1 || preparationCalls != 1 {
		return fmt.Errorf("frozen lookup, fresh resolver and preparation must each occur once in %s", function)
	}
	// Frozen recovery must enter the same durable adapter too. Requiring this
	// call as a top-level statement rejects accidentally placing all work inside
	// the fresh-only branch or silently skipping a failed branding-state lookup.
	preparationTopLevel := false
	for i, stmt := range fn.Body.List {
		assignment, ok := stmt.(*ast.AssignStmt)
		if !ok || i <= gateIndex || len(assignment.Rhs) != 1 {
			continue
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if ok && brandingGateCallNameForTestV1(call.Fun) == "e.prepareOrdinaryHistoricalFinalizationV1" {
			preparationTopLevel = true
		}
	}
	if !preparationTopLevel {
		return fmt.Errorf("fresh and frozen work must both enter durable preparation in %s", function)
	}
	for _, effect := range requiredEffects {
		if !seen[effect] {
			return fmt.Errorf("missing real effect entry %q in %s", effect, function)
		}
	}
	return nil
}

func checkBrandingErrorReturnForTestV1(statement ast.Stmt, message, function string) error {
	guard, ok := statement.(*ast.IfStmt)
	if !ok || guard.Init != nil || guard.Else != nil || len(guard.Body.List) != 1 {
		return fmt.Errorf("branding error must return immediately in %s", function)
	}
	condition, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || condition.Op != token.NEQ || brandingGateCallNameForTestV1(condition.X) != "err" || brandingGateCallNameForTestV1(condition.Y) != "nil" {
		return fmt.Errorf("branding error condition differs in %s", function)
	}
	returned, ok := guard.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) == 0 {
		return fmt.Errorf("branding error return missing in %s", function)
	}
	if message == "" {
		if brandingGateCallNameForTestV1(returned.Results[len(returned.Results)-1]) != "err" {
			return fmt.Errorf("frozen-input lookup error must be returned in %s", function)
		}
		return nil
	}
	wrapped, ok := returned.Results[len(returned.Results)-1].(*ast.CallExpr)
	if !ok || brandingGateCallNameForTestV1(wrapped.Fun) != "fmt.Errorf" || len(wrapped.Args) != 2 || brandingGateCallNameForTestV1(wrapped.Args[1]) != "err" {
		return fmt.Errorf("branding error must stay wrapped in %s", function)
	}
	literal, ok := wrapped.Args[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return fmt.Errorf("branding error context missing in %s", function)
	}
	text, err := strconv.Unquote(literal.Value)
	if err != nil || text != message {
		return fmt.Errorf("branding error context/wrapping differs in %s", function)
	}
	return nil
}

func brandingGateCallNameForTestV1(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		if parent := brandingGateCallNameForTestV1(value.X); parent != "" {
			return parent + "." + value.Sel.Name
		}
	}
	return ""
}

func TestFinalizationBrandingGateAssertionRejectsBypasses(t *testing.T) {
	const prefix = "package sign\nfunc (e *Engine) completeAcknowledgedDocument() error {\n"
	const suffix = "return nil\n}\n"
	const lookup = "frozenCertificate, err := e.ordinaryCertificateInputFrozenV1()\nif err != nil { return err }\n"
	const resolver = "_, err = e.resolveBrandingCSSForFinalizationOwnedV1()\nif err != nil { return fmt.Errorf(\"finalize acknowledgement: resolve branding: %w\", err) }\n"
	const gate = lookup + "if !frozenCertificate {\n" + resolver + "}\n"
	const effects = "retired, err := e.prepareOrdinaryHistoricalFinalizationV1()\n"
	check := func(source string) error {
		return checkFinalizationBrandingGateForTestV1(source, "completeAcknowledgedDocument",
			"e.prepareOrdinaryHistoricalFinalizationV1")
	}
	for _, assignment := range []string{gate, strings.Replace(gate, "_, err =", "brandCSS, err :=", 1)} {
		if err := check(prefix + assignment + effects + suffix); err != nil {
			t.Fatal("valid native/old assignment rejected", err)
		}
	}
	cases := []struct{ name, body string }{
		{"gate_removed", effects},
		{"gate_moved_after_effects", effects + gate},
		{"frozen_lookup_removed", strings.TrimPrefix(gate, lookup) + effects},
		{"frozen_lookup_error_swallowed", strings.Replace(gate, "if err != nil { return err }", "if err != nil { return nil }", 1) + effects},
		{"frozen_lookup_error_guard_removed", strings.Replace(gate, "if err != nil { return err }\n", "", 1) + effects},
		{"frozen_resolves_branding", strings.Replace(gate, "if !frozenCertificate", "if frozenCertificate", 1) + effects},
		{"frozen_else_resolves_branding", strings.TrimSuffix(gate, "}\n") + "} else {\n" + resolver + "}\n" + effects},
		{"extra_resolver_after_gate", gate + resolver + effects},
		{"error_return_removed", strings.Replace(gate, "return fmt.Errorf(\"finalize acknowledgement: resolve branding: %w\", err)", "", 1) + effects},
		{"error_swallowed", strings.Replace(gate, "return fmt.Errorf(\"finalize acknowledgement: resolve branding: %w\", err)", "return nil", 1) + effects},
		{"error_unwrapped", strings.Replace(gate, ": %w", ": %v", 1) + effects},
		{"wrong_error_condition", strings.Replace(gate, "err != nil", "err == nil", 1) + effects},
		{"old_storage_bypass", "e.Storage.PutEvidenceVersioned()\n" + gate + effects},
		{"old_renderer_bypass", "e.PDF.HTMLToPDF()\n" + gate + effects},
		{"old_native_storage_bypass", "final.StoreFinalV1()\n" + gate + effects},
		{"old_native_renderer_bypass", "sourceOwner.renderFinalBlocksPDFV1()\n" + gate + effects},
		{"preparation_only_fresh", strings.TrimSuffix(gate, "}\n") + effects + "}\n"},
		{"preparation_only_frozen", gate + "if frozenCertificate {\n" + effects + "}\n"},
		{"missing_real_effect", gate},
		{"comment_is_not_gate", "// e.resolveBrandingCSSForFinalizationOwnedV1()\n" + effects},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := check(prefix + tc.body + suffix); err == nil {
				t.Fatal("branding assertion accepted bypass")
			}
		})
	}
}
