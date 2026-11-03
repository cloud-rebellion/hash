// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package pdfadmission

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func serviceEmailNativeFunctionV1(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("missing actual native function %s", name)
	return nil
}
func serviceEmailNativeCallPositionsV1(fn *ast.FuncDecl, name string) []token.Pos {
	var out []token.Pos
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if c, ok := node.(*ast.CallExpr); ok {
			if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == name {
				out = append(out, c.Pos())
			} else if id, ok := c.Fun.(*ast.Ident); ok && id.Name == name {
				out = append(out, c.Pos())
			}
		}
		return true
	})
	return out
}

func TestServiceEmailNativeScalarAndBodyReadsFollowOwnedLoansV1(t *testing.T) {
	for _, tc := range []struct{ fn, grant string }{{"serviceEmailTemplateV1", "acquireOwnedRetainedBodyV1"}, {"changeServiceEmailTemplateV1", "retainV1"}} {
		t.Run(tc.fn, func(t *testing.T) {
			fn := serviceEmailNativeFunctionV1(t, "application_service_email_templates_v1.go", tc.fn)
			grants := serviceEmailNativeCallPositionsV1(fn, tc.grant)
			headers := serviceEmailNativeCallPositionsV1(fn, "GetServiceEmailTemplateHeaderV1")
			bodies := serviceEmailNativeCallPositionsV1(fn, "GetServiceEmailTemplateV1")
			if len(grants) != 2 || len(headers) != 1 || len(bodies) != 1 || !(grants[0] < headers[0] && headers[0] < grants[1] && grants[1] < bodies[0]) {
				t.Fatal("native owner must grant scalar source, then actual measured body before each fixed SQL read")
			}
			// A genuinely absent locked head is the only builtin fallback. Do not
			// replace database/source failure with an unconfigured-template branch.
			absent := 0
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Is" {
					return true
				}
				target, ok := call.Args[1].(*ast.SelectorExpr)
				if ok && target.Sel.Name == "ErrNoRows" {
					absent++
					if !(headers[0] < call.Pos() && call.Pos() < grants[1]) {
						t.Fatal("absence fallback moved after the selected body read")
					}
				}
				return true
			})
			if absent != 1 {
				t.Fatal("expected exactly one scalar absent-head fallback")
			}
		})
	}
}

func TestServiceEmailNativeProducerMeasuresSelectedRevisionBeforeRenderingV1(t *testing.T) {
	for _, tc := range []struct{ file, fn, source, next string }{
		{"application_comment_notifications_v1.go", "RenderCommentNotificationsV1", "serviceEmailTemplateV1", "applicationServiceEmailComponentsV1"},
		{"application_html_send_completion_mutations_v1.go", "PrepareCompletionOutputsV1", "serviceEmailTemplateV1", "applicationServiceEmailComponentsV1"},
		{"application_html_send_completion_mutations_v1.go", "RenderInviteV1", "cachedServiceEmailTemplateV1", "RenderServiceEmailV1"},
		{"application_package_send_outbox_batch_v1.go", "packageSendOutboxShapeV1", "cachedServiceEmailTemplateV1", "applicationServiceEmailComponentsV1"},
		{"application_presign_publication_v1.go", "PublishPreSignCustomerV1", "serviceEmailTemplateV1", "applicationServiceEmailComponentsV1"},
		{"application_reminder_v1.go", "PrepareV1", "serviceEmailTemplateV1", "applicationServiceEmailComponentsV1"},
		{"application_reminder_v1.go", "RenderV1", "cachedServiceEmailTemplateV1", "RenderServiceEmailV1"},
		{"application_historical_completion_outputs_v1.go", "RenderHistoricalCompletionMessagesV1", "serviceEmailTemplateV1", "applicationServiceEmailComponentsV1"},
		{"application_html_ceremony_notification_v1.go", "NewChangeNotificationV1", "changeServiceEmailTemplateV1", "applicationServiceEmailComponentsV1"},
		{"application_html_ceremony_notification_v1.go", "BorrowMessageV1", "BorrowContextV1", "RenderServiceEmailV1"},
	} {
		t.Run(tc.file+"/"+tc.fn, func(t *testing.T) {
			fn := serviceEmailNativeFunctionV1(t, tc.file, tc.fn)
			source := serviceEmailNativeCallPositionsV1(fn, tc.source)
			next := serviceEmailNativeCallPositionsV1(fn, tc.next)
			if len(source) == 0 || len(next) == 0 || source[0] >= next[0] {
				t.Fatal("actual producer bypassed source selection/measurement order")
			}
			if len(serviceEmailNativeCallPositionsV1(fn, "Render")) != 0 {
				t.Fatal("native producer bypasses selected revision with a builtin render")
			}
		})
	}
}
