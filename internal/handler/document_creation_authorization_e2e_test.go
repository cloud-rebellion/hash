//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// These regressions enter real admission middleware, block on PostgreSQL's
// actual quota/template/member/audit locks, and verify complete rollback.
// No renderer, mail dispatcher or production object storage is involved. PDF
// templates use the source-built sanitizer and a local versioned storage peer.
func setupDocumentCreationE2E(t *testing.T, source string) (lifecycleAuthorizationFixture, *generated.Template) {
	t.Helper()
	f := setupNativeTemplateAuthorizationE2E(t, "sender")
	tpl := seedAuthorizationTemplateE2E(t, f, source)

	return f, tpl
}

func enableDocumentCreationMCPE2E(f lifecycleAuthorizationFixture) {
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: versions.New(f.q), Billing: f.s.Billing, Storage: f.s.Storage, Send: f.s.Send, PDFCreationSessions: f.s.HTMLCreationSessions})
}

func submitDocumentCreationE2E(f lifecycleAuthorizationFixture, ctx context.Context, transport, credential string, args map[string]any) *httptest.ResponseRecorder {
	if transport == "mcp" {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "create_document", "arguments": args}})
		r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", bytes.NewReader(body)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(w, r)
		return w
	}
	body, _ := json.Marshal(args)
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/documents", bytes.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: credential})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func documentCreationArgsE2E(tpl *generated.Template) map[string]any {
	return map[string]any{"name": "Authorized sales draft", "source_kind": tpl.SourceKind, "template_id": tpl.ID}
}

func documentCreationTemplateQueryE2E(tpl *generated.Template) string {
	if tpl.SourceKind == "pdf" {
		return "GetPDFTemplateSourceHeaderForShareV1"
	}
	return "GetNonHTMLTemplateSourceHeaderForShareV1"
}

func documentCreationCredentialE2E(t *testing.T, f lifecycleAuthorizationFixture, transport string, expires bool) (string, uuid.UUID, time.Time) {
	t.Helper()
	if transport == "rest" {
		ttl := time.Hour
		if expires {
			ttl = time.Second
		}
		return dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl), uuid.Nil, time.Time{}
	}
	enableDocumentCreationMCPE2E(f)
	key, id := mintRecipientMCPKeyE2E(t, f, false, 0)
	var expiry time.Time
	if expires {
		expiry = time.Now().Add(time.Second)
		if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=$2 WHERE id=$1`, id, expiry); err != nil { //nolint:rawsql -- bounded fixture credential
			t.Fatal(err)
		}
	}
	return key.Plaintext, id, expiry
}

func expireDocumentCreationCredentialE2E(t *testing.T, f lifecycleAuthorizationFixture, transport, credential string, expiry time.Time) {
	t.Helper()
	if transport == "rest" {
		awaitSessionCookieExpiryE2E(t, f.s, credential)
		return
	}
	for time.Now().Before(expiry) {
		time.Sleep(10 * time.Millisecond)
	}
}

func assertDocumentCreationRefusedE2E(t *testing.T, f lifecycleAuthorizationFixture, transport string, w *httptest.ResponseRecorder, status int, message, before string) {
	t.Helper()
	if transport == "mcp" {
		assertLifecycleMCPResultE2E(t, w, true)
	} else if w.Code != status {
		t.Fatalf("creation=%d want%d %s", w.Code, status, w.Body.String())
	}
	if message != "" && !strings.Contains(w.Body.String(), message) {
		t.Fatalf("missing precise refusal %q: %s", message, w.Body.String())
	}
	if f.snapshot(t) != before {
		t.Fatal("refused creation committed document, version, audit or outbox")
	}
}

func holdDocumentCreationTemplateE2E(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) pgx.Tx {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := f.q.WithTx(tx).GetTemplateForUpdate(f.ctx, generated.GetTemplateForUpdateParams{ID: id, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestDocumentCreationRechecksAdmittedCredentialAfterTemplateWaitE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, source := range []string{"blocks", "pdf"} {
			changes := []string{"demotion", "expiry"}
			if transport == "rest" {
				changes = append(changes, "logout")
			} else {
				changes = append(changes, "key-delete", "scope-reduction")
			}
			for _, change := range changes {
				t.Run(transport+"/"+source+"/"+change, func(t *testing.T) {
					f, tpl := setupDocumentCreationE2E(t, source)
					credential, id, expiry := documentCreationCredentialE2E(t, f, transport, change == "expiry")
					before := f.snapshot(t)
					blocked := holdDocumentCreationTemplateE2E(t, f, tpl.ID)
					result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
						return submitDocumentCreationE2E(f, ctx, transport, credential, documentCreationArgsE2E(tpl))
					}, blocked)
					defer join()
					awaitNativeTemplateLockE2E(t, f, blocked, documentCreationTemplateQueryE2E(tpl), true)
					status, message := http.StatusForbidden, "permission or credential revoked"
					var err error
					switch change {
					case "demotion":
						_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
					case "logout":
						_, err = f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
					case "key-delete":
						_, err = f.pool.Exec(f.ctx, `DELETE FROM api_keys WHERE id=$1`, id) //nolint:rawsql -- synthetic revocation during template wait
					case "scope-reduction":
						_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, id) //nolint:rawsql -- synthetic scope change during template wait
					case "expiry":
						expireDocumentCreationCredentialE2E(t, f, transport, credential, expiry)
						status, message = http.StatusUnauthorized, "credential expired before transaction committed"
					}
					if err != nil {
						t.Fatal(err)
					}
					if err := blocked.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
					assertDocumentCreationRefusedE2E(t, f, transport, receiveSessionOperationE2E(t, result), status, message, before)
				})
			}
		}
	}
}

func TestDocumentCreationRechecksAdmittedCredentialAfterMemberWaitE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, change := range []string{"demotion", "expiry"} {
			t.Run(transport+"/"+change, func(t *testing.T) {
				f, tpl := setupDocumentCreationE2E(t, "blocks")
				credential, _, expiry := documentCreationCredentialE2E(t, f, transport, change == "expiry")
				before := f.snapshot(t)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
					t.Fatal(err)
				}
				result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
					return submitDocumentCreationE2E(f, ctx, transport, credential, documentCreationArgsE2E(tpl))
				}, blocked)
				defer join()
				awaitNativeTemplateLockE2E(t, f, blocked, "GetHTMLAuthoringActorHeaderV1", true)
				status, message := http.StatusForbidden, "permission or credential revoked"
				if change == "demotion" {
					if _, err := f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
						t.Fatal(err)
					}
				} else {
					expireDocumentCreationCredentialE2E(t, f, transport, credential, expiry)
					status, message = http.StatusUnauthorized, "credential expired before transaction committed"
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				assertDocumentCreationRefusedE2E(t, f, transport, receiveSessionOperationE2E(t, result), status, message, before)
			})
		}
	}
}

func TestDocumentCreationFinalCredentialCheckAfterAuditWaitE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, source := range []string{"blocks", "pdf"} {
			t.Run(transport+"/"+source, func(t *testing.T) {
				f, tpl := setupDocumentCreationE2E(t, source)
				credential, _, expiry := documentCreationCredentialE2E(t, f, transport, true)
				before := f.snapshot(t)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
					t.Fatal(err)
				}
				result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
					return submitDocumentCreationE2E(f, ctx, transport, credential, documentCreationArgsE2E(tpl))
				}, blocked)
				defer join()
				awaitNativeTemplateLockE2E(t, f, blocked, "AcquireOrgChainLock", true)
				expireDocumentCreationCredentialE2E(t, f, transport, credential, expiry)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				assertDocumentCreationRefusedE2E(t, f, transport, receiveSessionOperationE2E(t, result), http.StatusUnauthorized, "credential expired before transaction committed", before)
			})
		}
	}
}

func TestDocumentCreationOriginalCredentialAfterQuotaWaitE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, change := range []string{"demotion", "expiry"} {
			t.Run(transport+"/"+change, func(t *testing.T) {
				f, tpl := setupDocumentCreationE2E(t, "blocks")
				f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: "pro", ReviewRef: "synthetic creation quota approval"}})
				credential, _, expiry := documentCreationCredentialE2E(t, f, transport, change == "expiry")
				before := f.snapshot(t)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if err := f.q.WithTx(blocked).LockBillingUsageForOrg(f.ctx, f.org.String()); err != nil {
					t.Fatal(err)
				}
				result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
					return submitDocumentCreationE2E(f, ctx, transport, credential, documentCreationArgsE2E(tpl))
				}, blocked)
				defer join()
				awaitNativeTemplateLockE2E(t, f, blocked, "LockBillingUsageForOrg", true)
				status, message := http.StatusForbidden, "permission or credential revoked"
				if change == "demotion" {
					if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
						t.Fatal(err)
					}
				} else {
					expireDocumentCreationCredentialE2E(t, f, transport, credential, expiry)
					status, message = http.StatusUnauthorized, "credential expired before transaction committed"
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				assertDocumentCreationRefusedE2E(t, f, transport, receiveSessionOperationE2E(t, result), status, message, before)
			})
		}
	}
}

func TestDocumentCreationAlwaysValidatesTemplateReferenceE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, boundary := range []string{"other-tenant", "archived", "wrong-source"} {
			t.Run(transport+"/"+boundary, func(t *testing.T) {
				f, tpl := setupDocumentCreationE2E(t, "blocks")
				if boundary == "other-tenant" {
					foreign := setupHTMLTemplateAuthorizationE2E(t, f.pool.Config().ConnConfig.Database, "sender")
					tpl = seedAuthorizationTemplateE2E(t, foreign, "blocks")
					var exists bool
					if err := f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM templates WHERE id=$1 AND org_id=$2)", tpl.ID, foreign.org).Scan(&exists); err != nil || !exists {
						t.Fatal("foreign template must exist in the same actual database", exists, err)
					}
				} else if boundary == "archived" {
					if err := f.q.ArchiveTemplate(f.ctx, generated.ArchiveTemplateParams{ID: tpl.ID, OrgID: f.org}); err != nil {
						t.Fatal(err)
					}
				} else {
					tpl = seedAuthorizationTemplateE2E(t, f, "pdf")
				}
				credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
				args := documentCreationArgsE2E(tpl)
				args["source_kind"] = "blocks"
				args["blocks_json"] = json.RawMessage(`{"version":1,"blocks":[{"id":"own","type":"paragraph","text":"Explicit override"}]}`)
				args["variables_json"] = map[string]string{"customer": "Explicit override"}
				before := f.snapshot(t)
				status, message := http.StatusNotFound, "template not found"
				if boundary == "wrong-source" {
					status, message = http.StatusBadRequest, "template is not a blocks-source template"
				}
				assertDocumentCreationRefusedE2E(t, f, transport, submitDocumentCreationE2E(f, f.ctx, transport, credential, args), status, message, before)
			})
		}
	}
}

func loadCreatedDocumentE2E(t *testing.T, f lifecycleAuthorizationFixture, transport string, w *httptest.ResponseRecorder) *generated.Document {
	t.Helper()
	if transport == "mcp" {
		assertLifecycleMCPResultE2E(t, w, false)
	} else if w.Code != http.StatusCreated {
		t.Fatalf("authorized creation=%d %s", w.Code, w.Body.String())
	}
	var id uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT id FROM documents WHERE org_id=$1 AND name='Authorized sales draft'`, f.org).Scan(&id); err != nil { //nolint:rawsql -- scoped fixture result
		t.Fatal(err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	var events, snapshots int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.created'),(SELECT count(*) FROM document_versions WHERE document_id=$1)`, doc.ID).Scan(&events, &snapshots); err != nil { //nolint:rawsql -- synthetic atomic creation effects
		t.Fatal(err)
	}
	wantSnapshots := 0
	if transport == "mcp" && doc.SourceKind == "blocks" {
		wantSnapshots = 1
	}
	if events != 1 || snapshots != wantSnapshots || doc.SenderID != f.user.ID || doc.Status != "draft" {
		t.Fatalf("creation effects events/versions/sender/status=%d/%d/%s/%s", events, snapshots, doc.SenderID, doc.Status)
	}
	return doc
}

func TestDocumentCreationFreshTemplateDefaultsAndExplicitOverridesE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, source := range []string{"blocks", "pdf"} {
			overrides := []string{"defaults", "variables", "empty-values"}
			if source == "blocks" {
				overrides = append(overrides, "blocks", "both", "empty-blocks")
			}
			for _, override := range overrides {
				t.Run(transport+"/"+source+"/"+override, func(t *testing.T) {
					f, tpl := setupDocumentCreationE2E(t, source)
					credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
					args := documentCreationArgsE2E(tpl)
					var defaults map[string]string
					if err := json.Unmarshal(tpl.VariablesJson, &defaults); err != nil {
						t.Fatal(err)
					}
					want := defaults["customer"]
					if override == "variables" || override == "both" {
						want = "Explicit customer"
						args["variables_json"] = map[string]string{"customer": want}
					} else if override == "empty-values" {
						want = ""
						args["variables_json"] = map[string]string{}
					}
					wantTerms := "Original terms"
					if override == "blocks" || override == "both" {
						wantTerms = "Explicit terms"
						args["blocks_json"] = json.RawMessage(`{"version":1,"blocks":[{"id":"explicit","type":"paragraph","text":"Explicit terms"}]}`)
					} else if override == "empty-blocks" {
						wantTerms = ""
						args["blocks_json"] = json.RawMessage(`{"version":1,"blocks":[]}`)
					}
					doc := loadCreatedDocumentE2E(t, f, transport, submitDocumentCreationE2E(f, f.ctx, transport, credential, args))
					var values map[string]string
					if err := json.Unmarshal(doc.VariablesJson, &values); err != nil || values["customer"] != want || (override == "empty-values" && len(values) != 0) {
						t.Fatalf("values=%s wantcustomer=%q err=%v", doc.VariablesJson, want, err)
					}
					if !doc.TemplateID.Valid || uuid.UUID(doc.TemplateID.Bytes) != tpl.ID {
						t.Fatal("creation lost verified template reference")
					}
					if source == "blocks" {
						if !strings.Contains(string(doc.BlocksJson), wantTerms) || (override == "empty-blocks" && strings.Contains(string(doc.BlocksJson), "Original terms")) {
							t.Fatal("creation lost block defaults or explicit override")
						}
					} else if doc.PdfStorageKey != tpl.PdfStorageKey || !bytes.Equal(doc.PdfSha256, tpl.PdfSha256) || doc.PdfStorageVersionID != tpl.PdfStorageVersionID || !doc.EvidenceVersionPinsRequired || !strings.Contains(string(doc.MetadataRedactionReport), "template") {
						t.Fatalf("PDF template source/pins/report not preserved: %+v", doc)
					}
				})
			}
		}
	}
}

func TestDocumentCreationCopiesUpdatedTemplateAfterWaitE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f, tpl := setupDocumentCreationE2E(t, "blocks")
			credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			// A real first PATCH owns the source row and fresh measurement while
			// its audit is queued. The later creator must copy that committed edit.
			edit, joinEdit := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
				return submitSessionOperationContextE2E(ctx, f.s, http.MethodPatch, "/api/v1/templates/"+tpl.ID.String(), `{"blocks_json":{"version":1,"blocks":[{"id":"new","type":"paragraph","text":"Fresh updated terms"}]},"variables_json":{"customer":"Fresh updated customer"}}`, cookie)
			}, blocked)
			defer joinEdit()
			awaitNativeTemplateLockE2E(t, f, blocked, "AcquireOrgChainLock", true)
			// Bind the creator's row wait to the actual first PATCH backend.
			var editorPID int32
			if err := f.pool.QueryRow(f.ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND query LIKE '%-- name: AcquireOrgChainLock%' AND wait_event='advisory' AND state='active'`, htmlAuthoringNativeApplicationNameE2E(t, f.s)).Scan(&editorPID); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- exact native first PATCH waiter
			result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
				return submitDocumentCreationE2E(f, ctx, transport, credential, documentCreationArgsE2E(tpl))
			}, blocked)
			defer join()
			awaitNativeTemplatePIDLockE2E(t, f, editorPID, documentCreationTemplateQueryE2E(tpl), true)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if w := receiveSessionOperationE2E(t, edit); w.Code != http.StatusOK {
				t.Fatalf("genuine concurrent template PATCH=%d %s", w.Code, w.Body.String())
			}
			doc := loadCreatedDocumentE2E(t, f, transport, receiveSessionOperationE2E(t, result))
			if !strings.Contains(string(doc.BlocksJson), "Fresh updated terms") || !strings.Contains(string(doc.VariablesJson), "Fresh updated customer") {
				t.Fatalf("stale defaults copied blocks=%s values=%s", doc.BlocksJson, doc.VariablesJson)
			}
			ownedBlocksTemplateExactSourceV1(t, f, tpl.ID)
		})
	}
}

func TestDocumentCreationRejectsInvalidPDFValuesE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		for _, values := range []string{`null`, `[]`, `{"amount":100}`, `{"amount":null}`} {
			t.Run(transport+"/"+values, func(t *testing.T) {
				f, tpl := setupDocumentCreationE2E(t, "pdf")
				credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
				args := documentCreationArgsE2E(tpl)
				args["variables_json"] = json.RawMessage(values)
				before := f.snapshot(t)
				// MCP schema may reject these before the handler; either boundary
				// must refuse the values without a committed document or audit.
				w := submitDocumentCreationE2E(f, f.ctx, transport, credential, args)
				if transport == "rest" {
					assertDocumentCreationRefusedE2E(t, f, transport, w, http.StatusBadRequest, "invalid variables_json", before)
				} else {
					var response struct {
						Error  json.RawMessage `json:"error"`
						Result struct {
							IsError bool `json:"isError"`
						} `json:"result"`
					}
					if json.Unmarshal(w.Body.Bytes(), &response) != nil || (len(response.Error) == 0 && !response.Result.IsError) || f.snapshot(t) != before {
						t.Fatalf("MCP accepted malformed PDF variables: %s", w.Body.String())
					}
				}
			})
		}
	}
}

func TestDocumentCreationTemplateLockRetainedThroughAuditE2E(t *testing.T) {
	f, tpl := setupDocumentCreationE2E(t, "blocks")
	credential, _, _ := documentCreationCredentialE2E(t, f, "rest", false)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
		return submitDocumentCreationE2E(f, ctx, "rest", credential, documentCreationArgsE2E(tpl))
	}, blocked)
	defer join()
	awaitNativeTemplateLockE2E(t, f, blocked, "AcquireOrgChainLock", true)
	var creatorPID int32
	if err := f.pool.QueryRow(f.ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND query LIKE '%-- name: AcquireOrgChainLock%' AND wait_event='advisory' AND state='active'`, htmlAuthoringNativeApplicationNameE2E(t, f.s)).Scan(&creatorPID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- exact creator owns the template share lock
	edit, joinEdit := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
		return submitSessionOperationContextE2E(ctx, f.s, http.MethodPatch, "/api/v1/templates/"+tpl.ID.String(), `{"blocks_json":{"version":1,"blocks":[{"id":"later","type":"paragraph","text":"Later terms"}]},"variables_json":{"customer":"Later customer"}}`, credential)
	}, blocked)
	defer joinEdit()
	awaitNativeTemplatePIDLockE2E(t, f, creatorPID, "GetNonHTMLTemplateSourceHeaderForUpdateV1", true)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	doc := loadCreatedDocumentE2E(t, f, "rest", receiveSessionOperationE2E(t, result))
	if w := receiveSessionOperationE2E(t, edit); w.Code != http.StatusOK {
		t.Fatalf("template edit did not resume after document commit=%d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(string(doc.BlocksJson), "Original terms") || !strings.Contains(string(doc.VariablesJson), "Original customer") {
		t.Fatal("later template edit changed the committed document snapshot")
	}
	ownedBlocksTemplateExactSourceV1(t, f, tpl.ID)
}

func TestDocumentCreationOperatorQuotaRollsBackE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f, tpl := setupDocumentCreationE2E(t, "blocks")
			slug := "creation-quota-" + uuid.NewString()
			if _, err := f.pool.Exec(f.ctx, `INSERT INTO billing_plans(slug,name,document_quota_monthly,recipient_quota_monthly,features_json) VALUES($1,'Creation quota fixture',1,20,'{"mcp":true}')`, slug); err != nil { //nolint:rawsql -- fixture-reviewed bounded operator plan
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), `DELETE FROM billing_plans WHERE slug=$1`, slug) })
			f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: slug, ReviewRef: "synthetic bounded creation"}})
			credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
			before := f.snapshot(t)
			w := submitDocumentCreationE2E(f, f.ctx, transport, credential, documentCreationArgsE2E(tpl))
			assertDocumentCreationRefusedE2E(t, f, transport, w, http.StatusPaymentRequired, "", before)
		})
	}
}

func TestDocumentCreationAuditFailureRollsBackAndRetriesE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			f, tpl := setupDocumentCreationE2E(t, "blocks")
			credential, _, _ := documentCreationCredentialE2E(t, f, transport, false)
			function := "hash_creation_audit_fail_" + strings.ReplaceAll(f.org.String(), "-", "")
			trigger := function + "_trg"
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION "%s"() RETURNS trigger LANGUAGE plpgsql AS $body$ BEGIN IF NEW.org_id='%s'::uuid AND NEW.kind='document.created' THEN RAISE EXCEPTION 'synthetic creation audit failure'; END IF; RETURN NEW; END $body$`, function, f.org)); err != nil {
				t.Fatal(err)
			} //nolint:rawsql,gosec -- identifiers/literal derive from generated UUID
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE TRIGGER "%s" BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION "%s"()`, trigger, function)); err != nil {
				t.Fatal(err)
			} //nolint:rawsql,gosec
			cleanup := func() {
				_, _ = f.pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS "%s" ON events`, trigger))
				_, _ = f.pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS "%s"()`, function))
			} //nolint:rawsql,gosec
			t.Cleanup(cleanup)
			before := f.snapshot(t)
			w := submitDocumentCreationE2E(f, f.ctx, transport, credential, documentCreationArgsE2E(tpl))
			assertDocumentCreationRefusedE2E(t, f, transport, w, http.StatusInternalServerError, "", before)
			cleanup()
			_ = loadCreatedDocumentE2E(t, f, transport, submitDocumentCreationE2E(f, f.ctx, transport, credential, documentCreationArgsE2E(tpl)))
		})
	}
}
