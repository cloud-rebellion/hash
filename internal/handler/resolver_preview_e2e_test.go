//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type previewBlockingSource struct {
	calls   atomic.Int32
	entered chan resolver.Ref
	release chan struct{}
	failure atomic.Bool
	value   string
	peer    *crmSourcePeerE2E
	native  *crmConnectionPauseE2E
	records int64
}

func (*previewBlockingSource) Kind() resolver.SourceKind { return resolver.SourceCRMDeal }
func (s *previewBlockingSource) Fetch(ctx context.Context, ref resolver.Ref) (string, error) {
	if s.calls.Add(1) == 1 && s.entered != nil {
		s.entered <- ref
		select {
		case <-s.release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if s.failure.Load() {
		return "", resolver.ErrNotFound
	}
	return s.value, nil
}

func (s *previewBlockingSource) callsTotal() int64 {
	return int64(s.calls.Load()) + s.peer.deals.Load() - s.records
}
func (s *previewBlockingSource) unblock() {
	if s.release != nil {
		select {
		case <-s.release:
		default:
			close(s.release)
		}
	}
	if s.native != nil {
		s.native.finish()
	}
}

// Use the actual one-value observe/apply ceremony so Send owns the supported
// CRM HTTP source and the document already contains its human-reviewed value.
// Preview's independent callback remains only a cache/failure/wait probe.
func reviewResolverCRMFixtureE2E(t *testing.T, f *variableBindingAuthorizationFixture, source *previewBlockingSource) {
	t.Helper()
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	c := crmDocumentReadContextE2E(t, f.lifecycleAuthorizationFixture, cookie)
	in := CRMMappingRequest{CRMDocumentWitnessE2E(c), []crmDocumentMapping{{"customer", "crm.deal", crmSourceDealE2E, "title"}}}
	observation := crmDocumentObserveE2E(t, f.lifecycleAuthorizationFixture, cookie, in)
	w := crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodPost, "apply", cookie, crmDocumentApplyInputE2E(in, observation.ReviewDigest))
	if w.Code != http.StatusOK {
		t.Fatalf("genuine one-value CRM review=%d %s", w.Code, w.Body.String())
	}
	var err error
	f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	source.records = source.peer.deals.Load()
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	f.auditBaseline = len(events)
}

func setupResolverPreviewE2E(t *testing.T, role string, blocked, failure bool) (variableBindingAuthorizationFixture, *previewBlockingSource) {
	t.Helper()
	// Enrollment, source review and native document birth require a real owner.
	// Viewer/sender credentials are established only after that authorized setup.
	f := setupVariableBindingAuthorizationE2E(t, "owner")
	connection := setupCRMConnectionForFixtureE2E(t, f.lifecycleAuthorizationFixture)
	peer := newCRMSourcePeerE2E(t)
	peer.setDeal(t, "Current reviewed CRM customer")
	client, err := crmconnection.NewClient(peer.server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	f.s.CRMOrigin, f.s.CRMClient = peer.server.URL, client
	connection.active(t)
	source := &previewBlockingSource{value: "Current reviewed CRM customer", peer: peer}
	source.failure.Store(failure)
	f.s.Send.Resolver = resolver.New(f.q)
	f.s.Send.Resolver.CRM = &resolver.CRMRecords{Store: f.q, Client: client, Keys: f.s.CRMKeys, Origin: peer.server.URL}
	reviewResolverCRMFixtureE2E(t, &f, source)
	if failure {
		// Preview-only fallback is an explicit authoring choice. Native Send
		// forbids it; these source-failure read tests never send this document.
		body := `{"source_kind":"crm.deal","source_ref":"` + crmSourceDealE2E + `","source_path":"title","fallback":"Original fallback"}`
		if w := f.submitScoped("upsert", f.doc.ID, "customer", body, connection.cookie); w.Code != http.StatusOK {
			t.Fatalf("actual preview fallback preparation=%d %s", w.Code, w.Body.String())
		}
	}
	if blocked {
		source.entered = make(chan resolver.Ref, 1)
		source.release = make(chan struct{})
	}
	t.Cleanup(source.unblock)
	f.s.Resolver = resolver.New(f.q, source)
	if role != "owner" {
		f.user, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: role})
		if err != nil {
			t.Fatal(err)
		}
	}
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Send: f.s.Send, Resolver: f.s.Resolver, PublicURL: f.s.PublicURL, PDFCreationSessions: f.s.HTMLCreationSessions, Versions: f.s.Versions, Storage: f.s.Storage, Billing: f.s.Billing})
	return f, source
}

func submitResolverPreviewE2E(f variableBindingAuthorizationFixture, ctx context.Context, transport, credential string) *httptest.ResponseRecorder {
	if transport != "mcp" {
		suffix := "resolve-preview"
		if transport == "html" {
			suffix = "preview"
		}
		r := httptest.NewRequest(http.MethodGet, f.s.PublicURL+"/api/v1/documents/"+f.doc.ID.String()+"/"+suffix, nil).WithContext(ctx)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: credential})
		w := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(w, r)
		return w
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "preview_resolved_variables", "arguments": map[string]any{"document_id": f.doc.ID}}})
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+credential)
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func mintResolverReadKeyE2E(t *testing.T, f variableBindingAuthorizationFixture, document bool) (*auth.MintedKey, uuid.UUID) {
	t.Helper()
	mint, err := auth.MintAPIKey()
	if document {
		mint, err = auth.MintDocumentAgentKey()
	}
	if err != nil {
		t.Fatal(err)
	}
	if document {
		row, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{DocumentID: f.doc.ID, OrgID: f.org, Name: "Read preview fixture", Prefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"read"}, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1})
		if err != nil {
			t.Fatal(err)
		}
		return mint, row.ID
	}
	row, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, Name: "Read preview fixture", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	return mint, row.ID
}

func awaitResolverSourceE2E(t *testing.T, f variableBindingAuthorizationFixture, source *previewBlockingSource) {
	t.Helper()
	var nativeEntered <-chan struct{}
	if source.native != nil {
		nativeEntered = source.native.entered
	}
	select {
	case ref := <-source.entered:
		if ref.OrgID != f.org || ref.DocID != f.doc.ID || ref.Source != crmSourceDealE2E || ref.Path != "title" {
			t.Fatalf("lost source tenant/ref: %+v", ref)
		}
	case <-nativeEntered:
		// The real peer already checked the exact deal endpoint and original
		// account bearer. Bind that HTTP wait to this actual document's row;
		// no callback-shaped Ref is manufactured as native source evidence.
		bindings, err := f.q.ListVariableBindings(f.ctx, f.doc.ID)
		if err != nil || len(bindings) != 1 || bindings[0].SourceRef != crmSourceDealE2E || bindings[0].SourcePath != "title" || source.peer.unexpected.Load() != 0 || source.peer.deals.Load()-source.records != 1 {
			t.Fatal("native HTTP wait lost the original document/source/account", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("preview did not reach actual blocking source")
	}
}

func assertResolverPreviewResultE2E(t *testing.T, transport string, w *httptest.ResponseRecorder, want int, message string) string {
	t.Helper()
	if transport == "mcp" {
		text := fieldMCPTextE2E(t, w, want != http.StatusOK)
		if message != "" && !strings.Contains(text, message) {
			t.Fatalf("MCP preview=%s want %q", text, message)
		}
		return text
	}
	if w.Code != want || (message != "" && !strings.Contains(w.Body.String(), message)) {
		t.Fatalf("%s preview=%d %s want %d %q", transport, w.Code, w.Body.String(), want, message)
	}
	return w.Body.String()
}

func TestResolverPreviewViewerReadsAreSideEffectFreeE2E(t *testing.T) {
	for _, transport := range []string{"resolve", "html", "mcp"} {
		for _, failure := range []bool{false, true} {
			t.Run(transport+"/failure="+strconvBool(failure), func(t *testing.T) {
				f, source := setupResolverPreviewE2E(t, "viewer", false, failure)
				credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				if transport == "mcp" {
					mint, _ := mintResolverReadKeyE2E(t, f, false)
					credential = mint.Plaintext
				}
				before := f.snapshot(t)
				for i := 0; i < 2; i++ {
					answer := assertResolverPreviewResultE2E(t, transport, submitResolverPreviewE2E(f, f.ctx, transport, credential), http.StatusOK, "")
					expected := "Current reviewed CRM customer"
					if failure {
						expected = "Original fallback"
					}
					if !strings.Contains(answer, expected) {
						t.Fatalf("preview missing %q: %s", expected, answer)
					}
				}
				if f.snapshot(t) != before {
					t.Fatal("viewer preview/source failure/cache hit persisted an observation, content, audit, version, or outbox")
				}
				expectedCalls := int64(1)
				if failure {
					expectedCalls = 2
				}
				if source.callsTotal() != expectedCalls {
					t.Fatalf("source calls=%d want%d", source.callsTotal(), expectedCalls)
				}
			})
		}
	}
}
func strconvBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestResolverPreviewRechecksAfterSourceWaitE2E(t *testing.T) {
	for _, transport := range []string{"resolve", "html", "mcp"} {
		changes := []string{"binding-change", "binding-delete", "document-change", "send", "delete", "logout", "expiry", "viewer-demotion", "cancel"}
		if transport == "mcp" {
			changes = []string{"binding-change", "send", "delete", "key-delete", "scope-reduction", "key-expiry", "token-revocation", "viewer-demotion", "cancel"}
		}
		for _, change := range changes {
			t.Run(transport+"/"+change, func(t *testing.T) {
				f, source := setupResolverPreviewE2E(t, "sender", true, false)
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
				var keyID uuid.UUID
				if transport == "mcp" {
					mint, id := mintResolverReadKeyE2E(t, f, change == "token-revocation")
					credential, keyID = mint.Plaintext, id
				}
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				result := make(chan *httptest.ResponseRecorder, 1)
				joined := make(chan struct{})
				go func() { defer close(joined); result <- submitResolverPreviewE2E(f, ctx, transport, credential) }()
				defer func() { cancel(); source.unblock(); joinHTMLAuthoringRequestE2E(t, cancel, joined) }()
				awaitResolverSourceE2E(t, f, source)
				senderCookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				want, message := http.StatusConflict, resolver.ErrPreviewChanged.Error()
				var err error
				switch change {
				case "binding-change", "binding-delete":
					operation := "upsert"
					if change == "binding-delete" {
						operation = "delete"
					}
					if w := f.submit(operation, senderCookie); w.Code != bindingAuthorizationStatus(operation) {
						t.Fatalf("concurrent binding mutation=%d %s", w.Code, w.Body.String())
					}
				case "document-change":
					_, err = f.pool.Exec(f.ctx, `UPDATE documents SET name='Edited during preview',updated_at=clock_timestamp() WHERE id=$1`, f.doc.ID) //nolint:rawsql -- source-wait regression
				case "send":
					if w := f.lifecycleAuthorizationFixture.submit("send", senderCookie); w.Code != http.StatusOK {
						t.Fatalf("actual parallel send=%d %s", w.Code, w.Body.String())
					}
				case "delete":
					w := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/documents/"+f.doc.ID.String(), "", senderCookie)
					if w.Code != http.StatusNoContent {
						t.Fatalf("actual parallel delete=%d %s", w.Code, w.Body.String())
					}
					want, message = http.StatusNotFound, "document not found"
				case "logout":
					_, err = f.pool.Exec(f.ctx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`, f.user.ID)
					want, message = http.StatusForbidden, auth.ErrMutationPermissionRevoked.Error() //nolint:rawsql
				case "expiry":
					deadline := time.Now().Add(3 * time.Second)
					for {
						_, verifyErr := f.s.Cookies.Verify(credential)
						if verifyErr != nil {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("original cookie did not expire")
						}
						time.Sleep(10 * time.Millisecond)
					}
					want, message = http.StatusUnauthorized, auth.ErrMutationCredentialExpired.Error()
				case "viewer-demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
					want, message = http.StatusOK, "Current reviewed CRM customer"
				case "key-delete":
					_, err = f.pool.Exec(f.ctx, `DELETE FROM api_keys WHERE id=$1`, keyID)
					want, message = http.StatusForbidden, auth.ErrMutationPermissionRevoked.Error() //nolint:rawsql
				case "scope-reduction":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['write:authoring']::text[] WHERE id=$1`, keyID)
					want, message = http.StatusForbidden, auth.ErrMutationPermissionRevoked.Error() //nolint:rawsql
				case "key-expiry":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID)
					want, message = http.StatusUnauthorized, auth.ErrMutationCredentialExpired.Error() //nolint:rawsql
				case "token-revocation":
					_, err = f.q.RevokeDocAgentToken(f.ctx, generated.RevokeDocAgentTokenParams{ID: keyID, OrgID: f.org})
					want, message = http.StatusForbidden, auth.ErrMutationPermissionRevoked.Error()
				case "cancel":
					cancel()
					want, message = http.StatusInternalServerError, ""
				}
				if err != nil {
					t.Fatal(err)
				}
				before := f.snapshot(t)
				source.unblock()
				assertResolverPreviewResultE2E(t, transport, receiveSessionOperationE2E(t, result), want, message)
				if f.snapshot(t) != before {
					t.Fatal("late preview changed current binding/doc/audit/outbox after concurrent mutation or read revocation")
				}
			})
		}
	}
}

func TestResolverPreviewDocumentTokenConsumesOneAdmissionE2E(t *testing.T) {
	f, _ := setupResolverPreviewE2E(t, "viewer", false, false)
	mint, keyID := mintResolverReadKeyE2E(t, f, true)
	before := f.snapshot(t)
	assertResolverPreviewResultE2E(t, "mcp", submitResolverPreviewE2E(f, f.ctx, "mcp", mint.Plaintext), http.StatusOK, "Current reviewed CRM customer")
	var uses int32
	if err := f.pool.QueryRow(f.ctx, `SELECT used_count FROM document_agent_tokens WHERE id=$1`, keyID).Scan(&uses); err != nil || uses != 1 {
		t.Fatalf("read token uses=%d err=%v", uses, err)
	} //nolint:rawsql
	if f.snapshot(t) != before {
		t.Fatal("single-use read token preview mutated document state")
	}
	if w := submitResolverPreviewE2E(f, f.ctx, "mcp", mint.Plaintext); w.Code != http.StatusUnauthorized {
		t.Fatalf("one-use token replay=%d %s", w.Code, w.Body.String())
	}
}

func TestResolverSendFreshCRMRefusesCachedFallbackAndUnauthorizedWritesE2E(t *testing.T) {
	for _, change := range []string{"source-failure", "fallback", "binding-change", "binding-recreate", "logout", "key-delete", "invalidate"} {
		t.Run(change, func(t *testing.T) {
			f, source := setupResolverPreviewE2E(t, "sender", change != "source-failure" && change != "fallback", false)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			if change == "source-failure" || change == "fallback" {
				assertResolverPreviewResultE2E(t, "resolve", submitResolverPreviewE2E(f, f.ctx, "resolve", cookie), http.StatusOK, "")
				wantCalls := int64(2)
				if change == "source-failure" {
					source.failure.Store(true)
					source.peer.mu.Lock()
					source.peer.deal = json.RawMessage(`{}`) // actual HTTP response fails record identity/shape validation
					source.peer.mu.Unlock()
				} else {
					// A cached read is not authority to use an explicit fallback in
					// native Send when the real fresh provider response is invalid.
					body := `{"source_kind":"crm.deal","source_ref":"` + crmSourceDealE2E + `","source_path":"title","fallback":"Original fallback"}`
					if w := f.submitScoped("upsert", f.doc.ID, "customer", body, cookie); w.Code != http.StatusOK {
						t.Fatalf("actual fallback authoring=%d %s", w.Code, w.Body.String())
					}
					source.peer.mu.Lock()
					source.peer.deal = json.RawMessage(`{}`)
					source.peer.mu.Unlock()
				}
				before := f.snapshot(t)
				w := f.lifecycleAuthorizationFixture.submit("send", cookie)
				if w.Code == http.StatusOK || source.callsTotal() != wantCalls {
					t.Fatalf("send trusted preview cache/fallback: %d %s calls=%d", w.Code, w.Body.String(), source.callsTotal())
				}
				if f.snapshot(t) != before {
					t.Fatal("failed fresh CRM send persisted observation or ceremony")
				}
				return
			}
			source.native = source.peer.pauseRecord(t)
			var keyID uuid.UUID
			credential := cookie
			if change == "key-delete" {
				mint, id := mintDocumentMetadataKeyE2E(t, f.lifecycleAuthorizationFixture, false)
				credential, keyID = mint.Plaintext, id
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			result := make(chan *httptest.ResponseRecorder, 1)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				if change == "key-delete" {
					body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "send_document", "arguments": map[string]any{"document_id": f.doc.ID, "lawful_basis": "contract"}}})
					r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Authorization", "Bearer "+credential)
					w := httptest.NewRecorder()
					f.s.Routes().ServeHTTP(w, r)
					result <- w
				} else {
					requestFixture := f.lifecycleAuthorizationFixture
					requestFixture.ctx = ctx
					result <- requestFixture.submit("send", credential)
				}
			}()
			defer func() { cancel(); source.unblock(); joinHTMLAuthoringRequestE2E(t, cancel, joined) }()
			awaitResolverSourceE2E(t, f, source)
			var err error
			switch change {
			case "binding-change":
				if w := f.submit("upsert", cookie); w.Code != http.StatusOK {
					t.Fatalf("parallel binding update=%d %s", w.Code, w.Body.String())
				}
			case "binding-recreate":
				if w := f.submit("delete", cookie); w.Code != http.StatusNoContent {
					t.Fatal("parallel binding delete failed")
				}
				if w := f.submit("upsert", cookie); w.Code != http.StatusOK {
					t.Fatal("parallel binding recreate failed")
				}
			case "logout":
				_, err = f.pool.Exec(f.ctx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`, f.user.ID) //nolint:rawsql
			case "key-delete":
				_, err = f.pool.Exec(f.ctx, `DELETE FROM api_keys WHERE id=$1`, keyID) //nolint:rawsql
			case "invalidate":
				f.s.Send.Resolver.InvalidateForSourceOrgs(string(resolver.SourceCRMDeal), crmSourceDealE2E, []uuid.UUID{f.org})
			}
			if err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			source.unblock()
			w := receiveSessionOperationE2E(t, result)
			if change == "key-delete" {
				if text := fieldMCPTextE2E(t, w, true); !strings.Contains(text, auth.ErrMutationPermissionRevoked.Error()) {
					t.Fatalf("send key revocation=%s", text)
				}
			} else if w.Code == http.StatusOK {
				t.Fatalf("late send accepted %s: %s", change, w.Body.String())
			}
			if f.snapshot(t) != before {
				t.Fatal("late failed send persisted observations, frozen variables, notice, tokens, versions, audit or mail")
			}
		})
	}
}

func TestResolverDurableObservationRequiresExactRevisionsE2E(t *testing.T) {
	for _, change := range []string{"org", "document-revision", "binding-revision", "binding-recreated", "sent", "deleted"} {
		t.Run(change, func(t *testing.T) {
			f, _ := setupResolverPreviewE2E(t, "sender", false, false)
			bindings, err := f.q.ListVariableBindings(f.ctx, f.doc.ID)
			if err != nil {
				t.Fatal(err)
			}
			binding := bindings[0]
			args := generated.UpdateVariableBindingResolvedParams{DocumentID: f.doc.ID, OrgID: f.org, VariableName: binding.VariableName, LastValue: "Unreviewed in-flight source response", ExpectedDocumentUpdatedAt: f.doc.UpdatedAt, ExpectedBindingCreatedAt: binding.CreatedAt, ExpectedBindingUpdatedAt: binding.UpdatedAt}
			switch change {
			case "org":
				args.OrgID = uuid.New()
			case "document-revision":
				_, err = f.pool.Exec(f.ctx, `UPDATE documents SET updated_at=clock_timestamp() WHERE id=$1`, f.doc.ID) //nolint:rawsql
			case "binding-revision":
				_, err = f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{DocumentID: f.doc.ID, VariableName: "customer", SourceKind: "crm.deal", SourceRef: "deal_changed", SourcePath: "title"})
			case "binding-recreated":
				err = f.q.DeleteVariableBinding(f.ctx, generated.DeleteVariableBindingParams{DocumentID: f.doc.ID, VariableName: "customer"})
				if err == nil {
					_, err = f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{DocumentID: f.doc.ID, VariableName: "customer", SourceKind: "crm.deal", SourceRef: crmSourceDealE2E, SourcePath: "title"})
				}
			case "sent":
				w := f.lifecycleAuthorizationFixture.submit("send", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
				if w.Code != http.StatusOK {
					t.Fatalf("real guarded send=%d %s", w.Code, w.Body.String())
				}
			case "deleted":
				_, err = f.pool.Exec(f.ctx, `UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1`, f.doc.ID) //nolint:rawsql
			}
			if err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			if rows, err := f.q.UpdateVariableBindingResolved(f.ctx, args); err != nil || rows != 0 {
				t.Fatalf("stale observation rows=%d err=%v", rows, err)
			}
			errorsArgs := generated.UpdateVariableBindingErrorParams{DocumentID: args.DocumentID, OrgID: args.OrgID, VariableName: args.VariableName, LastError: "Unreviewed stale failure", ExpectedDocumentUpdatedAt: args.ExpectedDocumentUpdatedAt, ExpectedBindingCreatedAt: args.ExpectedBindingCreatedAt, ExpectedBindingUpdatedAt: args.ExpectedBindingUpdatedAt}
			if rows, err := f.q.UpdateVariableBindingError(f.ctx, errorsArgs); err != nil || rows != 0 {
				t.Fatalf("stale error observation rows=%d err=%v", rows, err)
			}
			if f.snapshot(t) != before {
				t.Fatal("stale observation changed current binding ledger")
			}
		})
	}
}

func TestResolverFrozenPreviewRemainsReadableAndNeverFetchesE2E(t *testing.T) {
	f, source := setupResolverPreviewE2E(t, "sender", false, false)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	if w := f.lifecycleAuthorizationFixture.submit("send", cookie); w.Code != http.StatusOK {
		t.Fatalf("freeze actual send=%d %s", w.Code, w.Body.String())
	}
	if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	calls := source.callsTotal()
	for _, transport := range []string{"resolve", "html", "mcp"} {
		credential := cookie
		if transport == "mcp" {
			mint, _ := mintResolverReadKeyE2E(t, f, false)
			credential = mint.Plaintext
		}
		answer := assertResolverPreviewResultE2E(t, transport, submitResolverPreviewE2E(f, f.ctx, transport, credential), http.StatusOK, "Current reviewed CRM customer")
		if transport != "html" && !strings.Contains(answer, `"frozen":true`) {
			t.Fatalf("frozen preview not labelled: %s", answer)
		}
	}
	if source.callsTotal() != calls || f.snapshot(t) != before {
		t.Fatal("frozen viewer/read-key previews fetched live source or mutated signing evidence")
	}
}

func TestResolverSendFreezesCurrentCRMInsteadOfCachedPreviewE2E(t *testing.T) {
	f, source := setupResolverPreviewE2E(t, "owner", false, false)
	source.peer.setDeal(t, "Current CRM value reviewed at send")
	reviewResolverCRMFixtureE2E(t, &f, source)
	// The current value is genuinely reviewed in the static draft. Only the
	// read-only preview probe returns an older cached value; Send must ignore it.
	source.value = "Older CRM value cached for preview"
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	before := f.snapshot(t)
	for i := 0; i < 2; i++ {
		answer := assertResolverPreviewResultE2E(t, "resolve", submitResolverPreviewE2E(f, f.ctx, "resolve", cookie), http.StatusOK, "Older CRM value cached for preview")
		if i == 1 && !strings.Contains(answer, `"resolved_from":"cached"`) {
			t.Fatalf("second preview did not exercise cache: %s", answer)
		}
	}
	if source.callsTotal() != 1 || f.snapshot(t) != before {
		t.Fatal("cached previews fetched twice or wrote document/binding observations")
	}
	sent := f.lifecycleAuthorizationFixture.submit("send", cookie)
	if sent.Code != http.StatusOK || source.callsTotal() != 2 {
		t.Fatalf("actual send did not fetch current CRM: %d %s calls=%d", sent.Code, sent.Body.String(), source.callsTotal())
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil || doc.Status != "sent" {
		t.Fatalf("sent document state=%v err=%v", doc, err)
	}
	var values map[string]string
	if err := json.Unmarshal(doc.VariablesJson, &values); err != nil || values["customer"] != "Current CRM value reviewed at send" {
		t.Fatalf("frozen variables=%s err=%v", doc.VariablesJson, err)
	}
	bindings, err := f.q.ListVariableBindings(f.ctx, f.doc.ID)
	if err != nil || len(bindings) != 1 || bindings[0].LastValue != values["customer"] || bindings[0].LastError != "" || !bindings[0].LastResolved.Valid {
		t.Fatalf("send observation not tied to frozen value: %+v err=%v", bindings, err)
	}
	var sentEvents, invitedEvents, observedEvents, outbox, confirmations, intents, wrongActors int
	if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.sent' AND payload_json->>'via'='rest' AND payload_json->>'lawful_basis'='contract' AND payload_json->>'lawful_basis_confirmed'='true'),
 (SELECT count(*) FROM events WHERE document_id=$1 AND kind='recipient.invited'),
 (SELECT count(*) FROM events WHERE document_id=$1 AND kind='crm.variables.observed' AND payload_json->>'assurance'='time-of-read'),
 (SELECT count(*) FROM email_deliveries WHERE to_email=$2),
 (SELECT count(*) FROM document_lawful_basis_confirmations WHERE document_id=$1 AND lawful_basis='contract'),
 (SELECT count(*) FROM send_sealing_intents WHERE document_id=$1),
 (SELECT count(*) FROM events WHERE document_id=$1 AND actor_user_id IS DISTINCT FROM $3)`, f.doc.ID, f.recipient.Email, f.user.ID).Scan(&sentEvents, &invitedEvents, &observedEvents, &outbox, &confirmations, &intents, &wrongActors); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- exact fixture reviewed send ledger
	if sentEvents != 1 || invitedEvents != 1 || observedEvents != 1 || outbox != 1 || confirmations != 1 || intents != 0 || wrongActors != 0 {
		t.Fatalf("reviewed send effects sent/invited/CRM/outbox/notice/pending-intents/wrong-actors=%d/%d/%d/%d/%d/%d/%d", sentEvents, invitedEvents, observedEvents, outbox, confirmations, intents, wrongActors)
	}
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != f.auditBaseline+3 {
		t.Fatalf("send chain invalid: %+v", result)
	}
	after := f.snapshot(t)
	assertResolverPreviewResultE2E(t, "resolve", submitResolverPreviewE2E(f, f.ctx, "resolve", cookie), http.StatusOK, "Current CRM value reviewed at send")
	if source.callsTotal() != 2 || f.snapshot(t) != after {
		t.Fatal("sent preview refetched CRM or altered frozen evidence")
	}
}
