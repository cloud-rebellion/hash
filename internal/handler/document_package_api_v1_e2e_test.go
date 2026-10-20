//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/packageauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func packageAPIArguments225(t *testing.T, pair [2]*generated.Document, transport string) string {
	t.Helper()
	in := map[string]any{"member_document_id": pair[1].ID.String(), "expected_updated_at": pair[0].UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_member_updated_at": pair[1].UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_package_id": "", "expected_generation": "0", "ordinal": 1, "title": "Additional agreement", "category": "Custom business terms"}
	if transport == "MCP" {
		in["document_id"] = pair[0].ID.String()
	}
	raw, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}
func packageAPIRequest225(q *ownedPublicReadFixtureV1, ctx context.Context, transport, tool string, root uuid.UUID, key, raw string) *http.Request {
	method, path := http.MethodPost, "/api/v1/documents/"+root.String()+"/attachments"
	if tool == "get_document_attachments" {
		method = http.MethodGet
	}
	if transport == "MCP" {
		method = http.MethodPost
		path = "/mcp"
		raw = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + raw + `}}`
	}
	r := httptest.NewRequest(method, q.f.s.PublicURL+path, strings.NewReader(raw)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", q.f.s.PublicURL)
	if transport == "MCP" {
		r.Header.Set("Authorization", "Bearer "+key)
	} else {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
	}
	return r
}
func packageAPISubmit225(q *ownedPublicReadFixtureV1, transport, tool string, root uuid.UUID, key, raw string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, packageAPIRequest225(q, q.f.ctx, transport, tool, root, key, raw))
	return w
}
func packageAPIReply225(t *testing.T, w *httptest.ResponseRecorder, transport string, status int, dst any) {
	t.Helper()
	body := w.Body.Bytes()
	if transport == "MCP" {
		body = []byte(fieldMCPTextE2E(t, w, false))
	} else if w.Code != status {
		t.Fatalf("attachment API status=%d want=%d %s", w.Code, status, body)
	}
	if e := json.Unmarshal(body, dst); e != nil {
		t.Fatal("attachment API JSON", e)
	}
	for _, private := range []string{"pdf_key", "pdf_intake_report", "metadata_redaction_report", "source_json", "key_hash"} {
		if strings.Contains(string(body), private) {
			t.Fatal("private source field escaped", private)
		}
	}
}
func packageAPIRefused225(t *testing.T, q *ownedPublicReadFixtureV1, w *httptest.ResponseRecorder, transport string, status int, before string, requests int64) {
	t.Helper()
	if transport == "MCP" {
		fieldMCPTextE2E(t, w, true)
	} else if w.Code != status {
		t.Fatalf("attachment refusal=%d want=%d %s", w.Code, status, w.Body.String())
	}
	if packageFullState223(t, q) != before || q.storagePeer.requests.Load() != requests {
		t.Fatal("refusal fetched or mutated")
	}
	ownedCreationAssertDrainedV1(t, q, 2)
}

// Real route/middleware, original cookies/API keys, native PG, strict isolated
// PDF worker and synthetic versioned S3. No configured provider/capacity claim.
func TestDocumentPackageStaffAPIV1E2E(t *testing.T) {
	q := newOwnedDocumentPackageMeasurementFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if e := malwarescan.Configure(q.f.ctx, "", "development"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := malwarescan.Configure(context.Background(), "", "development"); e != nil {
			t.Error(e)
		}
	})
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, PDFCreationSessions: q.runtime.SessionsV1(), Storage: q.f.s.Storage, Billing: q.f.s.Billing, PublicURL: q.f.s.PublicURL})
	key, _ := mintAuthoringMCPE2E(t, q.f)
	var selectedRoot uuid.UUID
	for _, transport := range []string{"REST", "MCP"} {
		t.Run(transport+" commits exact selection and reads frozen observation", func(t *testing.T) {
			pair := [2]*generated.Document{packageImported220(t, q, "Main agreement"), packageImported220(t, q, "DPA")}
			rootArgs := `{"document_id":"` + pair[0].ID.String() + `"}`
			var empty pdfadmission.DocumentPackageInventoryV1
			requests := q.storagePeer.requests.Load()
			packageAPIReply225(t, packageAPISubmit225(q, transport, "get_document_attachments", pair[0].ID, key.Plaintext, rootArgs), transport, http.StatusOK, &empty)
			if empty.DocumentID != pair[0].ID || empty.Schema != "hash-document-attachments-v1" || empty.PackageID != "" || empty.Generation != "0" || len(empty.Members) != 0 || empty.RequiresReselection || !empty.UpdatedAt.Equal(pair[0].UpdatedAt.Time) || requests != q.storagePeer.requests.Load() {
				t.Fatal("absent package observation differs", empty)
			}
			raw := packageAPIArguments225(t, pair, transport)
			var saved packageauthoring.OutcomeV1
			packageAPIReply225(t, packageAPISubmit225(q, transport, "add_document_attachment", pair[0].ID, key.Plaintext, raw), transport, http.StatusCreated, &saved)
			if saved.State != "committed" || saved.Attachment == nil || saved.Attachment.EventID == uuid.Nil || saved.ReconciliationRequired {
				t.Fatal("known success lost identity", saved)
			}
			got := saved.Attachment
			root := packageLatest223(t, q, pair[0].ID)
			if got.MemberDocumentID != pair[1].ID || got.Generation != 2 || got.Ordinal != 1 || !got.UpdatedAt.Equal(root.UpdatedAt.Time) || !got.UpdatedAt.After(pair[0].UpdatedAt.Time) {
				t.Fatal("post-trigger response differs", got)
			}
			event, e := q.f.q.GetEventByID(q.f.ctx, got.EventID)
			if e != nil || event.Kind != "document.attachment_added" || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != q.f.user.ID {
				t.Fatal("real selected audit", event, e)
			}
			observe := func() pdfadmission.DocumentPackageInventoryV1 {
				t.Helper()
				requests := q.storagePeer.requests.Load()
				var view pdfadmission.DocumentPackageInventoryV1
				packageAPIReply225(t, packageAPISubmit225(q, transport, "get_document_attachments", pair[0].ID, key.Plaintext, rootArgs), transport, http.StatusOK, &view)
				if requests != q.storagePeer.requests.Load() || view.PackageID != got.PackageID.String() || view.Generation != "2" || !view.UpdatedAt.Equal(got.UpdatedAt) || len(view.Members) != 1 || view.RequiresReselection {
					t.Fatal("stored observation differs", view)
				}
				a := view.Members[0]
				if a.DocumentID != pair[1].ID || a.Ordinal != 1 || a.Title != "Additional agreement" || a.Category != "Custom business terms" || a.PDFVersionID != pair[1].PdfStorageVersionID.String || a.PDFSHA256 != hex.EncodeToString(pair[1].PdfSha256) || a.PDFPages != 1 {
					t.Fatal("frozen metadata differs", a)
				}
				ownedCreationAssertDrainedV1(t, q, 2)
				return view
			}
			first := observe()
			before := packageFullState223(t, q)
			requests = q.storagePeer.requests.Load()
			packageAPIRefused225(t, q, packageAPISubmit225(q, transport, "add_document_attachment", pair[0].ID, key.Plaintext, raw), transport, http.StatusConflict, before, requests)
			if _, e = q.f.pool.Exec(q.f.ctx, `UPDATE documents SET name='Later source',metadata_redaction_report='{"later":true}',deleted_at=clock_timestamp() WHERE id=$1 AND org_id=$2`, pair[1].ID, q.f.org); e != nil {
				t.Fatal(e)
			}
			later := observe()
			a, _ := json.Marshal(first)
			b, _ := json.Marshal(later)
			if string(a) != string(b) {
				t.Fatal("live source changed selected observation")
			}
			if transport == "REST" {
				selectedRoot = pair[0].ID
			}
		})
		t.Run(transport+" strict requests refuse before storage", func(t *testing.T) {
			pair := [2]*generated.Document{packageImported220(t, q, "Strict main"), packageImported220(t, q, "Strict annex")}
			raw := packageAPIArguments225(t, pair, transport)
			for _, bad := range []string{strings.TrimSuffix(raw, "}") + `,"title":"duplicate"}`, strings.TrimSuffix(raw, "}") + `,"pdf_key":"caller-pin"}`, strings.Replace(raw, `"ordinal":1`, `"ordinal":1.0`, 1), strings.Replace(raw, `"expected_generation":"0"`, `"expected_generation":0`, 1)} {
				before := packageFullState223(t, q)
				requests := q.storagePeer.requests.Load()
				packageAPIRefused225(t, q, packageAPISubmit225(q, transport, "add_document_attachment", pair[0].ID, key.Plaintext, bad), transport, http.StatusBadRequest, before, requests)
			}
		})

		t.Run(transport+" unreviewed HTML refuses as an editable conflict", func(t *testing.T) {
			pair := [2]*generated.Document{packageImported220(t, q, "HTML review main"), createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)}
			before := packageFullState223(t, q)
			requests := q.storagePeer.requests.Load()
			w := packageAPISubmit225(q, transport, "add_document_attachment", pair[0].ID, key.Plaintext, packageAPIArguments225(t, pair, transport))
			packageAPIRefused225(t, q, w, transport, http.StatusConflict, before, requests)
			if transport == "MCP" && fieldMCPTextE2E(t, w, true) != "attachment is not eligible or its position is occupied; reload and review" {
				t.Fatal("HTML ineligibility lost its public conflict reason")
			}
		})
		t.Run(transport+" original credential revoked during actual parent wait", func(t *testing.T) {
			pair := [2]*generated.Document{packageImported220(t, q, "Wait main"), packageImported220(t, q, "Wait annex")}
			waitKey, keyID := mintAuthoringMCPE2E(t, q.f)
			blocked, holderPID := ownedReadHolderV1(t, q, pair[0].ID, false)
			ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
			result := make(chan *httptest.ResponseRecorder, 1)
			joined := false
			defer func() {
				cancel()
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = blocked.Rollback(cleanup)
				if !joined {
					select {
					case <-result:
					case <-cleanup.Done():
						t.Error("request cleanup did not join")
					}
				}
			}()
			request := packageAPIRequest225(q, ctx, transport, "add_document_attachment", pair[0].ID, waitKey.Plaintext, packageAPIArguments225(t, pair, transport))
			router := q.f.s.Routes()
			go func() { w := httptest.NewRecorder(); router.ServeHTTP(w, request); result <- w }()
			ownedReadWaitV1(t, q, holderPID, "GetHTMLRevisionDocumentReadHeaderV1")
			if transport == "REST" {
				if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"}); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "owner"}); e != nil {
						t.Error(e)
					}
				}()
			} else {
				if _, e := q.f.q.DeleteAPIKey(q.f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: q.f.user.ID}); e != nil {
					t.Fatal(e)
				}
			}
			before := packageFullState223(t, q)
			requests := q.storagePeer.requests.Load()
			if e := blocked.Commit(q.f.ctx); e != nil {
				t.Fatal(e)
			}
			var w *httptest.ResponseRecorder
			select {
			case w = <-result:
				joined = true
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			packageAPIRefused225(t, q, w, transport, http.StatusForbidden, before, requests)
		})
	}

	t.Run("MCP original key expires after actual provider work before commit", func(t *testing.T) {
		pair := [2]*generated.Document{packageImported220(t, q, "Expiry main"), packageImported220(t, q, "Expiry annex")}
		expiring, keyID := mintAuthoringMCPE2E(t, q.f)
		if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE api_keys SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1 AND org_id=$2", keyID, q.f.org); e != nil {
			t.Fatal(e)
		}
		blocked, e := q.f.pool.Begin(q.f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = q.f.q.WithTx(blocked).AcquireOrgChainLock(q.f.ctx, q.f.org.String()); e != nil {
			_ = blocked.Rollback(q.f.ctx)
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
		result := make(chan *httptest.ResponseRecorder, 1)
		joined := false
		defer func() {
			cancel()
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_ = blocked.Rollback(cleanup)
			if !joined {
				select {
				case <-result:
				case <-cleanup.Done():
					t.Error("expiry request did not join")
				}
			}
		}()
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		request := packageAPIRequest225(q, ctx, "MCP", "add_document_attachment", pair[0].ID, expiring.Plaintext, packageAPIArguments225(t, pair, "MCP"))
		router := q.f.s.Routes()
		go func() { w := httptest.NewRecorder(); router.ServeHTTP(w, request); result <- w }()
		awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "-- name: AcquireOrgChainLock", "advisory")
		expired := false
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if e = q.f.pool.QueryRow(q.f.ctx, "SELECT expires_at<=clock_timestamp() FROM api_keys WHERE id=$1 AND org_id=$2", keyID, q.f.org).Scan(&expired); e != nil {
				t.Fatal(e)
			}
			if expired {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !expired {
			t.Fatal("original key did not reach actual DB expiry")
		}
		if e = blocked.Commit(q.f.ctx); e != nil {
			t.Fatal(e)
		}
		var w *httptest.ResponseRecorder
		select {
		case w = <-result:
			joined = true
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if got := fieldMCPTextE2E(t, w, true); got != "the original login has expired" {
			t.Fatalf("late original expiry=%q", got)
		}
		if before != packageFullState223(t, q) || q.storagePeer.requests.Load() != requests+4 {
			t.Fatal("late expiry did not roll back real measured selection")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	t.Run("document token can observe only its root and cannot select", func(t *testing.T) {
		docKey, e := auth.MintDocumentAgentKey()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = q.f.q.InsertDocAgentToken(q.f.ctx, generated.InsertDocAgentTokenParams{DocumentID: selectedRoot, OrgID: q.f.org, Name: "Synthetic package confinement", Prefix: docKey.Prefix, KeyHash: docKey.Hash, Scopes: []string{"read", "write:authoring"}, CreatedBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}); e != nil {
			t.Fatal(e)
		}
		rootArgs := `{"document_id":"` + selectedRoot.String() + `"}`
		var view pdfadmission.DocumentPackageInventoryV1
		packageAPIReply225(t, packageAPISubmit225(q, "MCP", "get_document_attachments", selectedRoot, docKey.Plaintext, rootArgs), "MCP", http.StatusOK, &view)
		if view.DocumentID != selectedRoot || len(view.Members) != 1 {
			t.Fatal("scoped observation differs", view)
		}
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		other := `{"document_id":"` + uuid.New().String() + `"}`
		packageAPIRefused225(t, q, packageAPISubmit225(q, "MCP", "get_document_attachments", selectedRoot, docKey.Plaintext, other), "MCP", http.StatusForbidden, before, requests)
		packageAPIRefused225(t, q, packageAPISubmit225(q, "MCP", "add_document_attachment", selectedRoot, docKey.Plaintext, "{}"), "MCP", http.StatusForbidden, before, requests)
	})
	t.Run("REST refuses missing session and foreign origin", func(t *testing.T) {
		for _, mode := range []string{"session", "origin"} {
			tool := "get_document_attachments"
			if mode == "origin" {
				tool = "add_document_attachment"
			}
			r := packageAPIRequest225(q, q.f.ctx, "REST", tool, selectedRoot, "", "{}")
			want := http.StatusUnauthorized
			if mode == "session" {
				r.Header.Del("Cookie")
			} else {
				r.Header.Set("Origin", "https://foreign.invalid")
				want = http.StatusForbidden
			}
			before := packageFullState223(t, q)
			requests := q.storagePeer.requests.Load()
			w := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(w, r)
			packageAPIRefused225(t, q, w, "REST", want, before, requests)
		}
	})
	t.Run("linked selected-member privacy review blocks both observations", func(t *testing.T) {
		var member uuid.UUID
		if e := q.f.pool.QueryRow(q.f.ctx, "SELECT member_document_id FROM document_attachment_drafts_v1 a JOIN document_packages_v1 p ON p.id=a.package_id WHERE p.document_id=$1 AND p.org_id=$2", selectedRoot, q.f.org).Scan(&member); e != nil {
			t.Fatal(e)
		}
		request, e := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: member, Valid: true}, SubjectEmail: "synthetic@hash.example.test", SubjectName: "Synthetic participant", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			if _, e := q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: request.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); e != nil {
				t.Error(e)
			}
		}()
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		rootArgs := `{"document_id":"` + selectedRoot.String() + `"}`
		for _, transport := range []string{"REST", "MCP"} {
			packageAPIRefused225(t, q, packageAPISubmit225(q, transport, "get_document_attachments", selectedRoot, key.Plaintext, rootArgs), transport, http.StatusConflict, before, requests)
		}
	})
	t.Run("REST attachment budget enforced by reused router", func(t *testing.T) {
		router := q.f.s.Routes()
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		for i := 0; i < 11; i++ {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, packageAPIRequest225(q, q.f.ctx, "REST", "add_document_attachment", selectedRoot, "", "{}"))
			want := http.StatusBadRequest
			if i == 10 {
				want = http.StatusTooManyRequests
			}
			packageAPIRefused225(t, q, w, "REST", want, before, requests)
		}
	})
}
