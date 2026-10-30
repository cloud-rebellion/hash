//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests use actual PostgreSQL and the real exact-version storage client
// against a bounded synthetic S3 peer. They prove read admission and response
// metadata, not browser PDF parsing, Chromium layout or provider acceptance.
type signerReadStorageE2E struct {
	base        *fieldBrowserStoragePeer
	key         string
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

func (p *signerReadStorageE2E) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.release != nil && r.Method == http.MethodGet && r.URL.Path == "/"+p.base.bucket+"/"+p.key {
		select {
		case p.entered <- struct{}{}:
		default:
		}
		select {
		case <-p.release:
		case <-r.Context().Done():
			return
		}
	}
	p.base.ServeHTTP(w, r)
}

func (p *signerReadStorageE2E) unblock() {
	if p.release != nil {
		p.releaseOnce.Do(func() { close(p.release) })
	}
}

func attachSignerReadStorageE2E(t *testing.T, f *signerPDFFieldFixture, block bool) ([]byte, *signerReadStorageE2E) {
	t.Helper()
	// Serve the exact source bytes produced by the genuine admitted import.
	// A public-read fixture must not rewrite a sent contract's digest merely
	// to match a second synthetic PDF. The new peer changes transport only.
	body := bytes.Clone(f.sourceBody)
	if len(body) == 0 {
		t.Fatal("original genuine source bytes are unavailable")
	}
	peer := &signerReadStorageE2E{key: f.doc.PdfStorageKey.String, base: &fieldBrowserStoragePeer{
		bucket: "hash-signer-read-fixture", version: f.doc.PdfStorageVersionID.String,
		objects: map[string][]byte{f.doc.PdfStorageKey.String: body}, reads: make(map[string]int),
	}}
	if block {
		peer.entered, peer.release = make(chan struct{}, 1), make(chan struct{})
	}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	t.Cleanup(peer.unblock)
	client, err := storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1",
		Bucket: peer.base.bucket, AccessKey: "synthetic-public-read-access", SecretKey: "synthetic-public-read-secret",
		BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	f.s.Storage, f.s.Sign.Storage = client, client
	return body, peer
}

func signerReadRequestE2E(token, endpoint string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/sign/"+token+endpoint, nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("token", token)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
}

func invokeSignerReadE2E(s *Server, request *http.Request, endpoint string) *httptest.ResponseRecorder {
	// Direct handler fixtures retain the same eight-second owner as their
	// blocking cases; production routes supply their own finite middleware owner.
	ctx, cancel := context.WithTimeout(request.Context(), 8*time.Second)
	defer cancel()
	request = request.WithContext(ctx)
	w := httptest.NewRecorder()
	var handler http.HandlerFunc
	switch endpoint {
	case "":
		handler = s.handleSignerContext
	case "/pdf":
		handler = s.handleSignerPDF
	case "/fields":
		handler = s.handleSignerListFields
	default:
		panic("unknown synthetic signer read endpoint")
	}
	s.securityHeaders(handler).ServeHTTP(w, request)
	return w
}

func assertSignerObservationHeadersE2E(t *testing.T, w *httptest.ResponseRecorder, observation signerPDFObservation) {
	t.Helper()
	expected := map[string]string{"X-Hash-Document-Id": observation.DocumentID.String(),
		"X-Hash-Recipient-Id": observation.RecipientID.String(), "X-Hash-PDF-SHA256": observation.PDFSHA256,
		"X-Hash-HTML-Source-Commitment": observation.HTMLSourceCommitment}
	if observation.PageCount != 0 {
		expected["X-Hash-PDF-Pages"] = strconv.Itoa(int(observation.PageCount))
	} else {
		expected["X-Hash-PDF-Pages"] = ""
	}
	if observation.MaterializationRevision != 0 {
		expected["X-Hash-Materialization-Revision"] = strconv.Itoa(int(observation.MaterializationRevision))
	} else {
		expected["X-Hash-Materialization-Revision"] = ""
	}
	for name, value := range expected {
		if w.Header().Get(name) != value {
			t.Fatalf("public %s=%q want=%q", name, w.Header().Get(name), value)
		}
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("public read is missing no-store")
	}
}

func assertSignerReadHasNoSourceLeakE2E(t *testing.T, w *httptest.ResponseRecorder, doc *generated.Document) {
	t.Helper()
	text := w.Body.String()
	for _, secret := range []string{doc.OrgID.String(), doc.PdfStorageKey.String, doc.PdfStorageVersionID.String} {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatal("public read exposed a private organization/storage pin")
		}
	}
	for _, key := range []string{`"org_id"`, `"pdf_storage_key"`, `"pdf_storage_version_id"`, `"html_source_json"`, `"html_current_source_json"`, `"master"`, `"party_bindings"`} {
		if strings.Contains(text, key) {
			t.Fatalf("public read exposed private source property %s", key)
		}
	}
	for name, values := range w.Header() {
		for _, value := range values {
			if strings.Contains(value, doc.PdfStorageKey.String) || strings.Contains(value, doc.PdfStorageVersionID.String) || strings.Contains(value, doc.OrgID.String()) {
				t.Fatalf("public %s exposed a private storage/organization pin", name)
			}
		}
	}
}

func signerReadEventCountE2E(t *testing.T, f *signerPDFFieldFixture) int {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1`, f.doc.ID).Scan(&count); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	return count
}

func assertSignerReadNoEffectsE2E(t *testing.T, f *signerPDFFieldFixture, eventsBefore int) {
	t.Helper()
	var viewed, value, filled bool
	if err := f.pool.QueryRow(f.ctx, `SELECT r.first_viewed_at IS NOT NULL,f.value IS NOT NULL,f.completed_at IS NOT NULL
FROM recipients r JOIN document_fields f ON f.document_id=r.document_id WHERE r.id=$1 AND f.id=$2`, f.recipient.ID, f.field.ID).Scan(&viewed, &value, &filled); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if viewed || value || filled || signerReadEventCountE2E(t, f) != eventsBefore {
		t.Fatal("public GET committed view, field or audit effects")
	}
}

func assertSignerReadRefusedE2E(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusGone && w.Code != http.StatusConflict && w.Code != http.StatusNotFound {
		t.Fatalf("changed read status=%d body=%s", w.Code, w.Body.String())
	}
	for _, name := range []string{"X-Hash-Document-Id", "X-Hash-Recipient-Id", "X-Hash-PDF-SHA256", "X-Hash-PDF-Pages", "X-Hash-HTML-Source-Commitment", "X-Hash-Materialization-Revision"} {
		if w.Header().Get(name) != "" {
			t.Fatalf("refused public read emitted %s", name)
		}
	}
	if strings.Contains(w.Body.String(), "%PDF-") || strings.Contains(w.Body.String(), `"fields"`) || strings.Contains(w.Body.String(), `"pdf_observation"`) {
		t.Fatal("refused read emitted PDF, field or context observation body")
	}
}

func TestSignerPDFReadObservationMatchesContextFieldsAndExactBytesE2E(t *testing.T) {
	f := newSignerPDFFieldFixture(t)
	body, _ := attachSignerReadStorageE2E(t, f, false)
	events := signerReadEventCountE2E(t, f)
	contextResponse := invokeSignerReadE2E(f.s, signerReadRequestE2E(f.token, ""), "")
	if contextResponse.Code != http.StatusOK {
		t.Fatalf("public context status=%d body=%s", contextResponse.Code, contextResponse.Body.String())
	}
	var response struct {
		Observation signerPDFObservation `json:"pdf_observation"`
	}
	if err := json.Unmarshal(contextResponse.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	expected := signerPDFObservation{DocumentID: f.doc.ID, RecipientID: f.recipient.ID, PDFSHA256: hex.EncodeToString(f.doc.PdfSha256)}
	if response.Observation != expected {
		t.Fatalf("static PDF observation=%+v want=%+v", response.Observation, expected)
	}
	assertSignerReadHasNoSourceLeakE2E(t, contextResponse, f.doc)
	for _, endpoint := range []string{"/pdf", "/fields"} {
		w := invokeSignerReadE2E(f.s, signerReadRequestE2E(f.token, endpoint), endpoint)
		if w.Code != http.StatusOK {
			t.Fatalf("public %s status=%d body=%s", endpoint, w.Code, w.Body.String())
		}
		assertSignerObservationHeadersE2E(t, w, expected)
		assertSignerReadHasNoSourceLeakE2E(t, w, f.doc)
		if endpoint == "/pdf" && !bytes.Equal(w.Body.Bytes(), body) {
			t.Fatal("public PDF differs from its exact observed bytes")
		}
		if endpoint == "/fields" && !strings.Contains(w.Body.String(), f.field.ID.String()) {
			t.Fatal("public fields omitted the exact recipient field")
		}
	}
	assertSignerReadNoEffectsE2E(t, f, events)
}

func setupSignerHTMLReadE2E(t *testing.T) (lifecycleAuthorizationFixture, *htmlCreationStorageE2E, *generated.Document, *generated.Recipient, string, signerPDFObservation) {
	t.Helper()
	native := newOwnedPublicReadFixtureV1(t)
	doc, parties := native.createSentV1(t)
	f, peer := native.f, native.storagePeer
	if len(parties) != 2 {
		t.Fatal("genuine reviewed HTML ceremony requires two parties")
	}
	token := parties[0].Token
	recipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: parties[0].RecipientID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	expected := signerPDFObservation{DocumentID: doc.ID, RecipientID: recipient.ID, PDFSHA256: hex.EncodeToString(doc.PdfSha256),
		HTMLSourceCommitment: commitment, MaterializationRevision: doc.HtmlCurrentMaterializationSequence.Int32, PageCount: doc.HtmlCurrentPageCount.Int32}
	if expected.PageCount < 1 || expected.MaterializationRevision != 1 || expected.HTMLSourceCommitment == "" {
		t.Fatal("HTML fixture is missing its real registered observation")
	}
	return f, peer, doc, recipient, token, expected
}

func TestSignerHTMLReadObservationUsesRegisteredHistoryWithoutLeakingSourceE2E(t *testing.T) {
	f, _, doc, _, token, expected := setupSignerHTMLReadE2E(t)
	beforeReads := htmlContractInventoryE2E(t, f)
	for _, endpoint := range []string{"", "/pdf", "/fields"} {
		w := invokeSignerReadE2E(f.s, signerReadRequestE2E(token, endpoint), endpoint)
		if w.Code != http.StatusOK {
			t.Fatalf("registered HTML %s status=%d body=%s", endpoint, w.Code, w.Body.String())
		}
		assertSignerReadHasNoSourceLeakE2E(t, w, doc)
		if endpoint == "" {
			var response struct {
				Observation signerPDFObservation `json:"pdf_observation"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Observation != expected {
				t.Fatalf("registered HTML context observation mismatch error=%v", err)
			}
		} else {
			assertSignerObservationHeadersE2E(t, w, expected)
		}
	}
	if !bytes.Equal(beforeReads, htmlContractInventoryE2E(t, f)) {
		t.Fatal("registered HTML public GET changed the document ceremony or audit inventory")
	}
}

func TestSignerPDFReadRetainsOriginalAdmissionThroughStorageWaitE2E(t *testing.T) {
	for _, scenario := range []string{"natural_expiry", "revoked_token", "same_hash_extension", "document_extension", "pdf_source_swap", "deleted_document", "terminal_document", "printed_identity_change", "notice_config_change"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSignerPDFFieldFixture(t)
			_, peer := attachSignerReadStorageE2E(t, f, true)
			events := signerReadEventCountE2E(t, f)
			var deadline time.Time
			if scenario == "natural_expiry" || scenario == "same_hash_extension" || scenario == "document_extension" {
				deadline = time.Now().Add(750 * time.Millisecond)
				query, id := `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, f.recipient.ID
				if scenario == "document_extension" {
					query, id = `UPDATE documents SET expires_at=$2 WHERE id=$1`, f.doc.ID
				}
				if _, err := f.pool.Exec(f.ctx, query, id, deadline); err != nil {
					t.Fatal(err)
				} //nolint:rawsql
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			result := make(chan *httptest.ResponseRecorder, 1)
			done := make(chan struct{})
			request := signerReadRequestE2E(f.token, "/pdf")
			request = request.WithContext(context.WithValue(ctx, chi.RouteCtxKey, request.Context().Value(chi.RouteCtxKey)))
			go func() { defer close(done); result <- invokeSignerReadE2E(f.s, request, "/pdf") }()
			t.Cleanup(func() {
				cancel()
				peer.unblock()
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Error("public PDF did not drain before fixture cleanup")
				}
			})
			select {
			case <-peer.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("public PDF did not enter exact storage wait")
			}
			switch scenario {
			case "revoked_token":
				_, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_hash=$2 WHERE id=$1`, f.recipient.ID, auth.HashMagicToken(uuid.NewString()))
				if err != nil {
					t.Fatal(err)
				} //nolint:rawsql
			case "same_hash_extension":
				_, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, f.recipient.ID, time.Now().Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				} //nolint:rawsql
			case "document_extension":
				_, err := f.pool.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, f.doc.ID, time.Now().Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				} //nolint:rawsql
			case "pdf_source_swap":
				_, err := f.pool.Exec(f.ctx, `UPDATE documents SET pdf_sha256=$2 WHERE id=$1 AND org_id=$3`, f.doc.ID, bytes.Repeat([]byte{0x71}, 32), f.doc.OrgID)
				if err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- simulate independently changed persisted source
			case "deleted_document":
				_, err := f.pool.Exec(f.ctx, `UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1`, f.doc.ID)
				if err != nil {
					t.Fatal(err)
				} //nolint:rawsql
			case "terminal_document":
				_, err := f.pool.Exec(f.ctx, `UPDATE documents SET status='voided' WHERE id=$1`, f.doc.ID)
				if err != nil {
					t.Fatal(err)
				} //nolint:rawsql
			case "printed_identity_change":
				_, err := f.pool.Exec(f.ctx, `UPDATE recipients SET email=$2 WHERE id=$1`, f.recipient.ID, "Changed@synthetic-read.test")
				if err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- model independently changed persisted identity
			case "notice_config_change":
				f.s.PrivacyContact = "changed-privacy@hash.example.test"
			}
			if !deadline.IsZero() {
				time.Sleep(time.Until(deadline) + 30*time.Millisecond)
			}
			peer.unblock()
			select {
			case w := <-result:
				assertSignerReadRefusedE2E(t, w)
			case <-time.After(4 * time.Second):
				t.Fatal("public read did not finish after storage release")
			}
			assertSignerReadNoEffectsE2E(t, f, events)
			if scenario == "same_hash_extension" || scenario == "document_extension" {
				w := invokeSignerReadE2E(f.s, signerReadRequestE2E(f.token, "/pdf"), "/pdf")
				if w.Code != http.StatusOK {
					t.Fatalf("fresh extended admission status=%d body=%s", w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestSignerPublicReadRechecksOriginalAdmissionAfterDatabaseWaitE2E(t *testing.T) {
	for _, endpoint := range []string{"", "/fields"} {
		for _, scenario := range []string{"revoked_token", "extended_original_expiry"} {
			t.Run(endpoint+"/"+scenario, func(t *testing.T) {
				f := newSignerPDFFieldFixture(t)
				_, _ = attachSignerReadStorageE2E(t, f, false)
				events := signerReadEventCountE2E(t, f)
				var deadline time.Time
				if scenario == "extended_original_expiry" {
					deadline = time.Now().Add(750 * time.Millisecond)
					if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, f.recipient.ID, deadline); err != nil {
						t.Fatal(err)
					} //nolint:rawsql -- original admitted deadline
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				request := signerReadRequestE2E(f.token, endpoint)
				request = request.WithContext(context.WithValue(ctx, chi.RouteCtxKey, request.Context().Value(chi.RouteCtxKey)))
				// Admit through the real endpoint-specific native lookup BEFORE holding
				// the final read's parent. The old table hold stopped after acquiring a
				// recipient SHARE lock, so the fixture's token mutation blocked itself.
				var original *sign.RecipientContext
				var err error
				if endpoint == "/fields" {
					original, err = f.s.Sign.LookupSignerFieldsByTokenV1(ctx, auth.HashMagicToken(f.token))
				} else {
					original, err = f.s.Sign.LookupByToken(ctx, auth.HashMagicToken(f.token))
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := original.CloseReadV1(); err != nil {
						t.Error(err)
					}
				})
				observation, err := f.s.captureSignerReadObservation(request, original)
				if err != nil {
					t.Fatal(err)
				}
				held, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					cleanup, stop := context.WithTimeout(context.Background(), time.Second)
					defer stop()
					_ = held.Rollback(cleanup)
				}()
				if _, err = f.q.WithTx(held).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.doc.OrgID}); err != nil {
					t.Fatal(err)
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				done := make(chan struct{})
				t.Cleanup(func() {
					cancel()
					cleanup, stop := context.WithTimeout(context.Background(), time.Second)
					_ = held.Rollback(cleanup)
					stop()
					select {
					case <-done:
					case <-time.After(4 * time.Second):
						t.Error("original final native read did not join before fixture cleanup")
					}
				})
				go func() {
					defer close(done)
					w := httptest.NewRecorder()
					var responseErr error
					if endpoint == "/fields" {
						page, e := f.s.Sign.SignerFieldListV1(ctx, original, func(fresh *sign.RecipientContext) error {
							return f.s.validateSignerReadObservation(request, original, observation, fresh)
						})
						if page != nil {
							defer page.CloseConsumerV1()
						}
						responseErr = e
					} else {
						responseErr = f.s.recheckSignerRead(request, original, observation)
					}
					if responseErr != nil {
						writeSignerReadError(w, responseErr)
					} else {
						w.WriteHeader(http.StatusOK)
					}
					result <- w
				}()
				query := "-- name: GetSignerDocumentReadHeaderV1"
				if endpoint == "/fields" {
					query = "-- name: GetHTMLSendDocumentStateHeaderV1"
				}
				awaitSignerReadDatabaseWaitE2E(t, f, held, result, query, "transactionid")
				if scenario == "revoked_token" {
					_, err = held.Exec(f.ctx, `UPDATE recipients SET magic_token_hash=$2 WHERE id=$1`, f.recipient.ID, auth.HashMagicToken(uuid.NewString())) //nolint:rawsql -- same parent-owning independent transaction
				} else {
					_, err = held.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, f.recipient.ID, time.Now().Add(time.Hour)) //nolint:rawsql -- never renew the original opaque admission
					time.Sleep(time.Until(deadline) + 30*time.Millisecond)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err = held.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case w := <-result:
					assertSignerReadRefusedE2E(t, w)
				case <-time.After(4 * time.Second):
					t.Fatal("final native read did not finish after exact parent release")
				}
				assertSignerReadNoEffectsE2E(t, f, events)
			})
		}
	}
}

func TestSignerHTMLReadRetainsFinalLocksAndDeadlineThroughHistoryWaitE2E(t *testing.T) {
	for _, scenario := range []string{"expiry_during_final_history_wait", "rotation_waits_for_final_read", "document_change_waits_for_final_read"} {
		t.Run(scenario, func(t *testing.T) {
			f, base, doc, recipient, token, expected := setupSignerHTMLReadE2E(t)
			current, err := f.q.GetCurrentHTMLDocumentMaterialization(f.ctx, generated.GetCurrentHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: doc.OrgID})
			if err != nil {
				t.Fatal(err)
			}
			peer := attachHTMLHistoryObjectReadE2E(t, f, base, current, true, false)
			var deadline time.Time
			if scenario == "expiry_during_final_history_wait" {
				deadline = time.Now().Add(750 * time.Millisecond)
				if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, recipient.ID, deadline); err != nil {
					t.Fatal(err)
				} //nolint:rawsql
			}
			beforeReads := htmlContractInventoryE2E(t, f)
			proxy := &signerPDFFieldFixture{ctx: f.ctx, pool: f.pool, doc: doc}
			eventsBefore := signerReadEventCountE2E(t, proxy)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			request := signerReadRequestE2E(token, "/pdf")
			request = request.WithContext(context.WithValue(ctx, chi.RouteCtxKey, request.Context().Value(chi.RouteCtxKey)))
			result := make(chan *httptest.ResponseRecorder, 1)
			done := make(chan struct{})
			go func() { defer close(done); result <- invokeSignerReadE2E(f.s, request, "/pdf") }()
			// Establish failure cleanup before the first external wait too. Later
			// held-query cleanup additionally joins its exact blocker.
			t.Cleanup(func() {
				cancel()
				peer.unblock()
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Error("initial HTML storage read did not join before fixture cleanup")
				}
			})
			select {
			case version := <-peer.entered:
				if version != current.PdfVersionID {
					t.Fatal("public HTML read did not request exact registered version")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("public HTML did not enter external storage wait")
			}
			held, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Rollback(context.Background()) }()
			t.Cleanup(func() {
				cancel()
				peer.unblock()
				_ = held.Rollback(context.Background())
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Error("final history read did not drain before fixture cleanup")
				}
			})
			if _, err = held.Exec(f.ctx, `LOCK TABLE html_document_materializations IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			} //nolint:rawsql
			peer.unblock()
			query := "-- name: GetSignerCurrentMaterializationHeaderV1"
			awaitSignerReadDatabaseWaitE2E(t, proxy, held, result, query)
			var holderPID, readerPID int32
			if err = held.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); err != nil {
				t.Fatal(err)
			} //nolint:rawsql
			if err = f.pool.QueryRow(f.ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND position($1 in query)>0 AND wait_event='relation' AND $2=ANY(pg_blocking_pids(pid)) LIMIT 1`, query, holderPID).Scan(&readerPID); err != nil {
				t.Fatal(err)
			} //nolint:rawsql
			var mutation <-chan error
			if scenario != "expiry_during_final_history_wait" {
				mutationCtx, mutationCancel := context.WithTimeout(context.Background(), 8*time.Second)
				mutationResult := make(chan error, 1)
				mutationDone := make(chan struct{})
				mutation = mutationResult
				statement, id, arg := `UPDATE recipients SET magic_token_hash=$2 WHERE id=$1 AND document_id=$3`, recipient.ID, any(auth.HashMagicToken(uuid.NewString()))
				if scenario == "document_change_waits_for_final_read" {
					statement, id, arg = `UPDATE documents SET name=$2 WHERE id=$1 AND org_id=$3`, doc.ID, "Independently changed source observation name"
				}
				third := doc.ID
				if scenario == "document_change_waits_for_final_read" {
					third = doc.OrgID
				}
				go func() {
					defer close(mutationDone)
					tag, err := f.pool.Exec(mutationCtx, statement, id, arg, third)
					if err == nil && tag.RowsAffected() != 1 {
						err = pgx.ErrNoRows
					}
					mutationResult <- err
				}() //nolint:rawsql -- controlled independently authorized row change
				t.Cleanup(func() {
					mutationCancel()
					select {
					case <-mutationDone:
					case <-time.After(4 * time.Second):
						t.Error("serialized read mutation did not drain")
					}
				})
				awaitSignerReadMutationWaitE2E(t, f.ctx, f.pool, mutationResult, readerPID, statement)
			} else {
				time.Sleep(time.Until(deadline) + 30*time.Millisecond)
			}
			if err = held.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case w := <-result:
				if scenario == "expiry_during_final_history_wait" {
					assertSignerReadRefusedE2E(t, w)
				} else {
					if w.Code != http.StatusOK {
						t.Fatalf("serialized prior read status=%d body=%s", w.Code, w.Body.String())
					}
					assertSignerObservationHeadersE2E(t, w, expected)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("final history read did not finish after releasing exact wait")
			}
			if mutation != nil {
				select {
				case err := <-mutation:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(4 * time.Second):
					t.Fatal("mutation did not finish after releasing final read locks")
				}
				if scenario == "rotation_waits_for_final_read" {
					assertSignerReadRefusedE2E(t, invokeSignerReadE2E(f.s, signerReadRequestE2E(token, ""), ""))
				}
			} else if !bytes.Equal(beforeReads, htmlContractInventoryE2E(t, f)) {
				t.Fatal("expired final history read changed ceremony or audit inventory")
			}
			retained, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: doc.OrgID})
			if err != nil || retained.FirstViewedAt.Valid || signerReadEventCountE2E(t, proxy) != eventsBefore {
				t.Fatalf("final history read committed view/audit effects error=%v", err)
			}
		})
	}
}

func TestSignerFieldSaveReturnsDurableObservationAndRejectsIdentityDriftE2E(t *testing.T) {
	for _, scenario := range []string{"successful_save", "printed_name", "mailbox", "role", "routing_order", "locale"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSignerPDFFieldFixture(t)
			_, _ = attachSignerReadStorageE2E(t, f, false)
			eventsBefore := signerReadEventCountE2E(t, f)
			request := f.request(t)
			if scenario == "successful_save" {
				w := httptest.NewRecorder()
				f.s.securityHeaders(http.HandlerFunc(f.s.handleSignerSubmitFields)).ServeHTTP(w, request)
				if w.Code != http.StatusOK {
					t.Fatalf("durable field save status=%d body=%s", w.Code, w.Body.String())
				}
				assertSignerObservationHeadersE2E(t, w, signerPDFObservation{DocumentID: f.doc.ID, RecipientID: f.recipient.ID, PDFSHA256: hex.EncodeToString(f.doc.PdfSha256)})
				assertSignerReadHasNoSourceLeakE2E(t, w, f.doc)
				var value string
				var completed bool
				if err := f.pool.QueryRow(f.ctx, `SELECT value,completed_at IS NOT NULL FROM document_fields WHERE id=$1 AND document_id=$2`, f.field.ID, f.doc.ID).Scan(&value, &completed); err != nil {
					t.Fatal(err)
				} //nolint:rawsql
				if value != "Agreed final reference" || !completed || signerReadEventCountE2E(t, f) != eventsBefore+1 {
					t.Fatal("successful receipt did not describe a durable field/audit commit")
				}
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			request = request.WithContext(context.WithValue(ctx, chi.RouteCtxKey, request.Context().Value(chi.RouteCtxKey)))
			mutation := startSignerFieldsBeforeMutation621(t, f, request)
			held, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Rollback(context.Background()) }()
			mutation.blocker = held
			if _, err = f.q.WithTx(held).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.doc.OrgID}); err != nil {
				t.Fatal(err)
			}
			result := mutation.result
			mutation.unblock()
			awaitSignerFieldLock(t, f, held, result, "-- name: GetHTMLSendDocumentStateHeaderV1", "transactionid")
			statement, arg := `UPDATE recipients SET name=$2 WHERE id=$1 AND document_id=$3`, any("Changed printed name")
			switch scenario {
			case "mailbox":
				statement, arg = `UPDATE recipients SET email=$2 WHERE id=$1 AND document_id=$3`, "Changed@synthetic-read.test"
			case "role":
				statement, arg = `UPDATE recipients SET role=$2 WHERE id=$1 AND document_id=$3`, "provider"
			case "routing_order":
				statement, arg = `UPDATE recipients SET order_index=$2 WHERE id=$1 AND document_id=$3`, int32(7)
			case "locale":
				statement, arg = `UPDATE recipients SET locale=$2 WHERE id=$1 AND document_id=$3`, "sv"
			}
			if _, err = held.Exec(f.ctx, statement, f.recipient.ID, arg, f.doc.ID); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- independent row change under its required parent lock, committed before the original save resumes
			if err = held.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case w := <-result:
				if w.Code != http.StatusUnauthorized && w.Code != http.StatusConflict {
					t.Fatalf("identity-drift save status=%d body=%s", w.Code, w.Body.String())
				}
				if w.Header().Get("X-Hash-PDF-SHA256") != "" || strings.Contains(w.Body.String(), `"updated"`) {
					t.Fatal("refused save emitted a durable source receipt or update body")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("identity-drift save did not finish after exact document lock release")
			}
			assertSignerReadNoEffectsE2E(t, f, eventsBefore)
		})
	}
}

func awaitSignerReadMutationWaitE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, result <-chan error, blockerPID int32, statement string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-result:
			t.Fatalf("mutation bypassed final read locks: %v", err)
		default:
		}
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND position($1 in query)>0 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))`, statement, blockerPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		} //nolint:rawsql
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("credential/document mutation did not wait behind exact final read transaction")
}

func awaitSignerReadDatabaseWaitE2E(t *testing.T, f *signerPDFFieldFixture, held pgx.Tx, result <-chan *httptest.ResponseRecorder, query string, events ...string) {
	t.Helper()
	event := "relation"
	if len(events) > 1 {
		t.Fatal("one explicit database wait event supported")
	}
	if len(events) == 1 {
		event = events[0]
	}
	var pid int32
	if err := held.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	} //nolint:rawsql
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case w := <-result:
			t.Fatalf("public read returned before exact query wait: %d %s", w.Code, w.Body.String())
		default:
		}
		var waiting bool
		if err := f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND position($1 in query)>0 AND wait_event=$3 AND $2=ANY(pg_blocking_pids(pid)))`, query, pid, event).Scan(&waiting); err != nil {
			t.Fatal(err)
		} //nolint:rawsql
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("public read did not reach its exact held database query")
}
