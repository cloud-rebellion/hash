//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type signerPDFFieldFixture struct {
	ctx        context.Context
	pool       *pgxpool.Pool
	q          *generated.Queries
	s          *Server
	doc        *generated.Document
	recipient  *generated.Recipient
	field      *generated.DocumentField
	token      string
	sourceBody []byte
	native     *ownedPublicReadFixtureV1
}

// Every draft/party/field/source pin and ordinary Send is produced by the
// supported native APIs on the same original pool/runtime. An optional second
// party signs for real before the freeze guard is tested; no sent/signature
// row or wire-size cache is manufactured.
func newSignerPDFFieldFixture(t *testing.T, withPriorParty ...bool) *signerPDFFieldFixture {
	t.Helper()
	if len(withPriorParty) > 1 {
		t.Fatal("one explicit prior-party option supported")
	}
	prior := len(withPriorParty) == 1 && withPriorParty[0]
	native, doc := nativeBindingDocument259(t, true)
	f := native.f
	rows, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil || len(rows) != 1 {
		t.Fatal("genuine PDF field fixture signing party", err)
	}
	recipient := rows[0]
	base := "/api/v1/documents/" + doc.ID.String()
	text, err := json.Marshal(map[string]any{"recipient_id": recipient.ID.String(), "type": "text", "page": 1, "x_pct": 10, "y_pct": 10, "w_pct": 40, "h_pct": 5, "required": true, "label": "Reviewed reference"})
	if err != nil {
		t.Fatal(err)
	}
	response := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, base+"/fields", string(text), native.cookie)
	var created struct{ ID uuid.UUID }
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || created.ID == uuid.Nil {
		t.Fatalf("genuine text field birth=%d %s", response.Code, response.Body.String())
	}
	var other uuid.UUID
	if prior {
		response = submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, base+"/recipients", `{"role":"provider","name":"Previously signed party","email":"prior-party@pdf-field.test","locale":"en"}`, native.cookie)
		var party struct{ ID uuid.UUID }
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &party) != nil || party.ID == uuid.Nil {
			t.Fatalf("genuine prior party=%d %s", response.Code, response.Body.String())
		}
		other = party.ID
		body, _ := json.Marshal(map[string]any{"recipient_id": other.String(), "type": "signature", "page": 1, "x_pct": 20, "y_pct": 80, "w_pct": 40, "h_pct": 10, "required": true})
		response = submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, base+"/fields", string(body), native.cookie)
		if response.Code != http.StatusCreated {
			t.Fatalf("genuine prior party signature field=%d %s", response.Code, response.Body.String())
		}
	}
	sourceBody, err := readDocumentArtifact(f.ctx, f.s.Storage, doc, doc.PdfStorageKey.String, doc.PdfSha256, doc.PdfStorageVersionID)
	if err != nil || len(sourceBody) == 0 {
		t.Fatal("genuine exact imported source bytes", err)
	}
	response = submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, base+"/send", `{"lawful_basis":"contract"}`, native.cookie)
	var sent sendDocumentResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sent) != nil || len(sent.Links) != 1+map[bool]int{true: 1, false: 0}[prior] {
		t.Fatalf("genuine PDF field Send=%d %s", response.Code, response.Body.String())
	}
	token := ""
	for _, link := range sent.Links {
		invitation, parseErr := url.Parse(link.URL)
		if parseErr != nil || !strings.HasPrefix(invitation.Path, "/sign/") {
			t.Fatal("genuine PDF invitation missing", parseErr)
		}
		raw := strings.TrimPrefix(invitation.Path, "/sign/")
		if link.RecipientID == recipient.ID {
			token = raw
		}
		if link.RecipientID == other {
			result, signErr := ordinaryPreparationSign249(t, native, raw, "Previously signed party")
			if signErr != nil || result == nil || result.Completed {
				t.Fatal("genuine earlier party did not leave the main party pending", signErr)
			}
		}
	}
	if token == "" {
		t.Fatal("main party actual invitation missing")
	}
	doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	field, err := f.q.GetFieldForAuthoring(f.ctx, generated.GetFieldForAuthoringParams{ID: created.ID, DocumentID: doc.ID, OrgID: f.org})
	if err != nil || field.DocumentID != doc.ID {
		t.Fatal("genuine current text field absent", err)
	}
	recipient, err = f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	native.assertObserversOnlyV1(t)
	return &signerPDFFieldFixture{ctx: f.ctx, pool: f.pool, q: f.q, s: f.s, doc: doc, recipient: recipient, field: field, token: token, sourceBody: sourceBody, native: native}
}

func (f *signerPDFFieldFixture) request(t *testing.T) *http.Request {
	t.Helper()
	body, err := json.Marshal(submitFieldsInput{Values: []submitFieldValueInput{{FieldID: f.field.ID.String(), Value: "Agreed final reference"}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/sign/"+f.token+"/fields", strings.NewReader(string(body))).WithContext(f.ctx)
	route := chi.NewRouteContext()
	route.URLParams.Add("token", f.token)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
	rc, err := f.s.Sign.LookupByToken(f.ctx, auth.HashMagicToken(f.token))
	if err != nil {
		t.Fatal(err)
	}
	notice, err := f.s.signerPrivacyNotice(request, rc)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal("notice-only original read did not retire after its actual last use", err)
	}
	return request
}

func (f *signerPDFFieldFixture) assertNoFill(t *testing.T) {
	t.Helper()
	var value, filled bool
	var events int
	if err := f.pool.QueryRow(f.ctx, `SELECT value IS NOT NULL,completed_at IS NOT NULL,
		(SELECT count(*) FROM events WHERE document_id=$2 AND kind='document.field_filled') FROM document_fields WHERE id=$1`, f.field.ID, f.doc.ID).Scan(&value, &filled, &events); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if value || filled || events != 0 {
		t.Fatalf("refused fill committed value/completion/events=%t/%t/%d", value, filled, events)
	}
}

func TestSignerPDFFieldFillRetainsOriginalTokenThroughDocumentAndAuditWaitsE2E(t *testing.T) {
	for _, scenario := range []string{"rotated_while_document_waits", "extended_while_document_waits", "document_extended_while_document_waits", "expired_while_document_waits", "expired_while_audit_waits"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSignerPDFFieldFixture(t)
			var deadline time.Time
			if strings.HasPrefix(scenario, "expired") || strings.Contains(scenario, "extended") {
				deadline = time.Now().Add(500 * time.Millisecond)
				query, id := `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, f.recipient.ID
				if scenario == "document_extended_while_document_waits" {
					query, id = `UPDATE documents SET expires_at=$2 WHERE id=$1`, f.doc.ID
				}
				if _, err := f.pool.Exec(f.ctx, query, id, deadline); err != nil { //nolint:rawsql
					t.Fatal(err)
				}
			}
			request := f.request(t)
			mutation := startSignerFieldsBeforeMutation621(t, f, request)
			held, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Rollback(context.Background()) }()
			mutation.blocker = held
			query, event := "-- name: GetHTMLSendDocumentStateHeaderV1", "transactionid"
			if scenario == "expired_while_audit_waits" {
				if err := f.q.WithTx(held).AcquireOrgChainLock(f.ctx, f.doc.OrgID.String()); err != nil {
					t.Fatal(err)
				}
				query, event = "-- name: AcquireOrgChainLock", "advisory"
			} else if _, err := f.q.WithTx(held).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.doc.OrgID}); err != nil {
				t.Fatal(err)
			}
			result := mutation.result
			mutation.unblock()
			awaitSignerFieldLock(t, f, held, result, query, event)
			if scenario == "rotated_while_document_waits" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_hash=$2 WHERE id=$1`, f.recipient.ID, auth.HashMagicToken(uuid.NewString())); err != nil { //nolint:rawsql
					t.Fatal(err)
				}
			} else {
				if scenario == "extended_while_document_waits" {
					if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, f.recipient.ID, time.Now().Add(time.Hour)); err != nil { //nolint:rawsql
						t.Fatal(err)
					}
				} else if scenario == "document_extended_while_document_waits" {
					if _, err := held.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, f.doc.ID, time.Now().Add(time.Hour)); err != nil { //nolint:rawsql
						t.Fatal(err)
					}
				}
				<-time.After(time.Until(deadline) + 30*time.Millisecond)
			}
			if err := held.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case response := <-result:
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("stale field request status=%d body=%s", response.Code, response.Body.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("field request did not finish after releasing its exact lock")
			}
			f.assertNoFill(t)
			if strings.Contains(scenario, "extended") {
				fresh := httptest.NewRecorder()
				f.s.handleSignerSubmitFields(fresh, f.request(t))
				if fresh.Code != http.StatusOK {
					t.Fatalf("newly admitted extended link status=%d body=%s", fresh.Code, fresh.Body.String())
				}
			}
		})
	}
}

func TestSignerPDFFieldFillRefusesAnyPriorPartySignatureE2E(t *testing.T) {
	f := newSignerPDFFieldFixture(t, true)
	response := httptest.NewRecorder()
	f.s.handleSignerSubmitFields(response, f.request(t))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "frozen") {
		t.Fatalf("fill after another party signed status=%d body=%s", response.Code, response.Body.String())
	}
	f.assertNoFill(t)
}

func TestSignerPDFFieldFillBeforeSignatureCommitsCurrentNoticeE2E(t *testing.T) {
	f := newSignerPDFFieldFixture(t)
	response := httptest.NewRecorder()
	f.s.handleSignerSubmitFields(response, f.request(t))
	if response.Code != http.StatusOK {
		t.Fatalf("legacy fill status=%d body=%s", response.Code, response.Body.String())
	}
	var value, noticeDigest string
	if err := f.pool.QueryRow(f.ctx, `SELECT f.value,e.payload_json->>'notice_digest'
		FROM document_fields f JOIN events e ON e.document_id=f.document_id AND e.kind=$2 WHERE f.id=$1`, f.field.ID, audit.KindDocumentFieldFill).Scan(&value, &noticeDigest); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if value != "Agreed final reference" || noticeDigest == "" {
		t.Fatalf("current fill value=%q noticeDigest=%q", value, noticeDigest)
	}
}

func awaitSignerFieldLock(t *testing.T, f *signerPDFFieldFixture, held pgx.Tx, result <-chan *httptest.ResponseRecorder, query, event string) {
	t.Helper()
	var holderPID int32
	if err := held.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case response := <-result:
			t.Fatalf("field request returned before its lock wait: %d %s", response.Code, response.Body.String())
		default:
		}
		var waiting bool
		if err := f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE datname=current_database()
			AND position($1 in query)>0 AND wait_event=$2 AND $3=ANY(pg_blocking_pids(a.pid)))`, query, event, holderPID).Scan(&waiting); err != nil { //nolint:rawsql
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("field request did not reach the held synthetic lock")
}

// The real handler has captured its original lookup/notice before decoding the
// body. Pause at that actual input read, then let the caller establish its
// original mutation lock. This preserves the late-authority branch now that
// native lookup itself correctly takes a document SHARE lock.
type signerFieldsMutation621 struct {
	body                     io.ReadCloser
	ctx                      context.Context
	entered, release, done   chan struct{}
	enteredOnce, releaseOnce sync.Once
	result                   chan *httptest.ResponseRecorder
	cancel                   context.CancelFunc
	blocker                  pgx.Tx
}

func (g *signerFieldsMutation621) Read(p []byte) (int, error) {
	g.enteredOnce.Do(func() { close(g.entered) })
	select {
	case <-g.release:
		return g.body.Read(p)
	case <-g.ctx.Done():
		return 0, g.ctx.Err()
	}
}
func (g *signerFieldsMutation621) Close() error { return g.body.Close() }
func (g *signerFieldsMutation621) unblock()     { g.releaseOnce.Do(func() { close(g.release) }) }
func startSignerFieldsBeforeMutation621(t *testing.T, f *signerPDFFieldFixture, request *http.Request) *signerFieldsMutation621 {
	t.Helper()
	ctx, cancel := context.WithCancel(request.Context())
	g := &signerFieldsMutation621{body: request.Body, ctx: ctx, entered: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{}), result: make(chan *httptest.ResponseRecorder, 1), cancel: cancel}
	request = request.WithContext(ctx)
	request.Body = g
	t.Cleanup(func() {
		cancel()
		g.unblock()
		if g.blocker != nil {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			_ = g.blocker.Rollback(cleanup)
			stop()
		}
		select {
		case <-g.done:
		case <-time.After(4 * time.Second):
			t.Error("actual signer field mutation did not join before fixture cleanup")
		}
	})
	go func() {
		defer close(g.done)
		w := httptest.NewRecorder()
		f.s.securityHeaders(http.HandlerFunc(f.s.handleSignerSubmitFields)).ServeHTTP(w, request)
		g.result <- w
	}()
	select {
	case <-g.entered:
		return g
	case response := <-g.result:
		t.Fatalf("actual signer field handler refused before original read/notice/body gate: %d %s", response.Code, response.Body.String())
	case <-time.After(3 * time.Second):
		t.Fatal("actual signer field handler did not reach admitted input body")
	}
	return g
}
