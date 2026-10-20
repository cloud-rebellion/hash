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
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type signerPDFFieldFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	q         *generated.Queries
	s         *Server
	doc       *generated.Document
	recipient *generated.Recipient
	field     *generated.DocumentField
	token     string
}

func newSignerPDFFieldFixture(t *testing.T) *signerPDFFieldFixture {
	t.Helper()
	ctx, pool, q, server, org, owner := setupDSRE2E(t)
	doc, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{OrgID: org, SenderID: owner, Name: "Synthetic signer PDF fields", PdfStorageKey: pgtype.Text{String: "fixture.pdf", Valid: true}, PdfSha256: make([]byte, 32), PdfStorageVersionID: pgtype.Text{String: "synthetic-exact-source-version", Valid: true}, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	token, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Name: "Synthetic field recipient", Email: uuid.NewString() + "@pdf-field.test", Locale: "en",
		MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	field, err := q.CreateDraftField(ctx, generated.CreateDraftFieldParams{DocumentID: doc.ID, OrgID: org, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true}, Type: "text", Page: 1,
		XPct: pctToNumeric(10), YPct: pctToNumeric(10), WPct: pctToNumeric(40), HPct: pctToNumeric(5), Required: true, Label: pgtype.Text{String: "Reviewed reference", Valid: true}, OptionsJson: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.ConfirmDocumentLawfulBasis(ctx, generated.ConfirmDocumentLawfulBasisParams{DocumentID: doc.ID, OrgID: org, LawfulBasis: "contract", Via: "test", ConfirmedBy: pgtype.UUID{Bytes: owner, Valid: true}}); err != nil {
		t.Fatal(err)
	}
	doc = sendDSRDocumentE2E(t, ctx, pool, q, doc, recipient)
	server.OperatorName, server.PrivacyContact = "Synthetic operator", "privacy@hash.example.test"
	server.SupervisoryAuthority, server.PrivacyPolicyURL = "Synthetic DPA", "https://hash.example.test/privacy"
	server.Sign = &sign.Engine{Pool: pool, Queries: q, Audit: server.Audit}
	return &signerPDFFieldFixture{ctx: ctx, pool: pool, q: q, s: server, doc: doc, recipient: recipient, field: field, token: token}
}

func (f *signerPDFFieldFixture) request(t *testing.T) *http.Request {
	t.Helper()
	body, err := json.Marshal(submitFieldsInput{Values: []submitFieldValueInput{{FieldID: f.field.ID.String(), Value: "Agreed final reference"}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/sign/"+f.token+"/fields", strings.NewReader(string(body)))
	route := chi.NewRouteContext()
	route.URLParams.Add("token", f.token)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
	rc, err := f.s.Sign.LookupByToken(f.ctx, auth.HashMagicToken(f.token))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.CloseReadV1() })
	notice, err := f.s.signerPrivacyNotice(request, rc)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
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
			held, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Rollback(context.Background()) }()
			query, event := "-- name: GetDocumentForUpdate", "transactionid"
			if scenario == "expired_while_audit_waits" {
				if err := f.q.WithTx(held).AcquireOrgChainLock(f.ctx, f.doc.OrgID.String()); err != nil {
					t.Fatal(err)
				}
				query, event = "-- name: AcquireOrgChainLock", "advisory"
			} else if _, err := f.q.WithTx(held).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.doc.OrgID}); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				response := httptest.NewRecorder()
				f.s.handleSignerSubmitFields(response, request)
				result <- response
			}()
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
	f := newSignerPDFFieldFixture(t)
	var other uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `INSERT INTO recipients(document_id,role,name,email,magic_token_hash,magic_token_expires_at,locale,status)
		VALUES($1,'provider','Previously signed party',$2,$3,clock_timestamp()+interval '1 hour','en','signed') RETURNING id`, f.doc.ID, uuid.NewString()+"@pdf-signed.test", auth.HashMagicToken(uuid.NewString())).Scan(&other); err != nil { //nolint:rawsql -- simulate a historic multiparty ceremony
		t.Fatal(err)
	}
	if _, err := f.q.InsertSignature(f.ctx, generated.InsertSignatureParams{DocumentID: f.doc.ID, RecipientID: other, FieldID: f.field.ID, Font: "Caveat", TypedName: "Previously signed party", ImageStorageKey: "synthetic-signature", ImageSha256: make([]byte, 32), ImageVersionID: pgtype.Text{String: "synthetic-exact-signature-version", Valid: true}}); err != nil {
		t.Fatal(err)
	}
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
