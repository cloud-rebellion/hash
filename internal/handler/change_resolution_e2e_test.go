//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/actiontoken"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type changeResolutionFixture struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	q      *generated.Queries
	s      *Server
	org    uuid.UUID
	owner  uuid.UUID
	cookie string
}

func setupChangeResolutionE2E(t *testing.T) changeResolutionFixture {
	t.Helper()
	ctx, pool, q, s, org, owner := setupDSRE2E(t)
	s.Sign = &sign.Engine{Pool: pool, Queries: q, Audit: s.Audit}
	s.ActionSecret = strings.Repeat("resolution-fixture-", 4)
	user, err := q.GetUser(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(auth.SessionPayload{UserID: owner, Generation: user.SessionGeneration})
	if err != nil {
		t.Fatal(err)
	}
	return changeResolutionFixture{ctx, pool, q, s, org, owner, s.Cookies.Mint(payload, time.Hour)}
}

func (f changeResolutionFixture) seed(t *testing.T) (*generated.Document, *generated.ChangeRequest) {
	t.Helper()
	doc, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{
		OrgID: f.org, SenderID: f.owner, Name: "Resolution fidelity " + uuid.NewString(),
		BlocksJson:    json.RawMessage(`{"version":1,"blocks":[{"id":"payment-term","type":"paragraph","text":"Original payment term"}]}`),
		VariablesJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@resolution.test", Name: "Resolution signer",
		MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.q.ConfirmDocumentLawfulBasis(f.ctx, generated.ConfirmDocumentLawfulBasisParams{
		DocumentID: doc.ID, OrgID: f.org, LawfulBasis: "contract", Via: "test",
		ConfirmedBy: pgtype.UUID{Bytes: f.owner, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	// These receipts establish a synthetic sent state; this fixture has no
	// storage objects, SMTP worker, or live delivery side effects.
	doc = sendDSRDocumentE2E(t, f.ctx, f.pool, f.q, doc, recipient)
	doc, err = f.q.RequestChangesOnDocument(f.ctx, generated.RequestChangesOnDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	cr, err := f.q.CreateChangeRequest(f.ctx, generated.CreateChangeRequestParams{
		DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true}, Message: "Revise the payment term.",
		BlockID: "payment-term", Quote: "Original payment term", Proposed: "Revised payment term",
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc, cr
}

func (f changeResolutionFixture) submit(t *testing.T, endpoint string, documentID, requestID uuid.UUID, approve bool) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	action := "deny"
	if approve {
		action = "approve"
	}
	if endpoint == "email" {
		token := actiontoken.Mint(f.s.ActionSecret, actiontoken.Claims{
			Kind: "cr", OrgID: f.org.String(), DocID: documentID.String(), TargetID: requestID.String(), Action: action,
		}, time.Now(), time.Hour)
		form := url.Values{"t": {token}}
		req = httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/a/cr", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/documents/"+documentID.String()+"/change-requests/"+requestID.String()+"/"+action, nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: f.cookie})
	}
	req.Header.Set("Origin", f.s.PublicURL)
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, req)
	return w
}

// Snapshot only the negotiation's rows: unrelated member revocation audits must
// remain committed while a refused resolution rolls back all of its own state.
func (f changeResolutionFixture) snapshot(t *testing.T, documentID uuid.UUID) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'document', (SELECT to_jsonb(d) FROM documents d WHERE d.id=$1),
		'recipients', (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM recipients r WHERE r.document_id=$1),
		'requests', (SELECT coalesce(jsonb_agg(to_jsonb(cr) ORDER BY cr.id),'[]'::jsonb) FROM change_requests cr WHERE cr.document_id=$1),
		'fields', (SELECT coalesce(jsonb_agg(to_jsonb(df) ORDER BY df.id),'[]'::jsonb) FROM document_fields df WHERE df.document_id=$1),
		'signatures', (SELECT coalesce(jsonb_agg(to_jsonb(sg) ORDER BY sg.id),'[]'::jsonb) FROM signatures sg WHERE sg.document_id=$1),
		'versions', (SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.id),'[]'::jsonb) FROM document_versions v WHERE v.document_id=$1),
		'events', (SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e WHERE e.document_id=$1),
		'outbox', (SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY ed.id),'[]'::jsonb) FROM email_deliveries ed WHERE ed.to_email IN (SELECT email FROM recipients WHERE document_id=$1))
	)::text`, documentID).Scan(&state) //nolint:rawsql -- exact synthetic negotiation state in one database snapshot
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestChangeResolutionFailureFidelityAndRollbackE2E(t *testing.T) {
	for _, endpoint := range []string{"rest", "email"} {
		for _, fault := range []string{"audit", "audit-no-row", "request-update", "request-no-row"} {
			t.Run(endpoint+"/"+fault, func(t *testing.T) {
				f := setupChangeResolutionE2E(t)
				doc, cr := f.seed(t)
				if _, err := f.q.SetOrgChangeApprovalMode(f.ctx, generated.SetOrgChangeApprovalModeParams{ID: f.org, ChangeApprovalMode: "auto_apply"}); err != nil {
					t.Fatal(err)
				}
				before := f.snapshot(t, doc.ID)
				var published atomic.Int32
				f.s.Audit.Subscribe(func(_ context.Context, _ uuid.UUID, entry audit.Entry) {
					if entry.DocumentID != nil && *entry.DocumentID == doc.ID && entry.Payload["change_request"] == cr.ID.String() {
						published.Add(1)
					}
				})
				name := "hash_resolution_failure_" + strings.ReplaceAll(cr.ID.String(), "-", "")
				table, operation, condition := "events", "INSERT", fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.payload_json->>'change_request'='%s'", doc.ID, cr.ID)
				if fault == "request-update" || fault == "request-no-row" {
					table, operation, condition = "change_requests", "UPDATE", fmt.Sprintf("NEW.id='%s'::uuid", cr.ID)
				}
				failure := "RAISE EXCEPTION 'fixture resolution failure';"
				if fault == "audit-no-row" || fault == "request-no-row" {
					failure = "RETURN NULL;"
				}
				if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF %s THEN %s END IF; RETURN NEW; END $$;
				CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, condition, failure, name, operation, table, name)); err != nil { //nolint:rawsql,gosec -- identifiers and predicates contain only fixture constants and generated UUIDs
					t.Fatal(err)
				}
				dropFault := func() {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if _, err := f.pool.Exec(cleanupCtx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()`, name, table, name)); err != nil { //nolint:rawsql,gosec
						t.Error(err)
					}
				}
				t.Cleanup(dropFault)
				response := f.submit(t, endpoint, doc.ID, cr.ID, true)
				if response.Code != http.StatusInternalServerError {
					t.Fatalf("failed resolution status=%d want500", response.Code)
				}
				for _, leaked := range []string{"Already handled", "fixture resolution failure", "SQLSTATE", name} {
					if strings.Contains(response.Body.String(), leaked) {
						t.Fatalf("failed resolution falsely reported success or exposed database details: %q", leaked)
					}
				}
				if f.snapshot(t, doc.ID) != before || published.Load() != 0 {
					t.Fatal("failed resolution changed exact document/request/history/evidence/audit/outbox state or published an event")
				}
				current, err := f.q.GetDocumentByID(f.ctx, doc.ID)
				if err != nil || string(current.BlocksJson) != string(doc.BlocksJson) || current.Status != "changes_requested" {
					t.Fatalf("failed approval escaped document rollback: err=%v", err)
				}
				request, err := f.q.GetChangeRequest(f.ctx, generated.GetChangeRequestParams{ID: cr.ID, OrgID: f.org})
				if err != nil || request.Status != "open" || request.Resolution.Valid || request.ResolvedAt.Valid {
					t.Fatalf("failed approval escaped request rollback: err=%v", err)
				}
				countResolutionEvents := func() int {
					var count int
					if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1
						AND kind=$2 AND payload_json->>'change_request'=$3`, doc.ID, audit.KindChangesRequested, cr.ID.String()).Scan(&count); err != nil { //nolint:rawsql
						t.Fatal(err)
					}
					return count
				}
				if countResolutionEvents() != 0 {
					t.Fatal("failed approval committed a resolution audit")
				}
				dropFault()
				if response = f.submit(t, endpoint, doc.ID, cr.ID, true); response.Code != http.StatusOK {
					t.Fatalf("retry after restored database status=%d", response.Code)
				}
				current, err = f.q.GetDocumentByID(f.ctx, doc.ID)
				if err != nil || !strings.Contains(string(current.BlocksJson), "Revised payment term") || countResolutionEvents() != 1 {
					t.Fatalf("successful retry failed to atomically apply and audit: err=%v", err)
				}
				wantReplay := http.StatusConflict
				if endpoint == "email" {
					wantReplay = http.StatusOK
				}
				if response = f.submit(t, endpoint, doc.ID, cr.ID, true); response.Code != wantReplay {
					t.Fatalf("genuine replay status=%d want%d", response.Code, wantReplay)
				}
				if endpoint == "email" && !strings.Contains(response.Body.String(), "Already handled") {
					t.Fatal("genuine email replay lost its terminal confirmation")
				}
				if countResolutionEvents() != 1 || published.Load() != 1 {
					t.Fatal("successful retry/replay did not preserve exactly one committed and published resolution audit")
				}
			})
		}
	}
}

func TestChangeResolutionScopedNotFoundAndStateConflictsE2E(t *testing.T) {
	for _, endpoint := range []string{"rest", "email"} {
		t.Run(endpoint, func(t *testing.T) {
			f := setupChangeResolutionE2E(t)
			doc, cr := f.seed(t)
			otherDoc, otherRequest := f.seed(t)
			foreignOrg, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Foreign resolution fixture " + uuid.NewString(), Plan: "pro"})
			if err != nil {
				t.Fatal(err)
			}
			foreignOwner, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{
				OrgID: foreignOrg.ID, Email: uuid.NewString() + "@resolution.test", Name: "Foreign owner", Role: "owner",
			})
			if err != nil {
				t.Fatal(err)
			}
			foreignDoc, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{
				OrgID: foreignOrg.ID, SenderID: foreignOwner.ID, Name: "Foreign change request",
				BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			foreignRequest, err := f.q.CreateChangeRequest(f.ctx, generated.CreateChangeRequestParams{DocumentID: foreignDoc.ID, Message: "Foreign request"})
			if err != nil {
				t.Fatal(err)
			}
			for _, missing := range []struct {
				name       string
				documentID uuid.UUID
				requestID  uuid.UUID
			}{{"missing-document", uuid.New(), cr.ID}, {"missing-request", doc.ID, uuid.New()},
				{"request-for-other-document", doc.ID, otherRequest.ID},
				{"foreign-document", foreignDoc.ID, foreignRequest.ID}, {"foreign-request", doc.ID, foreignRequest.ID}} {
				response := f.submit(t, endpoint, missing.documentID, missing.requestID, true)
				if response.Code != http.StatusNotFound {
					t.Fatalf("%s status=%d want404", missing.name, response.Code)
				}
			}
			if _, err := f.q.ReopenDocumentToDraft(f.ctx, generated.ReopenDocumentToDraftParams{ID: doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			if response := f.submit(t, endpoint, doc.ID, cr.ID, false); response.Code != http.StatusConflict {
				t.Fatalf("document-state conflict status=%d want409", response.Code)
			}
			if _, err := f.q.SetOrgChangeApprovalMode(f.ctx, generated.SetOrgChangeApprovalModeParams{ID: f.org, ChangeApprovalMode: "auto_apply"}); err != nil {
				t.Fatal(err)
			}
			// An already-completed field is captured evidence. Auto-apply must
			// retain it and report a conflict instead of claiming a replay.
			if _, err := f.pool.Exec(f.ctx, `INSERT INTO document_fields
				(document_id,type,page,x_pct,y_pct,w_pct,h_pct,required,options_json,value,completed_at)
				VALUES($1,'text',1,0,0,20,5,true,'[]'::jsonb,'Captured answer',now())`, otherDoc.ID); err != nil { //nolint:rawsql
				t.Fatal(err)
			}
			if response := f.submit(t, endpoint, otherDoc.ID, otherRequest.ID, true); response.Code != http.StatusConflict {
				t.Fatalf("captured-evidence conflict status=%d want409", response.Code)
			}
			for _, requestID := range []uuid.UUID{cr.ID, otherRequest.ID} {
				current, err := f.q.GetChangeRequest(f.ctx, generated.GetChangeRequestParams{ID: requestID, OrgID: f.org})
				if err != nil || current.Status != "open" || current.Resolution.Valid {
					t.Fatalf("refused resolution changed an open request: err=%v", err)
				}
			}
		})
	}
}
