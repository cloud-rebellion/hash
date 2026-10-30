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
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type fieldAuthorizationFixture struct {
	recipientAuthorizationFixture
	field *generated.DocumentField
}

func setupFieldAuthorizationE2E(t *testing.T, role string) fieldAuthorizationFixture {
	t.Helper()
	f := setupRecipientAuthorizationE2E(t, role)
	rows, err := f.q.ListFieldsByDocument(f.ctx, f.doc.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("field fixture count=%d err=%v", len(rows), err)
	}
	return fieldAuthorizationFixture{recipientAuthorizationFixture: f, field: rows[0]}
}

func setupForeignFieldAuthorizationE2E(t *testing.T) fieldAuthorizationFixture {
	t.Helper()
	f := setupForeignRecipientAuthorizationE2E(t)
	rows, err := f.q.ListFieldsByDocument(f.ctx, f.doc.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("foreign field fixture count=%d err=%v", len(rows), err)
	}
	return fieldAuthorizationFixture{recipientAuthorizationFixture: f, field: rows[0]}
}

func (f fieldAuthorizationFixture) input() addFieldInput {
	return addFieldInput{RecipientID: f.recipient.ID.String(), Type: "text", XPct: 10, YPct: 20, WPct: 30, HPct: 5, Label: "Fixture question"}
}

func (f fieldAuthorizationFixture) submit(operation, cookie string) *httptest.ResponseRecorder {
	if operation == "delete" {
		return submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/fields/"+f.field.ID.String(), "", cookie)
	}
	return f.submitInput(f.doc.ID, f.input(), cookie)
}

func (f fieldAuthorizationFixture) submitInput(doc uuid.UUID, input addFieldInput, cookie string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(input)
	return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.String()+"/fields", string(body), cookie)
}

func (f fieldAuthorizationFixture) snapshot(t *testing.T) string {
	return f.snapshotDB(t, f.pool)
}

func (f fieldAuthorizationFixture) snapshotDB(t *testing.T, db generated.DBTX) string {
	t.Helper()
	var state string
	err := db.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
		SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
		'fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM document_fields f WHERE document_id IN (SELECT id FROM owned)),
		'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM signatures s WHERE document_id IN (SELECT id FROM owned)),
		'privacy_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
		'intents',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY document_id),'[]'::jsonb) FROM send_sealing_intents i WHERE org_id=$1),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE document_id IN (SELECT id FROM owned)),
		'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY id),'[]'::jsonb) FROM email_deliveries ed WHERE to_email IN (SELECT email FROM recipients WHERE document_id IN (SELECT id FROM owned)))
		)::text`, f.org).Scan(&state) //nolint:rawsql -- exact synthetic fixture state, including retained evidence and credentials
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func (f fieldAuthorizationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before {
		t.Fatal("refused field authoring changed content, recipients, credentials, fields, legal evidence, privacy linkage, audit, intent, or outbox")
	}
}

func fieldAuthoringStatus(operation string) int {
	if operation == "create" {
		return http.StatusCreated
	}
	return http.StatusNoContent
}

func fieldAuthoringKind(operation string) string {
	if operation == "create" {
		return "document.field_added"
	}
	return "document.field_deleted"
}

func TestFieldAuthoringRechecksSessionAfterDocumentWaitE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		for _, change := range []string{"demotion", "revocation", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupFieldAuthorizationE2E(t, "sender")
				owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
				before := f.snapshot(t)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- f.submit(operation, cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				want := http.StatusForbidden
				switch change {
				case "demotion":
					response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
					if response.Code != http.StatusOK {
						t.Fatalf("actual member demotion=%d %s", response.Code, response.Body.String())
					}
				case "revocation":
					if response := submitSessionOperationE2E(f.s, http.MethodPost, "/auth/logout", "", cookie); response.Code != http.StatusOK {
						t.Fatalf("actual logout=%d %s", response.Code, response.Body.String())
					}
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				response := receiveSessionOperationE2E(t, result)
				if response.Code != want {
					t.Fatalf("stale field %s=%d want%d %s", operation, response.Code, want, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestFieldAuthoringAuditWaitExpiryRollsBackE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupFieldAuthorizationE2E(t, "sender")
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit(operation, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if response := receiveSessionOperationE2E(t, result); response.Code != http.StatusUnauthorized {
				t.Fatalf("late field expiry=%d %s", response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
			if response := f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)); response.Code != fieldAuthoringStatus(operation) {
				t.Fatalf("fresh field retry=%d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestFieldAuthoringSenderOwnerCanonicalAuditAndDTOE2E(t *testing.T) {
	for _, role := range []string{"sender", "owner"} {
		for _, operation := range []string{"create", "delete"} {
			t.Run(role+"/"+operation, func(t *testing.T) {
				f := setupFieldAuthorizationE2E(t, role)
				response := f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
				if response.Code != fieldAuthoringStatus(operation) {
					t.Fatalf("valid field %s=%d %s", operation, response.Code, response.Body.String())
				}
				fieldID := f.field.ID
				if operation == "create" {
					var body struct {
						ID          uuid.UUID       `json:"id"`
						DocumentID  uuid.UUID       `json:"document_id"`
						RecipientID uuid.UUID       `json:"recipient_id"`
						Page        int             `json:"page"`
						Required    bool            `json:"required"`
						XPct        float64         `json:"x_pct"`
						Options     json.RawMessage `json:"options"`
					}
					if json.Unmarshal(response.Body.Bytes(), &body) != nil || body.ID == uuid.Nil || body.DocumentID != f.doc.ID || body.RecipientID != f.recipient.ID || body.Page != 1 || !body.Required || body.XPct != 10 || string(body.Options) != "{}" {
						t.Fatal("field DTO lost assignment, geometry, required/page defaults, or options")
					}
					fieldID = body.ID
				} else {
					var count int
					if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM document_fields WHERE id=$1`, fieldID).Scan(&count); err != nil || count != 0 {
						t.Fatalf("deleted field remains: count=%d err=%v", count, err)
					} //nolint:rawsql
				}
				var actor uuid.UUID
				var subject string
				if err := f.pool.QueryRow(f.ctx, `SELECT actor_user_id,payload_json->>'field_id' FROM events WHERE document_id=$1 AND kind=$2 AND NOT (id=ANY($3::uuid[]))`, f.doc.ID, fieldAuthoringKind(operation), f.originalAudit.ids()).Scan(&actor, &subject); err != nil || actor != f.user.ID || subject != fieldID.String() {
					t.Fatalf("field audit actor/subject=%s/%s err=%v", actor, subject, err)
				} //nolint:rawsql
				f.originalAudit.assertAdded(t, f.lifecycleAuthorizationFixture, 1)
				rows, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
				if err != nil {
					t.Fatal(err)
				}
				verifier := audit.NewChainVerifier()
				verifier.VerifyPage(rows)
				if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != len(f.originalAudit.events)+1 {
					t.Fatalf("field audit chain invalid: %+v", result)
				}
			})
		}
	}
}

func TestFieldAuthoringInternalFailuresRollBackAndRetryE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		for _, fault := range []string{"audit", "audit-no-row", "mutation-no-row"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f := setupFieldAuthorizationE2E(t, "owner")
				before := f.snapshot(t)
				name := "hash_field_failure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
				table, event, predicate := "events", "INSERT", fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.kind='%s'", f.doc.ID, fieldAuthoringKind(operation))
				failure, returned := "RAISE EXCEPTION 'fixture field failure';", "NEW"
				if fault == "audit-no-row" {
					failure = "RETURN NULL;"
				}
				if fault == "mutation-no-row" {
					table, failure = "document_fields", "RETURN NULL;"
					predicate = fmt.Sprintf("NEW.document_id='%s'::uuid", f.doc.ID)
					if operation == "delete" {
						event, predicate, returned = "DELETE", fmt.Sprintf("OLD.id='%s'::uuid", f.field.ID), "OLD"
					}
				}
				if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF %s THEN %s END IF; RETURN %s; END $$;
					CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, predicate, failure, returned, name, event, table, name)); err != nil {
					t.Fatal(err)
				} //nolint:rawsql,gosec -- fixed constants plus fixture UUIDs
				dropFault := func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if _, err := f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()`, name, table, name)); err != nil {
						t.Error(err)
					} //nolint:rawsql,gosec
				}
				t.Cleanup(dropFault)
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				response := f.submit(operation, cookie)
				if response.Code != http.StatusInternalServerError {
					t.Fatalf("internal field %s/%s=%d %s", operation, fault, response.Code, response.Body.String())
				}
				for _, leak := range []string{"fixture field failure", name, "SQLSTATE", "PL/pgSQL", "no rows"} {
					if strings.Contains(response.Body.String(), leak) {
						t.Fatalf("field error exposed %q", leak)
					}
				}
				f.assertUnchanged(t, before)
				dropFault()
				if response := f.submit(operation, cookie); response.Code != fieldAuthoringStatus(operation) {
					t.Fatalf("field retry after fault=%d %s", response.Code, response.Body.String())
				}
			})
		}
	}
}

func TestFieldAuthoringScopesDocumentRecipientAndFieldE2E(t *testing.T) {
	f := setupFieldAuthorizationE2E(t, "owner")
	foreign := setupForeignFieldAuthorizationE2E(t)
	sibling := createAuthoringSiblingE2E(t, f.lifecycleAuthorizationFixture, "Field sibling fixture")
	before, foreignBefore := f.snapshot(t), foreign.snapshot(t)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	for _, parent := range []uuid.UUID{uuid.New(), foreign.doc.ID} {
		if response := f.submitInput(parent, f.input(), cookie); response.Code != http.StatusNotFound {
			t.Fatalf("scoped field parent=%d %s", response.Code, response.Body.String())
		}
	}
	for _, target := range []struct{ doc, recipient uuid.UUID }{{f.doc.ID, uuid.New()}, {f.doc.ID, foreign.recipient.ID}, {sibling.ID, f.recipient.ID}} {
		input := f.input()
		input.RecipientID = target.recipient.String()
		if response := f.submitInput(target.doc, input, cookie); response.Code != http.StatusNotFound {
			t.Fatalf("scoped field recipient=%d %s", response.Code, response.Body.String())
		}
	}
	for _, target := range []uuid.UUID{uuid.New(), foreign.field.ID} {
		if response := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/fields/"+target.String(), "", cookie); response.Code != http.StatusNotFound {
			t.Fatalf("scoped field deletion=%d %s", response.Code, response.Body.String())
		}
	}
	f.assertUnchanged(t, before)
	foreign.assertUnchanged(t, foreignBefore)
}

func TestFieldDeleteRechecksOriginalOwnerAfterDocumentWaitE2E(t *testing.T) {
	f := setupFieldAuthorizationE2E(t, "sender")
	sibling := createAuthoringSiblingE2E(t, f.lifecycleAuthorizationFixture, "Moved field fixture")
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	go func() { result <- f.submit("delete", cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
	// Simulate a stale admission target. The engine must refuse rather than
	// follow the field to another document and delete under the wrong lock.
	if _, err := blocked.Exec(f.ctx, `UPDATE document_fields SET document_id=$2,recipient_id=NULL WHERE id=$1`, f.field.ID, sibling.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- synthetic relocation only
	expected := f.snapshotDB(t, blocked)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if response := receiveSessionOperationE2E(t, result); response.Code != http.StatusNotFound {
		t.Fatalf("stale field owner=%d %s", response.Code, response.Body.String())
	}
	f.assertUnchanged(t, expected)
}

func TestFieldAuthoringPreservesCapturedDraftEvidenceE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		for _, evidence := range []string{"field", "signature", "acceptance"} {
			t.Run(operation+"/"+evidence, func(t *testing.T) {
				f := setupFieldAuthorizationE2E(t, "owner")
				switch evidence {
				case "field":
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET value='',completed_at=now() WHERE id=$1`, f.field.ID); err != nil {
						t.Fatal(err)
					} //nolint:rawsql -- empty captured answer remains evidence
				case "acceptance":
					if err := f.q.SetRecipientStatus(f.ctx, generated.SetRecipientStatusParams{ID: f.recipient.ID, DocumentID: f.doc.ID, Status: "accepted"}); err != nil {
						t.Fatal(err)
					}
				case "signature":
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET type='signature' WHERE id=$1`, f.field.ID); err != nil {
						t.Fatal(err)
					} //nolint:rawsql -- synthetic partially captured ceremony
					if _, err := f.q.InsertSignature(f.ctx, generated.InsertSignatureParams{DocumentID: f.doc.ID, RecipientID: f.recipient.ID, FieldID: f.field.ID, Font: "serif", TypedName: "Captured field signer", ImageStorageKey: "org/" + f.org.String() + "/documents/" + f.doc.ID.String() + "/signatures/" + f.recipient.ID.String() + ".png", ImageSha256: make([]byte, 32), ImageVersionID: pgtype.Text{String: "field-fixture-signature-1", Valid: true}}); err != nil {
						t.Fatal(err)
					}
				}
				before := f.snapshot(t)
				response := f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
				if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "retained signing evidence") {
					t.Fatalf("captured %s field %s=%d %s", evidence, operation, response.Code, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestFieldAuthoringPreservesPrivacyReviewE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		for _, review := range []string{"linked", "global", "changing"} {
			t.Run(operation+"/"+review, func(t *testing.T) {
				f := setupFieldAuthorizationE2E(t, "owner")
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				if review == "changing" {
					pending, err := f.pool.Begin(f.ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer pending.Rollback(context.Background())
					if _, err := f.q.WithTx(pending).CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}); err != nil {
						t.Fatal(err)
					}
				} else {
					input := map[string]any{"kind": "erasure", "subject_email": f.recipient.Email, "subject_name": f.recipient.Name}
					if review == "linked" {
						input["document_id"], input["recipient_id"] = f.doc.ID.String(), f.recipient.ID.String()
					}
					body, _ := json.Marshal(input)
					if response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/dsr", string(body), cookie); response.Code != http.StatusAccepted {
						t.Fatalf("bootstrap actual privacy request=%d %s", response.Code, response.Body.String())
					}
				}
				before := f.snapshot(t)
				response := f.submit(operation, cookie)
				if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "privacy") {
					t.Fatalf("%s privacy field %s=%d %s", review, operation, response.Code, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func (f fieldAuthorizationFixture) setSourceKind(t *testing.T, db generated.DBTX, kind string) {
	t.Helper()
	// Metadata-only synthetic source: no object-store operation occurs. Valid
	// pins preserve all production database constraints during this race.
	rows, err := db.Exec(f.ctx, `UPDATE documents SET source_kind=$3,pdf_storage_key=$4,pdf_sha256=$5,pdf_storage_version_id=$6
		WHERE id=$1 AND org_id=$2 AND status='draft'`, f.doc.ID, f.org, kind, "org/"+f.org.String()+"/documents/"+f.doc.ID.String()+".pdf", make([]byte, 32), "field-fixture-source-1") //nolint:rawsql -- fixture source transition under the held parent
	if err != nil || rows.RowsAffected() != 1 {
		t.Fatalf("set fixture source=%s rows=%d err=%v", kind, rows.RowsAffected(), err)
	}
}

func TestFieldSignatureUsesFreshSourceAfterDocumentWaitE2E(t *testing.T) {
	for _, initial := range []string{"pdf", "blocks"} {
		t.Run(initial, func(t *testing.T) {
			f := setupFieldAuthorizationE2E(t, "sender")
			f.setSourceKind(t, f.pool, initial)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			input := f.input()
			input.Type = "signature"
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submitInput(f.doc.ID, input, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
			next, want := "pdf", http.StatusCreated
			if initial == "pdf" {
				next, want = "blocks", http.StatusBadRequest
			}
			f.setSourceKind(t, blocked, next)
			expected := f.snapshotDB(t, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != want {
				t.Fatalf("fresh signature source %s->%s=%d want%d %s", initial, next, response.Code, want, response.Body.String())
			}
			if want == http.StatusBadRequest {
				f.assertUnchanged(t, expected)
			}
		})
	}
	t.Run("PDF signature requires assigned recipient", func(t *testing.T) {
		f := setupFieldAuthorizationE2E(t, "sender")
		f.setSourceKind(t, f.pool, "pdf")
		before := f.snapshot(t)
		input := f.input()
		input.Type, input.RecipientID = "signature", ""
		response := f.submitInput(f.doc.ID, input, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("unassigned PDF signature=%d %s", response.Code, response.Body.String())
		}
		f.assertUnchanged(t, before)
	})
}

func TestFieldAuthoringPreservesBodyAndValidationLimitsE2E(t *testing.T) {
	for _, invalid := range []string{"x", "width", "bounds", "page", "label", "choices", "oversized-body", "nonfinite-json"} {
		t.Run(invalid, func(t *testing.T) {
			f := setupFieldAuthorizationE2E(t, "sender")
			before := f.snapshot(t)
			input := f.input()
			switch invalid {
			case "x":
				input.XPct = -1
			case "width":
				input.WPct = 0
			case "bounds":
				input.XPct, input.WPct = 90, 20
			case "page":
				input.Page = 1001
			case "label":
				input.Label = "Private label\ncontrol"
			case "choices":
				input.Type, input.Options = "dropdown", map[string]any{"choices": []string{"Duplicate", "Duplicate"}}
			case "oversized-body":
				input.Options = map[string]any{"untrusted": strings.Repeat("x", 17*1024)}
			}
			body, _ := json.Marshal(input)
			if invalid == "nonfinite-json" {
				body = []byte(`{"type":"text","x_pct":1e999,"w_pct":10,"h_pct":5}`)
			}
			response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/fields", string(body), dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid field %s=%d %s", invalid, response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "Private label") {
				t.Fatal("validation returned private label value")
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestFieldAuthoringAllowsReopenedHistoryAndEnforcesLiveDraftE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		for _, state := range []string{"sent", "soft-deleted", "reopened"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				f := setupFieldAuthorizationE2E(t, "owner")
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				want := http.StatusConflict
				if state == "soft-deleted" {
					if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET deleted_at=now() WHERE id=$1`, f.doc.ID); err != nil {
						t.Fatal(err)
					} //nolint:rawsql -- synthetic soft-deleted parent
					want = http.StatusNotFound
				} else {
					f.doc = sendRecipientAuthorizationNativeE2E(t, f.lifecycleAuthorizationFixture)
					if state == "reopened" {
						if _, err := f.q.RequestChangesOnDocument(f.ctx, generated.RequestChangesOnDocumentParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
							t.Fatal(err)
						}
						if response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/revise", "", cookie); response.Code != http.StatusOK {
							t.Fatalf("bootstrap revision=%d %s", response.Code, response.Body.String())
						}
						current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
						if err != nil || current.Status != "draft" || !current.Article13NoticeEpochAt.Valid {
							t.Fatalf("reopened historical epoch missing: err=%v", err)
						}
						want = fieldAuthoringStatus(operation)
					}
				}
				before := f.snapshot(t)
				response := f.submit(operation, cookie)
				if response.Code != want {
					t.Fatalf("%s field %s=%d want%d %s", state, operation, response.Code, want, response.Body.String())
				}
				if state != "reopened" {
					f.assertUnchanged(t, before)
				}
			})
		}
	}
}

func TestFieldAuthoringBoundedCountCanRecoverByDeletionE2E(t *testing.T) {
	f := setupFieldAuthorizationE2E(t, "owner")
	// One assigned field is already present. Fill only this isolated document
	// to the published cap without manufacturing thousands of audit entries.
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO document_fields(document_id,type,page,x_pct,y_pct,w_pct,h_pct,required,options_json)
		SELECT $1,'text',1,0,0,10,5,false,'{}'::jsonb FROM generate_series(1,999)`, f.doc.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- bounded synthetic cap fixture
	before := f.snapshot(t)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	if response := f.submit("create", cookie); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "field limit") {
		t.Fatalf("field cap=%d %s", response.Code, response.Body.String())
	}
	f.assertUnchanged(t, before)
	if response := f.submit("delete", cookie); response.Code != http.StatusNoContent {
		t.Fatalf("delete at field cap=%d %s", response.Code, response.Body.String())
	}
	if response := f.submit("create", cookie); response.Code != http.StatusCreated {
		t.Fatalf("create after capacity recovered=%d %s", response.Code, response.Body.String())
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM document_fields WHERE document_id=$1`, f.doc.ID).Scan(&count); err != nil || count != 1000 {
		t.Fatalf("field cap final count=%d err=%v", count, err)
	} //nolint:rawsql
}
