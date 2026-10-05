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

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/fields"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Actual /mcp middleware uses only synthetic local credentials. No PDF storage,
// signing ceremony or SMTP worker is claimed by these authoring fixtures.
type fieldMCPFixture struct {
	lifecycleAuthorizationFixture
	field *generated.DocumentField
}

func setupFieldMCPE2E(t *testing.T) fieldMCPFixture {
	t.Helper()
	f := setupLifecycleAuthorizationE2E(t, "owner", false, false)
	f.enableMCP()
	row, err := f.q.CreateDraftField(f.ctx, generated.CreateDraftFieldParams{
		DocumentID: f.doc.ID, OrgID: f.org, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true}, Type: "text", Page: 1,
		XPct: pctToNumeric(10), YPct: pctToNumeric(10), WPct: pctToNumeric(15), HPct: pctToNumeric(4),
		Label: pgtype.Text{String: "Existing field", Valid: true}, OptionsJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return fieldMCPFixture{f, row}
}

func fieldMCPArgumentsE2E(f fieldMCPFixture, tool string) map[string]any {
	if tool == "delete_document_field" {
		return map[string]any{"field_id": f.field.ID}
	}
	return map[string]any{"document_id": f.doc.ID, "recipient_id": f.recipient.ID, "type": "text", "label": "New MCP field"}
}

func submitFieldMCPE2E(f fieldMCPFixture, tool, key string, args map[string]any) *httptest.ResponseRecorder {
	return submitRecipientMCPE2E(f.lifecycleAuthorizationFixture, tool, key, args)
}

// Capture the intended soft-delete state while the fixture still owns the
// parent lock. The refused request cannot contribute to its own expected state.
func fieldMCPSnapshotInTxE2E(t *testing.T, f fieldMCPFixture, tx pgx.Tx) string {
	t.Helper()
	var state, related string
	if err := tx.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
		SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
		'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY document_id,variable_name),'[]'::jsonb) FROM document_variable_bindings b WHERE document_id IN (SELECT id FROM owned)),
		'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM document_versions v WHERE document_id IN (SELECT id FROM owned)),
		'confirmation',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY document_id),'[]'::jsonb) FROM document_lawful_basis_confirmations c WHERE document_id IN (SELECT id FROM owned)),
		'intent',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY document_id),'[]'::jsonb) FROM send_sealing_intents i WHERE document_id IN (SELECT id FROM owned)),
		'reminders',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY document_id),'[]'::jsonb) FROM reminders r WHERE document_id IN (SELECT id FROM owned)),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE document_id IN (SELECT id FROM owned)),
		'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY id),'[]'::jsonb) FROM email_deliveries ed WHERE to_email IN (SELECT email FROM recipients WHERE document_id IN (SELECT id FROM owned)))
		)::text`, f.org).Scan(&state); err != nil { //nolint:rawsql -- fixture-owned exact expected state
		t.Fatal(err)
	}
	if err := tx.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'fields',(SELECT coalesce(jsonb_agg(to_jsonb(df) ORDER BY df.id),'[]'::jsonb)
			FROM document_fields df JOIN documents d ON d.id=df.document_id WHERE d.org_id=$1),
		'privacy_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb)
			FROM data_subject_requests r WHERE r.org_id=$1))::text`, f.org).Scan(&related); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	return state + "\n" + related
}

func fieldMCPTextE2E(t *testing.T, response *httptest.ResponseRecorder, wantError bool) string {
	t.Helper()
	assertLifecycleMCPResultE2E(t, response, wantError)
	var reply struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &reply); err != nil || len(reply.Result.Content) != 1 || reply.Result.Content[0].Type != "text" {
		t.Fatalf("invalid MCP field content: %s", response.Body.String())
	}
	return reply.Result.Content[0].Text
}

func assertFieldMCPCommitE2E(t *testing.T, f fieldMCPFixture, tool string) *generated.DocumentField {
	t.Helper()
	rows, err := f.q.ListFieldsByDocument(f.ctx, f.doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	var subject *generated.DocumentField
	kind := "document.field_added"
	if tool == "delete_document_field" {
		kind, subject = "document.field_deleted", f.field
		if len(rows) != 0 {
			t.Fatal("successful field delete retained its target")
		}
	} else {
		if len(rows) != 2 {
			t.Fatal("successful field create did not commit exactly one field")
		}
		for _, row := range rows {
			if row.ID != f.field.ID && row.Label.String == "New MCP field" {
				subject = row
			}
		}
		if subject == nil {
			t.Fatal("successful field create did not commit the requested field")
		}
	}
	var total, matching int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE kind=$2 AND actor_user_id=$3
		AND payload_json->>'field_id'=$4 AND payload_json->>'tool'=$5 AND payload_json->>'via'='mcp')
		FROM events WHERE document_id=$1`, f.doc.ID, kind, f.user.ID, subject.ID.String(), tool).Scan(&total, &matching); err != nil {
		t.Fatal(err)
	}
	if total != 1 || matching != 1 {
		t.Fatalf("field audit total/matching=%d/%d want1/1", total, matching)
	}
	return subject
}

func TestFieldMCPCredentialsRecheckedAfterDocumentWaitE2E(t *testing.T) {
	for _, tool := range []string{"add_document_field", "delete_document_field"} {
		for _, change := range []string{"key-delete", "scope-reduction", "key-expiry", "document-token-revocation", "member-demotion"} {
			t.Run(tool+"/"+change, func(t *testing.T) {
				f := setupFieldMCPE2E(t)
				before := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture)
				mint, keyID := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, change == "document-token-revocation", 1)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitFieldMCPE2E(f, tool, mint.Plaintext, fieldMCPArgumentsE2E(f, tool)) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				switch change {
				case "key-delete":
					response := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/api-keys/"+keyID.String(), "", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
					if response.Code != http.StatusNoContent {
						t.Fatalf("actual key deletion status=%d", response.Code)
					}
				case "scope-reduction":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID)
				case "key-expiry":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID)
				case "document-token-revocation":
					_, err = f.q.RevokeDocAgentToken(f.ctx, generated.RevokeDocAgentTokenParams{ID: keyID, OrgID: f.org})
				case "member-demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				want := auth.ErrMutationPermissionRevoked.Error()
				if change == "key-expiry" {
					want = auth.ErrMutationCredentialExpired.Error()
				}
				if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != want {
					t.Fatalf("field credential refusal=%q want%q", got, want)
				}
				assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
				if change == "document-token-revocation" {
					key, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
					if err != nil || key.UsedCount != 1 || !key.LastUsedAt.Valid {
						t.Fatal("field authorization must retain exactly its original middleware use claim")
					}
				}
			})
		}
	}
}

func TestFieldMCPOneUseTokenAndReplayE2E(t *testing.T) {
	for _, tool := range []string{"add_document_field", "delete_document_field"} {
		t.Run(tool, func(t *testing.T) {
			f := setupFieldMCPE2E(t)
			if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
				t.Fatal(err)
			}
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, true, 1)
			args := fieldMCPArgumentsE2E(f, tool)
			fieldMCPTextE2E(t, submitFieldMCPE2E(f, tool, mint.Plaintext, args), false)
			assertFieldMCPCommitE2E(t, f, tool)
			key, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
			if err != nil || key.UsedCount != 1 || !key.LastUsedAt.Valid {
				t.Fatal("field mutation must not claim its one-use token twice")
			}
			before := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture)
			if response := submitFieldMCPE2E(f, tool, mint.Plaintext, args); response.Code != http.StatusUnauthorized {
				t.Fatalf("field one-use replay status=%d", response.Code)
			}
			assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
		})
	}
}

func TestFieldMCPRefusesForgedContextE2E(t *testing.T) {
	f := setupFieldMCPE2E(t)
	before := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture)
	ctx := context.WithValue(f.ctx, auth.UserIDKey, f.user.ID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, f.org)
	ctx = context.WithValue(ctx, auth.RoleKey, f.user.Role)
	ctx = context.WithValue(ctx, auth.EmailKey, f.user.Email)
	ctx = context.WithValue(ctx, auth.TokenScopesKey, []string{"write:authoring"})
	for _, tool := range []string{"add_document_field", "delete_document_field"} {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": fieldMCPArgumentsE2E(f, tool)}})
		request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
		response := httptest.NewRecorder()
		f.s.MCP.Handler().ServeHTTP(response, request)
		if got := fieldMCPTextE2E(t, response, true); got != auth.ErrMutationPermissionRevoked.Error() {
			t.Fatalf("forged field authorization=%q", got)
		}
		assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
	}
}

func TestFieldMCPScopeAndTenantBoundariesE2E(t *testing.T) {
	f, foreign := setupFieldMCPE2E(t), setupFieldMCPE2E(t)
	siblingDoc, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Field sibling", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	siblingField, err := f.q.CreateDraftField(f.ctx, generated.CreateDraftFieldParams{DocumentID: siblingDoc.ID, OrgID: f.org, Type: "text", Page: 1, XPct: pctToNumeric(0), YPct: pctToNumeric(0), WPct: pctToNumeric(15), HPct: pctToNumeric(4), OptionsJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	before, foreignBefore := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture), recipientMCPSnapshotE2E(t, foreign.lifecycleAuthorizationFixture)
	docKey, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, true, 0)
	orgKey, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
	for _, tool := range []string{"add_document_field", "delete_document_field"} {
		args := fieldMCPArgumentsE2E(f, tool)
		if tool == "add_document_field" {
			args["document_id"], args["recipient_id"] = siblingDoc.ID, ""
		} else {
			args["field_id"] = siblingField.ID
		}
		fieldMCPTextE2E(t, submitFieldMCPE2E(f, tool, docKey.Plaintext, args), true)
		args = fieldMCPArgumentsE2E(foreign, tool)
		want := fields.ErrDocumentNotFound.Error()
		if tool == "delete_document_field" {
			want = fields.ErrFieldNotFound.Error()
		}
		if got := fieldMCPTextE2E(t, submitFieldMCPE2E(f, tool, orgKey.Plaintext, args), true); got != want {
			t.Fatalf("foreign field mutation=%q want%q", got, want)
		}
		assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
		assertRecipientMCPUnchangedE2E(t, foreign.lifecycleAuthorizationFixture, foreignBefore)
	}
	args := fieldMCPArgumentsE2E(f, "add_document_field")
	args["recipient_id"] = foreign.recipient.ID
	fieldMCPTextE2E(t, submitFieldMCPE2E(f, "add_document_field", orgKey.Plaintext, args), true)
	assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
	assertRecipientMCPUnchangedE2E(t, foreign.lifecycleAuthorizationFixture, foreignBefore)
}

func TestFieldMCPBasisPointsDefaultsBoundsAndDropdownE2E(t *testing.T) {
	for _, name := range []string{"defaults", "quarter-page", "page-edge", "dropdown"} {
		t.Run(name, func(t *testing.T) {
			f := setupFieldMCPE2E(t)
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			args := fieldMCPArgumentsE2E(f, "add_document_field")
			x, y, width, height, page, required := 0.0, 0.0, 15.0, 4.0, 1.0, true
			switch name {
			case "quarter-page":
				args["x_pct"], args["y_pct"], args["w_pct"], args["h_pct"], args["page"], args["required"] = 2500, 2500, 2000, 750, 2, "false"
				x, y, width, height, page, required = 25, 25, 20, 7.5, 2, false
			case "page-edge":
				args["x_pct"], args["y_pct"], args["w_pct"], args["h_pct"] = 9000, 9600, 1000, 400
				x, y, width, height = 90, 96, 10, 4
			case "dropdown":
				args["type"], args["options"] = "dropdown", map[string]any{"choices": []string{"First option", "Second option"}}
			}
			text := fieldMCPTextE2E(t, submitFieldMCPE2E(f, "add_document_field", mint.Plaintext, args), false)
			var dto map[string]any
			if err := json.Unmarshal([]byte(text), &dto); err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]float64{"x_pct": x, "y_pct": y, "w_pct": width, "h_pct": height, "page": page} {
				if dto[key] != want {
					t.Fatalf("MCP field %s=%v want%v in %s", key, dto[key], want, text)
				}
			}
			if dto["required"] != required || dto["recipient_id"] != f.recipient.ID.String() || dto["options"] == nil {
				t.Fatalf("field DTO lost defaults, assignment or options: %s", text)
			}
			row := assertFieldMCPCommitE2E(t, f, "add_document_field")
			if numericToFloat(row.XPct) != x || numericToFloat(row.YPct) != y || numericToFloat(row.WPct) != width || numericToFloat(row.HPct) != height || float64(row.Page) != page || row.Required != required {
				t.Fatal("wire basis points did not persist canonical page-percentage geometry")
			}
			if name == "dropdown" {
				if validateSignerFieldValue(row, "Second option") != nil || validateSignerFieldValue(row, "Unconfigured option") == nil {
					t.Fatal("created dropdown choices do not bind actual signer validation")
				}
			}
		})
	}
}

func TestFieldMCPRejectsInvalidPlacementAndConfigurationE2E(t *testing.T) {
	for _, invalid := range []struct {
		name string
		args map[string]any
	}{
		{"zero-width", map[string]any{"w_pct": 0}}, {"zero-height", map[string]any{"h_pct": 0}},
		{"overflow-x", map[string]any{"x_pct": 9900}}, {"overflow-y", map[string]any{"y_pct": 9900}},
		{"negative-coordinate", map[string]any{"x_pct": -1}}, {"too-large-coordinate", map[string]any{"x_pct": 10001}},
		{"zero-page", map[string]any{"page": 0}}, {"too-large-page", map[string]any{"page": 1001}},
		{"invalid-required", map[string]any{"required": "yes"}},
		{"empty-dropdown", map[string]any{"type": "dropdown", "options": map[string]any{"choices": []string{}}}},
		{"duplicate-dropdown", map[string]any{"type": "dropdown", "options": map[string]any{"choices": []string{"Same", "Same"}}}},
		{"control-dropdown", map[string]any{"type": "dropdown", "options": map[string]any{"choices": []string{"Bad\nchoice"}}}},
		{"options-array", map[string]any{"options": []string{"wrong shape"}}},
		{"block-signature", map[string]any{"type": "signature"}},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			f := setupFieldMCPE2E(t)
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			before := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture)
			args := fieldMCPArgumentsE2E(f, "add_document_field")
			for key, value := range invalid.args {
				args[key] = value
			}
			fieldMCPTextE2E(t, submitFieldMCPE2E(f, "add_document_field", mint.Plaintext, args), true)
			assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
		})
	}
}

func TestFieldMCPPDFSignatureRequiresOwnedRecipientE2E(t *testing.T) {
	f := setupFieldMCPE2E(t)
	doc, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{
		OrgID: f.org, SenderID: f.user.ID, Name: "Synthetic PDF field fixture", PdfStorageKey: pgtype.Text{String: "fixture/authoring.pdf", Valid: true}, PdfSha256: make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: "pdf-field@example.test", Name: "PDF fixture signer", Locale: "en",
		MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
	before := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture)
	args := map[string]any{"document_id": doc.ID, "type": "signature"}
	fieldMCPTextE2E(t, submitFieldMCPE2E(f, "add_document_field", mint.Plaintext, args), true)
	assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
	args["recipient_id"] = f.recipient.ID
	if got := fieldMCPTextE2E(t, submitFieldMCPE2E(f, "add_document_field", mint.Plaintext, args), true); got != fields.ErrRecipientNotFound.Error() {
		t.Fatalf("PDF signature foreign-document recipient=%q", got)
	}
	assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
	args["recipient_id"] = recipient.ID
	fieldMCPTextE2E(t, submitFieldMCPE2E(f, "add_document_field", mint.Plaintext, args), false)
	rows, err := f.q.ListFieldsByDocument(f.ctx, doc.ID)
	if err != nil || len(rows) != 1 || rows[0].Type != "signature" || !rows[0].RecipientID.Valid || uuid.UUID(rows[0].RecipientID.Bytes) != recipient.ID {
		t.Fatal("PDF-only signature overlay did not bind its actual document recipient")
	}
}

func TestFieldMCPExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	for _, tool := range []string{"add_document_field", "delete_document_field"} {
		t.Run(tool, func(t *testing.T) {
			f := setupFieldMCPE2E(t)
			mint, keyID := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil {
				t.Fatal(err)
			}
			before := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitFieldMCPE2E(f, tool, mint.Plaintext, fieldMCPArgumentsE2E(f, tool)) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			deadline := time.Now().Add(3 * time.Second)
			for {
				var expired bool
				if err := f.pool.QueryRow(f.ctx, `SELECT expires_at<=clock_timestamp() FROM api_keys WHERE id=$1`, keyID).Scan(&expired); err != nil {
					t.Fatal(err)
				}
				if expired {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("fixture key did not expire")
				}
				time.Sleep(10 * time.Millisecond)
			}
			assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != auth.ErrMutationCredentialExpired.Error() {
				t.Fatalf("final field credential expiry=%q", got)
			}
			assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
		})
	}
}

func TestFieldMCPPendingPrivacyPreservesFieldsE2E(t *testing.T) {
	for _, linked := range []bool{true, false} {
		t.Run(fmt.Sprint("linked=", linked), func(t *testing.T) {
			f := setupFieldMCPE2E(t)
			documentID := pgtype.UUID{}
			if linked {
				documentID = pgtype.UUID{Bytes: f.doc.ID, Valid: true}
			}
			if _, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{
				OrgID: f.org, DocumentID: documentID, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true}, SubjectEmail: f.recipient.Email,
				SubjectName: f.recipient.Name, Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
			}); err != nil {
				t.Fatal(err)
			}
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			before := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture)
			for _, tool := range []string{"add_document_field", "delete_document_field"} {
				if got := fieldMCPTextE2E(t, submitFieldMCPE2E(f, tool, mint.Plaintext, fieldMCPArgumentsE2E(f, tool)), true); got != fields.ErrPendingPrivacyReview.Error() {
					t.Fatalf("pending field review refusal=%q", got)
				}
				assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
			}
		})
	}
}

func TestFieldMCPConcurrentSoftDeleteAndRetainedEvidenceE2E(t *testing.T) {
	for _, tool := range []string{"add_document_field", "delete_document_field"} {
		t.Run(tool+"/soft-delete-wait", func(t *testing.T) {
			f := setupFieldMCPE2E(t)
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitFieldMCPE2E(f, tool, mint.Plaintext, fieldMCPArgumentsE2E(f, tool)) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
			if _, err := blocked.Exec(f.ctx, `UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1`, f.doc.ID); err != nil {
				t.Fatal(err)
			}
			before := fieldMCPSnapshotInTxE2E(t, f, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != fields.ErrDocumentNotFound.Error() {
				t.Fatalf("field soft-delete refusal=%q", got)
			}
			assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
		})
		t.Run(tool+"/retained-evidence", func(t *testing.T) {
			f := setupFieldMCPE2E(t)
			if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET value='retained signing value',completed_at=clock_timestamp() WHERE id=$1`, f.field.ID); err != nil {
				t.Fatal(err)
			}
			mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
			before := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture)
			if got := fieldMCPTextE2E(t, submitFieldMCPE2E(f, tool, mint.Plaintext, fieldMCPArgumentsE2E(f, tool)), true); got != fields.ErrDocumentHasEvidence.Error() {
				t.Fatalf("field retained evidence refusal=%q", got)
			}
			assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
		})
	}
}

func TestFieldMCPInternalFailuresRollBackAndRetryE2E(t *testing.T) {
	for _, tool := range []string{"add_document_field", "delete_document_field"} {
		for _, fault := range []string{"audit-exception", "audit-no-row", "mutation-no-row"} {
			t.Run(tool+"/"+fault, func(t *testing.T) {
				f := setupFieldMCPE2E(t)
				mint, _ := mintRecipientMCPKeyE2E(t, f.lifecycleAuthorizationFixture, false, 0)
				before := recipientMCPSnapshotE2E(t, f.lifecycleAuthorizationFixture)
				name := "hash_mcp_field_failure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
				kind := "document.field_added"
				if tool == "delete_document_field" {
					kind = "document.field_deleted"
				}
				table, event := "events", "INSERT"
				predicate := fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.kind='%s'", f.doc.ID, kind)
				failure := "RAISE EXCEPTION 'fixture MCP field failure';"
				if fault == "audit-no-row" {
					failure = "RETURN NULL;"
				}
				if fault == "mutation-no-row" {
					table, failure = "document_fields", "RETURN NULL;"
					predicate = fmt.Sprintf("NEW.document_id='%s'::uuid", f.doc.ID)
					if tool == "delete_document_field" {
						event, predicate = "DELETE", fmt.Sprintf("OLD.id='%s'::uuid", f.field.ID)
					}
				}
				returnRow := "NEW"
				if event == "DELETE" {
					returnRow = "OLD"
				}
				if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF %s THEN %s END IF; RETURN %s; END $$;
					CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, predicate, failure, returnRow, name, event, table, name)); err != nil {
					t.Fatal(err)
				} //nolint:rawsql,gosec -- fixed fixture constants and generated UUID identifiers
				dropFault := func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if _, err := f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()`, name, table, name)); err != nil {
						t.Error(err)
					} //nolint:rawsql,gosec -- fixture-owned trigger and function
				}
				t.Cleanup(dropFault)
				args := fieldMCPArgumentsE2E(f, tool)
				if got := fieldMCPTextE2E(t, submitFieldMCPE2E(f, tool, mint.Plaintext, args), true); got != "internal error" {
					t.Fatalf("field internal failure exposed details: %q", got)
				}
				assertRecipientMCPUnchangedE2E(t, f.lifecycleAuthorizationFixture, before)
				dropFault()
				fieldMCPTextE2E(t, submitFieldMCPE2E(f, tool, mint.Plaintext, args), false)
				assertFieldMCPCommitE2E(t, f, tool)
			})
		}
	}
}
