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
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

// This helper is confined to lifecycle authorization tests. The older pooled
// helper remains available to component fixtures that deliberately exercise
// synthetic draft/foreign/malformed rows. Here, the actual public creator,
// topology writer, recipient authoring and normal Send own their native work.
// The single signer and two-child family match the original lifecycle cases.
func setupNativeLifecycleAuthorization256(t *testing.T, role string, sent, family bool) lifecycleAuthorizationFixture {
	t.Helper()
	if role != "owner" && role != "sender" {
		t.Fatal("native lifecycle fixture requires its original owner/sender role")
	}
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	return setupNativeLifecycleAuthorizationWithFixture257d(t, role, sent, family, q)
}

// Both profiles use this identical actual creator/topology/recipient/Send setup.
// A caller must construct its named test allocation before entering it.
func setupNativeLifecycleAuthorizationWithFixture257d(t *testing.T, role string, sent, family bool, q *ownedPublicReadFixtureV1) lifecycleAuthorizationFixture {
	t.Helper()
	if q == nil || (role != "owner" && role != "sender") {
		t.Fatal("native lifecycle fixture requires an actual owner/sender fixture")
	}
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Envelopes = envelopes.New(f.q)
	f.s.Send.Envelopes = f.s.Envelopes
	// Native Send accepts the real first-party org source, not an arbitrary
	// callback. Read the deterministic value from the actual fixture-owned
	// org row under the native source's original same-session authority.
	const customer = "Resolved fixture customer"
	if tag, err := f.pool.Exec(f.ctx, "UPDATE orgs SET name=$2,updated_at=clock_timestamp() WHERE id=$1", f.org, customer); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("actual lifecycle organization source setup", err)
	} //nolint:rawsql -- fixture-owned source data only; no authority/evidence rows
	f.s.Send.Resolver = resolver.New(f.q, &resolver.OrgSettingSource{Q: f.q})
	f.s.Sign.EnvelopeChildren = func(ctx context.Context, doc *generated.Document) ([]*generated.Document, error) {
		if doc == nil || !doc.IsEnvelope {
			return nil, nil
		}
		return f.s.Envelopes.Children(ctx, doc.ID, doc.OrgID)
	}
	create := func(name string, signature, frozen bool) uuid.UUID {
		blocks := []any{}
		if signature {
			blocks = []any{
				map[string]any{"id": "agreement", "type": "paragraph", "text": "Agreement for {{customer}}"},
				map[string]any{"id": "signature", "type": "signature_field", "attrs": map[string]any{"recipient_role": "signer"}},
			}
		}
		values := map[string]string{}
		if frozen {
			values["customer"] = "Frozen child fixture customer"
		}
		body, err := json.Marshal(map[string]any{
			"name": name, "source_kind": "blocks", "blocks_json": map[string]any{"version": 1, "blocks": blocks},
			"variables_json": values,
		})
		if err != nil {
			t.Fatal(err)
		}
		response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents", string(body), q.cookie)
		var created struct{ ID uuid.UUID }
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || created.ID == uuid.Nil {
			t.Fatalf("actual native lifecycle document creation=%d %s", response.Code, response.Body.String())
		}
		return created.ID
	}
	root := create("Native lifecycle authorization "+uuid.NewString(), !family, false)
	ids := []uuid.UUID{root}
	if family {
		response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+root.String()+"/promote-to-envelope", "{}", q.cookie)
		if response.Code != http.StatusOK {
			t.Fatalf("actual native lifecycle promotion=%d %s", response.Code, response.Body.String())
		}
		for position := 1; position <= 2; position++ {
			child := create("Native lifecycle child "+uuid.NewString(), true, true)
			body := fmt.Sprintf("{\"child_id\":\"%s\",\"position\":%d}", child, position)
			response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/envelopes/"+root.String()+"/attach", body, q.cookie)
			if response.Code != http.StatusOK {
				t.Fatalf("actual native lifecycle attachment=%d %s", response.Code, response.Body.String())
			}
			ids = append(ids, child)
		}
	}
	body, err := json.Marshal(map[string]any{"role": "signer", "email": uuid.NewString() + "@lifecycle.test", "name": "Lifecycle signer", "locale": "en"})
	if err != nil {
		t.Fatal(err)
	}
	response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+root.String()+"/recipients", string(body), q.cookie)
	var created struct{ ID uuid.UUID }
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || created.ID == uuid.Nil {
		t.Fatalf("actual native lifecycle recipient creation=%d %s", response.Code, response.Body.String())
	}
	f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	f.recipient, err = f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: created.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	// Retain the original unresolved binding arrangement and actual staged
	// observations. The kind intentionally changes from the unsupported test
	// callback to the real native org.setting producer. This setup query makes
	// no event, M94 or source authority. Public binding-writer modernization
	// remains separate application work.
	binding, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{
		DocumentID: root, VariableName: "customer", SourceKind: string(resolver.SourceOrgSetting), SourceRef: "synthetic fixture", SourcePath: "org.name",
	})
	if err != nil || binding == nil || binding.LastResolved.Valid || binding.LastValue != "" || binding.LastError != "" || binding.Fallback != "" {
		t.Fatal("original lifecycle binding must begin genuinely unresolved", err)
	}
	if role == "sender" {
		owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
		response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"sender"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
		if response.Code != http.StatusOK {
			t.Fatalf("actual lifecycle sender configuration=%d %s", response.Code, response.Body.String())
		}
		f.user, err = f.q.GetUser(f.ctx, f.user.ID)
		if err != nil || f.user.Role != role {
			t.Fatal("actual lifecycle membership readback", err)
		}
	}
	if sent {
		response := f.submit("send", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
		var sent sendDocumentResponse
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sent) != nil || sent.Status != "sent" || len(sent.Links) != 1 || sent.Links[0].RecipientID != f.recipient.ID {
			t.Fatalf("actual native lifecycle Send=%d %s", response.Code, response.Body.String())
		}
		link, err := url.Parse(sent.Links[0].URL)
		if err != nil || !strings.HasPrefix(link.Path, "/sign/") {
			t.Fatal("normal lifecycle Send omitted the actual invitation", err)
		}
		// Create the original process observer by genuine current invitation
		// lookup, then retire its actual reader before the authorization test.
		read := q.lookupV1(t, strings.TrimPrefix(link.Path, "/sign/"))
		if err := read.CloseReadV1(); err != nil {
			t.Fatal("native lifecycle invitation reader retirement", err)
		}
		t.Cleanup(func() { q.assertObserversOnlyV1(t) })
		f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
		if err != nil || f.doc.Status != "sent" {
			t.Fatal("native lifecycle Send document readback", err)
		}
		var values map[string]string
		bindings, bindingErr := f.q.ListVariableBindings(f.ctx, root)
		if json.Unmarshal(f.doc.VariablesJson, &values) != nil || values["customer"] != customer || bindingErr != nil || len(bindings) != 1 || bindings[0].VariableName != "customer" || bindings[0].SourceKind != string(resolver.SourceOrgSetting) || bindings[0].SourcePath != "org.name" || bindings[0].LastValue != customer || !bindings[0].LastResolved.Valid || bindings[0].LastError != "" || bindings[0].Fallback != "" {
			t.Fatal("real native lifecycle Send omitted resolved/frozen source or original binding observation", bindingErr)
		}
		f.recipient, err = f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: created.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A read-only witness attributes every original document event to its
	// same-transaction producer measurement. No backfill or cache repair.
	var events, measured int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,
 count(*) FILTER(WHERE m.event_id IS NOT NULL AND m.document_id=e.document_id AND m.org_id=e.org_id
  AND m.payload_wire_bytes=octet_length(e.payload_json::text)
  AND m.measurement_server_version_num=current_setting('server_version_num')::integer)::integer
 FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id
 WHERE e.org_id=$1 AND e.document_id=ANY($2::uuid[])`, f.org, ids).Scan(&events, &measured); err != nil || events == 0 || measured != events {
		t.Fatalf("actual native lifecycle producer measurements=%d/%d err=%v", events, measured, err)
	} //nolint:rawsql -- observe original producer measurements only
	if sent && family {
		// Deliberate historical fault shape for the existing void defense:
		// child credentials/schedules were never invitations created by root
		// Send. This adds no status, signature, audit or measurement authority.
		_, hash, err := auth.MintMagicToken()
		if err != nil {
			t.Fatal(err)
		}
		for _, child := range ids[1:] {
			if _, err := f.pool.Exec(f.ctx, `INSERT INTO recipients(document_id,role,name,email,magic_token_hash,magic_token_expires_at,locale)
 VALUES($1,'signer','Legacy child signer',$2,$3,$4,'en')`, child, uuid.NewString()+"@lifecycle.test", hash, time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- retain original malformed legacy child-credential defense
			if err := f.q.UpsertReminderSchedule(f.ctx, generated.UpsertReminderScheduleParams{DocumentID: child, Column2: json.RawMessage(`[{"days_after_send":3}]`), FiresRemaining: 1}); err != nil {
				t.Fatal(err)
			}
		}
	}
	q.f = f
	return f
}

func nativeLifecycleSubmit256(ctx context.Context, f lifecycleAuthorizationFixture, operation, cookie string) *httptest.ResponseRecorder {
	body := ""
	if operation == "send" {
		body = `{"lawful_basis":"contract"}`
	} else if operation == "void" {
		body = `{"reason":"Lifecycle fixture close"}`
	}
	return submitSessionOperationContextE2E(ctx, f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/"+operation, body, cookie)
}

func nativeLifecycleMCP256(ctx context.Context, f lifecycleAuthorizationFixture, tool, key string) *httptest.ResponseRecorder {
	arguments := map[string]any{"document_id": f.doc.ID}
	if tool == "void_document" {
		arguments["reason"] = "MCP fixture close"
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": arguments}})
	if err != nil {
		panic(err) // fixed scalar map cannot contain an unsupported JSON value
	}
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+key)
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, request)
	return response
}

func nativeLifecycleLockQuery256(operation string) string {
	if operation == "send" || operation == "remind" || operation == "remind_recipient" {
		return "-- name: GetHTMLSendDocumentStateHeaderV1"
	}
	return "-- name: GetDocumentForUpdate"
}
