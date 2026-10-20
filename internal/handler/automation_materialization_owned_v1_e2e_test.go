//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func ownedAutomationTemplateV1(t *testing.T, q *ownedPublicReadFixtureV1, count int) (templateResponse, automationSignatureRequestInput) {
	t.Helper()
	tree := map[string]any{"version": 0, "blocks": []any{map[string]any{"type": "paragraph", "text": "Approved exact prose for {{customer}} with {{company}}."}}}
	items := tree["blocks"].([]any)
	values := make([]automationSignatureRecipientInput, count)
	for i := range values {
		role := fmt.Sprintf("party%d", i)
		items = append(items, map[string]any{"type": "signature_field", "attrs": map[string]any{"recipient_role": role}})
		values[i] = automationSignatureRecipientInput{Role: role, Email: fmt.Sprintf("party%d@owned-automation.example.test", i), Name: fmt.Sprintf("Exact party %d", i), OrderIndex: int32(i), Locale: "en"}
	}
	tree["blocks"] = items
	created := ownedBlocksTemplateCallV1(t, q.f, q.cookie, http.MethodPost, "/api/v1/templates", map[string]any{"name": "Approved native automation source", "blocks_json": tree, "variables_json": map[string]string{"customer": "Template customer", "company": "Exact Company AB"}})
	if created.Code != http.StatusCreated {
		t.Fatalf("genuine automation template=%d %s", created.Code, created.Body.String())
	}
	var out templateResponse
	if err := json.Unmarshal(created.Body.Bytes(), &out); err != nil || out.ID == uuid.Nil || len(out.ContentSHA256) != 64 {
		t.Fatal("native pinned template missing", err)
	}
	return out, automationSignatureRequestInput{TemplateID: out.ID.String(), TemplateVersion: out.Version, TemplateContentSHA256: out.ContentSHA256, Name: "Exact automation contract", Variables: map[string]string{"customer": "Actual CRM customer"}, Recipients: values, LawfulBasis: "contract"}
}
func ownedAutomationMintV1(t *testing.T, q *ownedPublicReadFixtureV1, scopes []string) string {
	t.Helper()
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.f.q.CreateAPIKey(q.f.ctx, generated.CreateAPIKeyParams{OrgID: q.f.org, UserID: q.f.user.ID, Name: "Exact automation scope fixture", KeyPrefix: key.Prefix, KeyHash: key.Hash, Scopes: scopes}); err != nil {
		t.Fatal(err)
	}
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	return key.Plaintext
}
func ownedAutomationRequestV1(t *testing.T, q *ownedPublicReadFixtureV1, key, idempotency string, in automationSignatureRequestInput) *http.Request {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/api/automation/v1/signature-requests", bytes.NewReader(raw)).WithContext(q.f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set(automationIdempotencyHeader, idempotency)
	return r
}
func ownedAutomationCallV1(t *testing.T, q *ownedPublicReadFixtureV1, key, idempotency string, in automationSignatureRequestInput) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, ownedAutomationRequestV1(t, q, key, idempotency, in))
	return w
}
func ownedAutomationCountsV1(t *testing.T, q *ownedPublicReadFixtureV1) string {
	t.Helper()
	var counts string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_array((SELECT count(*) FROM automation_signature_requests WHERE org_id=$1),(SELECT count(*) FROM documents WHERE org_id=$1),(SELECT count(*) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1),(SELECT count(*) FROM document_versions WHERE org_id=$1),(SELECT count(*) FROM events WHERE org_id=$1),(SELECT count(*) FROM email_deliveries))::text`, q.f.org).Scan(&counts)
	if err != nil {
		t.Fatal(err)
	}
	return counts
}

// Actual public key dispatch, M97 template pin/seed, native fresh producer,
// Send reservation and replay all run against real PostgreSQL. Provider and
// identity peers remain the existing synthetic fixture; no deployment claim.
func TestOwnedAutomationActualPublicPinnedReplayAndAdmissionE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	template, in := ownedAutomationTemplateV1(t, q, 2)
	key := ownedAutomationMintV1(t, q, []string{"write:authoring", "write:workflow"})
	before := ownedAutomationCountsV1(t, q)
	sourceBefore := ownedBlocksTemplateCacheV1(t, f, template.ID)
	wrong := in
	wrong.TemplateVersion++
	if w := ownedAutomationCallV1(t, q, key, "wrong-version", wrong); w.Code != http.StatusPreconditionFailed {
		t.Fatalf("original actual pin refusal=%d %s", w.Code, w.Body.String())
	}
	if ownedAutomationCountsV1(t, q) != before {
		t.Fatal("pin refusal committed claim/PII/version/audit")
	}
	missingScope := ownedAutomationMintV1(t, q, []string{"write:authoring"})
	if w := ownedAutomationCallV1(t, q, missingScope, "scope-denied", in); w.Code != http.StatusForbidden {
		t.Fatalf("workflow scope refusal=%d", w.Code)
	}
	if ownedAutomationCountsV1(t, q) != before {
		t.Fatal("scope refusal committed state")
	}
	hook := newOwnedPlainAuditGateV1(audit.KindDocumentCreated)
	var once sync.Once
	f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
		if e.Kind != audit.KindDocumentCreated {
			return
		}
		once.Do(func() { hook.eventID = id; hook.entry = e; close(hook.started); <-hook.release; close(hook.returned) })
	})
	gate := newOwnedPlainResponseGateV1()
	done := make(chan struct{})
	started := false
	defer func() {
		gate.unblock()
		hook.unblock()
		ownedPlainAwaitV1(t, done, "automation handler cleanup")
		if started {
			ownedPlainAwaitV1(t, hook.returned, "automation hook cleanup")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	}()
	go func() {
		defer close(done)
		f.s.Routes().ServeHTTP(gate, ownedAutomationRequestV1(t, q, key, "exact-request", in))
	}()
	ownedPlainAwaitV1(t, gate.started, "automation response write")
	if gate.Code != http.StatusCreated {
		gate.unblock()
		ownedPlainAwaitV1(t, done, "automation refusal response")
		t.Fatalf("actual public automation=%d %s", gate.Code, gate.Body.String())
	}
	ownedPlainAwaitV1(t, hook.started, "automation original created hook")
	started = true
	ownedPlainAssertRetainedV1(t, q, "automation hook plus response")
	gate.unblock()
	ownedPlainAwaitV1(t, done, "automation response last use")
	ownedPlainAssertRetainedV1(t, q, "automation hook after actual response")
	hook.unblock()
	ownedPlainAwaitV1(t, hook.returned, "automation hook last use")
	ownedCreationAssertDrainedV1(t, q, 2)
	var sent automationSignatureRequestResponse
	if err := json.Unmarshal(gate.Body.Bytes(), &sent); err != nil || sent.Replayed || sent.Status != "sent" || sent.DocumentID == uuid.Nil || sent.AutomationRequestID == uuid.Nil {
		t.Fatal("actual composite response omitted durable reservation", err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: sent.DocumentID, OrgID: f.org})
	if err != nil || doc.TemplateID.Bytes != template.ID || doc.SourceKind != "blocks" {
		t.Fatal("actual template/source identity lost", err)
	}
	values, err := blocks.ParseVariableValues(doc.VariablesJson)
	if err != nil || values["customer"] != "Actual CRM customer" || values["company"] != "Exact Company AB" {
		t.Fatal("approved defaults/actual values were not frozen", err)
	}
	canonical, err := blocks.ParseCanonicalTree(doc.BlocksJson)
	if err != nil || len(canonical.Blocks) != 3 || canonical.Blocks[0].Text != "Approved exact prose for {{customer}} with {{company}}." {
		t.Fatal("automation rewrote approved prose", err)
	}
	var actualEvents, measuredEvents, recipientsCount, versionsCount int
	var exact bool
	err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events WHERE document_id=$1 AND kind IN ('document.created','recipient.created')),(SELECT count(*) FROM html_snapshot_event_payload_sizes_v1 c JOIN events e ON e.id=c.event_id WHERE e.document_id=$1 AND e.kind IN ('document.created','recipient.created') AND c.payload_wire_bytes=octet_length(e.payload_json::text) AND c.measurement_server_version_num=current_setting('server_version_num')::integer),(SELECT count(*) FROM recipients WHERE document_id=$1),(SELECT count(*) FROM document_versions WHERE document_id=$1),EXISTS(SELECT 1 FROM events WHERE document_id=$1 AND kind='document.created' AND convert_from(payload_hashed,'UTF8')::jsonb->>'template_id'=$2 AND (convert_from(payload_hashed,'UTF8')::jsonb->>'template_version')::integer=$3 AND convert_from(payload_hashed,'UTF8')::jsonb->>'template_content_sha256'=$4 AND convert_from(payload_hashed,'UTF8')::jsonb->>'automation_request_id'=$5)`, doc.ID, template.ID.String(), template.Version, template.ContentSHA256, sent.AutomationRequestID.String()).Scan(&actualEvents, &measuredEvents, &recipientsCount, &versionsCount, &exact)
	if err != nil || actualEvents != 3 || measuredEvents != 3 || recipientsCount != 2 || versionsCount != 1 || !exact {
		t.Fatal("fresh native atomic provenance/version/M94 missing", actualEvents, measuredEvents, recipientsCount, versionsCount, exact, err)
	}
	after := ownedAutomationCountsV1(t, q)
	replay := ownedAutomationCallV1(t, q, key, "exact-request", in)
	var replayed automationSignatureRequestResponse
	if replay.Code != http.StatusOK || json.Unmarshal(replay.Body.Bytes(), &replayed) != nil || !replayed.Replayed || replayed.DocumentID != sent.DocumentID || replayed.AutomationRequestID != sent.AutomationRequestID || ownedAutomationCountsV1(t, q) != after {
		t.Fatalf("original replay created extra durable state=%d", replay.Code)
	}
	changed := in
	changed.Name = "Changed contract"
	if w := ownedAutomationCallV1(t, q, key, "exact-request", changed); w.Code != http.StatusConflict || ownedAutomationCountsV1(t, q) != after {
		t.Fatalf("idempotency hash collision=%d", w.Code)
	}
	if ownedBlocksTemplateCacheV1(t, f, template.ID) != sourceBefore {
		t.Fatal("materialization/Send/replay repaired or mutated template source cache")
	}
	if tag, e := f.pool.Exec(f.ctx, "DELETE FROM pdf_template_source_sizes_v1 WHERE template_id=$1 AND org_id=$2", template.ID, f.org); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("genuine missing M97 negative", e)
	}
	if w := ownedAutomationCallV1(t, q, key, "missing-template-source", in); w.Code != http.StatusServiceUnavailable || ownedAutomationCountsV1(t, q) != after || ownedBlocksTemplateCacheV1(t, f, template.ID) != "missing" {
		t.Fatalf("missing M97 source did not fail atomically without repair=%d %s", w.Code, w.Body.String())
	}
	// Replay consumes its original durable reservation without consulting an
	// unrelated current template version/cache or authorizing a second ceremony.
	if w := ownedAutomationCallV1(t, q, key, "exact-request", in); w.Code != http.StatusOK || ownedAutomationCountsV1(t, q) != after {
		t.Fatalf("durable replay depended on current template cache=%d", w.Code)
	}
	ownedCreationAssertDrainedV1(t, q, 2)
}

// This actual original50-recipient materialization qualifies only the finite
// producer's event cardinality and ownership under the unchanged fixture
// limits. It does not send/sign50parties or establish physical capacity.
func TestOwnedAutomationActualOriginalMaxRecipientsMaterializationE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	template, in := ownedAutomationTemplateV1(t, q, automationMaxRecipients)
	key := ownedAutomationMintV1(t, q, []string{"write:authoring", "write:workflow"})
	var admitted context.Context
	request := ownedAutomationRequestV1(t, q, key, "original-max", in)
	auth.RequireAPIKey(f.s.APIKeys)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { admitted = r.Context() })).ServeHTTP(httptest.NewRecorder(), request)
	if admitted == nil {
		t.Fatal("actual original API credential admission failed")
	}
	inputOwner, err := f.s.HTMLCreationSessions.NewBlocksHTTPInputV1(admitted, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer inputOwner.CloseConsumerV1()
	var prepared preparedAutomationSignatureRequest
	var hash [32]byte
	if err = inputOwner.WithAutomationHTTPBodyV1(admitted, httptest.NewRecorder(), request.Body, func(raw []byte) error {
		var decoded automationSignatureRequestInput
		if e := decodeAutomationSignatureRequestRawV1(raw, &decoded); e != nil {
			return e
		}
		var e error
		prepared, hash, e = prepareAutomationSignatureRequest(decoded)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	ctx, response := newAutomationSendResponseV1(admitted)
	defer response.closeV1()
	defer func() { response.closeV1(); inputOwner.CloseConsumerV1(); ownedCreationAssertDrainedV1(t, q, 2) }()
	claim, replayed, err := f.s.materializeAutomationSignatureRequest(ctx, automationSignatureRequestProcessInput{User: auth.SessionUser{UserID: f.user.ID, OrgID: f.org, Role: f.user.Role, Email: f.user.Email}, Request: prepared, IdempotencyKeyHash: automationIdempotencyKeyHash("original-max"), RequestHash: hash, IP: "127.0.0.1", UserAgent: "Actual original max materialization"})
	if err != nil || replayed || claim == nil || claim.State != "ready" || !claim.DocumentID.Valid {
		t.Fatal("actual original maximum native materialization refused", err)
	}
	id := uuid.UUID(claim.DocumentID.Bytes)
	var actual, measured, parties, versions int
	var intrinsic bool
	err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events WHERE document_id=$1),(SELECT count(*) FROM html_snapshot_event_payload_sizes_v1 c JOIN events e ON e.id=c.event_id WHERE e.document_id=$1 AND c.payload_wire_bytes=octet_length(e.payload_json::text) AND c.measurement_server_version_num=current_setting('server_version_num')::integer),(SELECT count(*) FROM recipients WHERE document_id=$1),(SELECT count(*) FROM document_versions WHERE document_id=$1),EXISTS(SELECT 1 FROM documents d JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id AND p.org_id=d.org_id JOIN html_creation_response_sizes_v1 r ON r.document_id=d.id AND r.org_id=d.org_id JOIN document_read_report_sizes_v1 q ON q.document_id=d.id AND q.org_id=d.org_id WHERE d.id=$1 AND d.template_id=$2 AND d.status='draft' AND p.measurement_server_version_num=current_setting('server_version_num')::integer AND r.measurement_server_version_num=p.measurement_server_version_num AND q.measurement_server_version_num=p.measurement_server_version_num AND r.blocks_wire_bytes=octet_length(d.blocks_json::text) AND p.variables_wire_bytes=octet_length(d.variables_json::text))`, id, template.ID).Scan(&actual, &measured, &parties, &versions, &intrinsic)
	if err != nil || actual != automationMaxRecipients+1 || measured != actual || parties != automationMaxRecipients || versions != 1 || !intrinsic {
		t.Fatal("original maximum genuine fresh policy/report/response/events incomplete", actual, measured, parties, versions, intrinsic, err)
	}
	ownedPlainAssertRetainedV1(t, q, "original max materialization actual response consumer")
	response.closeV1()
	inputOwner.CloseConsumerV1()
	ownedCreationAssertDrainedV1(t, q, 2)
	// Keep the original count policy, including its refusal of the51st party.
	over := in
	over.Recipients = append(append([]automationSignatureRecipientInput(nil), in.Recipients...), automationSignatureRecipientInput{Role: "extra", Email: "extra@owned-automation.example.test", Name: "Extra"})
	if _, _, err = prepareAutomationSignatureRequest(over); err == nil {
		t.Fatal("existing50recipient policy was widened")
	}
}
