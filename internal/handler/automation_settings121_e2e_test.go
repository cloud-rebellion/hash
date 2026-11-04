//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
)

func automationFixture121(t *testing.T) folderFixture695 {
	t.Helper()
	f := folderSetup695(t)
	f.s.Send = &send.Engine{Pool: f.pool, Queries: f.q, Audit: f.s.Audit}
	return f
}
func automationBody121(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
func TestAutomation121SenderPreferencesOptInCASAndTenantE2E(t *testing.T) {
	f := automationFixture121(t)
	path := "/api/v1/automation-preferences"
	w := f.request(http.MethodGet, path, "")
	var out send.AutomationPreferencesV1
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Revision != 0 || out.NotifySigned || out.NotifyViewed || out.ViewedScope != "first_view_per_recipient_per_send" || out.UpdatedAt != nil {
		t.Fatal("absent preference silently enabled notifications", w.Code, w.Body.String())
	}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- f.request(http.MethodPut, path, `{"expected_revision":0,"notify_viewed":true,"notify_signed":true}`).Code
		}()
	}
	wg.Wait()
	close(codes)
	success, conflict := 0, 0
	for c := range codes {
		if c == 200 {
			success++
		} else if c == 409 {
			conflict++
		} else {
			t.Fatal("unexpected CAS result", c)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("CAS failed", success, conflict)
	}
	var rows, audits, outbox int64
	err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM sender_automation_preferences_v1 WHERE org_id=$1 AND sender_user_id=$2),(SELECT count(*) FROM events WHERE org_id=$1 AND actor_user_id=$2 AND document_id IS NULL AND kind='sender_automation_preferences.updated' AND payload_json->>'revision'='1'),(SELECT count(*) FROM email_deliveries WHERE smtp_org_id=$1)`, f.org, f.user.ID).Scan(&rows, &audits, &outbox)
	if err != nil || rows != 1 || audits != 1 || outbox != 0 {
		t.Fatal("settings changed delivery or audit scope", rows, audits, outbox, err)
	}
	other := automationFixture121(t)
	w = other.request(http.MethodGet, path, "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Revision != 0 || out.NotifySigned || out.NotifyViewed {
		t.Fatal("foreign preference leaked")
	}
	if w = f.request(http.MethodPut, path, `{"expected_revision":1,"notify_viewed":false,"notify_signed":false}`); w.Code != 200 {
		t.Fatal("explicit opt-out failed", w.Code)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE users SET role='viewer' WHERE id=$1`, f.user.ID); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if w = f.request(m, path, `{"expected_revision":2,"notify_viewed":true,"notify_signed":true}`); w.Code != 403 {
			t.Fatal("revoked sender authorized", m, w.Code)
		}
	}
}
func TestAutomation121DocumentTemplatePolicyCASPreservesSourceE2E(t *testing.T) {
	f := automationFixture121(t)
	doc := f.document(t, "Exact reminder source", "draft")
	tpl, err := f.q.CreateBlocksTemplate(f.ctx, generated.CreateBlocksTemplateParams{OrgID: f.org, Name: "Reminder default", BlocksJson: json.RawMessage(`{"version":0,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`), CreatedBy: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	tpath := "/api/v1/templates/" + tpl.ID.String() + "/reminder-policy"
	if w := f.request(http.MethodPut, tpath, `{"expected_revision":0,"mode":"interval","interval_days":4,"max_fires":3}`); w.Code != 200 {
		t.Fatal("template policy", w.Code, w.Body.String())
	}
	original, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: tpl.ID, OrgID: f.org})
	if err != nil || !reflect.DeepEqual(tpl, original) {
		t.Fatal("policy rewrote immutable template/source/version", err)
	}
	path := "/api/v1/documents/" + doc.ID.String() + "/reminder-policy"
	body := automationBody121(map[string]any{"expected_revision": 0, "expected_updated_at": doc.UpdatedAt.Time.UTC(), "mode": "interval", "interval_days": 2, "max_fires": 3})
	w := f.request(http.MethodPut, path, body)
	if w.Code != 200 {
		t.Fatal("doc policy", w.Code, w.Body.String())
	}
	var policy send.DocumentReminderPolicyV1
	if json.Unmarshal(w.Body.Bytes(), &policy) != nil || policy.Revision != 1 || policy.EffectivePolicy.Mode != "interval" || policy.Source != "document" || !policy.Editable || policy.Frozen {
		t.Fatal("document contract drift", w.Body.String())
	}
	fresh, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || !reflect.DeepEqual(doc, fresh) {
		t.Fatal("policy rewrote document/source/updated_at", err)
	}
	if w = f.request(http.MethodPut, path, body); w.Code != 409 {
		t.Fatal("stale policy accepted", w.Code)
	}
	stale := automationBody121(map[string]any{"expected_revision": 1, "expected_updated_at": doc.UpdatedAt.Time.Add(-time.Second), "mode": "disabled", "interval_days": 0, "max_fires": 0})
	if w = f.request(http.MethodPut, path, stale); w.Code != 412 {
		t.Fatal("stale source observation accepted", w.Code)
	}
	other := automationFixture121(t)
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if w = other.request(m, path, body); w.Code != 404 {
			t.Fatal("foreign doc policy read/write", m, w.Code)
		}
		if w = other.request(m, tpath, `{"expected_revision":1,"mode":"disabled","interval_days":0,"max_fires":0}`); w.Code != 404 {
			t.Fatal("foreign template policy read/write", m, w.Code)
		}
	}
	// Structural purpose compatibility fixture: no native source history is
	// fabricated. The real normal-purpose guard must keep settings read-only.
	if _, err = f.pool.Exec(f.ctx, `UPDATE documents SET metadata=jsonb_set(metadata,'{hash:document-purpose:v1}','{"schema_version":1,"purpose":"document"}'::jsonb) WHERE id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	}
	w = f.request(http.MethodGet, path, "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &policy) != nil || policy.Editable {
		t.Fatal("normal-purpose policy not readonly", w.Code)
	}
	if w = f.request(http.MethodPut, path, body); w.Code != 409 {
		t.Fatal("normal-purpose reminder mutation accepted", w.Code)
	}
}
func TestAutomation121GenuineNativeSendFreezesPolicyAndManualNeverRefillsE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	doc := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, "rest", cookie, map[string]any{"name": "Real policy Send", "source_kind": "blocks", "blocks_json": json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Synthetic reminder terms"},{"type":"signature_field","attrs":{"recipient_role":"signer"}}]}`), "variables_json": map[string]string{}}), "rest")
	path := "/api/v1/documents/" + doc.ID.String() + "/reminder-policy"
	w := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPut, path, map[string]any{"expected_revision": 0, "expected_updated_at": doc.UpdatedAt.Time.UTC(), "mode": "interval", "interval_days": 2, "max_fires": 3})
	if w.Code != 200 {
		t.Fatal("policy save", w.Code, w.Body.String())
	}
	w = ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/recipients", map[string]any{"email": uuid.NewString() + "@policy.example.test", "name": "Synthetic policy signer", "role": "signer", "order_index": 0, "locale": "en"})
	if w.Code != 201 {
		t.Fatal("native recipient", w.Code, w.Body.String())
	}
	w = ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/send", map[string]any{"lawful_basis": "contract"})
	if w.Code != 200 {
		t.Fatal("native Send", w.Code, w.Body.String())
	}
	var exact bool
	err := f.pool.QueryRow(f.ctx, `SELECT p.sender_user_id=d.sender_id AND p.mode='interval' AND p.interval_days=2 AND p.max_fires=3 AND p.source='document' AND p.document_policy_revision=1 AND r.fires_remaining=3 AND r.next_fire_at=d.sent_at+interval '48 hours' AND r.schedule_json='[{"days_after_send":2},{"days_after_send":4},{"days_after_send":6}]'::jsonb FROM documents d JOIN reminder_policy_snapshots_v1 p ON p.document_id=d.id AND p.sent_at=d.sent_at JOIN reminders r ON r.document_id=d.id WHERE d.id=$1 AND d.org_id=$2`, doc.ID, f.org).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("actual Send did not freeze exact policy/firstfire", err)
	}
	// Actual manual SQL invoked by the native adapter may postpone a remaining
	// schedule; it cannot create a row or replenish its count. This is SQL proof,
	// not an assertion that a synthetic human reminder/email was delivered.
	if _, err = f.pool.Exec(f.ctx, `UPDATE reminders SET fires_remaining=1 WHERE document_id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.q.ResetFrozenReminderAfterManualV1(f.ctx, generated.ResetFrozenReminderAfterManualV1Params{DocumentID: doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	var count int32
	var delay float64
	err = f.pool.QueryRow(f.ctx, `SELECT fires_remaining,extract(epoch FROM next_fire_at-last_fired_at) FROM reminders WHERE document_id=$1`, doc.ID).Scan(&count, &delay)
	if err != nil || count != 1 || delay != 2*24*60*60 {
		t.Fatal("manual reset replenished count or ignored frozen delay", count, delay, err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE reminders SET fires_remaining=0 WHERE document_id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.q.ResetFrozenReminderAfterManualV1(f.ctx, generated.ResetFrozenReminderAfterManualV1Params{DocumentID: doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT fires_remaining FROM reminders WHERE document_id=$1`, doc.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("exhausted manual count replenished", err)
	}
	w = ownedBlocksTemplateCallV1(t, f, cookie, http.MethodGet, path, nil)
	var policy send.DocumentReminderPolicyV1
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &policy) != nil || !policy.Frozen || policy.Editable || fmt.Sprint(policy.EffectivePolicy.OffsetsDays) != "[2 4 6]" {
		t.Fatal("sent policy not honest frozen readonly", w.Code, w.Body.String())
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE reminder_policy_snapshots_v1 SET interval_days=3 WHERE document_id=$1`, doc.ID); err == nil {
		t.Fatal("frozen schedule history mutable")
	}
	ownedPlainAssertDrainedV1(t, q)
}
