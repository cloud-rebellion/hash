//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The genuine legacy envelope constructor authors recipients on its root.
// Explicit child reminders must preserve that subject topology: they cannot
// manufacture child recipients or silently rotate/invite the root's parties.
// A subsequent root reminder must still produce fresh, measured capabilities
// that complete the original whole-envelope signature ceremony and report.
func TestNativeReminderLegacyChildNoopAndRootCompletionV1E2E(t *testing.T) {
	q, root, children, parties := reminderLegacyEnvelope255(t)
	f := q.f
	defer q.assertObserversOnlyV1(t)
	actor := sendengine.Actor{OrgID: f.org, UserID: &f.user.ID, Email: "untrusted-reminder@example.test", Via: "test", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" || user.Email != f.user.Email {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	beforeRoot := nativeReminderSnapshot254(t, q, root)
	beforeChild := nativeReminderSnapshot254(t, q, children[0])
	beforeMail := completedCompanionOutboxIDsV1(t, q)
	var childRecipients, childSchedules int
	if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*)::integer FROM recipients WHERE document_id=$1),
 (SELECT count(*)::integer FROM reminders WHERE document_id=$1)`, children[0]).Scan(&childRecipients, &childSchedules); err != nil || childRecipients != 0 || childSchedules != 0 {
		t.Fatal("normal root Send unexpectedly authored child recipients or schedules", err)
	} //nolint:rawsql -- observe the actual public constructor/Send topology only
	count, err := f.s.Send.Remind(f.ctx, actor, children[0], false)
	if err != nil || count != 0 {
		t.Fatalf("explicit genuine child reminder count=%d err=%v", count, err)
	}
	q.assertObserversOnlyV1(t)
	if nativeReminderSnapshot254(t, q, root) != beforeRoot || nativeReminderSnapshot254(t, q, children[0]) != beforeChild {
		t.Fatal("zero-recipient child reminder changed its own or root ceremony")
	}
	if after := completedCompanionOutboxIDsV1(t, q); !reminderSameOutbox255(beforeMail, after) {
		t.Fatal("zero-recipient child reminder manufactured an invitation")
	}
	count, err = f.s.Send.Remind(f.ctx, actor, root, false)
	if err != nil || count != len(parties) || count != 2 {
		t.Fatalf("actual root reminder count=%d err=%v", count, err)
	}
	q.assertObserversOnlyV1(t)
	var rootEvents, measured, childEvents int
	if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*)::integer FROM events WHERE org_id=$1 AND document_id=$2 AND kind='reminder.sent'),
 (SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m
  ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id
  WHERE e.org_id=$1 AND e.document_id=$2 AND e.kind='reminder.sent'
   AND m.payload_wire_bytes=octet_length(e.payload_json::text)
   AND m.measurement_server_version_num=current_setting('server_version_num')::integer),
 (SELECT count(*)::integer FROM events WHERE org_id=$1 AND document_id=ANY($3::uuid[]) AND kind='reminder.sent')`, f.org, root, children).Scan(&rootEvents, &measured, &childEvents); err != nil || rootEvents != 2 || measured != 2 || childEvents != 0 {
		t.Fatalf("actual root/child reminder evidence=%d/%d/%d err=%v", rootEvents, measured, childEvents, err)
	} //nolint:rawsql -- exact committed M94 producer witnesses, no cache repair
	oldIDs := make([]uuid.UUID, 0, len(beforeMail))
	for id := range beforeMail {
		oldIDs = append(oldIDs, id)
	}
	var newMail int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM email_deliveries WHERE NOT(id=ANY($1::uuid[]))", oldIDs).Scan(&newMail); err != nil || newMail != 2 {
		t.Fatal("root reminder did not issue exactly its two deliveries", newMail, err)
	}
	tokenPattern := regexp.MustCompile(regexp.QuoteMeta(strings.TrimRight(f.s.PublicURL, "/")) + `/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`)
	for index, party := range parties {
		var text, reply string
		if err := f.pool.QueryRow(f.ctx, "SELECT text_body,reply_to FROM email_deliveries WHERE NOT(id=ANY($1::uuid[])) AND to_email=(SELECT email FROM recipients WHERE id=$2 AND document_id=$3)", oldIDs, party.RecipientID, root).Scan(&text, &reply); err != nil || reply != f.user.Email {
			t.Fatal("root reminder lost canonical sender or exact party delivery", err)
		}
		match := tokenPattern.FindStringSubmatch(text)
		if len(match) != 2 || match[1] == party.Token {
			t.Fatal("root reminder did not create a fresh original capability")
		}
		actual, err := f.q.GetRecipientByTokenHash(f.ctx, auth.HashMagicToken(match[1]))
		if err != nil || actual.ID != party.RecipientID || actual.DocumentID != root {
			t.Fatal("reminder message did not name its actual root recipient", err)
		}
		if _, err := f.q.GetRecipientByTokenHash(f.ctx, auth.HashMagicToken(party.Token)); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("old root invitation was not exactly invalidated after genuine reminder rotation", err)
		}
		party.Token = match[1]
		response, err := participantCapacityRespond253(t, q, party, "signature")
		if err != nil || response == nil || response.Completed != (index == len(parties)-1) {
			t.Fatal("genuinely reminded whole-envelope response failed", err)
		}
		q.assertObserversOnlyV1(t)
	}
	completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
	if err != nil || completed.Status != "completed" || !completed.FinalPdfKey.Valid || !completed.FinalPdfVersionID.Valid || completed.FinalPdfVersionID.String == "" || !completed.AuditCertKey.Valid || !completed.AuditCertVersionID.Valid || completed.AuditCertVersionID.String == "" {
		t.Fatal("reminded whole-envelope ceremony did not retain final artifacts", err)
	}
	var reports, signatures, deliveries int
	if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*)::integer FROM document_participant_reports_v1 r JOIN documents d
  ON d.id=r.document_id AND d.org_id=r.org_id
  WHERE d.id=$1 AND d.org_id=$2 AND r.completion_effective_at=d.completion_effective_at
   AND r.final_pdf_sha256=d.final_pdf_sha AND r.audit_cert_sha256=d.audit_cert_sha256
   AND r.audit_payload_sha256=d.audit_payload_sha256 AND r.audit_signature_sha256=d.audit_signature_sha256),
 (SELECT count(*)::integer FROM signatures WHERE document_id=$1),
 (SELECT count(*)::integer FROM document_participant_report_deliveries_v1 WHERE document_id=$1 AND org_id=$2)`, root, f.org).Scan(&reports, &signatures, &deliveries); err != nil || reports != 1 || signatures != 2 || deliveries != 3 {
		t.Fatal("reminded root lacks its exact signatures, report and audience deliveries", reports, signatures, deliveries, err)
	}
	certificate, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, completed.AuditCertKey.String, completed.AuditCertSha256, completed.AuditCertVersionID)
	if err != nil || !bytes.HasPrefix(certificate, []byte("%PDF-")) {
		t.Fatal("mandatory separate report is not readable by its exact committed pin", err)
	}
	payload, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
	if err != nil {
		t.Fatal("mandatory report signed payload is not readable by its exact pin", err)
	}
	signature, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
	if err != nil || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
		t.Fatal("mandatory report detached signature does not verify", err)
	}
	for _, childID := range children {
		child, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: childID, OrgID: f.org})
		if err != nil || child.Status != "completed" || child.FinalPdfKey != completed.FinalPdfKey || child.FinalPdfVersionID != completed.FinalPdfVersionID || !bytes.Equal(child.FinalPdfSha, completed.FinalPdfSha) || child.AuditCertKey != completed.AuditCertKey || child.AuditCertVersionID != completed.AuditCertVersionID || !bytes.Equal(child.AuditCertSha256, completed.AuditCertSha256) || child.AuditPayloadKey != completed.AuditPayloadKey || child.AuditPayloadVersionID != completed.AuditPayloadVersionID || !bytes.Equal(child.AuditPayloadSha256, completed.AuditPayloadSha256) || child.AuditSignatureKey != completed.AuditSignatureKey || child.AuditSignatureVersionID != completed.AuditSignatureVersionID || !bytes.Equal(child.AuditSignatureSha256, completed.AuditSignatureSha256) {
			t.Fatal("reminded root did not complete the original exact child instrument", err)
		}
	}
}

func reminderSameOutbox255(a, b map[uuid.UUID]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			return false
		}
	}
	return true
}

// Adapted from the existing public block-envelope birth: normal draft creation,
// promote, attach, root recipient authoring and real Send; no lifecycle/history,
// measurements, child recipients or recipient tokens are seeded or repaired.
func reminderLegacyEnvelope255(t *testing.T) (*ownedPublicReadFixtureV1, uuid.UUID, []uuid.UUID, []signerBrowserPartyE2E) {
	t.Helper()
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Envelopes = envelopes.New(f.q)
	f.s.Send.Envelopes = f.s.Envelopes
	f.s.Sign.Storage = f.s.Storage
	f.s.Sign.EnvelopeChildren = func(ctx context.Context, doc *generated.Document) ([]*generated.Document, error) {
		if doc == nil || !doc.IsEnvelope {
			return nil, nil
		}
		return f.s.Envelopes.Children(ctx, doc.ID, doc.OrgID)
	}
	create := func(name, role string) uuid.UUID {
		tree := map[string]any{"version": 1, "blocks": []any{}}
		if role != "" {
			tree["blocks"] = []any{map[string]any{"id": "terms-" + role, "type": "paragraph", "text": "Approved " + role + " terms for {{company}}."}, map[string]any{"id": "signature-" + role, "type": "signature_field", "attrs": map[string]any{"recipient_role": role}}}
		}
		raw, err := json.Marshal(map[string]any{"name": name, "source_kind": "blocks", "blocks_json": tree, "variables_json": map[string]string{"company": "Synthetic reminder family"}})
		if err != nil {
			t.Fatal(err)
		}
		w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents", string(raw), q.cookie)
		var created struct{ ID uuid.UUID }
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.ID == uuid.Nil {
			t.Fatalf("actual legacy block creator=%d", w.Code)
		}
		return created.ID
	}
	root := create("Reminder legacy envelope", "")
	children := []uuid.UUID{create("Reminder buyer terms", "buyer"), create("Reminder seller terms", "seller")}
	base := "/api/v1/documents/" + root.String()
	if w := submitSessionOperationE2E(f.s, http.MethodPost, base+"/promote-to-envelope", "{}", q.cookie); w.Code != http.StatusOK {
		t.Fatalf("actual legacy promote=%d", w.Code)
	}
	reminderLegacyMeasurements255(t, q, append([]uuid.UUID{root}, children...), "after public promote", 1, 0, 0)
	for index, child := range children {
		if w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/envelopes/"+root.String()+"/attach", fmt.Sprintf("{\"child_id\":\"%s\",\"position\":%d}", child, index+1), q.cookie); w.Code != http.StatusOK {
			t.Fatalf("actual legacy attach=%d", w.Code)
		}
		reminderLegacyMeasurements255(t, q, append([]uuid.UUID{root}, children...), fmt.Sprintf("after public attach %d", index+1), 1, index+1, 0)
	}
	for index, role := range []string{"buyer", "seller"} {
		raw, err := json.Marshal(map[string]any{"email": role + "@reminder-family.example.test", "name": "Synthetic " + role, "role": role, "order_index": index, "locale": "en"})
		if err != nil {
			t.Fatal(err)
		}
		if w := submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", string(raw), q.cookie); w.Code != http.StatusCreated {
			t.Fatalf("actual legacy root recipient=%d", w.Code)
		}
	}
	actor := sendengine.Actor{OrgID: f.org, UserID: &f.user.ID, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	sent, err := f.s.Send.Send(f.ctx, actor, root)
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatal("actual normal legacy envelope Send failed", err)
	}
	parties := make([]signerBrowserPartyE2E, 0, len(sent.Links))
	for _, link := range sent.Links {
		u, err := url.Parse(link.URL)
		if err != nil || !strings.HasPrefix(u.Path, "/sign/") {
			t.Fatal("actual root Send omitted signer capability", err)
		}
		parties = append(parties, signerBrowserPartyE2E{Token: strings.Clone(strings.TrimPrefix(u.Path, "/sign/")), RecipientID: link.RecipientID, Name: strings.Clone(link.Name), Role: strings.Clone(link.Role)})
	}
	sent.Links = nil
	sent.CloseConsumerV1()
	reminderLegacyMeasurements255(t, q, append([]uuid.UUID{root}, children...), "after normal native Send", 1, 2, 3)
	// Normal Send starts the tenant observer. Only an actual first current
	// signer bootstrap starts the separate process observer required below.
	bootstrap := q.lookupV1(t, parties[0].Token)
	if err := bootstrap.CloseReadV1(); err != nil {
		t.Fatal("actual first envelope invitation bootstrap did not retire", err)
	}
	q.assertObserversOnlyV1(t)
	return q, root, children, parties
}

// This is a read-only producer attribution witness before any reminder or
// response is attempted. Public topology and native Send must create intrinsic
// current measurements themselves; the fixture never repairs missing history.
func reminderLegacyMeasurements255(t *testing.T, q *ownedPublicReadFixtureV1, family []uuid.UUID, stage string, wantPromoted, wantAttached, wantSent int) {
	t.Helper()
	rows, err := q.f.pool.Query(q.f.ctx, `SELECT e.document_id::text,e.kind,coalesce(e.payload_json->>'tool',''),
 count(*)::integer,
 count(*) FILTER(WHERE m.event_id IS NOT NULL AND m.document_id=e.document_id AND m.org_id=e.org_id
  AND m.payload_wire_bytes=octet_length(e.payload_json::text)
  AND m.measurement_server_version_num=current_setting('server_version_num')::integer)::integer
 FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id
 WHERE e.org_id=$1 AND e.document_id=ANY($2::uuid[])
 GROUP BY e.document_id,e.kind,coalesce(e.payload_json->>'tool','')
 ORDER BY e.document_id,e.kind,coalesce(e.payload_json->>'tool','')`, q.f.org, family)
	if err != nil {
		t.Fatal("actual envelope producer M94 observation failed", stage, err)
	} //nolint:rawsql -- actual immutable event/measurement read oracle, never repair
	defer rows.Close()
	groups := 0
	promoted, attached, sent := 0, 0, 0
	valid := true
	for rows.Next() {
		var document, kind, tool string
		var events, measured int
		if err := rows.Scan(&document, &kind, &tool, &events, &measured); err != nil {
			t.Fatal("actual envelope producer M94 observation decode failed", stage, err)
		}
		groups++
		if kind == "document.updated" && tool == "promote_to_envelope" {
			promoted += events
		}
		if kind == "document.updated" && tool == "attach_to_envelope" {
			attached += events
		}
		if kind == "document.sent" {
			sent += events
		}
		t.Logf("%s: document=%s kind=%s tool=%s actual_events=%d current_M94=%d", stage, document, kind, tool, events, measured)
		valid = valid && events > 0 && events == measured
	}
	if err := rows.Err(); err != nil || groups == 0 || !valid || promoted != wantPromoted || attached != wantAttached || sent != wantSent {
		t.Fatal("genuine envelope constructor lacks its exact measured original producers before reminders", stage, "promote/attach/sent", promoted, attached, sent, "expected", wantPromoted, wantAttached, wantSent, err)
	}
}
