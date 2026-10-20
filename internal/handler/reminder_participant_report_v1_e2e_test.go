//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
)

// This is a positive acceptance regression, not an expected-failure test. The
// original owned fixture creates, reviews and Sends its real approved HTML PDF;
// the public reminder must preserve completion of that partly signed ceremony.
// External renderer/storage protocol peers remain synthetic. No event cache,
// signature, status, finalization receipt or report is fabricated or repaired.
func TestReminderPreservesPartlySignedParticipantReportV1E2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	if len(parties) != 2 {
		t.Fatal("ordinary reminder regression requires two genuine parties")
	}
	defer q.assertObserversOnlyV1(t)

	first, err := ordinaryPreparationSign249(t, q, parties[0].Token, parties[0].Name)
	if err != nil || first == nil || first.Completed {
		t.Fatal("first genuine response did not leave the ordinary ceremony partly signed", err)
	}
	var beforeMissing int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*)::integer FROM events e
 WHERE e.document_id=$1 AND e.org_id=$2 AND NOT EXISTS (
 SELECT 1 FROM html_snapshot_event_payload_sizes_v1 m WHERE m.event_id=e.id
 AND m.document_id=e.document_id AND m.org_id=e.org_id
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer)`, doc.ID, f.org).Scan(&beforeMissing); err != nil || beforeMissing != 0 {
		t.Fatal("ordinary pre-reminder history was not genuinely measured", beforeMissing, err)
	} //nolint:rawsql -- scalar observation of actual committed rows; no backfill
	beforeMail := completedCompanionOutboxIDsV1(t, q)

	response := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/remind", "", q.cookie)
	var reminder struct {
		Reminded int `json:"reminded"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &reminder) != nil || reminder.Reminded != 1 {
		t.Fatal("public reminder did not commit exactly the remaining party", response.Code)
	}
	var events, measured int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,
 count(*) FILTER (WHERE m.event_id IS NOT NULL
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer
 AND m.payload_wire_bytes=octet_length(e.payload_json::text))::integer
 FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m
 ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id
 WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='reminder.sent'`, doc.ID, f.org).Scan(&events, &measured); err != nil || events != 1 {
		t.Fatal("public reminder omitted its actual scoped audit row", events, err)
	} //nolint:rawsql -- observe the fresh producer measurement, never insert it
	t.Logf("actual reminder audit rows=%d fresh exact payload measurements=%d", events, measured)
	if measured != events {
		// Keep this as a real failure, but continue to the actual final response
		// so the retained run also shows whether completion is stranded.
		t.Errorf("public reminder committed %d audit rows but only %d fresh exact payload measurements", events, measured)
	}
	var reminderID uuid.UUID
	if err = f.pool.QueryRow(f.ctx, "SELECT id FROM events WHERE document_id=$1 AND org_id=$2 AND kind='reminder.sent'", doc.ID, f.org).Scan(&reminderID); err != nil {
		t.Fatal(err)
	}
	event, err := f.q.GetEventByID(f.ctx, reminderID)
	if err != nil || event == nil {
		t.Fatal("committed reminder event unavailable", err)
	}
	computed, err := audit.RecomputeEventRowHash(event)
	if err != nil || !bytes.Equal(computed, event.RowHash) || !event.RecipientID.Valid || uuid.UUID(event.RecipientID.Bytes) != parties[1].RecipientID {
		t.Fatal("reminder audit is not the original remaining-party chain row", err)
	}

	// Use only the new actual outbox capability produced by Remind. Its token
	// must match the persisted recipient rotation; reusing the original link
	// would test expiry/refusal instead of the report completion integration.
	old := make([]uuid.UUID, 0, len(beforeMail))
	for id := range beforeMail {
		old = append(old, id)
	}
	var textBody string
	if err = f.pool.QueryRow(f.ctx, `SELECT text_body FROM email_deliveries
 WHERE NOT (id=ANY($1::uuid[])) AND to_email=(
 SELECT email FROM recipients WHERE id=$2 AND document_id=$3)`, old, parties[1].RecipientID, doc.ID).Scan(&textBody); err != nil {
		t.Fatal("new actual reminder outbox row unavailable", err)
	}
	capability := regexp.MustCompile(regexp.QuoteMeta(strings.TrimRight(f.s.PublicURL, "/")) + `/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`).FindStringSubmatch(textBody)
	if len(capability) != 2 || capability[1] == parties[1].Token {
		t.Fatal("public reminder did not issue a fresh outbox capability")
	}
	rotated, err := f.q.GetRecipientByTokenHash(f.ctx, auth.HashMagicToken(capability[1]))
	if err != nil || rotated.ID != parties[1].RecipientID || rotated.DocumentID != doc.ID {
		t.Fatal("actual reminder mail did not match the persisted rotation", err)
	}
	last, signErr := ordinaryPreparationSign249(t, q, capability[1], parties[1].Name)
	current, readErr := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if readErr != nil || current == nil {
		t.Fatal("ordinary document unavailable after the real final response", readErr)
	}
	var signatures, reports int
	if err = f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*)::integer FROM signatures WHERE document_id=$1),
 (SELECT count(*)::integer FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2)`, doc.ID, f.org).Scan(&signatures, &reports); err != nil {
		t.Fatal(err)
	}
	completed := last != nil && last.Completed
	t.Logf("after actual final response: completed=%v status=%s signatures=%d reports=%d", completed, current.Status, signatures, reports)
	if signErr != nil || !completed || current.Status != "completed" || signatures != 2 || reports != 1 {
		t.Fatal("reminded partly signed ceremony did not publish its mandatory participant report", signErr)
	}
	payload, err := readDocumentArtifact(f.ctx, f.s.Storage, current, current.AuditPayloadKey.String, current.AuditPayloadSha256, current.AuditPayloadVersionID)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := readDocumentArtifact(f.ctx, f.s.Storage, current, current.AuditSignatureKey.String, current.AuditSignatureSha256, current.AuditSignatureVersionID)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := evidence.ParseCertificateCommitments(payload)
	if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || !strings.Contains(string(payload), reminderID.String()) || !strings.Contains(string(payload), hex.EncodeToString(event.RowHash)) || !strings.Contains(string(payload), audit.KindReminderSent) || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
		t.Fatal("completed signed report omitted the exact real reminder event", err)
	}
	assertFreshParticipantReport406(t, f, current, payload)

}
