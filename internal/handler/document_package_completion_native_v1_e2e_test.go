//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Preparation, private batch authority, SQL and SDK requests are genuine.
// This local COMPLIANCE peer does not qualify a remote provider, an OS restart,
// a nonempty package Send, a signature or legal enforceability.
func packageCompletionBirth241(t *testing.T, q *ownedPublicReadFixtureV1) (pdfadmission.HTMLSendPackageIntentMetadataV1, uuid.UUID) {
	return packageCompletionPreparedBirth241(t, q, 1, true)
}
func packageCompletionPreparedBirth241(t *testing.T, q *ownedPublicReadFixtureV1, partyCount int, requiresSignature bool) (pdfadmission.HTMLSendPackageIntentMetadataV1, uuid.UUID) {
	t.Helper()
	root := packageImported220(t, q, "Prepared main-only native Send")
	if partyCount < 1 {
		t.Fatal("native completion preparation needs an actual party")
	}
	if !requiresSignature {
		input, err := json.Marshal(map[string]any{"expected_updated_at": root.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "requires_signature": false})
		if err != nil {
			t.Fatal(err)
		}
		response := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/documents/"+root.ID.String(), string(input), q.cookie)
		if response.Code != http.StatusOK {
			t.Fatal("actual draft acknowledgement mode update failed", response.Code)
		}
	}
	var recipient recipientResponse
	for i := 0; i < partyCount; i++ {
		input, err := json.Marshal(map[string]any{"email": fmt.Sprintf("native-completion-%03d@example.test", i), "name": fmt.Sprintf("Native completion recipient %d", i), "role": "signer", "locale": "en"})
		if err != nil {
			t.Fatal(err)
		}
		party := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/recipients", string(input), q.cookie)
		if party.Code != http.StatusCreated || json.Unmarshal(party.Body.Bytes(), &recipient) != nil || recipient.ID == uuid.Nil || recipient.DocumentID != root.ID {
			t.Fatal("genuine completion recipient creation failed", i, party.Code)
		}
		if requiresSignature {
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{"document_id": root.ID.String(), "type": "signature", "recipient_id": recipient.ID.String(), "page": 1, "required": true, "label": "Signature", "x_pct": 20, "y_pct": 65, "w_pct": 45, "h_pct": 10}, nil))
			if response.Code != http.StatusCreated {
				t.Fatal("genuine visible signature field creation failed", response.Code)
			}
		}
	}
	confirmation, err := q.f.q.ConfirmDocumentLawfulBasis(q.f.ctx, generated.ConfirmDocumentLawfulBasisParams{DocumentID: root.ID, OrgID: q.f.org, LawfulBasis: "contract", ConfirmedBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}, Via: "test"})
	if err != nil || confirmation == nil || confirmation.DocumentID != root.ID || strings.TrimSpace(confirmation.ControllerName) == "" || strings.TrimSpace(confirmation.ControllerContact) == "" {
		t.Fatal("actual lawful-basis/disclosure preparation failed", err)
	}
	// Confirmation changes the draft clock; use its genuinely refreshed value.
	root = packageLatest223(t, q, root.ID)
	p := packageCreate223(t, q, root)
	root = packageLatest223(t, q, root.ID)
	if root.RequiresSignature != requiresSignature {
		t.Fatal("prepared PDF signing mode differs from actual draft authoring")
	}
	var m pdfadmission.HTMLSendPackageIntentMetadataV1
	err = packageCaptureRun234(t, q, root, p, func(*pdfadmission.ApplicationHTMLSendOperationV1, *pdfadmission.ApplicationHTMLSendPackageDraftV1, authoring.Actor) error {
		return nil
	}, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
		if _, e := packageCaptureAppend234(t, call, w, prior); e != nil {
			return e
		}
		var e error
		m, e = w.CreatePackageIntentV1(call, pdfadmission.HTMLSendIntentActorV1{IP: "127.0.0.1", Via: "synthetic-owned-test", Tool: "native-package-completion"})
		if e != nil {
			return e
		}
		if _, e = w.FreezeBrandingV1(call); e != nil {
			return e
		}
		return w.BeginSendSealingV1(call)
	})
	if err != nil || m.AttemptID == uuid.Nil {
		t.Fatal("actual prepared package Send birth failed", err)
	}
	packageWorkerDrained239(t, q)
	return m, recipient.ID
}

func packageCompletionNativeFixture241(t *testing.T) (*ownedPublicReadFixtureV1, *packageRetentionNativePeer240, *storage.Client, pdfadmission.HTMLSendPackageIntentMetadataV1, uuid.UUID) {
	t.Helper()
	q := inspectionFixturePG236(t)
	m, recipient := packageCompletionBirth241(t, q)
	peer := &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}
	client := packageRetentionNativeClient240(t, q, peer)
	t.Cleanup(func() {
		peer.mu.Lock()
		failure := peer.failure
		peer.mu.Unlock()
		if failure != nil {
			t.Error("strict completion storage peer", failure)
		}
	})
	return q, peer, client, m, recipient
}
func packageCompletionConfig241(t *testing.T, q *ownedPublicReadFixtureV1) pdfadmission.PackageSendCompletionConfigV1 {
	t.Helper()
	var name string
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT name FROM orgs WHERE id=$1", q.f.org).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return pdfadmission.PackageSendCompletionConfigV1{PublicURL: q.f.s.PublicURL, OrgName: name, Audit: q.f.s.Audit}
}
func packageCompletionObservation241(v pdfadmission.HTMLSendPackageSendObservationV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, status string) error {
	if err := packageWorkerObservation239(v.Attempt, packageWorkerJob239{meta: m, created: m.CreatedAt}, pdfadmission.HTMLSendPackageAttemptCompletedV1); err != nil {
		return err
	}
	if !v.RetentionVerified || !v.CompletionVerified || v.Status != status || v.Attempt.RetentionStartedAt.IsZero() || v.Attempt.RetentionCompletedAt.IsZero() {
		return errors.New("native completion did not deliver exact durable effects")
	}
	return nil
}
func packageCompletionRun241(t *testing.T, q *ownedPublicReadFixtureV1, client *storage.Client, m pdfadmission.HTMLSendPackageIntentMetadataV1, status string) {
	t.Helper()
	batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
	defer batch.CloseConsumerV1()
	called := false
	more, err := batch.WithNextSendV1(client, packageCompletionConfig241(t, q), func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
		called = true
		if e := packageCompletionObservation241(v, m, status); e != nil {
			return e
		}
		return packageRetentionNativeNoWorkSQL240(q)
	})
	if !more || !called || err != nil {
		t.Fatal("actual native completion failed", more, called, err)
	}
	batch.CloseConsumerV1()
	packageWorkerDrained239(t, q)
}
func packageCompletionNativeState241(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1) string {
	t.Helper()
	return packageMeasurementState232(t, q) + packageMemberRetentionState240(t, q, m) + packageRetentionNativeCeremonyState240(t, q, m) + packageCompletionReceiptsState241(t, q, m)
}
func packageCompletionActualEffects241(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, status string, wantRecipients ...int) {
	t.Helper()
	packageAttemptInspect235(t, q, m, false, "completed")
	root := packageLatest223(t, q, m.Capture.DocumentID)
	if root.Status != status || !root.SentAt.Valid || !root.SentAt.Time.Equal(m.Article13NoticeEpochAt) || !root.Article13NoticeEpochAt.Time.Equal(m.Article13NoticeEpochAt) || !root.Article13NoticeEpochV61Committed || root.Article13NoticeSchema != "hash-a13-2026-08-31" || !root.EvidenceVersionPinsRequired {
		t.Fatal("native completion changed original signing epoch/status")
	}
	var outcome string
	var recipients, invites, sentEvents, invitedEvents, expiredEvents, mails, reminders, effectBytes int
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT c.outcome,c.recipient_count,c.invite_count,octet_length(c.effect_sha256),
 (SELECT count(*) FROM events WHERE document_id=c.document_id AND kind='document.sent' AND payload_json->>'package_send_attempt_id'=c.attempt_id::text),
 (SELECT count(*) FROM events WHERE document_id=c.document_id AND kind='recipient.invited' AND payload_json->>'package_send_attempt_id'=c.attempt_id::text),
 (SELECT count(*) FROM events WHERE document_id=c.document_id AND kind='document.expired' AND payload_json->>'package_send_attempt_id'=c.attempt_id::text),
 (SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM reminders WHERE document_id=c.document_id)
 FROM document_package_send_completions_v1 c WHERE c.attempt_id=$1 AND c.org_id=$2 AND c.document_id=$3`, m.AttemptID, m.Capture.OrgID, m.Capture.DocumentID).Scan(&outcome, &recipients, &invites, &effectBytes, &sentEvents, &invitedEvents, &expiredEvents, &mails, &reminders)
	expectedRecipients := 1
	if len(wantRecipients) > 1 {
		t.Fatal("invalid actual effect oracle cardinality")
	}
	if len(wantRecipients) == 1 {
		expectedRecipients = wantRecipients[0]
	}
	wantInvites, wantExpired := expectedRecipients, 0
	if status == "expired" {
		wantInvites, wantExpired = 0, 1
	}
	if err != nil || outcome != status || recipients != expectedRecipients || invites != wantInvites || effectBytes != 32 || sentEvents != 1 || invitedEvents != wantInvites || expiredEvents != wantExpired || mails != wantInvites || (status == "expired" && reminders != 0) {
		t.Fatal("native completion effect set differs", err, outcome, recipients, invites, sentEvents, invitedEvents, expiredEvents, mails, reminders)
	}
	if status == "expired" {
		var live int
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*) FROM recipients WHERE document_id=$1 AND magic_token_expires_at>clock_timestamp()", root.ID).Scan(&live); err != nil || live != 0 {
			t.Fatal("late expiry left a usable invitation", err, live)
		}
	}
	packageCompletionActualChain241(t, q, 1+wantInvites+wantExpired)
}

// Verify every real organization event from one consistent snapshot, including
// the package bridge's hashes and links to earlier ordinary authoring events.
func packageCompletionActualChain241(t *testing.T, q *ownedPublicReadFixtureV1, minimum int) {
	t.Helper()
	tx, err := q.f.pool.BeginTx(q.f.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("actual completion chain snapshot failed", err)
	}
	defer tx.Rollback(q.f.ctx)
	var total int
	if err = tx.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM events WHERE org_id=$1", q.f.org).Scan(&total); err != nil {
		t.Fatal("actual completion chain count failed", err)
	}
	verifier := audit.NewChainVerifier()
	params := generated.ListChainedEventsPageForOrgParams{OrgID: q.f.org, PageLimit: 64}
	for {
		page, e := q.f.q.WithTx(tx).ListChainedEventsPageForOrg(q.f.ctx, params)
		if e != nil {
			t.Fatal("actual completion chain page failed", e)
		}
		if len(page) == 0 {
			break
		}
		verifier.VerifyPage(page)
		last := page[len(page)-1]
		params.AfterCreatedAt = last.CreatedAt
		params.AfterID = pgtype.UUID{Bytes: last.ID, Valid: true}
	}
	result := verifier.Result()
	if !result.OK || !result.Complete || result.TotalChecked != total || total < minimum {
		t.Fatal("actual complete organization chain did not verify", result.TotalChecked, total, result.FailureCount)
	}
	if err = tx.Commit(q.f.ctx); err != nil {
		t.Fatal("actual completion chain snapshot did not retire", err)
	}
	t.Logf("actual complete organization chain recomputed and linked: %d events", total)
}

func TestDocumentPackageNativeCompletionV1E2E(t *testing.T) {
	t.Run("actual atomic Send and stale private slot preserve one invitation", func(t *testing.T) {
		q, peer, client, m, _ := packageCompletionNativeFixture241(t)
		first, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(q.f.ctx, pdfadmission.PackageSendRecoveryCursorV1{})
		if err != nil || first == nil {
			t.Fatal(err)
		}
		defer first.CloseConsumerV1()
		stale, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(q.f.ctx, pdfadmission.PackageSendRecoveryCursorV1{})
		if err != nil || stale == nil {
			t.Fatal(err)
		}
		defer stale.CloseConsumerV1()
		cfg := packageCompletionConfig241(t, q)
		for i, batch := range []*pdfadmission.ApplicationPackageSendRecoveryBatchV1{first, stale} {
			before, counts := "", peer.counts240()
			if i == 1 {
				before = packageCompletionNativeState241(t, q, m)
			}
			called := false
			more, err := batch.WithNextSendV1(client, cfg, func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
				called = true
				if e := packageCompletionObservation241(v, m, "sent"); e != nil {
					return e
				}
				return packageRetentionNativeNoWorkSQL240(q)
			})
			if !more || !called || err != nil {
				t.Fatal("genuine private completion slot failed", i, more, called, err)
			}
			if i == 1 && (peer.counts240() != counts || packageCompletionNativeState241(t, q, m) != before) {
				t.Fatal("terminal retry mutated ceremony or called storage")
			}
			batch.CloseConsumerV1()
		}
		packageWorkerDrained239(t, q)
		packageCompletionActualEffects241(t, q, m, "sent")
		if counts := peer.counts240(); counts[4] != 1 || counts[3] != 1 {
			t.Fatal("completion did not apply exactly one retained PDF", counts)
		}
		fresh := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
		more, err := fresh.WithNextSendV1(client, cfg, func(pdfadmission.HTMLSendPackageSendObservationV1) error {
			return errors.New("fresh queue redispatched terminal winner")
		})
		fresh.CloseConsumerV1()
		if more || err != nil {
			t.Fatal("terminal attempt remained pending", more, err)
		}
		packageWorkerDrained239(t, q)
		// Public viewing can append genuine audits: visit only after retry checks.
		var body string
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT text_body FROM email_deliveries LIMIT 1").Scan(&body); err != nil {
			t.Fatal(err)
		}
		match := regexp.MustCompile(`/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`).FindStringSubmatch(body)
		if len(match) != 2 {
			t.Fatal("committed durable invitation omitted its usable token")
		}
		for _, endpoint := range []string{"", "/pdf", "/fields"} {
			if w := q.requestV1(match[1], endpoint); w.Code != http.StatusOK {
				t.Fatal("committed outbox token public read failed", endpoint, w.Code)
			}
			q.assertObserversOnlyV1(t)
		}
	})
	t.Run("unstarted expired attempt aborts before storage", func(t *testing.T) {
		q, peer, client, m, _ := packageCompletionNativeFixture241(t)
		if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", m.Capture.DocumentID); err != nil {
			t.Fatal(err)
		}
		counts := peer.counts240()
		batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
		defer batch.CloseConsumerV1()
		called := false
		more, err := batch.WithNextSendV1(client, packageCompletionConfig241(t, q), func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
			called = true
			if e := packageWorkerObservation239(v.Attempt, packageWorkerJob239{meta: m, created: m.CreatedAt}, pdfadmission.HTMLSendPackageAttemptAbortedV1); e != nil {
				return e
			}
			if v.RetentionVerified || v.CompletionVerified || v.Status != "draft" {
				return errors.New("reversible expiry claimed completion")
			}
			return packageRetentionNativeNoWorkSQL240(q)
		})
		if !more || !called || err != nil {
			t.Fatal("unstarted expiry failed", more, called, err)
		}
		batch.CloseConsumerV1()
		packageWorkerDrained239(t, q)
		packageAttemptInspect235(t, q, m, false, "aborted")
		var receipts, mails int
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*) FROM document_package_send_completions_v1 WHERE attempt_id=$1),(SELECT count(*) FROM email_deliveries)", m.AttemptID).Scan(&receipts, &mails); err != nil || receipts != 0 || mails != 0 || peer.counts240() != counts || packageLatest223(t, q, m.Capture.DocumentID).Status != "draft" {
			t.Fatal("reversible expiry emitted irreversible effects", err, receipts, mails)
		}
	})
	t.Run("retained late expiry commits expired without invitations", func(t *testing.T) {
		q, peer, client, m, _ := packageCompletionNativeFixture241(t)
		packageRetentionNativeRun240(t, q, client, m, true)
		counts := peer.counts240()
		if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", m.Capture.DocumentID); err != nil {
			t.Fatal(err)
		}
		packageCompletionRun241(t, q, client, m, "expired")
		packageCompletionActualEffects241(t, q, m, "expired")
		if peer.counts240() != counts {
			t.Fatal("retained late expiry replayed provider work")
		}
	})
	for _, policy := range []string{"recipient", "visible field", "lawful basis", "current privacy"} {
		t.Run(policy+" refuses before provider retention", func(t *testing.T) {
			q, peer, client, m, recipient := packageCompletionNativeFixture241(t)
			switch policy {
			case "recipient":
				if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET email='invalid' WHERE id=$1", recipient); err != nil {
					t.Fatal(err)
				}
			case "visible field":
				if _, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM document_fields WHERE document_id=$1", m.Capture.DocumentID); err != nil {
					t.Fatal(err)
				}
			case "lawful basis":
				if _, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM document_lawful_basis_confirmations WHERE document_id=$1", m.Capture.DocumentID); err != nil {
					t.Fatal(err)
				}
			case "current privacy":
				if _, err := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: m.Capture.DocumentID, Valid: true}, SubjectEmail: "native-completion-privacy@example.test", Kind: "access", RequestedVia: "sender", PayloadJson: []byte("{}")}); err != nil {
					t.Fatal(err)
				}
			}
			before, counts := packageCompletionNativeState241(t, q, m), peer.counts240()
			batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
			defer batch.CloseConsumerV1()
			called := false
			more, err := batch.WithNextSendV1(client, packageCompletionConfig241(t, q), func(pdfadmission.HTMLSendPackageSendObservationV1) error { called = true; return nil })
			batch.CloseConsumerV1()
			packageWorkerDrained239(t, q)
			if !more || err == nil || called || peer.counts240() != counts || packageCompletionNativeState241(t, q, m) != before {
				t.Fatal("current policy refusal changed ceremony or reached provider", policy, more, called, err)
			}
			packageAttemptInspect235(t, q, m, true, "")
		})
	}
	t.Run("frozen branding refuses direct rewrite without weakening preparation", func(t *testing.T) {
		q, peer, _, m, _ := packageCompletionNativeFixture241(t)
		before, counts := packageCompletionNativeState241(t, q, m), peer.counts240()
		_, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM document_branding_override WHERE document_id=$1", m.Capture.DocumentID)
		packageExpectPG218(t, err, "P0001")
		if packageCompletionNativeState241(t, q, m) != before || peer.counts240() != counts {
			t.Fatal("frozen branding refusal changed ceremony")
		}
	})
	t.Run("copied batch close retains completion funding through actual callback", func(t *testing.T) {
		q, _, client, m, _ := packageCompletionNativeFixture241(t)
		batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
		defer batch.CloseConsumerV1()
		entered, release := make(chan struct{}), make(chan struct{})
		defer close(release)
		type result struct {
			more bool
			err  error
		}
		done := make(chan result, 1)
		cfg := packageCompletionConfig241(t, q)
		go func() {
			more, err := batch.WithNextSendV1(client, cfg, func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
				if e := packageCompletionObservation241(v, m, "sent"); e != nil {
					return e
				}
				close(entered)
				<-release
				return nil
			})
			done <- result{more, err}
		}()
		select {
		case <-entered:
		case r := <-done:
			t.Fatal("completion ended before callback", r)
		case <-q.f.ctx.Done():
			t.Fatal(q.f.ctx.Err())
		}
		before, err := q.runtime.SnapshotV1(q.f.org)
		if err != nil {
			t.Fatal(err)
		}
		copy := *batch
		copy.CloseConsumerV1()
		after, err := q.runtime.SnapshotV1(q.f.org)
		if err != nil || before.Global != after.Global || before.GlobalGrants != after.GlobalGrants || before.GlobalGrants <= 2 || q.runtime.SessionsV1().PendingV1().PackageSendRecoveryBatches != 1 {
			t.Fatal("copied close released live completion resources", err)
		}
		release <- struct{}{}
		select {
		case r := <-done:
			if !r.more || r.err != nil {
				t.Fatal("joined completion callback failed", r)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("actual completion callback did not join")
		}
		batch.CloseConsumerV1()
		packageWorkerDrained239(t, q)
		packageCompletionActualEffects241(t, q, m, "sent")
	})
	for _, expiry := range []string{"NULL expiry", "expiry beyond thirty days"} {
		t.Run(expiry+" uses the exact bounded magic-link policy", func(t *testing.T) {
			q, _, client, m, recipient := packageCompletionNativeFixture241(t)
			statement := "UPDATE documents SET expires_at=NULL WHERE id=$1"
			if expiry != "NULL expiry" {
				statement = "UPDATE documents SET expires_at=clock_timestamp()+interval '45 days' WHERE id=$1"
			}
			if _, err := q.f.pool.Exec(q.f.ctx, statement, m.Capture.DocumentID); err != nil {
				t.Fatal(err)
			}
			before := time.Now().UTC().Truncate(time.Microsecond)
			packageCompletionRun241(t, q, client, m, "sent")
			after := time.Now().UTC().Truncate(time.Microsecond)
			packageCompletionActualEffects241(t, q, m, "sent")
			var tokenExpiry, receiptExpiry time.Time
			if err := q.f.pool.QueryRow(q.f.ctx, "SELECT r.magic_token_expires_at,i.token_expires_at FROM recipients r JOIN document_package_send_initial_invite_receipts_v1 i ON i.recipient_id=r.id WHERE r.id=$1 AND i.attempt_id=$2", recipient, m.AttemptID).Scan(&tokenExpiry, &receiptExpiry); err != nil || !tokenExpiry.Equal(receiptExpiry) || tokenExpiry.Before(before.Add(30*24*time.Hour)) || tokenExpiry.After(after.Add(30*24*time.Hour)) || !tokenExpiry.Equal(tokenExpiry.UTC().Truncate(time.Microsecond)) {
				t.Fatal("actual minted token and immutable receipt violate UTC microsecond thirty-day policy", err)
			}
		})
	}
	t.Run("actual acknowledgement above one hundred recipients preserves normal policy", func(t *testing.T) {
		q := inspectionFixturePG236(t)
		packageWorkerEnterprisePlan239(t, q)
		m, _ := packageCompletionPreparedBirth241(t, q, 101, false)
		peer := &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}
		client := packageRetentionNativeClient240(t, q, peer)
		t.Cleanup(func() {
			peer.mu.Lock()
			failure := peer.failure
			peer.mu.Unlock()
			if failure != nil {
				t.Error("actual acknowledgement protocol peer", failure)
			}
		})
		packageCompletionRun241(t, q, client, m, "sent")
		packageCompletionActualEffects241(t, q, m, "sent", 101)
		if counts := peer.counts240(); counts[3] != 1 || counts[4] != 1 {
			t.Fatal("actual acknowledgement repeated retained PDF", counts)
		}
	})

}
