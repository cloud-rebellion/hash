//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func packageLifecycleDown249(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../db/migrations/00110_document_package_lifecycle.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(raw), "-- +goose Down", 2)
	if len(parts) != 2 {
		t.Fatal("package lifecycle migration has no explicit Down")
	}
	return parts[1]
}

func packageLifecycleBranding249(t *testing.T, q *ownedPublicReadFixtureV1, document uuid.UUID) {
	t.Helper()
	header, err := q.f.q.GetHTMLSendBrandingInputHeaderV1(q.f.ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: document, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.f.q.FreezeHTMLSendBrandingV1(q.f.ctx, htmlSendFreezeFixtureV1(header)); err != nil {
		t.Fatal(err)
	}
}

// A genuine imported main+DPA+NDA, actual recipient and lawful basis, measured
// through the native capture owner. No disabled trigger or synthetic completed
// receipt is used. This helper prepares acknowledgement mode; response/signing
// and final report publication have their separate HTTP acceptance tests.
func packageLifecyclePreparedBirth249(t *testing.T, q *ownedPublicReadFixtureV1) (pdfadmission.HTMLSendPackageIntentMetadataV1, uuid.UUID) {
	t.Helper()
	root := packageImported220(t, q, "Main contract with DPA and NDA")
	input, err := json.Marshal(map[string]any{"expected_updated_at": root.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "requires_signature": false})
	if err != nil {
		t.Fatal(err)
	}
	response := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/documents/"+root.ID.String(), string(input), q.cookie)
	if response.Code != http.StatusOK {
		t.Fatal("actual acknowledgement preparation failed", response.Code)
	}
	response = submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/recipients", `{"email":"package-lifecycle@example.test","name":"Package lifecycle recipient","role":"signer","locale":"en"}`, q.cookie)
	var party recipientResponse
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &party) != nil || party.ID == uuid.Nil {
		t.Fatal("actual lifecycle recipient creation failed", response.Code)
	}
	if _, err = q.f.q.ConfirmDocumentLawfulBasis(q.f.ctx, generated.ConfirmDocumentLawfulBasisParams{DocumentID: root.ID, OrgID: q.f.org, LawfulBasis: "contract", ConfirmedBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}, Via: "test"}); err != nil {
		t.Fatal(err)
	}
	root = packageLatest223(t, q, root.ID)
	dpa := packageImported220(t, q, "Data processing agreement")
	nda := packageImported220(t, q, "Non disclosure agreement")
	p := packageCreate223(t, q, root, dpa, nda)
	root = packageLatest223(t, q, root.ID)
	var m pdfadmission.HTMLSendPackageIntentMetadataV1
	err = packageCaptureRun234(t, q, root, p, nil, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
		if _, e := packageCaptureAppend234(t, call, w, prior); e != nil {
			return e
		}
		var e error
		m, e = w.CreatePackageIntentV1(call, pdfadmission.HTMLSendIntentActorV1{Via: "synthetic-owned-test", Tool: "actual-package-lifecycle"})
		if e != nil {
			return e
		}
		if _, e = w.FreezeBrandingV1(call); e != nil {
			return e
		}
		return w.BeginSendSealingV1(call)
	})
	if err != nil || m.AttemptID == uuid.Nil || m.Capture.MemberCount != 3 {
		t.Fatal("genuine main+DPA+NDA sealing failed", err)
	}
	packageWorkerDrained239(t, q)
	return m, party.ID
}

func TestDocumentPackageLifecycleLegacyRefusalsV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	root := packageImported220(t, q, "Unsatisfied attachment package Send")
	annex := packageImported220(t, q, "Required business attachment")
	packageCreate223(t, q, root, annex)
	packageLifecycleBranding249(t, q, root.ID)
	for _, mutation := range []string{
		"status='sealing'", "status='sent'", "status='in_progress'", "status='finalizing'", "status='completed'", "status='voided'", "status='expired'", "status='declined'",
		"is_envelope=true", "parent_envelope_id='11111111-1111-4111-8111-111111111111'", "source_kind='blocks'", "deleted_at=clock_timestamp()",
	} {
		t.Run(mutation, func(t *testing.T) {
			before := packageMeasurementState232(t, q)
			_, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET "+mutation+" WHERE id=$1 AND org_id=$2", root.ID, q.f.org) //nolint:rawsql -- fixed refusal cases, no external SQL
			packageExpectPG218(t, err, "23514")
			if packageMeasurementState232(t, q) != before {
				t.Fatal("unbound legacy dispatch or unsupported topology changed state")
			}
		})
	}
	t.Run("legacy NULL package intent cannot authorize selected attachments", func(t *testing.T) {
		before := packageMeasurementState232(t, q)
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		db := generated.New(tx)
		if _, err := db.CreateSendSealingIntent(q.f.ctx, generated.CreateSendSealingIntentParams{DocumentID: root.ID, OrgID: q.f.org, ActorUserID: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}, ActorEmail: q.f.user.Email, Via: "synthetic-legacy"}); err != nil {
			t.Fatal(err)
		}
		_, err := db.BeginDocumentSendSealing(q.f.ctx, generated.BeginDocumentSendSealingParams{ID: root.ID, OrgID: q.f.org})
		packageExpectPG218(t, err, "23514")
		rollbackHTMLQueryFixtureV1(t, tx)
		if packageMeasurementState232(t, q) != before {
			t.Fatal("legacy intent dispatch refusal changed state")
		}
	})
	t.Run("empty forward rollback restores closed M99 without inventing authority", func(t *testing.T) {
		before := packageMeasurementState232(t, q)
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		if _, err := tx.Exec(q.f.ctx, packageLifecycleDown249(t)); err != nil { //nolint:rawsql -- exact migration Down, discarded transaction
			t.Fatal(err)
		}
		_, err := tx.Exec(q.f.ctx, "UPDATE documents SET status='sealing' WHERE id=$1", root.ID)
		packageExpectPG218(t, err, "23514")
		rollbackHTMLQueryFixtureV1(t, tx)
		if packageMeasurementState232(t, q) != before {
			t.Fatal("empty rollback test changed source or draft")
		}
	})
	t.Run("ordinary legacy sealing and reversible abort remain supported", func(t *testing.T) {
		ordinary := packageImported220(t, q, "Ordinary document without attachments")
		header, err := q.f.q.GetHTMLSendBrandingInputHeaderV1(q.f.ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: ordinary.ID, OrgID: q.f.org})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = q.f.q.FreezeHTMLSendBrandingV1(q.f.ctx, htmlSendFreezeFixtureV1(header)); err != nil {
			t.Fatal(err)
		}
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		db := generated.New(tx)
		if _, err = db.CreateSendSealingIntent(q.f.ctx, generated.CreateSendSealingIntentParams{DocumentID: ordinary.ID, OrgID: q.f.org, ActorUserID: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}, ActorEmail: q.f.user.Email, Via: "synthetic-legacy"}); err != nil {
			t.Fatal(err)
		}
		if _, err = db.BeginDocumentSendSealing(q.f.ctx, generated.BeginDocumentSendSealingParams{ID: ordinary.ID, OrgID: q.f.org}); err != nil {
			t.Fatal("ordinary legacy sealing changed", err)
		}
		if n, e := db.AbortDocumentSendSealing(q.f.ctx, generated.AbortDocumentSendSealingParams{ID: ordinary.ID, OrgID: q.f.org}); e != nil || n != 1 {
			t.Fatal("ordinary legacy abort changed", n, e)
		}
		if n, e := db.DeleteSendSealingIntent(q.f.ctx, generated.DeleteSendSealingIntentParams{DocumentID: ordinary.ID, OrgID: q.f.org}); e != nil || n != 1 {
			t.Fatal("ordinary legacy intent cleanup changed", n, e)
		}
		if _, err = tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDocumentPackageLifecycleExactCaptureV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	root, capture, _ := packageCaptureOnly235(t, q, true)
	packageLifecycleBranding249(t, q, root.ID)
	t.Run("capture and attempt without exact intent cannot begin sealing", func(t *testing.T) {
		before := packageMeasurementState232(t, q)
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		db := generated.New(tx)
		if _, err := db.CreateDocumentPackageSendAttemptV1(q.f.ctx, packageAttemptInput235(capture)); err != nil {
			t.Fatal(err)
		}
		_, err := db.BeginDocumentSendSealing(q.f.ctx, generated.BeginDocumentSendSealingParams{ID: root.ID, OrgID: q.f.org})
		packageExpectPG218(t, err, "23514")
		rollbackHTMLQueryFixtureV1(t, tx)
		if packageMeasurementState232(t, q) != before {
			t.Fatal("missing intent refusal retained an orphan attempt")
		}
	})
	t.Run("pre-retention native attachment attempt can abort and retains history", func(t *testing.T) {
		_, _, m, err := packageAttemptBirth235(t, q, true)
		if err != nil {
			t.Fatal("genuine nonempty package sealing was refused", err)
		}
		if err = packageAttemptTransition235(t, q, m, "aborted", false); err != nil {
			t.Fatal("pre-retention package abort failed", err)
		}
		packageAttemptInspect235(t, q, m, false, "aborted")
	})
}

func TestDocumentPackageLifecycleRetainedReceiptV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	m, recipient := packageLifecyclePreparedBirth249(t, q)
	for _, mutation := range []string{"status='sent'", "status='finalizing'", "status='completed'", "name='replacement main'", "pdf_storage_version_id='replacement-version'", "requires_signature=true"} {
		t.Run("sealing refuses "+mutation, func(t *testing.T) {
			before := packageCompletionNativeState241(t, q, m)
			_, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET "+mutation+" WHERE id=$1", m.Capture.DocumentID) //nolint:rawsql -- fixed constraint probes
			code := "23514"
			if mutation == "status='sent'" {
				// The older M61 guard runs first and refuses sealing->sent
				// without the actual immutable notice allocation.
				code = "P0001"
			}
			packageExpectPG218(t, err, code)
			if packageCompletionNativeState241(t, q, m) != before {
				t.Fatal("premature lifecycle or captured source mutation changed state")
			}
		})
	}
	peer := &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}
	client := packageRetentionNativeClient240(t, q, peer)
	packageCompletionRun241(t, q, client, m, "sent")
	t.Cleanup(func() {
		peer.mu.Lock()
		defer peer.mu.Unlock()
		if peer.failure != nil {
			t.Error("actual lifecycle provider peer", peer.failure)
		}
	})
	var matches bool
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT hash_package_lifecycle_receipt_matches_v1($1,$2)", m.Capture.DocumentID, q.f.org).Scan(&matches); err != nil || !matches {
		t.Fatal("actual completed Send did not retain exact lifetime association", err)
	}
	// A recipient may leave the original initial-effect status after viewing.
	// This must not prevent normal later lifecycle.
	if err := q.f.q.SetRecipientStatus(q.f.ctx, generated.SetRecipientStatusParams{ID: recipient, DocumentID: m.Capture.DocumentID, Status: "viewed"}); err != nil {
		t.Fatal(err)
	}
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT hash_package_send_completion_matches_v1($1)", m.AttemptID).Scan(&matches); err != nil || matches {
		t.Fatal("fixture failed to separate original invite effects from later lifecycle", err)
	}
	if _, err := q.f.q.SetDocumentStatus(q.f.ctx, generated.SetDocumentStatusParams{ID: m.Capture.DocumentID, OrgID: q.f.org, Status: "in_progress"}); err != nil {
		t.Fatal("viewed recipient invalidated immutable Send receipt", err)
	}
	for _, mutation := range []string{"sent_at=sent_at+interval '1 microsecond'", "article13_notice_epoch_at=article13_notice_epoch_at+interval '1 microsecond'", "article13_notice_epoch_v61_committed=false", "pdf_storage_version_id='replacement-version'", "is_envelope=true", "deleted_at=clock_timestamp()"} {
		t.Run("retained package refuses "+mutation, func(t *testing.T) {
			before := packageCompletionNativeState241(t, q, m)
			_, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET "+mutation+" WHERE id=$1", m.Capture.DocumentID) //nolint:rawsql -- fixed lifetime binding probes
			code := "23514"
			if strings.HasPrefix(mutation, "sent_at=") || strings.HasPrefix(mutation, "article13_notice_epoch") {
				// Preserve the existing earlier M61 epoch immutability gate.
				code = "P0001"
			}
			packageExpectPG218(t, err, code)
			if packageCompletionNativeState241(t, q, m) != before {
				t.Fatal("retained lifetime refusal changed ceremony")
			}
		})
	}
	t.Run("unresponded negotiation may reopen and preserve old epoch", func(t *testing.T) {
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		db := generated.New(tx)
		paused, err := db.RequestChangesOnDocument(q.f.ctx, generated.RequestChangesOnDocumentParams{ID: m.Capture.DocumentID, OrgID: q.f.org})
		if err != nil {
			t.Fatal(err)
		}
		draft, err := db.ReopenDocumentToDraft(q.f.ctx, generated.ReopenDocumentToDraftParams{ID: m.Capture.DocumentID, OrgID: q.f.org})
		if err != nil || draft.SentAt.Valid || draft.Article13NoticeEpochAt != paused.Article13NoticeEpochAt {
			t.Fatal("unresponded revision lost previous immutable epoch", err)
		}
		if _, err = tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("occupied lifecycle rollback refuses without losing evidence", func(t *testing.T) {
		before := packageCompletionNativeState241(t, q, m)
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		_, err := tx.Exec(q.f.ctx, packageLifecycleDown249(t)) //nolint:rawsql -- exact migration Down in discarded transaction
		packageExpectPG218(t, err, "23514")
		rollbackHTMLQueryFixtureV1(t, tx)
		if packageCompletionNativeState241(t, q, m) != before {
			t.Fatal("occupied rollback changed retained package")
		}
	})
	q.assertObserversOnlyV1(t)
}

func TestDocumentPackageLifecycleIrreversibleExpiryV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	m, _ := packageLifecyclePreparedBirth249(t, q)
	peer := &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}
	peer.afterPut = func() error {
		_, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", m.Capture.DocumentID)
		return err
	}
	client := packageRetentionNativeClient240(t, q, peer)
	packageCompletionRun241(t, q, client, m, "expired")
	packageCompletionActualEffects241(t, q, m, "expired")
	peer.mu.Lock()
	failure := peer.failure
	peer.mu.Unlock()
	if failure != nil {
		t.Fatal("actual irreversible expiry peer", failure)
	}
	q.assertObserversOnlyV1(t)
}
