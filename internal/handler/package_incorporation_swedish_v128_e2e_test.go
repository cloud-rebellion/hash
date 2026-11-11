//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// Extend the existing real native fixture with an ordinary authorized draft
// locale update before capture. No frozen attempt/response/audit is seeded.
func packageRootLocaleV128(t *testing.T, q *ownedPublicReadFixtureV1, root *generated.Document, locales []string) *generated.Document {
	t.Helper()
	if len(locales) == 0 {
		return root
	}
	if len(locales) != 1 || (locales[0] != "en" && locales[0] != "sv") {
		t.Fatal("explicit fixture locale must be EN or SV")
	}
	raw, err := json.Marshal(map[string]any{"expected_updated_at": root.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "default_locale": locales[0]})
	if err != nil {
		t.Fatal(err)
	}
	response := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/documents/"+root.ID.String(), string(raw), q.cookie)
	if response.Code != http.StatusOK {
		t.Fatal("actual draft locale update failed", response.Code)
	}
	next := packageLatest223(t, q, root.ID)
	if next.DefaultLocale != locales[0] {
		t.Fatal("draft did not retain explicit locale")
	}
	return next
}

// Both completed responses and a pre-retention aborted Send retain immutable
// statement identity. Exercise the actual complete M128 Down transaction.
func packageRequireRetainedSvDownV128(t *testing.T, q *ownedPublicReadFixtureV1, attemptID uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
	defer cancel()
	state := func() string {
		var attempt, responses string
		if err := q.f.pool.QueryRow(ctx, "SELECT to_jsonb(a)::text,(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY recipient_id),'[]'::jsonb)::text FROM document_package_responses_v1 x WHERE x.attempt_id=a.attempt_id) FROM document_package_send_attempts_v1 a WHERE a.attempt_id=$1", attemptID).Scan(&attempt, &responses); err != nil {
			t.Fatal(err)
		}
		return attempt + responses
	}
	before := state()
	raw, err := os.ReadFile("../db/migrations/00128_workspace_email_and_signing_languages.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, found := strings.Cut(string(raw), "-- +goose Down")
	if !found {
		t.Fatal("actual M128 Down unavailable")
	}
	func() {
		tx := beginHTMLQueryFixtureV1(t, ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		_, err := tx.Exec(ctx, down) //nolint:rawsql -- exact retained-SV Down, disposable transaction always rolled back
		packageExpectPG218(t, err, "23514")
	}()
	if state() != before {
		t.Fatal("refused M128 downgrade changed retained package proof")
	}
}

func TestAbortedSwedishPackageAttemptStillPreventsDowngradeV128E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	m, _ := packageCompletionPreparedBirth241(t, q, 1, false, "sv")
	peer := &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}
	client := packageRetentionNativeClient240(t, q, peer)
	ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
	defer cancel()
	if _, err := q.f.pool.Exec(ctx, "UPDATE documents SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", m.Capture.DocumentID); err != nil {
		t.Fatal(err)
	}
	counts := peer.counts240()
	batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
	defer batch.CloseConsumerV1()
	observed := false
	more, err := batch.WithNextSendV1(client, packageCompletionConfig241(t, q), func(value pdfadmission.HTMLSendPackageSendObservationV1) error {
		observed = true
		if err := packageWorkerObservation239(value.Attempt, packageWorkerJob239{meta: m, created: m.CreatedAt}, pdfadmission.HTMLSendPackageAttemptAbortedV1); err != nil {
			return err
		}
		if value.RetentionVerified || value.CompletionVerified || value.Status != "draft" {
			return errors.New("reversible Swedish expiry claimed retention or completion")
		}
		return packageRetentionNativeNoWorkSQL240(q)
	})
	if !more || !observed || err != nil {
		t.Fatal("native Swedish pre-retention abort failed", err)
	}
	batch.CloseConsumerV1()
	packageWorkerDrained239(t, q)
	packageAttemptInspect235(t, q, m, false, "aborted")
	var version string
	var responses, completions, mails int
	if err := q.f.pool.QueryRow(ctx, "SELECT incorporation_version,(SELECT count(*) FROM document_package_responses_v1 WHERE attempt_id=$1),(SELECT count(*) FROM document_package_send_completions_v1 WHERE attempt_id=$1),(SELECT count(*) FROM email_deliveries WHERE smtp_org_id=$2) FROM document_package_send_attempts_v1 WHERE attempt_id=$1", m.AttemptID, q.f.org).Scan(&version, &responses, &completions, &mails); err != nil || version != documentpackage.IncorporationVersionSwedishV1 || responses != 0 || completions != 0 || mails != 0 || peer.counts240() != counts {
		t.Fatal("abort lost frozen Swedish identity or created irreversible effects", err)
	}
	// This must fail on the retained attempt alone: no response or mail exists.
	packageRequireRetainedSvDownV128(t, q, m.AttemptID)
}

func TestPreparedPackageLocaleDriftWaitsForLockedAdmissionAndRefusesV128E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	verifyContext, stopVerification := context.WithTimeout(q.f.ctx, 30*time.Second)
	defer stopVerification()
	root := packageImported220(t, q, "Prepared English package with later Swedish root")
	p := packageCreate223(t, q, root)
	root = packageLatest223(t, q, root.ID)
	if root.DefaultLocale != "en" {
		t.Fatal("fixture must begin with actual English root")
	}
	effects := func() string {
		var value string
		if err := q.f.pool.QueryRow(verifyContext, "SELECT jsonb_build_object('attempts',(SELECT count(*) FROM document_package_send_attempts_v1 WHERE document_id=$1),'captures',(SELECT count(*) FROM document_package_captures_v1 WHERE document_id=$1),'members',(SELECT count(*) FROM document_package_capture_members_v1 m JOIN document_package_captures_v1 c ON c.package_id=m.package_id AND c.revision=m.revision AND c.org_id=m.org_id WHERE c.document_id=$1),'intents',(SELECT count(*) FROM send_sealing_intents WHERE document_id=$1),'events',(SELECT count(*) FROM events WHERE document_id=$1),'mails',(SELECT count(*) FROM email_deliveries WHERE smtp_org_id=$2))::text", root.ID, q.f.org).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := effects()
	err := withPackageSendDraft234(t, q, root.ID, packageCaptureExpected234(p), false, func(op *pdfadmission.ApplicationHTMLSendOperationV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1, actor authoring.Actor) error {
		if err := prior.MeasurePDFsV1(q.f.s.Storage); err != nil {
			return err
		}
		providerRequests := q.storagePeer.requests.Load()
		ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
		defer cancel()
		held := beginHTMLQueryFixtureV1(t, ctx, q.f)
		result, finished := make(chan error, 1), make(chan struct{})
		started := false
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			op.EndConsumerV1()
			_ = held.Rollback(cleanup)
			if started {
				select {
				case <-finished:
				case <-cleanup.Done():
					t.Error("locale-drift admission did not retire")
				}
			}
		}()
		var holderPID int32
		if err := held.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&holderPID); err != nil {
			return err
		}
		if _, err := generated.New(held).SetDocumentDefaultLocale(ctx, generated.SetDocumentDefaultLocaleParams{ID: root.ID, OrgID: q.f.org, DefaultLocale: "sv"}); err != nil {
			return err
		}
		var capture pdfadmission.HTMLSendPackageCaptureMetadataV1
		var appended bool
		started = true
		go func() {
			defer close(finished)
			result <- withPackageCaptureAdmission234(t, q, op, actor, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1) error {
				appended = true
				var err error
				capture, err = work.AppendDocumentPackageCaptureV1(call, prior)
				if err == nil {
					return errors.New("prepared English source accepted later Swedish root")
				}
				return err
			})
		}()
		// Observe the real blocked state-header query and exact blocker chain,
		// rather than sleeping or calling a mocked postwait predicate.
		awaitSignerReadMutationWaitE2E(t, ctx, q.f.pool, result, holderPID, "-- name: GetHTMLSendDocumentStateHeaderV1")
		if err := held.Commit(ctx); err != nil {
			return err
		}
		select {
		case err := <-result:
			if !appended || capture != (pdfadmission.HTMLSendPackageCaptureMetadataV1{}) || !errors.Is(err, pdfadmission.ErrDocumentPackageSourceChangedV1) {
				return errors.New("locked locale drift did not refuse the original prepared capture")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		if _, present := op.PackageSendAttemptIDV1(); present {
			return errors.New("refused capture allocated a Send attempt")
		}
		if q.storagePeer.requests.Load() != providerRequests {
			return errors.New("admission repeated external PDF work after locale drift")
		}
		return nil
	})
	if err != nil {
		t.Fatal("actual prepared-to-locked locale race failed", err)
	}
	if after := packageLatest223(t, q, root.ID); after.DefaultLocale != "sv" || after.Status != "draft" {
		t.Fatal("fixture root change was not actually committed")
	}
	if effects() != before {
		t.Fatal("refused prepared locale drift changed native capture/attempt/audit/mail effects")
	}
	q.assertObserversOnlyV1(t)
}

func TestNativePackageFrozenEnglishAndSwedishConsentV128E2E(t *testing.T) {
	for _, locale := range []string{"en", "sv"} {
		for _, signed := range []bool{false, true} {
			name := locale + "-accept"
			if signed {
				name = locale + "-sign"
			}
			t.Run(name, func(t *testing.T) {
				f := newPackageResponseHTTPFixture247(t, signed, locale)
				copy := documentpackage.IncorporationCopyForLocaleV1(locale)
				var frozen string
				if err := f.q.f.pool.QueryRow(f.q.f.ctx, "SELECT incorporation_version FROM document_package_send_attempts_v1 WHERE attempt_id=$1", f.m.AttemptID).Scan(&frozen); err != nil || frozen != copy.Version {
					t.Fatal("native Send did not freeze actual root language", err)
				}
				before := packageCompletionNativeState241(t, f.q, f.m)
				other := documentpackage.IncorporationCopyV1()
				if locale == "en" {
					other = documentpackage.IncorporationCopyForLocaleV1("sv")
				}
				stale := f.response
				stale.IncorporationVersion, stale.IncorporationSHA256 = other.Version, other.SHA256
				if response := f.post247(t, &stale); response.Code != http.StatusPreconditionFailed {
					t.Fatal("other frozen language consent accepted", response.Code)
				}
				if packageCompletionNativeState241(t, f.q, f.m) != before {
					t.Fatal("refused cross-language consent changed native effects")
				}
				wrong := f.response
				wrong.IncorporationSHA256 = other.SHA256
				if response := f.post247(t, &wrong); response.Code != http.StatusBadRequest {
					t.Fatal("version/hash mismatch accepted", response.Code)
				}
				if response := f.post247(t, &f.response); response.Code != http.StatusOK {
					t.Fatal("actual current canonical consent refused", response.Code)
				}
				var version string
				var digest []byte
				var matches bool
				if err := f.q.f.pool.QueryRow(f.q.f.ctx, "SELECT incorporation_version,incorporation_sha256,hash_package_response_matches_v1(attempt_id,recipient_id) FROM document_package_responses_v1 WHERE attempt_id=$1 AND recipient_id=$2", f.m.AttemptID, f.recipient).Scan(&version, &digest, &matches); err != nil || version != copy.Version || hex.EncodeToString(digest) != copy.SHA256 || !matches {
					t.Fatal("database did not retain and validate exact frozen consent pair", err)
				}
				if locale == "sv" {
					packageRequireRetainedSvDownV128(t, f.q, f.m.AttemptID)
				}
				_, err := f.q.f.pool.Exec(f.q.f.ctx, "UPDATE document_package_send_attempts_v1 SET incorporation_version=$2 WHERE attempt_id=$1", f.m.AttemptID, other.Version)
				packageExpectPG218(t, err, "23514")
			})
		}
	}
}
