// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

func TestPackageSendCompletionTerminalAcknowledgementPreservesExactAttemptV1(t *testing.T) {
	r, id, c := inspectionFixture236()
	before, err := htmlSendPackageAttemptObservationV1(r, id, c)
	if err != nil {
		t.Fatal(err)
	}
	after := before
	after.RetentionStartedAt = before.CreatedAt.Add(time.Second)
	after.RetentionCompletedAt = before.CreatedAt.Add(2 * time.Second)
	after.TerminalAt = before.CreatedAt.Add(3 * time.Second)
	after.Outcome = HTMLSendPackageAttemptCompletedV1
	if !packageSendTerminalProgressV1(before, after) || packageRetentionProgressV1(before, after) {
		t.Fatal("completion either lost its separate authority or retention accepted terminal mutation")
	}
	for _, tc := range []struct {
		name string
		edit func(*HTMLSendPackageAttemptObservationV1)
	}{
		{"attempt", func(v *HTMLSendPackageAttemptObservationV1) { v.AttemptID = uuid.New() }},
		{"org", func(v *HTMLSendPackageAttemptObservationV1) { v.Capture.OrgID = uuid.New() }},
		{"root", func(v *HTMLSendPackageAttemptObservationV1) { v.Capture.DocumentID = uuid.New() }},
		{"capture", func(v *HTMLSendPackageAttemptObservationV1) { v.Capture.Revision++ }},
		{"manifest", func(v *HTMLSendPackageAttemptObservationV1) { v.Capture.CanonicalSHA256[0]++ }},
		{"commitment", func(v *HTMLSendPackageAttemptObservationV1) { v.Capture.CommitmentSHA256[0]++ }},
		{"actor", func(v *HTMLSendPackageAttemptObservationV1) { v.Capture.CreatedBy = uuid.New() }},
		{"epoch", func(v *HTMLSendPackageAttemptObservationV1) {
			v.Article13NoticeEpochAt = v.Article13NoticeEpochAt.Add(time.Microsecond)
		}},
		{"deadline", func(v *HTMLSendPackageAttemptObservationV1) { v.RetainUntil = v.RetainUntil.Add(time.Second) }},
		{"created", func(v *HTMLSendPackageAttemptObservationV1) { v.CreatedAt = v.CreatedAt.Add(time.Microsecond) }},
		{"no start", func(v *HTMLSendPackageAttemptObservationV1) { v.RetentionStartedAt = time.Time{} }},
		{"no completion", func(v *HTMLSendPackageAttemptObservationV1) { v.RetentionCompletedAt = time.Time{} }},
		{"no terminal", func(v *HTMLSendPackageAttemptObservationV1) { v.TerminalAt = time.Time{} }},
		{"not recorded", func(v *HTMLSendPackageAttemptObservationV1) { v.Outcome = HTMLSendPackageAttemptNotRecordedV1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := after
			tc.edit(&changed)
			if packageSendTerminalProgressV1(before, changed) {
				t.Fatal("changed terminal identity was acknowledged")
			}
		})
	}
	started := before
	started.RetentionStartedAt = after.RetentionStartedAt
	drift := after
	drift.RetentionStartedAt = drift.RetentionStartedAt.Add(time.Microsecond)
	if packageSendTerminalProgressV1(started, drift) {
		t.Fatal("completion changed an acknowledged retention start")
	}
	aborted := before
	aborted.Outcome = HTMLSendPackageAttemptAbortedV1
	aborted.TerminalAt = after.TerminalAt
	if !packageSendTerminalProgressV1(before, aborted) {
		t.Fatal("exact reversible abort unavailable")
	}
	if packageSendTerminalProgressV1(started, aborted) || packageSendTerminalProgressV1(after, before) || packageSendTerminalProgressV1(aborted, after) {
		t.Fatal("irreversible history was aborted, reopened or replayed")
	}
}

func TestPackageSendCompletionConfigurationIsOriginOnlyV1(t *testing.T) {
	logger := audit.New(nil, nil)
	for _, origin := range []string{"https://hash.example.test", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if !packageSendCompletionConfigValidV1(PackageSendCompletionConfigV1{PublicURL: origin, Audit: logger}) {
			t.Fatal("configured origin unavailable", origin)
		}
	}
	for _, origin := range []string{"", " https://hash.example.test", "http://hash.example.test", "https://user:pass@hash.example.test", "https://hash.example.test/", "https://hash.example.test/sign", "https://hash.example.test?", "https://hash.example.test?x=y", "https://hash.example.test#x", "javascript:alert(1)", "https://:443"} {
		t.Run(origin, func(t *testing.T) {
			if packageSendCompletionConfigValidV1(PackageSendCompletionConfigV1{PublicURL: origin, Audit: logger}) {
				t.Fatal("non-origin output configuration accepted")
			}
		})
	}
	if packageSendCompletionConfigValidV1(PackageSendCompletionConfigV1{PublicURL: "https://hash.example.test"}) {
		t.Fatal("completion without audit publication accepted")
	}
}

func TestPackageSendCompletionCannotMintAuthorityFromEmptyBatchV1(t *testing.T) {
	called := false
	cfg := PackageSendCompletionConfigV1{PublicURL: "https://hash.example.test", Audit: audit.New(nil, nil)}
	for _, h := range []*ApplicationPackageSendRecoveryBatchV1{nil, {}, {state: &applicationPackageSendRecoveryBatchStateV1{}}} {
		if more, err := h.WithNextSendV1(&storage.Client{}, cfg, func(HTMLSendPackageSendObservationV1) error { called = true; return nil }); more || err == nil {
			t.Fatal("unregistered batch entered finalization", more, err)
		}
	}
	if called {
		t.Fatal("empty batch delivered send effects")
	}
}

func TestPackageSendAuditPurposeDoesNotWidenLegacyPayloadsV1(t *testing.T) {
	for _, tc := range []struct {
		old, new HTMLAuditPurposeV1
		kind     string
	}{
		{HTMLAuditRecipientInvitedV1, HTMLAuditPackageRecipientInvitedV1, "recipient.invited"},
		{HTMLAuditDocumentSentV1, HTMLAuditPackageDocumentSentV1, "document.sent"},
		{HTMLAuditDocumentExpiredV1, HTMLAuditPackageDocumentExpiredV1, "document.expired"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			if tc.new.KindV1() != tc.kind {
				t.Fatal("package audit changed lifecycle kind")
			}
			for _, key := range []string{"package_send_schema", "package_send_attempt_id", "package_id", "capture_revision", "manifest_sha256", "legal_commitment_sha256"} {
				if htmlAuditRootKeyV1(tc.old, key) || !htmlAuditRootKeyV1(tc.new, key) {
					t.Fatal("package field widened legacy schema or is missing", key)
				}
			}
			for _, key := range []string{"token", "sign_url", "document_json", "arbitrary"} {
				if htmlAuditRootKeyV1(tc.new, key) {
					t.Fatal("unbounded/unneeded package audit field admitted", key)
				}
			}
		})
	}
}
