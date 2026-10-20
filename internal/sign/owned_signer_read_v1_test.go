// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestSignerLookupPurposePairsAreClosedBeforeRuntimeAndIndependentOfDiagnosticsV1(t *testing.T) {
	// This empty engine proves only dispatch preflight: it supplies no native
	// scope, credentials, SQL or resource authority. The actual model/ownership
	// and mutation-input controls are qualified against PostgreSQL separately.
	e := &Engine{}
	modes := []pdfadmission.SignerReadModeV1{"", "unknown", pdfadmission.SignerReadActiveV1, pdfadmission.SignerReadCompletedV1, pdfadmission.SignerReadActiveResponseV1, pdfadmission.SignerReadActiveRecheckV1}
	for _, mode := range modes {
		for _, native := range modes {
			for _, route := range []pdfadmission.SignerReadDiagnosticRouteV1{pdfadmission.SignerReadDiagnosticOtherV1, pdfadmission.SignerReadDiagnosticFieldsV1, pdfadmission.SignerReadDiagnosticPDFV1, pdfadmission.SignerReadDiagnosticCommentsV1, pdfadmission.SignerReadDiagnosticViewV1, pdfadmission.SignerReadDiagnosticPackageV1, 255} {
				rc, err := e.lookupOwnedSignerPurposeRouteV1(context.Background(), make([]byte, 32), mode, native, route)
				valid := mode == pdfadmission.SignerReadActiveV1 && (native == mode || native == pdfadmission.SignerReadActiveResponseV1) || mode == pdfadmission.SignerReadCompletedV1 && native == mode
				if rc != nil || !errors.Is(err, ErrSigningAdmissionUnavailableV1) || errors.Is(err, pdfadmission.ErrSignerReadV1) == valid {
					t.Fatal("purpose pair or diagnostic label changed preflight dispatch", mode, native, route, valid, err)
				}
			}
		}
	}
}

func TestPublicSignerReadRequiresActualProcessRuntimeBeforeQueriesV1(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	// The generated fixture can validate private credential policy; it is NOT
	// an owned native runtime, and public compatibility APIs must not adopt it.
	for _, lookup := range []func(context.Context, []byte) (*RecipientContext, error){f.engine.LookupByToken, f.engine.LookupCompletedArtifactByToken, f.engine.LookupCompletedAuditCertificateByTokenV1} {
		rc, err := lookup(context.Background(), f.digest)
		if rc != nil || !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
			t.Fatal("public lookup used unowned generated queries")
		}
	}
	if f.db.calls != 0 {
		t.Fatal("public lookup issued body SQL before actual runtime/global admission")
	}
	if err := (&RecipientContext{}).ValidateReadMaterializationV1(); !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("model shell supplied private Current read proof")
	}
}
func TestSignerReadFailureClassPreservesBusinessRefusalV1(t *testing.T) {
	for _, err := range []error{ErrMagicLinkExpired, ErrDocumentNotSignable, ErrSignerLawfulBasisUnavailable, ErrSignerControllerUnavailable, ErrCompletedArtifactUnavailable} {
		if errors.Is(signerReadErrorV1(err), ErrSigningAdmissionUnavailableV1) {
			t.Fatal("business refusal became capacity outage")
		}
	}
	if !errors.Is(signerReadErrorV1(pdfadmission.ErrSignerReadV1), ErrSigningAdmissionUnavailableV1) {
		t.Fatal("native missing-bound refusal lost unavailable class")
	}
}
func TestClosedSignerResultCannotRecheckOrValidateV1(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	// Bookkeeping-only closed result: no native session/admission/resource or
	// production authority is fabricated by this explicit shell.
	rc.readLease = &signerReadLeaseV1{issuer: f.engine, closed: true, original: cloneSignerReadContextV1(rc)}
	if _, _, _, err := rc.readLease.borrowOriginalV1(f.engine, rc, pdfadmission.SignerReadActiveV1); err == nil {
		t.Fatal("closed consumer supplied reusable original")
	}
	if err := rc.ValidateReadMaterializationV1(); err == nil {
		t.Fatal("closed consumer supplied current proof")
	}
	if err := f.engine.RecheckRecipientReadV1(context.Background(), rc, func(*RecipientContext) error { return nil }); err == nil {
		t.Fatal("closed shell rechecked without runtime")
	}
}

func TestBoundedSignerPreflightPreservesExpiryBeforeStateV1(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	past := pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true}
	future := pgtype.Timestamptz{Time: now.Add(time.Second), Valid: true}
	for _, a := range []pdfadmission.ApplicationSignerReadAccessV1{{RecipientExpiresAt: past}, {DocumentExpiresAt: past}, {RecipientExpiresAt: past, ActiveCeremony: true}} {
		if !errors.Is(signerReadPreflightV1(pdfadmission.SignerReadActiveV1, now, a), ErrMagicLinkExpired) {
			t.Fatal("early expired original became state/cache failure")
		}
	}
	if !errors.Is(signerReadPreflightV1(pdfadmission.SignerReadActiveV1, now, pdfadmission.ApplicationSignerReadAccessV1{RecipientExpiresAt: future}), ErrDocumentNotSignable) {
		t.Fatal("draft/terminal admitted before model loan")
	}
	// Historical active helper equality intentionally remains supported; the
	// full immutable credential constructor still performs its original checks.
	equal := pgtype.Timestamptz{Time: now, Valid: true}
	if err := signerReadPreflightV1(pdfadmission.SignerReadActiveV1, now, pdfadmission.ApplicationSignerReadAccessV1{RecipientExpiresAt: equal, DocumentExpiresAt: equal, ActiveCeremony: true}); err != nil {
		t.Fatal("historical active equality changed")
	}
	for _, a := range []pdfadmission.ApplicationSignerReadAccessV1{{RecipientExpiresAt: equal, CompletedCeremony: true, CompletedRecipient: true}, {RecipientExpiresAt: future, CompletedCeremony: true}, {RecipientExpiresAt: future, CompletedRecipient: true}, {CompletedCeremony: true, CompletedRecipient: true}} {
		if !errors.Is(signerReadPreflightV1(pdfadmission.SignerReadCompletedV1, now, a), ErrCompletedArtifactUnavailable) {
			t.Fatal("completed scalar refusal changed")
		}
	}
	if err := signerReadPreflightV1(pdfadmission.SignerReadCompletedV1, now, pdfadmission.ApplicationSignerReadAccessV1{RecipientExpiresAt: future, DocumentExpiresAt: past, CompletedCeremony: true, CompletedRecipient: true}); err != nil {
		t.Fatal("completed exception adopted document expiry or refused completed recipient")
	}
}

func TestSignerOriginalConsumerCloseWaitsForActualRecheckBorrowV1(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	// Explicit bookkeeping-only fixture: the empty opaque scope supplies NO
	// native scope or resource authority, and cleanup must never report success.
	l := &signerReadLeaseV1{issuer: f.engine, mode: pdfadmission.SignerReadActiveV1, scope: &pdfadmission.ApplicationSignerScopeV1{}, original: cloneSignerReadContextV1(rc)}
	rc.readLease = l
	original, _, finish, err := l.borrowOriginalV1(f.engine, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.CloseReadV1(); err == nil {
		t.Fatal("live borrowed body reported successful cleanup")
	}
	l.mu.Lock()
	retained := l.original == original && l.borrowers == 1
	l.mu.Unlock()
	if !retained {
		t.Fatal("close discarded original before joined actual recheck consumer")
	}
	if _, _, _, err := l.borrowOriginalV1(f.engine, rc, pdfadmission.SignerReadActiveV1); err == nil {
		t.Fatal("closed original created another consumer")
	}
	finish()
	finish()
	l.mu.Lock()
	joined := l.borrowers == 0 && l.original == nil
	l.mu.Unlock()
	if !joined {
		t.Fatal("joined local bookkeeping retained or double-decremented original")
	}
	if err := rc.CloseReadV1(); err == nil {
		t.Fatal("empty native owner shell fabricated physical cleanup")
	}
}
