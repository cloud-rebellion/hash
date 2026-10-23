// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"errors"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func readAmendmentFixture483(now time.Time) *RecipientContext {
	c := readCredentialFixture(now)
	c.Document.RequiresSignature = true
	c.AmendmentContext = &amendments.SignerContextV1{Schema: amendments.SignerContextSchemaV1, AmendmentID: uuid.New(), Revision: "1", DocumentID: c.Document.ID, OriginalDocumentID: uuid.New(), OriginalName: "Captured original", OriginalFinalPDFSHA256: strings.Repeat("1", 64), OriginalReportSHA256: strings.Repeat("2", 64), OriginalReportPDFSHA256: strings.Repeat("3", 64), Mode: amendments.SignatureV1, FileCommitmentSHA256: strings.Repeat("4", 64)}
	return c
}
func TestSignerReadAmendmentContextFreshComparisonAndCloneV1(t *testing.T) {
	now := time.Now()
	original := readAmendmentFixture483(now)
	fresh := cloneSignerReadContextV1(original)
	if fresh.AmendmentContext == original.AmendmentContext || ValidateRecipientReadCredential(original, fresh, now) != nil {
		t.Fatal("separate context clone lost exact original")
	}
	for _, change := range []func(*amendments.SignerContextV1){
		func(c *amendments.SignerContextV1) { c.AmendmentID = uuid.New() }, func(c *amendments.SignerContextV1) { c.Revision = "2" }, func(c *amendments.SignerContextV1) { c.OriginalDocumentID = uuid.New() }, func(c *amendments.SignerContextV1) { c.OriginalName += " changed" }, func(c *amendments.SignerContextV1) { c.OriginalFinalPDFSHA256 = strings.Repeat("5", 64) }, func(c *amendments.SignerContextV1) { c.OriginalReportSHA256 = strings.Repeat("6", 64) }, func(c *amendments.SignerContextV1) { c.OriginalReportPDFSHA256 = strings.Repeat("7", 64) }, func(c *amendments.SignerContextV1) { c.FileCommitmentSHA256 = strings.Repeat("8", 64) },
	} {
		next := cloneSignerReadContextV1(original)
		change(next.AmendmentContext)
		if !errors.Is(ValidateRecipientReadCredential(original, next, now), ErrMagicLinkExpired) {
			t.Fatal("fresh read substituted immutable amendment disclosure")
		}
	}
	fresh = cloneSignerReadContextV1(original)
	fresh.AmendmentContext = nil
	if ValidateRecipientReadCredential(original, fresh, now) == nil || ValidateRecipientReadCredential(fresh, original, now) == nil {
		t.Fatal("context disappeared or appeared during one original read")
	}
	fresh = cloneSignerReadContextV1(original)
	fresh.Document.RequiresSignature = false
	if ValidateRecipientReadCredential(original, fresh, now) == nil {
		t.Fatal("context became opposite ceremony")
	}
}
func TestSignerAmendmentReadBorrowRefusesCallerMutationV1(t *testing.T) {
	// Bookkeeping-only shell tests caller mutation and private-copy lifetime.
	// It supplies no actual SQL/runtime/credential/admission authority.
	e := &Engine{}
	rc := readAmendmentFixture483(time.Now())
	l := &signerReadLeaseV1{issuer: e, mode: pdfadmission.SignerReadActiveV1, scope: &pdfadmission.ApplicationSignerScopeV1{}, original: cloneSignerReadContextV1(rc)}
	rc.readLease = l
	rc.AmendmentContext.OriginalReportSHA256 = strings.Repeat("9", 64)
	if _, _, finish, err := l.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1); err == nil {
		finish()
		t.Fatal("caller replaced original canonical report pin")
	}
	rc.AmendmentContext = amendments.CloneSignerContextV1(l.original.AmendmentContext)
	original, _, finish, err := l.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	rc.AmendmentContext.OriginalName = "mutated after borrow"
	if original.AmendmentContext.OriginalName != "Captured original" {
		t.Fatal("retained context shares caller pointer")
	}
}
