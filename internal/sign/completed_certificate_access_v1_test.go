// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCompletedAuditCertificateObservationBindsExactArtifactV1(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	id, recipient, org := uuid.New(), uuid.New(), uuid.New()
	original := &RecipientContext{
		Recipient: &generated.GetRecipientByTokenHashRow{ID: recipient, DocumentID: id, Status: "signed", MagicTokenExpiresAt: ts(now.Add(time.Hour))},
		Document: &generated.Document{ID: id, OrgID: org, Status: "completed",
			FinalPdfKey: pgtype.Text{String: "final.pdf", Valid: true}, FinalPdfVersionID: pgtype.Text{String: "final-v1", Valid: true}, FinalPdfSha: bytes.Repeat([]byte{1}, 32),
			AuditCertKey: pgtype.Text{String: "audit.pdf", Valid: true}, AuditCertVersionID: pgtype.Text{String: "audit-v1", Valid: true}, AuditCertSha256: bytes.Repeat([]byte{2}, 32)},
	}
	fresh := func() *RecipientContext {
		doc, rec := *original.Document, *original.Recipient
		doc.AuditCertSha256 = bytes.Clone(doc.AuditCertSha256)
		doc.FinalPdfSha = bytes.Clone(doc.FinalPdfSha)
		return &RecipientContext{Recipient: &rec, Document: &doc}
	}
	if err := checkCompletedAuditCertificateObservationV1(original, fresh(), now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RecipientContext){
		"certificate-key":     func(c *RecipientContext) { c.Document.AuditCertKey.String = "other.pdf" },
		"certificate-version": func(c *RecipientContext) { c.Document.AuditCertVersionID.String = "audit-v2" },
		"certificate-hash":    func(c *RecipientContext) { c.Document.AuditCertSha256[0]++ },
		"missing-key":         func(c *RecipientContext) { c.Document.AuditCertKey.Valid = false },
		"blank-key":           func(c *RecipientContext) { c.Document.AuditCertKey.String = " " },
		"missing-version":     func(c *RecipientContext) { c.Document.AuditCertVersionID.Valid = false },
		"blank-version":       func(c *RecipientContext) { c.Document.AuditCertVersionID.String = " " },
		"missing-hash":        func(c *RecipientContext) { c.Document.AuditCertSha256 = nil },
		"short-hash":          func(c *RecipientContext) { c.Document.AuditCertSha256 = c.Document.AuditCertSha256[:31] },
		"final-key":           func(c *RecipientContext) { c.Document.FinalPdfKey.String = "other-final.pdf" },
		"final-version":       func(c *RecipientContext) { c.Document.FinalPdfVersionID.String = "final-v2" },
		"final-hash":          func(c *RecipientContext) { c.Document.FinalPdfSha[0]++ },
		"recipient":           func(c *RecipientContext) { c.Recipient.ID = uuid.New() },
		"document":            func(c *RecipientContext) { c.Document.ID = uuid.New() },
		"organization":        func(c *RecipientContext) { c.Document.OrgID = uuid.New() },
		"unsigned":            func(c *RecipientContext) { c.Recipient.Status = "viewed" },
		"unfinished":          func(c *RecipientContext) { c.Document.Status = "finalizing" },
		"expired":             func(c *RecipientContext) { c.Recipient.MagicTokenExpiresAt = ts(now) },
	} {
		t.Run(name, func(t *testing.T) {
			current := fresh()
			mutate(current)
			if err := checkCompletedAuditCertificateObservationV1(original, current, now); !errors.Is(err, ErrCompletedArtifactUnavailable) {
				t.Fatalf("changed certificate context accepted: %v", err)
			}
		})
	}
	// A renewal observed later cannot extend an already admitted read.
	current := fresh()
	current.Recipient.MagicTokenExpiresAt = ts(now.Add(3 * time.Hour))
	if err := checkCompletedAuditCertificateObservationV1(original, current, now.Add(2*time.Hour)); !errors.Is(err, ErrCompletedArtifactUnavailable) {
		t.Fatalf("renewal extended original deadline: %v", err)
	}
}
