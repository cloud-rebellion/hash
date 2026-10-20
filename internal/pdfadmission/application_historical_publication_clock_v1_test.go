// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestHistoricalPublicationKeepsLegalTupleWithIndependentAdvancingRowClocksV1(t *testing.T) {
	stamp := func(v time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: v, Valid: true} }
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	rootID := uuid.MustParse("51eca627-f451-4122-8099-44af5efcc90d")
	before := &generated.Document{ID: uuid.MustParse("388518be-9915-4b0e-9be5-3325335e4fd8"), OrgID: uuid.MustParse("a228d619-8483-4f97-9723-e23a8a18add0"), ParentEnvelopeID: pgtype.UUID{Bytes: rootID, Valid: true}, Status: "finalizing", SourceKind: "blocks", BlocksJson: []byte(`{"version":1}`), UpdatedAt: stamp(now), CompletionEffectiveAtBound: true, CompletionEffectiveAt: stamp(now.Add(time.Second)), FinalizationRetainUntil: stamp(now.AddDate(7, 0, 0)), EvidenceVersionPinsRequired: true}
	intent := &generated.DocumentFinalizationIntent{FinalPdfKey: "final.pdf", FinalPdfSha256: bytes.Repeat([]byte{1}, 32), FinalPdfVersionID: pgtype.Text{String: "final-v1", Valid: true}, AuditCertKey: "certificate.pdf", AuditCertSha256: bytes.Repeat([]byte{2}, 32), AuditCertVersionID: pgtype.Text{String: "certificate-v1", Valid: true}, AuditPayloadKey: "audit.json", AuditPayloadSha256: bytes.Repeat([]byte{3}, 32), AuditPayloadVersionID: pgtype.Text{String: "payload-v1", Valid: true}, AuditSignatureKey: "audit.sig", AuditSignatureSha256: bytes.Repeat([]byte{4}, 32), AuditSignatureVersionID: pgtype.Text{String: "signature-v1", Valid: true}}
	completed := *before
	completed.Status = "completed"
	completed.UpdatedAt = stamp(now.Add(3 * time.Second))
	completed.CompletedAt = before.CompletionEffectiveAt
	completed.FinalPdfKey = pgtype.Text{String: intent.FinalPdfKey, Valid: true}
	completed.FinalPdfSha = intent.FinalPdfSha256
	completed.FinalPdfVersionID = intent.FinalPdfVersionID
	completed.AuditCertKey = pgtype.Text{String: intent.AuditCertKey, Valid: true}
	completed.AuditCertSha256 = intent.AuditCertSha256
	completed.AuditCertVersionID = intent.AuditCertVersionID
	completed.AuditPayloadKey = pgtype.Text{String: intent.AuditPayloadKey, Valid: true}
	completed.AuditPayloadSha256 = intent.AuditPayloadSha256
	completed.AuditPayloadVersionID = intent.AuditPayloadVersionID
	completed.AuditSignatureKey = pgtype.Text{String: intent.AuditSignatureKey, Valid: true}
	completed.AuditSignatureSha256 = intent.AuditSignatureSha256
	completed.AuditSignatureVersionID = intent.AuditSignatureVersionID
	rootBefore, rootCompleted := *before, completed
	rootBefore.ID = rootID
	rootBefore.IsEnvelope = true
	rootBefore.ParentEnvelopeID = pgtype.UUID{}
	rootCompleted.ID = rootID
	rootCompleted.IsEnvelope = true
	rootCompleted.ParentEnvelopeID = pgtype.UUID{}
	rootCompleted.UpdatedAt = stamp(now.Add(2 * time.Second))
	if !historicalPublicationDocumentTupleV1(&rootBefore, &rootCompleted, intent) || !historicalPublicationDocumentTupleV1(before, &completed, intent) {
		t.Fatal("actual independently advanced root/child clocks rejected")
	}
	cases := map[string]func(*generated.Document){
		"repeatedClock": func(d *generated.Document) { d.UpdatedAt = before.UpdatedAt },
		"backwardClock": func(d *generated.Document) { d.UpdatedAt = stamp(now.Add(-time.Microsecond)) },
		"missingClock":  func(d *generated.Document) { d.UpdatedAt = pgtype.Timestamptz{} },
		"infiniteClock": func(d *generated.Document) { d.UpdatedAt.InfinityModifier = pgtype.Infinity },
		"completion":    func(d *generated.Document) { d.CompletedAt.Time = d.CompletedAt.Time.Add(time.Microsecond) },
		"completionCommitment": func(d *generated.Document) {
			d.CompletionEffectiveAt.Time = d.CompletionEffectiveAt.Time.Add(time.Microsecond)
		},
		"retention": func(d *generated.Document) {
			d.FinalizationRetainUntil.Time = d.FinalizationRetainUntil.Time.Add(time.Second)
		},
		"unboundCompletion":  func(d *generated.Document) { d.CompletionEffectiveAtBound = false },
		"pins":               func(d *generated.Document) { d.EvidenceVersionPinsRequired = false },
		"source":             func(d *generated.Document) { d.BlocksJson = bytes.Clone(before.BlocksJson); d.BlocksJson[0] = 'x' },
		"parent":             func(d *generated.Document) { d.ParentEnvelopeID = pgtype.UUID{} },
		"status":             func(d *generated.Document) { d.Status = "finalizing" },
		"finalKey":           func(d *generated.Document) { d.FinalPdfKey.String += "changed" },
		"finalDigest":        func(d *generated.Document) { d.FinalPdfSha = bytes.Repeat([]byte{5}, 32) },
		"finalVersion":       func(d *generated.Document) { d.FinalPdfVersionID.String += "changed" },
		"certificateKey":     func(d *generated.Document) { d.AuditCertKey.String += "changed" },
		"certificateDigest":  func(d *generated.Document) { d.AuditCertSha256 = bytes.Repeat([]byte{5}, 32) },
		"certificateVersion": func(d *generated.Document) { d.AuditCertVersionID.String += "changed" },
		"payloadKey":         func(d *generated.Document) { d.AuditPayloadKey.String += "changed" },
		"payloadDigest":      func(d *generated.Document) { d.AuditPayloadSha256 = bytes.Repeat([]byte{5}, 32) },
		"payloadVersion":     func(d *generated.Document) { d.AuditPayloadVersionID.String += "changed" },
		"signatureKey":       func(d *generated.Document) { d.AuditSignatureKey.String += "changed" },
		"signatureDigest":    func(d *generated.Document) { d.AuditSignatureSha256 = bytes.Repeat([]byte{5}, 32) },
		"signatureVersion":   func(d *generated.Document) { d.AuditSignatureVersionID.String += "changed" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			row := completed
			change(&row)
			if historicalPublicationDocumentTupleV1(before, &row, intent) {
				t.Fatal("changed legal/source/artifact tuple or non-advancing row clock accepted")
			}
		})
	}
	missingBefore := *before
	missingBefore.UpdatedAt = pgtype.Timestamptz{}
	if historicalPublicationDocumentTupleV1(&missingBefore, &completed, intent) {
		t.Fatal("missing private old clock accepted")
	}
}
