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

func TestHistoricalFinalizationCheckpointKeepsLegalTupleV1(t *testing.T) {
	now := pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC), Valid: true}
	intent := &generated.DocumentFinalizationIntent{DocumentID: uuid.New(), OrgID: uuid.New(), Mode: "signature", CompletionEffectiveAt: now, RetainUntil: now, FinalPdfKey: "f", FinalPdfSha256: bytes.Repeat([]byte{1}, 32), FinalPdfVersionID: pgtype.Text{String: "fv", Valid: true}, AuditCertKey: "c", AuditCertSha256: bytes.Repeat([]byte{2}, 32), AuditCertVersionID: pgtype.Text{String: "cv", Valid: true}, AuditPayloadKey: "p", AuditPayloadSha256: bytes.Repeat([]byte{3}, 32), AuditPayloadVersionID: pgtype.Text{String: "pv", Valid: true}, AuditSignatureKey: "s", AuditSignatureSha256: bytes.Repeat([]byte{4}, 32), AuditSignatureVersionID: pgtype.Text{String: "sv", Valid: true}, EvidenceVersionPinsRequired: true}
	if !historicalFinalizationSameIntentV1(intent, intent) {
		t.Fatal("same legal tuple refused")
	}
	retry := *intent
	retry.Attempts = 4
	retry.LastError = pgtype.Text{String: "previous attempt", Valid: true}
	retry.RetentionStartedAt = now
	retry.RetentionCompletedAt = now
	retry.UpdatedAt = now
	if !historicalFinalizationSameIntentV1(intent, &retry) {
		t.Fatal("retry metadata changed legal tuple")
	}
	cases := map[string]func(*generated.DocumentFinalizationIntent){"org": func(i *generated.DocumentFinalizationIntent) { i.OrgID = uuid.New() }, "version": func(i *generated.DocumentFinalizationIntent) { i.FinalPdfVersionID.String = "different" }, "digest": func(i *generated.DocumentFinalizationIntent) { i.AuditSignatureSha256 = bytes.Repeat([]byte{8}, 32) }, "pins": func(i *generated.DocumentFinalizationIntent) { i.EvidenceVersionPinsRequired = false }, "fittedID": func(i *generated.DocumentFinalizationIntent) {
		i.FittedPreparationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	}, "indexKey": func(i *generated.DocumentFinalizationIntent) {
		i.FitsIndexStorageKey = pgtype.Text{String: "index", Valid: true}
	}, "indexVersion": func(i *generated.DocumentFinalizationIntent) {
		i.FitsIndexVersionID = pgtype.Text{String: "version", Valid: true}
	}, "indexDigest": func(i *generated.DocumentFinalizationIntent) { i.FitsIndexSha256 = bytes.Repeat([]byte{6}, 32) }, "indexBytes": func(i *generated.DocumentFinalizationIntent) { i.FitsIndexBytes = pgtype.Int8{Int64: 1, Valid: true} }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			copy := *intent
			change(&copy)
			if historicalFinalizationSameIntentV1(intent, &copy) {
				t.Fatal("changed legal tuple accepted")
			}
		})
	}
}
