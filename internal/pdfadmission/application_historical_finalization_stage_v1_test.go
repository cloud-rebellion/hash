// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestHistoricalFinalizationIntentCommitmentV1(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 123000, time.UTC)
	deadline := now.AddDate(7, 0, 0).Truncate(time.Second).Add(time.Second)
	sum := sha256.Sum256([]byte("actual synthetic protocol digest"))
	p := generated.CreateDocumentFinalizationIntentParams{DocumentID: uuid.New(), OrgID: uuid.New(), Mode: "signature", CompletionEffectiveAt: pgtype.Timestamptz{Time: now, Valid: true}, RetainUntil: pgtype.Timestamptz{Time: deadline, Valid: true}, FinalPdfKey: "final-" + hex.EncodeToString(sum[:]) + ".pdf", FinalPdfSha256: bytes.Clone(sum[:]), FinalPdfVersionID: pgtype.Text{String: "final-v1", Valid: true}, AuditCertKey: "audit-" + hex.EncodeToString(sum[:]) + ".pdf", AuditCertSha256: bytes.Clone(sum[:]), AuditCertVersionID: pgtype.Text{String: "cert-v1", Valid: true}, AuditPayloadKey: "audit-payload-" + hex.EncodeToString(sum[:]) + ".txt", AuditPayloadSha256: bytes.Clone(sum[:]), AuditPayloadVersionID: pgtype.Text{String: "payload-v1", Valid: true}, AuditSignatureKey: "audit-signature-" + hex.EncodeToString(sum[:]) + ".txt", AuditSignatureSha256: bytes.Clone(sum[:]), AuditSignatureVersionID: pgtype.Text{String: "signature-v1", Valid: true}}
	intent := &generated.DocumentFinalizationIntent{DocumentID: p.DocumentID, OrgID: p.OrgID, Mode: p.Mode, CompletionEffectiveAt: p.CompletionEffectiveAt, RetainUntil: p.RetainUntil, FinalPdfKey: p.FinalPdfKey, FinalPdfSha256: p.FinalPdfSha256, FinalPdfVersionID: p.FinalPdfVersionID, AuditCertKey: p.AuditCertKey, AuditCertSha256: p.AuditCertSha256, AuditCertVersionID: p.AuditCertVersionID, AuditPayloadKey: p.AuditPayloadKey, AuditPayloadSha256: p.AuditPayloadSha256, AuditPayloadVersionID: p.AuditPayloadVersionID, AuditSignatureKey: p.AuditSignatureKey, AuditSignatureSha256: p.AuditSignatureSha256, AuditSignatureVersionID: p.AuditSignatureVersionID, EvidenceVersionPinsRequired: true}
	if !historicalFinalizationIntentMatchesV1(intent, p) {
		t.Fatal("exact commitment refused")
	}
	// Original comparisons use actual instants; equivalent PostgreSQL timestamps
	// in another location must not become a new staged tuple.
	zone := time.FixedZone("synthetic offset", 3600)
	same := *intent
	same.CompletionEffectiveAt.Time = same.CompletionEffectiveAt.Time.In(zone)
	same.RetainUntil.Time = same.RetainUntil.Time.In(zone)
	if !historicalFinalizationIntentMatchesV1(&same, p) {
		t.Fatal("equivalent timestamp refused")
	}
	cases := map[string]func(*generated.DocumentFinalizationIntent){
		"document": func(i *generated.DocumentFinalizationIntent) { i.DocumentID = uuid.New() }, "org": func(i *generated.DocumentFinalizationIntent) { i.OrgID = uuid.New() }, "mode": func(i *generated.DocumentFinalizationIntent) { i.Mode = "acknowledgement" }, "completion": func(i *generated.DocumentFinalizationIntent) {
			i.CompletionEffectiveAt.Time = i.CompletionEffectiveAt.Time.Add(time.Microsecond)
		}, "deadline": func(i *generated.DocumentFinalizationIntent) {
			i.RetainUntil.Time = i.RetainUntil.Time.Add(time.Second)
		},
		"finalKey": func(i *generated.DocumentFinalizationIntent) { i.FinalPdfKey += "x" }, "finalDigest": func(i *generated.DocumentFinalizationIntent) { i.FinalPdfSha256 = bytes.Repeat([]byte{9}, 32) }, "finalVersion": func(i *generated.DocumentFinalizationIntent) { i.FinalPdfVersionID.String += "x" },
		"certKey": func(i *generated.DocumentFinalizationIntent) { i.AuditCertKey += "x" }, "certDigest": func(i *generated.DocumentFinalizationIntent) { i.AuditCertSha256 = bytes.Repeat([]byte{9}, 32) }, "certVersion": func(i *generated.DocumentFinalizationIntent) { i.AuditCertVersionID.String += "x" },
		"payloadKey": func(i *generated.DocumentFinalizationIntent) { i.AuditPayloadKey += "x" }, "payloadDigest": func(i *generated.DocumentFinalizationIntent) { i.AuditPayloadSha256 = bytes.Repeat([]byte{9}, 32) }, "payloadVersion": func(i *generated.DocumentFinalizationIntent) { i.AuditPayloadVersionID.String += "x" },
		"signatureKey": func(i *generated.DocumentFinalizationIntent) { i.AuditSignatureKey += "x" }, "signatureDigest": func(i *generated.DocumentFinalizationIntent) { i.AuditSignatureSha256 = bytes.Repeat([]byte{9}, 32) }, "signatureVersion": func(i *generated.DocumentFinalizationIntent) { i.AuditSignatureVersionID.String += "x" }, "pins": func(i *generated.DocumentFinalizationIntent) { i.EvidenceVersionPinsRequired = false },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			copy := *intent
			change(&copy)
			if historicalFinalizationIntentMatchesV1(&copy, p) {
				t.Fatal("changed actual commitment accepted")
			}
		})
	}
	if historicalFinalizationIntentMatchesV1(nil, p) {
		t.Fatal("nil intent accepted")
	}
	if !historicalFinalizationIntentArtifactV1(p.FinalPdfKey, "final-", ".pdf", p.FinalPdfSha256, p.FinalPdfVersionID.String, true) {
		t.Fatal("content-addressed artifact refused")
	}
	if historicalFinalizationIntentArtifactV1(p.FinalPdfKey, "audit-", ".pdf", p.FinalPdfSha256, p.FinalPdfVersionID.String, true) || historicalFinalizationIntentArtifactV1(p.FinalPdfKey, "final-", ".pdf", p.FinalPdfSha256, "", true) || historicalFinalizationIntentArtifactV1(p.FinalPdfKey, "final-", ".pdf", sum[:31], p.FinalPdfVersionID.String, true) {
		t.Fatal("invalid artifact identity accepted")
	}
}
func TestHistoricalFinalizationIntentFullRowCloneV1(t *testing.T) {
	row := &generated.DocumentFinalizationIntent{Mode: "signature", FinalPdfKey: "final", FinalPdfSha256: []byte{1}, FinalPdfVersionID: pgtype.Text{String: "fv", Valid: true}, AuditCertKey: "cert", AuditCertSha256: []byte{2}, AuditCertVersionID: pgtype.Text{String: "cv", Valid: true}, AuditPayloadKey: "payload", AuditPayloadSha256: []byte{3}, AuditPayloadVersionID: pgtype.Text{String: "pv", Valid: true}, AuditSignatureKey: "sig", AuditSignatureSha256: []byte{4}, AuditSignatureVersionID: pgtype.Text{String: "sv", Valid: true}, LastError: pgtype.Text{String: "provider error", Valid: true}, FitsIndexStorageKey: pgtype.Text{String: "index", Valid: true}, FitsIndexVersionID: pgtype.Text{String: "iv", Valid: true}, FitsIndexSha256: []byte{5}}
	raw, err := historicalFinalizationIntentRawV1(row)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(len("signaturefinalfvcertcvpayloadpvsigsvprovider errorindexiv") + 5)
	if raw != want {
		t.Fatalf("full row raw=%d want=%d", raw, want)
	}
	copy := historicalFinalizationCloneIntentV1(row)
	for _, b := range [][]byte{copy.FinalPdfSha256, copy.AuditCertSha256, copy.AuditPayloadSha256, copy.AuditSignatureSha256, copy.FitsIndexSha256} {
		b[0] = 99
	}
	for i, b := range [][]byte{row.FinalPdfSha256, row.AuditCertSha256, row.AuditPayloadSha256, row.AuditSignatureSha256, row.FitsIndexSha256} {
		if b[0] != byte(i+1) {
			t.Fatal("private digest aliases exposed row")
		}
	}
}
