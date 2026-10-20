// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestHistoricalPublicationReferenceExactTupleAndOwnGrantV1(t *testing.T) {
	_, evidence, fixture, coordinator, ctx, _ := historicalFinalizationEvidenceFixtureV1(t)
	// Predicate-only witness fixture uses the REAL coordinator and an already
	// admitted actual private intent. It does not claim a public constructor or
	// PG serialization backend; actual journeys qualify that independent gate.
	grant, err := coordinator.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ParentBytes: 16384})
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Close()
	owner := &applicationHistoricalFinalizationLockStateV1{publicationIntent: historicalFinalizationCloneIntentV1(evidence.intent), publicationGrant: grant}
	owner.self = owner
	owner.publicationReference.owner = owner
	reference := &owner.publicationReference
	if !reference.MatchesIntentV1(evidence.intent) {
		t.Fatal("actual immutable tuple rejected")
	}
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	copyShell := &ApplicationHistoricalFinalizationPublicationReferenceV1{owner: owner}
	if copyShell.MatchesIntentV1(evidence.intent) {
		t.Fatal("copied publication shell accepted")
	}
	for name, change := range map[string]func(*generated.DocumentFinalizationIntent){
		"scope":    func(i *generated.DocumentFinalizationIntent) { i.OrgID[0] ^= 1 },
		"version":  func(i *generated.DocumentFinalizationIntent) { i.FinalPdfVersionID.String = "different" },
		"pin flag": func(i *generated.DocumentFinalizationIntent) { i.EvidenceVersionPinsRequired = false },
		"digest":   func(i *generated.DocumentFinalizationIntent) { i.AuditSignatureSha256[0] ^= 1 },
		"deadline": func(i *generated.DocumentFinalizationIntent) {
			i.RetainUntil.Time = i.RetainUntil.Time.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := historicalFinalizationCloneIntentV1(evidence.intent)
			change(changed)
			if reference.MatchesIntentV1(changed) {
				t.Fatal("changed actual legal tuple accepted")
			}
		})
	}
	retry := historicalFinalizationCloneIntentV1(evidence.intent)
	retry.LastError = pgtype.Text{String: "retry-only", Valid: true}
	retry.Attempts++
	if !reference.MatchesIntentV1(retry) {
		t.Fatal("retry metadata changed original legal identity")
	}
	if coordinator.SnapshotV1(fixture.scope.OrgID) != before {
		t.Fatal("comparison refunded native witness debt")
	}
	owner.closed = true
	if reference.MatchesIntentV1(evidence.intent) {
		t.Fatal("retired serialization witness accepted")
	}
}
