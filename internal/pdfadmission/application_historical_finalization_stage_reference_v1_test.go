// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestHistoricalFinalizationStageReferenceKeepsOnlyOriginalCommitmentV1(t *testing.T) {
	at := time.Date(2026, 10, 15, 10, 11, 12, 0, time.UTC)
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Status: "finalizing", RequiresSignature: true, CompletionEffectiveAtBound: true, CompletionEffectiveAt: pgtype.Timestamptz{Time: at, Valid: true}, FinalizationRetainUntil: pgtype.Timestamptz{Time: at.AddDate(7, 0, 0), Valid: true}}
	commitment, ok := historicalFinalizationStageCommitmentV1(doc)
	if !ok || !historicalFinalizationStageCommitmentMatchesV1(commitment, doc) {
		t.Fatal("actual immutable commitment rejected")
	}
	same := *doc
	same.CompletionEffectiveAt.Time = at.In(time.FixedZone("same instant", 3600))
	same.FinalizationRetainUntil.Time = same.FinalizationRetainUntil.Time.In(time.FixedZone("same deadline", 3600))
	if !historicalFinalizationStageCommitmentMatchesV1(commitment, &same) {
		t.Fatal("equivalent SQL instants rejected")
	}
	for name, change := range map[string]func(*generated.Document){
		"status": func(d *generated.Document) { d.Status = "in_progress" },
		"mode":   func(d *generated.Document) { d.RequiresSignature = false },
		"bound":  func(d *generated.Document) { d.CompletionEffectiveAtBound = false },
		"completion": func(d *generated.Document) {
			d.CompletionEffectiveAt.Time = d.CompletionEffectiveAt.Time.Add(time.Microsecond)
		},
		"deadline": func(d *generated.Document) {
			d.FinalizationRetainUntil.Time = d.FinalizationRetainUntil.Time.Add(time.Second)
		},
		"missing completion":  func(d *generated.Document) { d.CompletionEffectiveAt.Valid = false },
		"infinite completion": func(d *generated.Document) { d.CompletionEffectiveAt.InfinityModifier = pgtype.Infinity },
		"missing deadline":    func(d *generated.Document) { d.FinalizationRetainUntil.Valid = false },
		"infinite deadline":   func(d *generated.Document) { d.FinalizationRetainUntil.InfinityModifier = pgtype.Infinity },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *doc
			change(&changed)
			if historicalFinalizationStageCommitmentMatchesV1(commitment, &changed) {
				t.Fatal("changed commitment accepted")
			}
		})
	}
}

func TestHistoricalFinalizationStageReferenceRejectsCopiesAndRetirementV1(t *testing.T) {
	// This is an explicit private-state predicate fixture, not a synthetic SQL
	// transaction/lock grant or a public constructor acceptance claim.
	factory := &ApplicationSessionFactoryV1{state: &applicationSessionFactoryStateV1{}}
	owner := &applicationHistoricalFinalizationLockStateV1{factory: factory, org: uuid.New(), document: uuid.New(), acquired: true, stagePrepared: true}
	owner.self = owner
	owner.stageReference.owner = owner
	reference := &owner.stageReference
	if _, err := reference.ownerV1(factory); err != nil {
		t.Fatal(err)
	}
	copyShell := &ApplicationHistoricalFinalizationStageReferenceV1{owner: owner}
	if _, err := copyShell.ownerV1(factory); err == nil {
		t.Fatal("copied reference shell accepted")
	}
	if _, err := reference.ownerV1(&ApplicationSessionFactoryV1{state: factory.state}); err == nil {
		t.Fatal("different factory handle accepted")
	}
	owner.stagePrepared = false
	if _, err := reference.ownerV1(factory); err == nil {
		t.Fatal("unprepared reference accepted")
	}
	owner.stagePrepared = true
	owner.closed = true
	if _, err := reference.ownerV1(factory); err == nil {
		t.Fatal("retired serialization reference accepted")
	}
}
