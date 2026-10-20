// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHistoricalLegacyIntentPinEveryGeneratedColumnV1(t *testing.T) {
	stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 12, 0, 0, 123000, time.UTC), Valid: true}
	before := &generated.DocumentFinalizationIntent{DocumentID: uuid.New(), OrgID: uuid.New(), Mode: "signature", FinalPdfKey: "final", FinalPdfSha256: []byte{1}, AuditCertKey: "cert", AuditCertSha256: []byte{2}, AuditPayloadKey: "payload", AuditPayloadSha256: []byte{3}, AuditSignatureKey: "signature", AuditSignatureSha256: []byte{4}, RetentionStartedAt: stamp, RetentionCompletedAt: stamp, Attempts: 7, LastError: pgtype.Text{String: "original provider error", Valid: true}, CreatedAt: stamp, UpdatedAt: stamp, CompletionEffectiveAt: stamp, RetainUntil: stamp, FittedPreparationID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, FitsIndexStorageKey: pgtype.Text{String: "index", Valid: true}, FitsIndexVersionID: pgtype.Text{String: "iv", Valid: true}, FitsIndexSha256: []byte{5}, FitsIndexBytes: pgtype.Int8{Int64: 123, Valid: true}}
	versions := [4]string{"fv", "cv", "pv", "sv"}
	after := historicalFinalizationCloneIntentV1(before)
	after.FinalPdfVersionID = pgtype.Text{String: versions[0], Valid: true}
	after.AuditCertVersionID = pgtype.Text{String: versions[1], Valid: true}
	after.AuditPayloadVersionID = pgtype.Text{String: versions[2], Valid: true}
	after.AuditSignatureVersionID = pgtype.Text{String: versions[3], Valid: true}
	after.EvidenceVersionPinsRequired = true
	after.UpdatedAt.Time = after.UpdatedAt.Time.Add(time.Microsecond)
	if !historicalLegacyIntentPinTupleV1(before, after, versions) {
		t.Fatal("exact original CAS delta refused")
	}
	typ := reflect.TypeOf(*after)
	for index := 0; index < typ.NumField(); index++ {
		name := typ.Field(index).Name
		if name == "UpdatedAt" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			changed := historicalFinalizationCloneIntentV1(after)
			if !blockSendMutateTupleFieldV1(reflect.ValueOf(changed).Elem().Field(index)) {
				t.Fatalf("no mutation for generated column %s", name)
			}
			if historicalLegacyIntentPinTupleV1(before, changed, versions) {
				t.Fatalf("changed %s accepted", name)
			}
		})
	}
	// The independently retained publication witness must reject mutation of
	// every generated column, including each normally mutable checkpoint clock.
	if !historicalIntentExactRowV1(after, after) {
		t.Fatal("same exact intent refused")
	}
	for index := 0; index < typ.NumField(); index++ {
		name := typ.Field(index).Name
		t.Run("witness_"+name, func(t *testing.T) {
			changed := historicalFinalizationCloneIntentV1(after)
			if !blockSendMutateTupleFieldV1(reflect.ValueOf(changed).Elem().Field(index)) {
				t.Fatalf("no mutation for %s", name)
			}
			if historicalIntentExactRowV1(after, changed) {
				t.Fatalf("witness accepted changed %s", name)
			}
		})
	}
	// Before compatibility, a genuine original false requirement is data, not
	// pinned-publication authority. Exact comparison must preserve all columns
	// for both all-absent legacy pins and the original partial-pin refusal path.
	partial := historicalFinalizationCloneIntentV1(before)
	partial.FinalPdfVersionID = after.FinalPdfVersionID
	for _, originalCase := range []struct {
		name string
		row  *generated.DocumentFinalizationIntent
	}{{"legacy_original", before}, {"partial_original", partial}} {
		t.Run(originalCase.name, func(t *testing.T) {
			original := originalCase.row
			if !historicalIntentExactRowV1(original, historicalFinalizationCloneIntentV1(original)) {
				t.Fatal("identical original intent refused before compatibility")
			}
			if historicalFinalizationSameIntentV1(original, original) {
				t.Fatal("original legacy intent represented as pinned publication")
			}
			for index := 0; index < typ.NumField(); index++ {
				name := typ.Field(index).Name
				t.Run(name, func(t *testing.T) {
					changed := historicalFinalizationCloneIntentV1(original)
					if !blockSendMutateTupleFieldV1(reflect.ValueOf(changed).Elem().Field(index)) {
						t.Fatalf("no mutation for original column %s", name)
					}
					if historicalIntentExactRowV1(original, changed) {
						t.Fatalf("original witness accepted changed %s", name)
					}
				})
			}
		})
	}
	sameInstant := historicalFinalizationCloneIntentV1(after)
	sameInstant.CreatedAt.Time = sameInstant.CreatedAt.Time.In(time.FixedZone("same database instant", 7200))
	if !historicalIntentExactRowV1(after, sameInstant) || !historicalLegacyIntentPinTupleV1(before, sameInstant, versions) {
		t.Fatal("database-equal timestamp location refused")
	}
	for _, bad := range []pgtype.Timestamptz{{}, {Valid: true, InfinityModifier: pgtype.Infinity}, {Valid: true}} {
		changed := historicalFinalizationCloneIntentV1(after)
		changed.UpdatedAt = bad
		if historicalLegacyIntentPinTupleV1(before, changed, versions) {
			t.Fatal("non-finite/zero clock accepted")
		}
	}
	if historicalLegacyIntentPinTupleV1(nil, after, versions) || historicalLegacyIntentPinTupleV1(before, nil, versions) {
		t.Fatal("nil original accepted")
	}
	if historicalLegacyIntentHasPinsV1(before) {
		t.Fatal("legacy row represented as pinned")
	}
}

func TestHistoricalLegacyIntentBridgeNeedsActualNativeSourceV1(t *testing.T) {
	var missing *ApplicationHistoricalFinalizationSourceEvidenceV1
	if row, err := missing.EnsureIntentVersionsV1(context.Background()); row != nil || err == nil {
		t.Fatal("nil source admitted")
	}
	invented := &ApplicationHistoricalFinalizationSourceEvidenceV1{}
	invented.self = invented
	if row, err := invented.EnsureIntentVersionsV1(context.Background()); row != nil || err == nil {
		t.Fatal("invented source admitted")
	}
}

func TestHistoricalIntentWitnessCannotAcknowledgeInventedOwnerV1(t *testing.T) {
	var missing *ApplicationHistoricalFinalizationSourceEvidenceV1
	if ref, err := missing.ConfirmHistoricalPublicationIntentV1(nil); ref != nil || err == nil {
		t.Fatal("nil source acknowledged witness")
	}
	invented := &ApplicationHistoricalFinalizationSourceEvidenceV1{}
	invented.self = invented
	if ref, err := invented.ConfirmHistoricalPublicationIntentV1(&ApplicationHistoricalFinalizationStageReferenceV1{}); ref != nil || err == nil {
		t.Fatal("invented source acknowledged witness")
	}
	var missingPublication *ApplicationHistoricalFinalizationPublicationReferenceV1
	if missingPublication.MatchesOriginalIntentV1(nil, &generated.DocumentFinalizationIntent{}) || (&ApplicationHistoricalFinalizationPublicationReferenceV1{}).MatchesOriginalIntentV1(&ApplicationHTMLSendOperationV1{}, &generated.DocumentFinalizationIntent{}) {
		t.Fatal("invented original-row witness supplied native operation authority")
	}
	if historicalSourceWorkCommittedV1(nil) {
		t.Fatal("nil Work supplied commit")
	}
	w := &ApplicationHTMLSendWorkV1{}
	w.self = w
	if historicalSourceWorkCommittedV1(w) {
		t.Fatal("invented Work supplied commit")
	}
}

// Evidence gained the same nonblocking exit handshake: its actual metadata
// comparison and synchronous provider refusals cannot lose a pending Close.
func TestHistoricalEvidenceMetadataCloseRaceJoinsV1(t *testing.T) {
	for index := 0; index < 256; index++ {
		var released atomic.Int32
		e := &ApplicationHistoricalFinalizationEvidenceV1{releaseBody: func() { released.Add(1) }}
		e.self = e
		start := make(chan struct{})
		var joined sync.WaitGroup
		for _, fn := range []func(){func() { e.MatchesIntentV1(nil) }, func() { e.VerifyIntentArtifactsV1() }, func() { e.RetainIntentArtifactsV1() }, func() { e.CloseConsumerV1() }} {
			joined.Add(1)
			go func(f func()) { defer joined.Done(); <-start; f() }(fn)
		}
		close(start)
		joined.Wait()
		if released.Load() != 1 {
			t.Fatalf("iteration %d lost pending evidence Close: %d", index, released.Load())
		}
	}
}
