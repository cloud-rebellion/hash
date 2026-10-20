// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// Uses the existing explicitly synthetic already-open SQL/backend fixture.
// Real owner/admission/coordinator and concrete first-party HTTP SDK execute;
// this does not claim public factory/PG intent reads or provider Object Lock.
func historicalFinalizationEvidenceFixtureV1(t *testing.T) (*ApplicationHTMLSendWorkV1, *ApplicationHistoricalFinalizationEvidenceV1, *applicationFixtureV1, *workguard.CoordinatorV1, context.Context, *atomic.Int64) {
	return historicalFinalizationEvidenceFixtureWithPeerV1(t, nil)
}

// Optional concrete HTTP gate belongs only to this explicit synthetic SQL
// fixture. It is installed BEFORE genuine storage.New and native construction;
// no native client/source field or real resource decision is replaced later.
type historicalEvidencePeerGateV1 struct {
	entered, release chan struct{}
	once             sync.Once
	failure          bool
}

func historicalFinalizationEvidenceFixtureWithPeerV1(t *testing.T, gate *historicalEvidencePeerGateV1) (*ApplicationHTMLSendWorkV1, *ApplicationHistoricalFinalizationEvidenceV1, *applicationFixtureV1, *workguard.CoordinatorV1, context.Context, *atomic.Int64) {
	t.Helper()
	fixture, session, coordinator := applicationRequestLoanFixtureV1(t)
	factory := &ApplicationSessionFactoryV1{state: session.state.factory}
	factory.state.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	operation, err := factory.NewHTMLSendOperationV1(ctx, fixture.scope.OrgID, fixture.scope.DocumentID)
	if err != nil {
		t.Fatal(err)
	}
	stage := &ApplicationHTMLSendSQLStageV1{operation: operation, purpose: HTMLHistoricalFinalizationEvidenceV1, ctx: ctx, cancel: func() {}, session: session, active: true}
	stage.self = stage
	operation.stages = append(operation.stages, stage)
	payload := []byte("synthetic immutable finalization protocol object")
	sum := sha256.Sum256(payload)
	gets := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/finalization-evidence" || r.URL.Path == "/finalization-evidence/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("ETag", "\"fixed\"")
		w.Header().Set("Last-Modified", "Wed, 15 Oct 2025 00:00:00 GMT")
		w.Header().Set("X-Amz-Version-Id", "version-one")
		if r.Method == http.MethodGet {
			gets.Add(1)
			if gate != nil {
				if gate.entered != nil {
					gate.once.Do(func() { close(gate.entered) })
				}
				if gate.release != nil {
					select {
					case <-gate.release:
					case <-r.Context().Done():
						return
					}
				}
				if gate.failure {
					w.Header().Del("Content-Length")
					http.Error(w, "synthetic actual verification provider failure", http.StatusServiceUnavailable)
					return
				}
			}
			_, _ = w.Write(payload)
		}
	}))
	t.Cleanup(server.Close)
	client, err := storage.New(ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "finalization-evidence", AccessKey: "synthetic", SecretKey: "synthetic-secret", BucketLookup: "path", RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	intent := &generated.DocumentFinalizationIntent{DocumentID: fixture.scope.DocumentID, OrgID: fixture.scope.OrgID, Mode: "signature", CompletionEffectiveAt: pgtype.Timestamptz{Time: now, Valid: true}, RetainUntil: pgtype.Timestamptz{Time: storage.EvidenceRetentionDeadline(now, 7), Valid: true}, FinalPdfKey: "final.pdf", FinalPdfSha256: sum[:], FinalPdfVersionID: pgtype.Text{String: "version-one", Valid: true}, AuditCertKey: "cert.pdf", AuditCertSha256: sum[:], AuditCertVersionID: pgtype.Text{String: "version-one", Valid: true}, AuditPayloadKey: "payload.txt", AuditPayloadSha256: sum[:], AuditPayloadVersionID: pgtype.Text{String: "version-one", Valid: true}, AuditSignatureKey: "signature.txt", AuditSignatureSha256: sum[:], AuditSignatureVersionID: pgtype.Text{String: "version-one", Valid: true}, EvidenceVersionPinsRequired: true}
	var work *ApplicationHTMLSendWorkV1
	var evidence *ApplicationHistoricalFinalizationEvidenceV1
	t.Cleanup(func() {
		if evidence != nil {
			evidence.CloseConsumerV1()
		}
		if work != nil {
			work.CloseConsumerV1()
		}
		if !applicationDoneV1(fixture.done) {
			close(fixture.done)
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = fixture.adapter.CloseV1(cleanup)
	})
	err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		work, err = session.NewHTMLSendWorkV1(call, stage)
		if err != nil {
			return err
		}
		raw, err := historicalFinalizationIntentRawV1(intent)
		if err != nil {
			return err
		}
		raw += 5*int64(unsafe.Sizeof(generated.DocumentFinalizationIntent{})) + 2*int64(unsafe.Sizeof(generated.GetHTMLSendDocumentStateHeaderV1Row{}))
		closeRow, err := work.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
		if err != nil {
			return err
		}
		work.closes = append(work.closes, closeRow)
		// Explicit synthetic scalar/typed intent receipts AFTER their positive loan.
		work.state = &generated.GetHTMLSendDocumentStateHeaderV1Row{ID: fixture.scope.DocumentID, OrgID: fixture.scope.OrgID, BoundedStatus: "finalizing", UpdatedAt: pgtype.Timestamptz{Time: now, Valid: true}}
		work.finalization = &applicationHistoricalFinalizationV1{intent: historicalFinalizationCloneIntentV1(intent), intentView: intent, intentRead: true}
		evidence, err = work.NewHistoricalFinalizationEvidenceV1(call, client)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return work, evidence, fixture, coordinator, ctx, gets
}
func TestHistoricalFinalizationEvidenceActualProviderDenialAndFourArtifactsV1(t *testing.T) {
	work, evidence, fixture, coordinator, ctx, gets := historicalFinalizationEvidenceFixtureV1(t)
	occupied, err := coordinator.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	calls := gets.Load()
	if err = evidence.VerifyIntentArtifactsV1(); err == nil {
		t.Fatal("occupied actual same-provider slot admitted verification")
	}
	if gets.Load() != calls || coordinator.SnapshotV1(fixture.scope.OrgID) != before {
		t.Fatal("denied native provider issued network or changed charged debt")
	}
	occupied.Close()
	if err = evidence.VerifyIntentArtifactsV1(); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != calls+4 {
		t.Fatal("did not verify actual four committed artifacts", gets.Load()-calls)
	}
	if err = evidence.RetainIntentArtifactsV1(); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != calls+12 {
		t.Fatal("development retention did not verify allfour before exact post-retain check", gets.Load()-calls)
	}
	copied := &ApplicationHistoricalFinalizationEvidenceV1{self: evidence}
	copied.CloseConsumerV1()
	if evidence.closeRequested.Load() {
		t.Fatal("copied shell closed actual native owner")
	}
	work.CloseConsumerV1()
	if !work.resourcesClosed || evidence.intent != nil || evidence.work != nil || evidence.releaseBody != nil {
		t.Fatal("true consumer closure retained actual intent/source references")
	}
}
func TestHistoricalFinalizationEvidenceActualJoinKeepsDebtV1(t *testing.T) {
	for _, physicalFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(physicalFirst), func(t *testing.T) {
			gate := &historicalEvidencePeerGateV1{entered: make(chan struct{}), release: make(chan struct{})}
			work, evidence, fixture, coordinator, ctx, _ := historicalFinalizationEvidenceFixtureWithPeerV1(t, gate)
			var release sync.Once
			finish := func() { release.Do(func() { close(gate.release) }) }
			t.Cleanup(finish)
			result := make(chan error, 1)
			go func() { result <- evidence.VerifyIntentArtifactsV1() }()
			select {
			case <-gate.entered:
			case <-ctx.Done():
				t.Fatal("actual provider did not enter", ctx.Err())
			}
			if physicalFirst {
				close(fixture.done)
				if _, err := fixture.adapter.ReconcileCleanupV1(ctx); err != nil {
					t.Fatal(err)
				}
			}
			before := coordinator.SnapshotV1(fixture.scope.OrgID)
			if before.Global.ProviderStreams != 1 {
				t.Fatal("real provider stream not charged", before)
			}
			work.CloseConsumerV1()
			if work.resourcesClosed || evidence.intent == nil || coordinator.SnapshotV1(fixture.scope.OrgID) != before {
				t.Fatal("consumer/cancellation credited actual in-flight intent/provider")
			}
			// Genuine HTTP response/read/localIO join replaces the retired synthetic
			// providerV1 grant seam. Original positive debt/conjunction assertions stay.
			finish()
			select {
			case <-result:
			case <-ctx.Done():
				t.Fatal("actual provider failed to join", ctx.Err())
			}
			if !work.resourcesClosed || evidence.intent != nil {
				t.Fatal("actual final local call join did not retire consumer references")
			}
			if !physicalFirst {
				close(fixture.done)
			}
			if pending, err := fixture.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 0 {
				t.Fatal("actual physical+consumer conjunction did not settle", pending, err)
			}
			if coordinator.SnapshotV1(fixture.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("joined native debt remains")
			}
		})
	}
}
