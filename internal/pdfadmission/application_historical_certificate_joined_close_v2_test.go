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
	"github.com/google/uuid"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These shells intentionally have no native SQL/body/claims authority. They
// test the actual joined-close primitives with real positive Parent grants;
// original public E2E journeys separately establish output provenance.
func historicalCertificateCloseCoordinatorV2(t *testing.T) (context.Context, *workguard.CoordinatorV1, uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	limit := workguard.VectorV1{ParentBytes: 1 << 20}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, c, uuid.New()
}
func historicalCertificateCloseGrantV2(t *testing.T, ctx context.Context, c *workguard.CoordinatorV1, org uuid.UUID) *workguard.GrantV1 {
	t.Helper()
	g, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func historicalCertificateAssertDrainedV2(t *testing.T, c *workguard.CoordinatorV1, org uuid.UUID) {
	t.Helper()
	if got := c.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("real certificate ownership did not drain", got)
	}
}
func TestHistoricalCertificateClaimsCloseReleasesOutsideEnclosingSourceV2(t *testing.T) {
	ctx, c, org := historicalCertificateCloseCoordinatorV2(t)
	sourceGrant := historicalCertificateCloseGrantV2(t, ctx, c, org)
	finalGrant := historicalCertificateCloseGrantV2(t, ctx, c, org)
	var releases atomic.Int32
	source := &ApplicationHistoricalFinalizationSourceEvidenceV1{releaseBody: sourceGrant.Close}
	source.self = source
	final := &ApplicationHistoricalFinalizationPDFV1{grant: finalGrant, source: source, key: "owned-key", pin: storage.StoredObject{VersionID: "owned-version"}, releaseSource: func() { releases.Add(1); source.finishBodyBorrowV1() }}
	final.self = final
	locked := make(chan struct{})
	exit := make(chan struct{})
	joined := make(chan struct{})
	// Go mutex ownership is not goroutine-affine. Admit the actual consumer
	// here so any setup refusal fails in the test goroutine before handoff.
	if !source.lockV1() {
		t.Fatal("actual source metadata entry refused")
	}
	if !source.beginBodyBorrowLockedV1() {
		source.unlockV1()
		t.Fatal("actual source body registration refused")
	}
	if !final.lockV1() {
		source.unlockV1()
		t.Fatal("actual final metadata entry refused")
	}
	go func() {
		close(locked)
		<-exit
		final.unlockSourceConsumerV1(source)
		close(joined)
	}()
	select {
	case <-locked:
	case <-ctx.Done():
		close(exit)
		<-joined
		t.Fatal("actual metadata consumer handoff did not join")
	}
	// Both copied closes fence new work while the admitted enclosing consumer
	// owns the locks. Final cleanup unlocks source before its real callback.
	final.CloseConsumerV1()
	source.CloseConsumerV1()
	if got := c.SnapshotV1(org); got.Global.ParentBytes != 131072 {
		t.Fatal("lock-held source was credited", got)
	}
	close(exit)
	select {
	case <-joined:
	case <-ctx.Done():
		t.Fatal("final release reentered the enclosing source mutex")
	}
	if releases.Load() != 1 {
		t.Fatal("actual source borrower did not release once", releases.Load())
	}
	if final.key != "" || final.pin.VersionID != "" || final.hashFailure != nil {
		t.Fatal("closed final retained owned metadata aliases")
	}
	historicalCertificateAssertDrainedV2(t, c, org)
}
func TestHistoricalTerminalManifestBorrowKeepsScopeThroughCopiedCloseV2(t *testing.T) {
	ctx, c, org := historicalCertificateCloseCoordinatorV2(t)
	for index := 0; index < 256; index++ {
		factory := &ApplicationSessionFactoryV1{}
		doc := &generated.Document{ID: uuid.New(), OrgID: org}
		source := &ApplicationHistoricalFinalizationSourceEvidenceV1{document: doc, work: &ApplicationHTMLSendWorkV1{stage: &ApplicationHTMLSendSQLStageV1{operation: &ApplicationHTMLSendOperationV1{factory: factory}}}}
		h := &ApplicationHistoricalFinalizationHTMLV1{grant: historicalCertificateCloseGrantV2(t, ctx, c, org), factory: factory, org: org, document: doc.ID, html: "actual retained manifest"}
		h.self = h
		m := &ApplicationHistoricalTerminalManifestV1{html: h, updated: doc.UpdatedAt}
		m.self = m
		section, finish, err := m.borrowForCertificateV1(source)
		if err != nil {
			t.Fatal(err)
		}
		copied := m
		joined := make(chan struct{})
		go func() { copied.CloseConsumerV1(); close(joined) }()
		<-joined
		if section != "actual retained manifest" || c.SnapshotV1(org).Global.ParentBytes != 65536 {
			t.Fatal("copied Close credited actual manifest borrower")
		}
		finish()
		historicalCertificateAssertDrainedV2(t, c, org)
		// Exercise the exact former scope-read/clear race as well as the guaranteed
		// held-borrow case. Close-before-borrow may refuse; a real borrow must join.
		h = &ApplicationHistoricalFinalizationHTMLV1{grant: historicalCertificateCloseGrantV2(t, ctx, c, org), factory: factory, org: org, document: doc.ID, html: "racing manifest"}
		h.self = h
		m = &ApplicationHistoricalTerminalManifestV1{html: h, updated: doc.UpdatedAt}
		m.self = m
		start := make(chan struct{})
		var both sync.WaitGroup
		both.Add(2)
		go func() {
			defer both.Done()
			<-start
			section, finish, err := m.borrowForCertificateV1(source)
			if err == nil {
				if section != "racing manifest" {
					t.Error("borrowed manifest changed")
				}
				finish()
			}
		}()
		go func() { defer both.Done(); <-start; m.CloseConsumerV1() }()
		close(start)
		both.Wait()
		historicalCertificateAssertDrainedV2(t, c, org)
	}
}
func TestHistoricalStoredMetadataBorrowKeepsControlsThroughCopiedCloseV2(t *testing.T) {
	for _, kind := range []string{"final", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			ctx, c, org := historicalCertificateCloseCoordinatorV2(t)
			grant := historicalCertificateCloseGrantV2(t, ctx, c, org)
			entered := make(chan struct{})
			finish := make(chan struct{})
			joined := make(chan error, 1)
			var closes func()
			var final *ApplicationHistoricalFinalizationPDFV1
			var certificate *ApplicationHistoricalAuditCertificateV1
			if kind == "final" {
				final = &ApplicationHistoricalFinalizationPDFV1{grant: grant, stored: true, key: "final-key", pin: storage.StoredObject{VersionID: "final-version"}}
				final.self = final
				closes = final.CloseConsumerV1
				go func() {
					joined <- final.WithStoredFinalV1(func(key string, _ [sha256.Size]byte, version string) error {
						close(entered)
						<-finish
						if key != "final-key" || version != "final-version" {
							t.Error("final metadata changed during real consumer")
						}
						return nil
					})
				}()
			} else {
				certificate = &ApplicationHistoricalAuditCertificateV1{grant: grant, stored: true, keys: [3]string{"pdf", "payload", "signature"}, versions: [3]string{"pdf-v", "payload-v", "signature-v"}}
				certificate.self = certificate
				closes = certificate.CloseConsumerV1
				go func() {
					joined <- certificate.WithStoredV1(func(keys [3]string, _ [3][sha256.Size]byte, versions [3]string) error {
						close(entered)
						<-finish
						if keys != [3]string{"pdf", "payload", "signature"} || versions != [3]string{"pdf-v", "payload-v", "signature-v"} {
							t.Error("certificate metadata changed during real consumer")
						}
						return nil
					})
				}()
			}
			<-entered
			copiedClose := closes
			copiedClose()
			if got := c.SnapshotV1(org); got.Global.ParentBytes != 65536 {
				t.Fatal("copied Close credited active Stage metadata", got)
			}
			close(finish)
			if err := <-joined; err != nil {
				t.Fatal(err)
			}
			historicalCertificateAssertDrainedV2(t, c, org)
			if final != nil {
				if final.key != "" || final.pin.VersionID != "" {
					t.Fatal("final metadata aliases survived retirement")
				}
				if err := final.WithStoredFinalV1(func(string, [sha256.Size]byte, string) error { t.Error("closed metadata callback ran"); return nil }); err == nil {
					t.Fatal("closed final metadata accepted")
				}
			}
			if certificate != nil {
				if certificate.keys != [3]string{} || certificate.versions != [3]string{} {
					t.Fatal("certificate metadata aliases survived retirement")
				}
				if err := certificate.WithStoredV1(func([3]string, [3][sha256.Size]byte, [3]string) error {
					t.Error("closed metadata callback ran")
					return nil
				}); err == nil {
					t.Fatal("closed certificate metadata accepted")
				}
			}
		})
	}
}

func TestHistoricalFinalControlWaitsForActualSourceReleaseCallbackV3(t *testing.T) {
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprint(detached), func(t *testing.T) {
			ctx, c, org := historicalCertificateCloseCoordinatorV2(t)
			sourceGrant := historicalCertificateCloseGrantV2(t, ctx, c, org)
			finalGrant := historicalCertificateCloseGrantV2(t, ctx, c, org)
			source := &ApplicationHistoricalFinalizationSourceEvidenceV1{releaseBody: sourceGrant.Close}
			source.self = source
			entered := make(chan struct{})
			joined := make(chan struct{})
			final := &ApplicationHistoricalFinalizationPDFV1{grant: finalGrant, source: source, releaseSource: func() { close(entered); source.finishBodyBorrowV1() }}
			final.self = final
			if !source.lockV1() {
				t.Fatal("actual source metadata entry refused")
			}
			if !source.beginBodyBorrowLockedV1() {
				t.Fatal("actual source body registration refused")
			}
			source.CloseConsumerV1()
			if detached {
				final.stored = true
				final.bodyRetired = true
			}
			go func() {
				if detached {
					final.RetireSourceConsumerV1()
					final.CloseConsumerV1()
				} else {
					final.CloseConsumerV1()
				}
				close(joined)
			}()
			<-entered
			if detached {
				final.CloseConsumerV1()
			} // Actual copied Close races the blocked detached release.
			// This is the real finishBodyBorrow callback, blocked on its original source
			// mutex. Its once/closure remains a live consumer of final's fixed control.
			if got := c.SnapshotV1(org); got.Global.ParentBytes != 131072 {
				source.unlockV1()
				<-joined
				t.Fatal("fixed final control credited before source callback joined", got)
			}
			select {
			case <-joined:
				source.unlockV1()
				t.Fatal("source callback joined while its actual mutex remained held")
			default:
			}
			source.unlockV1()
			select {
			case <-joined:
			case <-ctx.Done():
				t.Fatal("actual source release did not join")
			}
			historicalCertificateAssertDrainedV2(t, c, org)
		})
	}
}
