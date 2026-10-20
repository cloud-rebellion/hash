// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
)

func TestEvidenceLocalObservationPreservesPositiveVersionAfterRetentionFailureV1(t *testing.T) {
	ctx, client, peer, coordinator, org := evidenceLocalTestClientV1(t)
	body := []byte("actual frozen participant report")
	digest := sha256.Sum256(body)
	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	peer.mu.Lock()
	peer.denyRetention = true
	peer.mu.Unlock()
	put, failure := client.PutEvidenceVersionedLocalOwnedV1(ctx, "report.pdf", "application/pdf", body, until, coordinator, org)
	if put != nil {
		defer put.CloseConsumerV1()
	}
	if put == nil || failure == nil || !strings.Contains(failure.Error(), "retention confirmation unavailable") {
		t.Fatal("actual late retention failure was lost", failure)
	}
	if err := put.WithStoredV1(func(StoredObject) error { return nil }); err == nil {
		t.Fatal("unverified positive version became successful evidence")
	}
	var version string
	err := put.WithObservationV1(func(observed StoredObject, succeeded bool) error {
		if succeeded || observed.SHA256 != digest || observed.VersionID != "version-1" {
			return errors.New("positive failed observation changed")
		}
		version = strings.Clone(observed.VersionID)
		copied := *put
		copied.CloseConsumerV1()
		if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes == 0 {
			return errors.New("checkpoint borrower lost its output owner")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("observation last use did not release its owner", got)
	}
	if err := put.WithObservationV1(func(StoredObject, bool) error { return nil }); err == nil {
		t.Fatal("retired observation was reusable")
	}
	peer.mu.Lock()
	peer.denyRetention = false
	beforeLatest := peer.latestHeads
	peer.mu.Unlock()
	resumed, err := client.PutEvidenceVersionedLocalPinnedOwnedV1(ctx, "report.pdf", version, "application/pdf", body, until, coordinator, org)
	if resumed != nil {
		defer resumed.CloseConsumerV1()
	}
	if err != nil || resumed == nil {
		t.Fatal("exact positive version could not resume", err)
	}
	if err = resumed.WithStoredV1(func(stored StoredObject) error {
		if stored.VersionID != version || stored.SHA256 != digest {
			return errors.New("pinned retry substituted another version")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	peer.mu.Lock()
	puts, latest, peerErr := peer.puts, peer.latestHeads, peer.failure
	peer.mu.Unlock()
	if puts != 1 || latest != beforeLatest || peerErr != nil {
		t.Fatal("pinned resume used latest or wrote another version", puts, latest, beforeLatest, peerErr)
	}
}

func TestEvidenceLocalPinnedResumeNeverReplacesMissingVersionV1(t *testing.T) {
	ctx, client, peer, coordinator, org := evidenceLocalTestClientV1(t)
	body := []byte("original evidence bytes")
	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	put, err := client.PutEvidenceVersionedLocalOwnedV1(ctx, "missing.pdf", "application/pdf", body, until, coordinator, org)
	if put != nil {
		defer put.CloseConsumerV1()
	}
	if err != nil || put == nil {
		t.Fatal(err)
	}
	var version string
	if err = put.WithStoredV1(func(stored StoredObject) error { version = strings.Clone(stored.VersionID); return nil }); err != nil {
		t.Fatal(err)
	}
	put.CloseConsumerV1()
	peer.mu.Lock()
	delete(peer.objects, "/native-evidence/missing.pdf")
	beforeLatest := peer.latestHeads
	peer.mu.Unlock()
	resumed, err := client.PutEvidenceVersionedLocalPinnedOwnedV1(ctx, "missing.pdf", version, "application/pdf", body, until, coordinator, org)
	if resumed != nil {
		defer resumed.CloseConsumerV1()
	}
	if err == nil || resumed == nil {
		t.Fatal("missing exact version became successful evidence", err)
	}
	if err = resumed.WithStoredV1(func(StoredObject) error { return nil }); err == nil {
		t.Fatal("failed pinned read produced success")
	}
	resumed.CloseConsumerV1()
	peer.mu.Lock()
	puts, latest, remaining := peer.puts, peer.latestHeads, len(peer.objects)
	peer.mu.Unlock()
	if puts != 1 || latest != beforeLatest || remaining != 0 {
		t.Fatal("missing pinned version fell back to latest or replacement", puts, latest, remaining)
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) {
		t.Fatal("failed pinned resume retained local debt", got)
	}
}
