// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/workguard"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEvidenceLocalStreamedVerificationV1ActualLargeObjectAndIndependentAcknowledgement(t *testing.T) {
	ctx, client, peer, putCoordinator, org := evidenceLocalTestClientV1(t)
	// The genuine public constructor/TLS/SDK stores an object larger than the
	// later complete24MiB logical local lane. Verification returns no full body.
	body := bytes.Repeat([]byte("actual complete evidence hash\n"), (17<<20)/29)
	digest := sha256.Sum256(body)
	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	put, err := client.PutEvidenceVersionedLocalOwnedV1(ctx, "streamed.pdf", "application/pdf", body, until, putCoordinator, org)
	if put != nil {
		defer put.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if err = put.WithStoredV1(func(value StoredObject) error { version = strings.Clone(value.VersionID); return nil }); err != nil {
		t.Fatal(err)
	}
	put.CloseConsumerV1()
	limits := workguard.VectorV1{ParentBytes: 24 << 20, ProviderStreams: 1}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	peer.mu.Lock()
	beforeGets := peer.gets
	peer.mu.Unlock()
	verified, denial, err := client.VerifyFinalizationEvidenceLocalOwnedV1(ctx, "streamed.pdf", version, digest[:], coordinator, org)
	if verified != nil {
		defer verified.CloseConsumerV1()
	}
	if err != nil || denial.CapacityV1() {
		t.Fatal("real bounded complete stream refused", denial.SnapshotV1(), err)
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.Global.ParentBytes >= limits.ParentBytes || got.GlobalGrants != 1 {
		t.Fatal("real IO not joined or independent acknowledgement lost", got)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	go func() { done <- verified.WithVerifiedV1(func() error { close(entered); <-release; return nil }) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	copied := *verified
	copied.CloseConsumerV1()
	verified.CloseConsumerV1()
	retained, denial, err := client.RetainFinalizationEvidenceLocalOwnedV1(ctx, "streamed.pdf", version, digest[:], until, coordinator, org)
	if retained != nil {
		defer retained.CloseConsumerV1()
	}
	if err != nil || denial.CapacityV1() {
		unblock()
		<-done
		t.Fatal("joined provider did not permit actual next retention lane", err)
	}
	if err = retained.WithRetainedV1(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	retained.CloseConsumerV1()
	peer.mu.Lock()
	afterGets, peerErr, puts, parts := peer.gets, peer.failure, peer.puts, peer.multipart
	peer.mu.Unlock()
	if afterGets != beforeGets+2 || peerErr != nil || puts != 1 || parts {
		t.Fatal("exact complete GET/retention policy changed", beforeGets, afterGets, peerErr, puts, parts)
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		t.Fatal("copied Close credited active acknowledgement Parent", got)
	}
	unblock()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("actual stream/result last use did not drain", got)
	}
}

func TestEvidenceLocalStreamedVerificationV1ClonesDigestBeforeActualBlockedGET(t *testing.T) {
	ctx, client, peer, coordinator, org := evidenceLocalTestClientV1(t)
	expected := sha256.Sum256([]byte("OK"))
	original := expected
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	peer.mu.Lock()
	peer.objects["/native-evidence/ordinary-verification.pdf"] = evidenceLocalPeerObjectV1{body: []byte("OK"), version: "ordinary-version", until: time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}
	peer.ordinaryEntered = entered
	peer.ordinaryRelease = release
	peer.mu.Unlock()
	type result struct {
		owned  *EvidenceLocalVerificationV1
		denial workguard.AdmissionDenialV1
		err    error
	}
	done := make(chan result, 1)
	go func() {
		h, d, e := client.VerifyFinalizationEvidenceLocalOwnedV1(ctx, "ordinary-verification.pdf", "ordinary-version", expected[:], coordinator, org)
		done <- result{h, d, e}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	clear(expected[:])
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 1 || got.Global.ParentBytes <= 0 {
		t.Fatal("actual outstanding HTTP body lost private ownership", got)
	}
	unblock()
	var got result
	select {
	case got = <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got.owned != nil {
		defer got.owned.CloseConsumerV1()
	}
	if got.err != nil || got.owned == nil || got.denial.CapacityV1() {
		t.Fatal("source digest alias escaped before actual GET", got.err)
	}
	if !bytes.Equal(got.owned.state.data, original[:]) {
		t.Fatal("independent digest changed after native source clear")
	}
	if err := got.owned.WithVerifiedV1(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	got.owned.CloseConsumerV1()
	if used := coordinator.SnapshotV1(org); used.Global != (workguard.VectorV1{}) {
		t.Fatal("joined source/IO consumer retained debt", used)
	}
}

func TestEvidenceLocalStreamedVerificationV1ExactAdmissionDenialAndOriginalErrors(t *testing.T) {
	ctx, client, peer, coordinator, org := evidenceLocalTestClientV1(t)
	payload := []byte("complete bounded source")
	digest := sha256.Sum256(payload)
	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	put, err := client.PutEvidenceVersionedLocalOwnedV1(ctx, "error-stream.pdf", "application/pdf", payload, until, coordinator, org)
	if put != nil {
		defer put.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if err = put.WithStoredV1(func(value StoredObject) error { version = strings.Clone(value.VersionID); return nil }); err != nil {
		t.Fatal(err)
	}
	put.CloseConsumerV1()
	held, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	baseline := coordinator.SnapshotV1(org)
	peer.mu.Lock()
	before := peer.heads + peer.gets + peer.puts
	peer.mu.Unlock()
	result, denial, err := client.VerifyFinalizationEvidenceLocalOwnedV1(ctx, "error-stream.pdf", version, digest[:], coordinator, org)
	if result != nil {
		result.CloseConsumerV1()
	}
	observation := denial.SnapshotV1()
	if result != nil || !errors.Is(err, workguard.ErrUnavailableV1) || !denial.CapacityV1() || observation.Dimension != workguard.AdmissionProviderStreamsV1 || observation.Requested != (workguard.VectorV1{ProviderStreams: 1}) || observation.Before.Global.ParentBytes <= baseline.Global.ParentBytes || observation.Before.GlobalGrants != baseline.GlobalGrants+1 {
		t.Fatal("actual independent Provider refusal snapshot changed", observation, err)
	}
	if after := coordinator.SnapshotV1(org); after != baseline {
		t.Fatal("pre-dispatch private Parent did not close", after, baseline)
	}
	changed := observation
	changed.Requested.ProviderStreams = 99
	if changed == observation || denial.SnapshotV1() != observation {
		t.Fatal("denial retained a mutable observation alias")
	}
	peer.mu.Lock()
	after := peer.heads + peer.gets + peer.puts
	peer.mu.Unlock()
	if after != before {
		t.Fatal("actual capacity refusal dispatched provider IO")
	}
	held.Close()
	tinyLimits := workguard.VectorV1{ParentBytes: 1, ProviderStreams: 1}
	tiny, err := workguard.NewV1(workguard.LimitsV1{Global: tinyLimits, Organisation: tinyLimits, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	result, denial, err = client.VerifyFinalizationEvidenceLocalOwnedV1(ctx, "error-stream.pdf", version, digest[:], tiny, org)
	if result != nil {
		result.CloseConsumerV1()
	}
	if result != nil || !errors.Is(err, workguard.ErrUnavailableV1) || !denial.CapacityV1() || denial.SnapshotV1().Dimension != workguard.AdmissionParentBytesV1 || tiny.SnapshotV1(org).Global != (workguard.VectorV1{}) {
		t.Fatal("first Parent refusal created an owner or false observation", denial.SnapshotV1(), err)
	}
	wrong := digest
	wrong[31] ^= 1
	_, originalErr := client.GetVerifiedVersionForSendV1(ctx, "error-stream.pdf", version, wrong[:])
	result, denial, err = client.VerifyFinalizationEvidenceLocalOwnedV1(ctx, "error-stream.pdf", version, wrong[:], coordinator, org)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if originalErr == nil || err == nil || originalErr.Error() != err.Error() || result == nil || denial.CapacityV1() {
		t.Fatal("complete digest failure identity/text changed", originalErr, err)
	}
	localFailure := err
	if err = result.WithVerifiedV1(func() error { return nil }); err == nil {
		t.Fatal("failed original hash represented as verified")
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		t.Fatal("original failure error consumer lost Parent or IO retained", got)
	}
	_ = fmt.Sprintf("%v", localFailure)
	result.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) {
		t.Fatal("original error last use did not drain", got)
	}
}
