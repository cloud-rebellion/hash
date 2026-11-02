// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTemplatePDFReadV1ActualTLSExactVersionAndOneShotBody(t *testing.T) {
	for _, kind := range []string{"ordinary", "opaque whitespace key", "consumer error"} {
		t.Run(kind, func(t *testing.T) {
			ctx, client, peer, coordinator, org, _ := packageReadFixture246(t, "")
			if kind == "opaque whitespace key" {
				peer.key = " main.pdf "
			}
			expected := sha256.Sum256(peer.body)
			h, denial, err := client.ReadTemplatePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], coordinator, org)
			if h != nil {
				defer h.CloseConsumerV1()
			}
			if err != nil || h == nil || denial.CapacityV1() {
				t.Fatal("exact real SDK read refused", err)
			}
			if h.RetiredV1() {
				t.Fatal("open byte owner retired")
			}
			funded := coordinator.SnapshotV1(org)
			if funded.Global.ProviderStreams != 0 || funded.Global.ParentBytes < int64(len(peer.body)) || funded.GlobalGrants != 1 {
				t.Fatal("body delivered before IO join or without funding", funded)
			}
			sentinel := errors.New("actual consumer refused")
			called := false
			err = h.WithPDFV1(func(body []byte) error {
				called = true
				if !bytes.Equal(body, peer.body) {
					return errors.New("returned body differs from exact original")
				}
				if kind == "consumer error" {
					return sentinel
				}
				return nil
			})
			if !called || (kind == "consumer error" && !errors.Is(err, sentinel)) || (kind != "consumer error" && err != nil) {
				t.Fatal("body borrower outcome lost", err)
			}
			copied := *h
			if err := copied.WithPDFV1(func([]byte) error { t.Error("copied body delivered twice"); return nil }); err == nil {
				t.Fatal("copied handle replayed body")
			}
			peer.mu.Lock()
			heads, gets, reads, puts, peerErr := peer.heads, peer.gets, peer.retentionReads, peer.putAttempts, peer.failure
			peer.mu.Unlock()
			if peerErr != nil || heads != 2 || gets != 1 || reads != 0 || puts != 0 {
				t.Fatal("unexpected provider protocol", heads, gets, reads, puts, peerErr)
			}
			copied.CloseConsumerV1()
			if !h.RetiredV1() || !copied.RetiredV1() || h.state.body != nil {
				t.Fatal("closed exact byte owner did not retire and clear")
			}
			packageRetentionDrain240(t, coordinator, org)
		})
	}
}

func TestTemplatePDFReadV1RejectsWrongVersionSizeDigestAndIncompleteBody(t *testing.T) {
	for _, kind := range []string{"wrong digest", "wrong HEAD version", "wrong GET version", "wrong GET size", "short GET body", "unknown GET size"} {
		t.Run(kind, func(t *testing.T) {
			variant := ""
			if strings.Contains(kind, "GET") {
				variant = kind
			}
			ctx, client, peer, coordinator, org, _ := packageReadFixture246(t, variant)
			expected := sha256.Sum256(peer.body)
			switch kind {
			case "wrong digest":
				expected[0] ^= 1
			case "wrong HEAD version":
				peer.wrongVersion = true
			}
			h, denial, err := client.ReadTemplatePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], coordinator, org)
			if h != nil {
				defer h.CloseConsumerV1()
			}
			if err == nil || h == nil || denial.CapacityV1() {
				t.Fatal("invalid provider evidence became a body", err)
			}
			called := false
			if err := h.WithPDFV1(func([]byte) error { called = true; return nil }); err == nil || called {
				t.Fatal("failed body was lent")
			}
			peer.mu.Lock()
			gets, reads, puts, peerErr := peer.gets, peer.retentionReads, peer.putAttempts, peer.failure
			peer.mu.Unlock()
			if peerErr != nil || reads != 0 || puts != 0 {
				t.Fatal("read mutated retention or protocol failed", reads, puts, peerErr)
			}
			if strings.Contains(kind, "HEAD") && gets != 0 {
				t.Fatal("HEAD mismatch still fetched body")
			}
			h.CloseConsumerV1()
			if !h.RetiredV1() {
				t.Fatal("joined failed body owner did not retire")
			}
			packageRetentionDrain240(t, coordinator, org)
		})
	}
}

func TestTemplatePDFReadV1CancellationJoinsActualHeldTLSBody(t *testing.T) {
	parent, client, peer, coordinator, org, _ := packageReadFixture246(t, "")
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	entered, serverDone, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	peer.blockGET, peer.entered, peer.getDone, peer.release = true, entered, serverDone, release
	expected := sha256.Sum256(peer.body)
	type result struct {
		h   *PackagePDFLocalReadV1
		err error
	}
	finished, joined := make(chan result, 1), make(chan struct{})
	var out result
	defer func() {
		cancel()
		unblock()
		if out.h != nil {
			out.h.CloseConsumerV1()
		}
		wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case <-joined:
			select {
			case late := <-finished:
				if late.h != nil {
					late.h.CloseConsumerV1()
				}
			default:
			}
		case <-wait.Done():
			t.Error("canceled real reader did not join")
		}
	}()
	go func() {
		defer close(joined)
		h, _, err := client.ReadTemplatePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], coordinator, org)
		finished <- result{h, err}
	}()
	select {
	case <-entered:
	case <-parent.Done():
		t.Fatal(parent.Err())
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 1 || got.Global.ParentBytes < int64(len(peer.body)) {
		t.Fatal("held actual GET lacks complete funding", got)
	}
	cancel()
	select {
	case out = <-finished:
	case <-parent.Done():
		t.Fatal("actual canceled GET did not return")
	}
	if out.err == nil || out.h == nil || out.h.RetiredV1() {
		t.Fatal("cancellation became success/consumer retirement", out.err)
	}
	if err := out.h.WithPDFV1(func([]byte) error { t.Error("canceled body delivered"); return nil }); err == nil {
		t.Fatal("canceled body lent")
	}
	owner := out.h.state.owner
	out.h.CloseConsumerV1()
	wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	select {
	case <-owner.joined:
	case <-wait.Done():
		t.Fatal("actual canceled IO did not join")
	}
	select {
	case <-serverDone:
	case <-wait.Done():
		t.Fatal("actual TLS handler did not join")
	}
	if !out.h.RetiredV1() {
		t.Fatal("actual IO join did not retire closed reader")
	}
	packageRetentionDrain240(t, coordinator, org)
}

func TestTemplatePDFReadV1CopiedCloseRetainsActualBlockedWriterFunding(t *testing.T) {
	ctx, client, peer, coordinator, org, _ := packageReadFixture246(t, "")
	expected := sha256.Sum256(peer.body)
	h, _, err := client.ReadTemplatePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], coordinator, org)
	if h != nil {
		defer h.CloseConsumerV1()
	}
	if err != nil || h == nil {
		t.Fatal(err)
	}
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer func() {
		h.CloseConsumerV1()
		unblock()
		wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case <-joined:
		case <-wait.Done():
			t.Error("actual writer cleanup did not join")
		}
	}()
	writer := packageReadWriter246(func(body []byte) (int, error) {
		if !bytes.Equal(body, peer.body) {
			return 0, errors.New("actual writer received altered bytes")
		}
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		if !bytes.Equal(body, peer.body) {
			return 0, errors.New("copied close cleared active writer bytes")
		}
		return len(body), nil
	})
	go func() {
		defer close(joined)
		finished <- h.WithPDFV1(func(body []byte) error { _, err := io.Copy(writer, bytes.NewReader(body)); return err })
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	funded := coordinator.SnapshotV1(org)
	copied := *h
	copied.CloseConsumerV1()
	h.CloseConsumerV1()
	if h.RetiredV1() || copied.RetiredV1() || h.state.owner == nil || coordinator.SnapshotV1(org) != funded || funded.Global.ProviderStreams != 0 || funded.Global.ParentBytes < int64(len(peer.body)) {
		t.Fatal("actual blocked writer debt was refunded", funded)
	}
	unblock()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("actual writer did not join")
	}
	if !h.RetiredV1() || !copied.RetiredV1() {
		t.Fatal("joined writer did not retire shared body")
	}
	packageRetentionDrain240(t, coordinator, org)
}
func TestTemplatePDFReadV1ActualBodyCeilingAndProviderAdmissionPrecedeIO(t *testing.T) {
	ctx, client, peer, coordinator, org, _ := packageReadFixture246(t, "")
	digest := sha256.Sum256(peer.body)
	held, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	before := coordinator.SnapshotV1(org)
	h, denial, err := client.ReadTemplatePDFLocalOwnedV1(ctx, peer.key, peer.version, digest[:], coordinator, org)
	if h != nil || !errors.Is(err, workguard.ErrUnavailableV1) || !denial.CapacityV1() || coordinator.SnapshotV1(org) != before {
		t.Fatal("provider denial minted a body or leaked Parent", err)
	}
	held.Close()
	cap := workguard.VectorV1{ParentBytes: (50 << 20) - 1, ProviderStreams: 1}
	tight, err := workguard.NewV1(workguard.LimitsV1{Global: cap, Organisation: cap, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	h, denial, err = client.ReadTemplatePDFLocalOwnedV1(ctx, peer.key, peer.version, digest[:], tight, org)
	if h != nil || !errors.Is(err, workguard.ErrUnavailableV1) || !denial.CapacityV1() {
		t.Fatal("fixed real body funding not required before provider", err)
	}
	peer.mu.Lock()
	calls := peer.heads + peer.gets
	peer.mu.Unlock()
	if calls != 0 {
		t.Fatal("admission refusal dispatched provider IO", calls)
	}
	packageRetentionDrain240(t, coordinator, org)
	packageRetentionDrain240(t, tight, org)
}
func TestTemplatePDFReadV1TwoConcurrentHTTPConsumersOwnIndependentParent(t *testing.T) {
	ctx, client, peer, c, org, _ := packageReadFixture246(t, "")
	digest := sha256.Sum256(peer.body)
	a, _, err := client.ReadTemplatePDFLocalOwnedV1(ctx, peer.key, peer.version, digest[:], c, org)
	if err != nil {
		t.Fatal(err)
	}
	defer a.CloseConsumerV1()
	b, _, err := client.ReadTemplatePDFLocalOwnedV1(ctx, peer.key, peer.version, digest[:], c, org)
	if err != nil {
		t.Fatal(err)
	}
	defer b.CloseConsumerV1()
	funded := c.SnapshotV1(org)
	if funded.Global.ParentBytes < 2*maxPinnedPDFReadBytesV1 || funded.GlobalGrants != 2 {
		t.Fatal("two real reads share or omit their body funding", funded)
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	finished := make(chan error, 2)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	for _, h := range []*PackagePDFLocalReadV1{a, b} {
		go func(h *PackagePDFLocalReadV1) {
			finished <- h.WithPDFV1(func(body []byte) error {
				entered <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				if !bytes.Equal(body, peer.body) {
					return errors.New("active body cleared")
				}
				return nil
			})
		}(h)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	a.CloseConsumerV1()
	b.CloseConsumerV1()
	if a.RetiredV1() || b.RetiredV1() || c.SnapshotV1(org) != funded {
		t.Fatal("close credited active HTTP consumers")
	}
	unblock()
	for i := 0; i < 2; i++ {
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if !a.RetiredV1() || !b.RetiredV1() {
		t.Fatal("joined consumers did not retire")
	}
	packageRetentionDrain240(t, c, org)
}

// These negative ownership cases use genuine native grants plus a real physical
// close barrier. They do not create a positive native storage/source witness.
func TestTemplatePDFReadV1FailedCleanupNeverMintsProviderCredit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	v := workguard.VectorV1{ParentBytes: 2 << 20, ProviderStreams: 1}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 1 << 20})
	provider, _ := c.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	// A failed/unjoined owner has no actual IO retirement evidence. A close call
	// and canceled context must not turn it into free capacity.
	owner := &evidenceLocalPutStateV1{ctx: ctx, grant: parent, provider: provider, joined: make(chan struct{}), changed: make(chan struct{})}
	owner.self = owner
	state := &packagePDFLocalReadStateV1{owner: owner, ctx: ctx}
	state.self = state
	h := &PackagePDFLocalReadV1{state: state}
	h.CloseConsumerV1()
	cancel()
	if h.RetiredV1() || c.SnapshotV1(org).Global.ProviderStreams != 1 {
		t.Fatal("failed cleanup minted provider credit")
	}
	// Test-only cleanup of synthetic grants; no positive IO retirement is asserted.
	parent.Close()
	provider.Close()
}
