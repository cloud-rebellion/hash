// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

// Actual constructor/TLS/SigV4/HEAD/GET, with finite hostile GET variants. This
// is a protocol peer, not a replacement native transport or positive receipt.
func packageReadFixture246(t *testing.T, variant string) (context.Context, *Client, *packageRetentionPeer240, *workguard.CoordinatorV1, uuid.UUID, Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	p := &packageRetentionPeer240{body: []byte("%PDF-1.7\nexact package read fixture\n%%EOF\n"), key: "main.pdf", version: "package+version/=01", mode: minio.Compliance, until: time.Now().UTC().Add(time.Hour).Truncate(time.Second)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if variant == "" || r.Method != http.MethodGet || r.URL.Path != "/package-evidence/"+p.key {
			p.serve240(w, r)
			return
		}
		if r.URL.Query().Get("versionId") != p.version || r.URL.Query().Has("retention") || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			p.reject240(w, "unexpected exact GET protocol")
			return
		}
		p.mu.Lock()
		p.gets++
		body := append([]byte(nil), p.body...)
		version := p.version
		p.mu.Unlock()
		if variant == "wrong GET version" {
			version = "substituted-version"
		}
		w.Header().Set("X-Amz-Version-Id", version)
		w.Header().Set("ETag", "\"package-exact-etag\"")
		w.Header().Set("Last-Modified", "Thu, 15 Oct 2026 12:00:00 GMT")
		w.Header().Set("Content-Type", "application/pdf")
		size := len(body)
		if variant == "wrong GET size" {
			size++
		}
		if variant != "unknown GET size" {
			w.Header().Set("Content-Length", strconv.Itoa(size))
		}
		if variant == "short GET body" {
			body = body[:len(body)-1]
		}
		if variant == "unknown GET size" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	cert := filepath.Join(t.TempDir(), "package-read-peer.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", cert)
	cfg := Config{Endpoint: strings.TrimPrefix(server.URL, "https://"), Region: "us-east-1", Bucket: "package-evidence", AccessKey: "synthetic-package-read-key", SecretKey: "synthetic-package-read-secret", UseSSL: true, BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, SkipTransientLifecycle: true}
	client, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	limits := workguard.VectorV1{ParentBytes: 192 << 20, ProviderStreams: 1}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, client, p, coordinator, uuid.New(), cfg
}

func TestPackagePDFReadV1ActualTLSExactVersionAndOneShotBody(t *testing.T) {
	for _, kind := range []string{"ordinary", "opaque whitespace key", "consumer error"} {
		t.Run(kind, func(t *testing.T) {
			ctx, client, peer, coordinator, org, _ := packageReadFixture246(t, "")
			if kind == "opaque whitespace key" {
				peer.key = " main.pdf "
			}
			expected := sha256.Sum256(peer.body)
			h, denial, err := client.ReadPackagePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], int64(len(peer.body)), coordinator, org)
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
			if peerErr != nil || heads != 1 || gets != 1 || reads != 0 || puts != 0 {
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

func TestPackagePDFReadV1RejectsWrongVersionSizeDigestAndIncompleteBody(t *testing.T) {
	for _, kind := range []string{"wrong digest", "wrong HEAD size", "wrong HEAD version", "wrong GET version", "wrong GET size", "short GET body", "unknown GET size"} {
		t.Run(kind, func(t *testing.T) {
			variant := ""
			if strings.Contains(kind, "GET") {
				variant = kind
			}
			ctx, client, peer, coordinator, org, _ := packageReadFixture246(t, variant)
			expected := sha256.Sum256(peer.body)
			size := int64(len(peer.body))
			switch kind {
			case "wrong digest":
				expected[0] ^= 1
			case "wrong HEAD size":
				size++
			case "wrong HEAD version":
				peer.wrongVersion = true
			}
			h, denial, err := client.ReadPackagePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], size, coordinator, org)
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

func TestPackagePDFReadV1InvalidInputsAndAdmissionRefuseBeforeObjectIO(t *testing.T) {
	ctx, client, peer, coordinator, org, cfg := packageReadFixture246(t, "")
	expected := sha256.Sum256(peer.body)
	copiedClient := *client
	devCfg := cfg
	devCfg.RequireObjectLock = false
	dev, err := New(ctx, devCfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"nil client", "copied client", "development client", "blank key", "null version", "development version", "short digest", "zero size", "over size"} {
		t.Run(kind, func(t *testing.T) {
			c, key, version, digest, size := client, peer.key, peer.version, expected[:], int64(len(peer.body))
			switch kind {
			case "nil client":
				c = nil
			case "copied client":
				c = &copiedClient
			case "development client":
				c = dev
			case "blank key":
				key = "   "
			case "null version":
				version = "null"
			case "development version":
				version = DevelopmentVersionID
			case "short digest":
				digest = digest[:31]
			case "zero size":
				size = 0
			case "over size":
				size = maxPinnedPDFReadBytesV1 + 1
			}
			h, _, err := c.ReadPackagePDFLocalOwnedV1(ctx, key, version, digest, size, coordinator, org)
			if h != nil {
				h.CloseConsumerV1()
			}
			if h != nil || !errors.Is(err, ErrPackagePDFLocalReadV1) {
				t.Fatal("invalid input allocated a byte owner", err)
			}
			packageRetentionDrain240(t, coordinator, org)
		})
	}
	held, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	before := coordinator.SnapshotV1(org)
	h, denial, err := client.ReadPackagePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], int64(len(peer.body)), coordinator, org)
	if h != nil {
		h.CloseConsumerV1()
	}
	if h != nil || !errors.Is(err, workguard.ErrUnavailableV1) || !denial.CapacityV1() || denial.SnapshotV1().Dimension != workguard.AdmissionProviderStreamsV1 || coordinator.SnapshotV1(org) != before {
		t.Fatal("Provider denial changed ownership", err)
	}
	held.Close()
	limits := workguard.VectorV1{ParentBytes: 32 << 20, ProviderStreams: 1}
	tight, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	h, denial, err = client.ReadPackagePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], maxPinnedPDFReadBytesV1, tight, org)
	if h != nil {
		h.CloseConsumerV1()
	}
	if h != nil || !errors.Is(err, workguard.ErrUnavailableV1) || !denial.CapacityV1() || denial.SnapshotV1().Dimension != workguard.AdmissionParentBytesV1 {
		t.Fatal("whole body was not prepaid before IO", err)
	}
	peer.mu.Lock()
	calls := peer.heads + peer.gets + peer.retentionReads + peer.putAttempts
	peer.mu.Unlock()
	if calls != 0 {
		t.Fatal("invalid/denied read dispatched object IO", calls)
	}
	packageRetentionDrain240(t, coordinator, org)
	packageRetentionDrain240(t, tight, org)
}

type packageReadWriter246 func([]byte) (int, error)

func (w packageReadWriter246) Write(body []byte) (int, error) { return w(body) }

func TestPackagePDFReadV1CopiedCloseRetainsActualBlockedWriterFunding(t *testing.T) {
	ctx, client, peer, coordinator, org, _ := packageReadFixture246(t, "")
	expected := sha256.Sum256(peer.body)
	h, _, err := client.ReadPackagePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], int64(len(peer.body)), coordinator, org)
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

func TestPackagePDFReadV1CancellationJoinsActualHeldTLSBody(t *testing.T) {
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
		h, _, err := client.ReadPackagePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], int64(len(peer.body)), coordinator, org)
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

func TestPackagePDFReadV1FreshNamespaceAndContextBeforeBodyBorrow(t *testing.T) {
	for _, kind := range []string{"namespace changed", "context canceled"} {
		t.Run(kind, func(t *testing.T) {
			parent, client, peer, coordinator, org, _ := packageReadFixture246(t, "")
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			expected := sha256.Sum256(peer.body)
			h, _, err := client.ReadPackagePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], int64(len(peer.body)), coordinator, org)
			if h != nil {
				defer h.CloseConsumerV1()
			}
			if err != nil || h == nil {
				t.Fatal(err)
			}
			if kind == "namespace changed" {
				client.bucket += "-changed"
			} else {
				cancel()
			}
			if err := h.WithPDFV1(func([]byte) error { t.Error("stale constructor/context body delivered"); return nil }); err == nil {
				t.Fatal("stale body borrowed")
			}
			if got := coordinator.SnapshotV1(org); got.Global.ParentBytes < int64(len(peer.body)) {
				t.Fatal("failed fresh check credited retained body", got)
			}
			h.CloseConsumerV1()
			if !h.RetiredV1() {
				t.Fatal("failed fresh-check reader did not retire")
			}
			packageRetentionDrain240(t, coordinator, org)
		})
	}
}

func TestPackagePDFReadV1RetirementWaitsForActualConnClose(t *testing.T) {
	// Predicate-only negative fixture with a real net.Pipe/Close-return barrier.
	// No constructor, verified PDF body or positive application receipt is minted.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	limits := workguard.VectorV1{ParentBytes: 2 << 20, ProviderStreams: 1}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Close()
	provider, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	left, right := net.Pipe()
	defer right.Close()
	barrier := &evidenceLocalCloseBarrierConnV1{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(barrier.release) }) }
	owner := &evidenceLocalPutStateV1{ctx: ctx, grant: grant, provider: provider, transport: storageHTTPTransportBaseV1(false), connections: make(map[*evidenceLocalConnV1]struct{}), bodies: make(map[*evidenceLocalResponseBodyV1]struct{}), changed: make(chan struct{}), joined: make(chan struct{}), closing: true}
	owner.self = owner
	conn := &evidenceLocalConnV1{owner: owner, inner: barrier, done: make(chan struct{}), scratch: make([]byte, 64<<10)}
	owner.connections[conn] = struct{}{}
	state := &packagePDFLocalReadStateV1{owner: owner}
	state.self = state
	h := &PackagePDFLocalReadV1{state: state}
	copied := *h
	defer func() {
		h.CloseConsumerV1()
		cancel()
		unblock()
		wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case <-owner.joined:
		case <-wait.Done():
			t.Error("actual close barrier cleanup did not join")
			return
		}
		if !h.RetiredV1() || !copied.RetiredV1() {
			t.Error("actual joined close did not retire shared reader")
		}
		packageRetentionDrain240(t, coordinator, org)
	}()
	go owner.closeIOV1()
	select {
	case <-barrier.entered:
	case <-ctx.Done():
		t.Fatal("real Close did not enter")
	}
	copied.CloseConsumerV1()
	cancel()
	if h.RetiredV1() || copied.RetiredV1() || state.owner != owner {
		t.Fatal("canceled/copied close retired unjoined owner")
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 1 || got.Global.ParentBytes <= 0 {
		t.Fatal("actual pending Close debt was refunded", got)
	}
	unblock()
	wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	select {
	case <-owner.joined:
	case <-wait.Done():
		t.Fatal("actual Close did not join")
	}
	if !h.RetiredV1() || !copied.RetiredV1() || state.owner != nil {
		t.Fatal("actual joined close did not retire reader")
	}
	packageRetentionDrain240(t, coordinator, org)
}
