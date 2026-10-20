// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"encoding/xml"
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

// The real constructor, TLS, SigV4 SDK and HTTP bodies run against a finite
// local protocol peer. These tests make no remote Object Lock conformance claim.
type packageRetentionPeer240 struct {
	mu                                                                                         sync.Mutex
	body                                                                                       []byte
	key                                                                                        string
	version                                                                                    string
	mode                                                                                       minio.RetentionMode
	until                                                                                      time.Time
	heads, gets, retentionReads, putAttempts, applied                                          int
	failure                                                                                    error
	loseResponse, lost, denyPut, denyRetentionRead, badReadback, corruptAfterPut, wrongVersion bool
	blockGET                                                                                   bool
	entered                                                                                    chan struct{}
	getDone                                                                                    chan struct{}
	release                                                                                    <-chan struct{}
	enteredOnce, doneOnce                                                                      sync.Once
}

func (p *packageRetentionPeer240) reject240(w http.ResponseWriter, message string) {
	p.mu.Lock()
	if p.failure == nil {
		p.failure = errors.New(message)
	}
	p.mu.Unlock()
	http.Error(w, message, http.StatusBadRequest)
}

func (p *packageRetentionPeer240) serve240(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	if !strings.Contains(path, "/") {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Has("versioning"):
			_, _ = io.WriteString(w, "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
		case r.Method == http.MethodGet && r.URL.Query().Has("object-lock"):
			_, _ = io.WriteString(w, "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>")
		default:
			p.reject240(w, "unexpected bucket protocol")
		}
		return
	}
	p.mu.Lock()
	key, version := p.key, p.version
	p.mu.Unlock()
	if r.URL.Path != "/package-evidence/"+key || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		p.reject240(w, "unexpected object or missing original authentication")
		return
	}
	if r.URL.Query().Get("versionId") != version || r.URL.Query().Has("versions") || r.URL.Query().Has("list-type") {
		p.reject240(w, "latest/listing or substituted exact version")
		return
	}
	if r.URL.Query().Has("retention") {
		if r.Method == http.MethodGet {
			p.mu.Lock()
			p.retentionReads++
			mode, until := p.mode, p.until
			denied := p.denyRetentionRead
			bad := p.badReadback && p.applied > 0
			p.mu.Unlock()
			if denied {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>initial retention observation refused</Message></Error>")
				return
			}
			if bad {
				mode = minio.Governance
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, "<Retention><Mode>"+string(mode)+"</Mode><RetainUntilDate>"+until.UTC().Format(time.RFC3339Nano)+"</RetainUntilDate></Retention>")
			return
		}
		if r.Method != http.MethodPut {
			p.reject240(w, "unexpected retention method")
			return
		}
		var requested struct {
			Mode  string    `xml:"Mode"`
			Until time.Time `xml:"RetainUntilDate"`
		}
		if err := xml.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&requested); err != nil || requested.Mode != "COMPLIANCE" || r.Header.Get("X-Amz-Bypass-Governance-Retention") != "" {
			p.reject240(w, "invalid compliance request or governance bypass")
			return
		}
		p.mu.Lock()
		p.putAttempts++
		if p.denyPut || (p.loseResponse && p.lost) {
			p.mu.Unlock()
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>finite retention response refused</Message></Error>")
			return
		}
		if requested.Until.Before(p.until) {
			p.mu.Unlock()
			p.reject240(w, "existing provider deadline was shortened")
			return
		}
		p.applied++
		p.mode = minio.Compliance
		p.until = requested.Until.UTC()
		if p.corruptAfterPut {
			p.body[0] ^= 1
		}
		lose := p.loseResponse
		if lose {
			p.lost = true
		}
		p.mu.Unlock()
		if lose {
			// Apply the real request, then close its actual TLS connection before
			// returning any HTTP response. A later SDK retry receives a refusal;
			// only fresh retention and byte reads can establish this success.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				p.reject240(w, "could not withhold actual retention response")
				return
			}
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		p.reject240(w, "unexpected object mutation")
		return
	}
	p.mu.Lock()
	body := append([]byte(nil), p.body...)
	wrong, block, entered, done, release := p.wrongVersion, p.blockGET, p.entered, p.getDone, p.release
	if r.Method == http.MethodHead {
		p.heads++
	} else {
		p.gets++
	}
	p.mu.Unlock()
	if wrong {
		version = "different-provider-version"
	}
	w.Header().Set("X-Amz-Version-Id", version)
	w.Header().Set("ETag", "\"package-exact-etag\"")
	w.Header().Set("Last-Modified", "Thu, 15 Oct 2026 12:00:00 GMT")
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if block {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		p.enteredOnce.Do(func() { close(entered) })
		defer p.doneOnce.Do(func() { close(done) })
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
	}
	_, _ = w.Write(body)
}

func packageRetentionFixture240(t *testing.T) (context.Context, *Client, *packageRetentionPeer240, *workguard.CoordinatorV1, uuid.UUID, Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	p := &packageRetentionPeer240{body: []byte("%PDF-1.7\nexact package storage fixture\n%%EOF\n"), key: "main.pdf", version: "package+version/=01", mode: minio.Compliance, until: time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)}
	server := httptest.NewTLSServer(http.HandlerFunc(p.serve240))
	t.Cleanup(server.Close)
	cert := filepath.Join(t.TempDir(), "package-peer.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", cert)
	cfg := Config{Endpoint: strings.TrimPrefix(server.URL, "https://"), Region: "us-east-1", Bucket: "package-evidence", AccessKey: "synthetic-package-key", SecretKey: "synthetic-package-secret", UseSSL: true, BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, SkipTransientLifecycle: true}
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

func packageRetentionDrain240(t *testing.T, coordinator *workguard.CoordinatorV1, org uuid.UUID) {
	t.Helper()
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("package receipt retained resources", got)
	}
}

func TestPackagePDFRetentionV1ActualTLSExactVersionAndFreshReadback(t *testing.T) {
	for _, kind := range []string{"extend", "exact whitespace key", "already longer", "applied response lost", "unapplied refusal", "initial retention unreadable", "governance longer", "bad readback", "postwrite bytes changed"} {
		t.Run(kind, func(t *testing.T) {
			ctx, client, peer, coordinator, org, _ := packageRetentionFixture240(t)
			target := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			expected := sha256.Sum256(peer.body)
			want := target
			peer.mu.Lock()
			switch kind {
			case "exact whitespace key":
				peer.key = " main.pdf "
			case "already longer":
				peer.until = target.Add(time.Hour)
				want = peer.until
			case "applied response lost":
				peer.loseResponse = true
			case "unapplied refusal":
				peer.denyPut = true
			case "initial retention unreadable":
				peer.denyRetentionRead = true
			case "governance longer":
				peer.mode = minio.Governance
				peer.until = target.Add(time.Hour)
				want = peer.until
			case "bad readback":
				peer.badReadback = true
			case "postwrite bytes changed":
				peer.corruptAfterPut = true
			}
			peer.mu.Unlock()
			h, denial, err := client.RetainPackagePDFLocalOwnedV1(ctx, peer.key, peer.version, expected[:], int64(len(peer.body)), target, coordinator, org)
			if h != nil {
				defer h.CloseConsumerV1()
				if h.RetiredV1() {
					t.Fatal("open consumer reported retirement")
				}
			}
			failed := kind == "unapplied refusal" || kind == "initial retention unreadable" || kind == "bad readback" || kind == "postwrite bytes changed"
			called := false
			if failed {
				if err == nil || h == nil || denial.CapacityV1() {
					t.Fatal("failed actual retention became success", err)
				}
				if e := h.WithRetainedV1(func(time.Time) error { called = true; return nil }); e == nil || called {
					t.Fatal("failed receipt delivered")
				}
			} else {
				if err != nil || h == nil || denial.CapacityV1() {
					t.Fatal("strict actual retention refused", err)
				}
				namespace, e := client.PackageEvidenceNamespaceV1()
				if e != nil || h.state.namespace != namespace {
					t.Fatal("receipt lost original namespace", e)
				}
				if e = h.WithRetainedV1(func(observed time.Time) error {
					called = true
					if observed != want.UTC() {
						return errors.New("provider deadline replaced by target")
					}
					return nil
				}); e != nil || !called {
					t.Fatal(e)
				}
				copyHandle := *h
				if e = copyHandle.WithRetainedV1(func(time.Time) error { return nil }); e == nil {
					t.Fatal("copied receipt acknowledged twice")
				}
			}
			peer.mu.Lock()
			puts, applied, reads, gets, lost, peerErr := peer.putAttempts, peer.applied, peer.retentionReads, peer.gets, peer.lost, peer.failure
			peer.mu.Unlock()
			if peerErr != nil {
				t.Fatal(peerErr)
			}
			if kind == "already longer" && (puts != 0 || applied != 0 || reads != 1 || gets != 2) {
				t.Fatal("existing longer deadline rewritten or bytes not checked twice", puts, reads, gets)
			}
			if !failed && kind != "already longer" && (puts < 1 || applied != 1 || reads < 2 || gets != 2) {
				t.Fatal("missing exact post-mutation verification", puts, applied, reads, gets)
			}
			if kind == "applied response lost" && !lost {
				t.Fatal("actual applied response was not withheld")
			}
			if kind == "initial retention unreadable" && (puts != 0 || applied != 0 || reads != 1 || gets != 1) {
				t.Fatal("unknown original retention was mutated", puts, applied, reads, gets)
			}
			h.CloseConsumerV1()
			if !h.RetiredV1() {
				t.Fatal("closed actual joined receipt did not retire")
			}
			packageRetentionDrain240(t, coordinator, org)
		})
	}
}

func TestPackagePDFRetentionV1RejectsBytesAndSizesBeforeMutation(t *testing.T) {
	for _, kind := range []string{"wrong bytes", "wrong size", "wrong version echo"} {
		t.Run(kind, func(t *testing.T) {
			ctx, client, peer, coordinator, org, _ := packageRetentionFixture240(t)
			expected := sha256.Sum256(peer.body)
			size := int64(len(peer.body))
			if kind == "wrong bytes" {
				expected[0] ^= 1
			}
			if kind == "wrong size" {
				size++
			}
			if kind == "wrong version echo" {
				peer.wrongVersion = true
			}
			h, denial, err := client.RetainPackagePDFLocalOwnedV1(ctx, "main.pdf", peer.version, expected[:], size, time.Now().UTC().Add(time.Hour).Truncate(time.Second), coordinator, org)
			if h != nil {
				defer h.CloseConsumerV1()
			}
			if err == nil || h == nil || denial.CapacityV1() {
				t.Fatal("bad source was retained", err)
			}
			called := false
			if e := h.WithRetainedV1(func(time.Time) error { called = true; return nil }); e == nil || called {
				t.Fatal("bad source receipt delivered")
			}
			peer.mu.Lock()
			puts, reads := peer.putAttempts, peer.retentionReads
			peer.mu.Unlock()
			if puts != 0 || reads != 0 {
				t.Fatal("source verification did not precede retention", puts, reads)
			}
			h.CloseConsumerV1()
			packageRetentionDrain240(t, coordinator, org)
		})
	}
}

func TestPackagePDFRetentionV1RefusesInvalidProfileAndCommitmentsBeforeIO(t *testing.T) {
	ctx, client, peer, coordinator, org, cfg := packageRetentionFixture240(t)
	expected := sha256.Sum256(peer.body)
	target := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	copied := *client
	devCfg := cfg
	devCfg.RequireObjectLock = false
	dev, err := New(ctx, devCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dev.PackageEvidenceNamespaceV1(); !errors.Is(err, ErrPackagePDFLocalRetentionV1) {
		t.Fatal("non-lock profile passed package namespace preflight", err)
	}
	for _, kind := range []string{"nil client", "copied client", "development profile", "empty key", "blank key", "empty version", "development version", "null version", "short hash", "zero size", "over size", "fractional target", "zero target"} {
		t.Run(kind, func(t *testing.T) {
			c, key, version, digest, size, until := client, "main.pdf", peer.version, expected[:], int64(len(peer.body)), target
			switch kind {
			case "nil client":
				c = nil
			case "copied client":
				c = &copied
			case "development profile":
				c = dev
			case "empty key":
				key = ""
			case "blank key":
				key = "   "
			case "empty version":
				version = ""
			case "development version":
				version = DevelopmentVersionID
			case "null version":
				version = "null"
			case "short hash":
				digest = digest[:31]
			case "zero size":
				size = 0
			case "over size":
				size = maxPinnedPDFReadBytesV1 + 1
			case "fractional target":
				until = until.Add(time.Nanosecond)
			case "zero target":
				until = time.Time{}
			}
			h, _, err := c.RetainPackagePDFLocalOwnedV1(ctx, key, version, digest, size, until, coordinator, org)
			if h != nil {
				h.CloseConsumerV1()
			}
			if h != nil || !errors.Is(err, ErrPackagePDFLocalRetentionV1) {
				t.Fatal("invalid input obtained receipt", kind, err)
			}
			packageRetentionDrain240(t, coordinator, org)
		})
	}
	peer.mu.Lock()
	heads, gets, puts, reads := peer.heads, peer.gets, peer.putAttempts, peer.retentionReads
	peer.mu.Unlock()
	if heads+gets+puts+reads != 0 {
		t.Fatal("invalid package authority dispatched object IO", heads, gets, puts, reads)
	}
}

func TestPackageEvidenceNamespaceV1ConstructorCoordinatesAndTamperRefusal(t *testing.T) {
	ctx, client, _, _, _, cfg := packageRetentionFixture240(t)
	want, err := client.PackageEvidenceNamespaceV1()
	if err != nil || want == ([32]byte{}) {
		t.Fatal(want, err)
	}
	rotated := cfg
	rotated.AccessKey = "different-synthetic-key"
	rotated.SecretKey = "different-synthetic-secret"
	other, err := New(ctx, rotated)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := other.PackageEvidenceNamespaceV1(); err != nil || got != want {
		t.Fatal("namespace included credentials", got, err)
	}
	for _, kind := range []string{"bucket", "region", "lookup"} {
		changed := cfg
		switch kind {
		case "bucket":
			changed.Bucket += "-other"
		case "region":
			changed.Region = "us-west-2"
		case "lookup":
			changed.BucketLookup = "auto"
		}
		other, err := New(ctx, changed)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := other.PackageEvidenceNamespaceV1(); err != nil || got == want {
			t.Fatal("distinct namespace coordinates aliased", kind, err)
		}
	}
	copyClient := *client
	if _, err := copyClient.PackageEvidenceNamespaceV1(); err == nil {
		t.Fatal("copied client obtained constructor namespace")
	}
	originalBucket := client.bucket
	client.bucket += "-tampered"
	if _, err := client.PackageEvidenceNamespaceV1(); err == nil {
		t.Fatal("client bucket tampering accepted")
	}
	client.bucket = originalBucket
	originalLock := client.requireEvidenceLock
	client.requireEvidenceLock = false
	if _, err := client.PackageEvidenceNamespaceV1(); err == nil {
		t.Fatal("constructor lock bit tampering accepted")
	}
	client.requireEvidenceLock = originalLock
	profile := client.localProfile
	originalEndpoint := profile.endpoint
	profile.endpoint += "-tampered"
	if _, err := client.PackageEvidenceNamespaceV1(); err == nil {
		t.Fatal("profile namespace tampering accepted")
	}
	profile.endpoint = originalEndpoint
	if got, err := client.PackageEvidenceNamespaceV1(); err != nil || got != want {
		t.Fatal("unchanged constructor identity lost", err)
	}
}

func TestPackagePDFRetentionV1CopiedCloseRetainsActualCallbackFunding(t *testing.T) {
	ctx, client, peer, coordinator, org, _ := packageRetentionFixture240(t)
	target := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	peer.until = target.Add(time.Hour)
	expected := sha256.Sum256(peer.body)
	h, _, err := client.RetainPackagePDFLocalOwnedV1(ctx, "main.pdf", peer.version, expected[:], int64(len(peer.body)), target, coordinator, org)
	if h != nil {
		defer h.CloseConsumerV1()
	}
	if err != nil || h == nil {
		t.Fatal(err)
	}
	ready, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	joined := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer func() {
		h.CloseConsumerV1()
		unblock()
		wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case <-joined:
			packageRetentionDrain240(t, coordinator, org)
		case <-wait.Done():
			t.Error("receipt callback did not join during cleanup")
		}
	}()
	go func() {
		defer close(joined)
		done <- h.WithRetainedV1(func(time.Time) error {
			close(ready)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	funded := coordinator.SnapshotV1(org)
	if funded.Global.ProviderStreams != 0 || funded.Global.ParentBytes <= 0 || funded.GlobalGrants != 1 {
		t.Fatal("receipt delivered before IO join or lost Parent", funded)
	}
	copyHandle := *h
	if h.RetiredV1() || copyHandle.RetiredV1() {
		t.Fatal("active receipt reported retirement")
	}
	copyHandle.CloseConsumerV1()
	h.CloseConsumerV1()
	if h.RetiredV1() || copyHandle.RetiredV1() || h.state.owner == nil {
		t.Fatal("copied close retired or discarded active callback owner")
	}
	if got := coordinator.SnapshotV1(org); got != funded {
		t.Fatal("copied close credited active receipt", funded, got)
	}
	if err := h.WithRetainedV1(func(time.Time) error { return nil }); err == nil {
		t.Fatal("closed receipt delivered again")
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("receipt consumer did not join")
	}
	packageRetentionDrain240(t, coordinator, org)
	if !h.RetiredV1() || !copyHandle.RetiredV1() || h.state.owner != nil {
		t.Fatal("joined callback did not retire shared actual owner")
	}
}

func TestPackagePDFRetentionV1CancellationJoinsActualHeldTLSBody(t *testing.T) {
	parent, client, peer, coordinator, org, _ := packageRetentionFixture240(t)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	entered, serverDone, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	peer.mu.Lock()
	peer.blockGET = true
	peer.entered = entered
	peer.getDone = serverDone
	peer.release = release
	peer.mu.Unlock()
	expected := sha256.Sum256(peer.body)
	type result struct {
		handle *PackagePDFLocalRetentionV1
		err    error
	}
	finished := make(chan result, 1)
	joined := make(chan struct{})
	var out result
	defer func() {
		cancel()
		unblock()
		if out.handle != nil {
			out.handle.CloseConsumerV1()
		}
		wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case <-joined:
			select {
			case out := <-finished:
				if out.handle != nil {
					out.handle.CloseConsumerV1()
				}
			default:
			}
		case <-wait.Done():
			t.Error("canceled retention producer did not join")
		}
	}()
	go func() {
		defer close(joined)
		h, _, err := client.RetainPackagePDFLocalOwnedV1(ctx, "main.pdf", peer.version, expected[:], int64(len(peer.body)), time.Now().UTC().Add(time.Hour).Truncate(time.Second), coordinator, org)
		finished <- result{h, err}
	}()
	select {
	case <-entered:
	case <-parent.Done():
		t.Fatal(parent.Err())
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 1 || got.Global.ParentBytes <= 0 {
		t.Fatal("held actual body lost provider/Parent", got)
	}
	cancel()
	select {
	case out = <-finished:
	case <-parent.Done():
		t.Fatal("canceled actual GET did not return")
	}
	if out.err == nil || out.handle == nil {
		t.Fatal("cancellation became retention success", out.err)
	}
	owner := out.handle.state.owner
	if out.handle.RetiredV1() {
		t.Fatal("cancellation retired an open consumer")
	}
	if e := out.handle.WithRetainedV1(func(time.Time) error { return nil }); e == nil {
		t.Fatal("canceled handle acknowledged retention")
	}
	out.handle.CloseConsumerV1()
	wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	select {
	case <-owner.joined:
	case <-wait.Done():
		t.Fatal("actual local IO did not join")
	}
	if !out.handle.RetiredV1() {
		t.Fatal("closed canceled receipt did not retire after actual IO join")
	}
	select {
	case <-serverDone:
	case <-wait.Done():
		t.Fatal("actual held TLS handler did not join")
	}
	peer.mu.Lock()
	puts := peer.putAttempts
	peer.mu.Unlock()
	if puts != 0 {
		t.Fatal("canceled preverification performed retention mutation")
	}
	packageRetentionDrain240(t, coordinator, org)
}

func TestPackagePDFRetentionV1RetiredWaitsForActualConnCloseJoin(t *testing.T) {
	// This predicate-only fixture uses a real net.Pipe and the existing finite
	// Close-return barrier. It constructs no positive constructor/S3/SQL receipt.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	limits := workguard.VectorV1{ParentBytes: 2 << 20, ProviderStreams: 1}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
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
	owner := &evidenceLocalPutStateV1{ctx: ctx, grant: parent, provider: provider, transport: storageHTTPTransportBaseV1(false), connections: make(map[*evidenceLocalConnV1]struct{}), bodies: make(map[*evidenceLocalResponseBodyV1]struct{}), changed: make(chan struct{}), joined: make(chan struct{}), closing: true}
	owner.self = owner
	conn := &evidenceLocalConnV1{owner: owner, inner: barrier, done: make(chan struct{}), scratch: make([]byte, 64<<10)}
	owner.connections[conn] = struct{}{}
	state := &packagePDFLocalRetentionStateV1{owner: owner}
	state.self = state
	h := &PackagePDFLocalRetentionV1{state: state}
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
			t.Error("actual joined owner did not retire")
		}
		packageRetentionDrain240(t, coordinator, org)
	}()
	go owner.closeIOV1()
	var nilHandle *PackagePDFLocalRetentionV1
	badState := &packagePDFLocalRetentionStateV1{self: state, owner: owner, closed: true}
	for _, invalid := range []*PackagePDFLocalRetentionV1{nilHandle, {}, {state: badState}} {
		if invalid.RetiredV1() {
			t.Fatal("invalid handle claimed actual retirement")
		}
		invalid.CloseConsumerV1()
	}
	if h.RetiredV1() {
		t.Fatal("open handle reported retirement")
	}
	select {
	case <-barrier.entered:
	case <-ctx.Done():
		t.Fatal("real Conn.Close did not enter", ctx.Err())
	}
	copied.CloseConsumerV1()
	cancel()
	if h.RetiredV1() || copied.RetiredV1() || state.owner != owner {
		t.Fatal("cancellation/copied close discarded unjoined owner")
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 1 || got.Global.ParentBytes <= 0 {
		t.Fatal("unjoined actual close was refunded", got)
	}
	unblock()
	wait, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	select {
	case <-owner.joined:
	case <-wait.Done():
		t.Fatal("actual Conn.Close did not join")
	}
	if !h.RetiredV1() || !copied.RetiredV1() || state.owner != nil {
		t.Fatal("actual joined release did not retire shared handle")
	}
	packageRetentionDrain240(t, coordinator, org)
}

func TestPackagePDFRetentionV1AdmissionDenialDoesNotDispatch(t *testing.T) {
	ctx, client, peer, coordinator, org, _ := packageRetentionFixture240(t)
	expected := sha256.Sum256(peer.body)
	held, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	before := coordinator.SnapshotV1(org)
	h, denial, err := client.RetainPackagePDFLocalOwnedV1(ctx, "main.pdf", peer.version, expected[:], int64(len(peer.body)), time.Now().UTC().Add(time.Hour).Truncate(time.Second), coordinator, org)
	if h != nil {
		h.CloseConsumerV1()
	}
	if h != nil || !errors.Is(err, workguard.ErrUnavailableV1) || !denial.CapacityV1() || denial.SnapshotV1().Dimension != workguard.AdmissionProviderStreamsV1 || coordinator.SnapshotV1(org) != before {
		t.Fatal("provider denial changed ownership", denial.SnapshotV1(), err)
	}
	peer.mu.Lock()
	calls := peer.heads + peer.gets + peer.putAttempts + peer.retentionReads
	peer.mu.Unlock()
	if calls != 0 {
		t.Fatal("capacity denial dispatched package IO", calls)
	}
	held.Close()
	packageRetentionDrain240(t, coordinator, org)
}
