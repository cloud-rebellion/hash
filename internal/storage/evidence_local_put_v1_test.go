// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
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
)

type evidenceLocalPeerObjectV1 struct {
	body    []byte
	version string
	until   string
}
type evidenceLocalPeerV1 struct {
	mu                sync.Mutex
	objects           map[string]evidenceLocalPeerObjectV1
	puts, heads, gets int
	multipart         bool
	failure           error
	denyPut           bool
	denyRetention     bool
	latestHeads       int
	ordinaryEntered   chan struct{}
	ordinaryRelease   <-chan struct{}
}

func (p *evidenceLocalPeerV1) serveV1(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/native-evidence/ordinary-") && p.ordinaryEntered != nil {
		w.Header().Set("Content-Length", "2")
		w.Header().Set("Last-Modified", "Thu, 15 Oct 2026 12:00:00 GMT")
		w.Header().Set("ETag", "\"ordinary-etag\"")
		w.Header().Set("X-Amz-Version-Id", "ordinary-version")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		p.ordinaryEntered <- struct{}{}
		select {
		case <-p.ordinaryRelease:
			_, _ = io.WriteString(w, "OK")
		case <-r.Context().Done():
		}
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.URL.Path == "/native-evidence" || r.URL.Path == "/native-evidence/" {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Has("versioning") {
			_, _ = io.WriteString(w, "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
			return
		}
		if r.URL.Query().Has("object-lock") {
			_, _ = io.WriteString(w, "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>")
			return
		}
	}
	if !strings.HasPrefix(r.URL.Path, "/native-evidence/") {
		p.failure = errors.New("unexpected protocol path")
		http.Error(w, "bad path", 400)
		return
	}
	if r.URL.Query().Has("uploads") || r.URL.Query().Has("uploadId") {
		p.multipart = true
		http.Error(w, "multipart is forbidden in this finite peer", 400)
		return
	}
	if r.Header.Get("Authorization") == "" {
		p.failure = errors.New("original static V4 authentication missing")
		http.Error(w, "missing authentication", 400)
		return
	}
	key := r.URL.Path
	if r.Method == http.MethodHead && r.URL.Query().Get("versionId") == "" {
		p.latestHeads++
	}
	object, found := p.objects[key]
	if r.Method == http.MethodPut && !r.URL.Query().Has("retention") {
		p.puts++
		if p.denyPut {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>original provider refused this owned evidence</Message></Error>")
			return
		}
		if r.Header.Get("X-Amz-Server-Side-Encryption") != "AES256" || r.Header.Get("X-Amz-Object-Lock-Mode") != "COMPLIANCE" || r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date") == "" {
			p.failure = errors.New("original encryption/retention PUT policy changed")
			http.Error(w, "missing evidence policy", 400)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxStoredObjectBytes+1))
		if err != nil || len(body) > maxStoredObjectBytes {
			p.failure = errors.New("actual PUT body failed")
			http.Error(w, "body failed", 400)
			return
		}
		object = evidenceLocalPeerObjectV1{body: body, version: "version-" + strconv.Itoa(p.puts), until: r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")}
		p.objects[key] = object
		w.Header().Set("X-Amz-Version-Id", object.version)
		w.Header().Set("ETag", "\"exact-peer-etag\"")
		w.WriteHeader(http.StatusOK)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if version := r.URL.Query().Get("versionId"); version != "" && version != object.version {
		p.failure = errors.New("exact version changed")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.URL.Query().Has("retention") {
		if p.denyRetention {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>retention confirmation unavailable</Message></Error>")
			return
		}
		if r.Method != http.MethodGet {
			p.failure = errors.New("already sufficient COMPLIANCE retention was rewritten")
			http.Error(w, "unexpected retention write", 400)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>"+object.until+"</RetainUntilDate></Retention>")
		return
	}
	w.Header().Set("X-Amz-Version-Id", object.version)
	w.Header().Set("ETag", "\"exact-peer-etag\"")
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Length", strconv.Itoa(len(object.body)))
	w.Header().Set("Last-Modified", "Thu, 15 Oct 2026 12:00:00 GMT")
	if r.Method == http.MethodHead {
		p.heads++
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == http.MethodGet {
		p.gets++
		_, _ = w.Write(object.body)
		return
	}
	p.failure = errors.New("unexpected protocol method")
	http.Error(w, "method failed", 400)
}
func evidenceLocalTestClientV1(t *testing.T) (context.Context, *Client, *evidenceLocalPeerV1, *workguard.CoordinatorV1, uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	peer := &evidenceLocalPeerV1{objects: make(map[string]evidenceLocalPeerObjectV1)}
	server := httptest.NewTLSServer(http.HandlerFunc(peer.serveV1))
	t.Cleanup(server.Close)
	certFile := filepath.Join(t.TempDir(), "peer-trust.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certFile)
	client, err := New(ctx, Config{Endpoint: strings.TrimPrefix(server.URL, "https://"), Region: "us-east-1", Bucket: "native-evidence", AccessKey: "local-protocol-key", SecretKey: "local-protocol-secret", UseSSL: true, BucketLookup: "path", RequireExistingBucket: true, RequireObjectLock: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	limits := workguard.VectorV1{ParentBytes: 192 << 20, ProviderStreams: 1}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, client, peer, coordinator, uuid.New()
}

func TestEvidenceLocalPUTV1ActualTLSOriginalPolicyReuseAndIndependentOutput(t *testing.T) {
	// A genuine TCP/TLS S3 protocol peer and real New/SDK/Transport; no claim of
	// remote S3 Object Lock compliance, native SQL/source or physical RSS proof.
	ctx, client, peer, coordinator, org := evidenceLocalTestClientV1(t)
	// Cross the pinned SDK's original automatic multipart boundary. The native
	// finalization lane must still issue a single actual PUT, never worker parts.
	original := bytes.Repeat([]byte("actual original source\n"), (17<<20)/22)
	expected := sha256.Sum256(original)
	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	first, err := client.PutEvidenceVersionedLocalOwnedV1(ctx, "final.pdf", "application/pdf", original, until, coordinator, org)
	if first != nil {
		defer first.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal(err)
	}
	original[0] ^= 1
	var committed StoredObject
	if err = first.WithStoredV1(func(value StoredObject) error {
		committed = value
		if value.SHA256 != expected || value.VersionID == "" {
			return errors.New("actual final version/digest changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	peer.mu.Lock()
	stored := peer.objects["/native-evidence/final.pdf"]
	peerErr, parts, puts := peer.failure, peer.multipart, peer.puts
	storedDigest := sha256.Sum256(stored.body)
	peer.mu.Unlock()
	if peerErr != nil || parts || puts != 1 || storedDigest != expected || stored.version != committed.VersionID {
		t.Fatal("actual authenticated/SSE/retention/single-PUT source changed", peerErr, parts, puts)
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		t.Fatal("stream not joined or result Parent lost", got)
	}
	reuse, err := client.PutEvidenceVersionedLocalOwnedV1(ctx, "final.pdf", "application/pdf", stored.body, until, coordinator, org)
	if reuse != nil {
		defer reuse.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = reuse.WithStoredV1(func(value StoredObject) error {
		if value != committed {
			return errors.New("latest-only identical retry did not reuse exact version")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reuse.CloseConsumerV1()
	peer.mu.Lock()
	puts = peer.puts
	peer.mu.Unlock()
	if puts != 1 {
		t.Fatal("identical evidence retry issued another PUT", puts)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- first.WithStoredV1(func(value StoredObject) error {
			if value != committed {
				return errors.New("result changed before borrow")
			}
			close(entered)
			<-release
			if value != committed {
				return errors.New("copied Close erased active result")
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	copied := *first
	copied.CloseConsumerV1()
	first.CloseConsumerV1()
	second, err := client.PutEvidenceVersionedLocalOwnedV1(ctx, "certificate.pdf", "application/pdf", []byte("independent certificate source"), until, coordinator, org)
	if second != nil {
		defer second.CloseConsumerV1()
	}
	if err != nil {
		close(release)
		<-done
		t.Fatal("joined first provider blocked actual next evidence PUT", err)
	}
	second.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		close(release)
		<-done
		t.Fatal("active result Parent credited or next stream retained", got)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("actual output last use did not drain", got)
	}
}

func TestEvidenceLocalPUTV1ActualErrorAndOriginalPreflightRefusal(t *testing.T) {
	ctx, client, peer, coordinator, org := evidenceLocalTestClientV1(t)
	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	peer.mu.Lock()
	peer.denyPut = true
	peer.mu.Unlock()
	result, err := client.PutEvidenceVersionedLocalOwnedV1(ctx, "denied.pdf", "application/pdf", []byte("actual denied source"), until, coordinator, org)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if result == nil || err == nil || !strings.Contains(err.Error(), "original provider refused this owned evidence") {
		t.Fatal("original provider error identity/text changed", err)
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		t.Fatal("actual error consumer lost Parent or IO stream retained", got)
	}
	if borrowErr := result.WithStoredV1(func(StoredObject) error { return nil }); borrowErr == nil {
		t.Fatal("failed PUT represented as successful stored evidence")
	}
	if borrowErr := result.WithObservationV1(func(StoredObject, bool) error { return nil }); borrowErr == nil {
		t.Fatal("provider refusal without a positive version invented an observation")
	}
	// This fixed error consumer finishes formatting before its sole actual Close.
	_ = fmt.Sprintf("%v", err)
	result.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) {
		t.Fatal("error last use retained local debt", got)
	}
	peer.mu.Lock()
	before := peer.puts + peer.gets + peer.heads
	peer.mu.Unlock()
	for _, bad := range []time.Time{{}, until.Add(time.Nanosecond)} {
		_, originalErr := client.PutEvidenceVersioned(ctx, "invalid.pdf", "application/pdf", []byte("invalid deadline"), bad)
		h, nativeErr := client.PutEvidenceVersionedLocalOwnedV1(ctx, "invalid.pdf", "application/pdf", []byte("invalid deadline"), bad, coordinator, org)
		if h != nil {
			h.CloseConsumerV1()
		}
		if originalErr == nil || nativeErr == nil || originalErr.Error() != nativeErr.Error() {
			t.Fatal("original pre-provider durable deadline refusal changed", originalErr, nativeErr)
		}
	}
	peer.mu.Lock()
	after := peer.puts + peer.gets + peer.heads
	peer.mu.Unlock()
	if after != before {
		t.Fatal("invalid durable deadline dispatched provider work")
	}
	held, holdErr := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if holdErr != nil {
		t.Fatal(holdErr)
	}
	h, capacityErr := client.PutEvidenceVersionedLocalOwnedV1(ctx, "capacity.pdf", "application/pdf", []byte("actual blocked source"), until, coordinator, org)
	if h != nil {
		h.CloseConsumerV1()
	}
	held.Close()
	if h != nil || !errors.Is(capacityErr, workguard.ErrUnavailableV1) {
		t.Fatal("real shared provider refusal changed or dispatched", capacityErr)
	}
	peer.mu.Lock()
	afterCapacity := peer.puts + peer.gets + peer.heads
	peer.mu.Unlock()
	if afterCapacity != after {
		t.Fatal("native capacity refusal dispatched S3 work")
	}
	copiedClient := *client
	if h, err := copiedClient.PutEvidenceVersionedLocalOwnedV1(ctx, "invented.pdf", "application/pdf", nil, until, coordinator, org); h != nil || err == nil {
		t.Fatal("copied Client minted genuine constructor profile")
	}
	if h, err := (&Client{mc: client.mc, bucket: client.bucket}).PutEvidenceVersionedLocalOwnedV1(ctx, "invented.pdf", "application/pdf", nil, until, coordinator, org); h != nil || err == nil {
		t.Fatal("invented Client minted genuine constructor profile")
	}
}

type evidenceLocalCloseBarrierConnV1 struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *evidenceLocalCloseBarrierConnV1) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return err
}
func TestEvidenceLocalPUTV1ProviderCreditsOnlyActualConnCloseJoin(t *testing.T) {
	// A real net.Pipe with a synthetic Close-return barrier isolates the local
	// join predicate. It does not construct a positive Client/source/SQL witness.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	v := workguard.VectorV1{ParentBytes: 2 << 20, ProviderStreams: 1}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 8, MaxOrganisationGrants: 8})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	barrier := &evidenceLocalCloseBarrierConnV1{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
	owner := &evidenceLocalPutStateV1{ctx: ctx, grant: parent, provider: provider, transport: storageHTTPTransportBaseV1(false), connections: make(map[*evidenceLocalConnV1]struct{}), bodies: make(map[*evidenceLocalResponseBodyV1]struct{}), changed: make(chan struct{}), joined: make(chan struct{}), closing: true}
	owner.self = owner
	conn := &evidenceLocalConnV1{owner: owner, inner: barrier, done: make(chan struct{}), scratch: make([]byte, 64<<10)}
	owner.connections[conn] = struct{}{}
	go owner.closeIOV1()
	select {
	case <-barrier.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	h := &EvidenceLocalPutV1{state: owner}
	copied := *h
	copied.CloseConsumerV1()
	cancel()
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 1 || got.Global.ParentBytes <= 0 {
		close(barrier.release)
		t.Fatal("cancellation/copied Close credited unjoined actual Conn.Close", got)
	}
	close(barrier.release)
	select {
	case <-owner.joined:
	case <-time.After(5 * time.Second):
		t.Fatal("actual Conn.Close did not join")
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) {
		t.Fatal("actual IO/consumer joined but debt retained", got)
	}
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("retired real connection staging reused")
	}
}

func TestEvidenceLocalPUTV1OriginalEightOrdinaryConnectionsBlockNativeThenIdleProgress(t *testing.T) {
	// Real New/SDK/TLS connections occupy the original ordinary Transport. A
	// native operation must wait on their SAME aggregate eight positions; real
	// ordinary body EOF/Close and idle retirement must then permit progress.
	ctx, client, peer, coordinator, org := evidenceLocalTestClientV1(t)
	entered := make(chan struct{}, boundedStorageConnectionsPerHostV1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	peer.ordinaryEntered = entered
	peer.ordinaryRelease = release
	type ordinaryResult struct {
		body io.ReadCloser
		err  error
	}
	ordinary := make(chan ordinaryResult, boundedStorageConnectionsPerHostV1)
	for index := 0; index < boundedStorageConnectionsPerHostV1; index++ {
		go func(i int) {
			body, _, _, err := (minio.Core{Client: client.mc}).GetObject(ctx, client.bucket, fmt.Sprintf("ordinary-%d.pdf", i), client.getOpts("ordinary-version"))
			ordinary <- ordinaryResult{body, err}
		}(index)
	}
	var readers []io.ReadCloser
	t.Cleanup(func() {
		for _, reader := range readers {
			_ = reader.Close()
		}
	})
	for index := 0; index < boundedStorageConnectionsPerHostV1; index++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		select {
		case actual := <-ordinary:
			if actual.err != nil || actual.body == nil {
				t.Fatal("actual ordinary connection did not become live", actual.err)
			}
			readers = append(readers, actual.body)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	type nativeResult struct {
		owner *EvidenceLocalPutV1
		err   error
	}
	nativeDone := make(chan nativeResult, 1)
	nativeCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() {
		h, err := client.PutEvidenceVersionedLocalOwnedV1(nativeCtx, "after-ordinary.pdf", "application/pdf", []byte("actual waiting native source"), time.Now().UTC().Add(time.Hour).Truncate(time.Second), coordinator, org)
		nativeDone <- nativeResult{h, err}
	}()
	gate := client.localProfile.connections
	waiting := false
	for !waiting {
		gate.mu.Lock()
		waiting = gate.waiters > 0
		active := 0
		for _, entry := range gate.hosts {
			active += entry.active
		}
		gate.mu.Unlock()
		if active != boundedStorageConnectionsPerHostV1 {
			t.Fatal("native exceeded/lost the original eight real connection positions", active)
		}
		if !waiting {
			select {
			case premature := <-nativeDone:
				if premature.owner != nil {
					premature.owner.CloseConsumerV1()
				}
				t.Fatal("native completed while all eight ordinary sockets were live", premature.err)
			case <-time.After(time.Millisecond):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	peer.mu.Lock()
	puts, heads := peer.puts, peer.heads
	peer.mu.Unlock()
	if puts != 0 || heads != 0 {
		t.Fatal("native dispatched before an original socket retired", puts, heads)
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 1 || got.Global.ParentBytes <= 0 {
		t.Fatal("blocked real dial/IO lost native ownership", got)
	}
	unblock()
	for _, reader := range readers {
		raw, err := io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil || closeErr != nil || string(raw) != "OK" {
			t.Fatal("ordinary source/EOF/Close changed", err, closeErr)
		}
	}
	select {
	case actual := <-nativeDone:
		if actual.owner != nil {
			defer actual.owner.CloseConsumerV1()
		}
		if actual.err != nil || actual.owner == nil {
			t.Fatal("actual newly idle ordinary connection did not release native admission", actual.err)
		}
		actual.owner.CloseConsumerV1()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("private/ordinary idle split caused false deadlock before original idle timeout")
	}
	client.localProfile.base.CloseIdleConnections()
	gate.mu.Lock()
	for _, entry := range gate.hosts {
		if entry.active > boundedStorageConnectionsPerHostV1 {
			gate.mu.Unlock()
			t.Fatal("aggregate host capacity exceeded original eight")
		}
	}
	gate.mu.Unlock()
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("shared real socket/native owner did not drain", got)
	}
}

func TestEvidenceLocalPUTV1SharedHostPositionNeedsActualCloseAndReadJoin(t *testing.T) {
	// The real net.Pipe/barrier isolates shared physical-position retirement,
	// independently of the result/provider owner tested above.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gate := newStorageConnectionAdmissionV1()
	key, err := gate.acquireV1(ctx, "tcp", "actual-peer:9000")
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	barrier := &evidenceLocalCloseBarrierConnV1{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
	conn := &storageAdmittedConnV1{inner: barrier, owner: gate, key: key}
	conn.joined = sync.NewCond(&conn.mu)
	readDone := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); readDone <- err }()
	for {
		conn.mu.Lock()
		active := conn.active
		conn.mu.Unlock()
		if active == 1 {
			break
		}
		select {
		case <-time.After(time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()
	select {
	case <-barrier.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	gate.mu.Lock()
	active := gate.hosts[key].active
	gate.mu.Unlock()
	if active != 1 {
		close(barrier.release)
		t.Fatal("logical cancellation/Read return credited unjoined actual Close", active)
	}
	select {
	case <-closeDone:
		close(barrier.release)
		t.Fatal("shared actual Close returned before underlying close join")
	default:
	}
	close(barrier.release)
	if err = <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err = <-readDone; err == nil {
		t.Fatal("actual blocked Read incorrectly succeeded")
	}
	gate.mu.Lock()
	leftHosts := len(gate.hosts)
	gate.mu.Unlock()
	if leftHosts != 0 {
		t.Fatal("joined shared physical position retained", leftHosts)
	}
}
