// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package api

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
	"github.com/labstack/echo/v4"
	"golang.org/x/net/http2"
)

type hashUnreadUpgradeBodyV1 struct{ reads, closes int }

func (b *hashUnreadUpgradeBodyV1) Read([]byte) (int, error) { b.reads++; panic("upgrade body read") }
func (b *hashUnreadUpgradeBodyV1) Close() error             { b.closes++; return nil }
func TestHashH2CUpgradeRefusesBeforeBodyUseV1(t *testing.T) {
	for _, token := range []string{"h2c", "H2C", "websocket, h2c", " h2c ", "other,H2c,other"} {
		for _, size := range []int64{-1, 1 << 30} {
			body := &hashUnreadUpgradeBodyV1{}
			req := httptest.NewRequest(http.MethodPost, "http://renderer.invalid/anything", nil)
			req.Body = body
			req.ContentLength = size
			req.Header.Set("Upgrade", token)
			called := false
			rec := httptest.NewRecorder()
			hashRejectH2CUpgradeV1(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, req)
			if rec.Code != 400 || rec.Header().Get("Connection") != "close" || called || body.reads != 0 || body.closes != 0 {
				t.Fatalf("token=%q size=%d status=%d called=%t reads=%d closes=%d", token, size, rec.Code, called, body.reads, body.closes)
			}
		}
	}
	for _, proto := range []int{1, 2} {
		req := httptest.NewRequest(http.MethodGet, "http://renderer.invalid/", nil)
		req.ProtoMajor = proto
		if proto == 1 {
			req.Header.Set("Upgrade", "websocket")
		} else {
			req.Header.Set("Upgrade", "h2c")
		}
		called := false
		hashRejectH2CUpgradeV1(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) })).ServeHTTP(httptest.NewRecorder(), req)
		if !called {
			t.Fatal("non-upgrade request refused")
		}
	}
}

func hashListenerFixtureV1(t *testing.T, handler http.Handler, timeout time.Duration, cert, key string) *hashAPIServerV1 {
	t.Helper()
	srv := &http.Server{Addr: "127.0.0.1:0", ReadTimeout: timeout, IdleTimeout: timeout, WriteTimeout: 2 * timeout}
	owned, err := startHashAPIServerV1(srv, handler, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := owned.stop(ctx); err != nil {
			t.Error("owned listener cleanup", err)
		}
	})
	return owned
}
func hashH2CClientV1(t *testing.T, dials *atomic.Int32) *http.Client {
	t.Helper()
	tr := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 2 * time.Second}
}
func TestHashListenerHTTP1AndH2PriorKnowledgeV1(t *testing.T) {
	owned := hashListenerFixtureV1(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Protocol", r.Proto)
		io.WriteString(w, r.URL.Path)
	}), time.Second, "", "")
	url := "http://" + owned.listener.Addr().String() + "/root/probe"
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.ProtoMajor != 1 || string(data) != "/root/probe" {
		t.Fatal("HTTP1 route", readErr, closeErr, response.Proto, string(data))
	}
	var dials atomic.Int32
	h2client := hashH2CClientV1(t, &dials)
	for range 3 {
		response, err = h2client.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr = io.ReadAll(response.Body)
		closeErr = response.Body.Close()
		if readErr != nil || closeErr != nil || response.ProtoMajor != 2 || string(data) != "/root/probe" {
			t.Fatal("H2 route", readErr, closeErr, response.Proto, string(data))
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("H2 requests did not reuse one connection: %d", dials.Load())
	}
	// Leave the H2 connection open: Stop must join its actual close.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := owned.stop(ctx); err != nil {
		t.Fatal(err)
	}
	owned.mu.Lock()
	left := len(owned.connections)
	owned.mu.Unlock()
	select {
	case <-owned.done:
	default:
		t.Fatal("serving goroutine remains")
	}
	if left != 0 {
		t.Fatal("hijacked connection remains", left)
	}
}

func TestHashListenerRawUpgradeRefusalWithoutUploadV1(t *testing.T) {
	var calls atomic.Int32
	owned := hashListenerFixtureV1(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }), time.Second, "", "")
	conn, err := net.DialTimeout("tcp", owned.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := "POST /unknown HTTP/1.1\r\nHost: test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: H2C\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\nExpect: 100-continue\r\nContent-Length: 1073741824\r\n\r\n"
	if _, err = io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, " 400 ") || calls.Load() != 0 {
		t.Fatalf("upgrade response=%q err=%v calls=%d", line, err, calls.Load())
	}
}

func hashTLSFilesV1(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Hash owned listener test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return certPath, keyPath, roots
}
func TestHashListenerTLSUsesSameBoundedServerV1(t *testing.T) {
	cert, key, roots := hashTLSFilesV1(t)
	owned := hashListenerFixtureV1(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "TLS route") }), time.Second, cert, key)
	if owned.server.ReadTimeout != time.Second || owned.server.IdleTimeout != time.Second || owned.server.WriteTimeout != 2*time.Second {
		t.Fatal("TLS server lost configured timeouts")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Get("https://" + owned.listener.Addr().String() + "/root/probe")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || response.ProtoMajor != 2 || string(data) != "TLS route" {
		t.Fatal("trusted TLS/H2 route", err, closeErr, response.Proto, string(data))
	}
}

func TestHashListenerUnfinishedRequestCannotPassShutdownV1(t *testing.T) {
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	callerDone := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	owned := hashListenerFixtureV1(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; io.WriteString(w, "retired") }), time.Second, "", "")
	go func() {
		defer close(callerDone)
		tr := &http.Transport{}
		defer tr.CloseIdleConnections()
		response, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Get("http://" + owned.listener.Addr().String() + "/held")
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			err = errors.Join(err, response.Body.Close())
		}
		finished <- err
	}()
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		select {
		case <-callerDone:
		case <-time.After(3 * time.Second):
			t.Error("caller cleanup did not join")
		}
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not enter")
	}
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := owned.stop(short)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unretired request accepted", err)
	}
	owned.mu.Lock()
	count := len(owned.connections)
	owned.mu.Unlock()
	if count == 0 {
		t.Fatal("active connection was forgotten")
	}
	once.Do(func() { close(release) })
	select {
	case err = <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caller did not retire")
	}
	select {
	case <-callerDone:
	case <-time.After(time.Second):
		t.Fatal("caller cleanup did not retire")
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = owned.stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestHashListenerBindAndCertificateFailuresAreSynchronousV1(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if value, err := startHashAPIServerV1(&http.Server{Addr: held.Addr().String()}, handler, "", ""); err == nil || value != nil {
		t.Fatal("occupied listener accepted", err)
	}
	if value, err := startHashAPIServerV1(&http.Server{Addr: held.Addr().String()}, handler, filepath.Join(t.TempDir(), "missing-cert"), "missing-key"); err == nil || value != nil || !strings.Contains(err.Error(), "TLS identity") {
		t.Fatal("TLS identity did not fail before binding", err)
	}
}

func TestHashApiStartPreservesRootAuthHealthReadinessV1(t *testing.T) {
	var ready atomic.Bool
	a := &Api{bindIp: "127.0.0.1", port: 0, rootPath: "/root/", timeout: time.Second, startTimeout: time.Second, correlationIdHeader: "Gotenberg-Trace", basicAuthUsername: "user", basicAuthPassword: "password", logger: slog.New(slog.DiscardHandler), readyFn: []func() error{func() error { ready.Store(true); return nil }}, routes: []Route{{Method: http.MethodGet, Path: "/probe", Handler: func(c echo.Context) error { return c.String(200, "rooted") }}}}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := a.Stop(ctx); !errors.Is(err, gotenberg.ErrCancelGracefulShutdownContext) {
			t.Error("API cleanup", err)
		}
	})
	if !ready.Load() {
		t.Fatal("readiness barrier skipped")
	}
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	base := "http://" + a.ownedServer.listener.Addr().String()
	for _, tc := range []struct {
		path   string
		auth   bool
		status int
	}{{"/root/probe", false, 401}, {"/root/probe", true, 200}, {"/root/health", false, 200}} {
		req, err := http.NewRequest(http.MethodGet, base+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if tc.auth {
			req.SetBasicAuth("user", "password")
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if response.StatusCode != tc.status || readErr != nil || closeErr != nil {
			t.Fatalf("route=%s status=%d err=%v/%v", tc.path, response.StatusCode, readErr, closeErr)
		}
	}
}

func TestHashListenerClosedH2SocketDoesNotHideRunningRequestV1(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseGate()
	owned := hashListenerFixtureV1(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	}), time.Second, "", "")
	dialed := make(chan net.Conn, 1)
	tr := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err == nil {
			dialed <- conn
		}
		return conn, err
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer tr.CloseIdleConnections()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+owned.listener.Addr().String()+"/held", nil)
		if err != nil {
			return
		}
		response, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Do(req)
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
	}()
	t.Cleanup(func() {
		cancel()
		releaseGate()
		tr.CloseIdleConnections()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("H2 caller did not join")
		}
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("H2 handler did not enter")
	}
	var conn net.Conn
	select {
	case conn = <-dialed:
	case <-time.After(time.Second):
		t.Fatal("exact client connection missing")
	}
	cancel()
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		owned.mu.Lock()
		count, requests := len(owned.connections), owned.requests
		owned.mu.Unlock()
		if count == 0 {
			if requests != 1 {
				t.Fatal("running H2 request was forgotten", requests)
			}
			break
		}
		select {
		case <-owned.changed:
		case <-deadline.C:
			t.Fatal("closed H2 connection did not retire")
		}
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := owned.stop(short)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("running request hidden behind closed socket", err)
	}
	releaseGate()
	joined, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	if err := owned.stop(joined); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("H2 caller remains")
	}
}

func TestHashListenerRetiredServerRefusesLateApplicationEntryV1(t *testing.T) {
	var calls atomic.Int32
	owned := hashListenerFixtureV1(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }), time.Second, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := owned.stop(ctx); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://renderer.invalid/late", nil)
	request.ProtoMajor, request.ProtoMinor, request.Proto = 2, 0, "HTTP/2.0"
	var outcome any
	func() {
		defer func() { outcome = recover() }()
		owned.server.Handler.ServeHTTP(httptest.NewRecorder(), request)
	}()
	if outcome != http.ErrAbortHandler || calls.Load() != 0 {
		t.Fatalf("late handler outcome=%v calls=%d", outcome, calls.Load())
	}
	owned.mu.Lock()
	requests, retiring := owned.requests, owned.retiring
	owned.mu.Unlock()
	if requests != 0 || !retiring {
		t.Fatalf("retirement fence lost: requests=%d retiring=%t", requests, retiring)
	}
}

type hashUncertainCloseConnV1 struct {
	net.Conn
	calls   int
	outcome error
}

func (c *hashUncertainCloseConnV1) Close() error {
	c.calls++
	return errors.Join(c.Conn.Close(), c.outcome)
}
func TestHashListenerUncertainSocketCloseRemainsOwnedV1(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	cause := errors.New("close outcome uncertain")
	raw := &hashUncertainCloseConnV1{Conn: left, outcome: cause}
	joined := make(chan struct{})
	close(joined)
	owned := &hashAPIServerV1{server: &http.Server{}, done: joined, changed: make(chan struct{}, 1), connections: make(map[*hashAPIConnV1]struct{})}
	tracked := &hashAPIConnV1{Conn: raw, owner: owned}
	owned.connections[tracked] = struct{}{}
	for range 2 {
		if err := tracked.Close(); !errors.Is(err, cause) {
			t.Fatal("uncertain close lost", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := owned.stop(ctx)
	if raw.calls != 1 || !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || len(owned.connections) != 1 {
		t.Fatalf("uncertain close was refunded: calls=%d retained=%d err=%v", raw.calls, len(owned.connections), err)
	}
}
