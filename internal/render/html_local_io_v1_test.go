// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func htmlLocalTestAdmissionV1(t *testing.T) (context.Context, *workguard.CoordinatorV1, uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	v := workguard.VectorV1{ParentBytes: 64 << 20, ProviderStreams: 1}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, c, uuid.New()
}

func TestHTMLLocalPDFV1OriginalRetriesRedirectAndConsumerClose(t *testing.T) {
	ctx, coordinator, org := htmlLocalTestAdmissionV1(t)
	// A deterministic local HTTP protocol peer, not Chromium, SQL/source proof,
	// a PDF parsing test or evidence of remote renderer process retirement.
	pdf := []byte("%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n")
	source := "<!doctype html><html><body>Actual original source</body></html>"
	var attempts, final atomic.Int32
	var mu sync.Mutex
	var frames [][]byte
	var peerErr error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		frames = append(frames, body)
		if err != nil {
			peerErr = err
		}
		mu.Unlock()
		if r.URL.Path == "/final" {
			final.Add(1)
			w.Header().Set("Trailer", "X-Hash-Local-Proof")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = w.Write(pdf)
			w.Header().Set("X-Hash-Local-Proof", "actual chunked trailer")
			return
		}
		if attempts.Add(1) < 3 {
			http.Error(w, "retry original route", http.StatusServiceUnavailable)
			return
		}
		_, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		fields := map[string]string{}
		if err == nil {
			parts := multipart.NewReader(bytes.NewReader(body), parameters["boundary"])
			for {
				part, nextErr := parts.NextPart()
				if nextErr == io.EOF {
					break
				}
				if nextErr != nil {
					err = nextErr
					break
				}
				value, readErr := io.ReadAll(part)
				if readErr != nil {
					err = readErr
					break
				}
				fields[part.FormName()+":"+part.FileName()] = string(value)
			}
		}
		if err == nil && (fields["files:index.html"] != source || fields["preferCssPageSize:"] != "true" || fields["waitDelay:"] != "1000ms" || fields["waitForExpression:"] != "window.ready === true") {
			err = errors.New("original multipart source/options changed")
		}
		mu.Lock()
		if err != nil {
			peerErr = err
		}
		mu.Unlock()
		w.Header().Set("Location", "/final")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	renderer := NewGotenberg(server.URL)
	result, err := renderer.HTMLToPDFLocalOwnedV1(ctx, source, PDFOptions{MaxResponseBytes: 16384, Assets: []FontAsset{}, PreferCSSPageSize: true, WaitDelay: "1000ms", WaitForExpression: "window.ready === true"}, coordinator, org)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if peerErr != nil {
		t.Fatal(peerErr)
	}
	if attempts.Load() != 3 || final.Load() != 1 || len(frames) != 4 {
		t.Fatal("original retries/redirects changed", attempts.Load(), final.Load(), len(frames))
	}
	for _, frame := range frames[1:] {
		if !bytes.Equal(frame, frames[0]) {
			t.Fatal("original retry/307 body changed")
		}
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		t.Fatal("private output Parent absent or joined local stream retained", got)
	}
	result.state.mu.Lock()
	joined, conns := result.state.ioJoined, len(result.state.connections)
	result.state.mu.Unlock()
	if !joined || conns == 0 {
		t.Fatal("actual local dial/IO not joined", joined, conns)
	}
	for conn := range result.state.connections {
		conn.mu.Lock()
		closed, innerClosed, active, staging := conn.closed, conn.innerClosed, conn.active, len(conn.scratch)
		conn.mu.Unlock()
		if !closed || !innerClosed || active != 0 || staging != 0 {
			t.Fatal("actual private connection staging not retired", closed, innerClosed, active, staging)
		}
	}
	entered, leave, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- result.WithPDFV1(func(actual []byte) error {
			if !bytes.Equal(actual, pdf) {
				return errors.New("actual returned PDF bytes changed")
			}
			close(entered)
			<-leave
			return nil
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	copied := *result
	copied.CloseConsumerV1()
	result.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		t.Fatal("copied close credited live output Parent or retained joined stream", got)
	}
	close(leave)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("local owner failed to drain", got)
	}
	if err := copied.WithPDFV1(func([]byte) error { return nil }); err == nil {
		t.Fatal("copied closed result was borrowed")
	}
}

func TestHTMLLocalPDFV1OriginalResponseLimit(t *testing.T) {
	ctx, coordinator, org := htmlLocalTestAdmissionV1(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		_, _ = io.WriteString(w, "%PDF-actual-response")
	}))
	defer server.Close()
	renderer := NewGotenberg(server.URL)
	result, err := renderer.HTMLToPDFLocalOwnedV1(ctx, "<html>Actual</html>", PDFOptions{Assets: []FontAsset{}, MaxResponseBytes: 4}, coordinator, org)
	if result == nil {
		t.Fatal("real failed response must retain its local owner")
	}
	defer result.CloseConsumerV1()
	if err == nil || !strings.Contains(err.Error(), "4-byte limit") {
		t.Fatal("original bounded response error changed", err)
	}
	if requests.Load() != 1 {
		t.Fatal("original successful HTTP response was retried", requests.Load())
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		t.Fatal("failed returned Parent was credited or joined stream retained", got)
	}
	result.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("failed local response did not drain", got)
	}
}

func TestHTMLLocalPDFV1DirectHTTPSKeepsSystemCertificateVerification(t *testing.T) {
	ctx, coordinator, org := htmlLocalTestAdmissionV1(t)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	renderer := NewGotenberg(server.URL)
	result, err := renderer.HTMLToPDFLocalOwnedV1(ctx, "<html>TLS</html>", PDFOptions{Assets: []FontAsset{}, MaxResponseBytes: 32}, coordinator, org)
	if result == nil {
		t.Fatal("real TLS attempt must retain its local owner")
	}
	defer result.CloseConsumerV1()
	var unknown x509.UnknownAuthorityError
	if err == nil || !errors.As(err, &unknown) || requests.Load() != 0 {
		t.Fatal("system certificate verification bypassed", err, requests.Load())
	}
	result.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("failed TLS local IO did not drain", got)
	}
}

func TestHTMLLocalPDFV1ProviderRefusalPrecedesActualRequest(t *testing.T) {
	ctx, coordinator, org := htmlLocalTestAdmissionV1(t)
	held, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	renderer := NewGotenberg(server.URL)
	result, err := renderer.HTMLToPDFLocalOwnedV1(ctx, "<html>source</html>", PDFOptions{Assets: []FontAsset{}, MaxResponseBytes: 32}, coordinator, org)
	if result != nil || err == nil || !errors.Is(err, workguard.ErrUnavailableV1) || requests.Load() != 0 {
		t.Fatal("renderer bypassed genuine provider refusal", result, err, requests.Load())
	}
	if got := coordinator.SnapshotV1(org); got.GlobalGrants != 1 || got.Global.ProviderStreams != 1 {
		t.Fatal("refusal credited existing owner", got)
	}
}

func TestHTMLLocalPDFV1CancellationNeedsActualOwnerClose(t *testing.T) {
	parent, coordinator, org := htmlLocalTestAdmissionV1(t)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	renderer := NewGotenberg(server.URL)
	type outcome struct {
		result *HTMLLocalPDFV1
		err    error
	}
	returned := make(chan outcome, 1)
	go func() {
		result, err := renderer.HTMLToPDFLocalOwnedV1(ctx, "<html>cancel</html>", PDFOptions{Assets: []FontAsset{}, MaxResponseBytes: 32}, coordinator, org)
		returned <- outcome{result, err}
	}()
	select {
	case <-entered:
	case <-parent.Done():
		t.Fatal(parent.Err())
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 1 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 2 {
		t.Fatal("actual blocked local IO stream or private Parent was credited", got)
	}
	cancel()
	var actual outcome
	select {
	case actual = <-returned:
	case <-parent.Done():
		t.Fatal(parent.Err())
	}
	if actual.result == nil || actual.err == nil || !errors.Is(actual.err, context.Canceled) {
		t.Fatal("actual cancellation result lost", actual.result, actual.err)
	}
	defer actual.result.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global.ParentBytes <= 0 || got.GlobalGrants < 1 {
		t.Fatal("cancellation credited a returned Parent owner", got)
	}
	copied := *actual.result
	copied.CloseConsumerV1()
	select {
	case <-actual.result.state.joined:
	case <-parent.Done():
		t.Fatal(parent.Err())
	}
	actual.result.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("actual cancelled local IO/consumer failed to drain", got)
	}
}

type htmlLocalRefusedJarV1 struct{ calls *atomic.Int32 }

func (j htmlLocalRefusedJarV1) Cookies(*url.URL) []*http.Cookie     { j.calls.Add(1); return nil }
func (j htmlLocalRefusedJarV1) SetCookies(*url.URL, []*http.Cookie) { j.calls.Add(1) }
func TestHTMLLocalPDFV1CustomClientCallbacksRefusedBeforeDispatch(t *testing.T) {
	for _, kind := range []string{"bound-dialer", "redirect", "jar", "tls-time", "empty-custom-transport"} {
		t.Run(kind, func(t *testing.T) {
			ctx, coordinator, org := htmlLocalTestAdmissionV1(t)
			var requests, callbacks atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
			defer server.Close()
			renderer := NewGotenberg(server.URL)
			switch kind {
			case "bound-dialer":
				dialer := &net.Dialer{Control: func(string, string, syscall.RawConn) error { callbacks.Add(1); return nil }}
				renderer.HTTP.Transport = &http.Transport{DialContext: dialer.DialContext}
			case "redirect":
				renderer.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { callbacks.Add(1); return nil }
			case "jar":
				renderer.HTTP.Jar = htmlLocalRefusedJarV1{calls: &callbacks}
			case "tls-time":
				renderer.HTTP.Transport = &http.Transport{TLSClientConfig: &tls.Config{Time: func() time.Time { callbacks.Add(1); return time.Now() }}}
			case "empty-custom-transport":
				renderer.HTTP.Transport = &http.Transport{}
			}
			result, err := renderer.HTMLToPDFLocalOwnedV1(ctx, "<html>exact source</html>", PDFOptions{Assets: []FontAsset{}, MaxResponseBytes: 32}, coordinator, org)
			if result != nil || !errors.Is(err, ErrHTMLLocalIOV1) || requests.Load() != 0 || callbacks.Load() != 0 {
				t.Fatal("unsupported callback/configuration dispatched", result, err, requests.Load(), callbacks.Load())
			}
			if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
				t.Fatal("unsupported configuration acquired ownership", got)
			}
		})
	}
}
func TestHTMLLocalPDFV1PrivateReplayFrameRetainsBodyUntilOwnerJoin(t *testing.T) {
	raw := []byte("actual original multipart retry frame")
	owner := newHTMLLocalReplayFrameV1(raw)
	first, err := owner.bodyV1()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(first)
	if err != nil || !bytes.Equal(actual, raw) {
		t.Fatal("first frame changed", err)
	}
	_ = first.Close()
	replay, err := owner.bodyV1()
	if err != nil {
		t.Fatal("body close disabled original transparent replay", err)
	}
	second, err := io.ReadAll(replay)
	if err != nil || !bytes.Equal(second, raw) {
		t.Fatal("safe original replay changed", err)
	}
	owner.closeV1()
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("private owner did not erase actual frame")
	}
	if _, err = owner.bodyV1(); err == nil {
		t.Fatal("captured GetBody reopened a retired original frame")
	}
	if _, err = replay.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("old replay reader retained source authority", err)
	}
}
