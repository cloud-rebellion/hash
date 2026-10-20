//go:build renderer_e2e

package chromium

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/dlclark/regexp2"
)

func TestHashProxyGenuineCONNECTRetirement(t *testing.T) {
	ownerEntered, ownerCanceled, ownerTerminal := make(chan struct{}), make(chan struct{}), make(chan struct{})
	decoyEntered, decoyCanceled, decoyTerminal := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseOwner, releaseDecoy := make(chan struct{}), make(chan struct{})
	var ownerRemote, decoyRemote string // published by each entered channel
	var ownerReleaseOnce, decoyReleaseOnce sync.Once
	finishOwner := func() { ownerReleaseOnce.Do(func() { close(releaseOwner) }) }
	finishDecoy := func() { decoyReleaseOnce.Do(func() { close(releaseDecoy) }) }
	const prefix = "<!doctype html><html><body><p>Hash real CONNECT held response</p>"
	const suffix = "</body></html>"
	var ownerBytes, decoyBytes int // published by their terminal channels
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var entered, canceled, terminal chan struct{}
		var release <-chan struct{}
		switch req.URL.Path {
		case "/owner":
			entered, canceled, terminal, release = ownerEntered, ownerCanceled, ownerTerminal, releaseOwner
		case "/decoy":
			entered, canceled, terminal, release = decoyEntered, decoyCanceled, decoyTerminal, releaseDecoy
		default:
			http.NotFound(w, req)
			return
		}
		defer close(terminal)
		if req.URL.Path == "/owner" {
			ownerRemote = req.RemoteAddr
		} else {
			decoyRemote = req.RemoteAddr
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Normal handler return must NOT make this prefix a complete chunked
		// response. Declare the full body so owner retirement proves framing
		// truncation, while releasing the independent decoy completes it.
		w.Header().Set("Content-Length", strconv.Itoa(len(prefix)+len(suffix)))
		written, err := io.WriteString(w, prefix)
		if err != nil || written != len(prefix) {
			t.Error("held prefix write failed")
			return
		}
		if req.URL.Path == "/owner" {
			ownerBytes = written
		} else {
			decoyBytes = written
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error("held prefix flush failed")
			return
		}
		close(entered)
		select {
		case <-req.Context().Done():
			close(canceled)
		case <-release:
			written, err := io.WriteString(w, suffix)
			if err != nil || written != len(suffix) {
				t.Error("complete suffix write failed")
				return
			}
			if req.URL.Path == "/owner" {
				ownerBytes += written
			} else {
				decoyBytes += written
			}
		}
	}))
	t.Cleanup(func() {
		finishOwner()
		finishDecoy()
		origin.Close()
		select {
		case <-ownerEntered:
			hashAwait(t, "TLS owner request handler terminal", ownerTerminal)
		default:
		}
		select {
		case <-decoyEntered:
			hashAwait(t, "TLS decoy request handler terminal", decoyTerminal)
		default:
		}
	})
	originURL := mustParseURL(t, origin.URL)
	var connects atomic.Int64
	type relay struct {
		done   chan struct{}
		errors [2]error // published only by done after both copies join
	}
	var relayMu sync.Mutex
	relays := make(map[string]*relay)
	// Longer than the entire public-call deadline: expiration cannot stand in
	// for owner retirement. Both exact relay outcomes are also checked below.
	corporate := hashNewProxyPeerWithDeadline(t, 90*time.Second, func(client net.Conn) {
		br := bufio.NewReader(client)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		} // preconnected browser socket may close before CONNECT
		if req.Method != http.MethodConnect || req.Host != originURL.Host {
			t.Error("unexpected genuine CONNECT authority")
			return
		}
		connects.Add(1)
		upstream, err := net.DialTimeout("tcp", originURL.Host, time.Second)
		if err != nil {
			t.Error(err)
			return
		}
		defer upstream.Close()
		ownedRelay := &relay{done: make(chan struct{})}
		relayMu.Lock()
		key := upstream.LocalAddr().String()
		if relays[key] != nil {
			relayMu.Unlock()
			t.Error("duplicate corporate socket identity")
			return
		}
		relays[key] = ownedRelay
		relayMu.Unlock()
		defer close(ownedRelay.done)
		if _, err := io.WriteString(client, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
			return
		}
		var copies sync.WaitGroup
		copies.Add(2)
		go func() { defer copies.Done(); defer upstream.Close(); _, ownedRelay.errors[0] = io.Copy(upstream, br) }()
		go func() { defer copies.Done(); defer client.Close(); _, ownedRelay.errors[1] = io.Copy(client, upstream) }()
		copies.Wait()
	})
	proxyURL := &url.URL{Scheme: "http", Host: corporate.listener.Addr().String()}
	newBrowser := func() (*Chromium, *chromiumBrowser) {
		args := hashNewGenuineBrowser(t).arguments
		args.allowList = []*regexp2.Regexp{regexp2.MustCompile(`^https://`+regexp.QuoteMeta(originURL.Host)+`(?:/|$)`, 0)}
		args.denyList = nil
		args.ignoreCertificateErrors = true              // explicit self-signed TLS fixture exception
		b := newChromiumBrowser(args).(*chromiumBrowser) // bind internal policy to fresh arguments
		b.pinningProxy.upstreamProxy = func(*url.URL) (*url.URL, error) { return proxyURL, nil }
		s := newHashProcessSupervisor(testLogger(), "chromium", b, 0, 2, 1, 0)
		t.Cleanup(func() {
			if err := s.Shutdown(); err != nil {
				t.Error("genuine browser shutdown: ", err)
			}
		})
		if err := s.Launch(); err != nil {
			t.Fatal(err)
		}
		return hashPublicModuleWithSupervisor(t, b, s), b
	}
	ownerMod, owner := newBrowser()
	decoyMod, decoy := newBrowser()
	ownerContext, decoyContext := owner.ctx, decoy.ctx
	ownerBrowser, decoyBrowser := chromedp.FromContext(owner.ctx).Browser, chromedp.FromContext(decoy.ctx).Browser
	decoyProcess := decoyBrowser.Process()
	canary := filepath.Join(decoy.userProfileDirPath, "hash-connect-independent-canary")
	if err := os.WriteFile(canary, []byte("independent"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	type call struct {
		done            chan struct{}
		result          chan error
		loadingFailures chan string
		navigation      chan hashNavigationRendererWitness
		bound           chan hashNavigationRendererWitness
		captureState    *hashNavigationCaptureState
		output          string
	}
	var calls []*call
	outputs := map[string]string{
		"owner": filepath.Join(t.TempDir(), "owner.pdf"),
		"decoy": filepath.Join(t.TempDir(), "decoy.pdf"),
	}
	t.Cleanup(func() {
		cancel()
		finishOwner()
		finishDecoy()
		for _, c := range calls {
			select {
			case <-c.done:
			case <-time.After(3 * time.Second):
				t.Error("genuine public conversion cleanup did not join: ", c.output)
			}
		}
	})
	start := func(mod *Chromium, path string) *call {
		api, err := mod.Chromium()
		if err != nil {
			t.Fatal(err)
		}
		c := &call{done: make(chan struct{}), result: make(chan error, 1), loadingFailures: make(chan string, 8), navigation: make(chan hashNavigationRendererWitness, 2), bound: make(chan hashNavigationRendererWitness, 2), captureState: &hashNavigationCaptureState{}, output: outputs[path]}
		calls = append(calls, c)
		// Capture only synthetic Chromium load-error names, not URLs/headers.
		handler := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
			Level: slog.LevelDebug,
			ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
				const prefix = "event EventLoadingFailed fired: "
				if attr.Key == slog.MessageKey && attr.Value.Kind() == slog.KindString && strings.HasPrefix(attr.Value.String(), prefix) {
					select {
					case c.loadingFailures <- strings.TrimPrefix(attr.Value.String(), prefix):
					default:
					}
				}
				return attr
			},
		})
		logger := slog.New(hashNavigationCaptureHandler{Handler: handler, witnesses: c.navigation, bound: c.bound, state: c.captureState})
		go func() {
			defer close(c.done)
			c.result <- api.Pdf(ctx, logger, origin.URL+"/"+path, c.output, DefaultPdfOptions())
		}()
		return c
	}
	ownerCall, decoyCall := start(ownerMod, "owner"), start(decoyMod, "decoy")
	// Two genuine browsers share the fixture's one CPU. Its admission and
	// public print work need a larger witness wait than native socket barriers.
	await := func(label string, done <-chan struct{}) {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal(label, ": caller deadline expired")
		case <-timer.C:
			t.Fatal("genuine renderer witness timed out: ", label)
		}
	}
	awaitHeld := func(label string, entered <-chan struct{}, c *call) {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-entered:
		case <-c.done:
			t.Fatal(label, ": conversion ended before held origin: ", <-c.result)
		case <-timer.C:
			t.Fatal("genuine renderer admission timed out: ", label)
		}
	}
	awaitHeld("genuine owner TLS response held", ownerEntered, ownerCall)
	awaitHeld("genuine decoy TLS response held", decoyEntered, decoyCall)
	awaitBound := func(label string, c *call) {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case w := <-c.bound:
			if !w.bound || w.frame == "" || w.loader == "" || w.request == "" || w.finished || w.failed {
				t.Fatal(label, ": main held request not bound")
			}
		case <-c.done:
			t.Fatal(label, ": conversion ended before bound witness: ", <-c.result)
		case <-ctx.Done():
			t.Fatal(label, ": caller deadline expired")
		case <-timer.C:
			t.Fatal(label, ": main binding witness timed out")
		}
	}
	awaitBound("owner main held request", ownerCall)
	awaitBound("independent main held request", decoyCall)
	if connects.Load() < 2 {
		t.Fatal("browsers did not issue genuine corporate CONNECT requests")
	}
	relayMu.Lock()
	ownerRelay, decoyRelay := relays[ownerRemote], relays[decoyRemote]
	relayMu.Unlock()
	if ownerRemote == decoyRemote || ownerRelay == nil || decoyRelay == nil || ownerRelay == decoyRelay {
		t.Fatal("TLS requests did not bind distinct exact corporate sockets")
	}
	oldGeneration := hashProxyGenerationForTest(owner.pinningProxy)
	if ctx.Err() != nil {
		t.Fatal("public-call deadline expired before owner retirement")
	}
	for label, done := range map[string]<-chan struct{}{
		"owner relay": ownerRelay.done, "owner callback": ownerCall.done, "owner cancellation": ownerCanceled,
		"decoy relay": decoyRelay.done, "decoy callback": decoyCall.done, "decoy cancellation": decoyCanceled,
	} {
		select {
		case <-done:
			t.Fatal(label, " was already terminal before owner retirement")
		default:
		}
	}
	if err := owner.pinningProxy.Stop(testLogger()); err != nil {
		t.Fatal(err)
	}
	await("owner origin observes real tunnel cancellation", ownerCanceled)
	await("owner origin handler terminal", ownerTerminal)
	await("exact owner corporate relay and both copies terminal", ownerRelay.done)
	for _, err := range ownerRelay.errors {
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			t.Fatal("owner relay timeout cannot prove retirement: ", err)
		}
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal("owner relay did not terminate by EOF or owned close: ", err)
		}
	}
	await("owner proxy retirement terminal", oldGeneration.retirement.done)
	await("owner public callback terminal after tunnel retirement", ownerCall.done)
	if ctx.Err() != nil {
		t.Fatal("owner response failure was masked by the caller deadline")
	}
	ownerResult := <-ownerCall.result
	// Preserve the terminal witness even when the result is unexpectedly nil.
	ownerWitness := hashTakeNavigationWitness(t, ownerCall.navigation)
	ownerCall.captureState.check(t)
	t.Logf("owner main request terminal: bound=%t frame=%s loader=%s request=%s finished=%t failed=%t failure_class=%d written=%d declared=%d result=%v", ownerWitness.bound, ownerWitness.frame, ownerWitness.loader, ownerWitness.request, ownerWitness.finished, ownerWitness.failed, ownerWitness.failure, ownerBytes, len(prefix)+len(suffix), ownerResult)
	observedTruncation := ownerWitness.failure >= 1 && ownerWitness.failure <= 3
drainFailures:
	for {
		select {
		case name := <-ownerCall.loadingFailures:
			switch name {
			case "net::ERR_CONTENT_LENGTH_MISMATCH", "net::ERR_INCOMPLETE_CHUNKED_ENCODING", "net::ERR_INVALID_CHUNKED_ENCODING":
				observedTruncation = true
				t.Log("actual interrupted Chromium response: ", name)
			}
		default:
			break drainFailures
		}
	}
	if !observedTruncation {
		t.Fatal("owner refusal was not bound to an actual truncated response")
	}
	if !errors.Is(ownerResult, ErrLoadingFailed) || !ownerWitness.bound || ownerWitness.frame == "" || ownerWitness.loader == "" || ownerWitness.request == "" || ownerWitness.finished || !ownerWitness.failed || ownerWitness.failure < 1 || ownerWitness.failure > 3 || ownerBytes != len(prefix) {
		t.Fatal("interrupted owner did not refuse the exact short main response: ", ownerResult)
	}
	if _, err := os.Stat(ownerCall.output); !os.IsNotExist(err) {
		t.Fatal("interrupted owner conversion wrote PDF")
	}
	if owner.ctx != ownerContext || chromedp.FromContext(owner.ctx).Browser != ownerBrowser || ownerBrowser.Process().Signal(syscall.Signal(0)) != nil {
		t.Fatal("browser shutdown hid proxy retirement")
	}
	select {
	case <-decoyCanceled:
		t.Fatal("independent TLS request was canceled")
	default:
	}
	select {
	case <-decoyRelay.done:
		t.Fatal("independent exact corporate relay retired")
	default:
	}
	if decoy.ctx != decoyContext || chromedp.FromContext(decoy.ctx).Browser != decoyBrowser || decoyProcess == nil || decoyProcess.Signal(syscall.Signal(0)) != nil || !decoy.Healthy(testLogger()) {
		t.Fatal("owner proxy retirement changed independent browser")
	}
	if raw, err := os.ReadFile(canary); err != nil || string(raw) != "independent" {
		t.Fatal("independent profile changed")
	}
	finishDecoy()
	await("independent public PDF completed", decoyCall.done)
	if err := <-decoyCall.result; err != nil {
		t.Fatal(fmt.Errorf("independent public PDF: %w", err))
	}
	await("independent complete origin body terminal", decoyTerminal)
	decoyWitness := hashTakeNavigationWitness(t, decoyCall.navigation)
	decoyCall.captureState.check(t)
	if !decoyWitness.bound || !decoyWitness.finished || decoyWitness.failed || decoyWitness.request == "" || decoyBytes != len(prefix)+len(suffix) {
		t.Fatal("independent complete main request was not proven")
	}
	hashAssertOutput(t, decoyCall.output, "pdf") // output prefix, not pixel/structure proof
	if hashProxyGenerationForTest(decoy.pinningProxy) == nil {
		t.Fatal("independent proxy was retired")
	}
}
