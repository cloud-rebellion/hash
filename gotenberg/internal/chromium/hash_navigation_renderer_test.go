//go:build renderer_e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
)

type hashNavigationRendererWitness struct {
	frame, loader, request  string
	bound, finished, failed bool
	failure                 uint8
	flags                   uint8
}

type hashNavigationRendererFailure struct {
	request   string
	document  bool
	truncated bool
}

// Record only synthetic protocol IDs and closed booleans, never URLs/headers.
// The bounded channel must not block the genuine target event loop.
type hashNavigationCaptureHandler struct {
	slog.Handler
	witnesses chan<- hashNavigationRendererWitness
	failures  chan<- hashNavigationRendererFailure
	bound     chan<- hashNavigationRendererWitness
	state     *hashNavigationCaptureState
}

type hashNavigationCaptureState struct {
	overflow  atomic.Bool
	terminals atomic.Int64
	bindings  atomic.Int64
}

func (s *hashNavigationCaptureState) check(t *testing.T) {
	t.Helper()
	if s == nil || s.overflow.Load() || s.terminals.Load() != 1 || s.bindings.Load() > 1 {
		t.Fatal("navigation diagnostic capture incomplete, duplicated or overflowed")
	}
}

func (h hashNavigationCaptureHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "hash main document navigation witness" || r.Message == "hash main document navigation bound" {
		var w hashNavigationRendererWitness
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "frame_id":
				w.frame = a.Value.String()
			case "loader_id":
				w.loader = a.Value.String()
			case "request_id":
				w.request = a.Value.String()
			case "bound":
				w.bound = a.Value.Bool()
			case "loading_finished":
				w.finished = a.Value.Bool()
			case "failed":
				w.failed = a.Value.Bool()
			case "loading_failure_class":
				w.failure = uint8(a.Value.Uint64())
			case "lifecycle_flags":
				w.flags = uint8(a.Value.Uint64())
			}
			return true
		})
		channel := h.witnesses
		if r.Message == "hash main document navigation bound" {
			channel = h.bound
			if h.state != nil {
				h.state.bindings.Add(1)
			}
		} else if h.state != nil {
			h.state.terminals.Add(1)
		}
		if channel != nil {
			select {
			case channel <- w:
			default:
				if h.state != nil {
					h.state.overflow.Store(true)
				}
			}
		}
	}
	if h.failures != nil && strings.HasPrefix(r.Message, "event EventLoadingFailed fired: ") {
		f := hashNavigationRendererFailure{truncated: r.Message == "event EventLoadingFailed fired: net::ERR_CONTENT_LENGTH_MISMATCH"}
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "request_id":
				f.request = a.Value.String()
			case "resource_type":
				f.document = a.Value.String() == "Document"
			}
			return true
		})
		select {
		case h.failures <- f:
		default:
			if h.state != nil {
				h.state.overflow.Store(true)
			}
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h hashNavigationCaptureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.Handler = h.Handler.WithAttrs(attrs)
	return h
}
func (h hashNavigationCaptureHandler) WithGroup(name string) slog.Handler {
	h.Handler = h.Handler.WithGroup(name)
	return h
}

func hashTakeNavigationWitness(t *testing.T, ch <-chan hashNavigationRendererWitness) hashNavigationRendererWitness {
	t.Helper()
	select {
	case w := <-ch:
		return w
	default:
		t.Fatal("main document protocol witness absent")
		return hashNavigationRendererWitness{}
	}
}

// Match the production HTML route's per-request working-directory allowance;
// never let an error-page PDF satisfy an ordinary file rendering fixture.
func hashGenuinePDFOptions(dir string) PdfOptions {
	o := DefaultPdfOptions()
	o.AllowedFilePrefixes = []string{dir}
	return o
}
func hashGenuineScreenshotOptions(dir string) ScreenshotOptions {
	o := DefaultScreenshotOptions()
	o.AllowedFilePrefixes = []string{dir}
	return o
}

func TestHashNavigationGenuineMainRequestAdmission(t *testing.T) {
	iframeRequested := make(chan struct{})
	var iframeOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/rejected", http.StatusFound)
		case "/rejected":
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "<!doctype html><p>Hash rejected main document</p>")
		case "/iframe":
			_, _ = io.WriteString(w, `<!doctype html><p>Hash complete main document</p><iframe src="/frame-truncated"></iframe>`)
		case "/frame-truncated":
			iframeOnce.Do(func() { close(iframeRequested) })
			w.Header().Set("Content-Length", "1000")
			_, _ = io.WriteString(w, "<!doctype html><p>Short iframe")
		default:
			_, _ = io.WriteString(w, "<!doctype html><p>Hash subsequent complete document</p>")
		}
	}))
	t.Cleanup(server.Close)
	args := hashNewGenuineBrowser(t).arguments
	localRoot := t.TempDir()
	localPrefix := (&url.URL{Scheme: "file", Path: localRoot}).String()
	args.allowList = []*regexp2.Regexp{regexp2.MustCompile(`^`+regexp.QuoteMeta(server.URL)+`(?:/|$)`, 0), regexp2.MustCompile(`^`+regexp.QuoteMeta(localPrefix)+`/`, 0)} // exact fixture-only origin and owned-file allowance
	args.denyList = nil
	b := newChromiumBrowser(args).(*chromiumBrowser)
	s := newHashProcessSupervisor(testLogger(), "chromium", b, 0, 2, 1, 0)
	t.Cleanup(func() {
		if err := s.Shutdown(); err != nil {
			t.Error(err)
		}
	})
	if err := s.Launch(); err != nil {
		t.Fatal(err)
	}
	mod := hashPublicModuleWithSupervisor(t, b, s)
	api, err := mod.Chromium()
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := hashTargetSnapshot(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, path  string
		idle        bool
		refuse      bool
		blockedFile bool
	}{
		{"redirected-main-status", "/redirect", false, true, false},
		{"iframe-framing-failure-separate-policy", "/iframe", false, false, false},
		{"subsequent-complete-main-both-idle-events", "/next", true, false, false},
		{"blocked-main-file", "", false, true, true},
		{"fast-local-file", "", false, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			u := server.URL + c.path
			if c.path == "" {
				path := filepath.Join(localRoot, "index.html")
				if err := os.WriteFile(path, []byte("<!doctype html><p>Hash fast local document</p>"), 0o600); err != nil {
					t.Fatal(err)
				}
				u = (&url.URL{Scheme: "file", Path: path}).String()
			}
			witnesses := make(chan hashNavigationRendererWitness, 2)
			failures := make(chan hashNavigationRendererFailure, 8)
			captureState := &hashNavigationCaptureState{}
			logger := slog.New(hashNavigationCaptureHandler{Handler: slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}), witnesses: witnesses, failures: failures, state: captureState})
			options := DefaultPdfOptions()
			if c.path == "" && !c.blockedFile {
				options.AllowedFilePrefixes = []string{localRoot}
			}
			options.FailOnHttpStatusCodes = []int64{404}
			options.SkipNetworkIdleEvent, options.SkipNetworkAlmostIdleEvent = !c.idle, !c.idle
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			output := filepath.Join(dir, "result.pdf")
			err := api.Pdf(ctx, logger, u, output, options)
			w := hashTakeNavigationWitness(t, witnesses)
			captureState.check(t)
			t.Logf("main request witness: bound=%t frame=%s loader=%s request=%s finished=%t failed=%t result=%v", w.bound, w.frame, w.loader, w.request, w.finished, w.failed, err)
			if ctx.Err() != nil {
				t.Fatal("navigation criterion masked by caller deadline")
			}
			if c.refuse {
				want := ErrInvalidHttpStatusCode
				if c.blockedFile {
					want = ErrLoadingFailed
				}
				if !errors.Is(err, want) {
					t.Fatal("redirected rejected main response accepted: ", err)
				}
				if c.blockedFile && w.failure != 5 {
					t.Fatal("blocked main file did not witness request-policy denial")
				}
				if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("rejected main response wrote output")
				}
			} else if err != nil || !w.bound || !w.finished || w.failed || w.frame == "" || w.loader == "" || w.request == "" {
				t.Fatal("complete main document not admitted: ", err)
			} else {
				hashAssertOutput(t, output, "pdf") // ordinary output smoke, not glyph proof
			}
			if c.idle && w.flags&15 != 15 {
				t.Fatal("both genuine keyed idle events not observed")
			}
			if c.path == "/iframe" {
				select {
				case <-iframeRequested:
				default:
					t.Fatal("truncated iframe was not requested")
				}
				observed := false
			drain:
				for {
					select {
					case f := <-failures:
						if f.document && f.truncated && f.request != "" && f.request != w.request {
							observed = true
							t.Logf("actual separate iframe framing failure request=%s", f.request)
						}
					default:
						break drain
					}
				}
				if !observed {
					t.Fatal("iframe case did not witness an actual separate document framing failure")
				}
			}
			after, err := hashTargetSnapshot(b)
			if err != nil || len(after) != len(baseline) {
				t.Fatal("conversion target cleanup unconfirmed: ", err)
			}
			for id, u := range baseline {
				if after[id] != u {
					t.Fatal("conversion changed baseline target")
				}
			}
			if !c.refuse {
				pdf, err := os.ReadFile(output)
				if err != nil || len(pdf) > 8<<20 {
					t.Fatal("bounded synthetic PDF export: ", err)
				}
				expected := "Hash subsequent complete document"
				if c.path == "/iframe" {
					expected = "Hash complete main document"
				}
				if c.path == "" {
					expected = "Hash fast local document"
				}
				meta, err := json.Marshal(struct {
					ExpectedText string `json:"expectedText"`
					Frame        string `json:"frame"`
					Loader       string `json:"loader"`
					Request      string `json:"request"`
					Flags        uint8  `json:"flags"`
				}{expected, w.frame, w.loader, w.request, w.flags})
				if err != nil {
					t.Fatal(err)
				}
				for suffix, data := range map[string][]byte{".pdf": pdf, ".json": meta} {
					if err := os.WriteFile(filepath.Join("/tmp/hash-navigation-outputs", c.name+suffix), data, 0o600); err != nil {
						t.Fatal("synthetic navigation output export: ", err)
					}
				}
			}
		})
	}
}
