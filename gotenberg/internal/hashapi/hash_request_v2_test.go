// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package api

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
	"github.com/labstack/echo/v4"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"log/slog"
	"mime/multipart"
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
)

func hashLifecycleEchoV2(t *testing.T) *echo.Echo {
	t.Helper()
	e := echo.New()
	e.HTTPErrorHandler = httpErrorHandler()
	e.Pre(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("logger", slog.New(slog.DiscardHandler))
			c.Set("outputFilename", c.Request().Header.Get("Gotenberg-Output-Filename"))
			return next(c)
		}
	})
	return e
}
func hashLifecycleFSV2(t *testing.T) *gotenberg.FileSystem {
	t.Helper()
	fs := gotenberg.NewFileSystem(new(gotenberg.OsMkdirAll))
	t.Cleanup(func() {
		if err := os.RemoveAll(fs.WorkingDirPath()); err != nil {
			t.Error(err)
		}
	})
	return fs
}
func hashAddMultipartRouteV2(e *echo.Echo, fs *gotenberg.FileSystem, path string, timeout, hard time.Duration, h echo.HandlerFunc) {
	e.POST(path, h, contextMiddleware(fs, timeout, 0, downloadFromConfig{disable: true}), hardTimeoutMiddleware(hard))
}
func hashMultipartBytesV2(t *testing.T, filename string) ([]byte, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	part, err := w.CreateFormFile("files", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(part, "owned input"); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes(), w.FormDataContentType()
}
func hashRetiredRegistryV2(t *testing.T, s *hashAPIServerV1) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		s.pruneRequestsV2()
		count, leases := s.requests, s.multipart
		s.mu.Unlock()
		if count == 0 && leases == 0 {
			return
		}
		if time.Now().After(until) {
			t.Fatalf("registry not retired requests=%d multipart=%d", count, leases)
		}
		time.Sleep(time.Millisecond)
	}
}

type hashCountingBodyV2 struct {
	r                    io.Reader
	reads, bytes, closes int
	closeErr             error
}

func (b *hashCountingBodyV2) Read(p []byte) (int, error) {
	b.reads++
	n, e := b.r.Read(p)
	b.bytes += n
	return n, e
}
func (b *hashCountingBodyV2) Close() error { b.closes++; return b.closeErr }

func TestHashLifecycleMultipartEntityBoundsV2(t *testing.T) {
	e, fs := hashLifecycleEchoV2(t), hashLifecycleFSV2(t)
	var calls atomic.Int32
	hashAddMultipartRouteV2(e, fs, "/multipart", time.Second, time.Second, func(c echo.Context) error {
		calls.Add(1)
		ctx := c.Get("context").(*Context)
		if _, err := os.Stat(filepath.Join(ctx.DirPath(), ".hash-entity.multipart")); !errors.Is(err, os.ErrNotExist) {
			return errors.New("staging body exposed as asset")
		}
		path := ctx.GeneratePath(".txt")
		if err := os.WriteFile(path, []byte("accepted"), 0o600); err != nil {
			return err
		}
		return ctx.AddOutputPaths(path)
	})
	s := hashListenerFixtureV1(t, e, time.Second, "", "")
	prefix := []byte("--hash-boundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nok\r\n--hash-boundary--\r\n")
	exact := append(append([]byte(nil), prefix...), bytes.Repeat([]byte("x"), int(hashMultipartEntityLimitV2)-len(prefix))...)
	cases := []struct {
		name    string
		data    []byte
		known   int64
		status  int
		maxRead int
	}{
		{"exact-with-epilogue", exact, -1, 200, int(hashMultipartEntityLimitV2)},
		{"known-oversize", nil, hashMultipartEntityLimitV2 + 1, 413, 0},
		{"unknown-epilogue-oversize", append(append([]byte(nil), exact...), 'x'), -1, 413, int(hashMultipartEntityLimitV2) + 1},
		{"malformed", []byte("not a multipart body"), -1, 400, 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := calls.Load()
			body := &hashCountingBodyV2{r: bytes.NewReader(tc.data)}
			req := httptest.NewRequest(http.MethodPost, "http://renderer.invalid/multipart", nil)
			req.Body = body
			req.ContentLength = tc.known
			req.Header.Set("Content-Type", "multipart/form-data; boundary=hash-boundary")
			rec := httptest.NewRecorder()
			s.server.Handler.ServeHTTP(rec, req)
			if rec.Code != tc.status || body.bytes > tc.maxRead || body.closes != 1 {
				t.Fatalf("status=%d read=%d closes=%d", rec.Code, body.bytes, body.closes)
			}
			if tc.status != 200 && calls.Load() != before {
				t.Fatal("rejected request entered handler")
			}
			hashRetiredRegistryV2(t, s)
		})
	}
}
func TestHashLifecycleStagingNameAndCacheIsolationV2(t *testing.T) {
	e, fs := hashLifecycleEchoV2(t), hashLifecycleFSV2(t)
	var calls atomic.Int32
	hashAddMultipartRouteV2(e, fs, "/multipart", time.Second, time.Second, func(c echo.Context) error {
		calls.Add(1)
		ctx := c.Get("context").(*Context)
		data, err := os.ReadFile(filepath.Join(ctx.DirPath(), ".hash-entity.multipart"))
		if err != nil || string(data) != "owned input" {
			return errors.New("uploaded asset was shadowed by staged entity")
		}
		return ErrNoOutputFile
	})
	s := hashListenerFixtureV1(t, e, time.Second, "", "")
	data, contentType := hashMultipartBytesV2(t, ".hash-entity.multipart")
	req := httptest.NewRequest(http.MethodPost, "http://renderer.invalid/multipart", bytes.NewReader(data))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rec, req)
	if rec.Code != 200 || calls.Load() != 1 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	hashRetiredRegistryV2(t, s)
	// A cached form cannot bypass staging; its disk-backed resources are adopted.
	cached := httptest.NewRequest(http.MethodPost, "http://renderer.invalid/multipart", bytes.NewReader(data))
	cached.Header.Set("Content-Type", contentType)
	if err := cached.ParseMultipartForm(1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cached.MultipartForm.RemoveAll(); err != nil {
			t.Error(err)
		}
	})
	file, err := cached.MultipartForm.File["files"][0].Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	tmp, ok := file.(*os.File)
	if !ok {
		t.Fatal("expected disk backed fixture")
	}
	name := tmp.Name()
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rec, cached)
	if rec.Code != 400 || calls.Load() != 1 {
		t.Fatal("cached form bypassed guard", rec.Code)
	}
	if _, err = os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cached spill not cleaned", err)
	}
	hashRetiredRegistryV2(t, s)
}
func TestHashLifecycleHeldHandlerRetainsWorkspaceAndAdmissionV2(t *testing.T) {
	e, fs := hashLifecycleEchoV2(t), hashLifecycleFSV2(t)
	type entered struct {
		ctx  *Context
		echo echo.Context
		late chan error
	}
	first, second := make(chan entered, 1), make(chan entered, 1)
	release1, release2 := make(chan struct{}), make(chan struct{})
	var once1, once2 sync.Once
	release := func() { once1.Do(func() { close(release1) }); once2.Do(func() { close(release2) }) }
	defer release()
	add := func(path string, hard time.Duration, ch chan entered, gate <-chan struct{}) {
		hashAddMultipartRouteV2(e, fs, path, time.Second, hard, func(c echo.Context) error {
			ctx := c.Get("context").(*Context)
			late := make(chan error, 1)
			ch <- entered{ctx, c, late}
			<-gate
			_, readErr := os.ReadFile(ctx.files["input.txt"])
			if path == "/one" {
				if ctx.OutputFilename("x.txt") != "first.txt" {
					readErr = errors.New("pooled filename changed")
				}
				if ctx.Request().Header.Get("Gotenberg-Output-Filename") != "first" {
					readErr = errors.New("pooled request changed")
				}
				c.Response().Header().Set("X-Late", "private")
				_, writeErr := c.Response().Writer.Write([]byte("late"))
				flushErr := http.NewResponseController(c.Response().Writer).Flush()
				if !errors.Is(writeErr, http.ErrHandlerTimeout) || !errors.Is(flushErr, http.ErrHandlerTimeout) {
					readErr = errors.Join(readErr, errors.New("late output escaped"))
				}
			}
			late <- readErr
			return ErrNoOutputFile
		})
	}
	add("/one", 30*time.Millisecond, first, release1)
	add("/two", time.Second, second, release2)
	s := hashListenerFixtureV1(t, e, time.Second, "", "")
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	data, contentType := hashMultipartBytesV2(t, "input.txt")
	var callers []chan struct{}
	t.Cleanup(func() {
		release()
		tr.CloseIdleConnections()
		for _, done := range callers {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("caller not joined")
			}
		}
	})
	do := func(path, filename string) chan error {
		result := make(chan error, 1)
		joined := make(chan struct{})
		callers = append(callers, joined)
		go func() {
			defer close(joined)
			req, _ := http.NewRequest(http.MethodPost, "http://"+s.listener.Addr().String()+path, bytes.NewReader(data))
			req.Header.Set("Content-Type", contentType)
			req.Header.Set("Gotenberg-Output-Filename", filename)
			res, err := client.Do(req)
			if err == nil {
				_, readErr := io.ReadAll(res.Body)
				err = errors.Join(readErr, res.Body.Close())
				if path == "/one" && res.StatusCode != 503 {
					err = errors.Join(err, errors.New("hard timeout not503"))
				}
			}
			result <- err
		}()
		return result
	}
	done1 := do("/one", "first")
	var held1 entered
	select {
	case held1 = <-first:
	case <-time.After(time.Second):
		t.Fatal("first not entered")
	}
	select {
	case err := <-done1:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("hard timeout did not answer")
	}
	if _, err := os.Stat(held1.ctx.DirPath()); err != nil {
		t.Fatal("workspace deleted while handler active", err)
	}
	done2 := do("/two", "second")
	var held2 entered
	select {
	case held2 = <-second:
	case <-time.After(time.Second):
		t.Fatal("second not entered")
	}
	if held1.echo == held2.echo {
		t.Fatal("active Echo context reused")
	}
	body := &hashCountingBodyV2{r: bytes.NewReader(data)}
	req := httptest.NewRequest(http.MethodPost, "http://renderer.invalid/two", nil)
	req.Body = body
	req.ContentLength = -1
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(rec, req)
	if rec.Code != 429 || body.reads != 0 {
		t.Fatalf("admission status=%d reads=%d", rec.Code, body.reads)
	}
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := s.stop(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("held worker passed Stop", err)
	}
	cancel()
	release()
	for _, info := range []entered{held1, held2} {
		select {
		case err := <-info.late:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("late callback not joined")
		}
	}
	select {
	case err := <-done2:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second caller not joined")
	}
	hashRetiredRegistryV2(t, s)
	if _, err := os.Stat(held1.ctx.DirPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("workspace not removed after retirement", err)
	}
}

type hashBlockingDrainWriterV2 struct {
	header                   http.Header
	entered, release, exited chan struct{}
	once                     sync.Once
	writes                   atomic.Int32
	readDeadlines            atomic.Int32
}

func (w *hashBlockingDrainWriterV2) Header() http.Header { return w.header }
func (w *hashBlockingDrainWriterV2) WriteHeader(int)     {}
func (w *hashBlockingDrainWriterV2) Write(p []byte) (int, error) {
	w.writes.Add(1)
	close(w.entered)
	<-w.release
	close(w.exited)
	return 0, os.ErrDeadlineExceeded
}
func (w *hashBlockingDrainWriterV2) SetReadDeadline(time.Time) error {
	w.readDeadlines.Add(1)
	w.once.Do(func() { close(w.release) })
	return nil
}
func (w *hashBlockingDrainWriterV2) SetWriteDeadline(time.Time) error { return nil }
func TestHashLifecycleAbortJoinsBlockedDrainAndGatesControlsV2(t *testing.T) {
	raw := &hashBlockingDrainWriterV2{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	s := &hashAPIServerV1{changed: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "http://renderer.invalid/", nil).WithContext(ctx)
	done := make(chan any, 1)
	callerDone := make(chan struct{})
	var gate *hashResponseV2
	go func() {
		defer close(callerDone)
		defer func() { done <- recover() }()
		s.serveOwnedV2(raw, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gate = w.(*hashResponseV2)
			_, _ = w.Write([]byte("blocked"))
		}))
	}()
	t.Cleanup(func() {
		cancel()
		raw.once.Do(func() { close(raw.release) })
		select {
		case <-callerDone:
		case <-time.After(2 * time.Second):
			t.Error("outer caller not joined")
		}
	})
	select {
	case <-raw.entered:
	case <-time.After(time.Second):
		t.Fatal("write not entered")
	}
	cancel()
	select {
	case value := <-done:
		if value != http.ErrAbortHandler {
			t.Fatal(value)
		}
	case <-time.After(time.Second):
		t.Fatal("abort deadlocked on unread body drain")
	}
	select {
	case <-raw.exited:
	default:
		t.Fatal("outer returned with raw I/O alive")
	}
	if raw.readDeadlines.Load() == 0 {
		t.Fatal("read deadline not expired")
	}
	if err := http.NewResponseController(gate).SetWriteDeadline(time.Now().Add(time.Hour)); !errors.Is(err, http.ErrHandlerTimeout) {
		t.Fatal("late deadline extension accepted", err)
	}
	gate.Header().Set("X-Late", "private")
	if _, err := gate.Write([]byte("late")); !errors.Is(err, http.ErrHandlerTimeout) {
		t.Fatal(err)
	}
	if raw.header.Get("X-Late") != "" || raw.writes.Load() != 1 {
		t.Fatal("late transport access")
	}
	hashRetiredRegistryV2(t, s)
}
func TestHashLifecycleCleanupFailureQuarantinesV2(t *testing.T) {
	for _, panicCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panicCleanup], func(t *testing.T) {
			later := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				o := hashRequestFromV2(r)
				if !o.reserveMultipart() {
					panic("fixture lease")
				}
				o.addCleanup(func() error { later = true; return nil })
				o.addCleanup(func() error {
					if panicCleanup {
						panic("cleanup")
					}
					return errors.New("injected close uncertainty")
				})
				w.Header().Set("Content-Length", "10000")
				_, _ = w.Write(bytes.Repeat([]byte("x"), 10000))
			})
			srv := &http.Server{Addr: "127.0.0.1:0", ReadTimeout: time.Second, WriteTimeout: 2 * time.Second}
			s, err := startHashAPIServerV1(srv, handler, "", "")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = s.stop(ctx)
				select {
				case <-s.done:
				default:
					t.Error("serving goroutine not joined")
				}
				s.mu.Lock()
				connections := len(s.connections)
				for o := range s.owners {
					select {
					case <-o.done:
					default:
						t.Error("quarantined worker still active")
					}
				}
				s.mu.Unlock()
				if connections != 0 {
					t.Error("connection remains")
				}
			})
			tr := &http.Transport{}
			defer tr.CloseIdleConnections()
			res, err := (&http.Client{Transport: tr, Timeout: time.Second}).Get("http://" + s.listener.Addr().String())
			if err == nil {
				_, err = io.ReadAll(res.Body)
				_ = res.Body.Close()
				if res.StatusCode != 200 {
					t.Fatal("committed status was rewritten", res.StatusCode)
				}
			}
			if err == nil {
				t.Fatal("uncertain cleanup yielded a complete successful body")
			}
			stop, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if err := s.stop(stop); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("quarantined Stop accepted", err)
			}
			s.mu.Lock()
			leases, count := s.multipart, s.requests
			s.mu.Unlock()
			if !later || leases != 1 || count != 1 || s.healthV2() == nil {
				t.Fatal("cleanup uncertainty refunded", later, leases, count)
			}
		})
	}
}
func TestHashLifecycleDeadlineControlsThroughOwnedHTTPV2(t *testing.T) {
	s := hashListenerFixtureV1(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := http.NewResponseController(w)
		if c.SetReadDeadline(time.Now().Add(time.Second)) != nil || c.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
			http.Error(w, "deadline guards unavailable", 503)
			return
		}
		_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 2<<20))
		w.WriteHeader(204)
	}), time.Second, "", "")
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	res, err := (&http.Client{Transport: tr, Timeout: time.Second}).Post("http://"+s.listener.Addr().String(), "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, res.Body)
	closeErr := res.Body.Close()
	if res.StatusCode != 204 || readErr != nil || closeErr != nil {
		t.Fatal("private deadline composition", res.StatusCode, readErr, closeErr)
	}
	hashRetiredRegistryV2(t, s)
}
func TestHashLifecycleArchiveAndOutputConfinementV2(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "private.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte(filepath.Base(p)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := &Context{dirPath: dir, Context: context.Background(), logger: slog.New(slog.DiscardHandler), outputPaths: []string{a, b}}
	archive, err := ctx.BuildOutputFile()
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) != 2 {
		t.Fatal("archive lost output")
	}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(r)
		closeErr := r.Close()
		if readErr != nil || closeErr != nil || string(data) != f.Name {
			t.Fatal("archive content", f.Name, readErr, closeErr)
		}
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err = os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if f, err := ctx.openOutputV2(link); err == nil {
		f.Close()
		t.Fatal("symlink output escaped")
	}
	ctx.outputPaths = []string{a, link}
	if path, err := ctx.BuildOutputFile(); err == nil || path != "" {
		t.Fatal("archive followed external symlink")
	}
	if err = ctx.AddOutputPaths(dir + "-outside/file"); !errors.Is(err, ErrOutOfBoundsOutputPath) {
		t.Fatal("prefix sibling accepted", err)
	}
}

func TestHashLifecycleChunkedOverflowDoesNotQuarantineV2(t *testing.T) {
	e, fs := hashLifecycleEchoV2(t), hashLifecycleFSV2(t)
	var calls atomic.Int32
	hashAddMultipartRouteV2(e, fs, "/multipart", 5*time.Second, time.Second, func(c echo.Context) error { calls.Add(1); return ErrNoOutputFile })
	s := hashListenerFixtureV1(t, e, 5*time.Second, "", "")
	data := bytes.Repeat([]byte("x"), int(hashMultipartEntityLimitV2)+1)
	for range 2 {
		conn, err := net.DialTimeout("tcp", s.listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		header := "POST /multipart HTTP/1.1\r\nHost: renderer\r\nContent-Type: multipart/form-data; boundary=b\r\nTransfer-Encoding: chunked\r\n\r\n"
		_, err = io.WriteString(conn, header+fmt.Sprintf("%x\r\n", len(data)))
		if err == nil {
			_, err = conn.Write(data)
		}
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		_, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		connErr := conn.Close()
		if response.StatusCode != 413 || readErr != nil || closeErr != nil || connErr != nil {
			t.Fatal("overflow response", response.StatusCode, readErr, closeErr, connErr)
		}
		hashRetiredRegistryV2(t, s)
		if err = s.healthV2(); err != nil {
			t.Fatal("intentional aborted body drain quarantined capacity", err)
		}
	}
	data, contentType := hashMultipartBytesV2(t, "input.txt")
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Post("http://"+s.listener.Addr().String()+"/multipart", contentType, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if response.StatusCode != 200 || readErr != nil || closeErr != nil || calls.Load() != 1 {
		t.Fatal("recovery request", response.StatusCode, readErr, closeErr, calls.Load())
	}
	hashRetiredRegistryV2(t, s)
}
func hashH2HeadersV2(t *testing.T, f *http2.Framer, stream uint32, path string, end bool) {
	t.Helper()
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "renderer"}, {Name: ":path", Value: path}} {
		if err := enc.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: b.Bytes(), EndHeaders: true, EndStream: end}); err != nil {
		t.Fatal(err)
	}
}
func TestHashLifecycleH2BlockedWriteResetsOnlyStreamV2(t *testing.T) {
	e := hashLifecycleEchoV2(t)
	entered := make(chan struct{})
	e.GET("/blocked", func(c echo.Context) error {
		close(entered)
		_, err := c.Response().Writer.Write(bytes.Repeat([]byte("x"), 64<<10))
		return err
	}, hardTimeoutMiddleware(30*time.Millisecond))
	e.GET("/canary", func(c echo.Context) error { return c.NoContent(204) })
	s := hashListenerFixtureV1(t, e, 5*time.Second, "", "")
	conn, err := net.DialTimeout("tcp", s.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	f := http2.NewFramer(conn, conn)
	f.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err = f.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatal(err)
	}
	hashH2HeadersV2(t, f, 1, "/blocked", true)
	reset := false
	for !reset {
		frame, err := f.ReadFrame()
		if err != nil {
			t.Fatal("blocked stream did not reset", err)
		}
		switch x := frame.(type) {
		case *http2.SettingsFrame:
			if !x.IsAck() {
				if err = f.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *http2.RSTStreamFrame:
			if x.StreamID == 1 {
				reset = true
			}
		}
	}
	select {
	case <-entered:
	default:
		t.Fatal("handler never wrote")
	}
	hashH2HeadersV2(t, f, 3, "/canary", true)
	canary := false
	for !canary {
		frame, err := f.ReadFrame()
		if err != nil {
			t.Fatal("independent H2 stream failed", err)
		}
		switch x := frame.(type) {
		case *http2.MetaHeadersFrame:
			if x.StreamID == 3 && x.StreamEnded() {
				status := ""
				for _, field := range x.Fields {
					if field.Name == ":status" {
						status = field.Value
					}
				}
				if status != "204" {
					t.Fatal("canary status", status)
				}
				canary = true
			}
		case *http2.GoAwayFrame:
			t.Fatal("stream deadline closed whole connection")
		}
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	hashRetiredRegistryV2(t, s)
}

type hashPanickingBodyV2 struct{ io.Reader }

func (b *hashPanickingBodyV2) Close() error { panic("fixture body close panic") }

func TestHashLifecycleArbitraryBodyCloseFailureQuarantinesV2(t *testing.T) {
	for _, scenario := range []string{"error", "panic"} {
		t.Run(scenario, func(t *testing.T) {
			s := &hashAPIServerV1{changed: make(chan struct{}, 1)}
			var body io.ReadCloser = &hashCountingBodyV2{r: strings.NewReader(""), closeErr: errors.New("fixture close error")}
			if scenario == "panic" {
				body = &hashPanickingBodyV2{Reader: strings.NewReader("")}
			}
			req := httptest.NewRequest(http.MethodGet, "http://renderer.invalid/", nil)
			req.Body = body
			aborted := false
			func() {
				defer func() {
					if value := recover(); value != nil {
						if value != http.ErrAbortHandler {
							panic(value)
						}
						aborted = true
					}
				}()
				s.serveOwnedV2(httptest.NewRecorder(), req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !hashRequestFromV2(r).reserveMultipart() {
						panic("fixture admission")
					}
					w.WriteHeader(200)
				}))
			}()
			if !aborted || s.healthV2() == nil {
				t.Fatal("body close uncertainty completed normally", aborted)
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.requests != 1 || s.multipart != 1 || len(s.owners) != 1 {
				t.Fatal("uncertain body close refunded", s.requests, s.multipart)
			}
			for owner := range s.owners {
				select {
				case <-owner.done:
				default:
					t.Fatal("body close test left worker running")
				}
				if !owner.outerDone || !owner.quarantined || owner.endErr == nil {
					t.Fatal("missing sticky quarantine")
				}
			}
		})
	}
}

type hashTruncatingWriterV2 struct {
	*httptest.ResponseRecorder
	path        string
	truncateErr error
	once        sync.Once
}

func (w *hashTruncatingWriterV2) WriteHeader(status int) {
	w.once.Do(func() { w.truncateErr = os.Truncate(w.path, 0) })
	w.ResponseRecorder.WriteHeader(status)
}

func TestHashLifecycleShortOutputCannotCompleteNormallyV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "output.pdf")
	if err := os.WriteFile(path, []byte("%PDF-owned-output"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := hashLifecycleEchoV2(t)
	var outputErr error
	e.GET("/", func(c echo.Context) error {
		ctx := &Context{dirPath: dir, Context: c.Request().Context(), logger: slog.New(slog.DiscardHandler), echoCtx: c}
		outputErr = ctx.sendOutputV2(c, path)
		return outputErr
	})
	raw := &hashTruncatingWriterV2{ResponseRecorder: httptest.NewRecorder(), path: path}
	s := &hashAPIServerV1{changed: make(chan struct{}, 1)}
	aborted := false
	func() {
		defer func() {
			if value := recover(); value != nil {
				if value != http.ErrAbortHandler {
					panic(value)
				}
				aborted = true
			}
		}()
		s.serveOwnedV2(raw, httptest.NewRequest(http.MethodGet, "http://renderer.invalid/", nil), e)
	}()
	if raw.truncateErr != nil {
		t.Fatal(raw.truncateErr)
	}
	if !aborted || outputErr == nil {
		t.Fatal("short attachment completed normally", aborted, outputErr)
	}
	if raw.Code != 200 || raw.Body.Len() != 0 {
		t.Fatal("committed attachment rewritten", raw.Code, raw.Body.String())
	}
	if raw.Header().Get("Content-Length") != "" {
		t.Fatal("early response framing escaped cleanup fence")
	}
	hashRetiredRegistryV2(t, s)
	if s.healthV2() != nil {
		t.Fatal("known output failure incorrectly quarantined cleaned resources")
	}
}

func TestHashLifecycleMalformedWireBodyDoesNotQuarantineV2(t *testing.T) {
	e, fs := hashLifecycleEchoV2(t), hashLifecycleFSV2(t)
	var calls atomic.Int32
	hashAddMultipartRouteV2(e, fs, "/multipart", time.Second, time.Second, func(c echo.Context) error { calls.Add(1); return ErrNoOutputFile })
	s := hashListenerFixtureV1(t, e, 2*time.Second, "", "")
	for _, scenario := range []struct {
		name, chunk string
		truncate    bool
	}{
		{"invalid-footer", "1\r\nxNO", false},
		{"truncated-chunk", "3\r\nx", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", s.listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			header := "POST /multipart HTTP/1.1\r\nHost: renderer\r\nContent-Type: multipart/form-data; boundary=b\r\nTransfer-Encoding: chunked\r\n\r\n"
			if _, err = io.WriteString(conn, header+scenario.chunk); err != nil {
				t.Fatal(err)
			}
			if scenario.truncate {
				if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			res, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
			if err == nil {
				_, readErr := io.ReadAll(res.Body)
				closeErr := res.Body.Close()
				if (!scenario.truncate && res.StatusCode != 400) || (scenario.truncate && res.StatusCode != 400 && res.StatusCode != 503) || readErr != nil || closeErr != nil {
					t.Fatal("malformed body response", res.StatusCode, readErr, closeErr)
				}
			} else if !scenario.truncate || !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
				t.Fatal("malformed body not rejected promptly", err)
			}
			if err = conn.Close(); err != nil {
				t.Fatal(err)
			}
			hashRetiredRegistryV2(t, s)
			if s.healthV2() != nil || calls.Load() != 0 {
				t.Fatal("malformed input consumed capacity or dispatched", s.healthV2(), calls.Load())
			}
		})
	}
	data, contentType := hashMultipartBytesV2(t, "input.txt")
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	res, err := (&http.Client{Transport: tr, Timeout: time.Second}).Post("http://"+s.listener.Addr().String()+"/multipart", contentType, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(res.Body)
	closeErr := res.Body.Close()
	if res.StatusCode != 200 || readErr != nil || closeErr != nil || calls.Load() != 1 {
		t.Fatal("post-malformed recovery", res.StatusCode, readErr, closeErr, calls.Load())
	}
	hashRetiredRegistryV2(t, s)
}

func TestHashLifecycleH2StalledUploadUsesProcessingDeadlineV2(t *testing.T) {
	e, fs := hashLifecycleEchoV2(t), hashLifecycleFSV2(t)
	var calls atomic.Int32
	hashAddMultipartRouteV2(e, fs, "/multipart", 50*time.Millisecond, time.Second, func(c echo.Context) error { calls.Add(1); return ErrNoOutputFile })
	e.GET("/canary", func(c echo.Context) error { return c.NoContent(204) })
	s := hashListenerFixtureV1(t, e, 3*time.Second, "", "")
	conn, err := net.DialTimeout("tcp", s.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	f := http2.NewFramer(conn, conn)
	f.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err = f.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"}, {Name: ":authority", Value: "renderer"}, {Name: ":path", Value: "/multipart"}, {Name: "content-type", Value: "multipart/form-data; boundary=b"}} {
		if err = encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	ended := false
	for !ended {
		frame, err := f.ReadFrame()
		if err != nil {
			t.Fatal("stalled upload did not retire within processing deadline", err)
		}
		switch x := frame.(type) {
		case *http2.SettingsFrame:
			if !x.IsAck() {
				if err = f.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *http2.MetaHeadersFrame:
			if x.StreamID == 1 {
				for _, field := range x.Fields {
					if field.Name == ":status" && field.Value != "503" {
						t.Fatal("stalled upload status", field.Value)
					}
				}
				ended = x.StreamEnded()
			}
		case *http2.DataFrame:
			if x.StreamID == 1 {
				ended = x.StreamEnded()
			}
		case *http2.RSTStreamFrame:
			if x.StreamID == 1 {
				ended = true
			}
		case *http2.GoAwayFrame:
			t.Fatal("stalled stream closed independent transport")
		}
	}
	hashRetiredRegistryV2(t, s)
	if calls.Load() != 0 || s.healthV2() != nil {
		t.Fatal("stalled upload dispatched or poisoned capacity", calls.Load(), s.healthV2())
	}
	hashH2HeadersV2(t, f, 3, "/canary", true)
	ended = false
	for !ended {
		frame, err := f.ReadFrame()
		if err != nil {
			t.Fatal("canary after stalled upload", err)
		}
		switch x := frame.(type) {
		case *http2.MetaHeadersFrame:
			if x.StreamID == 3 {
				status := ""
				for _, field := range x.Fields {
					if field.Name == ":status" {
						status = field.Value
					}
				}
				if status != "204" || !x.StreamEnded() {
					t.Fatal("post-stall canary", status)
				}
				ended = true
			}
		case *http2.GoAwayFrame:
			t.Fatal("stalled upload lost connection")
		}
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	hashRetiredRegistryV2(t, s)
}

func TestHashLifecycleGeneratedAttachmentsRejectRangesV2(t *testing.T) {
	e, fs := hashLifecycleEchoV2(t), hashLifecycleFSV2(t)
	content := []byte("%PDF-owned-complete\n")
	hashAddMultipartRouteV2(e, fs, "/multipart", time.Second, time.Second, func(c echo.Context) error {
		ctx := c.Get("context").(*Context)
		path := ctx.GeneratePath(".pdf")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return err
		}
		return ctx.AddOutputPaths(path)
	})
	s := hashListenerFixtureV1(t, e, 2*time.Second, "", "")
	data, contentType := hashMultipartBytesV2(t, "input.txt")
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	for _, ranges := range []string{"bytes=0-1,4-5", "bytes=0-1", ""} {
		req, err := http.NewRequest(http.MethodPost, "http://"+s.listener.Addr().String()+"/multipart", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		if ranges != "" {
			req.Header.Set("Range", ranges)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(res.Body)
		closeErr := res.Body.Close()
		expected := 200
		if ranges != "" {
			expected = 400
		}
		if res.StatusCode != expected || readErr != nil || closeErr != nil {
			t.Fatal("range policy", ranges, res.StatusCode, readErr, closeErr)
		}
		if ranges == "" && !bytes.Equal(body, content) {
			t.Fatal("complete recovery attachment changed")
		}
		if ranges != "" && (strings.Contains(res.Header.Get("Content-Type"), "multipart/byteranges") || bytes.Contains(body, content)) {
			t.Fatal("partial output producer admitted")
		}
		hashRetiredRegistryV2(t, s)
		if s.healthV2() != nil {
			t.Fatal("range refusal poisoned clean capacity")
		}
	}
}

type hashDelayedDeadlineContextV2 struct {
	context.Context
	until time.Time
}

func (c *hashDelayedDeadlineContextV2) Deadline() (time.Time, bool) { return c.until, true }

type hashReadFuncV2 func([]byte) (int, error)

func (f hashReadFuncV2) Read(p []byte) (int, error) { return f(p) }

func TestHashLifecycleProcessingDeadlineDoesNotDependOnTimerCallbackV2(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		after   bool
		readErr error
	}{
		{"before-read", false, nil}, {"after-read-eof", true, io.EOF}, {"after-read-transport-timeout", true, os.ErrDeadlineExceeded},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			deadline := time.Unix(2000000000, 0)
			ctx := &hashDelayedDeadlineContextV2{Context: context.Background(), until: deadline}
			now := deadline.Add(time.Second)
			if scenario.after {
				now = deadline.Add(-time.Second)
			}
			reads := 0
			source := hashReadFuncV2(func(p []byte) (int, error) {
				reads++
				now = deadline.Add(time.Second)
				p[0] = 'x'
				return 1, scenario.readErr
			})
			r := hashProcessingReaderV2{ctx: ctx, source: source, input: true, now: func() time.Time { return now }}
			n, err := r.Read(make([]byte, 8))
			status, _ := ParseError(err)
			expectedN := 0
			if scenario.after {
				expectedN = 1
			}
			stillDeadline, _ := ctx.Deadline()
			if n != expectedN || reads != expectedN || !errors.Is(err, context.DeadlineExceeded) || status != 503 || ctx.Err() != nil || !stillDeadline.Equal(deadline) {
				t.Fatal("deadline depends on cancellation callback", n, reads, err, status, ctx.Err(), stillDeadline)
			}
		})
	}
}
