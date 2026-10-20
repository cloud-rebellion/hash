package chromium

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/gotenberg/internal/hashapi"
	"github.com/labstack/echo/v4"
)

const hashRouteTestToken = "hash-synthetic-route-token-0123456789"

type hashRouteWriter struct {
	*httptest.ResponseRecorder
	readDeadline, writeDeadline time.Time
	readErr, writeErr           error
	writes                      int
}

func (w *hashRouteWriter) SetReadDeadline(d time.Time) error  { w.readDeadline = d; return w.readErr }
func (w *hashRouteWriter) SetWriteDeadline(d time.Time) error { w.writeDeadline = d; return w.writeErr }
func (w *hashRouteWriter) Write(b []byte) (int, error) {
	w.writes++
	return w.ResponseRecorder.Write(b)
}

type hashRouteReadWitness struct {
	reads int
	r     io.Reader
}

func (r *hashRouteReadWitness) Read(b []byte) (int, error) { r.reads++; return r.r.Read(b) }
func (r *hashRouteReadWitness) Close() error               { return nil }

func hashRouteRequestBytes(t *testing.T) (*hashSignatureMeasurePlan, *hashSignaturePDFPackage, []byte) {
	t.Helper()
	p, pack := hashSealTestPackage(t)
	raw, err := json.Marshal(hashSignaturePDFRequest{Schema: 1, Plan: *p, FontBytes: pack.font})
	if err != nil {
		t.Fatal("canonical request fixture")
	}
	return p, pack, raw
}

func hashRouteRequest(raw []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, hashSignaturePDFRoutePath, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+hashRouteTestToken)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func hashRouteInvoke(t *testing.T, route api.Route, r *http.Request) (*hashRouteWriter, error) {
	t.Helper()
	w := &hashRouteWriter{ResponseRecorder: httptest.NewRecorder()}
	err := route.Handler(echo.New().NewContext(r, w))
	return w, err
}

func TestHashSignaturePDFRouteStartupAdmissionAndRegistration(t *testing.T) {
	factory := func(context.Context, *slog.Logger, *hashSignatureMeasurePlan, []byte) (*hashSignaturePDFPackage, error) {
		t.Fatal("configuration called factory")
		return nil, nil
	}
	for _, tc := range []struct {
		name, token string
		budget      time.Duration
		valid       bool
	}{
		{"minimum-token", strings.Repeat("!", 32), 30 * time.Second, true},
		{"maximum-token", strings.Repeat("~", 128), 60 * time.Second, true},
		{"empty", "", 30 * time.Second, false},
		{"short", strings.Repeat("a", 31), 30 * time.Second, false},
		{"long", strings.Repeat("a", 129), 30 * time.Second, false},
		{"space", strings.Repeat("a", 31) + " ", 30 * time.Second, false},
		{"control", strings.Repeat("a", 31) + "\n", 30 * time.Second, false},
		{"delete", strings.Repeat("a", 31) + "\x7f", 30 * time.Second, false},
		{"non-ascii", strings.Repeat("a", 31) + "Å", 30 * time.Second, false},
		{"too-small-timeout", hashRouteTestToken, 15*time.Second - time.Nanosecond, false},
		{"unprovisioned-timeout", hashRouteTestToken, 0, false},
		{"overflowing-hard-timeout", hashRouteTestToken, time.Duration(1<<63-1) - 5*time.Second + time.Nanosecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := newHashSignaturePDFRoute(tc.token, tc.budget, factory)
			if tc.valid {
				if err != nil || r.Method != http.MethodPost || r.Path != hashSignaturePDFRoutePath || r.IsMultipart || !r.DisableTelemetry || r.Handler == nil {
					t.Fatal("closed route not configured")
				}
			} else if !errors.Is(err, errHashSignaturePDFRouteConfig) || err.Error() != "hash signature PDF route configuration is invalid" {
				t.Fatal("invalid configuration was admitted or echoed")
			}
		})
	}
	t.Setenv("HASH_SIGNATURE_FIT_TOKEN", hashRouteTestToken)
	mod := &Chromium{hashSignatureAPITimeout: 30 * time.Second}
	routes, err := mod.Routes()
	if err != nil || len(routes) != 8 || routes[6].Path != hashSignaturePDFRoutePath || routes[7].Path != "/hash/chromium/ordinary-page/v1" {
		t.Fatal("configured route absent")
	}
	if err := os.Unsetenv("HASH_SIGNATURE_FIT_TOKEN"); err != nil {
		t.Fatal("test environment")
	}
	routes, err = mod.Routes()
	if err != nil || len(routes) != 6 {
		t.Fatal("missing token did not omit route")
	}
	if err := os.Setenv("HASH_SIGNATURE_FIT_TOKEN", ""); err != nil {
		t.Fatal("test environment")
	}
	routes, err = mod.Routes()
	if err != nil || len(routes) != 6 {
		t.Fatal("configured blank token did not omit route")
	}
	if err := os.Setenv("HASH_SIGNATURE_FIT_TOKEN", "short"); err != nil {
		t.Fatal("test environment")
	}
	if _, err := mod.Routes(); !errors.Is(err, errHashSignaturePDFRouteConfig) {
		t.Fatal("configured invalid token admitted")
	}
	mod.disableRoutes = true
	if _, err := mod.Routes(); !errors.Is(err, errHashSignaturePDFRouteConfig) {
		t.Fatal("disabled routes bypassed invalid configuration")
	}
}

func TestHashSignaturePDFRouteAuthenticatesBeforeBodyRead(t *testing.T) {
	_, _, raw := hashRouteRequestBytes(t)
	for _, tc := range []struct {
		name    string
		headers []string
	}{
		{"missing", nil}, {"wrong-token", []string{"Bearer " + strings.Repeat("z", 32)}},
		{"lowercase-scheme", []string{"bearer " + hashRouteTestToken}},
		{"extra-space", []string{"Bearer  " + hashRouteTestToken}},
		{"trailing-space", []string{"Bearer " + hashRouteTestToken + " "}},
		{"duplicate", []string{"Bearer " + hashRouteTestToken, "Bearer " + hashRouteTestToken}},
		{"comma-list", []string{"Bearer " + hashRouteTestToken + ", Bearer " + hashRouteTestToken}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			route, err := newHashSignaturePDFRoute(hashRouteTestToken, 30*time.Second, func(context.Context, *slog.Logger, *hashSignatureMeasurePlan, []byte) (*hashSignaturePDFPackage, error) {
				calls++
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			r := hashRouteRequest(raw)
			r.Header.Del("Authorization")
			for _, h := range tc.headers {
				r.Header.Add("Authorization", h)
			}
			body := &hashRouteReadWitness{r: bytes.NewReader(raw)}
			r.Body = body
			w, err := hashRouteInvoke(t, route, r)
			if err != nil || w.Code != http.StatusUnauthorized || body.reads != 0 || calls != 0 || w.Body.String() != "hash signature PDF request refused\n" {
				t.Fatal("authentication read/published private input")
			}
		})
	}
}

func TestHashSignaturePDFRouteRefusesHostileClosedInputsBeforeFactory(t *testing.T) {
	_, _, raw := hashRouteRequestBytes(t)
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		body   []byte
		status int
	}{
		{"query", func(r *http.Request) { r.URL.RawQuery = "x=1" }, raw, 400},
		{"empty-query", func(r *http.Request) { r.URL.ForceQuery = true }, raw, 400},
		{"encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, raw, 400},
		{"empty-encoding", func(r *http.Request) { r.Header["Content-Encoding"] = []string{""} }, raw, 400},
		{"media-parameter", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, raw, 415},
		{"media-duplicate", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, raw, 415},
		{"method", func(r *http.Request) { r.Method = http.MethodGet }, raw, 405},
		{"declared-over-cap", func(r *http.Request) { r.ContentLength = hashSignaturePDFRequestLimit + 1 }, raw, 413},
		{"chunked-over-cap", func(r *http.Request) { r.ContentLength = -1 }, bytes.Repeat([]byte("x"), hashSignaturePDFRequestLimit+1), 413},
		{"leading-space", nil, append([]byte(" "), raw...), 400},
		{"trailing-space", nil, append(bytes.Clone(raw), '\n'), 400},
		{"duplicate", nil, bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1), 400},
		{"case-variant", nil, bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1), 400},
		{"missing-schema", nil, bytes.Replace(raw, []byte(`"schema":1,`), nil, 1), 400},
		{"null-schema", nil, bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":null`), 1), 400},
		{"wrong-schema", nil, bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":2`), 1), 400},
		{"null-plan", nil, []byte(`{"schema":1,"plan":null,"fontBytes":null}`), 400},
		{"unknown-html", nil, append([]byte(`{"html":"private-prose",`), raw[1:]...), 400},
		{"unknown-target-url", nil, bytes.Replace(raw, []byte(`"x":"0.05"`), []byte(`"url":"private-origin","x":"0.05"`), 1), 400},
		{"duplicate-target-key", nil, bytes.Replace(raw, []byte(`"x":"0.05"`), []byte(`"x":"0.05","x":"0.05"`), 1), 400},
		{"nested-case", nil, bytes.Replace(raw, []byte(`"text"`), []byte(`"Text"`), 1), 400},
		{"nested-null", nil, bytes.Replace(raw, []byte(`"targets":[`), []byte(`"targets":null,"extra":[`), 1), 400},
		{"trailing-value", nil, append(bytes.Clone(raw), []byte(`{}`)...), 400},
		{"font-bytes-changed", nil, bytes.Replace(raw, []byte(`"fontBytes":"`), []byte(`"fontBytes":"AA`), 1), 400},
		{"outside-target", nil, bytes.Replace(raw, []byte(`"w":"0.9"`), []byte(`"w":"1"`), 1), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			route, err := newHashSignaturePDFRoute(hashRouteTestToken, 30*time.Second, func(context.Context, *slog.Logger, *hashSignatureMeasurePlan, []byte) (*hashSignaturePDFPackage, error) {
				calls++
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			r := hashRouteRequest(tc.body)
			if tc.mutate != nil {
				tc.mutate(r)
			}
			w, err := hashRouteInvoke(t, route, r)
			if err != nil || w.Code != tc.status || calls != 0 || w.Body.String() != "hash signature PDF request refused\n" {
				t.Fatal("hostile input entered factory or error echoed input")
			}
		})
	}
}

func TestHashSignaturePDFRouteDeadlinePolicyAndExactPublication(t *testing.T) {
	p, pack, raw := hashRouteRequestBytes(t)
	for _, tc := range []struct {
		name                              string
		apiBudget, parentBudget, expected time.Duration
	}{
		{"default", 30 * time.Second, 0, 20 * time.Second},
		{"maximum-work", 2 * time.Minute, 0, 60 * time.Second},
		{"minimum-config", 15 * time.Second, 0, 5 * time.Second},
		{"original-deadline", 30 * time.Second, 3 * time.Second, 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := time.Now()
			calls := 0
			var factoryDeadline time.Time
			route, err := newHashSignaturePDFRoute(hashRouteTestToken, tc.apiBudget, func(ctx context.Context, _ *slog.Logger, plan *hashSignatureMeasurePlan, font []byte) (*hashSignaturePDFPackage, error) {
				calls++
				factoryDeadline, _ = ctx.Deadline()
				if ctx.Err() != nil || plan.inputSHA() != p.inputSHA() || !bytes.Equal(font, pack.font) {
					t.Fatal("factory input binding")
				}
				return pack, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			r := hashRouteRequest(raw)
			if tc.parentBudget > 0 {
				ctx, cancel := context.WithTimeout(r.Context(), tc.parentBudget)
				defer cancel()
				r = r.WithContext(ctx)
			}
			w, err := hashRouteInvoke(t, route, r)
			if err != nil || calls != 1 || w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), pack.Bytes()) || w.Header().Get("Content-Type") != hashSignaturePDFRouteMIME || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Length") != strconv.Itoa(len(pack.Bytes())) {
				t.Fatal("exact response binding")
			}
			if factoryDeadline.Before(before.Add(tc.expected-time.Second)) || factoryDeadline.After(time.Now().Add(tc.expected)) || w.readDeadline != factoryDeadline || w.writeDeadline.After(factoryDeadline) || w.writeDeadline.After(time.Now().Add(hashSignaturePDFRouteWriteLimit)) {
				t.Fatal("deadline widened")
			}
			if _, err := decodeHashSignaturePDFPackage(w.Body.Bytes(), p); err != nil {
				t.Fatal("published package invalid")
			}
		})
	}
}

func TestHashSignaturePDFRouteRefusesUnsupportedTransportBeforeReading(t *testing.T) {
	_, _, raw := hashRouteRequestBytes(t)
	calls := 0
	route, err := newHashSignaturePDFRoute(hashRouteTestToken, 30*time.Second, func(context.Context, *slog.Logger, *hashSignatureMeasurePlan, []byte) (*hashSignaturePDFPackage, error) {
		calls++
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r := hashRouteRequest(raw)
	body := &hashRouteReadWitness{r: bytes.NewReader(raw)}
	r.Body = body
	w := httptest.NewRecorder()
	err = route.Handler(echo.New().NewContext(r, w))
	if err == nil || err.Error() != "hash signature PDF response unavailable" || body.reads != 0 || calls != 0 || w.Body.Len() != 0 {
		t.Fatal("unsupported deadline transport admitted")
	}
}

type hashRouteFailRead struct{}

func (hashRouteFailRead) Read([]byte) (int, error) { return 0, errors.New("private-read-secret") }

func TestHashSignaturePDFRouteReadAndFactoryFailuresAreFixed(t *testing.T) {
	_, pack, raw := hashRouteRequestBytes(t)
	for _, mode := range []string{"read-error", "factory-error", "nil-package", "changed-package", "cancel-after-factory", "late-result"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			r := hashRouteRequest(raw)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			if mode == "late-result" {
				var c context.CancelFunc
				ctx, c = context.WithTimeout(r.Context(), 500*time.Millisecond)
				defer c()
			}
			r = r.WithContext(ctx)
			if mode == "read-error" {
				r.Body = &hashRouteReadWitness{r: hashRouteFailRead{}}
			}
			route, err := newHashSignaturePDFRoute(hashRouteTestToken, 30*time.Second, func(factoryCtx context.Context, _ *slog.Logger, _ *hashSignatureMeasurePlan, _ []byte) (*hashSignaturePDFPackage, error) {
				calls++
				switch mode {
				case "factory-error":
					return nil, errors.New("private-factory-secret")
				case "nil-package":
					return nil, nil
				case "changed-package":
					copy := &hashSignaturePDFPackage{pack.report, bytes.Clone(pack.pdf), pack.html, pack.font, pack.snapshot}
					copy.pdf[5] ^= 1
					return copy, nil
				case "cancel-after-factory":
					cancel()
				case "late-result":
					<-factoryCtx.Done()
				}
				return pack, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			w, err := hashRouteInvoke(t, route, r)
			if err != nil {
				t.Fatal("failure response unavailable")
			}
			if mode == "cancel-after-factory" || mode == "late-result" {
				if w.writes != 0 || w.Body.Len() != 0 {
					t.Fatal("canceled/late package published")
				}
			} else {
				want := http.StatusServiceUnavailable
				if mode == "read-error" {
					want = http.StatusBadRequest
				}
				if w.Code != want || w.Body.String() != "hash signature PDF request refused\n" {
					t.Fatal("private failure leaked or invalid package published")
				}
			}
			if mode == "read-error" && calls != 0 {
				t.Fatal("read error entered factory")
			}
			if mode == "late-result" && calls != 1 {
				t.Fatal("late-result fixture did not reach factory")
			}
		})
	}
}

type hashRouteUnwrapWriter struct{ http.ResponseWriter }

func (w hashRouteUnwrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestHashSignaturePDFRouteSupportsExplicitDeadlineUnwrap(t *testing.T) {
	_, pack, raw := hashRouteRequestBytes(t)
	calls := 0
	route, err := newHashSignaturePDFRoute(hashRouteTestToken, 30*time.Second, func(context.Context, *slog.Logger, *hashSignatureMeasurePlan, []byte) (*hashSignaturePDFPackage, error) {
		calls++
		return pack, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	w := &hashRouteWriter{ResponseRecorder: httptest.NewRecorder()}
	wrapped := hashRouteUnwrapWriter{ResponseWriter: hashRouteUnwrapWriter{ResponseWriter: w}}
	if err := route.Handler(echo.New().NewContext(hashRouteRequest(raw), wrapped)); err != nil || calls != 1 || !bytes.Equal(w.Body.Bytes(), pack.Bytes()) || w.readDeadline.IsZero() || w.writeDeadline.IsZero() {
		t.Fatal("explicit supported deadline unwrap refused")
	}
}

func TestHashSignaturePDFRouteOriginalCancellationAndEchoReuse(t *testing.T) {
	_, pack, raw := hashRouteRequestBytes(t)
	calls := 0
	route, err := newHashSignaturePDFRoute(hashRouteTestToken, 30*time.Second, func(context.Context, *slog.Logger, *hashSignatureMeasurePlan, []byte) (*hashSignaturePDFPackage, error) {
		calls++
		return pack, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r := hashRouteRequest(raw)
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	r = r.WithContext(ctx)
	body := &hashRouteReadWitness{r: bytes.NewReader(raw)}
	r.Body = body
	w, err := hashRouteInvoke(t, route, r)
	if err != nil || calls != 0 || body.reads != 0 || w.writes != 0 {
		t.Fatal("original cancellation ignored")
	}
	original := &hashRouteWriter{ResponseRecorder: httptest.NewRecorder()}
	recycled := &hashRouteWriter{ResponseRecorder: httptest.NewRecorder()}
	c := echo.New().NewContext(hashRouteRequest(raw), original)
	route, err = newHashSignaturePDFRoute(hashRouteTestToken, 30*time.Second, func(context.Context, *slog.Logger, *hashSignatureMeasurePlan, []byte) (*hashSignaturePDFPackage, error) {
		c.Reset(httptest.NewRequest(http.MethodGet, "/different", nil), recycled)
		return pack, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := route.Handler(c); err != nil || !bytes.Equal(original.Body.Bytes(), pack.Bytes()) || recycled.Body.Len() != 0 || recycled.writes != 0 {
		t.Fatal("pooled Echo context reused by preparation/publication")
	}
}
