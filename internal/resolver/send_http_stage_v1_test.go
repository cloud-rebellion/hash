// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSendHTTPStagesPreserveOriginalFetchDecisionsV1(t *testing.T) {
	cases := []struct {
		name, body, path string
		status           int
	}{
		{"text_plain_success", `{"value":"Approved & exact"}`, "value", 200},
		{"number_lexeme", `{"value":1e99999}`, "value", 202},
		{"escaped_nul", `{"value":"a\u0000b"}`, "value", 200},
		{"unpaired_utf16", `{"value":"\ud800"}`, "value", 200},
		{"subtree", `{"value":{"text":"<&>","items":[1e99999,true,null]}}`, "value", 200},
		{"array_path", `{"items":[{"value":"first"},{"value":"second"}]}`, "items.1.value", 206},
		{"missing_path", `{"other":1}`, "value", 200},
		{"null", `{"value":null}`, "value", 200},
		{"duplicate_decoded_key", `{"value":"first","\u0076alue":"second"}`, "value", 200},
		{"trailing", `{"value":"first"} {}`, "value", 200},
		{"invalid_utf8", "{\"value\":\"" + string([]byte{255}) + "\"}", "value", 200},
		{"root_array", `["value"]`, "value", 200},
		{"deep", strings.Repeat(`{"x":`, 66) + "1" + strings.Repeat("}", 66), "x", 200},
		{"empty_204", "", "value", 204},
		{"oversized", `{"value":"` + strings.Repeat("a", maxSourceResponseBytes) + `"}`, "value", 200},
		{"not_found", `{"private":"must not leak"}`, "value", 404},
		{"unavailable", `{"private":"must not leak"}`, "value", 503},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/v1/scans/exact-id" || r.Header.Get("Authorization") != "Bearer synthetic-token" || r.Header.Get("Accept") != "application/json" {
					t.Error("original source request changed")
				}
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			defer peer.Close()
			source := NewScannerFindingSource(peer.URL, "synthetic-token", true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ref := Ref{OrgID: uuid.New(), DocID: uuid.New(), Source: "exact-id", Path: c.path}
			expected, originalErr := source.Fetch(ctx, ref)
			stage, err := source.OpenSendReadV1(ctx, ref)
			got := ""
			if err == nil {
				defer stage.CloseV1()
				err = stage.ReadBodyV1()
				if err == nil {
					raw, viewErr := stage.BodyV1()
					if viewErr != nil {
						t.Fatal(viewErr)
					}
					// A caller's inspection projection cannot alter actual decoder bytes.
					for i := range raw {
						raw[i] = ' '
					}
					got, err = stage.DecodeValueV1()
					if _, replay := stage.DecodeValueV1(); !errors.Is(replay, ErrSendHTTPStageV1) {
						t.Fatal("decode replay admitted", replay)
					}
				}
			}
			if (err == nil) != (originalErr == nil) || got != expected {
				t.Fatalf("original%q/%v staged%q/%v", expected, originalErr, got, err)
			}
			if err != nil && originalErr != nil && err.Error() != originalErr.Error() {
				t.Fatalf("source error decision changed: original%v staged%v", originalErr, err)
			}
		})
	}
}
func TestSendHTTPStagesRefuseInvalidAndClosedOperationsV1(t *testing.T) {
	source := NewScannerFindingSource("http://unused.invalid", "synthetic-token")
	for _, id := range []string{"", ".", "..", "a/../b", "a?token=x", strings.Repeat("a", 257)} {
		if _, err := source.OpenSendReadV1(context.Background(), Ref{Source: id}); err == nil {
			t.Fatal("unsafe source ref admitted", id)
		}
	}
	var absent *SendHTTPReadV1
	if err := absent.ReadBodyV1(); !errors.Is(err, ErrSendHTTPStageV1) {
		t.Fatal(err)
	}
	if _, err := absent.BodyV1(); !errors.Is(err, ErrSendHTTPStageV1) {
		t.Fatal(err)
	}
	if _, err := absent.DecodeValueV1(); !errors.Is(err, ErrSendHTTPStageV1) {
		t.Fatal(err)
	}
	absent.CloseV1()
	if SendHTTPResponseByteLimitV1() != maxSourceResponseBytes {
		t.Fatal("HTTP source cap changed")
	}
}

// This qualifies the concrete staged response Read/Close join only. Native
// producer admission/consumer conjunction is a separate real owner contract.
type sendStageBlockingBodyV1 struct {
	started, finish chan struct{}
	once            sync.Once
	sent            bool
	closed          atomic.Int64
}

func (b *sendStageBlockingBodyV1) Read(dst []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.finish
	if b.sent {
		return 0, io.EOF
	}
	b.sent = true
	return copy(dst, []byte(`{"value":"exact"}`)), nil
}
func (b *sendStageBlockingBodyV1) Close() error { b.closed.Add(1); return nil }

type sendStageResponseClientV1 struct{ body io.ReadCloser }

func (c sendStageResponseClientV1) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: c.body}, nil
}
func TestSendHTTPStageCloseJoinsOriginalBlockedReadV1(t *testing.T) {
	body := &sendStageBlockingBodyV1{started: make(chan struct{}), finish: make(chan struct{})}
	source := NewScannerFindingSource("https://synthetic.invalid", "synthetic-token")
	source.Client = sendStageResponseClientV1{body: body}
	stage, err := source.OpenSendReadV1(context.Background(), Ref{Source: "exact", Path: "value"})
	if err != nil {
		t.Fatal(err)
	}
	var release sync.Once
	unblock := func() { release.Do(func() { close(body.finish) }) }
	done := make(chan error, 1)
	go func() { done <- stage.ReadBodyV1() }()
	joined := false
	t.Cleanup(func() {
		unblock()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("original synthetic read did not join")
			}
		}
		stage.CloseV1()
	})
	select {
	case <-body.started:
	case <-time.After(5 * time.Second):
		t.Fatal("read never started")
	}
	stage.CloseV1()
	if body.closed.Load() != 0 {
		t.Fatal("active original body closed before its actual read joined")
	}
	if _, err := stage.BodyV1(); !errors.Is(err, ErrSendHTTPStageV1) {
		t.Fatal("closed response exposed bytes", err)
	}
	unblock()
	select {
	case err := <-done:
		joined = true
		if !errors.Is(err, ErrSendHTTPStageV1) {
			t.Fatal("closed original read exposed success", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual read did not join")
	}
	if body.closed.Load() != 1 {
		t.Fatal("original body was not closed exactly once after join", body.closed.Load())
	}
	stage.CloseV1()
	if body.closed.Load() != 1 {
		t.Fatal("duplicate close changed original body lifetime")
	}
}
