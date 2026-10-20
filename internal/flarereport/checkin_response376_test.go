// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Counts and pulses come from actual postCheckin completion after bounded read
// and Close. Receiver arrival is deliberately insufficient. No sleep/retry,
// global SDK/transport mutation, raised deadline or zero-failure waiver.
func waitCheckinResponses376(t *testing.T, ctx context.Context, owner *Lifecycle, expected uint64) {
	t.Helper()
	for {
		d := owner.Diagnostics()
		if d.CheckinFailures != 0 {
			t.Fatal("checkin request/transport/response handling failed", d)
		}
		if d.CheckinResponses == expected {
			return
		}
		if d.CheckinResponses > expected {
			t.Fatal("unexpected extra completed checkin responses", d)
		}
		select {
		case <-owner.checkinProgress:
		case <-ctx.Done():
			t.Fatal("actual bounded checkin response handling did not complete", owner.Diagnostics())
		}
	}
}

func Test376CheckinResponsesRequireActualBoundedReadAndClose(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	joined := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(entered)
		select {
		case <-release:
			io.WriteString(w, `{}`)
		case <-r.Context().Done():
		}
	}))
	defer peer.Close()
	defer unblock()
	budget, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	owner := &Lifecycle{ctx: budget, checkinProgress: make(chan struct{}, 1)}
	go func() { defer close(joined); owner.postCheckin(peer.URL) }()
	// Ensure failure cleanup releases and physically joins the actual client call
	// before the test receiver closes, using the unchanged single finite owner.
	defer func() {
		unblock()
		select {
		case <-joined:
		case <-budget.Done():
			t.Error("actual checkin client did not join")
		}
	}()
	select {
	case <-entered:
	case <-budget.Done():
		t.Fatal("receiver never entered")
	}
	if d := owner.Diagnostics(); d.CheckinResponses != 0 || d.CheckinFailures != 0 {
		t.Fatal("headers/arrival were misreported as completed response", d)
	}
	select {
	case <-owner.checkinProgress:
		t.Fatal("client signaled completion while bounded response body remained held")
	default:
	}
	unblock()
	waitCheckinResponses376(t, budget, owner, 1)
	select {
	case <-joined:
	case <-budget.Done():
		t.Fatal("actual completed call did not return")
	}
}

func Test376CheckinReadCloseAndHTTPRefusalsRemainFailures(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/refused":
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{}`)
		case "/truncated":
			w.Header().Set("Content-Length", "5")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "{")
		case "/redirect":
			w.Header().Set("Location", "/must-not-follow")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/must-not-follow":
			t.Error("checkin followed a redirect")
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer peer.Close()
	budget, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	owner := &Lifecycle{ctx: budget, checkinProgress: make(chan struct{}, 1)}
	for _, path := range []string{"/refused", "/truncated", "/redirect"} {
		owner.postCheckin(peer.URL + path)
	}
	if d := owner.Diagnostics(); d.CheckinFailures != 3 || d.CheckinResponses != 0 {
		t.Fatal("unsuccessful actual responses counted as completed", d)
	}
	owner.postCheckin(peer.URL + "/ok")
	if d := owner.Diagnostics(); d.CheckinFailures != 3 || d.CheckinResponses != 1 {
		t.Fatal("genuine completed response not counted independently", d)
	}
	body := &closeErrorBody376{Reader: strings.NewReader(`{}`)}
	if completedCheckinResponse(&http.Response{StatusCode: http.StatusOK, Body: body}) || body.closes != 1 {
		t.Fatal("close error was accepted or original close skipped", body.closes)
	}
}

type closeErrorBody376 struct {
	*strings.Reader
	closes int
}

func (b *closeErrorBody376) Close() error {
	b.closes++
	return errors.New("synthetic private close detail")
}
