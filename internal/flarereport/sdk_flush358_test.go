// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

func Test358ProductionSDKFlushWaitsForActualReceiverCompletion(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	var mu sync.Mutex
	var bodies [][]byte
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		bodies = append(bodies, append([]byte(nil), raw...))
		mu.Unlock()
		select {
		case <-entered:
		default:
			close(entered)
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()
	defer unblock()
	options := sdkClientOptions(strings.Replace(receiver.URL, "://", "://fixture-public@", 1)+"/1", "hash", strings.Repeat("c", 40), "test")
	options.TracesSampleRate = 0
	client, err := sentry.NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { unblock(); client.Close() }()
	owner, cancelOwner := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelOwner()
	hub := sentry.NewHub(client, sentry.NewScope())
	hub.Scope().SetContext("private", sentry.Context{"value": "PRIVATE_358_CONTRACT"})
	ctx := sentry.SetHubOnContext(context.Background(), hub)
	// Capture must return without waiting for this receiver to complete.
	CaptureOperationFailure(ctx, OperationMCP, FailureInternal)
	wait, cancelWait := context.WithTimeout(owner, time.Second)
	defer cancelWait()
	select {
	case <-entered:
	case <-wait.Done():
		t.Fatal("actual receiver never entered after asynchronous capture")
	}
	short, cancelShort := context.WithTimeout(owner, 30*time.Millisecond)
	if client.FlushWithContext(short) {
		cancelShort()
		t.Fatal("SDK flush reported completion while actual HTTP response remains blocked")
	}
	cancelShort()
	unblock()
	flush, cancelFlush := context.WithTimeout(owner, time.Second)
	defer cancelFlush()
	if !client.FlushWithContext(flush) {
		t.Fatal("released actual receiver did not finish SDK flush")
	}
	mu.Lock()
	received := append([][]byte(nil), bodies...)
	mu.Unlock()
	if len(received) != 1 {
		t.Fatal("capture was missing or duplicated", len(received))
	}
	var events int
	for _, line := range strings.Split(string(received[0]), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) == nil && event["platform"] != nil && event["event_id"] != nil {
			events++
			if event["release"] != strings.Repeat("c", 40) || event["environment"] != "test" {
				t.Fatal("production client lost exact identity")
			}
		}
	}
	if events != 1 || strings.Contains(string(received[0]), "PRIVATE_358_CONTRACT") {
		t.Fatal("actual event count or privacy differs", events)
	}
}
