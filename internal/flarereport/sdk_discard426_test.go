// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

// Actual native HTTPTransport/recorder delivery to a local receiver does not
// qualify Flare storage, alerts, queue-overflow coverage, or release attribution
// of native client reports. No global hub, logger, or identity is modified.
func Test426ProductionSDKNativeDiscardReportReachesActualReceiver(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		name := "native_report"
		if disabled {
			name = "disabled_reports_negative_control"
		}
		t.Run(name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var enterOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			var mu sync.Mutex
			var bodies [][]byte
			var receiverFailure bool
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
				_ = r.Body.Close()
				if err != nil || len(raw) > 1<<20 || r.Method != http.MethodPost || r.URL.Path != "/api/1/envelope/" {
					mu.Lock()
					receiverFailure = true
					mu.Unlock()
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				mu.Lock()
				if len(bodies) >= 2 {
					receiverFailure = true
				} else {
					bodies = append(bodies, raw)
				}
				mu.Unlock()
				enterOnce.Do(func() { close(entered) })
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "{}")
			}))
			defer receiver.Close()
			defer unblock()
			const fixtureRelease = "cccccccccccccccccccccccccccccccccccccccc"
			const fixtureEnvironment = "test"
			options := sdkClientOptions(strings.Replace(receiver.URL, "://", "://fixture-public@", 1)+"/1", "hash", fixtureRelease, fixtureEnvironment)
			transport, ok := options.Transport.(*sentry.HTTPTransport)
			if !ok || transport.BufferSize != 30 || transport.Timeout != 3*time.Second || options.DisableClientReports || !options.DisableLogs || !options.DisableMetrics || options.BeforeSend == nil || options.BeforeSendTransaction == nil {
				t.Fatal("production native SDK configuration changed")
			}
			// Only this negative control changes a production option. Transport
			// and scrubbers are not replaced, wrapped, or given a custom recorder.
			if disabled {
				options.DisableClientReports = true
			}
			client, err := sentry.NewClient(options)
			if err != nil {
				t.Fatal("native client configuration rejected", err)
			}
			defer func() { unblock(); client.Close() }()
			owner, cancelOwner := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelOwner()
			started := time.Now()
			dropScope := sentry.NewScope()
			dropScope.AddEventProcessor(func(*sentry.Event, *sentry.EventHint) *sentry.Event { return nil })
			dropHub := sentry.NewHub(client, dropScope)
			for i := 0; i < 2; i++ {
				if dropHub.CaptureMessage("PRIVATE_426_SYNTHETIC_DISCARD") != nil {
					t.Fatal("controlled native processor did not discard")
				}
			}
			cleanScope := sentry.NewScope()
			cleanScope.SetContext("private", sentry.Context{"value": "PRIVATE_426_SYNTHETIC_CONTEXT"})
			cleanHub := sentry.NewHub(client, cleanScope)
			ctx := sentry.SetHubOnContext(context.Background(), cleanHub)
			CaptureOperationFailure(ctx, OperationMCP, FailureInternal)
			select {
			case <-entered:
			case <-owner.Done():
				t.Fatal("actual native HTTP receiver never entered")
			}
			short, cancelShort := context.WithTimeout(owner, 30*time.Millisecond)
			premature := client.FlushWithContext(short)
			cancelShort()
			if premature {
				t.Fatal("native flush completed before actual receiver was released")
			}
			unblock()
			joined, cancelJoined := context.WithTimeout(owner, time.Second)
			flushed := client.FlushWithContext(joined)
			cancelJoined()
			if !flushed {
				t.Fatal("released actual receiver did not join native SDK flush")
			}
			ended := time.Now()
			mu.Lock()
			received := append([][]byte(nil), bodies...)
			failed := receiverFailure
			mu.Unlock()
			if failed || len(received) != 1 {
				t.Fatal("actual native accepted request missing, duplicated or rejected")
			}
			hasReport, err := inspectSDKDiscardEnvelope426(received[0], fixtureRelease, fixtureEnvironment, started, ended)
			if err != nil {
				t.Fatal("native envelope did not satisfy safe actual-event oracle", err)
			}
			if hasReport == disabled {
				t.Fatal("native report oracle did not distinguish enabled delivery from disabled negative control")
			}
		})
	}
}

// Release/environment belong to the accepted event only. The native report has
// timestamp+discarded_events and project/time attribution, not release identity.
func inspectSDKDiscardEnvelope426(raw []byte, release, environment string, started, ended time.Time) (bool, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || bytes.Contains(raw, []byte("PRIVATE_426_")) {
		return false, fmt.Errorf("bounded fixture/privacy refusal")
	}
	lines := bytes.Split(raw, []byte{'\n'})
	if len(lines) < 4 || len(lines[len(lines)-1]) != 0 {
		return false, fmt.Errorf("native framing refusal")
	}
	var envelope struct {
		EventID string    `json:"event_id"`
		SentAt  time.Time `json:"sent_at"`
	}
	if json.Unmarshal(lines[0], &envelope) != nil || len(envelope.EventID) != 32 || envelope.SentAt.IsZero() {
		return false, fmt.Errorf("native envelope identity refusal")
	}
	events, reports := 0, 0
	for i := 1; i < len(lines)-1; i += 2 {
		if i+1 >= len(lines)-1 {
			return false, fmt.Errorf("incomplete native item")
		}
		var header struct {
			Type   string `json:"type"`
			Length int    `json:"length"`
		}
		if json.Unmarshal(lines[i], &header) != nil || header.Length != len(lines[i+1]) {
			return false, fmt.Errorf("native item length refusal")
		}
		switch header.Type {
		case "event":
			events++
			var event struct {
				EventID     string `json:"event_id"`
				Platform    string `json:"platform"`
				Release     string `json:"release"`
				Environment string `json:"environment"`
				ServerName  string `json:"server_name"`
				Message     string `json:"message"`
			}
			if json.Unmarshal(lines[i+1], &event) != nil || event.EventID != envelope.EventID || event.Platform != "go" || event.Release != release || event.Environment != environment || event.ServerName != "hash" || event.Message != "Hash operational failure" {
				return false, fmt.Errorf("accepted production event refusal")
			}
		case "client_report":
			reports++
			var fields map[string]json.RawMessage
			if json.Unmarshal(lines[i+1], &fields) != nil || len(fields) != 2 || fields["timestamp"] == nil || fields["discarded_events"] == nil {
				return false, fmt.Errorf("native report fields or attribution differ")
			}
			var report struct {
				Timestamp       time.Time `json:"timestamp"`
				DiscardedEvents []struct {
					Reason   string `json:"reason"`
					Category string `json:"category"`
					Quantity int64  `json:"quantity"`
				} `json:"discarded_events"`
			}
			if json.Unmarshal(lines[i+1], &report) != nil || report.Timestamp.Before(started.Add(-time.Second)) || report.Timestamp.After(ended.Add(time.Second)) || len(report.DiscardedEvents) != 1 {
				return false, fmt.Errorf("native report time/cardinality refusal")
			}
			item := report.DiscardedEvents[0]
			if item.Reason != "event_processor" || item.Category != "error" || item.Quantity != 2 {
				return false, fmt.Errorf("native known discard tuple differs")
			}
		default:
			return false, fmt.Errorf("unexpected native envelope item")
		}
	}
	if events != 1 || reports > 1 {
		return false, fmt.Errorf("native event/report count differs")
	}
	return reports == 1, nil
}
