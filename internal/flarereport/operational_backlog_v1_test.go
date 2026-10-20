// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOperationalBacklog426ActualNativeWirePrivacyAndJoinedClose(t *testing.T) {
	wire, peer, hub := newWire343(t)
	defer hub.Client().Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sh := &logShipper{endpoint: peer.URL + "/api/1/logs", key: "PRIVATE_INGEST_KEY_426", service: "hash-worker", release: strings.Repeat("b", 40), environment: "test", ctx: ctx, cancel: cancel, done: make(chan struct{}), ch: make(chan nativeLogLine, logShipBuffer), client: &http.Client{Timeout: time.Second}}
	go sh.run()
	l := &Lifecycle{ctx: ctx, shipper: sh, service: "hash-worker"}
	l.RecordOperationalBacklogV1(ctx, OperationalBacklogSnapshotV1{HasSample: true, ReadUnavailable: true, SampleAgeSeconds: 360, Stale: true, Data: OperationalBacklogDataV1{MailCount: 1000, MailDueCount: 2, MailLimitReached: true, MailOldestObservedAgeSeconds: 7200, MailOldestObservedOverdueSeconds: 60, FinalizingRootCount: 2, FinalizingIntentCount: 1, FinalizingMissingIntentCount: 1, FinalizingUnknownIntentAgeCount: 1}})
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	sh.beginClose(cleanup)
	select {
	case <-sh.done:
	case <-cleanup.Done():
		t.Fatal("existing native sender did not join")
	}
	wire.mu.Lock()
	bodies := append([][]byte(nil), wire.bodies...)
	wire.mu.Unlock()
	if len(bodies) != 1 {
		t.Fatal("actual backlog wire absent or duplicated", len(bodies))
	}
	var logs []nativeLogLine
	if err := json.Unmarshal(bodies[0], &logs); err != nil || len(logs) != 1 {
		t.Fatal("invalid actual wire", err)
	}
	var attrs map[string]json.RawMessage
	if err := json.Unmarshal(logs[0].Attributes, &attrs); err != nil || len(attrs) != 6 {
		t.Fatal("closed envelope widened", err)
	}
	if logs[0].Severity != "warn" || logs[0].Body != "Hash durable backlog observation" || !strings.Contains(string(logs[0].Attributes), `"mail_limit_reached":true`) || !strings.Contains(string(logs[0].Attributes), `"finalizing_missing_intent_count":1`) || sh.failed.Load() != 0 {
		t.Fatal("unknown/capped state or actual delivery changed")
	}
	for _, private := range []string{"PRIVATE_INGEST_KEY_426", peer.URL, "document_id", "org_id", "recipient", "last_error", "mail_body"} {
		if strings.Contains(string(bodies[0]), private) {
			t.Fatal("private data crossed actual wire", private)
		}
	}
}
func TestOperationalBacklog426ClosedValidationQueueAndOffRefusals(t *testing.T) {
	l, sh := diagnosticFixture409(context.Background())
	bad := []OperationalBacklogSnapshotV1{
		{},
		{HasSample: true, Data: OperationalBacklogDataV1{MailCount: 1001}},
		{HasSample: true, Data: OperationalBacklogDataV1{MailCount: 1, MailDueCount: 1, MailUnknownDueCount: 1}},
		{HasSample: true, Data: OperationalBacklogDataV1{FinalizingRootCount: 1}},
		{HasSample: true, SampleAgeSeconds: 300},
		{HasSample: false, ReadUnavailable: true, Data: OperationalBacklogDataV1{MailCount: 1}},
	}
	for _, s := range bad {
		l.RecordOperationalBacklogV1(context.Background(), s)
	}
	if sh.rejected.Load() != int64(len(bad)) || len(sh.ch) != 0 {
		t.Fatal("invalid telemetry enqueued")
	}
	good := OperationalBacklogSnapshotV1{ReadUnavailable: true}
	sh.ch <- nativeLogLine{Body: "original1"}
	sh.ch <- nativeLogLine{Body: "original2"}
	l.RecordOperationalBacklogV1(context.Background(), good)
	if sh.dropped.Load() != 1 || len(sh.ch) != 2 || (<-sh.ch).Body != "original1" || (<-sh.ch).Body != "original2" {
		t.Fatal("full queue blocked or displaced records")
	}
	l.shipper = nil
	if l.OperationalBacklogEnabledV1() {
		t.Fatal("logs-off enabled DB collection")
	}
	l.RecordOperationalBacklogV1(context.Background(), good)
	l.shipper = sh
	l.service = "hash"
	if l.OperationalBacklogEnabledV1() {
		t.Fatal("server acquired worker backlog owner")
	}
}
