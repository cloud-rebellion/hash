// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// The receiver normalizes native values to float64. Keep integer JSON exact.
	operationalMetricMaxIntegerV1 int64 = 1<<53 - 1
	operationalMetricMaxBodyV1          = 32 << 10
	operationalMetricMaxAckV1           = 4096
)

// One immutable validated observation, not a second sampler or SQL owner.
type operationalMetricSampleV1 struct {
	snapshot   OperationalBacklogSnapshotV1
	recordedAt time.Time
}

type operationalMetricValueV1 struct {
	name  string
	value int64
}

// This projection is closed over the existing backlog schema. No caller names,
// maps, private rows, free text, callbacks or reflection enter the metric wire.
func operationalMetricValuesV1(s OperationalBacklogSnapshotV1) [23]operationalMetricValueV1 {
	bit := func(v bool) int64 {
		if v {
			return 1
		}
		return 0
	}
	d := s.Data
	return [23]operationalMetricValueV1{
		{"hash.operational_backlog.has_sample", bit(s.HasSample)},
		{"hash.operational_backlog.read_unavailable", bit(s.ReadUnavailable)},
		{"hash.operational_backlog.sample_age_seconds", s.SampleAgeSeconds},
		{"hash.operational_backlog.stale", bit(s.Stale)},
		{"hash.operational_backlog.read_duration_ms", s.ReadDurationMilliseconds},
		{"hash.operational_backlog.observed_row_limit", OperationalBacklogRowLimitV1},
		{"hash.operational_backlog.mail_count", d.MailCount},
		{"hash.operational_backlog.mail_due_count", d.MailDueCount},
		{"hash.operational_backlog.mail_unknown_created_count", d.MailUnknownCreatedCount},
		{"hash.operational_backlog.mail_unknown_due_count", d.MailUnknownDueCount},
		{"hash.operational_backlog.mail_oldest_observed_age_seconds", d.MailOldestObservedAgeSeconds},
		{"hash.operational_backlog.mail_oldest_observed_overdue_seconds", d.MailOldestObservedOverdueSeconds},
		{"hash.operational_backlog.mail_limit_reached", bit(d.MailLimitReached)},
		{"hash.operational_backlog.mail_failed_count", d.MailFailedCount},
		{"hash.operational_backlog.mail_failed_unknown_created_count", d.MailFailedUnknownCreatedCount},
		{"hash.operational_backlog.mail_failed_oldest_observed_creation_age_seconds", d.MailFailedOldestObservedCreationAgeSeconds},
		{"hash.operational_backlog.mail_failed_limit_reached", bit(d.MailFailedLimitReached)},
		{"hash.operational_backlog.finalizing_root_count", d.FinalizingRootCount},
		{"hash.operational_backlog.finalizing_intent_count", d.FinalizingIntentCount},
		{"hash.operational_backlog.finalizing_missing_intent_count", d.FinalizingMissingIntentCount},
		{"hash.operational_backlog.finalizing_unknown_intent_age_count", d.FinalizingUnknownIntentAgeCount},
		{"hash.operational_backlog.finalizing_oldest_observed_intent_age_seconds", d.FinalizingOldestObservedIntentAgeSeconds},
		{"hash.operational_backlog.finalizing_limit_reached", bit(d.FinalizingLimitReached)},
	}
}

func operationalMetricRangeV1(s OperationalBacklogSnapshotV1) bool {
	for _, point := range operationalMetricValuesV1(s) {
		if point.value < 0 || point.value > operationalMetricMaxIntegerV1 {
			return false
		}
	}
	return true
}

func (l *Lifecycle) operationalMetricsEnabledV1() bool {
	return l.OperationalBacklogEnabledV1() && validEnvironment(l.shipper.environment) && !strings.EqualFold(strings.TrimSpace(os.Getenv("FLARE_LOG_LEVEL")), "off")
}

func (l *Lifecycle) retainOperationalMetricsV1(s OperationalBacklogSnapshotV1) {
	if !l.operationalMetricsEnabledV1() {
		return
	}
	if !operationalMetricRangeV1(s) {
		l.metricFailures.Add(1)
		return
	}
	l.operationalMetrics.Store(&operationalMetricSampleV1{snapshot: s, recordedAt: time.Now()})
}

type nativeOperationalMetricV1 struct {
	Name      string                    `json:"name"`
	Kind      string                    `json:"kind"`
	Value     int64                     `json:"value"`
	Labels    operationalMetricLabelsV1 `json:"labels"`
	Timestamp string                    `json:"timestamp"`
}

type operationalMetricLabelsV1 struct {
	Schema      string `json:"schema"`
	Service     string `json:"service"`
	Release     string `json:"release"`
	Environment string `json:"environment"`
}

func projectOperationalMetricsV1(sample *operationalMetricSampleV1, now time.Time, labels operationalMetricLabelsV1) ([]nativeOperationalMetricV1, bool) {
	if sample == nil || sample.recordedAt.IsZero() || now.Before(sample.recordedAt) {
		return nil, false
	}
	s := sample.snapshot
	if !operationalMetricRangeV1(s) {
		return nil, false
	}
	if s.HasSample {
		elapsed := int64(now.Sub(sample.recordedAt) / time.Second)
		if elapsed > operationalMetricMaxIntegerV1-s.SampleAgeSeconds {
			return nil, false
		}
		s.SampleAgeSeconds += elapsed
		s.Stale = s.SampleAgeSeconds >= 300
	}
	if !operationalMetricRangeV1(s) {
		return nil, false
	}
	values := operationalMetricValuesV1(s)
	points := make([]nativeOperationalMetricV1, 0, len(values))
	stamp := now.UTC().Format(time.RFC3339Nano)
	for _, value := range values {
		points = append(points, nativeOperationalMetricV1{Name: value.name, Kind: "gauge", Value: value.value, Labels: labels, Timestamp: stamp})
	}
	return points, true
}

// Called only by Lifecycle's existing ready heartbeat owner. Its cancellation
// and done join own the complete request/read/Close phase; there is no retry,
// detached cleanup, extra application goroutine, ticker or SQL query.
func (l *Lifecycle) emitOperationalMetricsV1() {
	if !l.operationalMetricsEnabledV1() {
		return
	}
	sample := l.operationalMetrics.Load()
	if sample == nil {
		return
	}
	sh := l.shipper
	labels := operationalMetricLabelsV1{"hash-operational-backlog-v1", sh.service, sh.release, sh.environment}
	points, valid := projectOperationalMetricsV1(sample, time.Now(), labels)
	if !valid || sh.client == nil || !strings.HasSuffix(sh.endpoint, "/logs") {
		l.metricFailures.Add(1)
		return
	}
	body, err := json.Marshal(points)
	if err != nil || len(body) > operationalMetricMaxBodyV1 {
		l.metricFailures.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(l.ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(sh.endpoint, "/logs")+"/metrics", bytes.NewReader(body))
	if err != nil {
		l.metricFailures.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Flare-Key", sh.key)
	// Reuse the native transport, without inheriting a cookie jar or redirects.
	client := &http.Client{Transport: sh.client.Transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		l.metricFailures.Add(1)
		return
	}
	if !completeOperationalMetricAckV1(response, len(points)) {
		l.metricFailures.Add(1)
		return
	}
	l.metricAcknowledged.Add(1)
}

func completeOperationalMetricAckV1(response *http.Response, expected int) bool {
	if response == nil || response.Body == nil {
		return false
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, operationalMetricMaxAckV1+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(raw) > operationalMetricMaxAckV1 || response.StatusCode != http.StatusOK || expected <= 0 {
		return false
	}
	// Token decoding rejects missing/null, duplicate and unknown fields as well
	// as fractional/string counts and trailing JSON. A bare 200 is not a receipt.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	var counts [3]*int64
	var receipt *string
	var fields uint8
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return false
		}
		var mask uint8
		switch key {
		case "accepted":
			mask = 1
		case "rejected":
			mask = 2
		case "dropped":
			mask = 4
		case "receipt_id":
			mask = 8
		default:
			return false
		}
		if fields&mask != 0 {
			return false
		}
		fields |= mask
		switch mask {
		case 1:
			err = decoder.Decode(&counts[0])
		case 2:
			err = decoder.Decode(&counts[1])
		case 4:
			err = decoder.Decode(&counts[2])
		case 8:
			err = decoder.Decode(&receipt)
		}
		if err != nil {
			return false
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || fields != 15 {
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false
	}
	return counts[0] != nil && counts[1] != nil && counts[2] != nil && *counts[0] == int64(expected) && *counts[1] == 0 && *counts[2] == 0 && receipt != nil && len(*receipt) > 0 && len(*receipt) <= 128 && strings.TrimSpace(*receipt) == *receipt
}
