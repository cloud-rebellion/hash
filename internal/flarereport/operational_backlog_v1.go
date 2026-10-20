// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"encoding/json"
	"time"
)

const OperationalBacklogRowLimitV1 int64 = 1000

// Counts partition observed roots only. Intent rows overlap roots and are not
// additional contracts. No private row, error, string label or callback fits.
type OperationalBacklogDataV1 struct {
	MailCount                                  int64 `json:"mail_count"`
	MailDueCount                               int64 `json:"mail_due_count"`
	MailUnknownCreatedCount                    int64 `json:"mail_unknown_created_count"`
	MailUnknownDueCount                        int64 `json:"mail_unknown_due_count"`
	MailOldestObservedAgeSeconds               int64 `json:"mail_oldest_observed_age_seconds"`
	MailOldestObservedOverdueSeconds           int64 `json:"mail_oldest_observed_overdue_seconds"`
	MailLimitReached                           bool  `json:"mail_limit_reached"`
	MailFailedCount                            int64 `json:"mail_failed_count"`
	MailFailedUnknownCreatedCount              int64 `json:"mail_failed_unknown_created_count"`
	MailFailedOldestObservedCreationAgeSeconds int64 `json:"mail_failed_oldest_observed_creation_age_seconds"`
	MailFailedLimitReached                     bool  `json:"mail_failed_limit_reached"`
	FinalizingRootCount                        int64 `json:"finalizing_root_count"`
	FinalizingIntentCount                      int64 `json:"finalizing_intent_count"`
	FinalizingMissingIntentCount               int64 `json:"finalizing_missing_intent_count"`
	FinalizingUnknownIntentAgeCount            int64 `json:"finalizing_unknown_intent_age_count"`
	FinalizingOldestObservedIntentAgeSeconds   int64 `json:"finalizing_oldest_observed_intent_age_seconds"`
	FinalizingLimitReached                     bool  `json:"finalizing_limit_reached"`
}

func (d OperationalBacklogDataV1) ValidV1() bool {
	if d.MailCount < 0 || d.MailCount > OperationalBacklogRowLimitV1 || d.MailDueCount < 0 || d.MailDueCount > d.MailCount || d.MailUnknownCreatedCount < 0 || d.MailUnknownCreatedCount > d.MailCount || d.MailUnknownDueCount < 0 || d.MailUnknownDueCount > d.MailCount-d.MailDueCount || d.MailOldestObservedAgeSeconds < 0 || d.MailOldestObservedOverdueSeconds < 0 {
		return false
	}
	if d.MailFailedCount < 0 || d.MailFailedCount > OperationalBacklogRowLimitV1 || d.MailFailedUnknownCreatedCount < 0 || d.MailFailedUnknownCreatedCount > d.MailFailedCount || d.MailFailedOldestObservedCreationAgeSeconds < 0 {
		return false
	}
	if d.FinalizingRootCount < 0 || d.FinalizingRootCount > OperationalBacklogRowLimitV1 || d.FinalizingIntentCount < 0 || d.FinalizingMissingIntentCount < 0 || d.FinalizingIntentCount > d.FinalizingRootCount || d.FinalizingMissingIntentCount != d.FinalizingRootCount-d.FinalizingIntentCount || d.FinalizingUnknownIntentAgeCount < 0 || d.FinalizingUnknownIntentAgeCount > d.FinalizingIntentCount || d.FinalizingOldestObservedIntentAgeSeconds < 0 {
		return false
	}
	if d.MailLimitReached != (d.MailCount == OperationalBacklogRowLimitV1) || d.MailFailedLimitReached != (d.MailFailedCount == OperationalBacklogRowLimitV1) || d.FinalizingLimitReached != (d.FinalizingRootCount == OperationalBacklogRowLimitV1) {
		return false
	}
	if d.MailFailedUnknownCreatedCount == d.MailFailedCount && d.MailFailedOldestObservedCreationAgeSeconds != 0 {
		return false
	}
	if d.MailUnknownCreatedCount == d.MailCount && d.MailOldestObservedAgeSeconds != 0 || d.MailDueCount == 0 && d.MailOldestObservedOverdueSeconds != 0 || d.FinalizingUnknownIntentAgeCount == d.FinalizingIntentCount && d.FinalizingOldestObservedIntentAgeSeconds != 0 {
		return false
	}
	return true
}

type OperationalBacklogSnapshotV1 struct {
	HasSample                bool                     `json:"has_sample"`
	ReadUnavailable          bool                     `json:"read_unavailable"`
	SampleAgeSeconds         int64                    `json:"sample_age_seconds"`
	Stale                    bool                     `json:"stale"`
	ReadDurationMilliseconds int64                    `json:"read_duration_ms"`
	Data                     OperationalBacklogDataV1 `json:"data"`
}

// The worker checks this before starting SQL. Off/nil remain no-ops; no DB or
// new network owner is added to Lifecycle's ready sender.
func (l *Lifecycle) OperationalBacklogEnabledV1() bool {
	return l != nil && l.ctx != nil && l.ctx.Err() == nil && l.service == "hash-worker" && l.shipper != nil && l.shipper.service == l.service && identityValue(l.shipper.release) != "" && identityValue(l.shipper.environment) != ""
}
func (l *Lifecycle) RecordOperationalBacklogV1(ctx context.Context, s OperationalBacklogSnapshotV1) {
	if !l.OperationalBacklogEnabledV1() || ctx == nil || ctx.Err() != nil {
		return
	}
	sh := l.shipper
	valid := s.Data.ValidV1() && s.SampleAgeSeconds >= 0 && s.ReadDurationMilliseconds >= 0 && s.ReadDurationMilliseconds <= 60000
	if !s.HasSample {
		valid = valid && s.ReadUnavailable && !s.Stale && s.SampleAgeSeconds == 0 && s.Data == (OperationalBacklogDataV1{})
	}
	if s.HasSample {
		valid = valid && s.Stale == (s.SampleAgeSeconds >= 300)
	}
	if !valid {
		sh.rejected.Add(1)
		return
	}
	// Checkin status follows the actual durable observation, independently of
	// the native-log rate/queue. Existing off/role/cancel/validation gates hold.
	l.recordOperationalBacklogHealthV1(s)
	attrs := struct {
		Schema      string                       `json:"schema"`
		Service     string                       `json:"service"`
		Release     string                       `json:"release"`
		Environment string                       `json:"environment"`
		RowLimit    int64                        `json:"observed_row_limit"`
		Snapshot    OperationalBacklogSnapshotV1 `json:"snapshot"`
	}{"hash-operational-backlog-v1", sh.service, sh.release, sh.environment, OperationalBacklogRowLimitV1, s}
	raw, err := json.Marshal(attrs)
	if err != nil || len(raw) > logShipMaxAttrs {
		sh.rejected.Add(1)
		return
	}
	if !sh.allow() {
		sh.dropped.Add(1)
		return
	}
	severity := "info"
	// Terminal failures remain visible until a fresh durable sample observes
	// their remediation. Healthy job checkins do not resolve this business state.
	if s.ReadUnavailable || s.Stale || s.Data.MailFailedCount > 0 {
		severity = "warn"
	}
	// Fixed native projection bypasses only the generic log floor. Original
	// off/queue/rate/size/context/close boundaries remain in force.
	sh.enqueue(nativeLogLine{Severity: severity, Body: "Hash durable backlog observation", Attributes: raw, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)})
}

// This scalar queue variant is distinct from the original12 invocation jobs.
// No snapshot/context/error/private row crosses the existing queue16 boundary.
func (l *Lifecycle) recordOperationalBacklogHealthV1(s OperationalBacklogSnapshotV1) {
	if l.checkinURL == "" {
		return
	}
	// A successful durable read resets age0. A same-second cached read failure
	// may also retain age0; ReadUnavailable independently prevents remediation.
	report := jobReport{backlogHealth: true, backlogUnhealthy: !s.HasSample || s.ReadUnavailable || s.Stale || s.SampleAgeSeconds > 0 || s.Data.MailFailedCount > 0, completedAt: time.Now()}
	select {
	case l.jobQueue <- report:
	default:
		l.jobDropped.Add(1)
	}
}

func (l *Lifecycle) sendOperationalBacklogHealthV1(report jobReport) {
	if l == nil || l.ctx == nil || l.ctx.Err() != nil || l.checkinURL == "" || !report.backlogHealth {
		return
	}
	// An old healthy queue item must not revive a stalled sampler. An unhealthy
	// observation is never mistaken for an old healthy item and silently lost.
	age := time.Since(report.completedAt)
	if !report.backlogUnhealthy && (age < 0 || age > jobReportInterval) {
		l.jobDropped.Add(1)
		return
	}
	status := "ok"
	if report.backlogUnhealthy {
		status = "error"
	}
	// Existing owned5s HTTP/drain/close and Lifecycle cancellation/join apply.
	// No exception, SQL, retry, new timer, goroutine or receiver feature.
	l.postCheckin(l.checkinURL + "-backlog?status=" + status)
}
