// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"strconv"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

// CriticalJob is a closed, process-wide vocabulary. No caller-supplied names,
// tenant identifiers, document IDs, messages, errors or callbacks are retained.
type CriticalJob string

const (
	JobEmailDispatch       CriticalJob = "email_dispatch"
	JobFinalizeRetry       CriticalJob = "finalize_retry"
	JobReminders           CriticalJob = "reminders"
	JobExpirations         CriticalJob = "expirations"
	JobWebhookRedrive      CriticalJob = "webhook_redrive"
	JobTelemetryRollup     CriticalJob = "telemetry_rollup"
	JobQuotaWarnings       CriticalJob = "quota_warnings"
	JobSoftDeletePurge     CriticalJob = "soft_delete_purge"
	JobCollabArchivePurge  CriticalJob = "collab_archive_purge"
	JobSendSealing         CriticalJob = "send_sealing"
	JobPackageSendRecovery CriticalJob = "package_send_recovery"
	JobComplianceRollup    CriticalJob = "compliance_rollup"
	criticalJobCount                   = 12
	jobReportInterval                  = 30 * time.Second
)

// JobTick is recorded only AFTER the original synchronous invocation returns.
// Returned counts nil-returning attempts, not completed contracts or mailbox
// delivery. Selected/oldest age are a bounded sample, never a global backlog.
type JobTick struct {
	InvocationState                                  JobInvocationState
	Job                                              CriticalJob
	Selected, Attempted, Returned, Failed            int64
	SentAcknowledged, RetryScheduled, TerminalFailed int64
	OldestSelectedAgeSeconds, UnknownAges            int64
	BatchLimitReached, Unavailable                   bool
	Duration                                         time.Duration
}
type jobReport struct {
	// A separate sampler-health variant never represents a job invocation.
	backlogHealth, backlogUnhealthy          bool
	tick                                     JobTick
	ticks, maxSelected                       int64
	stale, policyInvalid, policyUnobservable bool
	completedAt                              time.Time
}
type jobWindow struct {
	tick                    JobTick
	ticks, maxSelected      int64
	lastReport, completedAt time.Time
	lastProblem             uint8
}

var criticalJobNames = [criticalJobCount]CriticalJob{JobEmailDispatch, JobFinalizeRetry, JobReminders, JobExpirations, JobWebhookRedrive, JobTelemetryRollup, JobQuotaWarnings, JobSoftDeletePurge, JobCollabArchivePurge, JobSendSealing, JobPackageSendRecovery, JobComplianceRollup}
var criticalJobSuffixes = [criticalJobCount]string{"mail", "finalize", "remind", "expire", "webhook", "rollup", "quota", "purge", "archive", "seal", "package", "comply"}

func jobIndex(job CriticalJob) int {
	for i, name := range criticalJobNames {
		if job == name {
			return i
		}
	}
	return -1
}
func jobSuffix(job CriticalJob) string {
	i := jobIndex(job)
	if i < 0 {
		return ""
	}
	return criticalJobSuffixes[i]
}
func (l *Lifecycle) configureJobs() {
	for i, key := range []string{"HASH_FLARE_EMAIL_SAMPLE_MAX_AGE_SECONDS", "HASH_FLARE_FINALIZE_SAMPLE_MAX_AGE_SECONDS"} {
		value := os.Getenv(key)
		if value == "" {
			continue
		}
		seconds, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			l.jobPolicyInvalid[i] = true
			continue
		}
		l.jobMaxAge[i] = int64(seconds)
	}
}
func validJobTick(t JobTick) bool {
	if jobIndex(t.Job) >= 2 {
		return validInvocationState(t.InvocationState) && t.Duration >= 0 &&
			t.Selected == 0 && t.Attempted == 0 && t.Returned == 0 && t.Failed == 0 &&
			t.SentAcknowledged == 0 && t.RetryScheduled == 0 && t.TerminalFailed == 0 &&
			t.OldestSelectedAgeSeconds == 0 && t.UnknownAges == 0 && !t.BatchLimitReached && !t.Unavailable
	}
	if t.InvocationState != "" {
		return false
	}
	if jobIndex(t.Job) < 0 || t.Selected < 0 || t.Selected > 50 || t.Attempted < 0 || t.Attempted > t.Selected || t.Returned < 0 || t.Returned > 50 || t.Failed < 0 || t.Failed > 50 || t.Returned+t.Failed != t.Attempted || t.UnknownAges < 0 || t.UnknownAges > t.Selected || t.OldestSelectedAgeSeconds < 0 || t.Duration < 0 {
		return false
	}
	if t.SentAcknowledged < 0 || t.SentAcknowledged > 50 || t.RetryScheduled < 0 || t.RetryScheduled > 50 || t.TerminalFailed < 0 || t.TerminalFailed > 50 {
		return false
	}
	if t.Job == JobEmailDispatch {
		return t.SentAcknowledged+t.RetryScheduled+t.TerminalFailed == t.Returned
	}
	return t.SentAcknowledged == 0 && t.RetryScheduled == 0 && t.TerminalFailed == 0
}
func sumJob(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}
func addJobTick(a *JobTick, b JobTick) {
	a.Job = b.Job
	a.InvocationState = mergeInvocationState(a.InvocationState, b.InvocationState)
	a.Selected = sumJob(a.Selected, b.Selected)
	a.Attempted = sumJob(a.Attempted, b.Attempted)
	a.Returned = sumJob(a.Returned, b.Returned)
	a.Failed = sumJob(a.Failed, b.Failed)
	a.SentAcknowledged = sumJob(a.SentAcknowledged, b.SentAcknowledged)
	a.RetryScheduled = sumJob(a.RetryScheduled, b.RetryScheduled)
	a.TerminalFailed = sumJob(a.TerminalFailed, b.TerminalFailed)
	a.UnknownAges = sumJob(a.UnknownAges, b.UnknownAges)
	if b.OldestSelectedAgeSeconds > a.OldestSelectedAgeSeconds {
		a.OldestSelectedAgeSeconds = b.OldestSelectedAgeSeconds
	}
	a.BatchLimitReached = a.BatchLimitReached || b.BatchLimitReached
	a.Unavailable = a.Unavailable || b.Unavailable
	a.Duration = time.Duration(sumJob(int64(a.Duration), int64(b.Duration)))
}

// RecordJobTick is nonblocking with respect to collector/network I/O. It uses
// a fixed closed-job inventory and existing-owner queue of 16 scalar reports. Normal
// ticks aggregate for 30s; actual problem/recovery transitions report promptly.
// Cancellation never creates a completed/healthy checkin. Queue loss is counted.
func (l *Lifecycle) RecordJobTick(ctx context.Context, tick JobTick) {
	if l == nil || ctx == nil || ctx.Err() != nil || l.ctx.Err() != nil {
		return
	}
	if l.service != "hash-worker" || !validJobTick(tick) {
		l.jobRejected.Add(1)
		return
	}
	i := jobIndex(tick.Job)
	now := time.Now()
	stale := l.jobMaxAge[i] > 0 && tick.OldestSelectedAgeSeconds > l.jobMaxAge[i]
	var problem uint8
	if tick.Unavailable || tick.Failed > 0 {
		problem |= 1
	}
	if tick.RetryScheduled > 0 || tick.TerminalFailed > 0 {
		problem |= 2
	}
	if stale || l.jobPolicyInvalid[i] || l.jobMaxAge[i] > 0 && tick.UnknownAges > 0 {
		problem |= 4
	}
	switch tick.InvocationState {
	case InvocationPending:
		problem |= 8
	case InvocationPartial:
		problem |= 16
	case InvocationUnavailable:
		problem |= 32
	case InvocationUnobservable:
		problem |= 64
	}
	l.jobMu.Lock()
	window := &l.jobWindows[i]
	transition := !window.lastReport.IsZero() && problem != window.lastProblem
	var reports [2]jobReport
	count := 0
	// A pending error window must not contaminate a newly completed recovery.
	// Preserve its historical counts first, then report the real current tick.
	if transition && window.ticks > 0 {
		reports[count] = l.takeJobWindow(i, window)
		count++
	}
	addJobTick(&window.tick, tick)
	window.ticks = sumJob(window.ticks, 1)
	if tick.Selected > window.maxSelected {
		window.maxSelected = tick.Selected
	}
	window.completedAt = now
	due := window.lastReport.IsZero() || transition || now.Sub(window.lastReport) >= jobReportInterval
	window.lastProblem = problem
	if due {
		reports[count] = l.takeJobWindow(i, window)
		count++
		window.lastReport = now
	}
	// No context, private row or callback crosses this queue boundary. The
	// fixed pair staging does not increase the original queue16 capacity.
	for _, report := range reports[:count] {
		select {
		case l.jobQueue <- report:
		default:
			l.jobDropped.Add(1)
		}
	}
	l.jobMu.Unlock()
}

// takeJobWindow is called only under jobMu. Its completion timestamp belongs
// to the actual last tick in that window, never to a later recovery timer.
func (l *Lifecycle) takeJobWindow(i int, window *jobWindow) jobReport {
	report := jobReport{tick: window.tick, ticks: window.ticks, maxSelected: window.maxSelected, completedAt: window.completedAt, policyInvalid: l.jobPolicyInvalid[i]}
	report.stale = l.jobMaxAge[i] > 0 && report.tick.OldestSelectedAgeSeconds > l.jobMaxAge[i]
	report.policyUnobservable = l.jobMaxAge[i] > 0 && report.tick.UnknownAges > 0
	window.tick = JobTick{}
	window.ticks = 0
	window.maxSelected = 0
	return report
}

func (l *Lifecycle) sendJobReport(report jobReport) {
	if l.ctx.Err() != nil {
		return
	}
	tick := report.tick
	// A queued healthy report is not a timer heartbeat. If collector delay has
	// made it stale, drop it rather than reviving a potentially stalled job.
	if !invocationStateError(tick.InvocationState) && !report.tick.Unavailable && report.tick.Failed == 0 && report.tick.RetryScheduled == 0 && report.tick.TerminalFailed == 0 && !report.stale && !report.policyInvalid && !report.policyUnobservable && time.Since(report.completedAt) > jobReportInterval {
		l.jobDropped.Add(1)
		return
	}
	invocationError := invocationStateError(tick.InvocationState) || tick.Unavailable || tick.Failed > 0 || report.stale || report.policyInvalid || report.policyUnobservable
	smtpError := tick.RetryScheduled > 0 || tick.TerminalFailed > 0
	status := "ok"
	if invocationError {
		status = "error"
	}
	if l.shipper != nil {
		attrs := struct {
			Service            string             `json:"service"`
			Release            string             `json:"release"`
			Environment        string             `json:"environment"`
			Job                CriticalJob        `json:"job"`
			Observation        string             `json:"observation_kind"`
			InvocationState    JobInvocationState `json:"invocation_state,omitempty"`
			Status             string             `json:"status"`
			Ticks              int64              `json:"ticks"`
			Selected           int64              `json:"selected_observations"`
			MaxSelected        int64              `json:"max_selected_sample"`
			Attempted          int64              `json:"attempted"`
			Returned           int64              `json:"returned"`
			Failed             int64              `json:"failed"`
			Sent               int64              `json:"smtp_sent_acknowledged"`
			Retry              int64              `json:"smtp_retry_scheduled"`
			Terminal           int64              `json:"smtp_terminal_failed"`
			Oldest             int64              `json:"oldest_selected_age_seconds"`
			UnknownAges        int64              `json:"unknown_ages"`
			BatchLimit         bool               `json:"batch_limit_reached"`
			Unavailable        bool               `json:"invocation_unavailable"`
			Stale              bool               `json:"stale_sample"`
			PolicyInvalid      bool               `json:"age_policy_invalid"`
			PolicyUnobservable bool               `json:"age_policy_unobservable"`
			Duration           int64              `json:"duration_ms"`
		}{l.shipper.service, l.shipper.release, l.shipper.environment, tick.Job, jobObservationKind(tick), tick.InvocationState, status, report.ticks, tick.Selected, report.maxSelected, tick.Attempted, tick.Returned, tick.Failed, tick.SentAcknowledged, tick.RetryScheduled, tick.TerminalFailed, tick.OldestSelectedAgeSeconds, tick.UnknownAges, tick.BatchLimitReached, tick.Unavailable, report.stale, report.policyInvalid, report.policyUnobservable, tick.Duration.Milliseconds()}
		raw, _ := json.Marshal(attrs) // fixed scalar schema, no arbitrary marshalers
		if l.shipper.allow() {
			severity := "info"
			if invocationError || smtpError {
				severity = "error"
			}
			l.shipper.enqueue(nativeLogLine{Severity: severity, Body: "Hash critical job invocation returned", Attributes: raw, Timestamp: report.completedAt.UTC().Format(time.RFC3339Nano)})
		} else {
			l.shipper.dropped.Add(1)
		}
	}
	// Native job logs bypass the generic warn floor, but retain the original
	// shipper queue/rate/batch/time bounds. Issues remain distinct from checkins:
	// an empty successful queue poll cannot resolve an earlier SMTP issue.
	ctx := sentry.SetHubOnContext(l.ctx, sentry.NewHub(l.client, sentry.NewScope()))
	if tick.Unavailable && tick.Job == JobFinalizeRetry {
		CaptureOperationFailure(ctx, OperationWorker, FailureUnavailable)
	}
	if tick.Failed > 0 && tick.Job == JobFinalizeRetry {
		CaptureOperationFailure(ctx, OperationEvidence, FailureUnavailable)
	}
	if smtpError {
		CaptureOperationFailure(ctx, OperationSMTP, FailureDependency)
	}
	if l.checkinURL != "" {
		l.postCheckin(l.checkinURL + "-" + jobSuffix(tick.Job) + "?status=" + status)
	}
}
