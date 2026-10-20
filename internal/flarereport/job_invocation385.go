// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"time"
)

// JobInvocationState describes the original invocation, never SMTP receipt,
// document finality, row counts, legal effects or physical owner retirement.
type JobInvocationState string

const (
	InvocationReturned     JobInvocationState = "returned"
	InvocationPending      JobInvocationState = "pending"
	InvocationPartial      JobInvocationState = "partial"
	InvocationUnavailable  JobInvocationState = "unavailable"
	InvocationUnobservable JobInvocationState = "unobservable"
)

type JobInvocation struct {
	Job      CriticalJob
	State    JobInvocationState
	Duration time.Duration
}

func validInvocationState(state JobInvocationState) bool {
	switch state {
	case InvocationReturned, InvocationPending, InvocationPartial, InvocationUnavailable, InvocationUnobservable:
		return true
	}
	return false
}
func invocationStateError(state JobInvocationState) bool {
	return state == InvocationPartial || state == InvocationUnavailable || state == InvocationUnobservable
}
func invocationStateRank(state JobInvocationState) int {
	switch state {
	case "":
		return 0
	case InvocationReturned:
		return 1
	case InvocationPending:
		return 2
	case InvocationPartial:
		return 3
	case InvocationUnavailable:
		return 4
	case InvocationUnobservable:
		return 5
	}
	return 6
}
func mergeInvocationState(a, b JobInvocationState) JobInvocationState {
	if invocationStateRank(b) > invocationStateRank(a) {
		return b
	}
	return a
}
func jobObservationKind(tick JobTick) string {
	if tick.InvocationState != "" {
		return "invocation"
	}
	return "selected_sample"
}

// RecordJobInvocation cannot claim selected rows or throughput. New jobs keep
// their original100/500/scoped inventory behavior without raising the existing
// mail/finalizer50-row validation contract, queue16 or transport/time bounds.
func (l *Lifecycle) RecordJobInvocation(ctx context.Context, observation JobInvocation) {
	if jobIndex(observation.Job) < 2 {
		if l != nil {
			l.jobRejected.Add(1)
		}
		return
	}
	l.RecordJobTick(ctx, JobTick{Job: observation.Job, InvocationState: observation.State, Duration: observation.Duration})
}
