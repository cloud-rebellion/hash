// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

const heartbeatInterval = 2 * time.Minute

type Lifecycle struct {
	ctx                context.Context
	cancel             context.CancelFunc
	done               chan struct{}
	shipper            *logShipper
	client             *sentry.Client
	once               sync.Once
	checkinURL         string
	checkinKey         string
	checkinFailures    atomic.Uint64
	checkinResponses   atomic.Uint64
	checkinProgress    chan struct{}
	jobDropped         atomic.Uint64
	jobRejected        atomic.Uint64
	service            string
	diagnosticsEpoch   time.Time
	diagnosticsBusy    atomic.Bool
	operationalMetrics atomic.Pointer[operationalMetricSampleV1]
	metricAcknowledged atomic.Uint64
	metricFailures     atomic.Uint64
	jobQueue           chan jobReport
	jobMu              sync.Mutex
	jobWindows         [criticalJobCount]jobWindow
	jobMaxAge          [criticalJobCount]int64
	jobPolicyInvalid   [criticalJobCount]bool
}

func newLifecycle(parent context.Context, ready <-chan struct{}, service string, client *sentry.Client) *Lifecycle {
	return newLifecycleWithShipper(parent, ready, service, client, nil)
}

// Attach the immutable native shipper before the existing ready owner starts.
// A caller may supply an already-closed ready channel.
func newLifecycleWithShipper(parent context.Context, ready <-chan struct{}, service string, client *sentry.Client, makeShipper func(context.Context) *logShipper) *Lifecycle {
	diagnosticsEnabled := makeShipper != nil
	ctx, cancel := context.WithCancel(parent)
	owner := &Lifecycle{ctx: ctx, cancel: cancel, done: make(chan struct{}), client: client, service: service, checkinProgress: make(chan struct{}, 1), jobQueue: make(chan jobReport, 16)}
	owner.diagnosticsEpoch = time.Now().UTC()
	if makeShipper != nil {
		owner.shipper = makeShipper(owner.ctx)
	}
	owner.configureJobs()
	prefix := os.Getenv("HASH_FLARE_MONITOR_PREFIX")
	valid := prefix != "" && len(prefix) <= 40
	if valid {
		first := prefix[0]
		valid = first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z' || first >= '0' && first <= '9'
	}
	for _, ch := range prefix {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("._-", ch)) {
			valid = false
		}
	}
	if valid {
		if base, key, ok := parseDSNForLogs(os.Getenv("FLARE_DSN")); ok {
			owner.checkinURL = base[:len(base)-len("/logs")] + "/checkins/" + prefix + "-" + service
			owner.checkinKey = key
		}
	}
	go func() {
		defer close(owner.done)
		select {
		case <-ctx.Done():
			return
		case <-ready:
		}
		if ctx.Err() != nil {
			return
		}
		emit := func() {
			if diagnosticsEnabled {
				owner.emitDeliveryDiagnostics409()
			}
			if os.Getenv("FLARE_HEARTBEAT") != "off" {
				hub := sentry.NewHub(client, sentry.NewScope())
				hub.WithScope(func(scope *sentry.Scope) {
					scope.Clear()
					scope.SetLevel(sentry.LevelInfo)
					scope.SetTag("service", service)
					scope.SetFingerprint([]string{"service-up", service})
					hub.CaptureMessage("service-up:" + service)
				})
			}
			owner.checkin(service)
			owner.emitOperationalMetricsV1()
		}
		emit()
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				emit()
			case report := <-owner.jobQueue:
				if ctx.Err() == nil {
					if report.backlogHealth {
						owner.sendOperationalBacklogHealthV1(report)
					} else {
						owner.sendJobReport(report)
					}
				}
			}
		}
	}()
	return owner
}
func (l *Lifecycle) checkin(service string) {
	if l.checkinURL == "" {
		return
	}
	l.postCheckin(l.checkinURL)
}

func (l *Lifecycle) postCheckin(target string) {
	completed := false
	// A collapsed pulse accompanies completion of this actual client phase. No
	// caller callback, goroutine, network retry or new time budget is introduced.
	defer func() {
		if completed {
			l.checkinResponses.Add(1)
		}
		select {
		case l.checkinProgress <- struct{}{}:
		default:
		}
	}()
	ctx, stop := context.WithTimeout(l.ctx, 5*time.Second)
	defer stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		l.checkinFailures.Add(1)
		return
	}
	req.Header.Set("X-Flare-Key", l.checkinKey)
	response, err := (&http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		l.checkinFailures.Add(1)
		return
	}
	if !completedCheckinResponse(response) {
		l.checkinFailures.Add(1)
		return
	}
	completed = true
}

// completedCheckinResponse means the original bounded drain AND Close returned
// successfully on a 2xx response. It does not assert EOF beyond 4096 bytes, stored
// collector data, durable acceptance, or retirement of shared HTTP connections.
func completedCheckinResponse(response *http.Response) bool {
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	return readErr == nil && closeErr == nil && response.StatusCode >= 200 && response.StatusCode < 300
}

// Close cancels and joins the ready sender and native log worker, then flushes
// SDK events under the caller's independent finite deadline. No detached drain.
func (l *Lifecycle) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		return context.Canceled
	}
	l.once.Do(func() {
		if l.shipper != nil {
			l.shipper.beginClose(ctx)
		}
		l.cancel()
	})
	select {
	case <-l.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if l.shipper != nil {
		select {
		case <-l.shipper.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if l.client != nil && !l.client.FlushWithContext(ctx) {
		if err := ctx.Err(); err != nil {
			return err
		}
		return context.DeadlineExceeded
	}
	return nil
}

// DeliveryDiagnostics is payload-free. This bounded API supports later admin
// metrics plumbing; private counters alone are not claimed as live monitoring.
type DeliveryDiagnostics struct {
	Dropped  int64 `json:"dropped"`
	Failed   int64 `json:"failed"`
	Rejected int64 `json:"rejected"`
	// Failures includes request/transport/read/close/status errors, including
	// cancellation. It does not by itself prove collector refusal.
	CheckinFailures uint64 `json:"checkin_failures"`
	// Responses counts successful bounded local response handling, not persisted
	// or accepted Flare receipts.
	CheckinResponses uint64 `json:"checkin_responses"`
	JobDropped       uint64 `json:"job_dropped"`
	JobRejected      uint64 `json:"job_rejected"`
	// Metric acknowledgements require the native receiver's complete committed
	// receipt and full point count. Failures also include projection refusals.
	MetricAcknowledgedBatches uint64 `json:"metric_acknowledged_batches"`
	MetricFailures            uint64 `json:"metric_failures"`
}

func (l *Lifecycle) Diagnostics() DeliveryDiagnostics {
	if l == nil {
		return DeliveryDiagnostics{}
	}
	d := DeliveryDiagnostics{CheckinFailures: l.checkinFailures.Load(), CheckinResponses: l.checkinResponses.Load(), JobDropped: l.jobDropped.Load(), JobRejected: l.jobRejected.Load()}
	d.MetricAcknowledgedBatches = l.metricAcknowledged.Load()
	d.MetricFailures = l.metricFailures.Load()
	if l.shipper != nil {
		d.Dropped = l.shipper.dropped.Load()
		d.Failed = l.shipper.failed.Load()
		d.Rejected = l.shipper.rejected.Load()
	}
	return d
}
