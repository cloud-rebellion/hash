// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"encoding/json"
	"strconv"
	"time"
)

// This is a local counter snapshot in the EXISTING native logs stream. It is
// neither a metric export nor a collector receipt. Decimal strings preserve
// exact64-bit values in JSON clients; a new owner epoch starts a comparison
// window. Counters are local/non-durable; first snapshots need not start at zero.
// SDK queue/drop/flush and receiver persistence are deliberately not inferred.
func (l *Lifecycle) emitDeliveryDiagnostics409() {
	if l == nil || l.ctx == nil || l.ctx.Err() != nil || !l.diagnosticsBusy.CompareAndSwap(false, true) {
		return
	}
	defer l.diagnosticsBusy.Store(false)
	sh := l.shipper
	if sh == nil {
		return // FLARE_LOG_LEVEL=off remains off; no alternate egress.
	}
	if (l.service != "hash" && l.service != "hash-worker") || sh.service != l.service || identityValue(sh.release) == "" || identityValue(sh.environment) == "" || l.diagnosticsEpoch.IsZero() {
		sh.rejected.Add(1)
		return
	}
	epoch := l.diagnosticsEpoch.UTC().Format(time.RFC3339Nano)
	if len(epoch) > 40 {
		sh.rejected.Add(1)
		return
	}
	if !sh.allow() {
		sh.dropped.Add(1)
		return
	}
	d := l.Diagnostics()
	attrs := struct {
		Schema               string `json:"schema"`
		Service              string `json:"service"`
		Release              string `json:"release"`
		Environment          string `json:"environment"`
		CounterScope         string `json:"counter_scope"`
		CounterEpoch         string `json:"counter_epoch"`
		LogDropped           string `json:"log_dropped"`
		LogFailed            string `json:"log_failed"`
		LogRejected          string `json:"log_rejected"`
		CheckinFailures      string `json:"checkin_failures"`
		CheckinResponses     string `json:"checkin_responses"`
		JobDropped           string `json:"job_dropped"`
		JobRejected          string `json:"job_rejected"`
		CheckinsConfigured   bool   `json:"checkins_configured"`
		SDKDeliveryAccounted bool   `json:"sdk_delivery_accounted"`
	}{"hash-delivery-diagnostics-v1", sh.service, sh.release, sh.environment, "process_local", epoch,
		strconv.FormatInt(d.Dropped, 10), strconv.FormatInt(d.Failed, 10), strconv.FormatInt(d.Rejected, 10),
		strconv.FormatUint(d.CheckinFailures, 10), strconv.FormatUint(d.CheckinResponses, 10),
		strconv.FormatUint(d.JobDropped, 10), strconv.FormatUint(d.JobRejected, 10), l.checkinURL != "", false}
	raw, err := json.Marshal(attrs) // closed fixed scalar struct, no caller values/getters
	if err != nil || len(raw) > logShipMaxAttrs {
		sh.rejected.Add(1)
		return
	}
	// Bypass only the generic level floor, exactly like fixed job reports; keep
	// original rate/queue/context bounds. No slog/SDK callback can recurse here.
	// A drop of THIS snapshot increments log_dropped for a later real snapshot.
	sh.enqueue(nativeLogLine{Severity: "info", Body: "Hash telemetry delivery diagnostics", Attributes: raw, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)})
}
