// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
)

// Finalize-retry loop. When the last signer signs, the signature is committed
// before finalize runs; if Gotenberg or MinIO is down at that moment the
// document is left fully-signed but in_progress with no final PDF. This loop
// finds those stranded documents and re-invokes finalize idempotently, so a
// transient render/storage outage no longer leaves a legally-signed contract
// without its final PDF + audit certificate.
//
// Cadence: every 2 minutes. FinalizeStranded is guarded by a per-document
// advisory lock + an already-finalized short-circuit, so it never double-
// renders even if a late inline finalize races it.

const finalizeRetryInterval = 2 * time.Minute

func (w *worker) loopFinalizeRetry(ctx context.Context) {
	if w.signEngine == nil {
		slog.Warn("finalize_retry: sign engine unavailable (storage init failed); loop disabled")
		return
	}
	tick := time.NewTicker(finalizeRetryInterval)
	defer tick.Stop()
	w.runFinalizeRetryOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runFinalizeRetryOnce(ctx)
		}
	}
}

func (w *worker) runFinalizeRetryOnce(ctx context.Context) {
	started := time.Now()
	tick := flarereport.JobTick{Job: flarereport.JobFinalizeRetry}
	returned := false
	// Registered before the synchronous job work. Returning from FinalizeStranded
	// is an invocation result, not proof that a final PDF/report exists.
	defer func() {
		if returned {
			tick.Duration = time.Since(started)
			w.telemetry.RecordJobTick(ctx, tick)
		}
	}()
	docs, err := w.queries.GetStrandedDocuments(ctx, 50)
	if err != nil {
		tick.Unavailable = true
		slog.Warn("finalize_retry: list stranded", "err", err)
		returned = true
		return
	}
	tick.Selected = int64(len(docs))
	tick.BatchLimitReached = len(docs) == 50
	for _, d := range docs {
		observeJobAge(&tick, d.UpdatedAt)
		tick.Attempted++
		if err := w.signEngine.FinalizeStranded(ctx, d.OrgID, d.ID); err != nil {
			tick.Failed++
			// Don't poison the batch: log and move on. The doc stays stranded
			// and is retried next tick once the underlying outage clears.
			slog.Warn("finalize_retry: finalize failed",
				"document_id", d.ID, "org_id", d.OrgID, "err", err)
			continue
		}
		tick.Returned++
		slog.Info("finalize_retry: re-finalized stranded document",
			"document_id", d.ID, "org_id", d.OrgID)
	}
	returned = true
}
