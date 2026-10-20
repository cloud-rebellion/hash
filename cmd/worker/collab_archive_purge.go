// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
)

// Recovery replay is operational draft data, separate from locked signing
// evidence. Expiry is durable per archive; open privacy requests defer purge.
func (w *worker) loopCollabArchivePurge(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		w.runCollabArchivePurgeOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (w *worker) runCollabArchivePurgeOnce(ctx context.Context) {
	started := time.Now()
	state := w.runCollabArchivePurgeOnceObserved(ctx)
	w.reportInvocation385(ctx, flarereport.JobCollabArchivePurge, started, state)
}
func (w *worker) runCollabArchivePurgeOnceObserved(ctx context.Context) flarereport.JobInvocationState {
	batchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, err := w.queries.PurgeExpiredCollabRecoveryArchives(batchCtx)
	cancel()
	if err != nil && ctx.Err() == nil {
		slog.Warn("collab_archive_purge: failed; retry next tick", "err", err)
	}
	if err != nil {
		return flarereport.InvocationUnavailable
	}
	return flarereport.InvocationReturned
}
