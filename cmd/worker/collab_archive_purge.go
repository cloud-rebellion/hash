// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package main

import (
	"context"
	"log/slog"
	"time"
)

// Recovery replay is operational draft data, separate from locked signing
// evidence. Expiry is durable per archive; open privacy requests defer purge.
func (w *worker) loopCollabArchivePurge(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		batchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := w.queries.PurgeExpiredCollabRecoveryArchives(batchCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("collab_archive_purge: failed; retry next tick", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
