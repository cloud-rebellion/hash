// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/bright-interaction/hash/internal/objectretire"
	"github.com/bright-interaction/hash/internal/storage"
)

// Pending object deletion sweep (M127).
//
// A committed DSR PDF-history erasure leaves one pending_object_deletions_v1 row
// per stored object version it still owes the object store. The request makes the
// first attempt right after commit; this loop retries every due row until the
// exact version is gone, so a storage outage, a crash after commit or an ambiguous
// commit cannot leave a fulfilled erasure with the subject's PDF still stored.
//
// Same shape as the soft-delete purge: a bounded batch is leased by pushing
// next_attempt_at into the future (peers skip it, a crashed sweep leaves it
// eligible later), each row is attempted on its own, and a row is removed only
// after the object store confirmed the deletion. A failed attempt records a
// bounded error, counts the attempt and backs off exponentially.
//
// The soft-delete purge keeps its own delete-before-commit path on purpose: its
// revision rows are still present until it commits, so they remain the retry token
// and a storage failure rolls the row erasure back. Only an erasure that commits
// first needs the table.
const pendingObjectDeletionInterval = time.Minute

func (w *worker) loopPendingObjectDeletions(ctx context.Context) {
	tick := time.NewTicker(pendingObjectDeletionInterval)
	defer tick.Stop()
	for {
		w.runPendingObjectDeletionsOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (w *worker) runPendingObjectDeletionsOnce(ctx context.Context) {
	if w.queries == nil {
		return
	}
	if client, isClient := w.storage.(*storage.Client); w.storage == nil || (isClient && client == nil) {
		// Object storage failed to initialize; rows stay pending and are not
		// counted as attempts until it is available.
		slog.Warn("pending_object_deletions: object storage unavailable; rows stay pending")
		return
	}
	claimed, deleted, err := objectretire.Sweep(ctx, w.queries, w.storage)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("pending_object_deletions: sweep failed; retry next tick", "err", err)
		}
		return
	}
	if claimed > deleted {
		slog.Warn("pending_object_deletions: objects not yet deleted; retrying with backoff", "claimed", claimed, "deleted", deleted)
		return
	}
	slog.Debug("pending_object_deletions: tick complete", "claimed", claimed, "deleted", deleted)
}
