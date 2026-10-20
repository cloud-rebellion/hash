//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"strings"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
)

// The request phase repeats root SHARE during both real audit preflights; a
// root-query ordinal cannot identify dispatch. Observe its actual backend and
// both actual request-event INSERTs, then its successful COMMIT command tag.
// Only the next actual root statement can be the dispatch phase. These facts
// supply no receipt, mutation authority, SQL result or successful app response.
type signerAIRequestCommit335 struct {
	backend     atomic.Uint32
	requested   atomic.Bool
	aiRequested atomic.Bool
	committed   atomic.Bool
}

func (o *signerAIRequestCommit335) observeStart(c *pgx.Conn, d pgx.TraceQueryStartData) {
	pid := c.PgConn().PID()
	if strings.HasPrefix(d.SQL, "-- name: LockDocumentAIRootV1") {
		o.backend.CompareAndSwap(0, pid)
	}
	if o.backend.Load() != pid || !strings.HasPrefix(d.SQL, "-- name: InsertEvent") || len(d.Args) < 5 {
		return
	}
	kind, ok := d.Args[4].(string)
	if !ok {
		return
	}
	switch kind {
	case "clarifier.requested":
		o.requested.Store(true)
	case "ai.requested":
		o.aiRequested.Store(true)
	}
}
func (o *signerAIRequestCommit335) observeEnd(c *pgx.Conn, d pgx.TraceQueryEndData) {
	if d.Err == nil && d.CommandTag.String() == "COMMIT" && c.PgConn().PID() == o.backend.Load() && o.requested.Load() && o.aiRequested.Load() {
		o.committed.Store(true)
	}
}

func (o *signerAIRequestCommit335) dispatchRoot(c *pgx.Conn, d pgx.TraceQueryStartData) bool {
	return o.committed.Load() && o.backend.Load() != 0 && c.PgConn().PID() != o.backend.Load() && strings.HasPrefix(d.SQL, "-- name: LockDocumentAIRootV1")
}
