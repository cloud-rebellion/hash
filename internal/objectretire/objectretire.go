// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package objectretire owns the durable obligation to delete stored object
// versions after a committed privacy erasure.
//
// A DSR erasure removes the rows that name the subject's replaced PDF versions,
// so the objects can only be deleted after the transaction commits, and the rows
// that were the only pointer to them are gone by then. Record writes the pointer
// into the same transaction (pending_object_deletions_v1, M127). Attempt and
// Sweep delete the exact version and remove the row only after the object store
// confirmed it; a failure keeps the row, counts the attempt and backs off. The
// request handler calls Attempt right after commit and the worker calls Sweep, so
// a storage fault, a crash after commit or an ambiguous commit never leaves a
// fulfilled erasure with an object nobody can find.
package objectretire

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

const (
	// FirstAttemptGrace holds the sweep off a freshly recorded row while the
	// request that wrote it makes the first attempt.
	FirstAttemptGrace = 2 * time.Minute
	// LeaseDuration is how long a sweep owns a claimed row. It must outlast the
	// batch: AttemptTimeout times BatchLimit is the worst case if every delete hangs.
	LeaseDuration = 30 * time.Minute
	// AttemptTimeout bounds one object delete, including the exact-version
	// verification and inventory checks the storage client performs.
	AttemptTimeout = 15 * time.Second
	// BatchLimit bounds one sweep.
	BatchLimit = 50
	// AlertAttempts is the failed-attempt count at which a row is logged at
	// Error level on every further failure. With the 6 h backoff cap that is a
	// few log lines a day per row that cannot drain, naming the row and the cause.
	AlertAttempts = 5

	bookkeepingTimeout = 5 * time.Second
	baseBackoff        = 30 * time.Second
	maxBackoff         = 6 * time.Hour
	maxErrorBytes      = 300
)

// Object is one exact stored version: key, version id and committed SHA-256.
type Object struct {
	Key       string
	VersionID string
	SHA256    []byte
}

// Store is the slice of generated queries this package needs. *generated.Queries
// satisfies it, bound to a transaction for Record and to the pool otherwise.
type Store interface {
	InsertPendingObjectDeletionV1(context.Context, generated.InsertPendingObjectDeletionV1Params) (*generated.PendingObjectDeletionsV1, error)
	ClaimDuePendingObjectDeletionsV1(context.Context, generated.ClaimDuePendingObjectDeletionsV1Params) ([]*generated.PendingObjectDeletionsV1, error)
	DeletePendingObjectDeletionV1(context.Context, generated.DeletePendingObjectDeletionV1Params) (int64, error)
	RecordPendingObjectDeletionFailureV1(context.Context, generated.RecordPendingObjectDeletionFailureV1Params) (int64, error)
}

// Deleter removes one exact object version. An absent version is success, which
// is what makes a retry after a crash between the delete and the row removal safe.
type Deleter interface {
	DeleteVersion(ctx context.Context, key, versionID string, expectedSHA256 []byte) error
}

// Record writes one pending row per object. Call it with a Store bound to the
// erasure's transaction, before the commit, so the obligation commits with the
// erasure or not at all.
func Record(ctx context.Context, q Store, orgID, documentID uuid.UUID, dsrID *uuid.UUID, objects []Object) ([]*generated.PendingObjectDeletionsV1, error) {
	rows := make([]*generated.PendingObjectDeletionsV1, 0, len(objects))
	for _, object := range objects {
		var dsr pgtype.UUID
		if dsrID != nil {
			dsr = pgtype.UUID{Bytes: *dsrID, Valid: true}
		}
		row, err := q.InsertPendingObjectDeletionV1(ctx, generated.InsertPendingObjectDeletionV1Params{
			ID: uuid.New(), OrgID: orgID, DocumentID: documentID, DsrID: dsr,
			StorageKey: object.Key, VersionID: object.VersionID, Sha256: object.SHA256,
			GraceSeconds: FirstAttemptGrace.Seconds(),
		})
		if err != nil {
			return nil, fmt.Errorf("record pending object deletion: %w", err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Attempt deletes one pending object and removes its row, or records the failure.
// It reports whether the object is confirmed gone. The context is detached from
// the caller's cancellation: the requests most likely to be canceled are the ones
// whose cleanup matters most.
func Attempt(parent context.Context, q Store, deleter Deleter, row *generated.PendingObjectDeletionsV1) bool {
	return attempt(parent, q, deleter, row, AttemptTimeout)
}

// attempt is Attempt with the delete bounded by min(limit, AttemptTimeout).
func attempt(parent context.Context, q Store, deleter Deleter, row *generated.PendingObjectDeletionsV1, limit time.Duration) bool {
	if row == nil {
		return false
	}
	base := context.WithoutCancel(parent)
	var err error
	budgetCut := false
	if deleter == nil {
		err = fmt.Errorf("object storage is unavailable")
	} else {
		ctx, cancel := context.WithTimeout(base, min(limit, AttemptTimeout))
		err = deleter.DeleteVersion(ctx, row.StorageKey, row.VersionID, row.Sha256)
		budgetCut = limit < AttemptTimeout && errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded)
		cancel()
	}
	if budgetCut {
		// The caller's budget ended the delete, not the store: the object may
		// already be gone (RemoveObject precedes two bound confirmations). That
		// is not a failed attempt. Counting it would add an attempt and overwrite
		// a real last_error; the row keeps its grace and the sweep, which finds
		// an absent version and removes the row, settles it.
		return false
	}
	bookkeeping, cancel := context.WithTimeout(base, bookkeepingTimeout)
	defer cancel()
	if err == nil {
		if _, delErr := q.DeletePendingObjectDeletionV1(bookkeeping, generated.DeletePendingObjectDeletionV1Params{ID: row.ID, OrgID: row.OrgID}); delErr != nil {
			// The object is gone; the row stays and the next sweep finds the
			// version absent, which counts as done.
			return false
		}
		return true
	}
	lastError := DescribeError(err)
	_, _ = q.RecordPendingObjectDeletionFailureV1(bookkeeping, generated.RecordPendingObjectDeletionFailureV1Params{
		ID: row.ID, OrgID: row.OrgID, LastError: lastError, BackoffSeconds: Backoff(row.Attempts).Seconds(),
	})
	// A delete that can never succeed (a COMPLIANCE lock, an IAM deny, version
	// drift) retries forever by design, so the row is the only trace of an
	// erasure that reads fulfilled while the object is still stored. Name it.
	if attempts := row.Attempts + 1; attempts >= AlertAttempts {
		slog.Error("pending_object_deletions: object version still not deleted; operator action may be needed",
			"id", row.ID, "org_id", row.OrgID, "document_id", row.DocumentID, "attempts", attempts, "last_error", lastError)
	}
	return false
}

// AttemptAll runs an attempt for each row and returns how many objects are gone.
// The budget caps the delete calls, not only the decision to start one: each
// attempt gets whatever is left of it (never more than AttemptTimeout), and once
// it has elapsed no further attempt starts. The remaining rows stay pending for
// the sweep. A caller is therefore held for at most the budget plus one
// bookkeeping write (bookkeepingTimeout) even if the storage endpoint hangs. A
// budget of zero or less means no limit beyond AttemptTimeout per attempt.
func AttemptAll(ctx context.Context, q Store, deleter Deleter, rows []*generated.PendingObjectDeletionsV1, budget time.Duration) int {
	started := time.Now()
	done := 0
	for _, row := range rows {
		limit := AttemptTimeout
		if budget > 0 {
			remaining := budget - time.Since(started)
			if remaining <= 0 {
				break
			}
			limit = remaining
		}
		if attempt(ctx, q, deleter, row, limit) {
			done++
		}
	}
	return done
}

// Sweep leases a bounded batch of due rows and attempts each. It returns the
// number leased and the number confirmed gone.
func Sweep(ctx context.Context, q Store, deleter Deleter) (claimed, deleted int, err error) {
	claimCtx, cancel := context.WithTimeout(ctx, bookkeepingTimeout)
	rows, err := q.ClaimDuePendingObjectDeletionsV1(claimCtx, generated.ClaimDuePendingObjectDeletionsV1Params{
		LeaseSeconds: LeaseDuration.Seconds(), BatchLimit: BatchLimit,
	})
	cancel()
	if err != nil {
		return 0, 0, fmt.Errorf("claim pending object deletions: %w", err)
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			// The rest stay leased until the lease ends, then become due again.
			break
		}
		if Attempt(ctx, q, deleter, row) {
			deleted++
		}
	}
	return len(rows), deleted, nil
}

// Backoff is the wait before the next attempt, given the attempts already made.
func Backoff(attempts int32) time.Duration {
	delay := baseBackoff
	for i := int32(0); i < attempts && delay < maxBackoff; i++ {
		delay *= 2
	}
	return min(delay, maxBackoff)
}

// DescribeError turns a storage error into the bounded text kept in last_error.
// Storage errors name the bucket, the key or the provider's reason, never request
// data; control characters are dropped and the length is capped.
func DescribeError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	if len(text) > maxErrorBytes {
		text = text[:maxErrorBytes]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	return text
}
