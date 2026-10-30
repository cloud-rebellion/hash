//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Historical schemas do not contain today's complete generated.Document.
// Keep live canonical selectors, but freeze the two schema61/62 claim mutations:
// later participant-report schema assignments are not part of these cutovers.
// Only wildcard outputs and sqlc named arguments are adapted below; no current
// function/column or fabricated report evidence is installed in the old schema.
// Load everything on the test goroutine before starting any concurrent work.
// Frozen historical projection of the application statements inspected at
// 8125783a64889b4a08fec06aa227ff4eb6e9304d. The only omitted assignments are the
// later participant_report_schema selector/copy. Root tenant/status/deletion
// predicates, every family send/response/history high-water, retention function,
// child eligibility, canonical lock ordering and exact shared timestamps remain.
// These fixtures qualify M61/M62 chronology; current native signing is separate.
const historicalBeginDocumentFinalization62 = `-- name: BeginDocumentFinalization :one
-- The surrounding transaction holds the root row lock and has rechecked the
-- exact recipient readiness predicate. Capture one post-readiness timestamp,
-- but never let database clock rollback place completion before the durable
-- send epoch or any already-committed response or retained participant-history
-- row in the envelope family. PostgreSQL timestamps have microsecond precision,
-- so advancing each
-- prior high-water by one microsecond gives a strict and representable order.
WITH finalizing_root AS MATERIALIZED (
    SELECT d.id, d.org_id, d.sent_at
    FROM documents d
    WHERE d.id = sqlc.arg(id)
      AND d.org_id = sqlc.arg(org_id)
      AND d.status = 'in_progress'
      AND d.sent_at IS NOT NULL
      AND d.deleted_at IS NULL
), lifecycle_clock AS MATERIALIZED (
    SELECT root.id,
           GREATEST(
               statement_timestamp(),
               COALESCE((
                   SELECT max(member.sent_at) + interval '1 microsecond'
                   FROM documents member
                   WHERE member.id = root.id OR member.parent_envelope_id = root.id
               ), '-infinity'::timestamptz),
               COALESCE((
                   SELECT max(r.signed_at) + interval '1 microsecond'
                   FROM recipients r
                   JOIN documents member ON member.id = r.document_id
                   WHERE member.id = root.id OR member.parent_envelope_id = root.id
               ), '-infinity'::timestamptz),
               COALESCE((
                   SELECT max(s.signed_at) + interval '1 microsecond'
                   FROM signatures s
                   JOIN documents member ON member.id = s.document_id
                   WHERE member.id = root.id OR member.parent_envelope_id = root.id
               ), '-infinity'::timestamptz),
               COALESCE((
                   SELECT max(e.created_at) + interval '1 microsecond'
                   FROM events e
                   JOIN documents member ON member.id = e.document_id
                   WHERE e.org_id = root.org_id
                     AND (member.id = root.id OR member.parent_envelope_id = root.id)
               ), '-infinity'::timestamptz),
               COALESCE((
                   SELECT max(c.created_at) + interval '1 microsecond'
                   FROM document_comments c
                   JOIN documents member ON member.id = c.document_id
                   WHERE member.org_id = root.org_id
                     AND (member.id = root.id OR member.parent_envelope_id = root.id)
               ), '-infinity'::timestamptz),
               COALESCE((
                   SELECT max(v.created_at) + interval '1 microsecond'
                   FROM document_versions v
                   JOIN documents member ON member.id = v.document_id AND member.org_id = v.org_id
                   WHERE member.org_id = root.org_id
                     AND (member.id = root.id OR member.parent_envelope_id = root.id)
               ), '-infinity'::timestamptz),
               COALESCE((
                   SELECT max(p.updated_at) + interval '1 microsecond'
                   FROM document_proposals p
                   JOIN documents member ON member.id = p.document_id AND member.org_id = p.org_id
                   WHERE member.org_id = root.org_id
                     AND (member.id = root.id OR member.parent_envelope_id = root.id)
               ), '-infinity'::timestamptz)
           ) AS effective_at
    FROM finalizing_root root
)
UPDATE documents AS target
SET status = 'finalizing',
    completion_effective_at_bound = TRUE,
    completion_effective_at = COALESCE(target.completion_effective_at, lifecycle_clock.effective_at),
    -- Object Lock timestamps have whole-second precision. Round upward after
    -- the calendar-year addition so the deadline is never even fractionally
    -- shorter than the configured retention period.
    finalization_retain_until = COALESCE(
        finalization_retain_until,
        hash_evidence_retain_until(
            COALESCE(target.completion_effective_at, lifecycle_clock.effective_at),
            sqlc.arg(retention_years)::integer
        )
    ),
    updated_at = lifecycle_clock.effective_at
FROM lifecycle_clock
WHERE target.id = lifecycle_clock.id
  AND target.id = sqlc.arg(id)
  AND target.org_id = sqlc.arg(org_id)
  AND target.status = 'in_progress'
  AND target.sent_at IS NOT NULL
  AND target.deleted_at IS NULL
RETURNING target.*;`

const historicalBeginEnvelopeChildrenFinalization62 = `-- name: BeginEnvelopeChildrenFinalization :many
-- The caller holds the root and every child row lock before the parent claim
-- allocates its completion timestamp. Move the entire family into the same
-- non-interactive state in that transaction and copy, rather than recompute,
-- the root's exact completion and retention commitments. A child-addressed
-- comment or other lifecycle mutation therefore either commits before the
-- family high-water snapshot or observes finalizing and fails closed.
UPDATE documents AS child
SET status = 'finalizing',
    completion_effective_at_bound = parent.completion_effective_at_bound,
    completion_effective_at = parent.completion_effective_at,
    finalization_retain_until = parent.finalization_retain_until,
    updated_at = parent.completion_effective_at
FROM documents AS parent
WHERE child.parent_envelope_id = $1
  AND child.org_id = $2
  AND child.status IN ('sent','in_progress')
  AND child.deleted_at IS NULL
  AND parent.id = $1
  AND parent.org_id = $2
  AND parent.status = 'finalizing'
  AND parent.is_envelope = TRUE
  AND parent.parent_envelope_id IS NULL
  AND parent.deleted_at IS NULL
  AND parent.completion_effective_at_bound = TRUE
  AND parent.completion_effective_at IS NOT NULL
  AND parent.finalization_retain_until IS NOT NULL
RETURNING child.*;`

type historicalFamilySQL62 struct {
	db  generated.DBTX
	sql map[string]string
}

type historicalFamilyMember62 struct {
	ID, OrgID                  uuid.UUID
	Status                     string
	ParentEnvelopeID           pgtype.UUID
	CompletionEffectiveAtBound bool
	CompletionEffectiveAt      pgtype.Timestamptz
	FinalizationRetainUntil    pgtype.Timestamptz
	UpdatedAt                  pgtype.Timestamptz
}

func newHistoricalFamilySQL62(t *testing.T, db generated.DBTX) *historicalFamilySQL62 {
	t.Helper()
	q := &historicalFamilySQL62{db: db, sql: make(map[string]string)}
	for _, item := range []struct{ file, name, wildcard, prefix, frozen string }{
		{"documents.sql", "GetDocumentForUpdate", "SELECT *", "", ""},
		{"documents.sql", "GetStrandedDocuments", "SELECT d.*", "d.", ""},
		{"envelopes.sql", "ListEnvelopeChildren", "SELECT *", "", ""},
		{"envelopes.sql", "BeginEnvelopeChildrenFinalization", "RETURNING child.*", "child.", historicalBeginEnvelopeChildrenFinalization62},
		{"finalization.sql", "BeginDocumentFinalization", "RETURNING target.*", "target.", historicalBeginDocumentFinalization62},
	} {
		raw := []byte(item.frozen)
		if item.frozen == "" {
			var err error
			raw, err = os.ReadFile(filepath.Join("..", "db", "queries", item.file))
			must(t, err, "read canonical historical family selector")
		}
		marker := "-- name: " + item.name + " :"
		if strings.Count(string(raw), marker) != 1 {
			t.Fatalf("canonical query marker %q is not unique", marker)
		}
		query := string(raw)[strings.Index(string(raw), marker):]
		if end := strings.Index(query, "\n-- name: "); end >= 0 {
			query = query[:end]
		}
		if strings.Count(query, item.wildcard) != 1 {
			t.Fatalf("canonical query %s changed its wildcard output", item.name)
		}
		columns := []string{"id", "org_id", "status", "parent_envelope_id", "completion_effective_at_bound", "completion_effective_at", "finalization_retain_until", "updated_at"}
		for i := range columns {
			columns[i] = item.prefix + columns[i]
		}
		verb := "SELECT "
		if strings.HasPrefix(item.wildcard, "RETURNING ") {
			verb = "RETURNING "
		}
		query = strings.Replace(query, item.wildcard, verb+strings.Join(columns, ", "), 1)
		if item.name == "BeginDocumentFinalization" {
			for _, arg := range []struct {
				name, positional string
				count            int
			}{
				{"id", "$1", 2}, {"org_id", "$2", 2}, {"retention_years", "$3", 1},
			} {
				macro := "sqlc.arg(" + arg.name + ")"
				if strings.Count(query, macro) != arg.count {
					t.Fatalf("canonical %s argument %s changed", item.name, arg.name)
				}
				query = strings.ReplaceAll(query, macro, arg.positional)
			}
		}
		if strings.Contains(query, "sqlc.") {
			t.Fatalf("unhandled canonical query macro in %s", item.name)
		}
		q.sql[item.name] = query
	}
	return q
}

func (q *historicalFamilySQL62) WithTx(tx pgx.Tx) *historicalFamilySQL62 {
	return &historicalFamilySQL62{db: tx, sql: q.sql}
}

func scanHistoricalFamilyMember62(row interface{ Scan(...any) error }) (*historicalFamilyMember62, error) {
	var member historicalFamilyMember62
	err := row.Scan(&member.ID, &member.OrgID, &member.Status, &member.ParentEnvelopeID,
		&member.CompletionEffectiveAtBound, &member.CompletionEffectiveAt,
		&member.FinalizationRetainUntil, &member.UpdatedAt)
	return &member, err
}

func (q *historicalFamilySQL62) many(ctx context.Context, name string, args ...any) ([]*historicalFamilyMember62, error) {
	rows, err := q.db.Query(ctx, q.sql[name], args...)
	if err != nil {
		return nil, fmt.Errorf("historical %s: %w", name, err)
	}
	defer rows.Close()
	var result []*historicalFamilyMember62
	for rows.Next() {
		member, err := scanHistoricalFamilyMember62(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, member)
	}
	return result, rows.Err()
}

func (q *historicalFamilySQL62) GetDocumentForUpdate(ctx context.Context, arg generated.GetDocumentForUpdateParams) (*historicalFamilyMember62, error) {
	return scanHistoricalFamilyMember62(q.db.QueryRow(ctx, q.sql["GetDocumentForUpdate"], arg.ID, arg.OrgID))
}

func (q *historicalFamilySQL62) GetStrandedDocuments(ctx context.Context, limit int32) ([]*historicalFamilyMember62, error) {
	return q.many(ctx, "GetStrandedDocuments", limit)
}

func (q *historicalFamilySQL62) ListEnvelopeChildren(ctx context.Context, arg generated.ListEnvelopeChildrenParams) ([]*historicalFamilyMember62, error) {
	return q.many(ctx, "ListEnvelopeChildren", arg.ParentEnvelopeID, arg.OrgID)
}

func (q *historicalFamilySQL62) BeginDocumentFinalization(ctx context.Context, arg generated.BeginDocumentFinalizationParams) (*historicalFamilyMember62, error) {
	return scanHistoricalFamilyMember62(q.db.QueryRow(ctx, q.sql["BeginDocumentFinalization"], arg.ID, arg.OrgID, arg.RetentionYears))
}

func (q *historicalFamilySQL62) BeginEnvelopeChildrenFinalization(ctx context.Context, arg generated.BeginEnvelopeChildrenFinalizationParams) ([]*historicalFamilyMember62, error) {
	return q.many(ctx, "BeginEnvelopeChildrenFinalization", arg.ParentEnvelopeID, arg.OrgID)
}
