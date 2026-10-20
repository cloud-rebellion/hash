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

// Historical schemas do not contain today's complete generated.Document. Read
// the actual canonical queries, replacing only wildcard output projections
// and sqlc's named-argument spelling. Predicates, locks, ordering, updates and
// the full family lifecycle clock remain the application's canonical SQL.
// Load everything on the test goroutine before starting any concurrent work.
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
	for _, item := range []struct{ file, name, wildcard, prefix string }{
		{"documents.sql", "GetDocumentForUpdate", "SELECT *", ""},
		{"documents.sql", "GetStrandedDocuments", "SELECT d.*", "d."},
		{"envelopes.sql", "ListEnvelopeChildren", "SELECT *", ""},
		{"envelopes.sql", "BeginEnvelopeChildrenFinalization", "RETURNING child.*", "child."},
		{"finalization.sql", "BeginDocumentFinalization", "RETURNING target.*", "target."},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "db", "queries", item.file))
		must(t, err, "read canonical historical family query")
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
