// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package bootstrapowner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	hashdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const OperationTimeout = 30 * time.Second
const maxPublicTables = 1024

type Result struct {
	Schema   string    `json:"schema"`
	OrgID    uuid.UUID `json:"org_id"`
	UserID   uuid.UUID `json:"user_id"`
	AuditID  uuid.UUID `json:"audit_id"`
	Created  bool      `json:"created"`
	Replayed bool      `json:"replayed"`
}

// Provision uses only the caller's single connection. A committed result means
// pending owner provisioning, not password installation, authentication, mail
// delivery, billing entitlement, or Stage cutover authorization.
func Provision(parent context.Context, conn *pgx.Conn, in Input) (Result, error) {
	var empty Result
	in, err := Normalize(in)
	if err != nil {
		return empty, err
	}
	if parent == nil || conn == nil || conn.IsClosed() {
		return empty, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, OperationTimeout)
	defer cancel()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return empty, ErrUnavailable
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	for _, statement := range []string{
		`SET LOCAL lock_timeout='5s'`,
		`SET LOCAL statement_timeout='25s'`,
		`SET LOCAL search_path=public,pg_catalog`,
		`SELECT pg_advisory_xact_lock(hashtextextended('hash.bootstrap-owner.v1',0))`,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return empty, ErrUnavailable
		}
	}
	q := generated.New(tx)
	if err := q.LockStaffPasswordEmail(ctx, in.OwnerEmail); err != nil {
		return empty, ErrUnavailable
	}
	tables, err := lockPublicTables(ctx, tx)
	if err != nil {
		return empty, err
	}
	if err := requireExactMigrations(ctx, tx); err != nil {
		return empty, err
	}
	user, err := q.LockStaffPasswordUserByEmail(ctx, in.OwnerEmail)
	if err == nil {
		result, err := originalResult(ctx, q, in, user)
		if err != nil {
			return empty, err
		}
		// No row, credential, session generation or event is changed on retry.
		if err := tx.Commit(ctx); err != nil {
			return empty, ErrUnavailable
		}
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return empty, ErrUnavailable
	}
	if err := requireEmptyEstate(ctx, tx, tables); err != nil {
		return empty, err
	}
	org, err := q.CreateBootstrapOwnerOrg(ctx, generated.CreateBootstrapOwnerOrgParams{ID: in.OrgID, Name: in.Company, Plan: "starter"})
	if err != nil {
		return empty, ErrUnavailable
	}
	user, err = q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: in.OwnerEmail, Name: in.OwnerName, Role: "owner", ZitadelSub: pgtype.Text{}})
	if err != nil {
		return empty, ErrUnavailable
	}
	logger := audit.New(q, nil)
	pending, err := logger.LogTx(ctx, tx, audit.Entry{OrgID: org.ID, Kind: audit.KindMemberCreated,
		Payload: bootstrapPayload(in, user.ID)})
	if err != nil {
		return empty, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		// A connection loss can make the outcome unknown. Only an exact retry
		// inspecting the original committed evidence may return its identities.
		return empty, ErrUnavailable
	}
	logger.Publish(pending)
	return Result{Schema: "hash.bootstrap-owner.result.v1", OrgID: org.ID, UserID: user.ID, AuditID: pending.ID, Created: true}, nil
}

func lockPublicTables(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT c.relname FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p')
 ORDER BY c.relname LIMIT 1025`)
	if err != nil {
		return nil, ErrUnavailable
	}
	var tables, quoted []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, ErrUnavailable
		}
		tables = append(tables, name)
		quoted = append(quoted, pgx.Identifier{"public", name}.Sanitize())
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(tables) == 0 || len(tables) > maxPublicTables {
		return nil, ErrRefused
	}
	// Keep the empty-estate observation and writes in the same locked
	// transaction. Native registration and independent writers cannot race it.
	if _, err := tx.Exec(ctx, "LOCK TABLE "+strings.Join(quoted, ",")+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return nil, ErrUnavailable
	}
	return tables, nil
}

func requireExactMigrations(ctx context.Context, tx pgx.Tx) error {
	_, expected, err := hashdb.EmbeddedMigrationsIdentity()
	if err != nil {
		return ErrUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT version_id,is_applied FROM (
 SELECT DISTINCT ON(version_id) version_id,is_applied,id
 FROM public.goose_db_version WHERE version_id>0
 ORDER BY version_id,id DESC) latest ORDER BY version_id LIMIT 1025`)
	if err != nil {
		return ErrUnavailable
	}
	index, exact := 0, true
	for rows.Next() {
		var version int64
		var applied bool
		if err := rows.Scan(&version, &applied); err != nil {
			rows.Close()
			return ErrUnavailable
		}
		if index >= len(expected) || !applied || version != expected[index] {
			exact = false
		}
		index++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrUnavailable
	}
	if !exact || index != len(expected) {
		return ErrRefused
	}
	return nil
}

func requireEmptyEstate(ctx context.Context, tx pgx.Tx, tables []string) error {
	for _, resource := range []string{"signing_resource_control", "signing_resource_accounts"} {
		nonempty, err := TableHasBusinessRows(ctx, tx, resource)
		if err != nil {
			return err
		}
		if nonempty {
			return ErrRefused
		}
	}
	var plans bool
	if err := tx.QueryRow(ctx, `SELECT count(*)=3 AND count(*) FILTER(WHERE slug IN ('free','pro','enterprise'))=3 FROM public.billing_plans`).Scan(&plans); err != nil {
		return ErrUnavailable
	}
	if !plans {
		return ErrRefused
	}
	for _, table := range tables {
		switch table {
		case "goose_db_version", "billing_plans", "signing_resource_control", "signing_resource_accounts":
			continue
		}
		nonempty, err := TableHasBusinessRows(ctx, tx, table)
		if err != nil {
			return err
		}
		if nonempty {
			return ErrRefused
		}
	}
	return nil
}

func originalResult(ctx context.Context, q *generated.Queries, in Input, user *generated.User) (Result, error) {
	var empty Result
	if user == nil || user.ID == uuid.Nil || user.OrgID != in.OrgID || user.Email != in.OwnerEmail || user.Name != in.OwnerName || user.Role != "owner" {
		return empty, ErrRefused
	}
	org, err := q.GetOrg(ctx, in.OrgID)
	if err != nil {
		return empty, ErrUnavailable
	}
	if org.Name != in.Company || org.Plan != "starter" {
		return empty, ErrRefused
	}
	rows, err := q.ListChainedEventsPageForOrg(ctx, generated.ListChainedEventsPageForOrgParams{OrgID: in.OrgID, PageLimit: 1})
	if err != nil {
		return empty, ErrUnavailable
	}
	if len(rows) != 1 || !matchesOriginal(rows[0], in, user.ID) {
		return empty, ErrRefused
	}
	return Result{Schema: "hash.bootstrap-owner.result.v1", OrgID: in.OrgID, UserID: user.ID, AuditID: rows[0].ID, Replayed: true}, nil
}

func matchesOriginal(row *generated.Event, in Input, userID uuid.UUID) bool {
	if row == nil || row.ID == uuid.Nil || row.OrgID != in.OrgID || row.Kind != audit.KindMemberCreated ||
		row.ActorUserID.Valid || row.DocumentID.Valid || row.RecipientID.Valid || row.Ip != nil || row.Ua.Valid || len(row.PrevHash) != 0 ||
		!row.CreatedAt.Valid || row.CreatedAt.InfinityModifier != pgtype.Finite {
		return false
	}
	expected, _ := json.Marshal(bootstrapPayload(in, userID))
	if !bytes.Equal(row.PayloadHashed, expected) {
		return false
	}
	var sidecar map[string]any
	if json.Unmarshal(row.PayloadJson, &sidecar) != nil {
		return false
	}
	sidecarBytes, err := json.Marshal(sidecar)
	if err != nil || !bytes.Equal(sidecarBytes, expected) {
		return false
	}
	hash, err := audit.RecomputeEventRowHash(row)
	return err == nil && len(row.RowHash) == 32 && bytes.Equal(hash, row.RowHash)
}
