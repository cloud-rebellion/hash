// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
)

type dashboardDB struct {
	t       *testing.T
	orgID   uuid.UUID
	failAt  int
	calls   int
	rowsErr error
}

func (db *dashboardDB) read(args []any) error {
	db.t.Helper()
	db.calls++
	if len(args) == 0 || args[0] != db.orgID {
		db.t.Fatal("dashboard query did not use the authenticated workspace")
	}
	if db.calls == db.failAt {
		return errors.New("private database diagnostic that must not reach the client")
	}
	return nil
}

func (*dashboardDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("dashboard must not write")
}

func (db *dashboardDB) Query(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
	if err := db.read(args); err != nil {
		return nil, err
	}
	return dashboardRows{err: db.rowsErr}, nil
}

func (db *dashboardDB) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	return dashboardRow{err: db.read(args)}
}

type dashboardRows struct {
	pgx.Rows
	err error
}

func (dashboardRows) Close()       {}
func (dashboardRows) Next() bool   { return false }
func (r dashboardRows) Err() error { return r.err }

type dashboardRow struct{ err error }

func (r dashboardRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for _, value := range dest {
		*value.(*int64) = 0
	}
	return nil
}

func dashboardRequest(orgID uuid.UUID) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	ctx := context.WithValue(r.Context(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, orgID)
	return r.WithContext(ctx)
}

func TestDashboardRejectsEachFailedReadWithoutPartialStatistics(t *testing.T) {
	for failedRead := 1; failedRead <= 7; failedRead++ {
		t.Run(fmt.Sprintf("read_%d", failedRead), func(t *testing.T) {
			db := &dashboardDB{t: t, orgID: uuid.New(), failAt: failedRead}
			s := &Server{Queries: generated.New(db)}
			res := httptest.NewRecorder()
			s.handleDashboard(res, dashboardRequest(db.orgID))
			if res.Code != http.StatusInternalServerError || db.calls != failedRead {
				t.Fatalf("status=%d reads=%d; want 500 and stop at failed read %d", res.Code, db.calls, failedRead)
			}
			var body map[string]any
			if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 1 || body["error"] != "internal error" || strings.Contains(res.Body.String(), "private database") {
				t.Fatalf("expected generic error without partial statistics: %s", res.Body.String())
			}
		})
	}
}

func TestDashboardRejectsStatusIterationFailure(t *testing.T) {
	db := &dashboardDB{t: t, orgID: uuid.New(), rowsErr: errors.New("iteration failed")}
	res := httptest.NewRecorder()
	(&Server{Queries: generated.New(db)}).handleDashboard(res, dashboardRequest(db.orgID))
	if res.Code != http.StatusInternalServerError || db.calls != 1 {
		t.Fatalf("status=%d reads=%d; want 500 after status iteration failure", res.Code, db.calls)
	}
}

func TestDashboardEmptyWorkspaceIsSuccessfulAndAllReadsAreScoped(t *testing.T) {
	db := &dashboardDB{t: t, orgID: uuid.New()}
	res := httptest.NewRecorder()
	(&Server{Queries: generated.New(db)}).handleDashboard(res, dashboardRequest(db.orgID))
	if res.Code != http.StatusOK || db.calls != 7 {
		t.Fatalf("status=%d reads=%d; want 200 and seven workspace reads", res.Code, db.calls)
	}
	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, failed := body["error"]; failed || body["awaiting_signature"] != float64(0) {
		t.Fatalf("empty workspace is not a database failure: %s", res.Body.String())
	}
}
