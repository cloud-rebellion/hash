// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pressly/goose/v3"
)

// This explicit driver fixture runs the real pinned Goose/provider/locker
// protocol. It proves cancellation and pool-eviction bookkeeping, not actual
// PostgreSQL locks or SQL semantics (those have separate integration tests).
type migrationDriverState242 struct {
	mu                                                             sync.Mutex
	blockLock, blockSQL, badUnlock, errorUnlock                    bool
	historyPresent, unsupportedHistory, errorHistory, blockHistory bool
	entered                                                        chan struct{}
	once                                                           sync.Once
	next, lockID, historyID, sqlID, unlockID, closes, rollbacks    int
	held                                                           map[int]bool
	unlockBounded                                                  bool
}
type migrationConnector242 struct{ state *migrationDriverState242 }
type migrationDriver242 struct{}

func (migrationDriver242) Open(string) (driver.Conn, error) {
	return nil, errors.New("use explicit connector")
}
func (c migrationConnector242) Driver() driver.Driver { return migrationDriver242{} }
func (c migrationConnector242) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	c.state.next++
	return &migrationConn242{s: c.state, id: c.state.next}, nil
}

type migrationConn242 struct {
	s      *migrationDriverState242
	id     int
	closed bool
}

func (c *migrationConn242) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared migration")
}
func (c *migrationConn242) Close() error {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.s.closes++
		delete(c.s.held, c.id)
	}
	return nil
}
func (c *migrationConn242) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *migrationConn242) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &migrationTx242{c: c}, nil
}
func (c *migrationConn242) ResetSession(context.Context) error { return nil }
func (c *migrationConn242) IsValid() bool                      { c.s.mu.Lock(); defer c.s.mu.Unlock(); return !c.closed }
func (c *migrationConn242) ExecContext(ctx context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	c.s.mu.Lock()
	block := false
	switch {
	case strings.Contains(q, "pg_advisory_lock"):
		c.s.lockID = c.id
		// Model the ambiguous case too: server acquisition can precede a missing
		// client acknowledgement. Only closing this exact driver clears it.
		c.s.held[c.id] = true
		block = c.s.blockLock
	case strings.Contains(q, "migration_step"):
		c.s.sqlID = c.id
		block = c.s.blockSQL
	default:
		c.s.mu.Unlock()
		return nil, fmt.Errorf("unexpected fixture SQL")
	}
	c.s.mu.Unlock()
	if block {
		c.s.once.Do(func() { close(c.s.entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return driver.RowsAffected(1), nil
}
func (c *migrationConn242) QueryContext(ctx context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, "to_regclass") || strings.Contains(q, "GROUP BY version_id") {
		c.s.mu.Lock()
		c.s.historyID = c.id
		held, present := c.s.held[c.id], c.s.historyPresent
		supported, failed, blocked := !c.s.unsupportedHistory, c.s.errorHistory, c.s.blockHistory
		c.s.mu.Unlock()
		if !held {
			return nil, errors.New("metadata inspection lacked actual advisory ownership")
		}
		if strings.Contains(q, "to_regclass") {
			return &migrationRows242{value: present}, nil
		}
		if blocked {
			c.s.once.Do(func() { close(c.s.entered) })
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if failed {
			return nil, errors.New("synthetic metadata inspection response lost")
		}
		return &migrationRows242{value: supported}, nil
	}
	if !strings.Contains(q, "pg_advisory_unlock") {
		return nil, fmt.Errorf("unexpected fixture query")
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.s.unlockID = c.id
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) > 0 && time.Until(deadline) <= migrationCleanupTimeout {
		c.s.unlockBounded = true
	}
	if c.s.errorUnlock {
		return nil, errors.New("synthetic unlock response lost")
	}
	if c.s.badUnlock {
		return &migrationRows242{value: false}, nil
	}
	if !c.s.held[c.id] {
		return &migrationRows242{value: false}, nil
	}
	delete(c.s.held, c.id)
	return &migrationRows242{value: true}, nil
}

type migrationTx242 struct{ c *migrationConn242 }

func (*migrationTx242) Commit() error { return nil }
func (t *migrationTx242) Rollback() error {
	t.c.s.mu.Lock()
	defer t.c.s.mu.Unlock()
	t.c.s.rollbacks++
	return nil
}

type migrationRows242 struct {
	value bool
	done  bool
}

func (*migrationRows242) Columns() []string { return []string{"unlocked"} }
func (*migrationRows242) Close() error      { return nil }
func (r *migrationRows242) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.value
	return nil
}

func TestMigrationProviderPinnedSessionCancellationAndEvictionV1(t *testing.T) {
	for _, kind := range []string{"healthy", "cancel lock", "cancel migration", "unlock false", "unlock response lost", "unsupported history", "history inspection response lost", "cancel history inspection"} {
		t.Run(kind, func(t *testing.T) {
			s := &migrationDriverState242{entered: make(chan struct{}), held: make(map[int]bool), blockLock: kind == "cancel lock", blockSQL: kind == "cancel migration", badUnlock: kind == "unlock false", errorUnlock: kind == "unlock response lost", historyPresent: strings.Contains(kind, "history"), unsupportedHistory: kind == "unsupported history", errorHistory: kind == "history inspection response lost", blockHistory: kind == "cancel history inspection"}
			database := sql.OpenDB(migrationConnector242{state: s})
			database.SetMaxOpenConns(1)
			database.SetMaxIdleConns(1)
			defer database.Close()
			fsys := fstest.MapFS{"00001_fixture.sql": &fstest.MapFile{Data: []byte("-- +goose Up\nSELECT migration_step;\n-- +goose Down\nSELECT rollback_step;\n")}}
			provider, err := goose.NewProvider(goose.DialectPostgres, database, fsys, goose.WithDisableGlobalRegistry(true), goose.WithDisableVersioning(true), goose.WithSessionLocker(migrationSessionLocker{}))
			if err != nil {
				t.Fatal(err)
			}
			parent, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			result := make(chan error, 1)
			joined := make(chan struct{})
			go func() { defer close(joined); _, err := provider.Up(ctx); result <- err }()
			defer func() {
				cancel()
				select {
				case <-joined:
				case <-parent.Done():
					t.Error("migration driver did not join")
				}
			}()
			if s.blockLock || s.blockSQL || s.blockHistory {
				select {
				case <-s.entered:
				case <-parent.Done():
					t.Fatal("driver barrier not reached")
				}
				cancel()
			}
			select {
			case err = <-result:
			case <-parent.Done():
				t.Fatal("migration provider did not return")
			}
			s.mu.Lock()
			lockID, historyID, sqlID, unlockID, closes, rollbacks, held, bounded := s.lockID, s.historyID, s.sqlID, s.unlockID, s.closes, s.rollbacks, len(s.held), s.unlockBounded
			s.mu.Unlock()
			if kind == "healthy" {
				if err != nil || lockID == 0 || lockID != sqlID || lockID != unlockID || held != 0 || closes != 0 || !bounded {
					t.Fatal("healthy provider lost pinned lock lifecycle", err, lockID, sqlID, unlockID, closes, held, bounded)
				}
			} else if err == nil {
				t.Fatal("failed/cancelled lifecycle reported success")
			}
			if s.blockLock || s.blockSQL || s.blockHistory {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation identity lost", err)
				}
			}
			if kind == "cancel lock" {
				if sqlID != 0 || held != 0 || closes != 1 || database.Stats().Idle != 0 {
					t.Fatal("cancelled ambiguous lock returned its session to pool", sqlID, held, closes, database.Stats().Idle)
				}
			}
			if kind != "cancel lock" && historyID != lockID {
				t.Fatal("metadata inspection changed advisory-owning sessions", lockID, historyID)
			}
			if strings.Contains(kind, "history") {
				if !errors.Is(err, ErrMigrationHistoryUnsupportedV1) || lockID == 0 || sqlID != 0 || unlockID != 0 || held != 0 || closes != 1 || database.Stats().Idle != 0 {
					t.Fatal("unsupported or unacknowledged history reused its locked session", err, lockID, historyID, sqlID, unlockID, held, closes, database.Stats().Idle)
				}
			}
			if kind == "cancel migration" {
				if sqlID != lockID || held != 0 || rollbacks != 1 || (unlockID != 0 && unlockID != lockID) {
					t.Fatal("cancelled SQL lost original lock/session or rollback", lockID, sqlID, unlockID, held, rollbacks)
				}
			}
			if s.badUnlock || s.errorUnlock {
				if lockID != sqlID || lockID != unlockID || held != 0 || closes != 1 || database.Stats().Idle != 0 || !bounded {
					t.Fatal("unacknowledged unlock was reusable", lockID, sqlID, unlockID, held, closes, database.Stats().Idle, bounded)
				}
			}
		})
	}
}
func TestMigrationContextRejectsMissingOrCancelledAuthorityV1(t *testing.T) {
	s := &migrationDriverState242{held: make(map[int]bool)}
	database := sql.OpenDB(migrationConnector242{state: s})
	defer database.Close()
	if err := RunMigrationsContext(nil, database); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := RunMigrationsContext(context.Background(), nil); err == nil {
		t.Fatal("nil database accepted")
	}
	if err := RunMigrationsUpToContext(context.Background(), database, -1); err == nil {
		t.Fatal("negative UpTo target accepted")
	}
	if err := RunMigrationsDownToContext(context.Background(), database, -1); err == nil {
		t.Fatal("negative DownTo target aliased one-step rollback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunMigrationsContext(ctx, database); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled startup entered migration", err)
	}
	if _, err := GetMigrationVersionContext(ctx, database); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled version observation entered database", err)
	}
	s.mu.Lock()
	connections := s.next
	s.mu.Unlock()
	if connections != 0 {
		t.Fatal("refused startup acquired database session", connections)
	}
}
