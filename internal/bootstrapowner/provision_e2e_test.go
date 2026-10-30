//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package bootstrapowner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/passwordhash"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Each case owns a separate database, not the shared HASH_E2E_DB_URL estate.
// Its migration connection is closed before the actual command connection.
func bootstrapScratch(t *testing.T) (context.Context, *pgx.Conn, *pgx.ConnConfig) {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run the isolated PostgreSQL journeys")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	cfg, err := pgx.ParseConfig(dsn)
	bootstrapMust(t, err, "parse private PostgreSQL fixture configuration")
	name := bootstrapDatabasesE2E.Clone(t, "hash_bootstrap_")
	scratch := cfg.Copy()
	scratch.Database = name
	scratch.RuntimeParams["application_name"] = "hash-bootstrap-fixture-client"
	var conn *pgx.Conn
	t.Cleanup(func() {
		if conn == nil {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := conn.Close(cleanup); err != nil {
			t.Errorf("close owned bootstrap connection (%s)", bootstrapErrorDiagnostic(err))
			return
		}
		select {
		case <-conn.PgConn().CleanupDone():
		case <-cleanup.Done():
			t.Error("bootstrap native connection cleanup did not join")
		}
	})
	conn, err = pgx.ConnectConfig(ctx, scratch)
	bootstrapMust(t, err, "connect actual bootstrap operation")
	return ctx, conn, scratch
}

func bootstrapMust(t *testing.T, err error, phase string) {
	t.Helper()
	if err != nil {
		// Report only type/SQLSTATE/context classification. Raw connection and
		// SQL errors may include private configuration or row values.
		t.Fatalf("%s (%s)", phase, bootstrapErrorDiagnostic(err))
	}
}

func bootstrapErrorDiagnostic(err error) string {
	state := "none"
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		state = postgres.Code
	}
	return fmt.Sprintf("type=%T sqlstate=%s cancelled=%t deadline=%t", err, state, errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded))
}

func bootstrapObserveDatabaseRetired(t *testing.T, ctx context.Context, admin *pgx.Conn, database string) bool {
	t.Helper()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		var remaining int64
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname=$1", database).Scan(&remaining); err != nil {
			t.Errorf("observe owned bootstrap database backend retirement (%s)", bootstrapErrorDiagnostic(err))
			return false
		}
		if remaining == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			t.Errorf("owned bootstrap fixture retained %d database backends after connection close", remaining)
			return false
		case <-tick.C:
		}
	}
}

func bootstrapCounts(t *testing.T, ctx context.Context, conn *pgx.Conn) [8]int64 {
	t.Helper()
	var counts [8]int64
	err := conn.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM public.orgs),
 (SELECT count(*) FROM public.users),
 (SELECT count(*) FROM public.events),
 (SELECT count(*) FROM public.staff_password_credentials),
 (SELECT count(*) FROM public.staff_auth_requests),
 (SELECT count(*) FROM public.api_keys),
 (SELECT count(*) FROM public.org_subscriptions),
 (SELECT count(*) FROM public.email_deliveries)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5], &counts[6], &counts[7])
	bootstrapMust(t, err, "read scalar bootstrap state")
	return counts
}

func TestBootstrapOwnerFresh117ReplayPreservesNativeAccountE2E(t *testing.T) {
	ctx, conn, _ := bootstrapScratch(t)
	in := testInput()
	result, err := Provision(ctx, conn, in)
	bootstrapMust(t, err, "provision actual pending owner")
	if !result.Created || result.Replayed || result.OrgID != in.OrgID || result.UserID == uuid.Nil || result.AuditID == uuid.Nil {
		t.Fatal("first initialization did not return genuine identities")
	}
	if got := bootstrapCounts(t, ctx, conn); got != [8]int64{1, 1, 1, 0, 0, 0, 0, 0} {
		t.Fatal("initialization seeded authentication, mail, payment or duplicate state")
	}
	q := generated.New(conn)
	owner, err := q.GetUser(ctx, result.UserID)
	bootstrapMust(t, err, "read pending owner")
	if owner.OrgID != in.OrgID || owner.Email != in.OwnerEmail || owner.Name != in.OwnerName || owner.Role != "owner" || owner.ZitadelSub.Valid || owner.SessionGeneration != 0 {
		t.Fatal("pending owner identity differs from approved input")
	}
	event, err := q.GetEventByID(ctx, result.AuditID)
	bootstrapMust(t, err, "read original canonical provisioning event")
	if !matchesOriginal(event, in, owner.ID) || event.ActorUserID.Valid {
		t.Fatal("pending owner was falsely recorded as an authenticated actor")
	}
	// Model later native setup using the same credential/generation queries.
	// The maintenance retry must not reinstall or reset any account state.
	err = q.SetStaffPasswordCredential(ctx, generated.SetStaffPasswordCredentialParams{UserID: owner.ID, PasswordHash: passwordhash.DummyHash})
	bootstrapMust(t, err, "install later synthetic credential")
	owner, err = q.RotateStaffPasswordSession(ctx, generated.RotateStaffPasswordSessionParams{ID: owner.ID, SessionGeneration: 0})
	bootstrapMust(t, err, "record later native revocation generation")
	owner, err = q.BindUserZitadelSub(ctx, generated.BindUserZitadelSubParams{ID: owner.ID, ZitadelSub: pgtype.Text{String: "later-genuine-test-identity", Valid: true}})
	bootstrapMust(t, err, "record later optional identity binding")
	digest := bytes.Repeat([]byte{0x25}, 32)
	err = q.IssueStaffAuthRequest(ctx, generated.IssueStaffAuthRequestParams{ID: uuid.New(), Email: in.OwnerEmail, Purpose: "reset",
		UserID: pgtype.UUID{Bytes: owner.ID, Valid: true}, SessionGeneration: pgtype.Int8{Int64: owner.SessionGeneration, Valid: true}, TokenHash: digest, TtlSeconds: 1800})
	bootstrapMust(t, err, "create later synthetic recovery request")
	// LogTx requires a real caller transaction. Append through the normal
	// caller-owned boundary, not a fabricated event row or chain hash.
	tx, err := conn.Begin(ctx)
	bootstrapMust(t, err, "begin later account event")
	logger := audit.New(generated.New(tx), nil)
	pending, err := logger.LogTx(ctx, tx, audit.Entry{OrgID: in.OrgID, ActorUserID: &owner.ID, Kind: "member.password_reset", Payload: map[string]any{"member_id": owner.ID.String(), "provider": "password", "bootstrap": false}})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal("append later account audit")
	}
	bootstrapMust(t, tx.Commit(ctx), "commit later account event")
	logger.Publish(pending)
	credential, err := q.GetStaffPasswordCredentialForUser(ctx, owner.ID)
	bootstrapMust(t, err, "read later credential snapshot")
	request, err := q.GetStaffAuthRequest(ctx, digest)
	bootstrapMust(t, err, "read later recovery snapshot")
	before := bootstrapCounts(t, ctx, conn)
	retry, err := Provision(ctx, conn, in)
	bootstrapMust(t, err, "recover exact committed provisioning after lost acknowledgement")
	if retry.Created || !retry.Replayed || retry.OrgID != result.OrgID || retry.UserID != result.UserID || retry.AuditID != result.AuditID {
		t.Fatal("retry manufactured identities or a second creation receipt")
	}
	retained, err := q.GetUser(ctx, owner.ID)
	bootstrapMust(t, err, "read retained owner")
	retainedCredential, err := q.GetStaffPasswordCredentialForUser(ctx, owner.ID)
	bootstrapMust(t, err, "read retained credential")
	retainedRequest, err := q.GetStaffAuthRequest(ctx, digest)
	bootstrapMust(t, err, "read retained recovery request")
	if before != bootstrapCounts(t, ctx, conn) || !reflect.DeepEqual(owner, retained) || !reflect.DeepEqual(credential, retainedCredential) || !reflect.DeepEqual(request, retainedRequest) {
		t.Fatal("retry changed established account, recovery or audit state")
	}
	for _, change := range []func(*Input){
		func(v *Input) { v.OrgID = uuid.New() },
		func(v *Input) { v.OwnerEmail = "other@example.test" },
		func(v *Input) { v.OwnerName = "Other Owner" },
		func(v *Input) { v.Company = "Other Company" },
		func(v *Input) { v.ReviewRef = "different-review" },
	} {
		changed := in
		change(&changed)
		if _, err := Provision(ctx, conn, changed); err != ErrRefused {
			t.Fatal("mismatched identity or provenance was accepted as an original retry")
		}
		if before != bootstrapCounts(t, ctx, conn) {
			t.Fatal("refused retry changed application state")
		}
	}
}

func TestBootstrapOwnerRefusesUnrelatedEstateAndFalseReplayE2E(t *testing.T) {
	t.Run("unrelated-business-table", func(t *testing.T) {
		ctx, conn, _ := bootstrapScratch(t)
		_, err := conn.Exec(ctx, `CREATE TABLE public.bootstrap_owner_unrelated_fixture(id integer); INSERT INTO public.bootstrap_owner_unrelated_fixture VALUES(1)`)
		bootstrapMust(t, err, "create owned unrelated-state fixture")
		if _, err := Provision(ctx, conn, testInput()); err != ErrRefused {
			t.Fatal("unrelated retained state was treated as a fresh installation")
		}
		if bootstrapCounts(t, ctx, conn) != [8]int64{} {
			t.Fatal("refused initialization wrote owner state")
		}
	})
	t.Run("existing-owner-without-original-audit", func(t *testing.T) {
		ctx, conn, _ := bootstrapScratch(t)
		in := testInput()
		q := generated.New(conn)
		org, err := q.CreateBootstrapOwnerOrg(ctx, generated.CreateBootstrapOwnerOrgParams{ID: in.OrgID, Name: in.Company, Plan: "starter"})
		bootstrapMust(t, err, "create owned prior organization fixture")
		_, err = q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: in.OwnerEmail, Name: in.OwnerName, Role: "owner"})
		bootstrapMust(t, err, "create owned prior member fixture")
		before := bootstrapCounts(t, ctx, conn)
		if _, err := Provision(ctx, conn, in); err != ErrRefused || before != bootstrapCounts(t, ctx, conn) {
			t.Fatal("matching identities without authentic original provisioning were adopted")
		}
	})
}

func TestBootstrapOwnerConcurrentInitializationE2E(t *testing.T) {
	for _, different := range []bool{false, true} {
		name := "same-input"
		if different {
			name = "different-owner"
		}
		t.Run(name, func(t *testing.T) {
			ctx, conn, cfg := bootstrapScratch(t)
			other, err := pgx.ConnectConfig(ctx, cfg)
			bootstrapMust(t, err, "connect second isolated initializer")
			defer func() { bootstrapMust(t, other.Close(ctx), "close second initializer") }()
			inputs := [2]Input{testInput(), testInput()}
			if different {
				inputs[1].OrgID, inputs[1].OwnerEmail = uuid.New(), "second@example.test"
			}
			var results [2]Result
			var errs [2]error
			start := make(chan struct{})
			var joined sync.WaitGroup
			for i, c := range []*pgx.Conn{conn, other} {
				joined.Add(1)
				go func(i int, c *pgx.Conn) {
					defer joined.Done()
					<-start
					results[i], errs[i] = Provision(ctx, c, inputs[i])
				}(i, c)
			}
			close(start)
			joined.Wait()
			created, replayed, refused := 0, 0, 0
			for i, result := range results {
				if errs[i] == ErrRefused {
					refused++
					continue
				}
				bootstrapMust(t, errs[i], "concurrent initializer returned")
				if result.Created {
					created++
				}
				if result.Replayed {
					replayed++
				}
			}
			if created != 1 || (different && (refused != 1 || replayed != 0)) || (!different && (refused != 0 || replayed != 1 || results[0].UserID != results[1].UserID || results[0].AuditID != results[1].AuditID)) {
				t.Fatal("global first-owner fence did not serialize original creation and exact retry")
			}
			if bootstrapCounts(t, ctx, conn) != [8]int64{1, 1, 1, 0, 0, 0, 0, 0} {
				t.Fatal("concurrent setup duplicated or seeded additional state")
			}
		})
	}
}

func TestBootstrapOwnerResourceBaselinesAndCancellationE2E(t *testing.T) {
	ctx, conn, cfg := bootstrapScratch(t)
	tx, err := conn.Begin(ctx)
	bootstrapMust(t, err, "begin baseline inspection")
	for _, table := range []string{"signing_resource_control", "signing_resource_accounts", "orgs"} {
		business, err := TableHasBusinessRows(ctx, tx, table)
		bootstrapMust(t, err, "inspect real migration baseline")
		if business {
			t.Fatal("pristine M117 baseline was classified as business state")
		}
	}
	// TRUNCATE changes only this rollback-owned corruption fixture. Production
	// provisioning never truncates, repairs or activates any resource ledger.
	_, err = tx.Exec(ctx, `TRUNCATE public.signing_resource_control`)
	bootstrapMust(t, err, "create missing-baseline corruption fixture")
	business, err := TableHasBusinessRows(ctx, tx, "signing_resource_control")
	bootstrapMust(t, err, "inspect missing baseline")
	if !business {
		t.Fatal("missing mandatory control row was accepted as an empty baseline")
	}
	bootstrapMust(t, tx.Rollback(ctx), "discard missing-baseline fixture")
	tx, err = conn.Begin(ctx)
	bootstrapMust(t, err, "begin missing-account baseline fixture")
	_, err = tx.Exec(ctx, `TRUNCATE public.signing_resource_accounts`)
	bootstrapMust(t, err, "create missing-account corruption fixture")
	business, err = TableHasBusinessRows(ctx, tx, "signing_resource_accounts")
	bootstrapMust(t, err, "inspect missing global account")
	if !business {
		t.Fatal("missing mandatory global account was accepted as an empty baseline")
	}
	bootstrapMust(t, tx.Rollback(ctx), "discard missing-account fixture")
	tx, err = conn.Begin(ctx)
	bootstrapMust(t, err, "begin additional-account fixture")
	org, err := generated.New(tx).CreateOrg(ctx, generated.CreateOrgParams{Name: "Owned account baseline fixture", Plan: "starter"})
	bootstrapMust(t, err, "create owned tenant-account fixture")
	_, err = tx.Exec(ctx, `INSERT INTO public.signing_resource_accounts(account_key,scope,org_id) VALUES($1,'tenant',$1)`, org.ID)
	bootstrapMust(t, err, "insert actual additional tenant account")
	business, err = TableHasBusinessRows(ctx, tx, "signing_resource_accounts")
	bootstrapMust(t, err, "inspect additional tenant account")
	if !business {
		t.Fatal("additional tenant state was exempted as global migration scaffolding")
	}
	bootstrapMust(t, tx.Rollback(ctx), "discard additional-account fixture")
	other, err := pgx.ConnectConfig(ctx, cfg)
	bootstrapMust(t, err, "connect bounded cancellation fixture")
	defer func() { bootstrapMust(t, other.Close(ctx), "close cancellation connection") }()
	backendPID := int32(other.PgConn().PID())
	var backendStart pgtype.Timestamptz
	err = other.QueryRow(ctx, `SELECT backend_start FROM pg_catalog.pg_stat_activity
 WHERE pid=pg_backend_pid() AND datname=current_database()`).Scan(&backendStart)
	bootstrapMust(t, err, "capture original cancellation backend identity")
	if backendPID <= 0 || !backendStart.Valid || backendStart.InfinityModifier != pgtype.Finite {
		t.Fatal("original cancellation backend identity is unavailable")
	}
	tx, err = conn.Begin(ctx)
	bootstrapMust(t, err, "begin competing initialization fence")
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('hash.bootstrap-owner.v1',0))`)
	bootstrapMust(t, err, "hold competing initialization fence")
	short, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	_, refused := Provision(short, other, testInput())
	cancel()
	bootstrapMust(t, tx.Rollback(ctx), "release competing initialization fence")
	if refused != ErrUnavailable || bootstrapCounts(t, ctx, conn) != [8]int64{} {
		t.Fatal("cancelled initializer leaked state or reported success")
	}
	observeCancelledBootstrapBackend(t, ctx, conn, other, backendPID, backendStart)
	// pgx may deliberately close an interrupted connection. Backend settlement
	// must be proved independently before an ordinary fresh-connection retry.
	fresh, err := pgx.ConnectConfig(ctx, cfg)
	bootstrapMust(t, err, "connect genuine retry after observed cancellation cleanup")
	defer func() { bootstrapMust(t, fresh.Close(ctx), "close fresh retry connection") }()
	if _, err := Provision(ctx, fresh, testInput()); err != nil {
		t.Fatal("fresh retry failed after original backend settlement was observed")
	}
}

func observeCancelledBootstrapBackend(t *testing.T, parent context.Context, observer, original *pgx.Conn, pid int32, started pgtype.Timestamptz) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	if !original.IsClosed() {
		var idle bool
		err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity
 WHERE pid=$1 AND backend_start=$2 AND datname=current_database()
   AND state='idle' AND xact_start IS NULL)`, pid, started).Scan(&idle)
		bootstrapMust(t, err, "independently inspect original open backend transaction state")
		if !idle || original.PgConn().IsBusy() || original.PgConn().TxStatus() != 'I' {
			t.Fatal("cancelled original backend retained a transaction or unknown state")
		}
		return
	}
	// IsClosed alone says the handle is unusable. pgx's cancellation path can
	// still own asynchronous socket cleanup for up to its native15s deadline.
	select {
	case <-original.PgConn().CleanupDone():
	case <-ctx.Done():
		t.Fatal("original cancelled connection transport cleanup was not observed")
	}
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		var present bool
		err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity
 WHERE pid=$1 AND backend_start=$2 AND datname=current_database())`, pid, started).Scan(&present)
		bootstrapMust(t, err, "independently observe exact cancelled backend absence")
		if !present {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("exact original cancelled backend did not disappear before the observation deadline")
		case <-tick.C:
		}
	}
}
