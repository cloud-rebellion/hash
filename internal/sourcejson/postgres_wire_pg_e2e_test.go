//go:build owned_app_session_pg

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sourcejson_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This finite oracle uses one explicit disposable Unix/trust connection and an
// actual shared coordinator. It does not create tables/application rows, READY,
// controller receipts or production authentication/retirement authority.
// Root owns the real migrated PG16 fixture and its process/container disposal.
const postgresWireOracleMaxInputV1 = 32 << 10
const postgresWireOracleMaxNumbersV1 = 64
const postgresWireOracleMaxExponentV1 = 256
const postgresWireOracleMaxGeneratedV1 = 64

type postgresWireOracleCaseV1 struct{ name, raw string }

// Validate the TEST envelope before any PostgreSQL input. Streaming tokens keep
// duplicate numeric keys visible, so a discarded earlier value cannot hide an
// excessive exponent. These limits apply only to this disposable oracle, never
// to product content or the production wire bound.
func postgresWireOracleEnvelopeV1(raw []byte) error {
	if len(raw) == 0 || len(raw) > postgresWireOracleMaxInputV1 || !utf8.Valid(raw) {
		return errors.New("oracle input envelope")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	numbers, depth, tokens := 0, 0, 0
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("oracle input JSON")
		}
		tokens++
		if tokens > 2048 {
			return errors.New("oracle token envelope")
		}
		switch v := token.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
			} else {
				depth--
			}
			if depth < 0 || depth > 32 {
				return errors.New("oracle depth envelope")
			}
		case string:
			if strings.ContainsRune(v, 0) {
				return errors.New("oracle NUL envelope")
			}
		case json.Number:
			numbers++
			if numbers > postgresWireOracleMaxNumbersV1 {
				return errors.New("oracle number count envelope")
			}
			spelling := v.String()
			coefficient := spelling
			if at := strings.IndexAny(spelling, "eE"); at >= 0 {
				exponent, parseErr := strconv.ParseInt(spelling[at+1:], 10, 32)
				if parseErr != nil || exponent < -postgresWireOracleMaxExponentV1 || exponent > postgresWireOracleMaxExponentV1 {
					return errors.New("oracle exponent envelope")
				}
				coefficient = spelling[:at]
			}
			digits := 0
			for _, r := range coefficient {
				if r >= '0' && r <= '9' {
					digits++
				}
			}
			if digits > 64 {
				return errors.New("oracle coefficient envelope")
			}
		}
	}
	if depth != 0 {
		return errors.New("oracle balance envelope")
	}
	return nil
}

func postgresWireOracleCasesV1() []postgresWireOracleCaseV1 {
	cases := []postgresWireOracleCaseV1{
		{"empty_object", "{}"}, {"empty_array", "[]"}, {"null", "null"}, {"true", "true"}, {"false", "false"},
		{"unicode_literal", "{\"Å\":\"漢😀\",\"word\":\"éß\"}"},
		{"unicode_escaped", "{\"a\":\"\\u00e9\\ud83d\\ude00\\u6f22\"}"},
		{"quote_control_slash", "{\"s\":\"quote\\\" backslash\\\\ slash\\/ tab\\t line\\n backspace\\b form\\f return\\r\"}"},
		{"html_escape", "{\"s\":\"\\u003cscript\\u003e\\u0026\\u2028\\u2029\"}"},
		{"whitespace", " \n { \"a\" : [ 1 , 2 , 3 ] , \"b\" : { \"x\" : null } } \t"},
		{"nested_assets", "{\"master\":{\"assets\":[{\"name\":\"logo\",\"mime\":\"image/png\",\"data\":\"YWJjZA==\"}],\"sections\":{\"terms\":\"Å & < >\"}},\"values\":{\"company\":\"Example\"}}"},
		{"duplicate_keys", "{\"a\":1e32,\"a\":1e-32,\"a\":2,\"nested\":{\"x\":\"first\",\"x\":\"last\"}}"},
		{"duplicate_escaped_key", "{\"a\":1e16,\"\\u0061\":2}"},
		{"scale", "[1.2300,1.2300e2,1.2300e-2,0.000e3,-0.00100e-2]"},
		{"zero_sign_scale", "[-0,-0.000,-0e32,0e-32,0.000e-2]"},
		{"positive_exponent_bound", "1e256"},
		{"negative_exponent_bound", "-1.2300e-256"},
		{"long_coefficient", "1234567890123456789012345678901234567890123456789012345678901234"},
	}
	for i := 0; i < postgresWireOracleMaxGeneratedV1; i++ {
		exponent := (i*37)%(2*postgresWireOracleMaxExponentV1+1) - postgresWireOracleMaxExponentV1
		value := map[string]any{
			"text":   strings.Repeat("Å<&\"\\\n", i%17),
			"nested": []any{true, nil, map[string]string{"company": "Example " + strconv.Itoa(i), "unicode": "漢😀"}},
		}
		base, _ := json.Marshal(value) // fixed supported values cannot fail
		// Keep the generated decimal spelling literal; a float64 round trip could
		// destroy the scale/exponent behavior this actual PostgreSQL oracle checks.
		raw := "{\"n\":-1.2300e" + strconv.Itoa(exponent) + ",\"i\":" + strconv.Itoa(i) + ",\"body\":" + string(base) + "}"
		cases = append(cases, postgresWireOracleCaseV1{"generated_" + strconv.Itoa(i), raw})
	}
	cases = append(cases, postgresWireOracleCaseV1{"bounded_large_string", "{\"asset\":\"" + strings.Repeat("a", 24<<10) + "\",\"n\":1e256}"})
	return cases
}

func TestPostgreSQLJSONBWireUpperBoundRealPGV1(t *testing.T) {
	dsn := os.Getenv("HASH_OWNED_SESSION_PG_DSN")
	if dsn == "" {
		t.Fatal("HASH_OWNED_SESSION_PG_DSN required for disposable real-PG wire oracle")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid disposable Unix PG oracle config")
	}
	if !filepath.IsAbs(config.Host) || config.TLSConfig != nil || len(config.Fallbacks) != 0 || config.Password != "" {
		t.Fatal("oracle requires explicit disposable Unix/trust config without TLS/fallback/password")
	}
	config.ConnectTimeout = 2 * time.Second
	if config.RuntimeParams == nil {
		config.RuntimeParams = make(map[string]string)
	}
	config.RuntimeParams["application_name"] = "hash_wire_oracle_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	config.RuntimeParams["statement_timeout"] = "2000"
	config.RuntimeParams["lock_timeout"] = "1000"
	config.RuntimeParams["idle_in_transaction_session_timeout"] = "3000"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	limits := workguard.VectorV1{ParentBytes: 32 << 20, DBStagingBytes: 32 << 20, SQLSessions: 1}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal("construct explicit disposable wire-oracle coordinator")
	}
	work, err := pdfadmission.NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal("construct explicit disposable SQL work admission")
	}
	org := uuid.New()
	bodyGrant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 32 << 20, DBStagingBytes: 32 << 20})
	if err != nil {
		t.Fatal("admit bounded oracle parent/DB work")
	}
	var sqlGrant func()
	var conn *pgx.Conn
	connectStarted := false
	var cleanupOnce sync.Once
	var cleanupProblems []string
	cleanup := func() {
		cleanupOnce.Do(func() {
			closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			joined := !connectStarted
			if conn != nil {
				done := conn.PgConn().CleanupDone()
				if err := conn.Close(closeCtx); err != nil {
					cleanupProblems = append(cleanupProblems, "wire oracle connection close failed")
				}
				select {
				case <-done:
					joined = true
				case <-closeCtx.Done():
					cleanupProblems = append(cleanupProblems, "wire oracle client cleanup did not join")
				}
			}
			// This explicit test-fixture owner closes its raw work grants only after
			// synchronous query callers ended and actual pgx client cleanup joined.
			// This is NOT production physical backend/controller/debt retirement proof.
			if joined {
				if sqlGrant != nil {
					sqlGrant()
				}
				bodyGrant.Close()
			}
		})
	}
	t.Cleanup(func() {
		cleanup()
		for _, problem := range cleanupProblems {
			t.Error(problem)
		}
	})
	sqlGrant, err = work.SQLSessionV1(ctx, org)
	if err != nil {
		t.Fatal("admit bounded wire-oracle SQL session")
	}
	before := coordinator.SnapshotV1(org)
	if before.Global != limits || before.Organisation != limits || before.GlobalGrants != 2 || before.OrganisationGrants != 2 {
		t.Fatal("oracle resources were not charged before connection/input production")
	}
	connectStarted = true
	conn, err = pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("connect disposable PostgreSQL wire oracle")
	}
	var encoding string
	var serverVersion int
	if err = conn.QueryRow(ctx, "SELECT getdatabaseencoding(),current_setting('server_version_num')::integer").Scan(&encoding, &serverVersion); err != nil || encoding != "UTF8" || serverVersion < 160000 || serverVersion >= 170000 {
		t.Fatal("wire oracle requires actual UTF8 PostgreSQL16")
	}
	cases := postgresWireOracleCasesV1()
	if len(cases) > postgresWireOracleMaxGeneratedV1+32 {
		t.Fatal("wire oracle case count exceeded fixed envelope")
	}
	for _, test := range cases {
		if !t.Run(test.name, func(t *testing.T) {
			raw := []byte(test.raw)
			if err := postgresWireOracleEnvelopeV1(raw); err != nil {
				t.Fatal("oracle case exceeded pre-dispatch input/exponent envelope")
			}
			bound, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, raw)
			if err != nil || bound < 1 {
				t.Fatal("actual wire-bound helper refused supported bounded oracle input")
			}
			var wire string
			var actualBytes int64
			// Text parameter avoids a client JSON-number normalization. The actual
			// database emits its jsonb_out wire text; no expected canonical body is
			// reconstructed from the production scanner.
			if err = conn.QueryRow(ctx, "SELECT ($1::text::jsonb)::text,octet_length(($1::text::jsonb)::text)::bigint", string(raw)).Scan(&wire, &actualBytes); err != nil {
				t.Fatal("actual PostgreSQL JSONB wire oracle failed")
			}
			if actualBytes != int64(len(wire)) || !utf8.ValidString(wire) {
				t.Fatal("PostgreSQL/pgx UTF8 wire byte count disagreement")
			}
			if actualBytes > bound {
				t.Fatalf("wire undercount: bound=%d actual=%d", bound, actualBytes)
			}
			if coordinator.SnapshotV1(org) != before {
				t.Fatal("wire query/cancellation changed fixture resource ownership")
			}
		}) {
			return
		}
	}
	// Normal teardown uses the same fresh3s path as fatal cleanup, independent
	// of the overall10s workload context. No table or application state exists.
	cleanup()
	for _, problem := range cleanupProblems {
		t.Error(problem)
	}
	if len(cleanupProblems) == 0 && coordinator.SnapshotV1(org) != (workguard.SnapshotV1{}) {
		t.Fatal("joined explicit raw fixture work grants did not close exactly once")
	}
	t.Logf("actual UTF8 PostgreSQL16/pgx wire bound oracle qualified %d bounded cases, including64 deterministic generated cases; no app/READY/retirement/controller claim", len(cases))
}
