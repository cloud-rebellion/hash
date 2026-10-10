// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestDatabaseToolErrorDoesNotExposePrivateDiagnostics(t *testing.T) {
	const marker = "synthetic-private-diagnostic-token"
	for _, err := range []error{
		fmt.Errorf("webhook storage: %w", &pgconn.PgError{Code: "P0001", Message: marker, Detail: "https://example.invalid/?secret=" + marker}),
		errors.New("dial tcp host=" + marker + ": connection refused"),
		pgx.ErrNoRows,
	} {
		var logs bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
		message := sanitizeToolError(err)
		slog.SetDefault(previous)
		if message != "internal error" || strings.Contains(logs.String(), marker) {
			t.Fatalf("private diagnostics escaped response or log: response=%q, logs=%s", message, logs.String())
		}
		if !strings.Contains(logs.String(), "error_type") {
			t.Fatalf("safe diagnostic type missing: %s", logs.String())
		}
	}
}
