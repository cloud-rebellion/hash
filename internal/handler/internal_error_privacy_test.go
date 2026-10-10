// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestInternalErrorHelpersKeepDatabaseDiagnosticsOutOfResponseAndLogs(t *testing.T) {
	const (
		privateMessage = "private-database-message-marker"
		privateDetail  = "private-database-detail-marker"
		privateURL     = "https://private-webhook.example/private-url-marker?credential=private-query-marker"
		publicMessage  = "create document failed"
	)
	databaseErr := &pgconn.PgError{
		Code: "XX000", Message: privateMessage, Detail: privateDetail, Where: privateURL,
	}
	for _, helper := range []struct {
		name      string
		write     func(http.ResponseWriter, error)
		publicMsg string
	}{
		{name: "writeInternalError", write: writeInternalError, publicMsg: "internal error"},
		{
			name: "writeInternalErrorMsg", publicMsg: publicMessage,
			write: func(w http.ResponseWriter, err error) { writeInternalErrorMsg(w, publicMessage, err) },
		},
	} {
		for _, cause := range []struct {
			name string
			err  error
		}{
			{name: "database", err: databaseErr},
			{name: "wrapped", err: fmt.Errorf("upstream %s: %w", privateURL, databaseErr)},
		} {
			t.Run(helper.name+"/"+cause.name, func(t *testing.T) {
				var logs bytes.Buffer
				previous := slog.Default()
				slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
				t.Cleanup(func() { slog.SetDefault(previous) })

				response := httptest.NewRecorder()
				helper.write(response, cause.err)
				if response.Code != http.StatusInternalServerError {
					t.Fatalf("response status = %d, want 500", response.Code)
				}
				var body map[string]string
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if len(body) != 1 || body["error"] != helper.publicMsg {
					t.Fatalf("response = %#v, want approved public error %q", body, helper.publicMsg)
				}
				for _, marker := range []string{privateMessage, privateDetail, privateURL, "private-query-marker"} {
					if strings.Contains(response.Body.String(), marker) || strings.Contains(logs.String(), marker) {
						t.Fatal("private database diagnostic reached response or log")
					}
				}
				var entry map[string]any
				if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
					t.Fatal(err)
				}
				if entry["operation"] != helper.name || entry["error_type"] != fmt.Sprintf("%T", cause.err) {
					t.Fatalf("safe operation/error type missing: %#v", entry)
				}
				if _, exists := entry["err"]; exists {
					t.Fatal("log retained a raw error attribute")
				}
			})
		}
	}
}
