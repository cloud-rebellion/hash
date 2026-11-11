// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package packageauthoring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func captureLogV1(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestMissingResponseMeasurementHasDistinctLoggedResponseV1(t *testing.T) {
	buf := captureLogV1(t)
	org, doc := uuid.New(), uuid.New()
	cause := fmt.Errorf("read draft: %w", errors.Join(pdfadmission.ErrHTMLRevisionReadV1, pdfadmission.ErrHTMLResponseMeasurementMissingV1))
	status, message := PublicErrorLoggedV1(context.Background(), cause, org, doc)
	if status != http.StatusConflict {
		t.Fatalf("status=%d, want 409", status)
	}
	if _, def := PublicErrorV1(errors.New("other")); message == "attachment selection could not be completed" || def != "attachment selection could not be completed" {
		t.Fatalf("message=%q must differ from the catch-all", message)
	}
	for _, leak := range []string{"measurement", "html_creation", "pdfadmission", "ErrHTML"} {
		if strings.Contains(message, leak) {
			t.Fatalf("message leaks %q: %q", leak, message)
		}
	}
	log := buf.String()
	for _, want := range []string{org.String(), doc.String(), "response measurement missing"} {
		if !strings.Contains(log, want) {
			t.Fatalf("log lacks %q:\n%s", want, log)
		}
	}
}

func TestDefaultBranchLogsChainWithoutPersonalDataV1(t *testing.T) {
	buf := captureLogV1(t)
	org, doc := uuid.New(), uuid.New()
	secret := "alice@example.com"
	cause := fmt.Errorf("wrap %s: %w", secret, &pgconn.PgError{Code: "23505", Message: "dup " + secret, Detail: secret})
	status, _ := PublicErrorLoggedV1(context.Background(), cause, org, doc)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", status)
	}
	log := buf.String()
	for _, want := range []string{org.String(), doc.String(), "23505", "pgconn.PgError"} {
		if !strings.Contains(log, want) {
			t.Fatalf("log lacks %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, secret) {
		t.Fatalf("log leaked personal data:\n%s", log)
	}
}

func TestMappedErrorsAreNotLoggedV1(t *testing.T) {
	buf := captureLogV1(t)
	PublicErrorLoggedV1(context.Background(), ErrChangedV1, uuid.New(), uuid.New())
	if buf.Len() != 0 {
		t.Fatalf("unexpected log: %s", buf.String())
	}
}

func TestReviewGateIsMappedToAConflictInsteadOfGenericAvailability(t *testing.T) {
	err := &pgconn.PgError{Code: "23514", Message: "Replaced PDF requires review before sending"}
	status, message := PublicErrorV1(err)
	if status != http.StatusConflict {
		t.Fatalf("status=%d, want 409", status)
	}
	if message == "attachment selection could not be completed" || !strings.Contains(message, "reviewed") {
		t.Fatalf("message=%q lost the safe review instruction", message)
	}
}

func TestDynamicErrorTextAndClientAbortAreNotLoggedV1(t *testing.T) {
	buf := captureLogV1(t)
	secret := "alice@example.com"
	PublicErrorLoggedV1(context.Background(), errors.New("read "+secret+" failed"), uuid.New(), uuid.New())
	if log := buf.String(); log == "" || strings.Contains(log, secret) {
		t.Fatalf("dynamic text must log by type only:\n%s", log)
	}
	buf.Reset()
	PublicErrorLoggedV1(context.Background(), fmt.Errorf("load: %w", context.Canceled), uuid.New(), uuid.New())
	if buf.Len() != 0 {
		t.Fatalf("client abort must not log: %s", buf.String())
	}
}
