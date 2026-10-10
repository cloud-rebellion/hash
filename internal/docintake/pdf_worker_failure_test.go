// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package docintake

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/sanitize"
)

// The peer performs the real clean operation, then fails on the independently
// admitted page-count operation. No customer bytes or production worker are used.
func TestMain(m *testing.M) {
	if strings.HasPrefix(filepath.Base(os.Args[0]), "hash-intake-worker-peer-") {
		input, err := io.ReadAll(io.LimitReader(os.Stdin, sanitize.MaxPDFBytes+4096))
		if err != nil {
			os.Exit(2)
		}
		line, _, ok := bytes.Cut(input, []byte{'\n'})
		var request struct {
			Operation string `json:"operation"`
		}
		if !ok || json.Unmarshal(line, &request) != nil || request.Operation == "pages" {
			os.Exit(3)
		}
		if err := sanitize.ServePDFWorker(bytes.NewReader(input), os.Stdout); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestPageCountWorkerFailurePreservesRetryableCauseBeforeStorage(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	peer := filepath.Join(t.TempDir(), "hash-intake-worker-peer-count-failure")
	if err := os.Symlink(binary, peer); err != nil {
		t.Fatal(err)
	}
	if err := sanitize.ConfigurePDFWorker(context.Background(), peer, "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sanitize.ConfigurePDFWorker(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	st := &intakeStoreStub{}
	doc, pages, err := CreatePDFSourceDocument(context.Background(), &intakeQueriesStub{}, st, uuid.New(), uuid.New(), "Proposal", intakeTestPDF(t))
	if !errors.Is(err, sanitize.ErrPDFWorkerUnavailable) || !errors.Is(err, ErrSanitizePDF) || !strings.Contains(err.Error(), "count sanitized PDF pages") {
		t.Fatalf("count failure lost its retryable worker cause: %v", err)
	}
	if doc != nil || pages != 0 || len(st.putKeys) != 0 {
		t.Fatal("failed page count reached storage or returned a document")
	}
}
