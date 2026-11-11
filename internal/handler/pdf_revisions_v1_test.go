// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestPDFRevisionPinsMissingAreRequiredStaleAreMismatchesV1(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	stamp := "2026-11-07T10:00:00.123456Z"
	for name, c := range map[string][2]string{
		"empty": {"", ""}, "no digest": {stamp, ""}, "no time": {"", digest},
		"bad time": {"yesterday", digest}, "short digest": {stamp, "abcd"}, "upper digest": {stamp, strings.ToUpper(digest)},
	} {
		_, err := parsePDFRevisionPinsV1(c[0], c[1])
		var business *pdfRevisionBusinessV1
		if !errors.As(err, &business) || business.status != http.StatusPreconditionRequired {
			t.Fatalf("%s: err=%v, want 428", name, err)
		}
	}
	pins, err := parsePDFRevisionPinsV1(stamp, digest)
	if err != nil {
		t.Fatal(err)
	}
	at, _ := time.Parse(time.RFC3339Nano, stamp)
	doc := &generated.Document{UpdatedAt: pgtype.Timestamptz{Time: at, Valid: true}, PdfSha256: bytes.Repeat([]byte{0xab}, 32)}
	if !pins.matches(doc) {
		t.Fatal("exact pins refused")
	}
	stale := *doc
	stale.UpdatedAt.Time = at.Add(time.Microsecond)
	changed := *doc
	changed.PdfSha256 = bytes.Repeat([]byte{0xcd}, 32)
	if pins.matches(&stale) || pins.matches(&changed) || pins.matches(nil) {
		t.Fatal("stale or changed document accepted")
	}
}

func TestPDFRevisionRefusalsNameTheStateV1(t *testing.T) {
	ok := &generated.GetPDFRevisionBlockersV1Row{SourceKind: "pdf"}
	if err := pdfRevisionRefusalV1(ok); err != nil {
		t.Fatalf("plain imported PDF refused: %v", err)
	}
	for name, row := range map[string]*generated.GetPDFRevisionBlockersV1Row{
		"envelope":    {SourceKind: "pdf", IsEnvelope: true},
		"in envelope": {SourceKind: "pdf", InEnvelope: true},
		"amendment":   {SourceKind: "pdf", AmendmentLinked: true},
		"template":    {SourceKind: "pdf", TemplateBacked: true},
		"html":        {SourceKind: "pdf", HtmlSource: true},
		"blocks":      {SourceKind: "blocks"},
	} {
		err := pdfRevisionRefusalV1(row)
		var business *pdfRevisionBusinessV1
		if !errors.As(err, &business) || business.status != http.StatusConflict {
			t.Fatalf("%s: err=%v, want 409", name, err)
		}
	}
}

func TestPDFRevisionSummaryBoundsV1(t *testing.T) {
	if !validPDFRevisionSummaryV1("") || !validPDFRevisionSummaryV1(strings.Repeat("å", 500)) {
		t.Fatal("valid summary refused")
	}
	for name, s := range map[string]string{"long": strings.Repeat("a", 501), "nul": "a\x00b", "invalid utf8": "\xff"} {
		if validPDFRevisionSummaryV1(s) {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestPDFRevisionErrorMappingV1(t *testing.T) {
	s := &Server{}
	for name, c := range map[string]struct {
		err        error
		status     int
		code       string // "" means not asserted
		retryAfter string
	}{
		"pins":               {errPDFRevisionPinsMissingV1, http.StatusPreconditionRequired, "", ""},
		"conflict":           {pdfRevisionConflictV1("x"), http.StatusConflict, "", ""},
		"human only":         {errHumanReviewRequiredV1, http.StatusForbidden, "", ""},
		"scanner":            {malwarescan.ErrDetected, http.StatusBadRequest, "", ""},
		"scan down":          {malwarescan.ErrUnavailable, http.StatusServiceUnavailable, "", ""},
		"not draft":          {authoring.ErrDocumentNotDraft, http.StatusConflict, "", ""},
		"has evidence":       {authoring.ErrDocumentHasEvidence, http.StatusConflict, "", ""},
		"not found":          {authoring.ErrDocumentNotFound, http.StatusNotFound, "", ""},
		"gate in session":    {errors.Join(pdfadmission.ErrApplicationSessionV1, &pgconn.PgError{Code: "23514", Message: "Replaced PDF requires review before sending"}), http.StatusConflict, "pdf_review_required", ""},
		"check in session":   {errors.Join(pdfadmission.ErrApplicationSessionV1, &pgconn.PgError{Code: "23514", Message: "something else"}), http.StatusConflict, "pdf_revision_refused", ""},
		"lock in session":    {errors.Join(pdfadmission.ErrApplicationSessionV1, &pgconn.PgError{Code: "55P03"}), http.StatusServiceUnavailable, "", "1"},
		"bare session":       {pdfadmission.ErrApplicationSessionV1, http.StatusServiceUnavailable, "", "1"},
		"serialization":      {errors.Join(pdfadmission.ErrApplicationSessionV1, &pgconn.PgError{Code: "40001"}), http.StatusServiceUnavailable, "", "1"},
		"deadlock":           {errors.Join(pdfadmission.ErrApplicationSessionV1, &pgconn.PgError{Code: "40P01"}), http.StatusServiceUnavailable, "", "1"},
		"bare serialization": {&pgconn.PgError{Code: "40001"}, http.StatusServiceUnavailable, "", "1"},
		"bare deadlock":      {&pgconn.PgError{Code: "40P01"}, http.StatusServiceUnavailable, "", "1"},
		"bare lock":          {&pgconn.PgError{Code: "55P03"}, http.StatusServiceUnavailable, "", "1"},
		"no rows":            {pgx.ErrNoRows, http.StatusConflict, "pdf_revision_state_changed", ""},
		"no rows in tx":      {errors.Join(pdfadmission.ErrApplicationSessionV1, pgx.ErrNoRows), http.StatusConflict, "pdf_revision_state_changed", ""},
		"send gate PDF":      {&pgconn.PgError{Code: "23514", Message: "Replaced PDF requires review before sending"}, http.StatusConflict, "pdf_review_required", ""},
	} {
		w := httptest.NewRecorder()
		s.writePDFRevisionErrorV1(w, c.err)
		if w.Code != c.status {
			t.Fatalf("%s: status=%d want %d (%s)", name, w.Code, c.status, w.Body.String())
		}
		if got := w.Header().Get("Retry-After"); got != c.retryAfter {
			t.Fatalf("%s: Retry-After=%q want %q", name, got, c.retryAfter)
		}
		if c.code != "" {
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["code"] != c.code {
				t.Fatalf("%s: code=%q want %q (%s)", name, body["code"], c.code, w.Body.String())
			}
		}
	}
}

func TestPDFRevisionMCPFailuresStayActionableButBoundedV1(t *testing.T) {
	if got := safeMCPPDFRevisionFailureV1(pdfRevisionConflictV1("document or PDF changed; reload")); got == nil || !strings.Contains(got.Error(), "reload") {
		t.Fatal("stale pin message lost", got)
	}
	if got := safeMCPPDFRevisionFailureV1(errHumanReviewRequiredV1); !errors.Is(got, errHumanReviewRequiredV1) {
		t.Fatal("human review refusal collapsed", got)
	}
	if got := safeMCPPDFRevisionFailureV1(errors.New("pq: secret internal detail")); got == nil || strings.Contains(got.Error(), "secret") {
		t.Fatal("internal detail leaked", got)
	}
	if safeMCPPDFRevisionFailureV1(nil) != nil {
		t.Fatal("nil became an error")
	}
}

func TestPDFRevisionCommitMayHaveLandedV1(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want bool
	}{
		"unknown outcome":         {pdfadmission.ErrApplicationSessionCommitUnknownV1, true},
		"wrapped unknown outcome": {fmt.Errorf("commit: %w", pdfadmission.ErrApplicationSessionCommitUnknownV1), true},
		"joined unknown outcome":  {errors.Join(errors.New("x"), pdfadmission.ErrApplicationSessionCommitUnknownV1), true},
		"refused before dispatch": {pdfadmission.ErrApplicationSessionV1, false},
		"plain error":             {errors.New("boom"), false},
		"context canceled":        {context.Canceled, false},
	} {
		if got := pdfRevisionCommitMayHaveLandedV1(c.err); got != c.want {
			t.Fatalf("%s: got %v want %v", name, got, c.want)
		}
	}
}

func TestPDFRevisionReadAccessV1(t *testing.T) {
	org, user, other := uuid.New(), uuid.New(), uuid.New()
	row := func(role string, gen int64) *generated.User {
		return &generated.User{ID: user, OrgID: org, Role: role, SessionGeneration: gen}
	}
	boom := errors.New("connection reset")
	for name, c := range map[string]struct {
		cur    *generated.User
		err    error
		sender uuid.UUID
		gen    int64
		check  bool
		want   pdfRevisionAccessV1
	}{
		"sender":                  {row("member", 3), nil, user, 3, true, pdfRevisionAccessAllowedV1},
		"owner not sender":        {row("owner", 3), nil, other, 3, true, pdfRevisionAccessAllowedV1},
		"member not sender":       {row("member", 3), nil, other, 3, true, pdfRevisionAccessDeniedV1},
		"revoked session":         {row("owner", 4), nil, user, 3, true, pdfRevisionAccessDeniedV1},
		"mcp ignores generation":  {row("owner", 4), nil, user, 0, false, pdfRevisionAccessAllowedV1},
		"other org":               {&generated.User{ID: user, OrgID: other, Role: "owner", SessionGeneration: 3}, nil, user, 3, true, pdfRevisionAccessDeniedV1},
		"user gone":               {nil, pgx.ErrNoRows, user, 3, true, pdfRevisionAccessDeniedV1},
		"db error":                {nil, boom, user, 3, true, pdfRevisionAccessUnavailableV1},
		"db error wrapped":        {nil, fmt.Errorf("x: %w", boom), user, 3, false, pdfRevisionAccessUnavailableV1},
		"db error with stale row": {row("owner", 3), boom, user, 3, true, pdfRevisionAccessUnavailableV1},
	} {
		if got := pdfRevisionReadAccessV1(c.cur, c.err, org, user, c.sender, c.gen, c.check); got != c.want {
			t.Fatalf("%s: got %d want %d", name, got, c.want)
		}
	}
}
