// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/sanitize"
	sentry "github.com/getsentry/sentry-go"
)

func pdfCounter374(outcome Outcome) (count, milliseconds uint64) {
	for _, row := range SnapshotOperations() {
		if row.Operation == OperationPDF && row.Outcome == outcome {
			return row.Count, row.Milliseconds
		}
	}
	return 0, 0
}

func TestPDFWorker374FixedWirePrivacyAndExpectedRefusals(t *testing.T) {
	wire, _, hub := newWire343(t)
	const private = "PRIVATE_PDF_CONTRACT_TOKEN_BODY_374"
	hub.Scope().SetUser(sentry.User{Email: private})
	hub.Scope().SetTag("private", private)
	hub.Scope().SetContext("private", sentry.Context{"body": private})
	hub.Scope().SetRequest(httptest.NewRequest(http.MethodPost, "https://hash.example/completed/"+private+"?token="+private, strings.NewReader(private)))
	observer := PDFWorkerObserverV1(sentry.SetHubOnContext(context.Background(), hub))
	beforeRejected, _ := pdfCounter374(OutcomeRejected)
	for _, outcome := range []sanitize.PDFWorkerOutcomeV1{sanitize.PDFWorkerOutcomeRejectedV1, sanitize.PDFWorkerOutcomeCapacityV1, sanitize.PDFWorkerOutcomeCanceledV1, sanitize.PDFWorkerOutcomeSuccessV1} {
		observer(sanitize.PDFWorkerObservationV1{Operation: sanitize.PDFWorkerOperationCleanV1, Outcome: outcome, Elapsed: time.Millisecond})
	}
	flush343(t, hub)
	afterRejected, _ := pdfCounter374(OutcomeRejected)
	if afterRejected != beforeRejected+2 || len(wire.events(t)) != 0 {
		t.Fatal("expected validation/capacity/cancellation became pageable or lost counts")
	}
	for _, outcome := range []sanitize.PDFWorkerOutcomeV1{sanitize.PDFWorkerOutcomeUnavailableV1, sanitize.PDFWorkerOutcomeTimeoutV1, sanitize.PDFWorkerOutcomeInternalV1} {
		observer(sanitize.PDFWorkerObservationV1{Operation: sanitize.PDFWorkerOperationManualLayersV1, Outcome: outcome, Elapsed: 17 * time.Millisecond})
	}
	flush343(t, hub)
	encoded := wire.all()
	if strings.Contains(encoded, private) || strings.Contains(encoded, "hash.example") || !strings.Contains(encoded, "Hash operational failure") || !strings.Contains(encoded, `"operation":"pdf"`) || len(wire.events(t)) != 3 {
		t.Fatal("actual fixed PDF wire leaked inherited material or lost failure identity")
	}
	for _, category := range []string{"unavailable", "timeout", "internal"} {
		if !strings.Contains(encoded, `"failure_category":"`+category+`"`) {
			t.Fatal("fixed failure category missing")
		}
	}
}

func TestPDFWorker374ProbeUnknownsAndDurationBounds(t *testing.T) {
	wire, _, hub := newWire343(t)
	observer := PDFWorkerObserverV1(sentry.SetHubOnContext(context.Background(), hub))
	beforeCount, beforeMS := pdfCounter374(OutcomeSuccess)
	observer(sanitize.PDFWorkerObservationV1{Operation: sanitize.PDFWorkerOperationCleanV1, Outcome: sanitize.PDFWorkerOutcomeSuccessV1, Elapsed: -time.Second})
	observer(sanitize.PDFWorkerObservationV1{Operation: sanitize.PDFWorkerOperationPagesV1, Outcome: sanitize.PDFWorkerOutcomeSuccessV1, Elapsed: 48 * time.Hour})
	afterCount, afterMS := pdfCounter374(OutcomeSuccess)
	if afterCount != beforeCount+2 || afterMS != beforeMS+86400000 {
		t.Fatal("existing fixed duration bounds changed")
	}
	beforeInternal, _ := pdfCounter374(OutcomeInternal)
	for _, operation := range []sanitize.PDFWorkerOperationV1{sanitize.PDFWorkerOperationUnknownV1, sanitize.PDFWorkerOperationProbeV1, sanitize.PDFWorkerOperationV1(255)} {
		observer(sanitize.PDFWorkerObservationV1{Operation: operation, Outcome: sanitize.PDFWorkerOutcomeInternalV1})
	}
	observer(sanitize.PDFWorkerObservationV1{Operation: sanitize.PDFWorkerOperationCleanV1, Outcome: sanitize.PDFWorkerOutcomeUnknownV1})
	observer(sanitize.PDFWorkerObservationV1{Operation: sanitize.PDFWorkerOperationCleanV1, Outcome: sanitize.PDFWorkerOutcomeV1(255)})
	flush343(t, hub)
	afterInternal, _ := pdfCounter374(OutcomeInternal)
	if afterInternal != beforeInternal || len(wire.events(t)) != 0 {
		t.Fatal("probe or unknown enum created document failure authority")
	}
}
