// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

const (
	OperationPDF               Operation       = "pdf"
	OperationCRM               Operation       = "crm"
	OperationSigning           Operation       = "signing"
	OperationEvidence          Operation       = "evidence"
	OperationSMTP              Operation       = "smtp"
	OperationReminder          Operation       = "reminder"
	OperationWebhook           Operation       = "webhook"
	OperationImport            Operation       = "import"
	OperationAuthentication    Operation       = "authentication"
	OperationStorage           Operation       = "storage"
	OperationOIDCDiscovery     Operation       = "oidc_discovery"
	OperationOIDCTokenExchange Operation       = "oidc_token_exchange"
	OperationHealthPostgres    Operation       = "health_postgres"
	OperationHealthMalware     Operation       = "health_malware"
	OperationHealthPDFParser   Operation       = "health_pdf_parser"
	OperationHealthStorage     Operation       = "health_storage"
	OperationHealthGotenberg   Operation       = "health_gotenberg"
	FailureTimeout             FailureCategory = "timeout"
)

type Outcome string

const (
	OutcomeSuccess     Outcome = "success"
	OutcomeRejected    Outcome = "rejected"
	OutcomeCanceled    Outcome = "canceled"
	OutcomeInternal    Outcome = "internal"
	OutcomeDependency  Outcome = "dependency"
	OutcomeUnavailable Outcome = "unavailable"
	OutcomeTimeout     Outcome = "timeout"
)

var operationNames = [...]Operation{OperationHTTP, OperationMCP, OperationWorker, OperationMail, OperationPDF, OperationCRM, OperationSigning, OperationEvidence, OperationSMTP, OperationReminder, OperationWebhook, OperationImport, OperationAuthentication, OperationStorage, OperationOIDCDiscovery, OperationOIDCTokenExchange, OperationHealthPostgres, OperationHealthMalware, OperationHealthPDFParser, OperationHealthStorage, OperationHealthGotenberg}
var outcomeNames = [...]Outcome{OutcomeSuccess, OutcomeRejected, OutcomeCanceled, OutcomeInternal, OutcomeDependency, OutcomeUnavailable, OutcomeTimeout}

type operationCounter struct {
	count        atomic.Uint64
	milliseconds atomic.Uint64
}

var operationCounters [len(operationNames)][len(outcomeNames)]operationCounter

func operationIndex(operation Operation) int {
	for i, name := range operationNames {
		if name == operation {
			return i
		}
	}
	return -1
}
func outcomeIndex(outcome Outcome) int {
	for i, name := range outcomeNames {
		if name == outcome {
			return i
		}
	}
	return -1
}
func validOutcome(outcome Outcome) bool { return outcomeIndex(outcome) >= 0 }

// ObserveOperation takes only a closed operation/outcome and elapsed duration.
// Counts are fixed-size atomics, never a tenant/path/document keyed map. Normal
// denials/cancellations aggregate without creating pageable issues.
func ObserveOperation(ctx context.Context, operation Operation, outcome Outcome, elapsed time.Duration) {
	op, kind := operationIndex(operation), outcomeIndex(outcome)
	if op < 0 || kind < 0 {
		return
	}
	milliseconds := elapsed.Milliseconds()
	if milliseconds < 0 {
		milliseconds = 0
	}
	if milliseconds > 86400000 {
		milliseconds = 86400000
	}
	counter := &operationCounters[op][kind]
	counter.count.Add(1)
	counter.milliseconds.Add(uint64(milliseconds))
	level := slog.LevelInfo
	switch outcome {
	case OutcomeInternal, OutcomeDependency, OutcomeUnavailable, OutcomeTimeout:
		level = slog.LevelError
		CaptureOperationFailure(ctx, operation, FailureCategory(outcome))
	}
	slog.Log(ctx, level, "Hash operation outcome", slog.String("operation", string(operation)), slog.String("outcome", string(outcome)), slog.Int64("duration_ms", milliseconds))
}

type OperationSnapshot struct {
	Operation    Operation `json:"operation"`
	Outcome      Outcome   `json:"outcome"`
	Count        uint64    `json:"count"`
	Milliseconds uint64    `json:"milliseconds"`
}

func SnapshotOperations() []OperationSnapshot {
	out := make([]OperationSnapshot, 0, len(operationNames)*len(outcomeNames))
	for op, name := range operationNames {
		for kind, outcome := range outcomeNames {
			counter := &operationCounters[op][kind]
			if count := counter.count.Load(); count > 0 {
				out = append(out, OperationSnapshot{Operation: name, Outcome: outcome, Count: count, Milliseconds: counter.milliseconds.Load()})
			}
		}
	}
	return out
}
