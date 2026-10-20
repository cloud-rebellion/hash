// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"time"
)

// HealthDependency is a closed existing-probe name, never a hostname or URL.
type HealthDependency string

const (
	HealthPostgres  HealthDependency = "postgres"
	HealthMalware   HealthDependency = "malware"
	HealthPDFParser HealthDependency = "pdf_parser"
	HealthStorage   HealthDependency = "storage"
	HealthGotenberg HealthDependency = "gotenberg"
)

// ObserveHealthDependency records only the original probe's returned outcome.
// Success/cancellation retain the existing info floor; actual unavailable and
// timeout outcomes use the existing fixed error path. No new probe is invoked.
func ObserveHealthDependency(ctx context.Context, dependency HealthDependency, outcome Outcome, elapsed time.Duration) {
	var operation Operation
	switch dependency {
	case HealthPostgres:
		operation = OperationHealthPostgres
	case HealthMalware:
		operation = OperationHealthMalware
	case HealthPDFParser:
		operation = OperationHealthPDFParser
	case HealthStorage:
		operation = OperationHealthStorage
	case HealthGotenberg:
		operation = OperationHealthGotenberg
	default:
		return
	}
	switch outcome {
	case OutcomeSuccess, OutcomeUnavailable, OutcomeTimeout, OutcomeCanceled:
		ObserveOperation(ctx, operation, outcome, elapsed)
	}
}
