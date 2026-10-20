// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"strings"
	"testing"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

func TestHealthDependency409ClosedOutcomesAndSafeErrorEvents(t *testing.T) {
	wire, _, hub := newWire343(t)
	ctx := sentry.SetHubOnContext(context.Background(), hub)
	pairs := []struct {
		dependency HealthDependency
		operation  Operation
	}{
		{HealthPostgres, OperationHealthPostgres}, {HealthMalware, OperationHealthMalware},
		{HealthPDFParser, OperationHealthPDFParser}, {HealthStorage, OperationHealthStorage}, {HealthGotenberg, OperationHealthGotenberg},
	}
	for _, p := range pairs {
		ObserveHealthDependency(ctx, p.dependency, OutcomeUnavailable, time.Millisecond)
		ObserveHealthDependency(ctx, p.dependency, OutcomeCanceled, time.Millisecond)
		ObserveHealthDependency(ctx, p.dependency, OutcomeSuccess, time.Millisecond)
	}
	ObserveHealthDependency(ctx, HealthDependency("PRIVATE_HOST_409"), OutcomeUnavailable, 0)
	ObserveHealthDependency(ctx, HealthPostgres, Outcome("PRIVATE_ERROR_409"), 0)
	flush343(t, hub)
	events := wire.events(t)
	if len(events) != len(pairs) {
		t.Fatalf("expected only five actual unavailable events, got %d", len(events))
	}
	seen := map[string]bool{}
	for _, event := range events {
		tags, ok := event["tags"].(map[string]any)
		if !ok || tags["failure_category"] != "unavailable" {
			t.Fatal("fixed unavailable category missing")
		}
		seen[tags["operation"].(string)] = true
	}
	for _, p := range pairs {
		if !seen[string(p.operation)] {
			t.Fatal("fixed dependency collapsed or omitted", p.operation)
		}
	}
	if strings.Contains(wire.all(), "PRIVATE_HOST_409") || strings.Contains(wire.all(), "PRIVATE_ERROR_409") {
		t.Fatal("unknown dependency/outcome leaked or became pageable")
	}
}
