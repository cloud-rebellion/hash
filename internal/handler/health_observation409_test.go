// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
	sentry "github.com/getsentry/sentry-go"
)

type healthPrivateError409 struct{}

func (healthPrivateError409) Error() string { panic("telemetry invoked private Error()") }

func TestHealthProbe409ExactlyOnceOriginalBudgetErrorAndCleanup(t *testing.T) {
	for _, dependency := range []flarereport.HealthDependency{flarereport.HealthPostgres, flarereport.HealthMalware, flarereport.HealthPDFParser, flarereport.HealthStorage, flarereport.HealthGotenberg} {
		t.Run(string(dependency), func(t *testing.T) {
			parent := sentry.SetHubOnContext(context.Background(), sentry.NewHub(nil, sentry.NewScope()))
			calls := 0
			var original context.Context
			want := &healthPrivateError409{}
			got := observeHealthProbe409(parent, dependency, func(ctx context.Context) error {
				calls++
				original = ctx
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
					t.Fatal("original one-second probe budget changed")
				}
				return want
			})
			if calls != 1 || got != want || original.Err() != context.Canceled {
				t.Fatal("probe duplicated, error changed or child context survived")
			}
		})
	}
}

func TestHealthProbe409PreservesNilCancellationAndDeadline(t *testing.T) {
	for _, want := range []error{nil, context.Canceled, context.DeadlineExceeded} {
		parent := sentry.SetHubOnContext(context.Background(), sentry.NewHub(nil, sentry.NewScope()))
		calls := 0
		got := observeHealthProbe409(parent, flarereport.HealthPostgres, func(context.Context) error { calls++; return want })
		if calls != 1 || !errors.Is(got, want) {
			t.Fatal("fixed observer changed original probe result")
		}
	}
}
