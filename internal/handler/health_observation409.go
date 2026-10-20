// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
)

// Preserve exactly one original probe and its existing one-second child budget.
// No error value or caller data crosses into telemetry; the original response
// continues to use the identical returned error and optional-probe behavior.
func observeHealthProbe409(parent context.Context, dependency flarereport.HealthDependency, probe func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	started := time.Now()
	err := probe(ctx)
	outcome := flarereport.OutcomeSuccess
	if err != nil {
		outcome = flarereport.OutcomeUnavailable
		switch {
		case errors.Is(err, context.Canceled), ctx.Err() == context.Canceled:
			outcome = flarereport.OutcomeCanceled
		case errors.Is(err, context.DeadlineExceeded), ctx.Err() == context.DeadlineExceeded:
			outcome = flarereport.OutcomeTimeout
		}
	}
	flarereport.ObserveHealthDependency(parent, dependency, outcome, time.Since(started))
	return err
}
