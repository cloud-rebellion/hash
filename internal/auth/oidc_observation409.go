// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package auth

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
	"golang.org/x/oauth2"
)

// Only actual discovery/token-exchange calls reach this boundary. State, nonce,
// code validation and cached discovery are not invented provider attempts.
// Classify typed protocol/transport facts, never Error(), body or URL strings.
func oidcProviderOutcome409(operation flarereport.Operation, err error) flarereport.Outcome {
	if err == nil {
		return flarereport.OutcomeSuccess
	}
	if errors.Is(err, context.Canceled) {
		return flarereport.OutcomeCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return flarereport.OutcomeTimeout
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return flarereport.OutcomeTimeout
	}
	if operation == flarereport.OperationOIDCTokenExchange {
		var response *oauth2.RetrieveError
		if errors.As(err, &response) && response.Response != nil {
			status := response.Response.StatusCode
			// ErrorCode is a decoded OAuth protocol enum, not Error() text.
			// Provider5xx/rate failures cannot masquerade as a user refusal.
			if status >= 400 && status < 500 && status != 429 {
				switch response.ErrorCode {
				case "invalid_client", "unauthorized_client":
					return flarereport.OutcomeDependency
				case "invalid_grant", "access_denied", "interaction_required", "login_required", "consent_required":
					return flarereport.OutcomeRejected
				}
			}
		}
	}
	return flarereport.OutcomeDependency
}

func observeOIDCProvider409(ctx context.Context, operation flarereport.Operation, err error, elapsed time.Duration) {
	if operation != flarereport.OperationOIDCDiscovery && operation != flarereport.OperationOIDCTokenExchange {
		return
	}
	flarereport.ObserveOperation(ctx, operation, oidcProviderOutcome409(operation, err), elapsed)
}
