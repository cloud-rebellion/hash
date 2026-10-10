// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/webhooksecret"
)

const (
	webhookDrainLimit      = 50
	webhookDrainTimeout    = 2 * time.Minute
	webhookReadTimeout     = 5 * time.Second
	webhookAttemptTimeout  = 30 * time.Second
	webhookDispatchTimeout = 15 * time.Second
	webhookMarkTimeout     = 5 * time.Second
)

// Diagnostics are stable application codes. Provider response bodies and
// arbitrary dependency/transport errors never cross into persisted state.
const (
	webhookEndpointMissing      = "endpoint_missing"
	webhookEndpointInactive     = "endpoint_inactive"
	webhookEndpointUnavailable  = "endpoint_dependency_unavailable"
	webhookSecretInvalid        = "endpoint_secret_invalid"
	webhookEventMissing         = "event_missing"
	webhookEventUnavailable     = "event_dependency_unavailable"
	webhookEventInvalid         = "event_invalid"
	webhookTransportUnavailable = "delivery_transport_unavailable"
	webhookHTTPRefused          = "delivery_http_refused"
)

type webhookDeliveryOutcome struct {
	status        string
	statusCode    int32
	diagnostic    string
	nextAttemptAt time.Time
}

type webhookDeliveryDependencies struct {
	endpoint func(context.Context, uuid.UUID) (webhooksecret.DeliveryEndpoint, error)
	event    func(context.Context, uuid.UUID) (dispatch.WebhookEvent, error)
	dispatch func(context.Context, string, string, dispatch.WebhookEvent) dispatch.DispatchResult
	mark     func(context.Context, *generated.WebhookDelivery, webhookDeliveryOutcome) (int64, error)
	now      func() time.Time
}

func (w *worker) webhookDeliveryDependencies() webhookDeliveryDependencies {
	return webhookDeliveryDependencies{
		endpoint: w.webhookSecrets.EndpointForDelivery,
		event: func(ctx context.Context, id uuid.UUID) (dispatch.WebhookEvent, error) {
			return dispatch.LoadEvent(ctx, w.queries, id)
		},
		dispatch: w.dispatcher.DispatchWithSecret,
		mark: func(ctx context.Context, claim *generated.WebhookDelivery, outcome webhookDeliveryOutcome) (int64, error) {
			switch outcome.status {
			case "delivered":
				return w.queries.MarkClaimedWebhookDeliveryDelivered(ctx, generated.MarkClaimedWebhookDeliveryDeliveredParams{
					ID: claim.ID, ExpectedAttempts: claim.Attempts, ExpectedNextAttemptAt: claim.NextAttemptAt,
					LastStatusCode: outcome.statusCode,
				})
			case "retrying":
				return w.queries.MarkClaimedWebhookDeliveryRetrying(ctx, generated.MarkClaimedWebhookDeliveryRetryingParams{
					ID: claim.ID, ExpectedAttempts: claim.Attempts, ExpectedNextAttemptAt: claim.NextAttemptAt,
					LastStatusCode: outcome.statusCode, LastError: outcome.diagnostic,
					NextAttemptAt: pgtype.Timestamptz{Time: outcome.nextAttemptAt, Valid: true},
				})
			case "failed":
				return w.queries.MarkClaimedWebhookDeliveryFailed(ctx, generated.MarkClaimedWebhookDeliveryFailedParams{
					ID: claim.ID, ExpectedAttempts: claim.Attempts, ExpectedNextAttemptAt: claim.NextAttemptAt,
					LastStatusCode: outcome.statusCode, LastError: outcome.diagnostic,
				})
			default:
				return 0, errors.New("webhook checkpoint outcome invalid")
			}
		},
		now: time.Now,
	}
}

// A pass never leases deliveries ahead of network I/O. Crashes/cancellation or
// failed persistence leave the exact claim to expire naturally; only the new
// fenced SQL marks can acknowledge this attempt.
func drainWebhookDeliveries(ctx context.Context, limit int, claim func(context.Context) (*generated.WebhookDelivery, error), attempt func(context.Context, *generated.WebhookDelivery) error) error {
	if limit < 1 || limit > webhookDrainLimit || claim == nil || attempt == nil {
		return errors.New("webhook drain dependencies invalid")
	}
	for i := 0; i < limit; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		readCtx, cancel := context.WithTimeout(ctx, webhookReadTimeout)
		due, err := claim(readCtx)
		cancel()
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if due == nil {
			return errors.New("webhook claim missing")
		}
		if err := attempt(ctx, due); err != nil {
			return err
		}
	}
	return nil
}

func processClaimedWebhookDelivery(ctx context.Context, claim *generated.WebhookDelivery, deps webhookDeliveryDependencies) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if claim == nil || claim.ID == uuid.Nil || claim.EndpointID == uuid.Nil || claim.EventID == uuid.Nil ||
		claim.Status != "retrying" || claim.Attempts < 0 || !claim.NextAttemptAt.Valid ||
		claim.NextAttemptAt.InfinityModifier != pgtype.Finite || deps.endpoint == nil || deps.event == nil ||
		deps.dispatch == nil || deps.mark == nil || deps.now == nil {
		return false, errors.New("webhook claim dependencies invalid")
	}
	remaining := claim.NextAttemptAt.Time.Sub(deps.now()) - webhookMarkTimeout
	if remaining <= 0 {
		return false, nil
	}
	if remaining > webhookAttemptTimeout {
		remaining = webhookAttemptTimeout
	}
	attemptCtx, cancelAttempt := context.WithTimeout(ctx, remaining)
	defer cancelAttempt()

	readCtx, cancelRead := context.WithTimeout(attemptCtx, webhookReadTimeout)
	endpoint, err := deps.endpoint(readCtx, claim.EndpointID)
	if err == nil {
		err = readCtx.Err()
	}
	cancelRead()
	var outcome webhookDeliveryOutcome
	if err != nil {
		outcome = webhookFailureOutcome(claim, deps.now(), 0, webhookEndpointUnavailable, errors.Is(err, pgx.ErrNoRows) || errors.Is(err, webhooksecret.ErrEndpointInactive))
		if errors.Is(err, pgx.ErrNoRows) {
			outcome.diagnostic = webhookEndpointMissing
		} else if errors.Is(err, webhooksecret.ErrEndpointInactive) {
			outcome.diagnostic = webhookEndpointInactive
		}
	} else if endpoint.ID != claim.EndpointID || endpoint.OrgID == uuid.Nil {
		outcome = webhookFailureOutcome(claim, deps.now(), 0, webhookEventInvalid, true)
	} else if !webhooksecret.IsStrongSigningSecret(endpoint.SigningSecret) {
		// Never give DispatchWithSecret an empty/unsafe key: its legacy fallback
		// must not turn failed endpoint authentication into a network send.
		outcome = webhookFailureOutcome(claim, deps.now(), 0, webhookSecretInvalid, false)
	} else {
		readCtx, cancelRead = context.WithTimeout(attemptCtx, webhookReadTimeout)
		event, eventErr := deps.event(readCtx, claim.EventID)
		if eventErr == nil {
			eventErr = readCtx.Err()
		}
		cancelRead()
		if eventErr != nil {
			outcome = webhookFailureOutcome(claim, deps.now(), 0, webhookEventUnavailable, errors.Is(eventErr, pgx.ErrNoRows))
			if errors.Is(eventErr, pgx.ErrNoRows) {
				outcome.diagnostic = webhookEventMissing
			}
		} else if !validWebhookClaimEvent(claim, endpoint.OrgID, event) {
			outcome = webhookFailureOutcome(claim, deps.now(), 0, webhookEventInvalid, true)
		} else {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if claim.NextAttemptAt.Time.Sub(deps.now()) <= webhookMarkTimeout {
				return false, nil
			}
			if err := attemptCtx.Err(); err != nil {
				outcome = webhookFailureOutcome(claim, deps.now(), 0, webhookTransportUnavailable, false)
			} else {
				dispatchCtx, cancelDispatch := context.WithTimeout(attemptCtx, webhookDispatchTimeout)
				result := deps.dispatch(dispatchCtx, endpoint.URL, endpoint.SigningSecret, event)
				if result.Err == nil {
					result.Err = dispatchCtx.Err()
				}
				cancelDispatch()
				status := webhookStatusCode(result.Status)
				if result.Err == nil && result.Status >= 200 && result.Status < 300 {
					outcome = webhookDeliveryOutcome{status: "delivered", statusCode: status}
				} else {
					code := webhookHTTPRefused
					if result.Err != nil {
						code = webhookTransportUnavailable
					}
					outcome = webhookFailureOutcome(claim, deps.now(), status, code, false)
				}
			}
		}
	}
	// This window belongs to the original pass, separately from the consumed
	// attempt deadline. No background context may acknowledge a cancelled pass.
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !claim.NextAttemptAt.Time.After(deps.now()) {
		return false, nil
	}
	markCtx, cancelMark := context.WithTimeout(ctx, webhookMarkTimeout)
	defer cancelMark()
	rows, err := deps.mark(markCtx, claim, outcome)
	if err != nil {
		return false, err
	}
	if rows < 0 || rows > 1 {
		return false, errors.New("webhook checkpoint row count invalid")
	}
	return rows == 1, nil
}

func validWebhookClaimEvent(claim *generated.WebhookDelivery, endpointOrgID uuid.UUID, event dispatch.WebhookEvent) bool {
	orgID, err := uuid.Parse(event.OrgID)
	return err == nil && orgID != uuid.Nil && orgID == endpointOrgID && event.EventID == claim.EventID.String() &&
		!event.OccurredAt.IsZero() && dispatch.IsPublicEventKind(event.Kind)
}

func webhookFailureOutcome(claim *generated.WebhookDelivery, now time.Time, statusCode int32, diagnostic string, permanent bool) webhookDeliveryOutcome {
	outcome := webhookDeliveryOutcome{status: "failed", statusCode: statusCode, diagnostic: diagnostic}
	if !permanent {
		if delay, ok := dispatch.Backoff(int(claim.Attempts)); ok {
			outcome.status = "retrying"
			outcome.nextAttemptAt = now.Add(delay)
		}
	}
	return outcome
}

func webhookStatusCode(status int) int32 {
	if status < 100 || status > 599 {
		return 0
	}
	return int32(status)
}
