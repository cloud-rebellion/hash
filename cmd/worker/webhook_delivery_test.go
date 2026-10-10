// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/webhooksecret"
)

type webhookDeliveryFixture struct {
	endpointOrgID                                       uuid.UUID
	now                                                 time.Time
	claim                                               generated.WebhookDelivery
	event                                               dispatch.WebhookEvent
	secret                                              string
	endpointErr                                         error
	eventErr                                            error
	result                                              dispatch.DispatchResult
	markErr                                             error
	markRows                                            int64
	endpointCalls, eventCalls, dispatchCalls, markCalls int
	outcomes                                            []webhookDeliveryOutcome
	markedClaims                                        []generated.WebhookDelivery
	dispatchedEvents                                    []dispatch.WebhookEvent
}

func newWebhookDeliveryFixture() *webhookDeliveryFixture {
	now := time.Now().UTC()
	orgID := uuid.New()
	claim := generated.WebhookDelivery{ID: uuid.New(), EndpointID: uuid.New(), EventID: uuid.New(), Status: "retrying", NextAttemptAt: pgtype.Timestamptz{Time: now.Add(5 * time.Minute), Valid: true}}
	return &webhookDeliveryFixture{
		now: now, claim: claim, endpointOrgID: orgID,
		event:  dispatch.WebhookEvent{EventID: claim.EventID.String(), OrgID: orgID.String(), Kind: "document.completed", OccurredAt: now, AutomationRequestID: uuid.NewString(), Payload: map[string]any{"state": "synthetic"}},
		secret: "synthetic-signing-secret-0123456789abcdef",
		result: dispatch.DispatchResult{Status: 204}, markRows: 1,
	}
}

func (f *webhookDeliveryFixture) dependencies(t *testing.T) webhookDeliveryDependencies {
	t.Helper()
	return webhookDeliveryDependencies{
		endpoint: func(ctx context.Context, id uuid.UUID) (webhooksecret.DeliveryEndpoint, error) {
			assertWebhookDeadline(t, ctx, webhookReadTimeout)
			if id != f.claim.EndpointID {
				t.Fatal("wrong endpoint")
			}
			f.endpointCalls++
			return webhooksecret.DeliveryEndpoint{ID: id, OrgID: f.endpointOrgID, URL: "https://subscriber.example.invalid/callback", SigningSecret: f.secret}, f.endpointErr
		},
		event: func(ctx context.Context, id uuid.UUID) (dispatch.WebhookEvent, error) {
			assertWebhookDeadline(t, ctx, webhookReadTimeout)
			if id != f.claim.EventID {
				t.Fatal("wrong event")
			}
			f.eventCalls++
			return f.event, f.eventErr
		},
		dispatch: func(ctx context.Context, url, secret string, event dispatch.WebhookEvent) dispatch.DispatchResult {
			assertWebhookDeadline(t, ctx, webhookDispatchTimeout)
			if secret != f.secret || secret == "" || url != "https://subscriber.example.invalid/callback" {
				t.Fatal("dispatch lost authenticated endpoint")
			}
			f.dispatchCalls++
			f.dispatchedEvents = append(f.dispatchedEvents, event)
			return f.result
		},
		mark: func(ctx context.Context, claim *generated.WebhookDelivery, outcome webhookDeliveryOutcome) (int64, error) {
			assertWebhookDeadline(t, ctx, webhookMarkTimeout)
			f.markCalls++
			f.markedClaims = append(f.markedClaims, *claim)
			f.outcomes = append(f.outcomes, outcome)
			return f.markRows, f.markErr
		},
		now: func() time.Time { return f.now },
	}
}

func assertWebhookDeadline(t *testing.T, ctx context.Context, maximum time.Duration) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining <= 0 || remaining > maximum+100*time.Millisecond || ctx.Err() != nil {
		t.Fatal("webhook operation lost its independent bounded context")
	}
}

func TestWebhookDependenciesRetryAndRecoverWithoutUnauthenticatedDispatch(t *testing.T) {
	for _, dependency := range []string{"endpoint", "event", "authenticated secret"} {
		t.Run(dependency, func(t *testing.T) {
			f := newWebhookDeliveryFixture()
			failure := errors.New("synthetic dependency outage with private provider text")
			code := webhookEndpointUnavailable
			switch dependency {
			case "endpoint":
				f.endpointErr = failure
			case "event":
				f.eventErr = failure
				code = webhookEventUnavailable
			case "authenticated secret":
				f.endpointErr = fmt.Errorf("authenticate synthetic ciphertext: %w", failure)
			}
			before := f.claim
			applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, f.dependencies(t))
			if err != nil || !applied || f.dispatchCalls != 0 || f.markCalls != 1 || !reflect.DeepEqual(before, f.claim) {
				t.Fatal("dependency outage dispatched or mutated its claim")
			}
			outcome := f.outcomes[0]
			if outcome.status != "retrying" || outcome.diagnostic != code || outcome.statusCode != 0 || !outcome.nextAttemptAt.Equal(f.now.Add(time.Minute)) {
				t.Fatal("dependency outage became terminal or lost first backoff")
			}
			f.endpointErr, f.eventErr = nil, nil
			f.now = outcome.nextAttemptAt
			f.claim.Attempts++
			f.claim.NextAttemptAt.Time = f.now.Add(5 * time.Minute)
			applied, err = processClaimedWebhookDelivery(context.Background(), &f.claim, f.dependencies(t))
			if err != nil || !applied || f.dispatchCalls != 1 || f.outcomes[1].status != "delivered" {
				t.Fatal("recovered dependency did not deliver once with a fresh claim")
			}
			want, _ := json.Marshal(f.event)
			got, _ := json.Marshal(f.dispatchedEvents[0])
			if string(got) != string(want) {
				t.Fatal("retry changed event or automation correlation bytes")
			}
		})
	}
}

func TestWebhookMissingDependenciesAndUnsafeSecretsNeverDispatch(t *testing.T) {
	for _, tc := range []struct {
		name, code, status    string
		endpointErr, eventErr error
		secret                string
	}{
		{name: "missing endpoint", code: webhookEndpointMissing, status: "failed", endpointErr: fmt.Errorf("lookup: %w", pgx.ErrNoRows)},
		{name: "missing event", code: webhookEventMissing, status: "failed", eventErr: fmt.Errorf("lookup: %w", pgx.ErrNoRows)},
		{name: "inactive endpoint", code: webhookEndpointInactive, status: "failed", endpointErr: webhooksecret.ErrEndpointInactive},
		{name: "empty secret", code: webhookSecretInvalid, status: "retrying"},
		{name: "weak secret", code: webhookSecretInvalid, status: "retrying", secret: strings.Repeat("a", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWebhookDeliveryFixture()
			f.endpointErr, f.eventErr = tc.endpointErr, tc.eventErr
			if tc.endpointErr == nil && tc.eventErr == nil {
				f.secret = tc.secret
			}
			applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, f.dependencies(t))
			if err != nil || !applied || f.dispatchCalls != 0 || len(f.outcomes) != 1 || f.outcomes[0].status != tc.status || f.outcomes[0].diagnostic != tc.code {
				t.Fatal("missing dependency or unauthenticated key reached dispatch")
			}
		})
	}
	for _, kind := range []string{"different event", "invalid org", "internal kind", "missing time"} {
		t.Run(kind, func(t *testing.T) {
			f := newWebhookDeliveryFixture()
			switch kind {
			case "different event":
				f.event.EventID = uuid.NewString()
			case "invalid org":
				f.event.OrgID = uuid.Nil.String()
			case "internal kind":
				f.event.Kind = "internal.synthetic"
			case "missing time":
				f.event.OccurredAt = time.Time{}
			}
			applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, f.dependencies(t))
			if err != nil || !applied || f.dispatchCalls != 0 || f.outcomes[0].diagnostic != webhookEventInvalid || f.outcomes[0].status != "failed" {
				t.Fatal("invalid event was dispatched")
			}
		})
	}
}

func TestWebhookDependencyFailuresUseBoundedBackoff(t *testing.T) {
	schedule := []time.Duration{time.Minute, 5 * time.Minute, 25 * time.Minute, 2 * time.Hour, 12 * time.Hour, 24 * time.Hour}
	for prior := 0; prior <= len(schedule); prior++ {
		t.Run(fmt.Sprintf("prior_%d", prior), func(t *testing.T) {
			f := newWebhookDeliveryFixture()
			f.claim.Attempts = int32(prior)
			f.endpointErr = errors.New("synthetic unavailable keyring")
			applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, f.dependencies(t))
			if err != nil || !applied || f.dispatchCalls != 0 || f.outcomes[0].diagnostic != webhookEndpointUnavailable {
				t.Fatal("dependency failure bypassed retry policy")
			}
			outcome := f.outcomes[0]
			if prior < len(schedule) {
				if outcome.status != "retrying" || !outcome.nextAttemptAt.Equal(f.now.Add(schedule[prior])) {
					t.Fatal("wrong retry delay")
				}
			} else if outcome.status != "failed" || !outcome.nextAttemptAt.IsZero() {
				t.Fatal("retry exhaustion remained unbounded")
			}
		})
	}
}

func TestWebhookClaimCannotDispatchAcrossEndpointTenant(t *testing.T) {
	for _, fault := range []string{"cross organization event", "missing endpoint org", "wrong endpoint identity"} {
		t.Run(fault, func(t *testing.T) {
			f := newWebhookDeliveryFixture()
			deps := f.dependencies(t)
			switch fault {
			case "cross organization event":
				f.event.OrgID = uuid.NewString()
			case "missing endpoint org":
				f.endpointOrgID = uuid.Nil
			case "wrong endpoint identity":
				base := deps.endpoint
				deps.endpoint = func(ctx context.Context, id uuid.UUID) (webhooksecret.DeliveryEndpoint, error) {
					endpoint, err := base(ctx, id)
					endpoint.ID = uuid.New()
					return endpoint, err
				}
			}
			before := f.claim
			applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, deps)
			if err != nil || !applied || f.dispatchCalls != 0 || f.markCalls != 1 || !reflect.DeepEqual(before, f.claim) {
				t.Fatal("unowned endpoint/event reached dispatch or mutated claim")
			}
			if outcome := f.outcomes[0]; outcome.status != "failed" || outcome.diagnostic != webhookEventInvalid || outcome.statusCode != 0 {
				t.Fatal("cross-tenant admission did not produce the fixed terminal refusal")
			}
		})
	}
}

func TestWebhookProviderDiagnosticsAreRedacted(t *testing.T) {
	privateText := "synthetic-private-token https://private.example.invalid/account?secret=synthetic"
	for _, tc := range []struct {
		name, code     string
		result         dispatch.DispatchResult
		expectedStatus int32
	}{
		{"transport", webhookTransportUnavailable, dispatch.DispatchResult{Err: errors.New(privateText), Body: privateText}, 0},
		{"http", webhookHTTPRefused, dispatch.DispatchResult{Status: 503, Body: privateText}, 503},
		{"invalid status", webhookHTTPRefused, dispatch.DispatchResult{Status: 1000000, Body: privateText}, 0},
		{"cancelled DNS", webhookTransportUnavailable, dispatch.DispatchResult{Err: context.DeadlineExceeded, Body: privateText}, 0},
		{"success", "", dispatch.DispatchResult{Status: 204, Body: privateText}, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWebhookDeliveryFixture()
			f.result = tc.result
			applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, f.dependencies(t))
			if err != nil || !applied || f.dispatchCalls != 1 || f.outcomes[0].diagnostic != tc.code || f.outcomes[0].statusCode != tc.expectedStatus {
				t.Fatal("provider diagnostics escaped their fixed code contract")
			}
			if strings.Contains(fmt.Sprintf("%+v", f.outcomes[0]), privateText) {
				t.Fatal("persisted private provider text")
			}
		})
	}
}

func TestWebhookClaimFenceAndCancellationLeaveNaturalExpiry(t *testing.T) {
	t.Run("expired before dependencies", func(t *testing.T) {
		f := newWebhookDeliveryFixture()
		f.claim.NextAttemptAt.Time = f.now.Add(2 * time.Second)
		applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, f.dependencies(t))
		if err != nil || applied || f.endpointCalls+f.eventCalls+f.dispatchCalls+f.markCalls != 0 {
			t.Fatal("stale claim reached external work")
		}
	})
	t.Run("superseded at checkpoint", func(t *testing.T) {
		f := newWebhookDeliveryFixture()
		f.markRows = 0
		before := f.claim
		applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, f.dependencies(t))
		if err != nil || applied || f.markCalls != 1 || f.dispatchCalls != 1 || !reflect.DeepEqual(f.markedClaims[0], before) || !reflect.DeepEqual(f.claim, before) {
			t.Fatal("stale checkpoint retried an unfenced overwrite")
		}
	})
	t.Run("checkpoint outage", func(t *testing.T) {
		f := newWebhookDeliveryFixture()
		f.markErr = errors.New("synthetic database connection with private values")
		before := f.claim
		applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, f.dependencies(t))
		if !errors.Is(err, f.markErr) || applied || f.markCalls != 1 || !reflect.DeepEqual(f.claim, before) {
			t.Fatal("checkpoint outage changed claim or bypassed SQL")
		}
	})
	t.Run("cancelled before work", func(t *testing.T) {
		f := newWebhookDeliveryFixture()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		applied, err := processClaimedWebhookDelivery(ctx, &f.claim, f.dependencies(t))
		if !errors.Is(err, context.Canceled) || applied || f.endpointCalls+f.markCalls != 0 {
			t.Fatal("cancelled pass acknowledged a claim")
		}
	})
	t.Run("cancelled after network", func(t *testing.T) {
		f := newWebhookDeliveryFixture()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		deps := f.dependencies(t)
		deps.dispatch = func(context.Context, string, string, dispatch.WebhookEvent) dispatch.DispatchResult {
			f.dispatchCalls++
			cancel()
			return dispatch.DispatchResult{Status: 204}
		}
		applied, err := processClaimedWebhookDelivery(ctx, &f.claim, deps)
		if !errors.Is(err, context.Canceled) || applied || f.markCalls != 0 || f.dispatchCalls != 1 {
			t.Fatal("cancelled network attempt used a background acknowledgement")
		}
	})
	t.Run("lease expires during network", func(t *testing.T) {
		f := newWebhookDeliveryFixture()
		deps := f.dependencies(t)
		deps.dispatch = func(context.Context, string, string, dispatch.WebhookEvent) dispatch.DispatchResult {
			f.now = f.now.Add(6 * time.Minute)
			return dispatch.DispatchResult{Status: 204}
		}
		applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, deps)
		if err != nil || applied || f.markCalls != 0 {
			t.Fatal("expired lease attempted a checkpoint")
		}
	})
}

func TestWebhookOperationDeadlinesAndIndependentMarkWindow(t *testing.T) {
	f := newWebhookDeliveryFixture()
	deps := f.dependencies(t)
	var dispatchCtx context.Context
	deps.dispatch = func(ctx context.Context, _ string, _ string, _ dispatch.WebhookEvent) dispatch.DispatchResult {
		assertWebhookDeadline(t, ctx, webhookDispatchTimeout)
		dispatchCtx = ctx
		return dispatch.DispatchResult{Err: context.DeadlineExceeded}
	}
	baseMark := deps.mark
	deps.mark = func(ctx context.Context, claim *generated.WebhookDelivery, outcome webhookDeliveryOutcome) (int64, error) {
		if dispatchCtx == nil || dispatchCtx.Err() == nil || ctx.Err() != nil {
			t.Fatal("checkpoint inherited spent dispatch context")
		}
		return baseMark(ctx, claim, outcome)
	}
	applied, err := processClaimedWebhookDelivery(context.Background(), &f.claim, deps)
	if err != nil || !applied || f.outcomes[0].diagnostic != webhookTransportUnavailable {
		t.Fatal("deadline failure could not checkpoint within independent window")
	}
}

func TestWebhookDrainClaimsJustInTimeAndIsBounded(t *testing.T) {
	claims, attempts := 0, 0
	fakeNow := time.Now().UTC()
	firstLease := fakeNow.Add(5 * time.Minute)
	err := drainWebhookDeliveries(context.Background(), webhookDrainLimit, func(ctx context.Context) (*generated.WebhookDelivery, error) {
		assertWebhookDeadline(t, ctx, webhookReadTimeout)
		if claims != attempts {
			t.Fatal("delivery leased ahead of preceding network attempt")
		}
		claims++
		return &generated.WebhookDelivery{NextAttemptAt: pgtype.Timestamptz{Time: fakeNow.Add(5 * time.Minute), Valid: true}}, nil
	}, func(_ context.Context, claim *generated.WebhookDelivery) error {
		if !claim.NextAttemptAt.Time.Equal(fakeNow.Add(5 * time.Minute)) {
			t.Fatal("dispatch inherited old batch lease")
		}
		fakeNow = fakeNow.Add(15 * time.Second)
		attempts++
		return nil
	})
	if err != nil || claims != 50 || attempts != 50 || !fakeNow.After(firstLease) {
		t.Fatal("drain was not bounded or did not model the old batch lease failure")
	}
}

func TestWebhookDrainStopsOnCancellationOrPersistenceFailure(t *testing.T) {
	for _, tc := range []string{"empty", "cancelled", "cancelled after first attempt", "checkpoint failure", "claim failure", "nil claim", "invalid limit"} {
		t.Run(tc, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, attempts, limit := 0, 0, webhookDrainLimit
			failure := errors.New("synthetic persistence outage")
			if tc == "cancelled" {
				cancel()
			}
			if tc == "invalid limit" {
				limit++
			}
			err := drainWebhookDeliveries(ctx, limit, func(context.Context) (*generated.WebhookDelivery, error) {
				calls++
				if tc == "empty" {
					return nil, pgx.ErrNoRows
				}
				if tc == "claim failure" {
					return nil, failure
				}
				if tc == "nil claim" {
					return nil, nil
				}
				return &generated.WebhookDelivery{}, nil
			}, func(context.Context, *generated.WebhookDelivery) error {
				attempts++
				if tc == "cancelled after first attempt" {
					cancel()
					return nil
				}
				return failure
			})
			switch tc {
			case "empty":
				if err != nil || calls != 1 || attempts != 0 {
					t.Fatal("empty queue was not normal completion")
				}
			case "cancelled":
				if !errors.Is(err, context.Canceled) || calls != 0 {
					t.Fatal("cancelled drain claimed work")
				}
			case "cancelled after first attempt":
				if !errors.Is(err, context.Canceled) || calls != 1 || attempts != 1 {
					t.Fatal("drain claimed another delivery after pass cancellation")
				}
			case "invalid limit":
				if err == nil || calls != 0 {
					t.Fatal("invalid bound performed claims")
				}
			case "checkpoint failure":
				if !errors.Is(err, failure) || calls != 1 || attempts != 1 {
					t.Fatal("persistence outage leased more deliveries")
				}
			case "claim failure":
				if !errors.Is(err, failure) || calls != 1 || attempts != 0 {
					t.Fatal("claim outage attempted network")
				}
			case "nil claim":
				if err == nil || calls != 1 || attempts != 0 {
					t.Fatal("nil claim reached network")
				}
			}
		})
	}
}
