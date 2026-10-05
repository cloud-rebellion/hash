// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"testing"
)

func TestEmailClaimsWaitForPreviousAttempt(t *testing.T) {
	claims, attempts := 0, 0
	err := dispatchClaimedEmails(context.Background(), func(_ context.Context, limit int32) ([]*generated.EmailDelivery, error) {
		if limit != 1 || claims != attempts {
			t.Fatal("messages leased ahead of sends")
		}
		claims++
		if claims > 3 {
			return nil, nil
		}
		return []*generated.EmailDelivery{{}}, nil
	}, func(context.Context, *generated.EmailDelivery) error { attempts++; return nil })
	if err != nil || claims != 4 || attempts != 3 {
		t.Fatalf("unexpected drain %d/%d %v", claims, attempts, err)
	}
}
func TestEmailClaimPassIsBoundedAndHonorsCancellation(t *testing.T) {
	count := 0
	claim := func(context.Context, int32) ([]*generated.EmailDelivery, error) {
		count++
		return []*generated.EmailDelivery{{}}, nil
	}
	if err := dispatchClaimedEmails(context.Background(), claim, func(context.Context, *generated.EmailDelivery) error { return nil }); err != nil || count != 50 {
		t.Fatalf("unbounded pass %d %v", count, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dispatchClaimedEmails(ctx, claim, func(context.Context, *generated.EmailDelivery) error { return nil }); err == nil || count != 50 {
		t.Fatal("claimed after cancellation")
	}
}

func TestEmailDrainStopsOnAcknowledgementFailure(t *testing.T) {
	failure := errors.New("acknowledgement unavailable")
	claims := 0
	err := dispatchClaimedEmails(context.Background(), func(context.Context, int32) ([]*generated.EmailDelivery, error) {
		claims++
		return []*generated.EmailDelivery{{}}, nil
	}, func(context.Context, *generated.EmailDelivery) error { return failure })
	if !errors.Is(err, failure) || claims != 1 {
		t.Fatalf("ack failure ignored: %d %v", claims, err)
	}
}
