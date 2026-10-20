//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
)

// Sender comment authorization, canonical actor, late expiry, internal SQL
// failure and missing-document journeys migrated to the genuine native HTTP
// and typed engine fixtures in comment_{policy,credentials}_native_v1_e2e_test.
// Those fixtures retain the actual WorkRuntime, original session and measured
// audit/outbox ownership. The old ordinary-pool fixture cannot prove them.
type senderCommentDeliverySpy struct{ calls atomic.Int32 }

func (s *senderCommentDeliverySpy) Send(context.Context, dispatch.Message) error {
	s.calls.Add(1)
	return nil
}

// Compatibility methods must never become an alternate ordinary writer. This
// is solely a dependency-free refusal test, not current comment acceptance.
func TestRetiredRawCommentMethodsCannotWriteE2E(t *testing.T) {
	for _, name := range []string{"signer", "sender", "guarded-sender"} {
		t.Run(name, func(t *testing.T) {
			spy := &senderCommentDeliverySpy{}
			e := &sign.Engine{Mailer: spy}
			guardCalled := false
			guard := func(context.Context, *generated.User) error {
				guardCalled = true
				return auth.ErrMutationPermissionRevoked
			}
			var row *generated.DocumentComment
			var err error
			switch name {
			case "signer":
				row, err = e.SignerComment(context.Background(), nil, "Valid retired compatibility declaration", sign.ParticipantResponseEvidence{})
			case "sender":
				row, err = e.SenderComment(context.Background(), uuid.Nil, uuid.Nil, uuid.Nil, "Untrusted author", "Valid retired compatibility declaration")
			case "guarded-sender":
				row, err = e.SenderCommentWithAuthorization(context.Background(), uuid.Nil, uuid.Nil, uuid.Nil, "Untrusted author", "Valid retired compatibility declaration", guard)
			}
			if row != nil || !errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) || spy.calls.Load() != 0 || guardCalled {
				t.Fatal("retired raw compatibility method reached a dependency or alternate writer", name, err)
			}
		})
	}
}
