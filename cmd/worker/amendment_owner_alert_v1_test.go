// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"testing"
)

type ownerAlertCounter483 struct{ calls int }

func (m *ownerAlertCounter483) Send(context.Context, dispatch.Message) error { m.calls++; return nil }
func TestOwnerAlert483UnavailableFreshCheckPreventsSMTP(t *testing.T) {
	mail := &ownerAlertCounter483{}
	w := &worker{emailSender: mail}
	row := &generated.EmailDelivery{ID: uuid.New(), ToEmail: "owner@example.test", HeadersJson: []byte(dispatch.AmendmentOwnerAlertHeadersJSONV1)}
	out, e := w.attemptEmailObserved(context.Background(), row)
	if e == nil || out != emailCheckpointFailed || mail.calls != 0 {
		t.Fatal("unavailable native authority reached SMTP")
	}
}
