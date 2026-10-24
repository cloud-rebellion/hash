// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package passwordhash

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestArgon2idPasswordRoundTrip(t *testing.T) {
	password := "a long exact password  "
	encoded, err := Hash(t.Context(), password)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, password) {
		t.Fatal("plaintext password retained")
	}
	for _, sample := range []struct {
		password string
		want     bool
	}{
		{password, true}, {"a long exact password", false}, {"different password", false},
	} {
		got, err := Verify(t.Context(), sample.password, encoded)
		if err != nil || got != sample.want {
			t.Fatalf("password verification=%t %v", got, err)
		}
	}
}

func TestArgon2idRejectsUnboundedOrNoncanonicalParameters(t *testing.T) {
	for _, encoded := range []string{
		strings.Replace(DummyHash, "m=65536", "m=4294967295", 1),
		strings.Replace(DummyHash, "t=3", "t=4294967295", 1),
		strings.Replace(DummyHash, "p=4", "p=0", 1),
		strings.Replace(DummyHash, "v=19", "v=16", 1),
		DummyHash + "=", strings.Replace(DummyHash, "p=4", "p=4junk", 1),
		strings.Repeat("A", 513),
	} {
		if _, err := Verify(t.Context(), "password", encoded); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("unsupported encoded parameters were accepted: %v", err)
		}
	}
}

func TestPasswordHashCancellationAndBoundedAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Hash(ctx, "password"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled hash=%v", err)
	}
	for i := 0; i < cap(slots); i++ {
		slots <- struct{}{}
	}
	for i := 0; i < cap(waiters); i++ {
		waiters <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(slots); i++ {
			<-slots
		}
		for i := 0; i < cap(waiters); i++ {
			<-waiters
		}
	}()
	if _, err := acquire(t.Context()); !errors.Is(err, ErrBusy) {
		t.Fatalf("unbounded password work admitted: %v", err)
	}
}
