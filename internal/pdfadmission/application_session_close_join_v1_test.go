// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNativeSessionCloseJoinRequiresActualRetirementV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Explicit in-memory control-gate fixture, not a SQL/backend retirement proof.
	s := &applicationOwnedSessionV1{changed: make(chan struct{}), closed: true, retiring: 1}
	done := make(chan error, 1)
	go func() { done <- applicationSessionWaitRetiringV1(ctx, s) }()
	select {
	case err := <-done:
		t.Fatalf("close activity inferred retirement: %v", err)
	case <-time.After(15 * time.Millisecond):
	}
	s.mu.Lock()
	s.retired = true
	applicationSessionSignalV1(s)
	s.mu.Unlock()
	select {
	case err := <-done:
		t.Fatalf("retired flag bypassed actual Close return/map cleanup: %v", err)
	case <-time.After(15 * time.Millisecond):
	}
	s.mu.Lock()
	s.retiring = 0
	applicationSessionSignalV1(s)
	s.mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("actual retirement did not join")
	}
}
func TestNativeSessionCloseJoinRefusesUnknownEndedAndCancellationV1(t *testing.T) {
	for name, s := range map[string]*applicationOwnedSessionV1{
		"unknown":       {changed: make(chan struct{}), closed: true, unknown: true, retiring: 1},
		"ended attempt": {changed: make(chan struct{}), closed: true},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := applicationSessionWaitRetiringV1(ctx, s); !errors.Is(err, ErrApplicationSessionUnknownV1) {
				t.Fatalf("unjoined debt accepted: %v", err)
			}
			if s.retired {
				t.Fatal("gate manufactured retirement")
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	s := &applicationOwnedSessionV1{changed: make(chan struct{}), closed: true, retiring: 1}
	if err := applicationSessionWaitRetiringV1(ctx, s); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatalf("caller deadline lost: %v", err)
	}
	if s.retired {
		t.Fatal("deadline manufactured retirement")
	}
}
func TestNativeObserverReadinessJoinsExistingProbeGateV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// The closed factory makes the eventual readiness result deterministic and
	// prevents any network. The occupied real guard represents an active fixed
	// observer probe; readiness must join it before inspecting/starting anything.
	o := &applicationSessionOrganisationV1{factory: &applicationSessionFactoryStateV1{closing: true}, guard: make(chan struct{}, 1)}
	o.guard <- struct{}{}
	done := make(chan error, 1)
	go func() { done <- o.ensureObserverV1(ctx) }()
	select {
	case err := <-done:
		t.Fatalf("readiness bypassed actual observer gate: %v", err)
	case <-time.After(15 * time.Millisecond):
	}
	<-o.guard
	select {
	case err := <-done:
		if !errors.Is(err, ErrApplicationSessionV1) {
			t.Fatalf("original closed-factory refusal changed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("observer join did not finish")
	}
	if o.observer != nil {
		t.Fatal("gate created a replacement observer")
	}
}
