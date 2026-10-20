// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"
)

// These explicit in-memory control-gate fixtures exercise the actual process
// dispatch gate. They supply no SQL, observer, grant or physical-retirement
// evidence. The real browser/PostgreSQL journey remains separately required.
func processProbeGateFixtureV1() (*applicationSessionFactoryStateV1, *applicationSessionOrganisationV1, *applicationOwnedSessionV1) {
	p := &applicationSessionFactoryStateV1{sessions: make(map[*applicationOwnedSessionV1]struct{})}
	o := &applicationSessionOrganisationV1{factory: p, processControl: true}
	s := applicationSessionNewOwnerV1(o, [16]byte{}, false)
	s.closed, s.retiring = true, 1
	p.sessions[s] = struct{}{}
	return p, o, s
}

func TestProcessProbeWaitsForOriginalCloseBeforeDispatchV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, o, old := processProbeGateFixtureV1()
	type result struct {
		s   *applicationOwnedSessionV1
		err error
	}
	started, done := make(chan struct{}), make(chan result, 1)
	// Holding the original owner mutex lets us observe the selector holding
	// p.mu at that exact gate, before any retirement state is advanced.
	old.mu.Lock()
	p.mu.Lock()
	go func() {
		close(started)
		s, err := applicationSignerProbeOwnerV1(ctx, p, o)
		done <- result{s, err}
	}()
	<-started
	p.mu.Unlock()
	for p.mu.TryLock() {
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			old.mu.Unlock()
			t.Fatal("selector never reached the original owner gate")
		case <-time.After(time.Millisecond):
		}
	}
	old.mu.Unlock()
	select {
	case r := <-done:
		t.Fatalf("active original close was refused or bypassed: owner=%v err=%v", r.s != nil, r.err)
	case <-time.After(25 * time.Millisecond):
	}
	p.mu.Lock()
	if len(p.sessions) != 1 {
		t.Error("gate allocated before the original close joined")
	}
	p.mu.Unlock()
	old.mu.Lock()
	old.retired = true
	applicationSessionSignalV1(old)
	old.mu.Unlock()
	select {
	case r := <-done:
		t.Fatalf("retired flag bypassed the actual close-return gate: %v", r.err)
	case <-time.After(25 * time.Millisecond):
	}
	// Model the original Close's completed map cleanup and returned continuation,
	// exactly as the existing control-state close-join tests; no SQL is credited.
	p.mu.Lock()
	delete(p.sessions, old)
	old.mu.Lock()
	old.retiring = 0
	applicationSessionSignalV1(old)
	old.mu.Unlock()
	p.mu.Unlock()
	select {
	case r := <-done:
		if r.err != nil || r.s == nil || r.s == old || r.s.organisation != o || r.s.dialed || r.s.retired {
			t.Fatalf("joined gate did not register one unstarted process owner: %v", r.err)
		}
		p.mu.Lock()
		_, present := p.sessions[r.s]
		if len(p.sessions) != 1 || !present || o.observer != nil {
			t.Error("gate changed observer or owner accounting")
		}
		p.mu.Unlock()
	case <-ctx.Done():
		t.Fatal("joined process dispatch did not return")
	}
}

func TestProcessProbeDispatchPreservesQuarantineAndBoundsV1(t *testing.T) {
	for _, name := range []string{"unknown", "ended", "deadline", "closing", "full"} {
		t.Run(name, func(t *testing.T) {
			p, o, old := processProbeGateFixtureV1()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			want := ErrApplicationSessionUnknownV1
			switch name {
			case "unknown":
				old.unknown = true
			case "ended":
				old.retiring = 0
			case "deadline":
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 15*time.Millisecond)
				defer stop()
			case "closing":
				p.closing = true
				want = ErrApplicationSessionV1
			case "full":
				old.closed, old.retiring = false, 0
				for len(p.sessions) < applicationSessionMaxWorkV1 {
					p.sessions[applicationSessionNewOwnerV1(o, [16]byte{}, false)] = struct{}{}
				}
				want = ErrApplicationSessionV1
			}
			before := len(p.sessions)
			owner, err := applicationSignerProbeOwnerV1(ctx, p, o)
			if owner != nil || !errors.Is(err, want) || (name == "deadline" && !errors.Is(err, context.DeadlineExceeded)) {
				t.Fatalf("original refusal/deadline changed: owner=%v err=%v", owner != nil, err)
			}
			if len(p.sessions) != before || old.retired || o.observer != nil {
				t.Fatal("refusal manufactured retirement, owner or observer")
			}
		})
	}
}

func TestProcessProbeDoesNotJoinUnrelatedOwnerV1(t *testing.T) {
	p, o, old := processProbeGateFixtureV1()
	old.organisation = &applicationSessionOrganisationV1{factory: p}
	old.unknown = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	owner, err := applicationSignerProbeOwnerV1(ctx, p, o)
	if err != nil || owner == nil || owner == old || owner.organisation != o || old.retired || !old.unknown || len(p.sessions) != 2 || o.observer != nil {
		t.Fatalf("unrelated owner was joined, credited or altered: %v", err)
	}
}
