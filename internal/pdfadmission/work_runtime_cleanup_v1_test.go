// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func waitWorkRuntimeCleanupSignalV1(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(4*workRuntimeCleanupIntervalV1 + workRuntimeCleanupPassV1):
		t.Fatal(description)
	}
}

func TestWorkRuntimeCleanupPassDeadlineAndRetryV1(t *testing.T) {
	type observation struct {
		ctx      context.Context
		bounded  bool
		lifetime time.Duration
	}
	attempts := make(chan observation, 2)
	stop := startWorkRuntimeCleanupV1(func(ctx context.Context) error {
		deadline, bounded := ctx.Deadline()
		select {
		case attempts <- observation{ctx, bounded, time.Until(deadline)}:
		default:
		}
		<-ctx.Done()
		return errors.New("synthetic unresolved cleanup")
	})
	defer stop()
	read := func() observation {
		t.Helper()
		select {
		case observed := <-attempts:
			return observed
		case <-time.After(4*workRuntimeCleanupIntervalV1 + workRuntimeCleanupPassV1):
			t.Fatal("bounded cleanup error prevented the next scheduled pass")
			return observation{}
		}
	}
	first, second := read(), read()
	for _, observed := range []observation{first, second} {
		if !observed.bounded || observed.lifetime <= 0 || observed.lifetime > workRuntimeCleanupPassV1 {
			t.Fatal("cleanup pass lacked its own fixed positive deadline")
		}
	}
	if first.ctx == second.ctx || !errors.Is(first.ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("retry reused an expired pass context or ignored its deadline")
	}
}

func TestWorkRuntimeCleanupStopCancelsAndJoinsV1(t *testing.T) {
	entered := make(chan struct{}, 1)
	cancelled := make(chan error, 1)
	allowReturn := make(chan struct{})
	returned := make(chan struct{})
	var releaseOnce, returnedOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(allowReturn) }) }
	stop := startWorkRuntimeCleanupV1(func(ctx context.Context) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case cancelled <- ctx.Err():
		default:
		}
		<-allowReturn
		returnedOnce.Do(func() { close(returned) })
		return ctx.Err()
	})
	stopped := make(chan struct{})
	stopStarted := false
	defer func() {
		release()
		stop()
		if stopStarted {
			waitWorkRuntimeCleanupSignalV1(t, stopped, "stop caller did not join")
		}
	}()
	waitWorkRuntimeCleanupSignalV1(t, entered, "cleanup pass did not start")
	stopStarted = true
	go func() { stop(); close(stopped) }()
	select {
	case err := <-cancelled:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("stop did not cancel the live pass before its deadline")
		}
	case <-time.After(workRuntimeCleanupPassV1):
		t.Fatal("stop left the live pass context running")
	}
	select {
	case <-stopped:
		t.Fatal("stop returned before the in-flight pass actually returned")
	case <-time.After(25 * time.Millisecond):
	}
	release()
	waitWorkRuntimeCleanupSignalV1(t, stopped, "stop failed to join the released pass")
	select {
	case <-returned:
	default:
		t.Fatal("joined stop did not include callback completion")
	}
	var callers sync.WaitGroup
	for i := 0; i < 4; i++ {
		callers.Add(1)
		go func() { defer callers.Done(); stop() }()
	}
	idempotent := make(chan struct{})
	go func() { callers.Wait(); close(idempotent) }()
	waitWorkRuntimeCleanupSignalV1(t, idempotent, "repeated concurrent stops were not idempotent")
}

func TestWorkRuntimeCleanupPassesRemainSerialV1(t *testing.T) {
	entered := make(chan struct{})
	allowReturn := make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	var calls, active, peak atomic.Int32
	release := func() { releaseOnce.Do(func() { close(allowReturn) }) }
	stop := startWorkRuntimeCleanupV1(func(context.Context) error {
		calls.Add(1)
		n := active.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		defer active.Add(-1)
		enteredOnce.Do(func() { close(entered) })
		// Deliberately retain this callback beyond its context deadline. A
		// scheduler must join it, not spawn a replacement on the next tick.
		<-allowReturn
		return nil
	})
	defer func() { release(); stop() }()
	waitWorkRuntimeCleanupSignalV1(t, entered, "cleanup pass did not start")
	<-time.After(workRuntimeCleanupIntervalV1 + workRuntimeCleanupPassV1 + 100*time.Millisecond)
	if calls.Load() != 1 || active.Load() != 1 || peak.Load() != 1 {
		t.Fatal("another cleanup pass overlapped an unfinished pass")
	}
	release()
	stop()
	if active.Load() != 0 || peak.Load() != 1 {
		t.Fatal("stop left a callback running or allowed overlapping passes")
	}
}

func TestWorkRuntimeCleanupUsesActualFactoryAndPreservesUnknownV1(t *testing.T) {
	// Real offline pool/runtime/coordinator/factory; only the private owner
	// states are synthetic. No connection is dispatched and these assertions
	// are not physical backend-retirement or observer-replacement evidence.
	pool := workRuntimePoolTestV1(t, 2)
	runtime, err := NewWorkRuntimeV1(pool, workRuntimeLimitsTestV1(), 4)
	if err != nil {
		t.Fatal("construct actual offline runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	org := uuid.New()
	factory := runtime.SessionsV1().state
	organisation := &applicationSessionOrganisationV1{factory: factory, org: org, guard: make(chan struct{}, 1)}
	factory.organisations[org] = organisation
	var releases []func()
	stop := func() {}
	defer func() {
		stop()
		// These are the test's local vector loans, never dispatched SQL. Their
		// fixture disposal does not mark an unknown owner retired or proven.
		for _, release := range releases {
			release()
		}
	}()
	closedOwner := func() (*applicationOwnedSessionV1, <-chan struct{}) {
		t.Helper()
		release, err := runtime.WorkV1().SQLSessionV1(ctx, org)
		if err != nil {
			t.Fatal("fund synthetic closed owner through actual coordinator")
		}
		releases = append(releases, release)
		retired := make(chan struct{})
		var once sync.Once
		owner := applicationSessionNewOwnerV1(organisation, uuid.New(), false)
		owner.closed = true
		owner.grant = func() { once.Do(func() { release(); close(retired) }) }
		factory.mu.Lock()
		factory.sessions[owner] = struct{}{}
		factory.mu.Unlock()
		return owner, retired
	}
	first, firstRetired := closedOwner()
	unknownRelease, err := runtime.WorkV1().SQLSessionV1(ctx, org)
	if err != nil {
		t.Fatal("fund synthetic unproven owner through actual coordinator")
	}
	releases = append(releases, unknownRelease)
	var unknownCredited atomic.Bool
	unknown := applicationSessionNewOwnerV1(organisation, uuid.New(), false)
	unknown.closed, unknown.dialed, unknown.unknown, unknown.active = true, true, true, 1
	unknown.grant = func() { unknownCredited.Store(true); unknownRelease() }
	factory.sessions[unknown] = struct{}{}
	stop = runtime.StartCleanupV1()
	waitWorkRuntimeCleanupSignalV1(t, firstRetired, "background sweep did not retire eligible closed owner")
	// The grant callback precedes factory-map removal. Observe that actual
	// removal rather than treating the release notification as a joined pass.
	for {
		factory.mu.Lock()
		_, present := factory.sessions[first]
		factory.mu.Unlock()
		if !present {
			break
		}
		select {
		case <-time.After(5 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("retired owner remained registered")
		}
	}
	if snapshot := runtime.coordinator.SnapshotV1(org); snapshot.Global != (workguard.VectorV1{SQLSessions: 1}) || snapshot.Organisation != snapshot.Global || snapshot.GlobalGrants != 1 || snapshot.OrganisationGrants != 1 || unknownCredited.Load() || !(&ApplicationSessionV1{state: first}).RetiredV1() {
		t.Fatal("sweep credited active unknown ownership")
	}
	unknown.mu.Lock()
	unknown.active = 0
	unknown.mu.Unlock()
	second, secondRetired := closedOwner()
	waitWorkRuntimeCleanupSignalV1(t, secondRetired, "subsequent actual-factory sweep did not run")
	stop()
	factory.mu.Lock()
	_, secondPresent := factory.sessions[second]
	_, unknownPresent := factory.sessions[unknown]
	factory.mu.Unlock()
	if secondPresent || !(&ApplicationSessionV1{state: second}).RetiredV1() || !unknownPresent || unknownCredited.Load() || (&ApplicationSessionV1{state: unknown}).RetiredV1() {
		t.Fatal("sweep manufactured retirement for an unfenced unknown owner")
	}
	cleanup, finish := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer finish()
	if err := runtime.CloseV1(cleanup); !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatal("runtime close accepted unproven retirement")
	}
	if snapshot := runtime.coordinator.SnapshotV1(org); snapshot.Global != (workguard.VectorV1{SQLSessions: 1}) || snapshot.Organisation != snapshot.Global || snapshot.GlobalGrants != 1 || snapshot.OrganisationGrants != 1 || unknownCredited.Load() {
		t.Fatal("shutdown credited the retained unknown owner")
	}
}

func TestWorkRuntimeCleanupAbsentRuntimeIsNoOpV1(t *testing.T) {
	for _, runtime := range []*WorkRuntimeV1{nil, {}} {
		stop := runtime.StartCleanupV1()
		stop()
		stop()
		if runtime.WorkV1() != nil || runtime.SessionsV1() != nil {
			t.Fatal("absent runtime acquired work objects")
		}
	}
}
