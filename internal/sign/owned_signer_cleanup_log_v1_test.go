// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// These are explicit bookkeeping/invariant-failure controls. An absent native
// reader is never a physical SQL retirement fixture or successful-close proof.
// The cached publication error exercises the original joined-error path without
// adding a production fault adapter. Real native fault qualification stays open.
type signerCleanupLogRecord436 struct {
	level         slog.Level
	body          string
	attrs         []slog.Attr
	leaseUnlocked bool
}

type signerCleanupLogSink436 struct {
	mu        sync.Mutex
	lease     *signerReadLeaseV1
	records   []signerCleanupLogRecord436
	started   chan struct{}
	release   chan struct{}
	blockOnce sync.Once
}

func (*signerCleanupLogSink436) Enabled(context.Context, slog.Level) bool { return true }
func (h *signerCleanupLogSink436) Handle(_ context.Context, r slog.Record) error {
	entry := signerCleanupLogRecord436{level: r.Level, body: r.Message}
	if h.lease.mu.TryLock() {
		entry.leaseUnlocked = true
		h.lease.mu.Unlock()
	}
	r.Attrs(func(a slog.Attr) bool { entry.attrs = append(entry.attrs, a); return true })
	h.mu.Lock()
	h.records = append(h.records, entry)
	h.mu.Unlock()
	if h.started != nil {
		h.blockOnce.Do(func() { close(h.started); <-h.release })
	}
	return nil
}
func (h *signerCleanupLogSink436) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *signerCleanupLogSink436) WithGroup(string) slog.Handler      { return h }
func (h *signerCleanupLogSink436) snapshot() []signerCleanupLogRecord436 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]signerCleanupLogRecord436(nil), h.records...)
}
func installSignerCleanupLog436(t *testing.T, lease *signerReadLeaseV1) *signerCleanupLogSink436 {
	t.Helper()
	sink := &signerCleanupLogSink436{lease: lease}
	previous := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return sink
}
func assertSignerCleanupLog436(t *testing.T, sink *signerCleanupLogSink436, count int) {
	t.Helper()
	rows := sink.snapshot()
	if len(rows) != count {
		t.Fatal("unexpected final cleanup log count")
	}
	for _, row := range rows {
		if row.level != slog.LevelError || row.body != "owned signer read cleanup failed" || !row.leaseUnlocked || len(row.attrs) != 2 {
			t.Fatal("cleanup log level/body/attribute count or mutex boundary changed")
		}
		for i, want := range []struct{ key, value string }{{"operation", "signing"}, {"outcome", "unavailable"}} {
			if row.attrs[i].Key != want.key || row.attrs[i].Value.Kind() != slog.KindString || row.attrs[i].Value.String() != want.value {
				t.Fatal("cleanup log exported a nonclosed attribute")
			}
		}
	}
}
func cachedSignerPublicationFailure436(err error) *ownedHistoricalFinalizationPublicationV1 {
	publication := &ownedHistoricalFinalizationPublicationV1{err: err}
	publication.once.Do(func() {}) // Explicit previously completed synthetic failure.
	return publication
}

func TestSignerFinalCleanupFailureLogPrivacyV1(t *testing.T) {
	private := errors.New("private-token-436 https://private.invalid/document customer@example.invalid")
	lease := &signerReadLeaseV1{historicalPublication: cachedSignerPublicationFailure436(private)}
	sink := installSignerCleanupLog436(t, lease)
	result := lease.closeV1()
	if !errors.Is(result, private) || !errors.Is(result, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("joined publication and missing-reader errors were not preserved")
	}
	if !strings.Contains(result.Error(), private.Error()) {
		t.Fatal("caller error was scrubbed or replaced")
	}
	assertSignerCleanupLog436(t, sink, 1)
	for _, row := range sink.snapshot() {
		if strings.Contains(row.body, private.Error()) {
			t.Fatal("private failure entered log body")
		}
		for _, a := range row.attrs {
			if strings.Contains(a.Value.String(), private.Error()) {
				t.Fatal("private failure entered log attributes")
			}
		}
	}
}

func TestSignerFinalCleanupFailureConcurrentRetriesLogOnceV1(t *testing.T) {
	lease := &signerReadLeaseV1{}
	sink := installSignerCleanupLog436(t, lease)
	sink.started, sink.release = make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(sink.release) }) }
	first, firstDone, retries := make(chan error, 1), make(chan struct{}), make(chan struct{})
	retriesStarted := false
	t.Cleanup(func() {
		unblock()
		select {
		case <-firstDone:
		case <-time.After(2 * time.Second):
			t.Error("first cleanup call remained unjoined")
		}
		if retriesStarted {
			select {
			case <-retries:
			case <-time.After(2 * time.Second):
				t.Error("cleanup retry calls remained unjoined")
			}
		}
	})
	go func() { defer close(firstDone); first <- lease.closeV1() }()
	select {
	case <-sink.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first final failure did not enter logger")
	}
	var joined sync.WaitGroup
	retriesStarted = true
	joined.Add(32)
	for i := 0; i < 32; i++ {
		go func() {
			defer joined.Done()
			if !errors.Is(lease.closeV1(), ErrSigningAdmissionUnavailableV1) {
				t.Error("retry changed cleanup failure")
			}
		}()
	}
	go func() { joined.Wait(); close(retries) }()
	select {
	case <-retries:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup retries could not join while logger held its own consumer")
	}
	select {
	case <-first:
		t.Fatal("test logger did not retain the first reporting call")
	default:
	}
	assertSignerCleanupLog436(t, sink, 1)
	unblock()
	select {
	case err := <-first:
		if !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
			t.Fatal("first close failure changed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reporting close did not join")
	}
	if !errors.Is(lease.closeV1(), ErrSigningAdmissionUnavailableV1) {
		t.Fatal("later retry falsely reported successful native cleanup")
	}
	assertSignerCleanupLog436(t, sink, 1)
}

func TestSignerSoftPendingCleanupDoesNotLogFinalFailureV1(t *testing.T) {
	for _, state := range []struct {
		name      string
		borrowers int
		running   bool
	}{{"borrower", 1, false}, {"cleanup_running", 0, true}} {
		t.Run(state.name, func(t *testing.T) {
			private := errors.New("retained-private-publication-436")
			publication := cachedSignerPublicationFailure436(private)
			lease := &signerReadLeaseV1{borrowers: state.borrowers, cleanupRunning: state.running, historicalPublication: publication}
			sink := installSignerCleanupLog436(t, lease)
			if !errors.Is(lease.closeV1(), ErrSigningAdmissionUnavailableV1) {
				t.Fatal("soft pending close changed its original refusal")
			}
			if lease.historicalPublication != publication || lease.cleanupFailureReported || lease.borrowers != state.borrowers || lease.cleanupRunning != state.running {
				t.Fatal("soft pending close consumed ownership or claimed a final attempt")
			}
			assertSignerCleanupLog436(t, sink, 0)
		})
	}
}

func TestSignerLastBorrowerReportsDiscardedFinalCleanupFailureV1(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	lease := &signerReadLeaseV1{issuer: f.engine, mode: pdfadmission.SignerReadActiveV1, scope: &pdfadmission.ApplicationSignerScopeV1{}, original: cloneSignerReadContextV1(rc)}
	rc.readLease = lease
	sink := installSignerCleanupLog436(t, lease)
	_, _, finish, err := lease.borrowOriginalV1(f.engine, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		t.Fatal("bookkeeping fixture could not borrow its original")
	}
	if !errors.Is(rc.CloseReadV1(), ErrSigningAdmissionUnavailableV1) {
		t.Fatal("live borrower did not retain its original refusal")
	}
	assertSignerCleanupLog436(t, sink, 0)
	finish()
	finish()
	if lease.borrowers != 0 || lease.original != nil {
		t.Fatal("original borrower did not retire exactly once")
	}
	assertSignerCleanupLog436(t, sink, 1)
	if !errors.Is(rc.CloseReadV1(), ErrSigningAdmissionUnavailableV1) {
		t.Fatal("missing native reader became successful cleanup")
	}
	assertSignerCleanupLog436(t, sink, 1)
}

func TestSignerCanceledPublicationFinalFailureStillLogsV1(t *testing.T) {
	// This is a cached failed publication outcome, not caller cancellation or
	// a real PG fault. The final failed result must not be hidden by Canceled.
	private := errors.New("private-canceled-publication-436")
	publicationErr := errors.Join(context.Canceled, private)
	lease := &signerReadLeaseV1{historicalPublication: cachedSignerPublicationFailure436(publicationErr)}
	sink := installSignerCleanupLog436(t, lease)
	result := lease.closeV1()
	if !errors.Is(result, context.Canceled) || !errors.Is(result, private) || !errors.Is(result, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("final cancellation/publication/reader outcomes changed")
	}
	assertSignerCleanupLog436(t, sink, 1)
}
