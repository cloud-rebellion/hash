// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitselect

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestSelectionV1CommitsBeforeRetentionAndReadsStableOriginal(t *testing.T) {
	service, request, sql, objects := setupSelectionV1(t)
	objects.beforeRetain = func(n int) {
		sql.mu.Lock()
		defer sql.mu.Unlock()
		if sql.row == nil || !sql.row.RetentionStartedAt.Valid || sql.row.RetentionCompletedAt.Valid {
			t.Fatal("irreversible retention preceded durable start")
		}
	}
	selected, err := service.SelectV1(context.Background(), request)
	if err != nil || selected == nil || selected.ID() == uuid.Nil {
		t.Fatalf("selected: %v", err)
	}
	if sql.row == nil || !sql.row.RetentionCompletedAt.Valid || len(objects.retained) != 3 {
		t.Fatal("full retained set not committed")
	}
	for _, until := range objects.until {
		if until != selected.RetentionFloor() {
			t.Fatal("retention target was regenerated")
		}
	}
	if selected.ManifestObject() != request.Manifest || selected.Binding() != request.Binding {
		t.Fatal("selection substituted pins")
	}
	objects.beforeRetain = nil
	// A different preparation for the same authority must resume the original,
	// not consume its supplied manifest or make any new retained object.
	competing := request
	competing.Binding.OperationID = uuid.New()
	competing.Manifest.VersionID = "nonexistent candidate"
	competing.OwnerID = uuid.New()
	again, err := service.SelectV1(context.Background(), competing)
	if err != nil || again.ID() != selected.ID() || again.Binding() != selected.Binding() || len(objects.retained) != 3 {
		t.Fatalf("stable duplicate: %v", err)
	}
	raw := selected.Retained().SpanBytes()
	raw[0] ^= 1
	if !bytes.Equal(again.Retained().SpanBytes(), selected.Retained().SpanBytes()) {
		t.Fatal("selected accessor aliased archive bytes")
	}
}
func TestSelectionV1UnknownCommitFreshSQLReconciliation(t *testing.T) {
	for _, phase := range []struct {
		name string
		at   int
	}{{"attempt checkpoint", 1}, {"selection", 2}, {"retention start", 3}, {"retention complete", 4}} {
		t.Run(phase.name, func(t *testing.T) {
			service, request, sql, objects := setupSelectionV1(t)
			sql.failCommitAt = phase.at
			selected, err := service.SelectV1(context.Background(), request)
			if err != nil || selected == nil || sql.row == nil || !sql.row.RetentionCompletedAt.Valid || len(objects.retained) != 3 {
				t.Fatalf("lost successful COMMIT: %v", err)
			}
			if sql.sessions < 6 {
				t.Fatal("uncertain COMMIT reused original session")
			}
			if strings.Contains(errStringV1(err), "PRIVATE") {
				t.Fatal("SQL details escaped")
			}
		})
	}
}
func TestSelectionV1UnknownRollbackAndNegativeSQLCheckpoint(t *testing.T) {
	service, request, sql, objects := setupSelectionV1(t)
	sql.rollbackCommitAt = 2
	selected, err := service.SelectV1(context.Background(), request)
	if selected != nil || !errors.Is(err, ErrNotSelectedV1) || sql.row != nil || !sql.state.Preparation.SelectionNotCommittedAt.Valid || len(objects.retained) != 0 {
		t.Fatalf("unknown rollback was not safely closed: %v", err)
	}
	// Negative reconciliation is not storage cleanup: all original objects stay.
	if len(objects.blobs) != 3 {
		t.Fatal("uncertainty compensated storage")
	}
	service, request, sql, objects = setupSelectionV1(t)
	sql.failCommitAt = 2
	sql.failBeginAt = 4
	selected, err = service.SelectV1(context.Background(), request)
	if selected != nil || !errors.Is(err, ErrOutcomeUnknownV1) || sql.row == nil || len(objects.retained) != 0 {
		t.Fatalf("unavailable fresh SQL claimed result: %v", err)
	}
	sql.failBeginAt = 0
	sql.failCommitAt = 0
	selected, err = service.ResumeV1(context.Background(), request.Binding)
	if err != nil || selected == nil || len(objects.retained) != 3 {
		t.Fatalf("fresh independent resume: %v", err)
	}
}
func TestSelectionV1PartialRetentionAndPostIOAuthorityDrift(t *testing.T) {
	service, request, sql, objects := setupSelectionV1(t)
	objects.failAt = 2
	selected, err := service.SelectV1(context.Background(), request)
	if selected != nil || !errors.Is(err, ErrRetentionPendingV1) || sql.row == nil || !sql.row.RetentionStartedAt.Valid || sql.row.RetentionCompletedAt.Valid || len(objects.retained) != 2 || strings.Contains(errStringV1(err), "PRIVATE") {
		t.Fatalf("partial retention published success: %v", err)
	}
	if len(objects.blobs) != 3 {
		t.Fatal("partial WORM compensated")
	}
	objects.failAt = 0
	selected, err = service.ResumeV1(context.Background(), request.Binding)
	if err != nil || selected == nil || len(objects.retained) != 5 || !sql.row.RetentionCompletedAt.Valid {
		t.Fatalf("exact retained retry: %v", err)
	}
	service, request, sql, objects = setupSelectionV1(t)
	objects.beforeRetain = func(n int) {
		if n == 3 {
			sql.mu.Lock()
			sql.state.AllFields[1].Page = 2
			sql.mu.Unlock()
		}
	}
	selected, err = service.SelectV1(context.Background(), request)
	if selected != nil || !errors.Is(err, ErrAuthorityChangedV1) || sql.row.RetentionCompletedAt.Valid || len(objects.retained) != 3 {
		t.Fatalf("changed authority admitted after retention: %v", err)
	}
}
func TestSelectionV1OriginalPolicyAndCancellationNoRetention(t *testing.T) {
	for _, mode := range []string{"no permission", "wrong target", "fractional target", "callback canceled", "expired credential", "mutated callback snapshot"} {
		t.Run(mode, func(t *testing.T) {
			service, request, sql, objects := setupSelectionV1(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			service.Admit = func(ctx context.Context, state LockedStateV1) (AdmissionV1, error) {
				b, e := AdmitArchiveBudgetV1(state, testEntriesV1(state))
				if e != nil {
					return AdmissionV1{}, e
				}
				floor := retentionFloor(state.Preparation.CeremonyEpoch.Time)
				switch mode {
				case "no permission":
					return AdmissionV1{}, nil
				case "wrong target":
					floor = floor.Add(time.Second)
				case "fractional target":
					floor = floor.Add(time.Nanosecond)
				case "callback canceled":
					cancel()
				case "expired credential":
					return AdmissionV1{}, errors.New("credential expired PRIVATE")
				case "mutated callback snapshot":
					state.Document.PdfStorageVersionID.String = "other"
				}
				return AuthorizeV1(b, floor)
			}
			selected, err := service.SelectV1(ctx, request)
			if selected != nil || err == nil || sql.row != nil || len(objects.retained) != 0 || strings.Contains(errStringV1(err), "PRIVATE") {
				t.Fatalf("denial retained/published: %v", err)
			}
			if mode == "callback canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation cause lost")
			}
		})
	}
}
func TestSelectionV1CancellationAfterUnknownCommitDoesNotRestart(t *testing.T) {
	service, request, sql, objects := setupSelectionV1(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service.Admit = func(ctx context.Context, state LockedStateV1) (AdmissionV1, error) {
		a, e := testAdmissionV1(ctx, state)
		if sql.commits == 1 {
			cancel()
		}
		return a, e
	}
	selected, err := service.SelectV1(ctx, request)
	if selected != nil || !errors.Is(err, context.Canceled) || sql.row != nil || len(objects.retained) != 0 {
		t.Fatalf("canceled final guard retained: %v", err)
	}
	// A fresh caller can see the attempted checkpoint, but no negative checkpoint
	// was guessed from the canceled observation. No retry-render or storage PUT API
	// exists on this service.
	if !sql.state.Preparation.SelectionCommitAttemptedAt.Valid || sql.state.Preparation.SelectionNotCommittedAt.Valid {
		t.Fatal("cancellation guessed SQL absence")
	}
}
func TestSelectionV1ConcurrentDuplicateCeremonyRetainsSamePins(t *testing.T) {
	service, request, sql, objects := setupSelectionV1(t)
	var wg sync.WaitGroup
	results := make(chan *SelectedV1, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, e := service.SelectV1(context.Background(), request)
			results <- result
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("duplicate race: %v", e)
		}
	}
	var winner uuid.UUID
	for result := range results {
		if result == nil {
			t.Fatal("missing result")
		}
		if winner == uuid.Nil {
			winner = result.ID()
		}
		if result.ID() != winner || result.ManifestObject() != request.Manifest {
			t.Fatal("race selected different exact set")
		}
	}
	if sql.row == nil || sql.row.ID != winner || !sql.row.RetentionCompletedAt.Valid {
		t.Fatal("race did not preserve stable selection")
	}
	for _, pin := range objects.retained {
		if pin.Key != request.Manifest.Key && pin.Key != strings.TrimSuffix(request.Manifest.Key, "manifest.json")+"span.html" && pin.Key != strings.TrimSuffix(request.Manifest.Key, "manifest.json")+"page-1.fit" {
			t.Fatal("race created another object set")
		}
	}
}
func TestSelectionV1RejectsAllTargetAndSourceGeometryDrift(t *testing.T) {
	for _, mode := range []string{"source version", "source digest", "unoccupied geometry", "second target coordinates", "target omission", "target addition", "target recipient", "optional target", "extra object", "unverified version", "shadow object", "row source bytes", "epoch", "foreign row", "budget reservation"} {
		t.Run(mode, func(t *testing.T) {
			service, request, sql, objects := setupSelectionV1(t)
			switch mode {
			case "source version":
				sql.state.Document.PdfStorageVersionID.String = "changed"
			case "source digest":
				sql.state.Document.PdfSha256[0] ^= 1
			case "unoccupied geometry":
				sql.state.Preparation.GeometrySha256[0] ^= 1
			case "second target coordinates":
				_ = sql.state.AllFields[1].XPct.Scan("5.0001")
			case "target omission":
				sql.state.AllFields = sql.state.AllFields[:1]
			case "target addition":
				f := *sql.state.AllFields[0]
				f.ID = uuid.New()
				sql.state.AllFields = append(sql.state.AllFields, &f)
			case "target recipient":
				sql.state.AllFields[1].RecipientID.Bytes = uuid.New()
			case "optional target":
				sql.state.AllFields[1].Required = false
			case "extra object":
				o := *sql.state.Objects[0]
				o.Kind = "other"
				sql.state.Objects = append(sql.state.Objects, &o)
			case "unverified version":
				sql.state.Objects[1].ReadbackVerifiedAt.Valid = false
			case "shadow object":
				sql.state.Objects[1].VersionID.String = "latest"
			case "row source bytes":
				sql.state.Preparation.SourceBytes++
			case "epoch":
				sql.state.Document.Article13NoticeEpochAt.Time = sql.state.Document.Article13NoticeEpochAt.Time.Add(time.Microsecond)
			case "foreign row":
				sql.state.Preparation.OrgID = uuid.New()
			case "budget reservation":
				sql.state.Preparation.ReservedBytes = 1
			}
			result, e := service.SelectV1(context.Background(), request)
			if result != nil || !errors.Is(e, ErrAuthorityChangedV1) || sql.row != nil || len(objects.retained) != 0 {
				t.Fatalf("drift admitted: %v", e)
			}
		})
	}
}
func TestArchiveBudgetV1IncludesUnpublishedUnknownAndZIPOverhead(t *testing.T) {
	_, _, sql, _ := setupSelectionV1(t)
	state := cloneStateV1(sql.state)
	proof, e := AdmitArchiveBudgetV1(state, testEntriesV1(state))
	if e != nil || proof.UpperBoundBytes() <= state.Document.SignatureFitReservedBytes+2200164 {
		t.Fatalf("ZIP overhead omitted: %v", e)
	}
	prior := proof.UpperBoundBytes()
	op := uuid.New()
	state.Inventory = append(state.Inventory, &generated.ListSignatureFitInventoryRow{PreparationID: op, RecipientID: uuid.New(), Status: "staging", ExpectedObjects: 3, ReservedBytes: 4 << 20, UploadAttemptedAt: timestamp(time.Now()), OwnerID: uuid.New()})
	state.Document.SignatureFitReservedBytes += 4 << 20
	next, e := AdmitArchiveBudgetV1(state, testEntriesV1(state))
	if e != nil || next.UpperBoundBytes() <= prior+(4<<20) {
		t.Fatal("unpublished/unknown inventory or reserved headers omitted")
	}
	if proof.matches(state) {
		t.Fatal("stale proof reused after inventory/reservation change")
	}
	state.Document.SignatureFitReservedBytes = manualfit.MaxEvidenceBytesV1 - 1
	if _, e = AdmitArchiveBudgetV1(state, testEntriesV1(state)); e == nil {
		t.Fatal("fit-only cap was claimed whole ZIP admission")
	}
	state = cloneStateV1(sql.state)
	for _, mode := range []string{"missing essential", "duplicate entry", "traversal", "oversized entry", "private unlisted future PDF"} {
		entries := testEntriesV1(state)
		switch mode {
		case "missing essential":
			entries = entries[:5]
		case "duplicate entry":
			entries = append(entries, entries[0])
		case "traversal":
			entries[0].Name = "../source.pdf"
		case "oversized entry":
			entries[1].Bytes = manualfit.MaxEvidenceBytesV1
		case "private unlisted future PDF":
			entries[1].Bytes = 0
		}
		if _, e = AdmitArchiveBudgetV1(state, entries); e == nil {
			t.Fatalf("invalid complete export proof %s", mode)
		}
	}
	state.Inventory[0].VersionID = pgtype.Text{String: " another opaque version ", Valid: true}
	if proof.matches(state) {
		t.Fatal("inventory exact-version drift ignored")
	}
}
func TestRetentionFloorV1MatchesCanonicalWholeSeconds(t *testing.T) {
	exact := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	fractional := exact.Add(123456 * time.Nanosecond)
	if want := time.Date(2033, 10, 11, 12, 0, 0, 0, time.UTC); retentionFloor(exact) != want {
		t.Fatal("whole second floor gained unnecessary second")
	}
	if retentionFloor(fractional) != retentionFloor(exact).Add(time.Second) {
		t.Fatal("fractional floor rounded down")
	}
}
func errStringV1(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var _ = generated.Document{}

func TestSelectionV1PreservesPrivateDistinctCancellationCause(t *testing.T) {
	service, request, _, objects := setupSelectionV1(t)
	cause := errors.New("PRIVATE_CALLER_CANCELLATION_REASON")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	_, e := service.SelectV1(ctx, request)
	if !errors.Is(e, context.Canceled) || !errors.Is(e, cause) || strings.Contains(errStringV1(e), "PRIVATE") || len(objects.retained) != 0 {
		t.Fatalf("distinct cancellation was lost or leaked: %v", e)
	}
	unknownErr := unknown(ctx, nil)
	if !errors.Is(unknownErr, ErrOutcomeUnknownV1) || !errors.Is(unknownErr, cause) || strings.Contains(unknownErr.Error(), "PRIVATE") {
		t.Fatal("unknown outcome lost private cancellation identity")
	}
}
func TestArchiveBudgetV1ExactKnownSourceNearLimit(t *testing.T) {
	_, _, sql, _ := setupSelectionV1(t)
	state := cloneStateV1(sql.state)
	entries := testEntriesV1(state)
	// The fit reservations leave a narrow residual space. A fabricated one-byte
	// source would make the entire ZIP appear admitted unless known source size
	// participates independently of the caller proposal.
	state.Preparation.SourceBytes = 50 << 20
	state.Document.SignatureFitReservedBytes = 110 << 20
	unknownDebt := &generated.ListSignatureFitInventoryRow{
		PreparationID: uuid.New(), RecipientID: uuid.New(), Status: "staging", ExpectedObjects: 3,
		ReservedBytes: state.Document.SignatureFitReservedBytes - state.Preparation.ReservedBytes,
	}
	state.Inventory = append(state.Inventory, unknownDebt)
	entries[0].Bytes = 1
	if _, e := AdmitArchiveBudgetV1(state, entries); e == nil {
		t.Fatal("one-byte source understated authoritative source near160MiB")
	}
	entries[0].Bytes = state.Preparation.SourceBytes
	if _, e := AdmitArchiveBudgetV1(state, entries); e == nil {
		t.Fatal("exact source plus all fit reservations and ZIP overhead exceeded160MiB")
	}
	// A coherent lower reservation is the positive control: the rejection above
	// must exercise the actual aggregate cap rather than counter inconsistency.
	state.Document.SignatureFitReservedBytes = 100 << 20
	unknownDebt.ReservedBytes = state.Document.SignatureFitReservedBytes - state.Preparation.ReservedBytes
	if _, e := AdmitArchiveBudgetV1(state, entries); e != nil {
		t.Fatal("coherent source plus debt below archive cap was refused", e)
	}
}

func TestUnknownV1FiltersPrivateTransportCancellation(t *testing.T) {
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		e := unknown(context.Background(), errors.Join(sentinel, errors.New("PRIVATE_TRANSPORT_DETAIL")))
		if !errors.Is(e, ErrOutcomeUnknownV1) || !errors.Is(e, sentinel) || strings.Contains(e.Error(), "PRIVATE") {
			t.Fatalf("provider cancellation was lost or leaked: %v", e)
		}
	}
}

func TestSelectionV1WinnerAppearsAfterInitialLookup(t *testing.T) {
	service, request, sql, objects := setupSelectionV1(t)
	winner := uuid.New()
	sql.beginHook = func(n int, s *memoryStoreV1) {
		if n == 2 {
			other := &memoryTxV1{s: s, state: cloneStateV1(s.state)}
			other.state.Preparation.SelectionCommitAttemptedAt = timestamp(time.Now())
			if _, e := other.Select(context.Background(), request, winner); e != nil {
				t.Fatal(e)
			}
			s.state = other.state
			s.row = other.row
		}
	}
	result, e := service.SelectV1(context.Background(), request)
	if e != nil || result == nil || result.ID() != winner || len(objects.retained) != 3 {
		t.Fatalf("winner after initial lookup was denied or replaced: %v", e)
	}
}
