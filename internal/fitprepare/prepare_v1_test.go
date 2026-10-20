// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

func TestPrepareV1DurableAllPagesAndReadOnlyRestart(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 2)
	prepared, err := f.preparer.Prepare(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Binding().OperationID != f.request.OperationID || prepared.Binding().AuthoritySHA256 != f.request.Authority.SHA256() || len(prepared.Manifest().Pages()) != 2 || len(f.renderer.calls) != 2 || f.inspector.fragments != 2 || f.journal.operation.Status != "prepared" {
		t.Fatal("complete all-page protocol absent")
	}
	if prepared.Manifest().AggregateBytes() >= f.journal.operation.ReservedBytes {
		t.Fatal("fixture must leave conservative ceiling unused")
	}
	for _, n := range f.objects.puts {
		if n != 1 {
			t.Fatal("repeated SDK PUT")
		}
	}
	// A restart has no renderer, original span, font bundle or captured page bytes.
	f.preparer.Renderer = nil
	f.request.Span = nil
	f.request.LeaseUntil = time.Time{}
	beforePuts := len(f.objects.events)
	beforeJournal := len(f.journal.events)
	first := prepared.ManifestObject()
	again, err := f.preparer.Prepare(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	if again.ManifestObject() != first || !bytes.Equal(again.Manifest().CanonicalJSON(), prepared.Manifest().CanonicalJSON()) {
		t.Fatal("restart replaced selected bytes")
	}
	for _, event := range f.objects.events[beforePuts:] {
		if strings.HasPrefix(event, "put:") || strings.HasPrefix(event, "resolve:") {
			t.Fatal("prepared restart mutated storage")
		}
	}
	for _, event := range f.journal.events[beforeJournal:] {
		if event != "get" && event != "objects" {
			t.Fatal("prepared restart mutated SQL inventory")
		}
	}
	copied := again.Manifest().Pages()
	copied[0].Package.VersionID = "changed"
	if again.Manifest().Pages()[0].Package.VersionID == "changed" {
		t.Fatal("mutable prepared accessor")
	}
}

func TestPrepareV1EveryFrozenFontPreservesOriginalName(t *testing.T) {
	for _, file := range []string{"v1-case-1.fit", "v1-case-3.fit", "v1-case-5.fit", "v1-case-7.fit", "v1-case-9.fit"} {
		t.Run(file, func(t *testing.T) {
			f := protocolFixtureV1(t, file, 1)
			prepared, err := f.preparer.Prepare(context.Background(), f.request)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.Manifest().Authority().Input().TypedName != f.request.Authority.Input().TypedName || prepared.Manifest().Authority().Input().Font != f.request.Authority.Input().Font || len(prepared.Manifest().Authority().Input().TypedName) != len(f.request.Authority.Input().TypedName) {
				t.Fatal("original name/font changed")
			}
		})
	}
}

func TestPrepareV1UnknownUploadPositiveRecoveryNeverRendersAgain(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	f.objects.failPutKind = "page"
	f.objects.commitUnknownPut = true
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("unknown result incorrectly handled: %v", err)
	}
	originalCalls := len(f.renderer.calls)
	f.preparer.Renderer = nil
	prepared, err := f.preparer.Prepare(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.renderer.calls) != originalCalls || prepared.Manifest().Pages()[0].Package.VersionID == "" {
		t.Fatal("recovery rerendered or lost exact version")
	}
	for _, n := range f.objects.puts {
		if n != 1 {
			t.Fatal("recovery repeated original PUT")
		}
	}
}

func TestPrepareV1UnknownUploadEmptyHistoryStaysPending(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	f.objects.failPutKind = "page"
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
		t.Fatal(err)
	}
	f.preparer.Renderer = nil
	for j := 0; j < 3; j++ {
		if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
			t.Fatalf("empty history became permission: %v", err)
		}
	}
	if len(f.renderer.calls) != 1 || f.objects.puts[manualfit.ObjectPrefixV1(f.request.OperationID, f.request.Authority.Input().OrgID, f.request.Authority.Input().DocumentID)+"page-1.fit"] != 1 || f.journal.operation.Status != "staging" {
		t.Fatal("pending upload was rewritten, abandoned or rerendered")
	}
}

func TestPrepareV1UnknownCommittedCheckpointsRecoverExactBytes(t *testing.T) {
	for _, point := range []string{"reserve", "object:span:0", "pin:span:0", "verified:span:0", "object:page:1", "pin:page:1", "verified:page:1", "object:manifest:0", "pin:manifest:0", "verified:manifest:0", "prepared"} {
		t.Run(point, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			f.journal.failAfter = point
			if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
				t.Fatalf("ambiguous checkpoint: %v", err)
			}
			// A page reserved before its upload requires exact original captured bytes;
			// no renderer determinism or silently reconstructed replacement is claimed.
			f.request.OriginalPayloads = map[ObjectIDV1][]byte{{"page", 1}: f.renderer.packages[1].Bytes()}
			prepared, err := f.preparer.Prepare(context.Background(), f.request)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.Binding().OperationID != f.request.OperationID {
				t.Fatal("recovery created another operation")
			}
			for _, n := range f.objects.puts {
				if n != 1 {
					t.Fatal("checkpoint recovery repeated PUT")
				}
			}
		})
	}
}

func TestPrepareV1UnknownAttemptCommitDoesNotAuthorizePut(t *testing.T) {
	for _, kind := range []string{"span", "page", "manifest"} {
		t.Run(kind, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			page := int32(0)
			if kind == "page" {
				page = 1
			}
			f.journal.failAfter = checkpointNameV1("attempt", kind, page)
			if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
				t.Fatal(err)
			}
			row := f.journal.objects[ObjectIDV1{kind, page}]
			if row == nil || !row.UploadAttemptedAt.Valid || f.objects.puts[row.StorageKey] != 0 {
				t.Fatal("unknown SQL attempt dispatched PUT")
			}
			if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) || f.objects.puts[row.StorageKey] != 0 {
				t.Fatal("restart inferred unknown attempt was safe to retry")
			}
		})
	}
}

func TestPrepareV1ReservedUnattemptedPageRequiresMatchingOriginalPayload(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	f.journal.failAfter = "object:page:1"
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
		t.Fatal(err)
	}
	calls := len(f.renderer.calls)
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrOriginalPayloadV1) || len(f.renderer.calls) != calls {
		t.Fatal("reserved page was regenerated")
	}
	raw := f.renderer.packages[1].Bytes()
	raw[len(raw)-1] ^= 1
	f.request.OriginalPayloads = map[ObjectIDV1][]byte{{"page", 1}: raw}
	if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil || len(f.renderer.calls) != calls {
		t.Fatal("different original payload accepted")
	}
	f.request.OriginalPayloads = map[ObjectIDV1][]byte{{"page", 1}: f.renderer.packages[1].Bytes()}
	if _, err := f.preparer.Prepare(context.Background(), f.request); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareV1ExpiredLeaseTakeoverPreservesOriginalUploader(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	f.objects.failPutKind = "page"
	f.objects.commitUnknownPut = true
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
		t.Fatal(err)
	}
	row := f.journal.objects[ObjectIDV1{"page", 1}]
	originalOwner := row.UploadOwnerID
	newOwner := uuid.New()
	f.request.OwnerID = newOwner
	f.request.TakeoverExpiredLease = true
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrLeaseV1) {
		t.Fatal("active owner was stolen")
	}
	f.journal.operation.LeaseUntil = timestampV1(time.Now().Add(-time.Second))
	f.request.LeaseUntil = time.Now().Add(time.Hour).Truncate(time.Microsecond)
	f.preparer.Renderer = nil
	prepared, err := f.preparer.Prepare(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil || f.journal.operation.OwnerID != newOwner || f.journal.operation.Attempts != 2 || f.journal.objects[ObjectIDV1{"page", 1}].UploadOwnerID != originalOwner {
		t.Fatal("original upload ownership or takeover attempt changed")
	}
}

func TestPrepareV1AdmissionAndBudgetBeforeEffects(t *testing.T) {
	for _, mode := range []string{"missing", "denied", "ZIP-overflow", "processing-overflow", "zero-source-admission"} {
		t.Run(mode, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			switch mode {
			case "missing":
				f.request.Admission = nil
			case "denied":
				f.request.Admission = func(context.Context, *manualfit.AuthorityV1) (BudgetV1, error) {
					return BudgetV1{}, errors.New("PRIVATE_CREDENTIAL_DETAIL")
				}
			case "ZIP-overflow":
				f.budget.EvidenceOtherBytes = manualfit.MaxEvidenceBytesV1
			case "processing-overflow":
				f.budget.ProcessingOtherBytes = sanitize.MaxPDFBytes
			case "zero-source-admission":
				f.budget.EvidenceOtherBytes = 0
			}
			if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unsafe admission result")
			}
			if f.journal.operation != nil || len(f.objects.events) != 0 || len(f.renderer.calls) != 0 {
				t.Fatal("admission denial caused an effect")
			}
		})
	}
}

func TestPrepareV1ActualFitAndProcessingCeilingsBeforePageUpload(t *testing.T) {
	for _, mode := range []string{"fit-ceiling", "processing-ceiling"} {
		t.Run(mode, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			if mode == "fit-ceiling" {
				f.budget.FitBytes = int64(len(f.request.Span)) + 1
			} else {
				pdf := f.renderer.packages[1].PDF()
				f.budget.ProcessingOtherBytes = sanitize.MaxPDFBytes - int64(len(pdf)) + 1
			}
			if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrBudgetV1) {
				t.Fatal(err)
			}
			key := manualfit.ObjectPrefixV1(f.request.OperationID, f.request.Authority.Input().OrgID, f.request.Authority.Input().DocumentID) + "page-1.fit"
			if f.objects.puts[key] != 0 {
				t.Fatal("page upload preceded actual byte admission")
			}
		})
	}
}

func TestPrepareV1PreparedRecoveryRequiresOriginalSourceAndAllPages(t *testing.T) {
	for _, mode := range []string{"source-bytes", "source-geometry", "omitted-page", "foreign-object", "empty-version", "unversioned"} {
		t.Run(mode, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 2)
			if _, err := f.preparer.Prepare(context.Background(), f.request); err != nil {
				t.Fatal(err)
			}
			f.preparer.Renderer = nil
			f.request.Span = nil
			switch mode {
			case "source-bytes":
				f.objects.sourceRaw[0] = 'x'
			case "source-geometry":
				f.inspector.geometry.Pages = append([]sanitize.PDFManualPage(nil), f.inspector.geometry.Pages...)
				f.inspector.geometry.Pages[1].Rotation = 90
			case "omitted-page":
				delete(f.journal.objects, ObjectIDV1{"page", 2})
			case "foreign-object":
				f.journal.objects[ObjectIDV1{"page", 2}].PreparationID = uuid.New()
			case "empty-version":
				f.journal.objects[ObjectIDV1{"page", 2}].VersionID.String = ""
			case "unversioned":
				f.journal.objects[ObjectIDV1{"page", 2}].VersionID.String = " null "
			}
			if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil {
				t.Fatal("partial or changed original archive recovered")
			}
		})
	}
}

func TestPrepareV1CancellationPreservesCauseAndNoEffects(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.preparer.Prepare(ctx, f.request); !errors.Is(err, context.Canceled) || len(f.journal.events) != 0 || len(f.objects.events) != 0 {
		t.Fatal("canceled invocation dispatched work or lost cause")
	}
	f = protocolFixtureV1(t, "v1-case-1.fit", 1)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	f.objects.readHook = func(key string, raw []byte) ([]byte, error) { cancel(); return raw, nil }
	if _, err := f.preparer.Prepare(ctx, f.request); !errors.Is(err, context.Canceled) || len(f.objects.puts) != 0 || f.journal.operation.Status != "staging" {
		t.Fatal("canceled source read continued the saga")
	}
}

func TestPrepareV1PrivateCancellationCauseBeforeAdmission(t *testing.T) {
	for _, mode := range []string{"canceled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			privateCause := errors.New("PRIVATE_CALLER_CANCELLATION_DETAIL")
			var ctx context.Context
			var cancel context.CancelFunc
			want := error(context.Canceled)
			if mode == "deadline" {
				ctx, cancel = context.WithDeadlineCause(context.Background(), time.Now().Add(-time.Second), privateCause)
				want = context.DeadlineExceeded
			} else {
				canceled, cancelCause := context.WithCancelCause(context.Background())
				cancelCause(privateCause)
				ctx = canceled
				cancel = func() { cancelCause(nil) }
			}
			defer cancel()
			prepared, err := f.preparer.Prepare(ctx, f.request)
			if prepared != nil || !errors.Is(err, ErrPreparationV1) || !errors.Is(err, want) || !errors.Is(err, privateCause) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("private cancellation identity or sanitization lost: %v", err)
			}
			if len(f.journal.events) != 0 || len(f.objects.events) != 0 || len(f.renderer.calls) != 0 {
				t.Fatal("canceled invocation reached durable or provider work")
			}
		})
	}
}

func TestPrepareV1PrivateCancellationCauseDuringAdmission(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	privateCause := errors.New("PRIVATE_ADMISSION_CANCEL_DETAIL")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	f.request.Admission = func(context.Context, *manualfit.AuthorityV1) (BudgetV1, error) {
		cancel(privateCause)
		return BudgetV1{}, errors.New("PRIVATE_ADMISSION_PROVIDER_DETAIL")
	}
	prepared, err := f.preparer.Prepare(ctx, f.request)
	if prepared != nil || !errors.Is(err, ErrPreparationV1) || !errors.Is(err, context.Canceled) || !errors.Is(err, privateCause) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("admission cancellation identity or sanitization lost: %v", err)
	}
	if len(f.journal.events) != 0 || len(f.objects.events) != 0 || len(f.renderer.calls) != 0 {
		t.Fatal("canceled admission dispatched further work")
	}
}

type cancellationInspectorV1 struct {
	InspectorV1
	sourceCalls int
}

func (i *cancellationInspectorV1) Source(ctx context.Context, raw []byte) (sanitize.PDFManualGeometry, error) {
	i.sourceCalls++
	return i.InspectorV1.Source(ctx, raw)
}

func TestPrepareV1PrivateCancellationCauseDuringSourceRead(t *testing.T) {
	for _, mode := range []string{"acknowledged", "provider-error"} {
		t.Run(mode, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			privateCause := errors.New("PRIVATE_SOURCE_CANCEL_DETAIL")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			inspector := &cancellationInspectorV1{InspectorV1: f.inspector}
			f.preparer.Inspector = inspector
			f.objects.readHook = func(key string, raw []byte) ([]byte, error) {
				cancel(privateCause)
				if mode == "provider-error" {
					clear(raw)
					return nil, errors.New("PRIVATE_SOURCE_PROVIDER_DETAIL")
				}
				return raw, nil
			}
			prepared, err := f.preparer.Prepare(ctx, f.request)
			if prepared != nil || !errors.Is(err, ErrPreparationV1) || !errors.Is(err, context.Canceled) || !errors.Is(err, privateCause) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("source cancellation identity or sanitization lost: %v", err)
			}
			if f.journal.operation == nil || f.journal.operation.Status != "staging" || len(f.objects.events) != 1 || len(f.objects.puts) != 0 || len(f.renderer.calls) != 0 || inspector.sourceCalls != 0 {
				t.Fatal("canceled exact source read advanced to inspection or upload")
			}
		})
	}
}

type cancellationObjectsV1 struct {
	ObjectsV1
	cancel context.CancelCauseFunc
	cause  error
}

func (o cancellationObjectsV1) PutFitTransientReserved(ctx context.Context, r storage.FitTransientReservation, raw []byte) (storage.StoredObject, error) {
	stored, err := o.ObjectsV1.PutFitTransientReserved(ctx, r, raw)
	if err != nil {
		return stored, err
	}
	o.cancel(o.cause)
	return stored, errors.New("PRIVATE_COMMITTED_PUT_RESPONSE_DETAIL")
}

func TestPrepareV1PrivateCancellationCauseAfterCommittedPutRemainsUncertain(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	privateCause := errors.New("PRIVATE_PUT_CANCEL_DETAIL")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	f.preparer.Objects = cancellationObjectsV1{ObjectsV1: f.objects, cancel: cancel, cause: privateCause}
	prepared, err := f.preparer.Prepare(ctx, f.request)
	if prepared != nil || !errors.Is(err, ErrPreparationV1) || !errors.Is(err, ErrUncertainIOV1) || !errors.Is(err, context.Canceled) || !errors.Is(err, privateCause) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("uncertain PUT cancellation identity or sanitization lost: %v", err)
	}
	row := f.journal.objects[ObjectIDV1{"span", 0}]
	if row == nil || !row.UploadAttemptedAt.Valid || row.VersionID.Valid || row.ReadbackVerifiedAt.Valid || f.objects.puts[row.StorageKey] != 1 || len(f.objects.blobs) != 1 || len(f.renderer.calls) != 0 || f.journal.operation.Status != "staging" {
		t.Fatal("canceled committed PUT was published, retried or forgotten")
	}
}

func TestPrepareV1AttemptLimitAndTypedNilDependencies(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	f.objects.failPutKind = "page"
	if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil {
		t.Fatal("fixture did not stop")
	}
	f.journal.operation.Attempts = 8
	f.journal.operation.LeaseUntil = timestampV1(time.Now().Add(-time.Second))
	f.request.TakeoverExpiredLease = true
	f.request.LeaseUntil = time.Now().Add(time.Hour).Truncate(time.Microsecond)
	if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil || f.journal.operation.Attempts != 8 {
		t.Fatal("bounded attempt limit exceeded")
	}
	f = protocolFixtureV1(t, "v1-case-1.fit", 1)
	f.preparer.Journal = (*SQLJournalV1)(nil)
	if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil {
		t.Fatal("typed nil journal accepted")
	}
}

func TestPrepareV1InvalidOriginalSpanBeforeIO(t *testing.T) {
	for _, mode := range []string{"active", "wrong-name", "wrong-font", "trailing-node"} {
		t.Run(mode, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			in := f.request.Authority.Input()
			geometry := f.request.Authority.Geometry()
			switch mode {
			case "active":
				f.request.Span = []byte("<span class=\"hash-signature\" data-font=\"Caveat\" onclick=\"alert(1)\">" + in.TypedName + "</span>")
			case "wrong-name":
				f.request.Span = []byte("<span class=\"hash-signature\" data-font=\"Caveat\">different</span>")
			case "wrong-font":
				f.request.Span = bytes.ReplaceAll(f.request.Span, []byte(in.Font), []byte("Great Vibes"))
			case "trailing-node":
				f.request.Span = append(bytes.Clone(f.request.Span), []byte("<script>alert(1)</script>")...)
			}
			// Even a matching caller-supplied digest cannot turn active/mismatched HTML
			// into an admitted original archived signature span.
			in.SpanSHA256 = digestV1(f.request.Span)
			authority, err := manualfit.BuildAuthorityV1(in, geometry)
			if err != nil {
				t.Fatal(err)
			}
			f.request.Authority = authority
			f.request.Admission = func(context.Context, *manualfit.AuthorityV1) (BudgetV1, error) { return f.budget, nil }
			if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrIdentityV1) {
				t.Fatal(err)
			}
			if len(f.journal.events) != 0 || len(f.objects.events) != 0 || len(f.renderer.calls) != 0 {
				t.Fatal("invalid original span reached SQL/provider/renderer")
			}
		})
	}
}
