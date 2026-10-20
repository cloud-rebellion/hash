// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/jackc/pgx/v5"
)

// These tests reuse the explicitly synthetic, metadata-rebound protocol fixture.
// They prove dispatch/recovery/resource-lease behavior only, not real SQL commits,
// renderer fitting, worker isolation, S3/WORM, authorization or active Sign.
type originalsFixtureV1 struct {
	journal           *journalFixtureV1
	authority         *manualfit.AuthorityV1
	bodies            map[ObjectIDV1][]byte
	keys              map[ObjectIDV1]string
	mimes             map[ObjectIDV1]string
	reserveCalls      int
	authorityCalls    int
	captures          map[ObjectIDV1]int
	loads             map[ObjectIDV1]int
	failCapture       ObjectIDV1
	failCaptureOnce   bool
	authorityError    error
	authorityOverride *manualfit.AuthorityV1
	loadErrors        map[ObjectIDV1]error
	authorityHook     func()
	loadHook          func(ObjectIDV1)
	captureHook       func(ObjectIDV1)
	activeAuthority   int
	activeBodies      int
	bodyLeases        []*OriginalPayloadV1
	bodyViews         [][]byte
	authorityLeases   []*OriginalAuthorityV1
}

func attachOriginalsV1(f *preparationFixtureV1) *originalsFixtureV1 {
	o := &originalsFixtureV1{journal: f.journal, bodies: make(map[ObjectIDV1][]byte), keys: make(map[ObjectIDV1]string), mimes: make(map[ObjectIDV1]string), captures: make(map[ObjectIDV1]int), loads: make(map[ObjectIDV1]int), loadErrors: make(map[ObjectIDV1]error)}
	f.preparer.Originals = o
	return o
}

func (o *originalsFixtureV1) Reserve(ctx context.Context, arg generated.ReserveSignatureFitPreparationParams, a *manualfit.AuthorityV1, span []byte) (*generated.SignatureFitPreparation, error) {
	o.reserveCalls++
	row, err := o.journal.Reserve(ctx, arg)
	if o.journal.operation != nil && o.journal.operation.ID == arg.ID {
		captured, decodeErr := manualfit.DecodeAuthorityV1(a.CanonicalJSON())
		if decodeErr != nil {
			return nil, decodeErr
		}
		o.authority = captured
		id := ObjectIDV1{Kind: "span", Page: 0}
		o.bodies[id] = bytes.Clone(span)
		o.keys[id] = manualfit.ObjectPrefixV1(arg.ID, arg.OrgID, arg.DocumentID) + "span.html"
		o.mimes[id] = "text/html"
	}
	return row, err
}

func (o *originalsFixtureV1) Authority(ctx context.Context, row *generated.SignatureFitPreparation) (*OriginalAuthorityV1, error) {
	o.authorityCalls++
	if row == nil || o.journal.operation == nil || row.ID != o.journal.operation.ID || o.authority == nil {
		return nil, pgx.ErrNoRows
	}
	a := o.authority
	if o.authorityOverride != nil {
		a = o.authorityOverride
	}
	o.activeAuthority++
	lease := &OriginalAuthorityV1{authority: a, release: func() { o.activeAuthority-- }}
	o.authorityLeases = append(o.authorityLeases, lease)
	if o.authorityHook != nil {
		o.authorityHook()
	}
	return lease, o.authorityError
}

func (o *originalsFixtureV1) Capture(ctx context.Context, row *generated.SignatureFitPreparation, id ObjectIDV1, key, mime string, raw []byte) error {
	o.captures[id]++
	if o.activeAuthority != 0 || row == nil || o.journal.operation == nil || row.ID != o.journal.operation.ID || row.Status != "staging" {
		return ErrIdentityV1
	}
	wantKey, wantMIME, cap, ok := objectLayoutV1(id, manualfit.ObjectPrefixV1(row.ID, row.OrgID, row.DocumentID))
	if !ok || key != wantKey || mime != wantMIME || len(raw) == 0 || int64(len(raw)) > cap {
		return ErrOriginalPayloadV1
	}
	if prior, exists := o.bodies[id]; exists {
		if !bytes.Equal(prior, raw) || o.keys[id] != key || o.mimes[id] != mime {
			return ErrIdentityV1
		}
	} else {
		o.bodies[id] = bytes.Clone(raw)
		o.keys[id], o.mimes[id] = key, mime
	}
	if o.captureHook != nil {
		o.captureHook(id)
	}
	if o.failCaptureOnce && o.failCapture == id {
		o.failCaptureOnce = false
		return errors.New("PRIVATE_CAPTURE_ACK_DETAIL")
	}
	return nil
}

func (o *originalsFixtureV1) Load(ctx context.Context, row *generated.SignatureFitPreparation, id ObjectIDV1) (*OriginalPayloadV1, error) {
	o.loads[id]++
	if o.activeAuthority != 0 || o.activeBodies != 0 || row == nil || o.journal.operation == nil || row.ID != o.journal.operation.ID {
		return nil, ErrIdentityV1
	}
	if err := o.loadErrors[id]; err != nil {
		return nil, err
	}
	raw, ok := o.bodies[id]
	if !ok {
		return nil, pgx.ErrNoRows
	}
	o.activeBodies++
	view := bytes.Clone(raw)
	lease := &OriginalPayloadV1{body: view, release: func() { o.activeBodies-- }}
	o.bodyLeases = append(o.bodyLeases, lease)
	o.bodyViews = append(o.bodyViews, view)
	if o.loadHook != nil {
		o.loadHook(id)
	}
	return lease, nil
}

func (o *originalsFixtureV1) assertClosed(t *testing.T) {
	t.Helper()
	if o.activeAuthority != 0 || o.activeBodies != 0 {
		t.Fatal("original consumer resource hold leaked")
	}
	for _, lease := range o.authorityLeases {
		if lease.Authority() != nil {
			t.Fatal("authority lease remains reachable")
		}
		lease.Close()
	}
	for _, lease := range o.bodyLeases {
		if lease.Bytes() != nil {
			t.Fatal("body lease remains reachable")
		}
		lease.Close()
	}
	for _, view := range o.bodyViews {
		for _, b := range view {
			if b != 0 {
				t.Fatal("closed body was not cleared")
			}
		}
	}
	if o.activeAuthority != 0 || o.activeBodies != 0 {
		t.Fatal("Close released a resource twice")
	}
}

func originalCaptureCountV1(o *originalsFixtureV1) int {
	n := 0
	for _, v := range o.captures {
		n += v
	}
	return n
}
func originalLoadCountV1(o *originalsFixtureV1) int {
	n := 0
	for _, v := range o.loads {
		n += v
	}
	return n
}

func TestPrepareV1OriginalsAtomicAuthorityAndSpanBeforeProvider(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	o := attachOriginalsV1(f)
	originalSpan := bytes.Clone(f.request.Span)
	f.journal.failBefore = "objects"
	if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("missing bounded refusal")
	}
	if o.reserveCalls != 1 || o.authority == nil || o.authority.SHA256() != f.request.Authority.SHA256() || !bytes.Equal(o.bodies[ObjectIDV1{Kind: "span", Page: 0}], originalSpan) || len(f.objects.events) != 0 || len(f.renderer.calls) != 0 {
		t.Fatal("authority/span did not commit before provider IO")
	}
	o.assertClosed(t)
	f.request.Span = nil
	prepared, err := f.preparer.Prepare(context.Background(), f.request)
	if err != nil || prepared == nil || o.reserveCalls != 1 || prepared.Manifest().Authority().SHA256() != o.authority.SHA256() || !bytes.Equal(o.bodies[ObjectIDV1{Kind: "span", Page: 0}], originalSpan) {
		t.Fatalf("captured authority/span cold resume failed: %v", err)
	}
	o.assertClosed(t)
}

func TestPrepareV1OriginalsUnknownAtomicReserveStopsBeforeProvider(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	o := attachOriginalsV1(f)
	f.journal.failAfter = "reserve"
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("atomic original reserve acknowledgment was not protected: %v", err)
	}
	if o.authority == nil || len(o.bodies[ObjectIDV1{Kind: "span", Page: 0}]) == 0 || len(f.objects.events) != 0 || len(f.renderer.calls) != 0 {
		t.Fatal("unknown reserve forgot originals or dispatched")
	}
	f.request.Span = nil
	if prepared, err := f.preparer.Prepare(context.Background(), f.request); err != nil || prepared == nil || o.reserveCalls != 1 {
		t.Fatalf("positive atomic original readback did not resume: %v", err)
	}
	o.assertClosed(t)
}

func TestPrepareV1OriginalsCaptureConflictStopsBeforeObjectOrPut(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	o := attachOriginalsV1(f)
	id := ObjectIDV1{Kind: "page", Page: 1}
	o.failCapture, o.failCaptureOnce = id, true
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
		t.Fatal(err)
	}
	// A conflicting durable identity after the owned read must fail at Capture;
	// even genuine decoded original bytes cannot overwrite an immutable cache.
	o.loadHook = func(loaded ObjectIDV1) {
		if loaded == id {
			o.bodies[id][len(o.bodies[id])-1] ^= 1
			o.loadHook = nil
		}
	}
	f.request.Span = nil
	f.preparer.Renderer = nil
	calls := len(f.renderer.calls)
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrIdentityV1) || !errors.Is(err, ErrUncertainIOV1) || f.journal.objects[id] != nil || len(f.renderer.calls) != calls {
		t.Fatalf("capture conflict advanced or lost identity: %v", err)
	}
	o.assertClosed(t)
}

func TestPrepareV1OriginalsCaptureBeforeReservationColdResume(t *testing.T) {
	for _, kind := range []string{"span", "page", "manifest"} {
		t.Run(kind, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			o := attachOriginalsV1(f)
			id := ObjectIDV1{Kind: kind, Page: 0}
			if kind == "page" {
				id.Page = 1
			}
			o.failCapture, o.failCaptureOnce = id, true
			if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("capture acknowledgment was not uncertain/redacted: %v", err)
			}
			captured := bytes.Clone(o.bodies[id])
			if len(captured) == 0 || f.journal.objects[id] != nil {
				t.Fatal("capture-before-reserve crash window absent")
			}
			rendered := len(f.renderer.calls)
			if kind != "span" {
				f.preparer.Renderer = nil
			}
			f.request.Span = nil
			f.request.OriginalPayloads = nil
			prepared, err := f.preparer.Prepare(context.Background(), f.request)
			if err != nil || prepared == nil || !bytes.Equal(captured, o.bodies[id]) {
				t.Fatalf("original body was not recovered: %v", err)
			}
			if kind != "span" && len(f.renderer.calls) != rendered {
				t.Fatal("captured original page was rerendered")
			}
			for _, n := range f.objects.puts {
				if n != 1 {
					t.Fatal("cold resume repeated original PUT")
				}
			}
			o.assertClosed(t)
		})
	}
}

func TestPrepareV1OriginalsReservedNeverAttemptedColdResume(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 1)
	o := attachOriginalsV1(f)
	id := ObjectIDV1{Kind: "page", Page: 1}
	f.journal.failAfter = "object:page:1"
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
		t.Fatal(err)
	}
	row := f.journal.objects[id]
	if row == nil || row.UploadAttemptedAt.Valid || len(o.bodies[id]) == 0 {
		t.Fatal("never-attempted original fixture absent")
	}
	calls := len(f.renderer.calls)
	f.preparer.Renderer = nil
	f.request.Span = nil
	conflicting := bytes.Clone(o.bodies[id])
	conflicting[len(conflicting)-1] ^= 1
	f.request.OriginalPayloads = map[ObjectIDV1][]byte{id: conflicting}
	if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrOriginalPayloadV1) || f.objects.puts[row.StorageKey] != 0 || len(f.renderer.calls) != calls {
		t.Fatalf("supplied conflicting body advanced: %v", err)
	}
	o.assertClosed(t)
	f.request.OriginalPayloads = nil
	if prepared, err := f.preparer.Prepare(context.Background(), f.request); err != nil || prepared == nil || f.objects.puts[row.StorageKey] != 1 || len(f.renderer.calls) != calls {
		t.Fatalf("durable cold original failed: %v", err)
	}
	o.assertClosed(t)
}

func TestPrepareV1OriginalsMissingConflictingAndUnresolvedReadsRefuse(t *testing.T) {
	for _, mode := range []string{"authority", "missing-reserved-page", "tampered-captured-page", "unresolved-absence"} {
		t.Run(mode, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			o := attachOriginalsV1(f)
			id := ObjectIDV1{Kind: "page", Page: 1}
			if mode == "authority" {
				f.journal.failBefore = "objects"
				if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil {
					t.Fatal("fixture stop absent")
				}
				in := f.request.Authority.Input()
				in.Source.VersionID += "different"
				a, err := manualfit.BuildAuthorityV1(in, f.request.Authority.Geometry())
				if err != nil {
					t.Fatal(err)
				}
				o.authorityOverride = a
			} else if mode == "missing-reserved-page" {
				f.journal.failAfter = "object:page:1"
				if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
					t.Fatal(err)
				}
				delete(o.bodies, id)
			} else {
				o.failCapture, o.failCaptureOnce = id, true
				if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
					t.Fatal(err)
				}
				if mode == "tampered-captured-page" {
					o.bodies[id][len(o.bodies[id])-1] ^= 1
				} else {
					o.loadErrors[id] = errors.Join(pgx.ErrNoRows, ErrUncertainIOV1)
				}
			}
			calls := len(f.renderer.calls)
			puts := len(f.objects.events)
			captures := originalCaptureCountV1(o)
			f.request.Span = nil
			if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("unsafe original accepted: %v", err)
			}
			if len(f.renderer.calls) != calls || originalCaptureCountV1(o) != captures {
				t.Fatal("missing/conflicting/uncertain original generated a replacement")
			}
			if mode == "authority" && len(f.objects.events) != puts {
				t.Fatal("changed frozen authority reached source IO")
			}
			for _, row := range f.journal.objects {
				if row.Kind == "page" && f.objects.puts[row.StorageKey] != 0 {
					t.Fatal("refused original page uploaded")
				}
			}
			o.assertClosed(t)
		})
	}
}

func TestPrepareV1OriginalsUnknownAttemptNeverLoadsOrReplays(t *testing.T) {
	for _, kind := range []string{"span", "page", "manifest"} {
		t.Run(kind, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			o := attachOriginalsV1(f)
			id := ObjectIDV1{Kind: kind, Page: 0}
			if kind == "page" {
				id.Page = 1
			}
			f.journal.failAfter = checkpointNameV1("attempt", kind, id.Page)
			if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) {
				t.Fatal(err)
			}
			row := f.journal.objects[id]
			if row == nil || !row.UploadAttemptedAt.Valid || f.objects.puts[row.StorageKey] != 0 {
				t.Fatal("unknown-attempt fixture absent")
			}
			captures, loads, calls := originalCaptureCountV1(o), originalLoadCountV1(o), len(f.renderer.calls)
			f.request.Span = nil
			f.preparer.Renderer = nil
			if _, err := f.preparer.Prepare(context.Background(), f.request); !errors.Is(err, ErrUncertainIOV1) || f.objects.puts[row.StorageKey] != 0 || originalCaptureCountV1(o) != captures || originalLoadCountV1(o) != loads || len(f.renderer.calls) != calls {
				t.Fatalf("unknown attempt became original replay permission: %v", err)
			}
			o.assertClosed(t)
		})
	}
}

func TestPrepareV1OriginalsCancellationClosesEveryConsumerLease(t *testing.T) {
	for _, mode := range []string{"authority", "authority-mismatch", "span-load", "span-conflict", "page-capture"} {
		t.Run(mode, func(t *testing.T) {
			f := protocolFixtureV1(t, "v1-case-1.fit", 1)
			o := attachOriginalsV1(f)
			cause := errors.New("PRIVATE_ORIGINAL_CANCEL_CAUSE")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			switch mode {
			case "authority":
				o.authorityHook = func() { cancel(cause) }
			case "authority-mismatch":
				in := f.request.Authority.Input()
				in.Source.VersionID += "changed"
				changed, err := manualfit.BuildAuthorityV1(in, f.request.Authority.Geometry())
				if err != nil {
					t.Fatal(err)
				}
				o.authorityOverride = changed
				o.authorityHook = func() { cancel(cause) }
			case "span-load":
				o.loadHook = func(id ObjectIDV1) {
					if id.Kind == "span" {
						cancel(cause)
					}
				}
			case "span-conflict":
				o.loadHook = func(id ObjectIDV1) {
					if id.Kind == "span" {
						o.bodyViews[len(o.bodyViews)-1][0] ^= 1
						cancel(cause)
					}
				}
			case "page-capture":
				o.captureHook = func(id ObjectIDV1) {
					if id.Kind == "page" {
						cancel(cause)
					}
				}
			}
			prepared, err := f.preparer.Prepare(ctx, f.request)
			if prepared != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("cancellation identity/redaction lost: %v", err)
			}
			if mode != "page-capture" && (len(f.objects.events) != 0 || len(f.renderer.calls) != 0) {
				t.Fatal("canceled original read advanced to source/renderer")
			}
			if mode == "page-capture" && f.journal.objects[ObjectIDV1{Kind: "page", Page: 1}] != nil {
				t.Fatal("canceled capture advanced to object reservation")
			}
			o.assertClosed(t)
		})
	}
}

func TestPrepareV1OriginalsPreparedRecoveryIsReadOnlyAndPageLeasesDoNotAccumulate(t *testing.T) {
	f := protocolFixtureV1(t, "v1-case-1.fit", 2)
	o := attachOriginalsV1(f)
	// Stage both synthetic originals before any85 object row to exercise two
	// consecutive borrowed leases. No claim of real producer/SQL proof is made.
	f.journal.failBefore = "objects"
	if _, err := f.preparer.Prepare(context.Background(), f.request); err == nil {
		t.Fatal("fixture capture stop absent")
	}
	row := clonePreparationTestV1(f.journal.operation)
	for page, pkg := range f.renderer.packages {
		id := ObjectIDV1{Kind: "page", Page: int32(page)}
		key, mime, _, ok := objectLayoutV1(id, manualfit.ObjectPrefixV1(row.ID, row.OrgID, row.DocumentID))
		if !ok {
			t.Fatal("page layout")
		}
		raw := pkg.Bytes()
		if err := o.Capture(context.Background(), row, id, key, mime, raw); err != nil {
			t.Fatal(err)
		}
		clear(raw)
	}
	f.preparer.Renderer = nil
	f.request.Span = nil
	prepared, err := f.preparer.Prepare(context.Background(), f.request)
	if err != nil || prepared == nil {
		t.Fatal(err)
	}
	o.assertClosed(t)
	captures, loads, reserves, calls := originalCaptureCountV1(o), originalLoadCountV1(o), o.reserveCalls, len(f.renderer.calls)
	f.request.Span = nil
	f.preparer.Renderer = nil
	beforeJournal := len(f.journal.events)
	again, err := f.preparer.Prepare(context.Background(), f.request)
	if err != nil || again == nil || again.ManifestObject() != prepared.ManifestObject() || originalCaptureCountV1(o) != captures || originalLoadCountV1(o) != loads || o.reserveCalls != reserves || len(f.renderer.calls) != calls {
		t.Fatalf("prepared recovery mutated originals: %v", err)
	}
	for _, event := range f.journal.events[beforeJournal:] {
		if event != "get" && event != "objects" {
			t.Fatal("prepared recovery mutated SQL inventory")
		}
	}
	o.assertClosed(t)
}
