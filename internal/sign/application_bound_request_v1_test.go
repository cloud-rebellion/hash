// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are metadata/ownership tests, never SQL acknowledgement, retirement,
// READY or application-signing acceptance. Genuine owned-session/PG interleavings
// remain in the separate component qualification plan.
func TestApplicationRequestHeaderRejectsUntrustedAccountingV1(t *testing.T) {
	key := applicationRequestKeyV1{uuid.New(), uuid.New(), uuid.New()}
	baseline := generated.GetSignatureFitRequestScopeHeaderV1Row{
		OrgID: key.org, DocumentID: key.document, AdmissionID: uuid.New(),
		CeremonyEpoch:     pgtype.Timestamptz{Time: time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC), Valid: true},
		StaticBasisSha256: make([]byte, 32), DocumentNameBytes: 100, LawfulBasisBytes: 20,
		ControllerNameBytes: 30, ControllerContactBytes: 40, ConfirmationBasisBytes: 50,
		ConfirmationViaBytes: 60, ControllerOrgNameBytes: 70,
		CurrentContextProcessingBytes: 8192 + 100 + 20 + 30 + 40 + 50 + 60 + 70,
	}
	if got, err := applicationRequestHeaderV1(&baseline, key); err != nil || got != baseline.CurrentContextProcessingBytes {
		t.Fatalf("genuine scalar sum rejected: %d %v", got, err)
	}
	cases := []struct {
		name   string
		mutate func(*generated.GetSignatureFitRequestScopeHeaderV1Row)
	}{
		{"wrong tenant", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) { h.OrgID = uuid.New() }},
		{"wrong document", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) { h.DocumentID = uuid.New() }},
		{"missing admission", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) { h.AdmissionID = uuid.Nil }},
		{"missing epoch", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) { h.CeremonyEpoch.Valid = false }},
		{"infinite epoch", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) {
			h.CeremonyEpoch.InfinityModifier = pgtype.Infinity
		}},
		{"zero epoch", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) { h.CeremonyEpoch.Time = time.Time{} }},
		{"short basis SHA", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) { h.StaticBasisSha256 = []byte{1} }},
		{"negative raw counter", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) { h.LawfulBasisBytes = -1 }},
		{"unbound sum", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) { h.CurrentContextProcessingBytes++ }},
		{"overflow", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) { h.ControllerOrgNameBytes = math.MaxInt64 }},
		{"oversized declared document name", func(h *generated.GetSignatureFitRequestScopeHeaderV1Row) {
			h.DocumentNameBytes = requestDocumentNameMaxBytesV1 + 1
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := baseline
			tc.mutate(&h)
			if _, err := applicationRequestHeaderV1(&h, key); err == nil {
				t.Fatal("untrusted metadata accepted")
			}
		})
	}
}

func TestApplicationBoundRequestPreservesPrivateCancellationCauseV1(t *testing.T) {
	secret := errors.New("do not expose connection secret")
	deadline, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, stop := context.WithCancelCause(deadline)
	stop(secret)
	err := applicationBoundRequestErrorV1(ctx, errApplicationBoundRequestUnknownV1)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, secret) || !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatalf("lost cancellation/outcome identity: %v", err)
	}
	if strings.Contains(err.Error(), secret.Error()) {
		t.Fatal("private cause exposed")
	}
	err = applicationBoundRequestErrorV1(deadline, errors.Join(ErrMagicLinkExpired, secret))
	if !errors.Is(err, ErrMagicLinkExpired) || strings.Contains(err.Error(), secret.Error()) {
		t.Fatalf("expiry sentinel/privacy lost: %v", err)
	}
	if applicationBoundRequestContextV1(context.Background()) == nil {
		t.Fatal("unbounded owner accepted")
	}
	if applicationBoundRequestContextV1(nil) == nil {
		t.Fatal("nil owner accepted")
	}
}

func TestApplicationRequestClaimHasOneConcurrentOwnerV1(t *testing.T) {
	j := &applicationRequestJournalV1{owners: make(map[applicationRequestKeyV1]*applicationRequestOperationV1)}
	key := applicationRequestKeyV1{uuid.New(), uuid.New(), uuid.New()}
	const n = 32
	var wg sync.WaitGroup
	results := make(chan *applicationRequestOperationV1, n)
	failures := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); op, err := j.claimV1(key); results <- op; failures <- err }()
	}
	wg.Wait()
	close(results)
	close(failures)
	successes := 0
	var owner *applicationRequestOperationV1
	for op := range results {
		if op != nil {
			successes++
			owner = op
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent request issued %d owners", successes)
	}
	refused := 0
	for err := range failures {
		if err != nil {
			if !errors.Is(err, errApplicationBoundRequestUnknownV1) {
				t.Fatalf("wrong refusal: %v", err)
			}
			refused++
		}
	}
	if refused != n-1 || j.owners[key] != owner {
		t.Fatal("original concurrent owner was lost")
	}
	j.closing = true
	if _, err := j.claimV1(applicationRequestKeyV1{uuid.New(), uuid.New(), uuid.New()}); err == nil {
		t.Fatal("new owner issued during shutdown")
	}
}

func TestApplicationRequestOwnerRegistryIsBoundedV1(t *testing.T) {
	j := &applicationRequestJournalV1{owners: make(map[applicationRequestKeyV1]*applicationRequestOperationV1)}
	for i := 0; i < applicationBoundRequestOwnersV1; i++ {
		if _, err := j.claimV1(applicationRequestKeyV1{uuid.New(), uuid.New(), uuid.New()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := j.claimV1(applicationRequestKeyV1{uuid.New(), uuid.New(), uuid.New()}); err == nil {
		t.Fatal("unbounded unknown ownership")
	}
}

func TestApplicationRequestUnknownCaptureCannotCloseOrPublishV1(t *testing.T) {
	j := &applicationRequestJournalV1{owners: make(map[applicationRequestKeyV1]*applicationRequestOperationV1)}
	key := applicationRequestKeyV1{uuid.New(), uuid.New(), uuid.New()}
	op := &applicationRequestOperationV1{journal: j, key: key, attempted: true, unknown: true,
		metadata:  &generated.ReserveBoundSignatureFitRequestV1Row{PreparationID: uuid.New()},
		authority: []byte("synthetic authority"), span: []byte("synthetic span"),
	}
	j.owners[key] = op
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !errors.Is(op.CloseV1(ctx), errApplicationBoundRequestUnknownV1) {
		t.Fatal("unknown COMMIT owner closed without exact reconciliation")
	}
	if j.owners[key] != op || op.closed || len(op.authority) == 0 || len(op.span) == 0 {
		t.Fatal("unknown original owner/body provenance discarded")
	}
	if _, _, _, err := op.dataV1(); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("unknown data exposed")
	}
	// An acknowledged row is still not physical retirement. This owner has no
	// dispatched/retired session; no synthetic bool can turn it into a receipt.
	op.unknown = false
	op.acknowledged = true
	if _, _, _, err := op.dataV1(); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("acknowledgement substituted for physical retirement")
	}
}
