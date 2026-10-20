// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/versions"
)

func versionsJSONOracleV1(t *testing.T, id uuid.UUID, deltas []versionDelta) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(map[string]any{
		"schema_version": 1, "document_id": id.String(), "versions": deltas, "count": len(deltas),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFitsVersionsJSONSizeMatchesMarshalIndent(t *testing.T) {
	id := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	escaped := "quote\" slash\\ controls\b\f\n\r\t\x00\x1f <>& \u2028\u2029 invalid\xff\xc0 Å🦉"
	fullChange := versions.BlockChange{
		Kind: versions.ChangeKind(escaped), BlockID: escaped, Type: escaped, Position: -123,
		FromText: escaped, ToText: escaped + "new", FromAttr: escaped + "old", ToAttr: escaped + "new",
	}
	for _, tc := range []struct {
		name   string
		deltas []versionDelta
	}{
		{"nil-versions", nil},
		{"empty-versions", []versionDelta{}},
		{"empty-optional-fields", []versionDelta{{VersionNo: 1}}},
		{"empty-diff-omitted", []versionDelta{{VersionNo: 1, Diff: []versions.BlockChange{}}}},
		{"escaped-every-field", []versionDelta{{VersionNo: -2147483648, CreatedAt: escaped, CreatedVia: escaped, Summary: escaped, Diff: []versions.BlockChange{fullChange}}}},
		{"multiple-versions-and-changes", []versionDelta{
			{VersionNo: 1, CreatedAt: "2026-10-13T00:00:00Z", CreatedVia: "api", Summary: "First"},
			{VersionNo: 2147483647, CreatedAt: escaped, CreatedVia: "portal", Diff: []versions.BlockChange{
				{Kind: versions.ChangeAdded, BlockID: "added", Position: 0},
				{Kind: versions.ChangeRemoved, BlockID: "removed", Position: -1, FromText: "old"},
				fullChange,
			}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oracle := versionsJSONOracleV1(t, id, tc.deltas)
			size, err := fitsVersionsJSONSizeV1(context.Background(), id, tc.deltas)
			if err != nil || size != int64(len(oracle)) {
				t.Fatalf("size=%d actual=%d err=%v", size, len(oracle), err)
			}
			fitted, err := marshalEvidenceVersionsJSONV1(context.Background(), id, tc.deltas, true)
			if err != nil || !bytes.Equal(fitted, oracle) {
				t.Fatalf("fitted encoding changed: %v", err)
			}
			legacy, err := marshalEvidenceVersionsJSONV1(context.Background(), id, tc.deltas, false)
			if err != nil || !bytes.Equal(legacy, oracle) {
				t.Fatalf("legacy encoding changed: %v", err)
			}
		})
	}
}

func TestFitsVersionsJSONExactFourMiBBoundary(t *testing.T) {
	if manualfit.MaxVersionsJSONBytesV1 != 4<<20 {
		t.Fatal("version JSON cap changed")
	}
	id := uuid.New()
	// Obtain fixed overhead from the real serializer, not the budget formulas.
	overhead := len(versionsJSONOracleV1(t, id, []versionDelta{{VersionNo: 1, Summary: "x"}})) - 1
	for _, delta := range []int{-1, 0, 1} {
		t.Run(map[int]string{-1: "below", 0: "at", 1: "above"}[delta], func(t *testing.T) {
			want := int(manualfit.MaxVersionsJSONBytesV1) + delta
			deltas := []versionDelta{{VersionNo: 1, Summary: strings.Repeat("x", want-overhead)}}
			raw, err := marshalEvidenceVersionsJSONV1(context.Background(), id, deltas, true)
			if delta > 0 {
				if raw != nil || !errors.Is(err, ErrEvidenceTooLarge) {
					t.Fatalf("above-cap serialization accepted: %v", err)
				}
				return
			}
			if err != nil || len(raw) != want {
				t.Fatalf("boundary=%d actual=%d err=%v", want, len(raw), err)
			}
		})
	}
}

func TestFitsVersionsJSONExpansionRefusesEachUnboundedField(t *testing.T) {
	id := uuid.New()
	expanded := strings.Repeat("<", int(manualfit.MaxVersionsJSONBytesV1/6)+1)
	if int64(len(expanded)) >= manualfit.MaxVersionsJSONBytesV1 {
		t.Fatal("fixture must fit the old raw-string admission")
	}
	for _, field := range []string{"created_at", "created_via", "summary", "kind", "block_id", "type", "from_text", "to_text", "from_attr", "to_attr"} {
		t.Run(field, func(t *testing.T) {
			entry := versionDelta{VersionNo: 1}
			change := versions.BlockChange{Kind: versions.ChangeModified, BlockID: "block"}
			switch field {
			case "created_at":
				entry.CreatedAt = expanded
			case "created_via":
				entry.CreatedVia = expanded
			case "summary":
				entry.Summary = expanded
			case "kind":
				change.Kind = versions.ChangeKind(expanded)
			case "block_id":
				change.BlockID = expanded
			case "type":
				change.Type = expanded
			case "from_text":
				change.FromText = expanded
			case "to_text":
				change.ToText = expanded
			case "from_attr":
				change.FromAttr = expanded
			case "to_attr":
				change.ToAttr = expanded
			}
			if field != "created_at" && field != "created_via" && field != "summary" {
				entry.Diff = []versions.BlockChange{change}
			}
			raw, err := marshalEvidenceVersionsJSONV1(context.Background(), id, []versionDelta{entry}, true)
			if raw != nil || !errors.Is(err, ErrEvidenceTooLarge) {
				t.Fatalf("unaccounted %s expansion: %v", field, err)
			}
		})
	}
}

func TestFitsVersionsJSONOversizeRefusesBeforeExpandedAllocation(t *testing.T) {
	// This package test is deliberately not parallel. The raw fixture is <1MiB,
	// while default HTML escaping would allocate an output larger than4MiB.
	// Measure the actual production serializer, not a separate counting helper.
	id := uuid.New()
	deltas := []versionDelta{{VersionNo: 1, Summary: strings.Repeat("<", int(manualfit.MaxVersionsJSONBytesV1/6)+1)}}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	raw, err := marshalEvidenceVersionsJSONV1(context.Background(), id, deltas, true)
	runtime.ReadMemStats(&after)
	if raw != nil || !errors.Is(err, ErrEvidenceTooLarge) {
		t.Fatalf("oversize export accepted: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 1<<20 {
		t.Fatalf("refusal allocated %d bytes before returning; escaped JSON must not be allocated", allocated)
	}
}

type versionsCancellationCheckpointV1 struct {
	context.Context
	cancel      context.CancelCauseFunc
	cause       error
	checkpoints int
	at          int
}

func (c *versionsCancellationCheckpointV1) Err() error {
	c.checkpoints++
	if c.checkpoints == c.at {
		c.cancel(c.cause)
	}
	return c.Context.Err()
}

func TestFitsVersionsJSONCancellationRetainsPrivateCause(t *testing.T) {
	id := uuid.New()
	for _, mode := range []string{"canceled", "deadline", "during-escaping", "after-encoding"} {
		t.Run(mode, func(t *testing.T) {
			cause := errors.New("PRIVATE_VERSION_EXPORT_CANCELLATION")
			var ctx context.Context
			var stop func()
			want := error(context.Canceled)
			deltas := []versionDelta{{VersionNo: 1, CreatedVia: strings.Repeat("x", 20000)}}
			switch mode {
			case "canceled":
				base, cancel := context.WithCancelCause(context.Background())
				cancel(cause)
				ctx = base
				stop = func() { cancel(nil) }
			case "deadline":
				base, cancel := context.WithDeadlineCause(context.Background(), time.Now().Add(-time.Second), cause)
				ctx = base
				stop = cancel
				want = context.DeadlineExceeded
			case "during-escaping":
				base, cancel := context.WithCancelCause(context.Background())
				ctx = &versionsCancellationCheckpointV1{Context: base, cancel: cancel, cause: cause, at: 5}
				stop = func() { cancel(nil) }
			case "after-encoding":
				base, cancel := context.WithCancelCause(context.Background())
				deltas = []versionDelta{{VersionNo: 1}}
				ctx = &versionsCancellationCheckpointV1{Context: base, cancel: cancel, cause: cause, at: 6}
				stop = func() { cancel(nil) }
			}
			defer stop()
			raw, err := marshalEvidenceVersionsJSONV1(ctx, id, deltas, true)
			if raw != nil || !errors.Is(err, want) || !errors.Is(err, cause) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("private cancellation identity/sanitization lost: %v", err)
			}
		})
	}
	raw, err := marshalEvidenceVersionsJSONV1(nil, id, []versionDelta{}, true)
	if raw != nil || !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatal("nil cancellation context admitted")
	}
}

func TestFitsVersionsJSONAggregateOldNewAttributesBounded(t *testing.T) {
	id := uuid.New()
	// Each side fits by itself; the exported old/new pair exceeds the shared cap.
	attribute := strings.Repeat("<", int(manualfit.MaxVersionsJSONBytesV1/12))
	for _, field := range []string{"from_attr", "to_attr"} {
		change := versions.BlockChange{Kind: versions.ChangeModified, BlockID: "block"}
		if field == "from_attr" {
			change.FromAttr = attribute
		} else {
			change.ToAttr = attribute
		}
		if raw, err := marshalEvidenceVersionsJSONV1(context.Background(), id, []versionDelta{{VersionNo: 2, Diff: []versions.BlockChange{change}}}, true); err != nil || raw == nil {
			t.Fatalf("individual %s refused: %v", field, err)
		}
	}
	combined := []versionDelta{{VersionNo: 2, Diff: []versions.BlockChange{{Kind: versions.ChangeModified, BlockID: "block", FromAttr: attribute, ToAttr: attribute}}}}
	if raw, err := marshalEvidenceVersionsJSONV1(context.Background(), id, combined, true); raw != nil || !errors.Is(err, ErrEvidenceTooLarge) {
		t.Fatalf("old/new aggregate escaping accepted: %v", err)
	}
}
