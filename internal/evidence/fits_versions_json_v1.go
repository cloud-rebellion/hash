// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/versions"
)

// versionDelta preserves the existing versions.json fields and ordering.
type versionDelta struct {
	VersionNo  int32                  `json:"version_no"`
	CreatedAt  string                 `json:"created_at"`
	CreatedVia string                 `json:"created_via"`
	Summary    string                 `json:"summary,omitempty"`
	Diff       []versions.BlockChange `json:"diff,omitempty"`
}

// Both export budgets count JSON string escaping without allocating its output.
type fitsJSONStringBudgetV1 interface{ add(int64) error }

// This budget counts exactly MarshalIndent("", "  ") for versions.json.
// It admits JSON serialization only. versions.Diff has already parsed and
// allocated its working trees/change strings; those allocations are separate.
type fitsVersionsJSONBudgetV1 struct {
	used           int64
	expected, seen int
	nullVersions   bool
}

func (b *fitsVersionsJSONBudgetV1) add(n int64) error {
	if n < 0 || b.used < 0 || b.used > manualfit.MaxVersionsJSONBytesV1 || n > manualfit.MaxVersionsJSONBytesV1-b.used {
		return ErrEvidenceTooLarge
	}
	b.used += n
	return nil
}

// A member includes the previous comma, newline, indentation and quoted key.
func (b *fitsVersionsJSONBudgetV1) member(depth int, name string, index int) error {
	n := int64(1 + 2*depth + len(name) + 4)
	if index > 0 {
		n++
	}
	return b.add(n)
}

func (b *fitsVersionsJSONBudgetV1) element(depth, index int) error {
	n := int64(1 + 2*depth)
	if index > 0 {
		n++
	}
	return b.add(n)
}

func (b *fitsVersionsJSONBudgetV1) close(depth int, nonempty bool) error {
	n := int64(1)
	if nonempty {
		n += int64(1 + 2*depth)
	}
	return b.add(n)
}

func (b *fitsVersionsJSONBudgetV1) stringMember(ctx context.Context, depth int, name, value string, index int) error {
	if err := b.member(depth, name, index); err != nil {
		return err
	}
	return fitsEventsJSONStringBoundV1(ctx, b, value)
}

func (b *fitsVersionsJSONBudgetV1) numberMember(depth int, name string, value int64, index int) error {
	if err := b.member(depth, name, index); err != nil {
		return err
	}
	return b.add(int64(len(strconv.FormatInt(value, 10))))
}

func newFitsVersionsJSONBudgetV1(ctx context.Context, documentID uuid.UUID, count int, nullVersions bool) (*fitsVersionsJSONBudgetV1, error) {
	if ctx == nil || count < 0 || (nullVersions && count != 0) {
		return nil, ErrArtifactIntegrity
	}
	if count > maxEvidenceVersions {
		return nil, ErrEvidenceTooLarge
	}
	if ctx.Err() != nil {
		return nil, safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	b := &fitsVersionsJSONBudgetV1{expected: count, nullVersions: nullVersions}
	if err := b.add(1); err != nil {
		return nil, err
	}
	// encoding/json sorts the existing envelope map keys alphabetically.
	if err := b.numberMember(1, "count", int64(count), 0); err != nil {
		return nil, err
	}
	if err := b.stringMember(ctx, 1, "document_id", documentID.String(), 1); err != nil {
		return nil, err
	}
	if err := b.numberMember(1, "schema_version", 1, 2); err != nil {
		return nil, err
	}
	if err := b.member(1, "versions", 3); err != nil {
		return nil, err
	}
	n := int64(1) // opening array; nil slices instead encode the four bytes null.
	if nullVersions {
		n = 4
	}
	if err := b.add(n); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *fitsVersionsJSONBudgetV1) change(ctx context.Context, change versions.BlockChange, index int) error {
	if ctx.Err() != nil {
		return safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	if err := b.element(4, index); err != nil {
		return err
	}
	if err := b.add(1); err != nil {
		return err
	}
	if err := b.stringMember(ctx, 5, "kind", string(change.Kind), 0); err != nil {
		return err
	}
	if err := b.stringMember(ctx, 5, "block_id", change.BlockID, 1); err != nil {
		return err
	}
	member := 2
	if change.Type != "" {
		if err := b.stringMember(ctx, 5, "type", change.Type, member); err != nil {
			return err
		}
		member++
	}
	if err := b.numberMember(5, "position", int64(change.Position), member); err != nil {
		return err
	}
	member++
	for _, field := range [...]struct{ name, value string }{
		{"from_text", change.FromText}, {"to_text", change.ToText},
		{"from_attr", change.FromAttr}, {"to_attr", change.ToAttr},
	} {
		if field.value == "" {
			continue
		}
		if err := b.stringMember(ctx, 5, field.name, field.value, member); err != nil {
			return err
		}
		member++
	}
	return b.close(4, true)
}

func (b *fitsVersionsJSONBudgetV1) version(ctx context.Context, entry versionDelta) error {
	if b.seen >= b.expected || b.nullVersions {
		return ErrArtifactIntegrity
	}
	if ctx.Err() != nil {
		return safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	if err := b.element(2, b.seen); err != nil {
		return err
	}
	if err := b.add(1); err != nil {
		return err
	}
	if err := b.numberMember(3, "version_no", int64(entry.VersionNo), 0); err != nil {
		return err
	}
	if err := b.stringMember(ctx, 3, "created_at", entry.CreatedAt, 1); err != nil {
		return err
	}
	if err := b.stringMember(ctx, 3, "created_via", entry.CreatedVia, 2); err != nil {
		return err
	}
	member := 3
	if entry.Summary != "" {
		if err := b.stringMember(ctx, 3, "summary", entry.Summary, member); err != nil {
			return err
		}
		member++
	}
	if len(entry.Diff) > 0 {
		if err := b.member(3, "diff", member); err != nil {
			return err
		}
		if err := b.add(1); err != nil {
			return err
		}
		for i, change := range entry.Diff {
			if err := b.change(ctx, change, i); err != nil {
				return err
			}
		}
		if err := b.close(3, true); err != nil {
			return err
		}
	}
	if err := b.close(2, true); err != nil {
		return err
	}
	b.seen++
	return nil
}

func (b *fitsVersionsJSONBudgetV1) finish(ctx context.Context) error {
	if b.seen != b.expected {
		return ErrArtifactIntegrity
	}
	if ctx.Err() != nil {
		return safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	if !b.nullVersions {
		if err := b.close(1, b.expected > 0); err != nil {
			return err
		}
	}
	return b.close(0, true)
}

func fitsVersionsJSONSizeV1(ctx context.Context, documentID uuid.UUID, deltas []versionDelta) (int64, error) {
	budget, err := newFitsVersionsJSONBudgetV1(ctx, documentID, len(deltas), deltas == nil)
	if err != nil {
		return 0, err
	}
	for _, entry := range deltas {
		if err := budget.version(ctx, entry); err != nil {
			return 0, err
		}
	}
	if err := budget.finish(ctx); err != nil {
		return 0, err
	}
	return budget.used, nil
}

// The fitted path refuses escaping expansion before MarshalIndent allocates
// JSON output. The legacy path retains the same serializer and existing limits.
func marshalEvidenceVersionsJSONV1(ctx context.Context, documentID uuid.UUID, deltas []versionDelta, fitted bool) ([]byte, error) {
	var expected int64
	var err error
	if fitted {
		expected, err = fitsVersionsJSONSizeV1(ctx, documentID, deltas)
		if err != nil {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, safeFitsEvidenceErrorV1(ctx, ctx.Err())
		}
	}
	raw, err := json.MarshalIndent(map[string]any{
		"schema_version": 1, "document_id": documentID.String(), "versions": deltas, "count": len(deltas),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	if fitted && ctx.Err() != nil {
		clear(raw)
		return nil, safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	// A format/schema change must update the counter and its independent oracle
	// tests together. Preserve a fail-closed defense against accounting drift.
	if fitted && int64(len(raw)) != expected {
		return nil, ErrArtifactIntegrity
	}
	return raw, nil
}
