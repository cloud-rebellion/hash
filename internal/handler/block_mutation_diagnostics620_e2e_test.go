//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Query-boundary samples diagnose real owned block-edit refusal without
// retaining SQL, arguments, errors, bodies or credentials. Sampled maxima are
// lower bounds, not admission authority or a complete resource peak. The
// original allocation, query context, locks and all refusal oracles are intact.
type blockMutationTrace620 struct {
	mu                          sync.Mutex
	runtime                     *pdfadmission.WorkRuntimeV1
	org                         uuid.UUID
	count                       uint64
	last                        [16]blockMutationSample620
	maxParent, maxDB, maxGrants int64
}

type blockMutationSample620 struct {
	Query                   string
	Parent, DB, Grants, SQL int64
}

func (p *blockMutationTrace620) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.runtime == nil {
		return ctx
	}
	snapshot, err := p.runtime.SnapshotV1(p.org)
	if err != nil {
		return ctx
	}
	name := "unnamed"
	if strings.HasPrefix(data.SQL, "-- name: ") {
		candidate, _, _ := strings.Cut(strings.TrimPrefix(data.SQL, "-- name: "), " ")
		if len(candidate) > 0 && len(candidate) <= 96 && strings.IndexFunc(candidate, func(c rune) bool {
			return c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9')
		}) < 0 {
			name = candidate
		}
	}
	p.last[p.count%uint64(len(p.last))] = blockMutationSample620{name, snapshot.Organisation.ParentBytes, snapshot.Organisation.DBStagingBytes, snapshot.OrganisationGrants, snapshot.Organisation.SQLSessions}
	p.count++
	p.maxParent = max(p.maxParent, snapshot.Organisation.ParentBytes)
	p.maxDB = max(p.maxDB, snapshot.Organisation.DBStagingBytes)
	p.maxGrants = max(p.maxGrants, snapshot.OrganisationGrants)
	return ctx
}
func (*blockMutationTrace620) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (p *blockMutationTrace620) begin620(t *testing.T, q *ownedPublicReadFixtureV1, document uuid.UUID) {
	t.Helper()
	// This independent fixture witness only checks genuine producer caches; it
	// never writes, repairs or supplies them to the application's native reader.
	h, err := q.f.q.GetHTMLRevisionDocumentReadHeaderV1(q.f.ctx, generated.GetHTMLRevisionDocumentReadHeaderV1Params{DocumentID: document, OrgID: q.f.org})
	if err != nil || h == nil {
		t.Logf("block fixture genuine source header unavailable: %T", err)
	} else if h.ServerVersionNum < 1 || h.PolicyMeasurementServerVersionNum != h.ServerVersionNum || h.ResponseMeasurementServerVersionNum != h.ServerVersionNum || h.ReportMeasurementServerVersionNum != h.ServerVersionNum || h.BlocksWireBytes < 0 || h.VariablesWireBytes < 0 || h.MetadataWireBytes < 0 || h.ReportWireBytes < 0 || h.HtmlOriginWireBytes != 0 || h.HtmlCurrentWireBytes != 0 {
		t.Logf("block fixture genuine producer cache mismatch: policy=%d response=%d report=%d server=%d blocks=%d vars=%d metadata=%d reportbytes=%d origin=%d current=%d", h.PolicyMeasurementServerVersionNum, h.ResponseMeasurementServerVersionNum, h.ReportMeasurementServerVersionNum, h.ServerVersionNum, h.BlocksWireBytes, h.VariablesWireBytes, h.MetadataWireBytes, h.ReportWireBytes, h.HtmlOriginWireBytes, h.HtmlCurrentWireBytes)
	}
	p.mu.Lock()
	p.runtime, p.org = q.runtime, q.f.org
	p.mu.Unlock()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		snapshot, err := p.runtime.SnapshotV1(p.org)
		t.Logf("native block diagnostic: query_samples=%d sampled_max_parent=%d sampled_max_db=%d sampled_max_grants=%d final=%+v snapshot_error=%t", p.count, p.maxParent, p.maxDB, p.maxGrants, snapshot, err != nil)
		start := uint64(0)
		if p.count > uint64(len(p.last)) {
			start = p.count - uint64(len(p.last))
		}
		for n := start; n < p.count; n++ {
			t.Logf("native block boundary %d: %+v", n, p.last[n%uint64(len(p.last))])
		}
		// This is a numeric observation only, never a replacement for the
		// existing joined physical-backend and retained-work cleanup assertions.
	})
}
