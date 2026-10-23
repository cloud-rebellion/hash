// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import (
	"context"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
)

// An approved source observation is born only from the concrete protected
// account-before/records/account-after read. No public Snapshot or report DTO
// can mint its private resolver fence. The native caller owns body/provider
// capacity and retains this object through its actual last consumer.
type ApprovedCRMSourceV1 struct {
	self     *ApprovedCRMSourceV1
	snapshot crmconnection.Snapshot
}

func ReadApprovedCRMSourceV1(ctx context.Context, client *crmconnection.Client, keys *crmconnection.Keyring, connection crmconnection.Connection, refs []crmconnection.RecordRef) (*ApprovedCRMSourceV1, error) {
	if client == nil || keys == nil || len(refs) < 1 || len(refs) > 3 {
		return nil, ErrSourceFreshness
	}
	seen := map[crmconnection.RecordKind]bool{}
	for _, ref := range refs {
		if seen[ref.Kind] || crmconnection.ValidateRecordRef(ref) != nil {
			return nil, ErrSourceFreshness
		}
		seen[ref.Kind] = true
	}
	snapshot, err := client.ReadRecords(ctx, connection, keys, refs)
	if err != nil {
		return nil, err
	}
	if snapshot.Identity != connection.Identity || validateCRMRelationships(snapshot) != nil || !crmObservationCurrent(snapshot.CompletedAt, time.Now()) {
		return nil, ErrSourceFreshness
	}
	h := &ApprovedCRMSourceV1{snapshot: snapshot}
	h.self = h
	return h, nil
}

func (h *ApprovedCRMSourceV1) IdentityV1() crmconnection.Identity {
	if h == nil || h.self != h {
		return crmconnection.Identity{}
	}
	return h.snapshot.Identity
}
func (h *ApprovedCRMSourceV1) CheckDeadlineV1() error {
	if h == nil || h.self != h || !crmObservationCurrent(h.snapshot.CompletedAt, time.Now()) {
		return ErrSourceFreshness
	}
	return nil
}
func (h *ApprovedCRMSourceV1) ScalarV1(kind, id, path string) (string, error) {
	if h.CheckDeadlineV1() != nil {
		return "", ErrSourceFreshness
	}
	r, ok := h.snapshot.Record(crmconnection.RecordKind(kind), id)
	if !ok {
		return "", ErrSourceFreshness
	}
	return r.Value(path)
}

// Read actual persisted rows under the final native transaction; exported
// binding-shaped input is deliberately not an alternative constructor.
func (h *ApprovedCRMSourceV1) ReportsForDocumentV1(ctx context.Context, tx pgx.Tx, doc *generated.Document) ([]ResolveReport, error) {
	if h.CheckDeadlineV1() != nil || tx == nil || doc == nil || doc.OrgID != h.snapshot.Identity.OrgID {
		return nil, ErrSourceFreshness
	}
	q := generated.New(tx)
	bindings, err := q.ListCRMMappingBindingsForShare(ctx, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil || len(bindings) == 0 || len(bindings) > 64 {
		return nil, ErrSourceFreshness
	}
	out := make([]ResolveReport, 0, len(bindings))
	for _, b := range bindings {
		if b == nil || b.DocumentID != doc.ID || !isCRMKind(b.SourceKind) || b.Fallback != "" {
			return nil, ErrSourceFreshness
		}
		value, proof, fence, err := crmValue(&h.snapshot, b)
		if err != nil {
			return nil, err
		}
		actual := *b
		out = append(out, ResolveReport{bindingSnapshot: &actual, crmFence: fence, CRMObservation: proof, Variable: b.VariableName, SourceKind: b.SourceKind, SourceRef: b.SourceRef, SourcePath: b.SourcePath, Value: value, ResolvedFrom: "source"})
	}
	if err = CheckCRMReports(ctx, q, doc.OrgID, out); err != nil {
		return nil, err
	}
	return out, nil
}
