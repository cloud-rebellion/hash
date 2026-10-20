// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"unsafe"
)

func historicalFinalizingRoleCommitmentV1(parent, child *generated.Document) error {
	if parent == nil || child == nil {
		return ErrHTMLSendWorkV1
	}
	matched := false
	switch parent.Status {
	case "completed":
		matched = child.Status == "completed"
	case "finalizing":
		matched = child.Status == "finalizing"
	case "sent", "in_progress", "changes_requested":
		matched = child.Status == "sent" || child.Status == "in_progress"
	}
	if !matched {
		return fmt.Errorf("resolve signer roles: child %s status %s does not match envelope status %s", child.ID, child.Status, parent.Status)
	}
	if parent.Status != "finalizing" {
		return nil
	}
	for _, d := range []*generated.Document{parent, child} {
		if !d.CompletionEffectiveAtBound {
			return errors.New("completion-effective timestamp is not bound across the envelope family")
		}
		if !d.CompletionEffectiveAt.Valid || d.CompletionEffectiveAt.Time.IsZero() {
			return errors.New("completion-effective timestamp is unavailable")
		}
		if !d.FinalizationRetainUntil.Valid || d.FinalizationRetainUntil.Time.IsZero() {
			return errors.New("finalization retention deadline is unavailable")
		}
		if d.FinalizationRetainUntil.Time.UTC().Nanosecond() != 0 {
			return errors.New("finalization retention deadline must use whole-second precision")
		}
		if !d.FinalizationRetainUntil.Time.Equal(storage.EvidenceRetentionDeadline(d.CompletionEffectiveAt.Time, article13.RetentionYearsV1)) {
			return errors.New("finalization retention deadline does not match completion commitment")
		}
	}
	if !parent.CompletionEffectiveAt.Time.Equal(child.CompletionEffectiveAt.Time) {
		return errors.New("completion-effective timestamp differs from the envelope")
	}
	if !parent.FinalizationRetainUntil.Time.Equal(child.FinalizationRetainUntil.Time) {
		return errors.New("retention deadline differs from the envelope")
	}
	return nil
}

// M67's existing BEFORE UPDATE trigger owns each row clock independently of
// the SQL's requested updated_at. Completion/retention still copy the root's
// exact legal commitments; only this returned actual monotonic row clock varies.
func historicalFinalizationChildFreezeTupleV1(old, child, parent *generated.Document) bool {
	if old == nil || child == nil || parent == nil || !old.UpdatedAt.Valid || !child.UpdatedAt.Valid || child.UpdatedAt.Time.IsZero() || !child.UpdatedAt.Time.After(old.UpdatedAt.Time) {
		return false
	}
	want := *old
	want.Status = "finalizing"
	want.CompletionEffectiveAtBound = parent.CompletionEffectiveAtBound
	want.CompletionEffectiveAt = parent.CompletionEffectiveAt
	want.FinalizationRetainUntil = parent.FinalizationRetainUntil
	want.UpdatedAt = child.UpdatedAt
	return htmlSendDocumentExactTupleEqualV1(&want, child)
}
func (w *ApplicationHTMLSendWorkV1) HistoricalFinalizationMembersV1(call context.Context) ([]*generated.Document, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	if w.familyRoot != nil || !w.sourceDocument.IsEnvelope {
		w.mu.Unlock()
		return nil, nil
	}
	if state.memberViews != nil {
		rows := state.memberViews
		w.mu.Unlock()
		return rows, nil
	}
	attempted := w.familyMembersAttempted
	w.mu.Unlock()
	if !attempted {
		if _, err = w.ReadEnvelopeMembersV1(call); err != nil {
			return nil, err
		}
	}
	w.mu.Lock()
	members := w.familyMembers
	w.mu.Unlock()
	if len(members) == 0 {
		return nil, errors.New("claim finalization: envelope has no children")
	}
	views := make([]*generated.Document, len(members))
	for i, member := range members {
		if member == nil {
			return nil, ErrHTMLSendWorkV1
		}
		member.mu.Lock()
		read := member.modelsRead
		member.mu.Unlock()
		if !read {
			if _, err = member.ReadModelsV1(call); err != nil {
				return nil, err
			}
		}
		member.mu.Lock()
		views[i] = member.models.Document
		member.mu.Unlock()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.finalization != state {
		return nil, ErrHTMLSendWorkV1
	}
	state.memberViews = views
	return views, nil
}

// Only exact native readiness on this actual root can drive the existing
// atomic transition. Every prospective root/member RETURNING body is admitted
// before the first SQL write; no caller rows or reported byte sizes are used.
func (w *ApplicationHTMLSendWorkV1) BeginHistoricalFinalizingV1(call context.Context) (*generated.Document, []*generated.Document, error) {
	if w == nil || w.self != w {
		return nil, nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	if w.stage.purpose != HTMLHistoricalFinalizationClaimV1 || w.familyRoot != nil || !state.ready || state.beginAttempted || w.sourceDocument.Status != "in_progress" {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	state.beginAttempted = true
	before := w.sourceDocument
	members := w.familyMembers
	if before.IsEnvelope && (!w.familyMembersAttempted || len(members) == 0 || len(state.memberViews) != len(members)) {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	w.mu.Unlock()
	row, frozen, err := w.beginHistoricalFinalizingRowsV1(call, before, members)
	if err != nil {
		return nil, nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.finalization != state {
		return nil, nil, ErrHTMLSendWorkV1
	}
	state.claimed = htmlSendCloneDocumentV1(row)
	return row, frozen, nil
}

// The original claim and a genuine post-audit response use this same private
// transition only after their independent fresh readiness checks. It issues no
// Claim/StageReference authority; the exported Claim guard stays unchanged.
func (w *ApplicationHTMLSendWorkV1) beginHistoricalFinalizingRowsV1(call context.Context, before *generated.Document, members []*ApplicationHTMLSendWorkV1) (*generated.Document, []*generated.Document, error) {
	w.mu.Lock()
	if !w.valid(call) || before == nil || w.sourceDocument != before || before.Status != "in_progress" || w.familyRoot != nil || before.ParentEnvelopeID.Valid || len(members) != len(w.familyMembers) {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	for i, member := range members {
		if member == nil || member != w.familyMembers[i] {
			w.mu.Unlock()
			return nil, nil, ErrHTMLSendWorkV1
		}
	}
	raw, _, err := w.admitDocumentReturnV1(call, int64(len("finalizing")))
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	bookkeeping := int64(0)
	if !htmlInputAddV1(&bookkeeping, int64(len(members)), 8*int64(unsafe.Sizeof((*generated.Document)(nil)))+8*int64(unsafe.Sizeof(uuid.UUID{}))+8*int64(unsafe.Sizeof(int64(0)))) {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	closeBookkeeping, err := w.actor.acquireOwnedRetainedBodyV1(call, bookkeeping, 0)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	w.closes = append(w.closes, closeBookkeeping)
	w.sourceBorrowers++
	w.mu.Unlock()
	borrowed := make([]bool, len(members))
	defer func() {
		for i, member := range members {
			if !borrowed[i] {
				continue
			}
			member.mu.Lock()
			member.sourceBorrowers--
			closes, actor := member.retireSourcesLockedV1()
			member.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			member.releaseFamilyRootIfRetiredV1()
		}
		w.mu.Lock()
		w.sourceBorrowers--
		closes, actor := w.retireSourcesLockedV1()
		w.mu.Unlock()
		htmlSendCloseSourceResourcesV1(closes, actor)
		w.releaseFamilyRootIfRetiredV1()
	}()
	raws := make([]int64, len(members))
	seen := make([]bool, len(members))
	for i, member := range members {
		member.mu.Lock()
		d := member.sourceDocument
		if !member.valid(call) || member.familyRoot != w || d == nil || d.OrgID != before.OrgID || d.IsEnvelope || !d.ParentEnvelopeID.Valid || uuid.UUID(d.ParentEnvelopeID.Bytes) != before.ID || d.DeletedAt.Valid || (d.Status != "sent" && d.Status != "in_progress") {
			member.mu.Unlock()
			return nil, nil, ErrHTMLSendWorkV1
		}
		member.sourceBorrowers++
		borrowed[i] = true
		raws[i], _, err = member.admitDocumentReturnV1(call, int64(len("finalizing")))
		member.mu.Unlock()
		if err != nil {
			return nil, nil, err
		}
	}
	row, err := w.queries.BeginDocumentFinalization(call, generated.BeginDocumentFinalizationParams{RetentionYears: article13.RetentionYearsV1, ID: before.ID, OrgID: before.OrgID})
	if err != nil {
		return nil, nil, err
	}
	expected := *before
	if row == nil {
		return nil, nil, ErrHTMLSendWorkV1
	}
	expected.Status = row.Status
	expected.CompletionEffectiveAtBound = row.CompletionEffectiveAtBound
	expected.CompletionEffectiveAt = row.CompletionEffectiveAt
	expected.FinalizationRetainUntil = row.FinalizationRetainUntil
	expected.UpdatedAt = row.UpdatedAt
	if !w.verifyDocumentReturnV1(row, raw) || row.Status != "finalizing" || !row.CompletionEffectiveAtBound || !row.CompletionEffectiveAt.Valid || !row.FinalizationRetainUntil.Valid || !htmlSendDocumentExactTupleEqualV1(&expected, row) {
		return nil, nil, ErrHTMLSendWorkV1
	}
	var frozen []*generated.Document
	if before.IsEnvelope {
		frozen, err = w.queries.BeginEnvelopeChildrenFinalization(call, generated.BeginEnvelopeChildrenFinalizationParams{ParentEnvelopeID: pgtype.UUID{Bytes: before.ID, Valid: true}, OrgID: before.OrgID})
		if err != nil {
			return nil, nil, err
		}
		if len(frozen) != len(members) {
			return nil, nil, fmt.Errorf("envelope child freeze updated %d of %d children", len(frozen), len(members))
		}
		for _, child := range frozen {
			index := blockSendFamilyReturnedIndexV1(members, child)
			if index < 0 || seen[index] {
				return nil, nil, ErrHTMLSendWorkV1
			}
			seen[index] = true
			member := members[index]
			member.mu.Lock()
			old := member.sourceDocument
			valid := member.verifyDocumentReturnV1(child, raws[index]) && historicalFinalizationChildFreezeTupleV1(old, child, row)
			member.mu.Unlock()
			if !valid {
				return nil, nil, ErrHTMLSendWorkV1
			}
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceDocument != before {
		return nil, nil, ErrHTMLSendWorkV1
	}
	return row, frozen, nil
}
