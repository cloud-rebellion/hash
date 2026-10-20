// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// This file adds only actual one-level membership to the existing Send owner.
// Work's private familyRoot/memberDocument/familyPin fields are populated here,
// never from a caller document or UUID. Physical session/stage/admission identity
// remains the original root's; member source/body methods must check this proof.
//
// Parent integration must:
//   - use logicalDocumentV1() in fixed member reads, never mutate session.document;
//   - permit the member's actual parent scalar in ReadModelsV1, comparing its full
//     document to familyPin before exposing it; original unsupported child business
//     guards still inspect genuine full bodies;
//   - close registered familyMembers before root source consumers, and keep that
//     registry until actual root resource retirement;
//   - invoke releaseFamilyRootIfRetiredV1 AFTER native body/actor closes in both
//     Work.CloseConsumerV1 and its original source-borrower retirement callback.
func (w *ApplicationHTMLSendWorkV1) ReadEnvelopeMembersV1(call context.Context) ([]*ApplicationHTMLSendWorkV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	var out []*ApplicationHTMLSendWorkV1
	w.mu.Lock()
	rootLocked := true
	defer func() {
		if rootLocked {
			w.mu.Unlock()
		}
		// Every registered partial constructor has exactly one temporary borrower.
		// Join all of them on success, refusal and cancellation before permitting
		// either member bodies or the root registry allowance to retire.
		for _, member := range out {
			if member == nil {
				continue
			}
			member.mu.Lock()
			member.sourceBorrowers--
			closes, actor := member.retireSourcesLockedV1()
			member.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			member.releaseFamilyRootIfRetiredV1()
		}
	}()
	if !w.valid(call) || w.familyRoot != nil || w.memberDocument != uuid.Nil ||
		w.familyMembersAttempted || w.state == nil || !w.state.IsEnvelope ||
		w.state.ParentEnvelopeID.Valid || w.sourceDocument == nil || w.models == nil ||
		!w.sourceDocument.IsEnvelope || w.sourceDocument.ParentEnvelopeID.Valid ||
		w.sourceDocument.ID != w.session.state.document ||
		w.sourceDocument.OrgID != w.session.state.org {
		return nil, ErrHTMLSendWorkV1
	}
	w.familyMembersAttempted = true
	s := w.session.state
	// The already-owned positive root authoring header contains the larger
	// concrete M94 scalar-header class. This query returns only fixed identities,
	// a timestamp and COUNT; no dynamic member list or body has been allocated yet.
	if unsafe.Sizeof(generated.GetBlockSendFamilyMemberCountV1Row{}) >
		unsafe.Sizeof(generated.GetHTMLRevisionDocumentReadHeaderV1Row{}) {
		return nil, ErrHTMLSendWorkV1
	}
	count, err := w.queries.GetBlockSendFamilyMemberCountV1(call, generated.GetBlockSendFamilyMemberCountV1Params{
		DocumentID: s.document, OrgID: s.org,
	})
	if err != nil {
		return nil, err
	}
	if count == nil || count.DocumentID != s.document || count.OrgID != s.org ||
		count.UpdatedAt != w.state.UpdatedAt || count.UpdatedAt != w.sourceDocument.UpdatedAt ||
		count.MemberCount < 0 || w.sourceBorrowers < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	raw, err := blockSendFamilySlotBytesV1(count.MemberCount)
	if err != nil {
		return nil, err
	}
	// This internal amount is derived only from the genuine scalar COUNT and
	// actual fixed native result/owner types. The existing retained-body grant
	// includes independent positive typed and DB classes even for zero members.
	// The concrete per-member fixed-type sum also dominates this query's scalar
	// row wire (UUID/timestamp/boolean/integer fields and <=17-byte status), so
	// DB staging grows with the actual member count before materialized pins.
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	var pins []*generated.ListBlockSendFamilyMemberPinsV1Row
	params := generated.ListBlockSendFamilyMemberPinsV1Params{DocumentID: s.document, OrgID: s.org, ExpectedUpdatedAt: count.UpdatedAt, ExpectedCount: count.MemberCount}
	if w.stage.purpose == HTMLHistoricalFinalizationClaimV1 || w.stage.purpose == HTMLHistoricalFinalizationResumeV1 || w.stage.purpose == HTMLHistoricalFinalizationPublicationV1 || w.stage.purpose == HTMLHistoricalFinalizationSourceV1 || w.stage.purpose == HTMLBlockSignMutationV1 || w.stage.purpose == HTMLAcknowledgementMutationV1 || w.stage.purpose == HTMLReminderManualV1 || w.stage.purpose == HTMLReminderScheduledV1 {
		var actual []*generated.ListHistoricalFinalizationFamilyMemberPinsV1Row
		actual, err = w.queries.ListHistoricalFinalizationFamilyMemberPinsV1(call, generated.ListHistoricalFinalizationFamilyMemberPinsV1Params(params))
		if err == nil {
			pins = make([]*generated.ListBlockSendFamilyMemberPinsV1Row, len(actual))
			for i, row := range actual {
				if row != nil {
					copy := generated.ListBlockSendFamilyMemberPinsV1Row(*row)
					pins[i] = &copy
				}
			}
		}
	} else {
		pins, err = w.queries.ListBlockSendFamilyMemberPinsV1(call, params)
	}
	if err != nil {
		return nil, err
	}
	if int64(len(pins)) != count.MemberCount || count.MemberCount > math.MaxInt64-int64(w.sourceBorrowers) {
		return nil, ErrHTMLSendWorkV1
	}
	// Native SQL establishes PK uniqueness and the unchanged membership ordering.
	// The registry and returned view have separate backing: callers cannot rewrite
	// the private list used for source ownership and cancellation/last-use joining.
	w.familyMembers = make([]*ApplicationHTMLSendWorkV1, 0, len(pins))
	out = make([]*ApplicationHTMLSendWorkV1, len(pins))
	for i, pin := range pins {
		if pin == nil || pin.ID == uuid.Nil || pin.ID == s.document ||
			pin.OrgID != s.org || pin.ParentDocumentID != s.document ||
			!pin.ParentEnvelopeID.Valid || uuid.UUID(pin.ParentEnvelopeID.Bytes) != s.document ||
			len(pin.BoundedStatus) > 17 {
			return nil, ErrHTMLSendWorkV1
		}
		member := &ApplicationHTMLSendWorkV1{
			call: call, session: w.session, stage: w.stage, queries: w.queries,
			familyRoot: w, memberDocument: pin.ID, familyPin: pin, sourceBorrowers: 1,
		}
		member.self = member
		// Capture the member BEFORE its fixed header/state or any expanded body can
		// be produced. Root cancellation can therefore find every partial constructor.
		w.familyMembers = append(w.familyMembers, member)
		out[i] = member
		w.sourceBorrowers++
		root := w
		var once sync.Once
		member.familyReleaseRoot = func() {
			once.Do(func() {
				root.mu.Lock()
				root.sourceBorrowers--
				closes, actor := root.retireSourcesLockedV1()
				root.mu.Unlock()
				htmlSendCloseSourceResourcesV1(closes, actor)
				root.releaseFamilyRootIfRetiredV1()
			})
		}
	}
	// Root ownership is fully registered before any child header/state query.
	// Do not hold root.mu while acquiring a member mutex or doing child SQL.
	w.mu.Unlock()
	rootLocked = false
	for _, member := range out {
		member.mu.Lock()
		if member.closed || member.resourcesClosed {
			member.mu.Unlock()
			return nil, ErrHTMLSendWorkV1
		}
		// This creates only an independently owned native header on the SAME real
		// root session. There is no child OpenV1, synthetic Tx or pool fallback.
		actor, e := w.session.NewHTMLAuthoringReaderV1(call)
		if e != nil {
			member.mu.Unlock()
			return nil, errors.Join(ErrHTMLSendWorkV1, e)
		}
		member.actor = actor
		pin := member.familyPin
		state, e := w.queries.GetHTMLSendDocumentStateHeaderV1(call, generated.GetHTMLSendDocumentStateHeaderV1Params{
			DocumentID: pin.ID, OrgID: s.org,
		})
		if e != nil {
			member.mu.Unlock()
			return nil, e
		}
		if !blockSendFamilyStateMatchesPinV1(pin, state) {
			member.mu.Unlock()
			return nil, ErrHTMLSendWorkV1
		}
		member.state = state
		member.mu.Unlock()
	}
	return out, nil
}

func blockSendFamilyStateMatchesPinV1(pin *generated.ListBlockSendFamilyMemberPinsV1Row, state *generated.GetHTMLSendDocumentStateHeaderV1Row) bool {
	return pin != nil && state != nil &&
		state.ID == pin.ID && state.OrgID == pin.OrgID &&
		state.UpdatedAt == pin.UpdatedAt && state.ExpiresAt == pin.ExpiresAt &&
		state.SenderID == pin.SenderID && state.IsEnvelope == pin.IsEnvelope &&
		state.ParentEnvelopeID == pin.ParentEnvelopeID &&
		state.RequiresSignature == pin.RequiresSignature && state.HasHtmlSource == pin.HasHtmlSource &&
		state.IsPdfSource == pin.IsPdfSource && state.BoundedStatus == pin.BoundedStatus &&
		state.EvidenceVersionPinsRequired == pin.EvidenceVersionPinsRequired &&
		state.SentAt == pin.SentAt && state.Article13NoticeEpochAt == pin.Article13NoticeEpochAt &&
		state.Article13NoticeEpochV61Committed == pin.Article13NoticeEpochV61Committed &&
		state.HasSupportedArticle13NoticeSchema == pin.HasSupportedArticle13NoticeSchema
}

// The fixed class covers SQLC old/new result slices, both private/public member
// lists, actual per-member state/pin and Work/reader headers, callback/once state,
// and the two independently decoded <=17-byte status strings. Dynamic document,
// collection, resolver and source producers require their separate native loans.
func blockSendFamilySlotBytesV1(count int64) (int64, error) {
	if count < 0 {
		return 0, ErrHTMLSendWorkV1
	}
	per := int64(0)
	for _, n := range []int64{
		4 * int64(unsafe.Sizeof((*generated.ListBlockSendFamilyMemberPinsV1Row)(nil))),
		2 * int64(unsafe.Sizeof(generated.ListBlockSendFamilyMemberPinsV1Row{})),
		4 * int64(unsafe.Sizeof((*ApplicationHTMLSendWorkV1)(nil))),
		2 * int64(unsafe.Sizeof(ApplicationHTMLSendWorkV1{})),
		2 * int64(unsafe.Sizeof(ApplicationHTMLAuthoringReaderV1{})),
		2 * int64(unsafe.Sizeof(applicationHTMLAuthoringBodyHeaderV1{})),
		2 * int64(unsafe.Sizeof(generated.GetHTMLSendDocumentStateHeaderV1Row{})),
		2 * int64(unsafe.Sizeof(sync.Once{})),
		16 * int64(unsafe.Sizeof(uintptr(0))), 34,
	} {
		if !htmlInputAddV1(&per, n, 1) {
			return 0, ErrHTMLSendWorkV1
		}
	}
	total := int64(0)
	if !htmlInputAddV1(&total, count, per) {
		return 0, ErrHTMLSendWorkV1
	}
	return total, nil
}

// Called only AFTER this member's native body/actor closes, and only when its
// actual source borrowers have joined and resourcesClosed is authoritative.
// Cancellation, copied shell closure and physical SQL close alone never release
// the root's still-live member registry/slot allowance.
func (w *ApplicationHTMLSendWorkV1) releaseFamilyRootIfRetiredV1() {
	if w == nil || w.self != w {
		return
	}
	w.mu.Lock()
	if !w.resourcesClosed || w.familyReleaseRoot == nil {
		w.mu.Unlock()
		return
	}
	release := w.familyReleaseRoot
	w.familyReleaseRoot = nil
	w.familyPin = nil
	w.familyRoot = nil
	w.mu.Unlock()
	release()
}
