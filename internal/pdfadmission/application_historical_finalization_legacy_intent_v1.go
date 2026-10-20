// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"unsafe"
)

// SQL timestamptz equality is instant/finite equality, including nullable clocks.
func historicalIntentClockEqualV1(a, b pgtype.Timestamptz) bool {
	return a.Valid == b.Valid && (!a.Valid || (a.InfinityModifier == b.InfinityModifier && a.Time.Equal(b.Time)))
}

func historicalLegacyIntentHasPinsV1(i *generated.DocumentFinalizationIntent) bool {
	return i != nil && i.EvidenceVersionPinsRequired &&
		i.FinalPdfVersionID.Valid && strings.TrimSpace(i.FinalPdfVersionID.String) != "" &&
		i.AuditCertVersionID.Valid && strings.TrimSpace(i.AuditCertVersionID.String) != "" &&
		i.AuditPayloadVersionID.Valid && strings.TrimSpace(i.AuditPayloadVersionID.String) != "" &&
		i.AuditSignatureVersionID.Valid && strings.TrimSpace(i.AuditSignatureVersionID.String) != ""
}

// Only the original four version columns, their required bit and the finite
// UPDATE clock can change. Preserve every retained original/artifact/legal,
// checkpoint/failure and optional fitted column, including their byte bodies.
func historicalLegacyIntentPinTupleV1(before, after *generated.DocumentFinalizationIntent, versions [4]string) bool {
	if before == nil || after == nil || !historicalLegacyIntentHasPinsV1(after) || !applicationStampV1(after.UpdatedAt) {
		return false
	}
	return after.DocumentID == before.DocumentID && after.OrgID == before.OrgID && after.Mode == before.Mode &&
		after.FinalPdfKey == before.FinalPdfKey && bytes.Equal(after.FinalPdfSha256, before.FinalPdfSha256) &&
		after.AuditCertKey == before.AuditCertKey && bytes.Equal(after.AuditCertSha256, before.AuditCertSha256) &&
		after.AuditPayloadKey == before.AuditPayloadKey && bytes.Equal(after.AuditPayloadSha256, before.AuditPayloadSha256) &&
		after.AuditSignatureKey == before.AuditSignatureKey && bytes.Equal(after.AuditSignatureSha256, before.AuditSignatureSha256) &&
		historicalIntentClockEqualV1(after.RetentionStartedAt, before.RetentionStartedAt) && historicalIntentClockEqualV1(after.RetentionCompletedAt, before.RetentionCompletedAt) &&
		after.Attempts == before.Attempts && after.LastError == before.LastError && historicalIntentClockEqualV1(after.CreatedAt, before.CreatedAt) &&
		historicalIntentClockEqualV1(after.CompletionEffectiveAt, before.CompletionEffectiveAt) && historicalIntentClockEqualV1(after.RetainUntil, before.RetainUntil) &&
		after.FittedPreparationID == before.FittedPreparationID && after.FitsIndexStorageKey == before.FitsIndexStorageKey &&
		after.FitsIndexVersionID == before.FitsIndexVersionID && bytes.Equal(after.FitsIndexSha256, before.FitsIndexSha256) && after.FitsIndexBytes == before.FitsIndexBytes &&
		after.FinalPdfVersionID.String == versions[0] && after.AuditCertVersionID.String == versions[1] &&
		after.AuditPayloadVersionID.String == versions[2] && after.AuditSignatureVersionID.String == versions[3]
}

// This is the original one-time digest-history compatibility bridge, using
// only a genuine Source24 root's native intent and concrete provider. No caller
// intent, key, version, cost, transaction or completion flag supplies authority.
// It is called at the original post-source/signature/family compatibility gate.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) EnsureIntentVersionsV1(call context.Context) (*generated.DocumentFinalizationIntent, error) {
	if e == nil || e.self != e {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer e.unlockV1()
	if !e.validV1() || !e.sourceChecked || e.intentVersionsAttempted {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	e.intentVersionsAttempted = true
	w := e.work
	if _, err := w.ReadHistoricalFinalizationIntentV1(call); err != nil {
		return nil, err
	}
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil || state.intent == nil || state.intentView == nil || w.familyRoot != nil {
		w.mu.Unlock()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	before, view := state.intent, state.intentView
	w.mu.Unlock()
	if before.EvidenceVersionPinsRequired {
		if !historicalLegacyIntentHasPinsV1(before) {
			return nil, errors.New("resume finalization: pinned intent is missing an object VersionId")
		}
		e.intentVersionOriginal = before
		e.intentVersionPinned = before
		return view, nil
	}
	if before.FinalPdfVersionID.Valid || before.AuditCertVersionID.Valid || before.AuditPayloadVersionID.Valid || before.AuditSignatureVersionID.Valid {
		return nil, errors.New("resume finalization: legacy intent has a partial VersionId set")
	}
	// The private old full row already has its actual header/body allowance.
	// Price CAS/possible reload/private copies plus all four bounded provider
	// version texts before expanding a returned row or issuing that UPDATE.
	raw, err := historicalFinalizationIntentRawV1(before)
	if err != nil {
		return nil, err
	}
	returnRaw := raw
	if !htmlInputAddV1(&returnRaw, e.limits.VersionIDBytes, 4) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	parent := int64(0)
	if !htmlInputAddV1(&parent, returnRaw, 5) || !htmlInputAddV1(&parent, 1, 5*int64(unsafe.Sizeof(generated.DocumentFinalizationIntent{}))+2*int64(unsafe.Sizeof(generated.PinLegacyDocumentFinalizationIntentVersionsParams{}))+2*int64(unsafe.Sizeof(generated.GetDocumentFinalizationIntentParams{}))+4*int64(unsafe.Sizeof([4]string{}))) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.finalization != state || state.intent != before {
		w.mu.Unlock()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	closeReturn, err := w.actor.acquireOwnedRetainedBodyV1(call, parent, returnRaw)
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	w.closes = append(w.closes, closeReturn)
	w.mu.Unlock()
	var versions [4]string
	artifacts := [4]struct {
		key    string
		digest []byte
	}{{before.FinalPdfKey, before.FinalPdfSha256}, {before.AuditCertKey, before.AuditCertSha256}, {before.AuditPayloadKey, before.AuditPayloadSha256}, {before.AuditSignatureKey, before.AuditSignatureSha256}}
	for index, artifact := range artifacts {
		stored, err := e.readV1(artifact.key, "", artifact.digest, true, nil)
		if err != nil {
			return nil, fmt.Errorf("resume finalization: resolve legacy version for %q: %w", artifact.key, err)
		}
		if strings.TrimSpace(stored.VersionID) == "" {
			return nil, fmt.Errorf("resume finalization: resolve legacy version for %q returned no VersionId", artifact.key)
		}
		versions[index] = stored.VersionID
	}
	pinned, err := w.queries.PinLegacyDocumentFinalizationIntentVersions(call, generated.PinLegacyDocumentFinalizationIntentVersionsParams{FinalPdfVersionID: pgtype.Text{String: versions[0], Valid: true}, AuditCertVersionID: pgtype.Text{String: versions[1], Valid: true}, AuditPayloadVersionID: pgtype.Text{String: versions[2], Valid: true}, AuditSignatureVersionID: pgtype.Text{String: versions[3], Valid: true}, DocumentID: before.DocumentID, OrgID: before.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		pinned, err = w.queries.GetDocumentFinalizationIntent(call, generated.GetDocumentFinalizationIntentParams{DocumentID: before.DocumentID, OrgID: before.OrgID})
	}
	if err != nil {
		return nil, fmt.Errorf("resume finalization: persist legacy VersionIds: %w", err)
	}
	n, err := historicalFinalizationIntentRawV1(pinned)
	if err != nil || n > returnRaw || !historicalLegacyIntentPinTupleV1(before, pinned, versions) {
		return nil, errors.New("resume finalization: persisted VersionIds do not match resolved artifacts")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.finalization != state || state.intent != before {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	state.intent = historicalFinalizationCloneIntentV1(pinned)
	state.intentView = pinned
	e.intentVersionOriginal = before
	e.intentVersionPinned = state.intent
	return pinned, nil
}
