// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
)

// The purpose is fixed by native callsites; no caller count or resource amount
// enters the producer. Recheck never grants later materialization authority.
type htmlStoredTemplatePurposeV1 uint8

const (
	htmlStoredTemplateCurrentV1 htmlStoredTemplatePurposeV1 = iota
	htmlStoredTemplateRecheckV1
	htmlStoredTemplatePreparationV1
)

func (p htmlStoredTemplatePurposeV1) coversV1(want htmlStoredTemplatePurposeV1) bool {
	return p <= htmlStoredTemplatePreparationV1 && want <= htmlStoredTemplatePreparationV1 && p >= want
}

// The fixed array is covered by the original native header loan. Source copies
// are made under the actual scoped body loan before exposing mutable DB models.
// No equality or later caller-mutated model grants new source authority.
type htmlAuthoringCanonicalSourceV1 struct {
	id                        uuid.UUID
	version                   int32
	revision                  bool
	digest                    [32]byte
	digestValid               bool
	purpose                   htmlStoredTemplatePurposeV1
	master, defaults          []byte
	content                   htmlmaster.TemplateCommitment
	started, ready, delivered bool
	reused, preparedDelivered bool
	prepared                  *htmlAuthoringPreparedRetainedTemplateV1
}

func (r *ApplicationHTMLAuthoringReaderV1) rememberCanonicalSourceV1(id uuid.UUID, version int32, revision bool, master, defaults, digest []byte) error {
	if r.canonicalCount >= len(r.canonicalSources) {
		return ErrHTMLAuthoringReadV1
	}
	var fixedDigest [32]byte
	copy(fixedDigest[:], digest)
	entry := htmlAuthoringCanonicalSourceV1{id: id, version: version, revision: revision, master: bytes.Clone(master), defaults: bytes.Clone(defaults), digest: fixedDigest, digestValid: len(digest) == 32}
	// Only a NEW genuine SQL-read entry may reuse this SAME reader's private
	// validated result. Caller-mutated public models and digest claims cannot
	// create this path; every raw byte, fixed digest and purpose must match.
	for i := r.canonicalCount - 1; i >= 0; i-- {
		previous := &r.canonicalSources[i]
		if previous.ready && htmlAuthoringCanonicalSameV1(previous, &entry) {
			entry.content = previous.content
			entry.prepared = previous.prepared
			entry.purpose = previous.purpose
			entry.ready = true
			entry.reused = true
			break
		}
	}
	r.canonicalSources[r.canonicalCount] = entry
	r.canonicalCount++
	return nil
}

// These fixed one-shot producers canonicalize only a model freshly read by this
// SAME native reader. They preserve original input spelling and SHA decisions,
// and expose neither arbitrary JSON nor caller work declarations. Each returned
// byte slice is a charged copy; caller mutation cannot alter the source owner.
func (r *ApplicationHTMLAuthoringReaderV1) CanonicalCurrentTemplateV1(ctx context.Context, id uuid.UUID, version int32) (htmlmaster.TemplateCommitment, error) {
	return r.canonicalSourceV1(ctx, id, version, false, htmlStoredTemplateCurrentV1)
}
func (r *ApplicationHTMLAuthoringReaderV1) CanonicalRetainedTemplateV1(ctx context.Context, id uuid.UUID, version int32) (htmlmaster.TemplateCommitment, error) {
	return r.canonicalSourceV1(ctx, id, version, true, htmlStoredTemplatePreparationV1)
}

// CanonicalRetainedTemplateRecheckV1 is the fixed final/recheck profile. Its
// callers compare immutable pins or read declarations/defaults; they never
// materialize from this result. Full preparation remains a separate producer.
func (r *ApplicationHTMLAuthoringReaderV1) CanonicalRetainedTemplateRecheckV1(ctx context.Context, id uuid.UUID, version int32) (htmlmaster.TemplateCommitment, error) {
	return r.canonicalSourceV1(ctx, id, version, true, htmlStoredTemplateRecheckV1)
}
func (r *ApplicationHTMLAuthoringReaderV1) canonicalSourceV1(ctx context.Context, id uuid.UUID, version int32, revision bool, purpose htmlStoredTemplatePurposeV1) (result htmlmaster.TemplateCommitment, failure error) {
	phase := "reader_identity"
	defer func() { failure = htmlCanonicalFailureV1(ctx, phase, failure) }()
	var empty htmlmaster.TemplateCommitment
	if r == nil || r.self != r {
		return empty, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	phase = "reader_scope"
	if !r.valid(ctx) {
		return empty, ErrHTMLAuthoringReadV1
	}
	var entry *htmlAuthoringCanonicalSourceV1
	for i := r.canonicalCount - 1; i >= 0; i-- {
		s := &r.canonicalSources[i]
		if s.id == id && s.version == version && s.revision == revision {
			entry = s
			break
		}
	}
	if entry == nil || entry.started || entry.delivered {
		phase = "reader_entry_missing"
		if entry != nil {
			phase = "reader_entry_delivered"
			if entry.started {
				phase = "reader_entry_started"
			}
		}
		return empty, ErrHTMLAuthoringReadV1
	}
	entry.started = true
	phase = "model_owner"
	owner, err := r.session.newHTMLCanonicalModelConsumerV1(ctx)
	if err != nil {
		return empty, err
	}
	// Install the genuine route consumer before any parser/inspection loan. The
	// factory retains producer recovery but never closes a live route consumer.
	r.closeConsumers = append(r.closeConsumers, owner.CloseConsumerV1)
	defer owner.finishV1()
	content := entry.content
	if entry.reused && entry.purpose.coversV1(purpose) {
		// The original parser/Compile/output grants remain live. Price THIS new
		// defensive byte-copy consumer before exposing another actual result.
		phase = "reused_copy_cost"
		cost, e := htmlAuthoringCanonicalCopyResourcesV1(content, 0, 0)
		if e != nil {
			return empty, e
		}
		if e = owner.holdAtV1(ctx, cost, "reused_copy_hold"); e != nil {
			return empty, e
		}
	} else {
		phase = "canonical_model"
		var e error
		content, e = owner.canonicalTemplateV1(ctx, entry.master, entry.defaults, entry.digest, entry.digestValid, purpose)
		if e != nil {
			return empty, e
		}
	}
	entry.content = content
	if !entry.purpose.coversV1(purpose) {
		entry.purpose = purpose
	}
	entry.ready = true
	entry.delivered = true
	return htmlmaster.TemplateCommitment{MasterJSON: bytes.Clone(content.MasterJSON), DefaultsJSON: bytes.Clone(content.DefaultsJSON), SHA256: content.SHA256}, nil
}

func htmlAuthoringCanonicalSameV1(a, b *htmlAuthoringCanonicalSourceV1) bool {
	return a != nil && b != nil && a.id == b.id && a.version == b.version && a.revision == b.revision && a.digestValid && b.digestValid && a.digest == b.digest && bytes.Equal(a.master, b.master) && bytes.Equal(a.defaults, b.defaults)
}
