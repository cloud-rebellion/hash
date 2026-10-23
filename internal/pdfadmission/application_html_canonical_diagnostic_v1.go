// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"sync"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

type htmlCanonicalDiagnosticKeyV1 struct{}
type htmlCanonicalDiagnosticObservationV1 struct {
	mu     sync.Mutex
	stage  string
	denial workguard.AdmissionDenialV1
}

// This optional observation grants no native work, source or retirement
// authority. Its only production caller is the explicit-prior API instantiate.
// The private holder contains no identifiers, source bytes, errors or aliases
// to native owners/coordinators. Every child context shares this one first
// refusal; separately constructed contexts never share an observation.
func WithHTMLCanonicalDiagnosticV1(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, htmlCanonicalDiagnosticKeyV1{}, &htmlCanonicalDiagnosticObservationV1{})
}

// Only fixed labels and numeric facts from the exact original admission
// decision cross the package boundary. These are not available-credit facts.
type HTMLCanonicalDiagnosticSnapshotV1 struct {
	Stage                                                                      string
	AtomicDecision                                                             bool
	Reason, Dimension                                                          uint8
	RequestedParentBytes, GlobalParentBytes, OrganisationParentBytes           int64
	GlobalParentLimit, OrganisationParentLimit                                 int64
	GlobalGrants, OrganisationGrants, GlobalGrantLimit, OrganisationGrantLimit int64
}

func HTMLCanonicalDiagnosticV1(ctx context.Context) HTMLCanonicalDiagnosticSnapshotV1 {
	o := htmlCanonicalObservationV1(ctx)
	if o == nil {
		return HTMLCanonicalDiagnosticSnapshotV1{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !htmlCanonicalStageV1(o.stage) {
		return HTMLCanonicalDiagnosticSnapshotV1{}
	}
	d := o.denial.SnapshotV1() // immutable same-decision value, never a live Snapshot
	return HTMLCanonicalDiagnosticSnapshotV1{Stage: o.stage, AtomicDecision: d.Reason != workguard.AdmissionNotDeniedV1,
		Reason: uint8(d.Reason), Dimension: uint8(d.Dimension), RequestedParentBytes: d.Requested.ParentBytes,
		GlobalParentBytes: d.Before.Global.ParentBytes, OrganisationParentBytes: d.Before.Organisation.ParentBytes,
		GlobalParentLimit: d.GlobalLimit.ParentBytes, OrganisationParentLimit: d.OrganisationLimit.ParentBytes,
		GlobalGrants: d.Before.GlobalGrants, OrganisationGrants: d.Before.OrganisationGrants,
		GlobalGrantLimit: d.GlobalGrantLimit, OrganisationGrantLimit: d.OrganisationGrantLimit}
}

func htmlCanonicalObservationV1(ctx context.Context) *htmlCanonicalDiagnosticObservationV1 {
	if ctx == nil {
		return nil
	}
	o, _ := ctx.Value(htmlCanonicalDiagnosticKeyV1{}).(*htmlCanonicalDiagnosticObservationV1)
	return o
}
func htmlCanonicalStageV1(stage string) bool {
	switch stage {
	case "reader_identity", "reader_scope", "reader_entry_missing", "reader_entry_started", "reader_entry_delivered",
		"model_owner", "owner_context", "owner_factory", "owner_state", "reused_copy_cost", "reused_copy_hold", "canonical_model",
		"model_hold", "model_scratch", "model_purpose", "model_digest",
		"parse_master_shape", "parse_master_cost", "parse_defaults_shape", "parse_defaults_cost", "parse_hold", "parse_decode", "parse_bounds",
		"inspection_cost", "inspection_hold", "inspection_scan", "canonical_cost", "canonical_scratch", "canonical_parse", "canonical_digest",
		"retention_cost", "retention_hold", "future_master_shape", "future_master_cost", "future_defaults_shape", "future_defaults_cost", "future_parse_hold",
		"future_decode", "future_inspection_cost", "future_inspection_hold", "future_inspection_scan", "future_canonical_cost", "future_canonical_scratch",
		"readiness_cost", "readiness_scratch", "future_retention_cost", "future_retention_hold":
		return true
	}
	return false
}
func htmlCanonicalRecordV1(ctx context.Context, stage string, denial workguard.AdmissionDenialV1) {
	o := htmlCanonicalObservationV1(ctx)
	if o == nil || !htmlCanonicalStageV1(stage) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stage == "" {
		o.stage = stage
		o.denial = denial
	}
}
func htmlCanonicalFailureV1(ctx context.Context, stage string, err error) error {
	if err != nil {
		htmlCanonicalRecordV1(ctx, stage, workguard.AdmissionDenialV1{})
	}
	return err // exact original error identity, Error/Is/As and nil behavior
}

// Called under the ORIGINAL factory/model locks with the ORIGINAL private
// parent delta. First use acquires ONE owner credit; later uses grow that same
// continuously retained credit atomically before allocation. Each path makes
// one decision, with no retry, refund, extra grant or changed byte limit.
func htmlCanonicalChargeV1(ctx context.Context, work *WorkAdmissionV1, org uuid.UUID, credit *workguard.GrantV1, additionalBytes int64, stage string) (*workguard.GrantV1, error) {
	if work == nil || work.coordinator == nil {
		htmlCanonicalRecordV1(ctx, stage, workguard.AdmissionDenialV1{})
		return nil, workguard.ErrUnavailableV1
	}
	observed := htmlCanonicalObservationV1(ctx) != nil
	var denial workguard.AdmissionDenialV1
	var err error
	if credit == nil {
		if observed {
			credit, denial, err = work.coordinator.TryAcquireWithDenialV1(ctx, org, workguard.VectorV1{ParentBytes: additionalBytes})
		} else {
			credit, err = work.coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: additionalBytes})
		}
	} else {
		if observed {
			denial, err = credit.TryGrowParentWithDenialV1(ctx, additionalBytes)
		} else {
			err = credit.TryGrowParentV1(ctx, additionalBytes)
		}
	}
	if err != nil {
		htmlCanonicalRecordV1(ctx, stage, denial)
		return nil, err
	}
	return credit, nil
}
