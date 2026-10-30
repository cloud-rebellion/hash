// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// The declaration comes from the actual admitted Apply body. Values are never
// accepted from a caller map: the fixed producer selects them from the protected
// client's concrete snapshot using only this body's exact mappings. The route's
// original review digest, account/CAS and fresh transaction gates still decide
// whether applying that observation is authorized.
type htmlCRMRevisionInputV1 struct {
	ExpectedOrgID                uuid.UUID `json:"expected_org_id"`
	ExpectedUserID               uuid.UUID `json:"expected_user_id"`
	ExpectedUpdatedAt            string    `json:"expected_updated_at"`
	ExpectedHTMLSourceCommitment string    `json:"expected_html_source_commitment"`
	ExpectedConnectionID         string    `json:"expected_connection_id"`
	ExpectedConnectionGeneration string    `json:"expected_connection_generation"`
	ReviewedDigest               string    `json:"reviewed_digest"`
	Confirmed                    bool      `json:"confirmed"`
}

type htmlCRMRevisionMappingV1 struct {
	Variable   string `json:"variable"`
	SourceKind string `json:"source_kind"`
	SourceRef  string `json:"source_ref"`
	SourcePath string `json:"source_path"`
}

// The block-value/mapping-only route has exactly one original transaction.
// Its real input capture is identical to HTML CRM revision, but only the final
// Mutation stage is legal; ordinary/HTML four-stage ordering is unchanged.
func (f *ApplicationSessionFactoryV1) NewCRMDocumentValuesOperationV1(ctx context.Context, org, document, actor uuid.UUID, input *ApplicationHTMLAuthoringInputV1, snapshot *crmconnection.Snapshot) (*ApplicationHTMLRevisionOperationV1, error) {
	op, err := f.NewHTMLCRMRevisionOperationV1(ctx, org, document, actor, input, snapshot)
	if err != nil {
		return nil, err
	}
	op.state.crmValuesOnly = true
	return op, nil
}

// Count actual retained typed provider strings/maps and the scalar extraction
// before copying or selecting them. The protected client already bounds every
// response; these are logical native loans, not larger input/runtime limits or
// a claim of measured process/provider capacity. Original snapshot retention,
// selection scratch and the detached declaration coexist until source retirement.
func htmlCRMRevisionSnapshotResourcesV1(snapshot *crmconnection.Snapshot) (int64, error) {
	if snapshot == nil {
		return 4096, nil // Explicit mapping-only/unlink has no provider response.
	}
	if len(snapshot.Records) > crmconnection.MaxUniqueRecords {
		return 0, ErrHTMLRevisionOperationV1
	}
	n := int64(unsafe.Sizeof(*snapshot)) + 4096
	text := func(value string) bool { return htmlRevisionRetentionAllocV1(&n, int64(len(value))) }
	for _, value := range [...]string{snapshot.Identity.Origin, snapshot.Identity.CRMTeamID, snapshot.Identity.CRMUserID,
		snapshot.CredentialBefore.CRMUserID, snapshot.CredentialBefore.CRMTeamID, snapshot.CredentialBefore.Name, snapshot.CredentialBefore.Email, snapshot.CredentialBefore.BodySHA256,
		snapshot.CredentialAfter.CRMUserID, snapshot.CredentialAfter.CRMTeamID, snapshot.CredentialAfter.Name, snapshot.CredentialAfter.Email, snapshot.CredentialAfter.BodySHA256} {
		if !text(value) {
			return 0, ErrHTMLRevisionOperationV1
		}
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(snapshot.Records))*int64(unsafe.Sizeof(crmconnection.RecordObservation{}))) {
		return 0, ErrHTMLRevisionOperationV1
	}
	for _, record := range snapshot.Records {
		for _, value := range [...]string{string(record.Kind), record.ID, record.CRMTeamID, record.BodySHA256} {
			if !text(value) {
				return 0, ErrHTMLRevisionOperationV1
			}
		}
		for _, fields := range []map[string]crmconnection.Scalar{record.Fields, record.Relationships} {
			// Original map plus fixed selection/copy output, including growth slots.
			slots := 2 * htmlInputPowerV1(max(8, (int64(len(fields))*8+6)/7))
			if !htmlInputAddV1(&n, slots, 2*128) || !htmlInputAddV1(&n, 1, 2*16*256) {
				return 0, ErrHTMLRevisionOperationV1
			}
			for key, scalar := range fields {
				if !text(key) || !text(scalar.Value) {
					return 0, ErrHTMLRevisionOperationV1
				}
			}
		}
	}
	// Retain the original typed snapshot and bounded extraction/selection scratch
	// together; cloned scalar strings share no mutable map with the server caller.
	if !htmlInputAddV1(&n, n, 3) {
		return 0, ErrHTMLRevisionOperationV1
	}
	return htmlRevisionRetentionFinishV1(n)
}

func (f *ApplicationSessionFactoryV1) NewHTMLCRMRevisionOperationV1(ctx context.Context, org, document, actor uuid.UUID, input *ApplicationHTMLAuthoringInputV1, snapshot *crmconnection.Snapshot) (*ApplicationHTMLRevisionOperationV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || document == uuid.Nil || actor == uuid.Nil || input == nil || input.state == nil || !applicationContextV1(ctx) {
		return nil, ErrHTMLRevisionOperationV1
	}
	p, state := f.state, input.state
	p.mu.Lock()
	state.mu.Lock()
	_, registered := p.htmlInputProducers[state]
	if !registered || p.closing || p.work == nil || p.work.coordinator == nil || state.factory != p || state.org != org || state.profile != HTMLCRMDocumentApplyInputV1 || state.consumerClosed || state.retired || !state.ready || len(state.raw) == 0 {
		state.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLRevisionOperationV1
	}
	cost, err := htmlCRMRevisionSnapshotResourcesV1(snapshot)
	if err != nil {
		state.mu.Unlock()
		p.mu.Unlock()
		return nil, err
	}
	releaseValues, err := p.work.acquire(ctx, org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		state.mu.Unlock()
		p.mu.Unlock()
		return nil, errors.Join(ErrHTMLRevisionOperationV1, err)
	}
	state.active++
	raw := state.raw
	state.mu.Unlock()
	p.mu.Unlock()
	var once sync.Once
	var releaseExtraction func()
	release := func() {
		once.Do(func() {
			if releaseExtraction != nil {
				releaseExtraction()
			}
			releaseValues()
			state.finishV1()
		})
	}
	accepted := false
	defer func() {
		if !accepted {
			release()
		}
	}()
	var body struct {
		htmlCRMRevisionInputV1
		Mappings []htmlCRMRevisionMappingV1 `json:"mappings"`
	}
	if err := json.Unmarshal(bytes.Clone(raw), &body); err != nil {
		return nil, err
	}
	if body.ExpectedOrgID != org || body.ExpectedUserID != actor || !body.Confirmed || len(body.ReviewedDigest) != 64 || body.Mappings == nil || len(body.Mappings) > crmconnection.MaxRecordReferences ||
		(len(body.Mappings) > 0 && snapshot == nil) {
		return nil, ErrHTMLRevisionOperationV1
	}
	if snapshot != nil {
		if snapshot.Identity.OrgID != org || snapshot.Identity.ID.String() != body.ExpectedConnectionID || strconv.FormatInt(snapshot.Identity.Generation, 10) != body.ExpectedConnectionGeneration {
			return nil, ErrHTMLRevisionOperationV1
		}
		if err := resolver.ValidateCRMSelection(*snapshot); err != nil {
			return nil, err
		}
	}
	// Price each selected value separately: many mappings may legitimately
	// select the SAME provider scalar. A snapshot-sized envelope alone would
	// miss those detached string copies and their declaration map.
	extraction := int64(4096)
	if !htmlInputAddV1(&extraction, 2*htmlInputPowerV1(max(8, (int64(len(body.Mappings))*8+6)/7)), 2*80) {
		return nil, ErrHTMLRevisionOperationV1
	}
	for _, mapping := range body.Mappings {
		found := false
		for _, record := range snapshot.Records {
			if string(record.Kind) != mapping.SourceKind || record.ID != mapping.SourceRef {
				continue
			}
			value, err := record.Value(mapping.SourcePath)
			if err != nil || !htmlRevisionRetentionAllocV1(&extraction, int64(len(mapping.Variable))) || !htmlRevisionRetentionAllocV1(&extraction, int64(len(value))) {
				return nil, ErrHTMLRevisionOperationV1
			}
			found = true
			break
		}
		if !found {
			return nil, ErrHTMLRevisionOperationV1
		}
	}
	extraction, err = htmlRevisionRetentionFinishV1(extraction)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return nil, ErrHTMLRevisionOperationV1
	}
	releaseExtraction, err = p.work.acquire(ctx, org, workguard.VectorV1{ParentBytes: extraction})
	p.mu.Unlock()
	if err != nil {
		return nil, errors.Join(ErrHTMLRevisionOperationV1, err)
	}
	declaration := htmlRevisionDeclarationV1{ExpectedUpdatedAt: strings.Clone(body.ExpectedUpdatedAt), ExpectedHTMLSourceCommitment: strings.Clone(body.ExpectedHTMLSourceCommitment), Summary: "Reviewed CRM information applied", Values: make(map[string]string, len(body.Mappings))}
	for _, mapping := range body.Mappings {
		if _, duplicate := declaration.Values[mapping.Variable]; duplicate {
			return nil, ErrHTMLRevisionOperationV1
		}
		if err := resolver.ValidateBinding(mapping.Variable, resolver.SourceKind(mapping.SourceKind), mapping.SourceRef, mapping.SourcePath, ""); err != nil {
			return nil, err
		}
		found := false
		for _, record := range snapshot.Records {
			if string(record.Kind) != mapping.SourceKind || record.ID != mapping.SourceRef {
				continue
			}
			value, err := record.Value(mapping.SourcePath)
			if err != nil || !utf8.ValidString(value) || len(value) > crmconnection.MaxScalarBytes {
				return nil, ErrHTMLRevisionOperationV1
			}
			declaration.Values[strings.Clone(mapping.Variable)] = strings.Clone(value)
			found = true
			break
		}
		if !found {
			return nil, ErrHTMLRevisionOperationV1
		}
	}
	if !applicationContextV1(ctx) {
		return nil, ErrHTMLRevisionOperationV1
	}
	accepted = true
	op := f.newHTMLRevisionOperationV1(ctx, org, document, actor, declaration, release)
	op.state.crmApply = true
	return op, nil
}
