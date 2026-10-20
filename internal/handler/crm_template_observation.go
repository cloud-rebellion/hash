// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

type CRMTemplateCandidate struct {
	Name      string        `json:"name"`
	Values    htmlStringMap `json:"values"`
	Sections  htmlStringMap `json:"sections,omitempty"`
	ExpiresAt string        `json:"expires_at,omitempty"`
}

type CRMTemplateObservationRequest struct {
	CRMTemplateWitness
	Candidate *CRMTemplateCandidate `json:"candidate"`
	Mappings  []crmDocumentMapping  `json:"mappings"`
}

type crmTemplateObservationItem struct {
	crmDocumentMapping
	CurrentPresent    bool                          `json:"current_present"`
	CurrentValue      string                        `json:"current_value"`
	Available         bool                          `json:"available"`
	Value             *string                       `json:"value,omitempty"`
	UnavailableReason string                        `json:"unavailable_reason,omitempty"`
	CRMObservation    *resolver.CRMValueObservation `json:"crm_observation,omitempty"`
}

type crmTemplateObservation struct {
	crmTemplateResponseWitness
	Mappings       []crmDocumentMapping         `json:"mappings"`
	Items          []crmTemplateObservationItem `json:"items"`
	ReviewDigest   string                       `json:"review_digest"`
	ReviewReceipt  string                       `json:"review_receipt,omitempty"`
	CanCreate      bool                         `json:"can_create"`
	ObservedAt     string                       `json:"observed_at"`
	ExpiresAt      string                       `json:"expires_at"`
	ContractIssues []htmlmaster.ContractIssue   `json:"contract_issues,omitempty"`

	snapshot      *crmconnection.Snapshot
	values        map[string]string
	candidateSHA  string
	observationAt time.Time
}

func (in CRMTemplateCandidate) validate(now time.Time) error {
	if strings.TrimSpace(in.Name) == "" || !utf8.ValidString(in.Name) || utf8.RuneCountInString(in.Name) > 200 || strings.ContainsRune(in.Name, '\x00') ||
		len(in.Values) > htmlmaster.MaxDefinitions || len(in.Sections) > htmlmaster.MaxDefinitions {
		return errCRMTemplateInput
	}
	if in.ExpiresAt != "" {
		at, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil || !at.After(now) {
			return errCRMTemplateInput
		}
	}
	return nil
}

// Canonical commitments retain omitted versus explicitly empty maps. They bind
// untouched manual inputs, not just the eventual CRM scalar overlay.
func crmTemplateCandidateDigest(in CRMTemplateCandidate) (string, error) {
	if in.ExpiresAt != "" {
		at, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil {
			return "", errCRMTemplateInput
		}
		in.ExpiresAt = at.UTC().Format(time.RFC3339Nano)
	}
	canonical, err := json.Marshal(struct {
		Name      string        `json:"name"`
		Values    htmlStringMap `json:"values"`
		Sections  htmlStringMap `json:"sections"`
		ExpiresAt string        `json:"expires_at"`
	}{in.Name, in.Values, in.Sections, in.ExpiresAt})
	if err != nil {
		return "", errCRMTemplateInput
	}
	return crmScalarSHA("hash.crm-template-candidate.v1\x00" + string(canonical)), nil
}

func crmTemplateMappings(current *crmTemplateContext, in []crmDocumentMapping) ([]crmDocumentMapping, []crmconnection.RecordRef, error) {
	if current == nil || current.compiled == nil {
		return nil, nil, errCRMTemplateInput
	}
	// Reuse declared-scalar admission without constructing a document or source.
	definitions := &crmDocumentContext{variables: make([]crmDocumentVariable, 0, len(current.variables))}
	for _, v := range current.variables {
		definitions.variables = append(definitions.variables, crmDocumentVariable{Name: v.Name, Required: v.Required, MaxChars: v.MaxChars})
	}
	return crmCanonicalMappings(definitions, in)
}

func (s *Server) observeCRMTemplate(ctx context.Context, current *crmTemplateContext, candidate CRMTemplateCandidate, requested []crmDocumentMapping) (*crmTemplateObservation, error) {
	if err := candidate.validate(time.Now()); err != nil {
		return nil, err
	}
	mappings, refs, err := crmTemplateMappings(current, requested)
	if err != nil {
		return nil, err
	}
	values := maps.Clone(current.defaults)
	for key, value := range candidate.Values {
		values[key] = value
	}
	// Validate declaration names and text limits before requesting private data.
	if _, err = current.compiled.ContractReadiness(htmlmaster.Input{Values: values, Sections: candidate.Sections}); err != nil {
		return nil, err
	}
	candidateSHA, err := crmTemplateCandidateDigest(candidate)
	if err != nil {
		return nil, err
	}
	out := &crmTemplateObservation{crmTemplateResponseWitness: current.response, Mappings: mappings, Items: []crmTemplateObservationItem{}, CanCreate: true,
		values: values, candidateSHA: candidateSHA, observationAt: time.Now().UTC()}
	if len(refs) != 0 {
		conn, err := s.crmActiveConnection(&crmDocumentContext{connection: current.connection})
		if err != nil {
			return nil, err
		}
		snapshot, err := s.CRMClient.ReadRecords(ctx, conn, s.CRMKeys, refs)
		if err != nil {
			return nil, err
		}
		if resolver.ValidateCRMSelection(snapshot) != nil || snapshot.Identity != conn.Identity || crmObservationDeadline(snapshot.CompletedAt, time.Now()) != nil {
			return nil, errCRMTemplateChanged
		}
		out.snapshot = &snapshot
		out.observationAt = snapshot.CompletedAt.UTC()
	}
	definitions := map[string]crmTemplateVariable{}
	for _, field := range current.variables {
		definitions[field.Name] = field
	}
	for _, mapping := range mappings {
		definition := definitions[mapping.Variable]
		before, exists := values[mapping.Variable]
		item := crmTemplateObservationItem{crmDocumentMapping: mapping, CurrentPresent: exists, CurrentValue: before}
		record, ok := out.snapshot.Record(crmconnection.RecordKind(mapping.SourceKind), mapping.SourceRef)
		if !ok {
			return nil, errCRMTemplateChanged
		}
		value, err := record.Value(mapping.SourcePath)
		if errors.Is(err, crmconnection.ErrFieldUnavailable) {
			item.UnavailableReason = "field_unavailable"
		} else if err != nil {
			return nil, err
		} else if !utf8.ValidString(value) || len(value) > crmconnection.MaxScalarBytes || utf8.RuneCountInString(value) > definition.MaxChars {
			item.UnavailableReason = "exceeds_contract_field_limit"
		} else if definition.Required && strings.TrimSpace(value) == "" {
			item.UnavailableReason = "required_value_missing"
		} else {
			// A successful optional empty value is explicitly present in the new
			// immutable source. Missing and null values never become empty text.
			item.Available = true
			item.Value = &value
			identity := out.snapshot.Identity
			item.CRMObservation = &resolver.CRMValueObservation{ConnectionID: identity.ID, Generation: current.response.Connection.Generation,
				Origin: identity.Origin, CRMTeamID: identity.CRMTeamID, CRMUserID: identity.CRMUserID, RecordUpdatedAt: record.RecordUpdatedAt,
				ObservedAt: record.ObservedAt, BodySHA256: record.BodySHA256, ValueSHA256: crmScalarSHA(value)}
			if mapping.SourceKind == string(crmconnection.Contact) && mapping.SourcePath == "full_name" {
				item.CRMObservation.Transformation = "trim-first-and-last-name-v1"
			}
			out.values[mapping.Variable] = value
		}
		if !item.Available {
			out.CanCreate = false
		}
		out.Items = append(out.Items, item)
	}
	ready, err := current.compiled.ContractReadiness(htmlmaster.Input{Values: out.values, Sections: candidate.Sections})
	if err != nil {
		return nil, err
	}
	if current.compiled.ContractProfile() != nil && !ready.Complete {
		out.CanCreate = false
		out.ContractIssues = ready.Issues
	}
	if out.CanCreate {
		if _, err = current.compiled.Materialize(htmlmaster.Input{Values: out.values, Sections: candidate.Sections}); err != nil {
			if errors.Is(err, htmlmaster.ErrMissingValues) || errors.Is(err, htmlmaster.ErrContractIncomplete) {
				out.CanCreate = false
			} else {
				return nil, err
			}
		}
	}
	// Scalar values rather than provider timestamps govern human confirmation.
	// Creation independently reads and audits the newest server-side provenance.
	type valueWitness struct {
		Mapping     crmDocumentMapping `json:"mapping"`
		Available   bool               `json:"available"`
		ValueSHA256 string             `json:"value_sha256"`
	}
	items := make([]valueWitness, 0, len(out.Items))
	for _, item := range out.Items {
		value := valueWitness{Mapping: item.crmDocumentMapping, Available: item.Available}
		if item.Value != nil {
			value.ValueSHA256 = crmScalarSHA(*item.Value)
		}
		items = append(items, value)
	}
	canonical, err := json.Marshal(struct {
		Witness      crmTemplateResponseWitness `json:"witness"`
		CandidateSHA string                     `json:"candidate_sha256"`
		Items        []valueWitness             `json:"items"`
	}{current.response, candidateSHA, items})
	if err != nil {
		return nil, err
	}
	out.ReviewDigest = crmScalarSHA("hash.crm-template-population-review.v1\x00" + string(canonical))
	out.ObservedAt = out.observationAt.Format(time.RFC3339Nano)
	out.ExpiresAt = out.observationAt.Add(resolver.CRMObservationMaxAge).Format(time.RFC3339Nano)
	return out, nil
}

func (s *Server) recheckCRMTemplateObservation(ctx context.Context, actor authoring.Actor, id uuid.UUID, witness CRMTemplateWitness, identity *crmconnection.Identity, completed time.Time) error {
	current, err := s.readCRMTemplate(ctx, actor, id, witness.ExpectedTemplateVersion, witness.ExpectedTemplateContentSHA256, &witness)
	if err != nil {
		return err
	}
	defer current.closeOwnedV1()
	if identity != nil && (current.connection == nil || current.connection.Status != "active" || crmIdentity(current.connection) != *identity) {
		return errCRMTemplateChanged
	}
	if crmObservationDeadline(completed, time.Now()) != nil {
		return errCRMTemplateChanged
	}
	return nil
}

func (s *Server) handleCRMTemplateObservations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, id, ok := s.crmTemplateActor(w, r)
	if !ok {
		return
	}
	r, closeInput, inputOK := s.beginHTMLAuthoringInputV1(w, r, actor.OrgID, pdfadmission.HTMLCRMTemplateObservationInputV1)
	if !inputOK {
		return
	}
	defer closeInput()
	var in CRMTemplateObservationRequest
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	decodeErr := decodeCRMTemplateJSON(r, &in)
	if writeHTMLAuthoringInputFailureV1(w, decodeErr) {
		return
	}
	if decodeErr != nil || in.Candidate == nil {
		s.writeCRMTemplateError(w, errCRMTemplateInput)
		return
	}
	if err := in.CRMTemplateWitness.validate(actor); err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	current, err := s.readCRMTemplate(ctx, actor, id, in.ExpectedTemplateVersion, in.ExpectedTemplateContentSHA256, &in.CRMTemplateWitness)
	if err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	defer current.closeOwnedV1()
	observation, err := s.observeCRMTemplate(ctx, current, *in.Candidate, in.Mappings)
	if err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	var identity *crmconnection.Identity
	if observation.snapshot != nil {
		identity = &observation.snapshot.Identity
	}
	if err = s.recheckCRMTemplateObservation(ctx, actor, id, in.CRMTemplateWitness, identity, observation.observationAt); err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	if observation.CanCreate {
		observation.ReviewReceipt, err = s.mintCRMTemplateReceipt(r, actor, current, observation)
		if err != nil {
			s.writeCRMTemplateError(w, err)
			return
		}
	}
	writeJSON(w, 200, observation)
}

func (s *Server) handleCRMTemplateSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, id, ok := s.crmTemplateActor(w, r)
	if !ok {
		return
	}
	r, closeInput, inputOK := s.beginHTMLAuthoringInputV1(w, r, actor.OrgID, pdfadmission.HTMLCRMTemplateSearchInputV1)
	if !inputOK {
		return
	}
	defer closeInput()
	var in struct {
		CRMTemplateWitness
		Kind   crmconnection.RecordKind `json:"kind"`
		Query  string                   `json:"query"`
		Offset int                      `json:"offset"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	decodeErr := decodeCRMTemplateJSON(r, &in)
	if writeHTMLAuthoringInputFailureV1(w, decodeErr) {
		return
	}
	if decodeErr != nil {
		s.writeCRMTemplateError(w, errCRMTemplateInput)
		return
	}
	if err := in.CRMTemplateWitness.validate(actor); err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	search := crmconnection.SearchInput{Kind: in.Kind, Query: in.Query, Offset: in.Offset}
	if err := crmconnection.ValidateSearchInput(search); err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	current, err := s.readCRMTemplate(ctx, actor, id, in.ExpectedTemplateVersion, in.ExpectedTemplateContentSHA256, &in.CRMTemplateWitness)
	if err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	defer current.closeOwnedV1()
	conn, err := s.crmActiveConnection(&crmDocumentContext{connection: current.connection})
	if err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	result, err := s.CRMClient.SearchRecords(ctx, conn, s.CRMKeys, search)
	if err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	if result.Identity != conn.Identity {
		s.writeCRMTemplateError(w, errCRMTemplateChanged)
		return
	}
	if err = s.recheckCRMTemplateObservation(ctx, actor, id, in.CRMTemplateWitness, &result.Identity, result.CompletedAt); err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	type choice struct {
		Kind            crmconnection.RecordKind `json:"kind"`
		ID              string                   `json:"id"`
		Label           string                   `json:"label"`
		Secondary       string                   `json:"secondary"`
		RecordUpdatedAt time.Time                `json:"record_updated_at"`
	}
	choices := make([]choice, 0, len(result.Choices))
	for _, c := range result.Choices {
		choices = append(choices, choice{c.Kind, c.ID, c.Label, c.Secondary, c.RecordUpdatedAt})
	}
	writeJSON(w, 200, struct {
		crmTemplateResponseWitness
		Kind       crmconnection.RecordKind `json:"kind"`
		Query      string                   `json:"query"`
		Offset     int                      `json:"offset"`
		Choices    []choice                 `json:"choices"`
		HasMore    bool                     `json:"has_more"`
		NextOffset int                      `json:"next_offset"`
	}{current.response, in.Kind, in.Query, in.Offset, choices, result.HasMore, result.NextOffset})
}
