// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

type crmDocumentMapping struct {
	Variable   string `json:"variable"`
	SourceKind string `json:"source_kind"`
	SourceRef  string `json:"source_ref"`
	SourcePath string `json:"source_path"`
}

type CRMMappingRequest struct {
	CRMDocumentWitness
	Mappings []crmDocumentMapping `json:"mappings"`
}

type crmDocumentObservationItem struct {
	crmDocumentMapping
	CurrentValue      string                        `json:"current_value"`
	CurrentPresent    bool                          `json:"current_present"`
	Available         bool                          `json:"available"`
	Value             *string                       `json:"value,omitempty"`
	UnavailableReason string                        `json:"unavailable_reason,omitempty"`
	CRMObservation    *resolver.CRMValueObservation `json:"crm_observation,omitempty"`
}

type crmDocumentObservation struct {
	crmDocumentResponseWitness
	Mappings       []crmDocumentMapping         `json:"mappings"`
	Items          []crmDocumentObservationItem `json:"items"`
	ReviewDigest   string                       `json:"review_digest"`
	CanApply       bool                         `json:"can_apply"`
	ContentChanged bool                         `json:"content_changed"`
	ObservedAt     string                       `json:"observed_at"`
	ContractIssues []htmlmaster.ContractIssue   `json:"contract_issues,omitempty"`
	snapshot       *crmconnection.Snapshot
	values         map[string]string
}

func crmScalarSHA(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func crmCanonicalMappings(current *crmDocumentContext, in []crmDocumentMapping) ([]crmDocumentMapping, []crmconnection.RecordRef, error) {
	if in == nil || len(in) > crmconnection.MaxRecordReferences {
		return nil, nil, errCRMDocumentInput
	}
	declared := map[string]bool{}
	for _, v := range current.variables {
		declared[v.Name] = true
	}
	seen := map[string]bool{}
	selected := map[crmconnection.RecordKind]string{}
	result := append([]crmDocumentMapping{}, in...)
	for _, m := range result {
		kind := resolver.SourceKind(m.SourceKind)
		if !declared[m.Variable] || seen[m.Variable] || (kind != resolver.SourceCRMDeal && kind != resolver.SourceCRMContact && kind != resolver.SourceCRMCompany) {
			return nil, nil, errCRMDocumentInput
		}
		if resolver.ValidateBinding(m.Variable, kind, m.SourceRef, m.SourcePath, "") != nil {
			return nil, nil, errCRMDocumentInput
		}
		seen[m.Variable] = true
		recordKind := crmconnection.RecordKind(m.SourceKind)
		if previous, ok := selected[recordKind]; ok && previous != m.SourceRef {
			return nil, nil, errCRMDocumentInput
		}
		selected[recordKind] = m.SourceRef
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Variable < result[j].Variable })
	refs := make([]crmconnection.RecordRef, 0, len(selected))
	for kind, id := range selected {
		refs = append(refs, crmconnection.RecordRef{Kind: kind, ID: id})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Kind < refs[j].Kind })
	return result, refs, nil
}

func (s *Server) crmActiveConnection(current *crmDocumentContext) (crmconnection.Connection, error) {
	row := current.connection
	if s.CRMClient == nil || s.CRMKeys == nil || row == nil || row.Status != "active" || row.Origin != s.CRMOrigin || !row.VerifiedAt.Valid {
		return crmconnection.Connection{}, crmconnection.ErrNotConfigured
	}
	return crmconnection.Connection{Identity: crmIdentity(row), Enabled: true, VerifiedAt: row.VerifiedAt.Time, Ciphertext: append([]byte(nil), row.CredentialCiphertext...)}, nil
}

func crmObservationDeadline(at, now time.Time) error {
	if at.IsZero() || at.After(now) || now.Sub(at) > resolver.CRMObservationMaxAge {
		return errCRMDocumentChanged
	}
	return nil
}

// The private snapshot is populated exclusively by the protected server client.
// Public proof DTOs and client-requested hashes cannot manufacture admission.
func (s *Server) observeCRMDocument(ctx context.Context, current *crmDocumentContext, in []crmDocumentMapping) (*crmDocumentObservation, error) {
	mappings, refs, err := crmCanonicalMappings(current, in)
	if err != nil {
		return nil, err
	}
	values, err := blocks.ParseVariableValues(current.doc.VariablesJson)
	if err != nil {
		return nil, err
	}
	out := &crmDocumentObservation{crmDocumentResponseWitness: current.response, Mappings: mappings, Items: []crmDocumentObservationItem{}, CanApply: true, values: values}
	if len(refs) != 0 {
		conn, err := s.crmActiveConnection(current)
		if err != nil {
			return nil, err
		}
		snapshot, err := s.CRMClient.ReadRecords(ctx, conn, s.CRMKeys, refs)
		if err != nil {
			return nil, err
		}
		if err = resolver.ValidateCRMSelection(snapshot); err != nil {
			return nil, errCRMDocumentChanged
		}
		if snapshot.Identity != conn.Identity {
			return nil, errCRMDocumentChanged
		}
		out.snapshot = &snapshot
		out.ObservedAt = snapshot.CompletedAt.UTC().Format(time.RFC3339Nano)
	}
	definitions := map[string]crmDocumentVariable{}
	for _, field := range current.variables {
		definitions[field.Name] = field
	}
	for _, m := range mappings {
		field := definitions[m.Variable]
		_, present := out.values[m.Variable]
		item := crmDocumentObservationItem{crmDocumentMapping: m, CurrentValue: field.CurrentValue, CurrentPresent: present}
		record, ok := out.snapshot.Record(crmconnection.RecordKind(m.SourceKind), m.SourceRef)
		if !ok {
			return nil, errCRMDocumentChanged
		}
		value, err := record.Value(m.SourcePath)
		if errors.Is(err, crmconnection.ErrFieldUnavailable) {
			item.UnavailableReason = "field_unavailable"
		} else if err != nil {
			return nil, err
		} else if !utf8.ValidString(value) || len(value) > crmconnection.MaxScalarBytes || utf8.RuneCountInString(value) > field.MaxChars {
			item.UnavailableReason = "exceeds_contract_field_limit"
		} else if field.Required && strings.TrimSpace(value) == "" {
			item.UnavailableReason = "required_value_missing"
		} else {
			item.Available = true
			item.Value = &value
			item.CRMObservation = &resolver.CRMValueObservation{ConnectionID: out.snapshot.Identity.ID, Generation: current.response.Connection.Generation, Origin: out.snapshot.Identity.Origin, CRMTeamID: out.snapshot.Identity.CRMTeamID, CRMUserID: out.snapshot.Identity.CRMUserID, RecordUpdatedAt: record.RecordUpdatedAt, ObservedAt: record.ObservedAt, BodySHA256: record.BodySHA256, ValueSHA256: crmScalarSHA(value)}
			if m.SourceKind == string(crmconnection.Contact) && m.SourcePath == "full_name" {
				item.CRMObservation.Transformation = "trim-first-and-last-name-v1"
			}
			before, exists := out.values[m.Variable]
			if !exists || before != value {
				out.ContentChanged = true
			}
			out.values[m.Variable] = value
		}
		if !item.Available {
			out.CanApply = false
		}
		out.Items = append(out.Items, item)
	}
	if out.CanApply && len(mappings) != 0 && len(current.doc.HtmlSourceJson) != 0 {
		input, err := htmlsource.InputForCurrent(current.doc)
		if err != nil {
			return nil, err
		}
		master, err := htmlmaster.Decode(input.MasterJSON)
		if err != nil {
			return nil, err
		}
		compiled, err := htmlmaster.Compile(master)
		if err != nil {
			return nil, err
		}
		ready, err := compiled.ContractReadiness(htmlmaster.Input{Values: out.values, Sections: input.Sections})
		if err != nil {
			return nil, errCRMDocumentInput
		}
		if compiled.ContractProfile() != nil && !ready.Complete {
			out.CanApply = false
			out.ContractIssues = ready.Issues
		}
	}
	// Re-reading may change record body/timestamps while preserving the exact
	// reviewed mapped values. The fresh provenance is audited at Apply; this
	// confirmation digest binds source identity and values, not an old read time.
	type valueWitness struct {
		Mapping        crmDocumentMapping `json:"mapping"`
		Available      bool               `json:"available"`
		ValueSHA256    string             `json:"value_sha256"`
		CurrentPresent bool               `json:"current_present"`
	}
	items := make([]valueWitness, 0, len(out.Items))
	for _, item := range out.Items {
		v := valueWitness{Mapping: item.crmDocumentMapping, Available: item.Available, CurrentPresent: item.CurrentPresent}
		if item.Value != nil {
			v.ValueSHA256 = crmScalarSHA(*item.Value)
		}
		items = append(items, v)
	}
	canonical, err := json.Marshal(struct {
		Witness crmDocumentResponseWitness `json:"witness"`
		Items   []valueWitness             `json:"items"`
	}{current.response, items})
	if err != nil {
		return nil, err
	}
	out.ReviewDigest = crmScalarSHA("hash.crm-document-review.v1\x00" + string(canonical))
	return out, nil
}

func (s *Server) recheckCRMObservation(ctx context.Context, actor authoring.Actor, id uuid.UUID, witness CRMDocumentWitness, identity *crmconnection.Identity, completed time.Time) error {
	current, err := s.readCRMDocument(ctx, actor, id, &witness)
	if err != nil {
		return err
	}
	if identity != nil {
		if current.connection == nil || current.connection.Status != "active" || crmIdentity(current.connection) != *identity {
			return errCRMDocumentChanged
		}
		if err = crmObservationDeadline(completed, time.Now()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleCRMDocumentObservations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, id, ok := s.crmDocumentActor(w, r)
	if !ok {
		return
	}
	var in CRMMappingRequest
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if decodeSignerJSON(r, &in) != nil {
		s.writeCRMDocumentError(w, errCRMDocumentInput)
		return
	}
	if err := in.CRMDocumentWitness.validate(actor); err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	current, err := s.readCRMDocument(ctx, actor, id, &in.CRMDocumentWitness)
	if err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	observation, err := s.observeCRMDocument(ctx, current, in.Mappings)
	if err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	var identity *crmconnection.Identity
	var completed time.Time
	if observation.snapshot != nil {
		identity = &observation.snapshot.Identity
		completed = observation.snapshot.CompletedAt
	}
	if err = s.recheckCRMObservation(ctx, actor, id, in.CRMDocumentWitness, identity, completed); err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	writeJSON(w, 200, observation)
}

func (s *Server) handleCRMDocumentSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, id, ok := s.crmDocumentActor(w, r)
	if !ok {
		return
	}
	var in struct {
		CRMDocumentWitness
		Kind   crmconnection.RecordKind `json:"kind"`
		Query  string                   `json:"query"`
		Offset int                      `json:"offset"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if decodeSignerJSON(r, &in) != nil {
		s.writeCRMDocumentError(w, errCRMDocumentInput)
		return
	}
	if err := in.CRMDocumentWitness.validate(actor); err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	search := crmconnection.SearchInput{Kind: in.Kind, Query: in.Query, Offset: in.Offset}
	if err := crmconnection.ValidateSearchInput(search); err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	current, err := s.readCRMDocument(ctx, actor, id, &in.CRMDocumentWitness)
	if err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	conn, err := s.crmActiveConnection(current)
	if err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	result, err := s.CRMClient.SearchRecords(ctx, conn, s.CRMKeys, search)
	if err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	if result.Identity != conn.Identity {
		s.writeCRMDocumentError(w, errCRMDocumentChanged)
		return
	}
	if err = s.recheckCRMObservation(ctx, actor, id, in.CRMDocumentWitness, &result.Identity, result.CompletedAt); err != nil {
		s.writeCRMDocumentError(w, err)
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
		crmDocumentResponseWitness
		Kind       crmconnection.RecordKind `json:"kind"`
		Query      string                   `json:"query"`
		Offset     int                      `json:"offset"`
		Choices    []choice                 `json:"choices"`
		HasMore    bool                     `json:"has_more"`
		NextOffset int                      `json:"next_offset"`
	}{current.response, in.Kind, in.Query, in.Offset, choices, result.HasMore, result.NextOffset})
}
