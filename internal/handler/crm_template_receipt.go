// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

const crmTemplateReceiptPurpose = "hash.crm-template-population-review.v1"
const maxCRMTemplateReceiptJSON = 4096
const maxCRMTemplateReceipt = 8192

var errCRMTemplateReceipt = errors.New("initial CRM confirmation is missing, expired or does not match")

// No cookie, candidate text, scalar value or raw CRM body is carried here.
// This purpose never grants template approval, sending or document review.
type crmTemplateReceipt struct {
	CRMTemplateWitness
	SchemaVersion   int       `json:"schema_version"`
	ReceiptID       uuid.UUID `json:"receipt_id"`
	TemplateID      uuid.UUID `json:"template_id"`
	HasMappings     bool      `json:"has_mappings"`
	Origin          string    `json:"origin"`
	CRMTeamID       string    `json:"crm_team_id"`
	CRMUserID       string    `json:"crm_user_id"`
	CandidateSHA256 string    `json:"candidate_sha256"`
	ReviewDigest    string    `json:"review_digest"`
	SessionSHA256   string    `json:"session_sha256"`
	ObservedAt      time.Time `json:"observed_at"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (p crmTemplateReceipt) validate(now time.Time) error {
	actor := authoring.Actor{OrgID: p.ExpectedOrgID, UserID: p.ExpectedUserID}
	if p.SchemaVersion != 1 || p.ReceiptID == uuid.Nil || p.TemplateID == uuid.Nil || p.CRMTemplateWitness.validate(actor) != nil ||
		!htmlPreviewSHA256(p.CandidateSHA256) || !htmlPreviewSHA256(p.ReviewDigest) || !htmlPreviewSHA256(p.SessionSHA256) ||
		p.ObservedAt.IsZero() || p.IssuedAt.Before(p.ObservedAt) || p.IssuedAt.After(now) || !p.ExpiresAt.Equal(p.ObservedAt.Add(resolver.CRMObservationMaxAge)) ||
		!p.IssuedAt.Before(p.ExpiresAt) || !now.Before(p.ExpiresAt) {
		return errCRMTemplateReceipt
	}
	if p.HasMappings {
		id, err := uuid.Parse(p.ExpectedConnectionID)
		generation, generationErr := crmGeneration(p.ExpectedConnectionGeneration, false)
		identity := crmconnection.Identity{ID: id, OrgID: p.ExpectedOrgID, Generation: generation, Origin: p.Origin, CRMTeamID: p.CRMTeamID, CRMUserID: p.CRMUserID}
		if err != nil || generationErr != nil || crmconnection.ValidateIdentity(identity) != nil {
			return errCRMTemplateReceipt
		}
	} else if p.Origin != "" || p.CRMTeamID != "" || p.CRMUserID != "" {
		return errCRMTemplateReceipt
	}
	return nil
}

func crmTemplateWitnessFor(current *crmTemplateContext) CRMTemplateWitness {
	response := current.response
	witness := CRMTemplateWitness{ExpectedOrgID: response.OrgID, ExpectedUserID: response.UserID, ExpectedTemplateVersion: response.TemplateVersion,
		ExpectedTemplateContentSHA256: response.TemplateContentSHA256, ExpectedTemplateApprovedBy: response.TemplateApprovedBy,
		ExpectedTemplateApprovedAt: response.TemplateApprovedAt, ExpectedConnectionGeneration: "0"}
	if response.Connection != nil {
		witness.ExpectedConnectionID = response.Connection.ID.String()
		witness.ExpectedConnectionGeneration = response.Connection.Generation
	}
	return witness
}

func crmTemplateSameWitness(a, b CRMTemplateWitness) bool {
	at, aErr := time.Parse(time.RFC3339Nano, a.ExpectedTemplateApprovedAt)
	bt, bErr := time.Parse(time.RFC3339Nano, b.ExpectedTemplateApprovedAt)
	a.ExpectedTemplateApprovedAt, b.ExpectedTemplateApprovedAt = "", ""
	return aErr == nil && bErr == nil && at.Equal(bt) && a == b
}

func (s *Server) mintCRMTemplateReceipt(r *http.Request, actor authoring.Actor, current *crmTemplateContext, observation *crmTemplateObservation) (string, error) {
	if s == nil || s.Cookies == nil || r == nil || current == nil || observation == nil || !observation.CanCreate ||
		current.response.OrgID != actor.OrgID || current.response.UserID != actor.UserID {
		return "", errCRMTemplateReceipt
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", errCRMTemplateReceipt
	}
	receipt := crmTemplateReceipt{CRMTemplateWitness: crmTemplateWitnessFor(current), SchemaVersion: 1, ReceiptID: uuid.New(), TemplateID: current.response.TemplateID,
		HasMappings: len(observation.Mappings) != 0, CandidateSHA256: observation.candidateSHA, ReviewDigest: observation.ReviewDigest,
		SessionSHA256: htmlPreviewSessionSHA256(cookie.Value), ObservedAt: observation.observationAt.UTC(), IssuedAt: time.Now().UTC(),
		ExpiresAt: observation.observationAt.Add(resolver.CRMObservationMaxAge).UTC()}
	if observation.snapshot != nil {
		identity := observation.snapshot.Identity
		receipt.Origin, receipt.CRMTeamID, receipt.CRMUserID = identity.Origin, identity.CRMTeamID, identity.CRMUserID
	}
	if receipt.validate(time.Now()) != nil {
		return "", errCRMTemplateReceipt
	}
	payload, err := json.Marshal(receipt)
	if err != nil || len(payload) > maxCRMTemplateReceiptJSON {
		return "", errCRMTemplateReceipt
	}
	token, err := s.Cookies.MintPurpose(crmTemplateReceiptPurpose, payload, time.Until(receipt.ExpiresAt))
	if err != nil || len(token) > maxCRMTemplateReceipt {
		return "", errCRMTemplateReceipt
	}
	return token, nil
}

func (s *Server) validateCRMTemplateReceipt(r *http.Request, actor authoring.Actor, templateID uuid.UUID, witness CRMTemplateWitness, candidate CRMTemplateCandidate, mappings []crmDocumentMapping, reviewDigest, token string) (crmTemplateReceipt, error) {
	var receipt crmTemplateReceipt
	if s == nil || s.Cookies == nil || r == nil || token == "" || len(token) > maxCRMTemplateReceipt || !htmlPreviewSHA256(reviewDigest) || witness.validate(actor) != nil || mappings == nil {
		return receipt, errCRMTemplateReceipt
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return receipt, errCRMTemplateReceipt
	}
	payload, err := s.Cookies.VerifyPurpose(crmTemplateReceiptPurpose, token)
	if err != nil || len(payload) == 0 || len(payload) > maxCRMTemplateReceiptJSON {
		return receipt, errCRMTemplateReceipt
	}
	request := &http.Request{Body: io.NopCloser(bytes.NewReader(payload))}
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil || len(fields) != 21 {
		return crmTemplateReceipt{}, errCRMTemplateReceipt
	}
	if decodeCRMTemplateJSON(request, &receipt) != nil || receipt.validate(time.Now()) != nil || !crmTemplateSameWitness(receipt.CRMTemplateWitness, witness) ||
		receipt.TemplateID != templateID || receipt.HasMappings != (len(mappings) != 0) || receipt.ReviewDigest != reviewDigest ||
		subtle.ConstantTimeCompare([]byte(receipt.SessionSHA256), []byte(htmlPreviewSessionSHA256(cookie.Value))) != 1 {
		return crmTemplateReceipt{}, errCRMTemplateReceipt
	}
	digest, err := crmTemplateCandidateDigest(candidate)
	if err != nil || digest != receipt.CandidateSHA256 {
		return crmTemplateReceipt{}, errCRMTemplateReceipt
	}
	return receipt, nil
}
