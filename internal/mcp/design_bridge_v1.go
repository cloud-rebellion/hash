// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// The native handler adapter implements these typed operations. No synthetic
// HTTP request, session cookie or second policy implementation is involved.
type DesignActorV1 struct {
	authoring.Actor
	KeyID uuid.UUID
}
type DesignTemplateReadInputV1 struct {
	Version               int32  `json:"version,omitempty"`
	ExpectedContentSHA256 string `json:"expected_content_sha256,omitempty"`
	// Only the existing get_template adapter selects its legacy response shape.
	LegacyResponse bool `json:"-"`
}
type DesignTemplateInputV1 struct {
	Name            string          `json:"name"`
	HTMLMasterJSON  json.RawMessage `json:"html_master_json"`
	VariablesJSON   json.RawMessage `json:"variables_json"`
	ExpectedVersion int32           `json:"expected_version,omitempty"`
}
type DesignPreviewInputV1 struct {
	ExpectedVersion       int32             `json:"expected_version"`
	ExpectedContentSHA256 string            `json:"expected_content_sha256"`
	Values                map[string]string `json:"values,omitempty"`
	Sections              map[string]string `json:"sections,omitempty"`
}
type DesignCreationInputV1 struct {
	Purpose                       documentpurpose.Purpose `json:"purpose"`
	Name                          string                  `json:"name"`
	ExpectedTemplateVersion       int32                   `json:"expected_template_version"`
	ExpectedTemplateContentSHA256 string                  `json:"expected_template_content_sha256"`
	Values                        map[string]string       `json:"values,omitempty"`
	Sections                      map[string]string       `json:"sections,omitempty"`
	RequestID                     uuid.UUID               `json:"request_id"`
}
type DesignRevisionInputV1 struct {
	ExpectedUpdatedAt            string            `json:"expected_updated_at"`
	ExpectedHTMLSourceCommitment string            `json:"expected_html_source_commitment"`
	Values                       map[string]string `json:"values,omitempty"`
	Sections                     map[string]string `json:"sections,omitempty"`
	Summary                      string            `json:"summary,omitempty"`
}
type DesignTemplateMoveInputV1 struct {
	ExpectedUpdatedAt             string            `json:"expected_updated_at"`
	ExpectedHTMLSourceCommitment  string            `json:"expected_html_source_commitment"`
	TemplateVersion               int32             `json:"template_version"`
	ExpectedTemplateContentSHA256 string            `json:"expected_template_content_sha256"`
	Values                        map[string]string `json:"values,omitempty"`
	Sections                      map[string]string `json:"sections,omitempty"`
	Summary                       string            `json:"summary,omitempty"`
}
type DesignPDFInputV1 struct {
	Revision                     int32  `json:"revision,omitempty"`
	ExpectedUpdatedAt            string `json:"expected_updated_at"`
	ExpectedPDFSHA256            string `json:"expected_pdf_sha256"`
	ExpectedHTMLSourceCommitment string `json:"expected_html_source_commitment,omitempty"`
}
type DesignReviewInputV1 struct {
	ExpectedUpdatedAt            string `json:"expected_updated_at"`
	ExpectedPDFSHA256            string `json:"expected_pdf_sha256"`
	ExpectedHTMLSourceCommitment string `json:"expected_html_source_commitment"`
}
type DesignResultV1 struct {
	Value   any
	Release func()
}
type DesignBridgeV1 interface {
	ReadTemplateV1(context.Context, DesignActorV1, uuid.UUID, DesignTemplateReadInputV1) (DesignResultV1, error)
	WriteTemplateV1(context.Context, DesignActorV1, uuid.UUID, DesignTemplateInputV1, *pdfadmission.ApplicationHTMLAuthoringInputV1, json.RawMessage) (DesignResultV1, error)
	PreviewTemplateV1(context.Context, DesignActorV1, uuid.UUID, DesignPreviewInputV1) (DesignResultV1, error)
	CreateDocumentV1(context.Context, DesignActorV1, uuid.UUID, DesignCreationInputV1) (DesignResultV1, error)
	DocumentSourceV1(context.Context, DesignActorV1, uuid.UUID) (DesignResultV1, error)
	DocumentHistoryV1(context.Context, DesignActorV1, uuid.UUID) (DesignResultV1, error)
	DocumentPDFV1(context.Context, DesignActorV1, uuid.UUID, DesignPDFInputV1) (DesignResultV1, error)
	ReviseDocumentV1(context.Context, DesignActorV1, uuid.UUID, DesignRevisionInputV1, *pdfadmission.ApplicationHTMLAuthoringInputV1) (DesignResultV1, error)
	ReviewDocumentV1(context.Context, DesignActorV1, uuid.UUID, DesignReviewInputV1, []int) (DesignResultV1, error)
	MoveDocumentTemplateV1(context.Context, DesignActorV1, uuid.UUID, DesignTemplateMoveInputV1, *pdfadmission.ApplicationHTMLAuthoringInputV1) (DesignResultV1, error)
}

// Visual review is a caller attestation, never inferred from rendering, saving,
// downloading, readback or this coverage check. The native receipt supplies N.
func DesignPageCoverageV1(pages []int, n int) error {
	if n < 1 || n > 500 || len(pages) != n {
		return errors.New("inspect every page of the exact PDF before explicitly reviewing it")
	}
	seen := make([]bool, n)
	for _, p := range pages {
		if p < 1 || p > n || seen[p-1] {
			return errors.New("reviewed_pages must contain every PDF page exactly once")
		}
		seen[p-1] = true
	}
	return nil
}

type designOwnedResultV1 struct{ state *designOwnedStateV1 }
type designOwnedStateV1 struct {
	mu      sync.Mutex
	value   any
	release func()
	input   *pdfadmission.ApplicationHTMLAuthoringInputV1
	closed  bool
}

func (o *designOwnedResultV1) MarshalJSON() ([]byte, error) {
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	if o.state.closed {
		return nil, errors.New("design response is closed")
	}
	return json.Marshal(o.state.value)
}
func (o *designOwnedResultV1) CloseConsumerV1() {
	if o == nil || o.state == nil {
		return
	}
	s := o.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	release, input, value := s.release, s.input, s.value
	s.release = nil
	s.input = nil
	s.value = nil
	s.mu.Unlock()
	if nested, ok := value.(interface{ CloseConsumerV1() }); ok {
		nested.CloseConsumerV1()
	}
	if release != nil {
		release()
	}
	if input != nil {
		input.CloseConsumerV1()
	}
}
