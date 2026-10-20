// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func htmlInputHandlerFactoryTestV1(t *testing.T) (*Server, *workguard.CoordinatorV1) {
	t.Helper()
	v := workguard.VectorV1{ParentBytes: 8 << 30}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	w, err := pdfadmission.NewWorkAdmissionV1(c)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig("postgres://synthetic:synthetic@127.0.0.1:9/synthetic?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	f, err := pdfadmission.NewApplicationSessionFactoryV1(cfg, w, pdfadmission.ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{HTMLCreationSessions: f}, c
}
func TestHTMLAuthoringOwnedParserRetainsLegacyStrictInterpretationV1(t *testing.T) {
	s, c := htmlInputHandlerFactoryTestV1(t)
	org := uuid.New()
	for _, tc := range []struct {
		profile pdfadmission.HTMLAuthoringInputProfileV1
		raw     string
		dst     func() any
		crm     bool
		ok      bool
	}{
		{pdfadmission.HTMLTemplateApprovalInputV1, `{"expected_version":1,"expected_content_sha256":"x","preview_receipt":"r","expected_preview_pdf_sha256":"p"}`, func() any { return &htmlTemplateApprovalInput{} }, false, true},
		{pdfadmission.HTMLTemplateApprovalInputV1, `{"expected_version":1,"expected_version":2}`, func() any { return &htmlTemplateApprovalInput{} }, false, false},
		{pdfadmission.HTMLTemplatePreviewInputV1, `{"expected_version":1,"values":{"arbitrary.key":"Å😀"},"sections":{}}`, func() any { return &htmlTemplatePreviewInput{} }, false, true},
		{pdfadmission.HTMLTemplatePreviewInputV1, `{"expected_version":1,"values":{"x":null}}`, func() any { return &htmlTemplatePreviewInput{} }, false, false},
		{pdfadmission.HTMLDocumentCreationInputV1, `{"name":"x","expected_template_version":1,"values":{"x":"y"}}`, func() any { return &htmlDocumentInput{} }, false, true},
		{pdfadmission.HTMLDocumentCreationInputV1, `{"name":"x","request_id":null}`, func() any { return &htmlDocumentInput{} }, false, false},
		{pdfadmission.HTMLCRMTemplateObservationInputV1, `{"candidate":{"name":"x","values":{"x":"y"}},"mappings":[]}`, func() any { return &CRMTemplateObservationRequest{} }, true, true},
		{pdfadmission.HTMLCRMTemplateObservationInputV1, `{"candidate":null,"mappings":[]}`, func() any { return &CRMTemplateObservationRequest{} }, true, false},
		{pdfadmission.HTMLCreationClosureInputV1, `{"expected_org_id":"x","expected_user_id":"y","confirmed":true}`, func() any { return &htmlCreationCloseInput{} }, true, true},
		{pdfadmission.HTMLCreationClosureInputV1, `{"confirmed":null}`, func() any { return &htmlCreationCloseInput{} }, true, false},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		req := httptest.NewRequest("POST", "/", strings.NewReader(tc.raw)).WithContext(ctx)
		rec := httptest.NewRecorder()
		req, close, ok := s.beginHTMLAuthoringInputV1(rec, req, org, tc.profile)
		if !ok {
			cancel()
			t.Fatal("owned input did not start", rec.Code, rec.Body.String())
		}
		var err error
		if tc.crm {
			err = decodeCRMTemplateJSON(req, tc.dst())
		} else {
			err = decodeSignerJSON(req, tc.dst())
		}
		if (err == nil) != tc.ok {
			close()
			cancel()
			t.Fatalf("strict legacy result changed for %s: %v", tc.raw, err)
		}
		if errors.Is(err, pdfadmission.ErrHTMLAuthoringInputV1) {
			close()
			cancel()
			t.Fatal("compatibility fixture hit capacity", err)
		}
		if c.SnapshotV1(org).GlobalGrants != 2 {
			close()
			cancel()
			t.Fatal("raw/parser consumers ended before caller used result")
		}
		close()
		cancel()
		if c.SnapshotV1(org).GlobalGrants != 0 {
			t.Fatal("actual parser consumer leaked")
		}
	}
}
func TestHTMLAuthoringOwnedMasterUsesActualCanonicalSourceV1(t *testing.T) {
	s, c := htmlInputHandlerFactoryTestV1(t)
	org := uuid.New()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw := `{"name":"Reusable contract","html_master_json":{"schema_version":1,"html":"<p>Exact approved text</p>"},"variables_json":{}}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(raw)).WithContext(ctx)
	rec := httptest.NewRecorder()
	req, close, ok := s.beginHTMLAuthoringInputV1(rec, req, org, pdfadmission.HTMLTemplateMasterInputV1)
	if !ok {
		t.Fatal(rec.Body.String())
	}
	defer close()
	in, actual, err := parseHTMLTemplateInput(req)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := htmlmaster.CanonicalTemplate(in.HTMLMasterJSON, in.VariablesJSON)
	if err != nil {
		t.Fatal(err)
	}
	if actual.SHA256 != expected.SHA256 || !bytes.Equal(actual.MasterJSON, expected.MasterJSON) {
		t.Fatal("source canonical/provenance changed")
	}
	if got := c.SnapshotV1(org); got.GlobalGrants != 7 || got.Global.SQLSessions != 0 {
		t.Fatalf("actual input lifetime wrong: %+v", got)
	}
	// No caller-supplied alternate master can replace the internally captured raw
	// source; the owner accepts canonicalization only once for that real body.
	if _, err := canonicalHTMLAuthoringInputV1(req, []byte(`{"schema_version":1,"html":"<p>replacement</p>"}`), []byte("{}")); !errors.Is(err, pdfadmission.ErrHTMLAuthoringInputV1) {
		t.Fatal("a second foreign source canonical operation was admitted", err)
	}
}
