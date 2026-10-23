// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPreSign488ActualOwnedClosedInputProfilesV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 32<<20)
	org := uuid.New()
	for _, tc := range []struct {
		name    string
		profile HTMLAuthoringInputProfileV1
		raw     string
	}{
		{"approved API source", HTMLPreSignAPISourceInputV1, `{"request_id":"11111111-1111-4111-8111-111111111111","expected_org_id":"22222222-2222-4222-8222-222222222222","expected_user_id":"33333333-3333-4333-8333-333333333333","policy":{"id":"44444444-4444-4444-8444-444444444444","revision":1,"sha256":"` + strings.Repeat("a", 64) + `"},"grant":{"id":"55555555-5555-4555-8555-555555555555","revision":1,"sha256":"` + strings.Repeat("b", 64) + `"},"document_name":"Controlled source","crm_records":[{"kind":"crm.contact","id":"contact-1"},{"kind":"crm.company","id":"company-1"},{"kind":"crm.deal","id":"deal-1"}]}`},
		{"policy API linked source", HTMLPreSignAPISourceInputV1, `{"request_id":"11111111-1111-4111-8111-111111111111","expected_org_id":"22222222-2222-4222-8222-222222222222","expected_user_id":"33333333-3333-4333-8333-333333333333","policy":{"id":"44444444-4444-4444-8444-444444444444","revision":1,"sha256":"` + strings.Repeat("a", 64) + `"},"grant":{"id":"55555555-5555-4555-8555-555555555555","revision":1,"sha256":"` + strings.Repeat("b", 64) + `"},"document_name":"New policy terms","prior":{"execution_id":"66666666-6666-4666-8666-666666666666","execution_sha256":"` + strings.Repeat("c", 64) + `","document_id":"77777777-7777-4777-8777-777777777777","source_commitment":"` + strings.Repeat("d", 64) + `","materialization_id":"88888888-8888-4888-8888-888888888888","materialization_revision":1,"template":{"id":"99999999-9999-4999-8999-999999999999","version":1,"content_sha256":"` + strings.Repeat("e", 64) + `","approved_by":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","approved_at":"2026-10-23T10:00:00Z"}}}`},
		{"linked new ceremony", HTMLPreSignSupersessionInputV1, `{"prior":{"execution_id":"11111111-1111-4111-8111-111111111111","execution_sha256":"` + strings.Repeat("a", 64) + `","document_id":"22222222-2222-4222-8222-222222222222","source_commitment":"` + strings.Repeat("b", 64) + `","materialization_id":"33333333-3333-4333-8333-333333333333","materialization_revision":1,"template":{"id":"44444444-4444-4444-8444-444444444444","version":1,"content_sha256":"` + strings.Repeat("c", 64) + `","approved_by":"55555555-5555-4555-8555-555555555555","approved_at":"2026-10-23T10:00:00Z"}},"template_id":"44444444-4444-4444-8444-444444444444","source":{"name":"New terms","expected_template_version":1,"expected_template_content_sha256":"` + strings.Repeat("c", 64) + `","values":{"customer_name":"Controlled customer"},"sections":{"terms":"New terms"},"request_id":"66666666-6666-4666-8666-666666666666","expected_org_id":"22222222-2222-4222-8222-222222222222","expected_user_id":"33333333-3333-4333-8333-333333333333"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := f.NewHTMLAuthoringInputV1(ctx, org, tc.profile)
			if err != nil {
				t.Fatal(err)
			}
			defer h.CloseConsumerV1()
			body, err := h.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(tc.raw)))
			if err != nil || string(body) != tc.raw {
				t.Fatal("fixed route rejected its actual closed wire shape", err)
			}
			if p := f.PendingV1(); p.HTMLInputProducers != 1 || p.WorkSessions != 0 || p.ObserverSessions != 0 {
				t.Fatal("request body escaped original nonSQL owner", p)
			}
			if s := c.SnapshotV1(org); s.Global.ParentBytes <= 0 || s.Global.SQLSessions != 0 {
				t.Fatal("actual scanner/body debt missing", s)
			}
			h.CloseConsumerV1()
			if p := f.PendingV1(); p.HTMLInputProducers != 0 {
				t.Fatal("completed consumer did not retire", p)
			}
			if s := c.SnapshotV1(org); s.GlobalGrants != 0 {
				t.Fatal("completed input retained resources", s)
			}
		})
	}
	if err := f.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPreSign488InputShapesRefuseUnownedBodiesAndPreserveOrdinaryV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, raw := range []string{
		`{"values":{"provider_name":"caller override"}}`,
		`{"policy":{"id":"x","revision":1,"sha256":"x","rules":{}}}`,
		`{"crm_records":[{"kind":"crm.contact","id":"1","path":"email"}]}`,
		`{"crm_records":[{},{},{},{}]}`,
		`{"crm_records":[{"kind":"crm.contact","id":{"nested":"value"}}]}`,
		`{"prior":{"template":{"unknown":"x"}}}`,
		`{"prior":{"audit":{"invented":true}}}`,
		`{"prior":{"source_commitment":{"nested":"value"}}}`,
		`{"prior":{"template":{"content_sha256":["copied"]}}}`,
		`{"prior":{"provider_signature":"copied"}}`,
		`{"reviewed":true}`,
	} {
		if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLPreSignAPISourceInputV1, []byte(raw)); err == nil {
			t.Fatal("API preallocation filter admitted unowned caller content")
		}
	}
	for _, raw := range []string{
		`{"prior":{"template":{"unknown":"x"}}}`,
		`{"source":{"values":{"x":{"nested":"value"}}}}`,
		`{"source":{"provider_signature":"copied"}}`,
		`{"prior":{"audit":{"invented":true}}}`,
	} {
		if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLPreSignSupersessionInputV1, []byte(raw)); err == nil {
			t.Fatal("supersession admitted private authority or copied evidence")
		}
	}
	// Scalar/null tokens belong to the existing bounded preallocation pass.
	// Admission here grants no typed or parent authority: the real closed API
	// decoder separately rejects prior:null (covered by its route-wire oracle).
	if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLPreSignAPISourceInputV1, []byte(`{"prior":null}`)); err != nil {
		t.Fatal("preallocation changed the original scalar/null boundary", err)
	}
	if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLDocumentCreationInputV1, []byte(`{"policy":{"id":"x"}}`)); err == nil {
		t.Fatal("ordinary HTML creation shape was broadened")
	}
	if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLDocumentCreationInputV1, []byte(`{"name":"Existing","values":{"declared":"value"},"sections":{}}`)); err != nil {
		t.Fatal("ordinary HTML creation shape changed", err)
	}
}

func TestPreSign488ActualInputByteCeilingsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 32<<20)
	org := uuid.New()
	for _, tc := range []struct {
		profile HTMLAuthoringInputProfileV1
		limit   int64
	}{{HTMLPreSignAPISourceInputV1, 16 << 10}, {HTMLPreSignSupersessionInputV1, 1 << 20}} {
		h, err := f.NewHTMLAuthoringInputV1(ctx, org, tc.profile)
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(strings.Repeat(" ", int(tc.limit)+1))))
		var max *http.MaxBytesError
		if !errors.As(err, &max) || max.Limit != tc.limit {
			h.CloseConsumerV1()
			t.Fatal("fixed profile byte ceiling changed", err)
		}
		h.CloseConsumerV1()
		if s := c.SnapshotV1(org); s.GlobalGrants != 0 {
			t.Fatal("refused body retained input grants", s)
		}
	}
	if err := f.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}
