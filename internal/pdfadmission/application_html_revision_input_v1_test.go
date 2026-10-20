// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTMLRevisionActualInputProfileAndOriginalCeilingV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 32<<20)
	org := uuid.New()
	h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLDocumentRevisionInputV1)
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseConsumerV1()
	raw := "{\"expected_updated_at\":\"2026-10-14T10:00:00Z\",\"expected_html_source_commitment\":\"" + strings.Repeat("a", 64) + "\",\"values\":{\"arbitrary declared name\":\"Å & text\"},\"sections\":{\"terms\":\"Changed\"},\"summary\":\"Reviewed changes\"}"
	got, err := h.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(raw)))
	if err != nil || string(got) != raw {
		t.Fatalf("actual revision body changed: %q %v", got, err)
	}
	if p := f.PendingV1(); p.HTMLInputProducers != 1 || p.WorkSessions != 0 || p.ObserverSessions != 0 {
		t.Fatalf("revision body did not use same non-SQL owner: %+v", p)
	}
	if s := c.SnapshotV1(org); s.GlobalGrants != 2 || s.Global.ParentBytes <= 1<<20 || s.Global.SQLSessions != 0 {
		t.Fatalf("actual raw/parser debt absent: %+v", s)
	}
	h.CloseConsumerV1()
	if p := f.PendingV1(); p.HTMLInputProducers != 0 {
		t.Fatal("finished revision consumer retained")
	}
	over, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLDocumentRevisionInputV1)
	if err != nil {
		t.Fatal(err)
	}
	defer over.CloseConsumerV1()
	if _, err = over.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(strings.Repeat(" ", (1<<20)+1)))); err == nil {
		t.Fatal("original 1MiB ceiling changed")
	} else {
		var max *http.MaxBytesError
		if !errors.As(err, &max) || max.Limit != 1<<20 {
			t.Fatalf("wrong original limit: %v", err)
		}
	}
	over.CloseConsumerV1()
	if err = f.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestHTMLRevisionShapePreservesLegacyTypedAuthorityV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := []string{"{}", "{\"values\":{\"É Arbitrary\":\"text\"},\"sections\":{},\"summary\":\"x\"}", "{\"expected_updated_at\":null,\"expected_html_source_commitment\":false,\"summary\":123}"}
	for _, raw := range accepted {
		if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLDocumentRevisionInputV1, []byte(raw)); err != nil {
			t.Fatalf("shape replaced later unchanged typed/pin authority: %s %v", raw, err)
		}
	}
	refused := []string{"{\"extra\":\"x\"}", "{\"values\":{\"x\":{\"nested\":\"bad\"}}}", "{\"sections\":[\"not a map\"]}"}
	for _, raw := range refused {
		if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLDocumentRevisionInputV1, []byte(raw)); err == nil {
			t.Fatalf("already-invalid unbounded shape admitted: %s", raw)
		}
	}
}
