// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
	"testing"
	"time"
)

// The existing processor-override tests retain their HTTP/parser/status
// assertions, but their actual request bytes now use the SAME native input
// owner as production. This reuses the existing block-input unit64MiB/16grant
// profile. SQL/provider resources are disabled, so this helper cannot create a
// native database frame or manufacture any template/document/cache authority.
func automationUnitInputFactoryV1(t *testing.T) *pdfadmission.ApplicationSessionFactoryV1 {
	t.Helper()
	v := workguard.VectorV1{ParentBytes: 64 << 20}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	w, err := pdfadmission.NewWorkAdmissionV1(c)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig("postgres://unit_input@127.0.0.1:1/unit_input?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	f, err := pdfadmission.NewApplicationSessionFactoryV1(cfg, w, pdfadmission.ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := f.CloseV1(ctx); err != nil {
			t.Error("actual input factory close", err)
		}
		pending := f.PendingV1()
		snap := c.SnapshotV1(uuid.Nil)
		if pending.HTMLInputProducers != 0 || pending.WorkSessions != 0 || pending.ObserverSessions != 0 || pending.HTMLAdmissions != 0 || snap.Global != (workguard.VectorV1{}) || snap.GlobalGrants != 0 {
			t.Errorf("real request owner survived fixture: pending=%+v vector=%+v", pending, snap)
		}
	})
	return f
}
func automationUnitRequestV1(t *testing.T, r *http.Request) *http.Request {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return r.WithContext(ctx)
}
