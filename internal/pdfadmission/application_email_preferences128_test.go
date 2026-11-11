// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package pdfadmission

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func TestWorkspaceEmail128NativeContextAndOutputStayOwned(t *testing.T) {
	admission, coordinator := serviceEmailControlProfile760(t)
	org := uuid.New()
	if _, _, err := admission.NewServiceEmailControlV1(context.Background(), org); err == nil || coordinator.SnapshotV1(org) != (workguard.SnapshotV1{}) {
		t.Fatal("unbounded context acquired native resource ownership")
	}
	call, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx, owner, err := admission.NewServiceEmailControlV1(call, org)
	if err != nil {
		t.Fatal(err)
	}
	before := coordinator.SnapshotV1(org)
	if owner.AdmitNativeContextV1(context.Background(), dispatch.TemplateContext{}) == nil || coordinator.SnapshotV1(org) != before {
		t.Fatal("foreign context acquired native work")
	}
	if owner.AdmitNativeContextV1(ctx, dispatch.TemplateContext{OrgName: strings.Repeat("x", dispatch.ServiceEmailDesignRenderedBytesV1+1)}) == nil || coordinator.SnapshotV1(org) != before {
		t.Fatal("unbounded context allocated work")
	}
	if err = owner.AdmitNativeContextV1(ctx, dispatch.TemplateContext{Locale: "legacy-unknown", OrgName: "Original workspace"}); err != nil {
		t.Fatal("resource admission changed native locale fallback", err)
	}
	if err = owner.ReserveNativeOutputV1(ctx); err != nil {
		t.Fatal(err)
	}
	funded := coordinator.SnapshotV1(org)
	if funded.Organisation.DBStagingBytes < 2*dispatch.ServiceEmailDesignRenderedBytesV1+dispatch.ServiceEmailRenderedSubjectBytesV1 {
		t.Fatal("native frozen outbox body/subject not funded", funded)
	}
	if owner.ReserveSampleOutputV1(ctx) == nil || coordinator.SnapshotV1(org) != funded {
		t.Fatal("second operation reused native output reservation")
	}
	owner.CloseConsumerV1()
	owner.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got != (workguard.SnapshotV1{}) {
		t.Fatal("native resource ownership leaked", got)
	}
	if owner.AdmitNativeContextV1(ctx, dispatch.TemplateContext{}) == nil {
		t.Fatal("closed native consumer accepted work")
	}
}
