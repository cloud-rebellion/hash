// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
)

func TestSupersessionExpectedPinsCannotMintNativeBirthOrAuditV1(t *testing.T) {
	p := PreSignSupersessionParentV1{ExecutionID: uuid.New(), ExecutionSHA256: strings.Repeat("a", 64), DocumentID: uuid.New(), SourceCommitment: strings.Repeat("b", 64), MaterializationID: uuid.New(), MaterializationRevision: 1, Template: presign.TemplatePin{ID: uuid.New(), Version: 1, ContentSHA256: strings.Repeat("c", 64), ApprovedBy: uuid.New(), ApprovedAt: time.Now().Add(-time.Hour)}}
	if err := p.ValidateV1(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*PreSignSupersessionParentV1){func(v *PreSignSupersessionParentV1) { v.MaterializationID = uuid.Nil }, func(v *PreSignSupersessionParentV1) { v.MaterializationRevision = 0 }, func(v *PreSignSupersessionParentV1) { v.ExecutionSHA256 = strings.Repeat("A", 64) }, func(v *PreSignSupersessionParentV1) { v.Template.ApprovedAt = time.Time{} }} {
		bad := p
		change(&bad)
		if bad.ValidateV1() == nil {
			t.Fatal("malformed parent observation accepted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	user, request, event := uuid.New(), uuid.New(), uuid.New()
	for _, r := range []*ApplicationHTMLAuthoringReaderV1{nil, {}, func() *ApplicationHTMLAuthoringReaderV1 {
		x := &ApplicationHTMLAuthoringReaderV1{}
		x.self = x
		return x
	}()} {
		if r.CheckPreSignSupersessionTemplateV1(ctx, p.Template.ID, 1, p.Template.ContentSHA256) == nil {
			t.Fatal("shell admitted current approved source")
		}
		if r.CheckPreSignSupersessionParentV1(ctx, user, p, p.Template.ID) == nil {
			t.Fatal("shell admitted terminal source")
		}
		if _, err := r.ReadPreSignSupersessionRequestV1(ctx, user, request, ""); err == nil {
			t.Fatal("shell manufactured original request")
		}
		if _, ready, err := r.ReadPreSignSupersessionBirthV1(ctx, user, request, strings.Repeat("d", 64), p, p.Template.ID); err == nil || ready {
			t.Fatal("shell manufactured real HTML birth")
		}
		if r.SealPreSignSupersessionBirthV1(ctx, user, request, event, strings.Repeat("d", 64), p, p.Template.ID) == nil {
			t.Fatal("shell sealed caller-provided event")
		}
	}
	for _, status := range []string{"draft", "sealing", "sent", "viewed", "", "completed_extra"} {
		if preSignTerminalParentV1(status) {
			t.Fatal("live or unknown parent became eligible")
		}
	}
	for _, status := range []string{"completed", "voided", "declined", "expired"} {
		if !preSignTerminalParentV1(status) {
			t.Fatal("known terminal state refused")
		}
	}
	same := p.Template
	same.ApprovedAt = same.ApprovedAt.In(time.FixedZone("same instant", 3600))
	if !preSignSameTemplateV1(p.Template, same) {
		t.Fatal("equal actual approval instant differed")
	}
	same.Version++
	if preSignSameTemplateV1(p.Template, same) {
		t.Fatal("different approved revision adopted")
	}
}
