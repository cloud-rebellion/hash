// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package amendments

import (
	"github.com/google/uuid"
	"testing"
	"time"
)

func amendmentFixtureV1() (uuid.UUID, CreateV1) {
	return uuid.New(), CreateV1{RequestID: uuid.New(), ExpectedHeadRevision: "0", AmendmentDocumentID: uuid.New(), ExpectedDocumentUpdatedAt: time.Date(2026, 10, 21, 12, 0, 0, 123000, time.UTC), Mode: SignatureV1, CoverReviewed: true, Basis: BasisV1{Kind: "reviewed_legacy_clause", ClauseReference: "Clause 12, page 4", ReviewedClause: "Changes may require a fresh signature, explicit acknowledgement, or agreed email notice.", AllowedModes: []ModeV1{SignatureV1, AcknowledgementV1, AgreedNoticeV1}, AllowedChannels: []string{"email"}, EffectiveCondition: "Subject to the conditions in clause 12; no effectiveness inferred from SMTP."}}
}
func TestAmendmentModesRequireReviewedPermittedBasisV1(t *testing.T) {
	for _, mode := range []ModeV1{SignatureV1, AcknowledgementV1, AgreedNoticeV1} {
		t.Run(string(mode), func(t *testing.T) {
			original, in := amendmentFixtureV1()
			in.Mode = mode
			if e := in.ValidateV1(original); e != nil {
				t.Fatal(e)
			}
		})
	}
	mutations := map[string]func(*CreateV1){
		"no cover review": func(v *CreateV1) { v.CoverReviewed = false }, "no original clause": func(v *CreateV1) { v.Basis.ReviewedClause = "" }, "invented mode": func(v *CreateV1) { v.Mode = "email_signature" }, "mode not permitted": func(v *CreateV1) { v.Mode = AgreedNoticeV1; v.Basis.AllowedModes = []ModeV1{SignatureV1} }, "notice no channel": func(v *CreateV1) { v.Mode = AgreedNoticeV1; v.Basis.AllowedChannels = nil }, "invented channel": func(v *CreateV1) { v.Basis.AllowedChannels = []string{"sms"} }, "duplicate mode": func(v *CreateV1) { v.Basis.AllowedModes = []ModeV1{SignatureV1, SignatureV1} }, "missing effect conditions": func(v *CreateV1) { v.Basis.EffectiveCondition = "" }, "client frozen policy contents": func(v *CreateV1) {
			id := uuid.New()
			v.Basis.Kind = "frozen_agreement_policy"
			v.Basis.FrozenPolicyID = &id
		}, "noncanonical head": func(v *CreateV1) { v.ExpectedHeadRevision = "01" }, "head mismatch": func(v *CreateV1) { v.ExpectedHeadRevision = "1" }, "missing timestamp": func(v *CreateV1) { v.ExpectedDocumentUpdatedAt = time.Time{} }, "missing idempotency": func(v *CreateV1) { v.RequestID = uuid.Nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			original, in := amendmentFixtureV1()
			mutate(&in)
			if in.ValidateV1(original) == nil {
				t.Fatal("accepted invalid authority/input")
			}
		})
	}
}
func TestAmendmentRequestDigestBindsReviewedMaterialV1(t *testing.T) {
	_, in := amendmentFixtureV1()
	baseline, e := RequestDigestV1(in)
	if e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*CreateV1){"mode": func(v *CreateV1) { v.Mode = AcknowledgementV1 }, "candidate": func(v *CreateV1) { v.AmendmentDocumentID = uuid.New() }, "condition": func(v *CreateV1) { v.Basis.EffectiveCondition += " after 30 days" }, "head": func(v *CreateV1) { id := uuid.New(); v.ExpectedHeadID = &id; v.ExpectedHeadRevision = "1" }, "clause": func(v *CreateV1) { v.Basis.ReviewedClause += " Changed." }, "cover": func(v *CreateV1) { v.CoverReviewed = false }} {
		t.Run(name, func(t *testing.T) {
			_, copy := amendmentFixtureV1()
			copy = in
			copy.Basis = in.Basis
			mutate(&copy)
			got, e := RequestDigestV1(copy)
			if e != nil || got == baseline {
				t.Fatal("request commitment did not bind", name, e)
			}
		})
	}
	same, e := RequestDigestV1(in)
	if e != nil || same != baseline {
		t.Fatal("identical replay drift")
	}
}
func TestNoticeExactAudienceAndBytesV1(t *testing.T) {
	makeInput := func() IssueNoticeV1 {
		return IssueNoticeV1{RequestID: uuid.New(), ExpectedHeadRevision: "1", ExpectedDocumentUpdatedAt: time.Now().UTC(), Subject: "DPA update", Text: "Please read the exact new DPA provided with this notice.", RecipientEmails: []string{"legal@example.test", "owner@example.test"}, Reviewed: true}
	}
	in := makeInput()
	if e := in.ValidateV1(); e != nil {
		t.Fatal(e)
	}
	before, _ := NoticeDigestV1(in)
	for name, mutate := range map[string]func(*IssueNoticeV1){"header injection": func(v *IssueNoticeV1) { v.Subject += "\r\nBCC: stranger@example.test" }, "display address": func(v *IssueNoticeV1) { v.RecipientEmails = []string{"Person <legal@example.test>"} }, "duplicate": func(v *IssueNoticeV1) { v.RecipientEmails = []string{"legal@example.test", "LEGAL@example.test"} }, "unreviewed": func(v *IssueNoticeV1) { v.Reviewed = false }, "empty audience": func(v *IssueNoticeV1) { v.RecipientEmails = nil }} {
		t.Run(name, func(t *testing.T) {
			v := makeInput()
			mutate(&v)
			if v.ValidateV1() == nil {
				t.Fatal("accepted unsafe notice")
			}
		})
	}
	in.Text += "\nDifferent terms."
	after, _ := NoticeDigestV1(in)
	if before == after {
		t.Fatal("notice bytes not committed")
	}
}
func TestSMTPStateNeverBecomesLegalAcceptanceV1(t *testing.T) {
	for _, status := range []string{"pending", "retrying", "sent", "failed"} {
		state, e := DeliveryStateV1(status)
		if e != nil || state == "signed" || state == "accepted" || state == "delivered" || state == "effective" {
			t.Fatal(status, state, e)
		}
	}
	if _, e := DeliveryStateV1("delivered"); e == nil {
		t.Fatal("unknown provider observation became verified receipt")
	}
}
