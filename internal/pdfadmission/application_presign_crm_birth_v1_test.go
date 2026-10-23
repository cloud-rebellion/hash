// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func TestPreSignCRMSelectionRequiresPolicyKindsAndExactRecordModeV1(t *testing.T) {
	d := presignregistry.WorkflowDefinition{Kind: presignregistry.KindApprovedData, DataRules: presignregistry.DataRules{CRM: &presignregistry.CRMScope{Selection: "fixed_record_set", Records: []presignregistry.RecordRule{{Kind: "crm.deal", ID: "deal_1"}, {Kind: "crm.contact", ID: "contact_1"}}}}}
	refs, err := preSignCRMRefsV1(d, nil)
	if err != nil || len(refs) != 2 || refs[0].ID != "contact_1" || refs[1].ID != "deal_1" {
		t.Fatal("stored fixed records not selected", err)
	}
	if _, err = preSignCRMRefsV1(d, []presignregistry.RecordRule{{Kind: "crm.deal", ID: "deal_2"}}); err == nil {
		t.Fatal("caller overrode fixed policy records")
	}
	c := *d.DataRules.CRM
	c.Selection = "execution_record_set"
	c.Records = []presignregistry.RecordRule{{Kind: "crm.deal"}, {Kind: "crm.contact"}}
	d.DataRules.CRM = &c
	selected := []presignregistry.RecordRule{{Kind: "crm.contact", ID: "contact_2"}, {Kind: "crm.deal", ID: "deal_2"}}
	if refs, err = preSignCRMRefsV1(d, selected); err != nil || len(refs) != 2 || refs[0].ID != "contact_2" || refs[1].ID != "deal_2" {
		t.Fatal("declared dynamic selection refused", err)
	}
	for name, bad := range map[string][]presignregistry.RecordRule{
		"missing": selected[:1], "duplicate": {selected[0], selected[0]}, "foreign kind": {selected[0], {Kind: "crm.company", ID: "company_1"}},
		"path injection": {selected[0], {Kind: "crm.deal", ID: "../secrets"}}, "empty": {selected[0], {Kind: "crm.deal"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := preSignCRMRefsV1(d, bad); err == nil {
				t.Fatal("unapproved record selection accepted")
			}
		})
	}
}

func TestPreSignCRMConsumerCloseKeepsBodyCreditThroughActualLastFrameV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	org := uuid.New()
	c, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 4096}, Organisation: workguard.VectorV1{ParentBytes: 4096}, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	body, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	h := &ApplicationPreSignCRMSourceV1{body: body}
	h.self = h
	if !h.lockV1() {
		t.Fatal("original frame did not enter")
	}
	h.CloseConsumerV1()
	if g, e := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 1}); e == nil {
		g.Close()
		t.Fatal("close returned credit before actual last frame")
	}
	h.unlockV1()
	if g, e := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 4096}); e != nil {
		t.Fatal("joined consumer did not release body credit", e)
	} else {
		g.Close()
	}
	if h.lockV1() {
		h.unlockV1()
		t.Fatal("closed consumer resumed")
	}
	for _, shell := range []*ApplicationPreSignCRMSourceV1{nil, {}, func() *ApplicationPreSignCRMSourceV1 { x := &ApplicationPreSignCRMSourceV1{}; x.self = x; return x }()} {
		if shell.ReadV1() == nil || shell.CheckDeadlineV1() == nil {
			t.Fatal("shell manufactured actual provider proof")
		}
		shell.CloseConsumerV1()
	}
}
