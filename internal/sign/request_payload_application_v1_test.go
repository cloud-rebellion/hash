// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// Genuine lookup/issue uses actual generated queries over explicitly synthetic
// rows. A zero public session is an invalid-dispatch witness only; it cannot
// mint the actual fixed factory/fence ownership needed for positive acquisition.
func TestApplicationRequestPayloadAdapterV1GenuineScopeAndFixedCosts(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	intent, err := f.engine.issueFittedSigningIntentV1(ctx, rc, presentedCredentialTestInputV1(t, rc))
	if err != nil {
		t.Fatal(err)
	}
	scope := pdfadmission.ApplicationScopeV1{OrgID: rc.Document.OrgID, DocumentID: rc.Document.ID, AdmissionID: uuid.New(), OwnerID: uuid.New(), StaticBasisSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	adapter, err := f.engine.newApplicationRequestPayloadAdmissionV1(ctx, rc, intent, &pdfadmission.ApplicationSessionV1{}, scope)
	if err != nil {
		t.Fatal(err)
	}
	budget, err := requestPayloadBudgetForV1(rc.presentedCredential, requestOriginMaxBytesV1, acceptedIntentMaxBytesV1)
	if err != nil {
		t.Fatal(err)
	}
	fixed, err := pdfadmission.ApplicationRequestPayloadResourcesForV1(pdfadmission.ApplicationRequestPayloadCostV1{OriginBytes: budget.OriginBytes, IntentBytes: budget.IntentBytes, RawContextBytes: budget.RawContextBytes})
	if err != nil || fixed.WorkingBytes != budget.WorkingBytes {
		t.Fatal("private codec and fixed coordinator formula drifted")
	}
	if release, err := adapter.AcquireRequestPayloadV1(ctx, budget); release != nil || err == nil {
		if release != nil {
			release()
		}
		t.Fatal("zero session fabricated physical owner")
	}
	for _, name := range []string{"org", "document", "recipient", "working", "raw overflow"} {
		t.Run(name, func(t *testing.T) {
			bad := budget
			switch name {
			case "org":
				bad.OrgID = uuid.New()
			case "document":
				bad.DocumentID = uuid.New()
			case "recipient":
				bad.RecipientID = uuid.New()
			case "working":
				bad.WorkingBytes--
			case "raw overflow":
				bad.RawContextBytes = 1<<63 - 1
			}
			if release, err := adapter.AcquireRequestPayloadV1(ctx, bad); release != nil || err == nil {
				if release != nil {
					release()
				}
				t.Fatal("unscoped/arbitrary cost admitted")
			}
		})
	}
	scope.OrgID = uuid.New()
	if _, err = f.engine.newApplicationRequestPayloadAdmissionV1(ctx, rc, intent, &pdfadmission.ApplicationSessionV1{}, scope); err == nil {
		t.Fatal("foreign accounting scope accepted")
	}
	rc.presentedCredential = nil
	if _, err = f.engine.newApplicationRequestPayloadAdmissionV1(ctx, rc, intent, &pdfadmission.ApplicationSessionV1{}, scope); err == nil {
		t.Fatal("synthetic rows accepted")
	}
}
func TestApplicationRequestHeaderV1RequiresPrivateProvenanceBeforeIntent(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Header admission takes no typedName/font/notice or private intent and does
	// not issue/Marshal it. Real resource ownership is required at the session.
	r, err := f.engine.acquireApplicationRequestHeaderV1(ctx, rc, &pdfadmission.ApplicationSessionV1{})
	if r != nil || err == nil {
		if r != nil {
			r()
		}
		t.Fatal("zero physical session manufactured a header loan")
	}
	copyRC := *rc
	copyRC.presentedCredential = nil
	if r, err = f.engine.acquireApplicationRequestHeaderV1(ctx, &copyRC, &pdfadmission.ApplicationSessionV1{}); r != nil || !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("exported context without receipt admitted")
	}
	another := &Engine{Now: func() time.Time { return f.now }}
	if r, err = another.acquireApplicationRequestHeaderV1(ctx, rc, &pdfadmission.ApplicationSessionV1{}); r != nil || !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("cross-engine receipt admitted")
	}
	rc.Document.OrgID = uuid.New()
	if r, err = f.engine.acquireApplicationRequestHeaderV1(ctx, rc, &pdfadmission.ApplicationSessionV1{}); r != nil || !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("mutated exported tenant admitted")
	}
}
