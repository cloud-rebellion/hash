// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/billing"
	"unsafe"
)

// Original full PlanForOrgWithReads quota policy on this SAME initial real
// session, before original recipient/binding/source parser decisions. A second
// parent-lock transaction is neither opened nor synthesized to run the policy.
func (w *ApplicationHTMLSendWorkV1) EnforceQuotaV1(call context.Context, engine *billing.Engine) error {
	if w == nil || w.self != w || engine == nil {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.stage.purpose != HTMLSendPreparationV1 || !w.initialPolicyRead || w.modelsRead || w.sourceStarted || w.quotaAttempted || w.recipientsAttempted || w.bindingsAttempted {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	w.quotaAttempted = true
	// The quota path precedes NewResolverV1. Fund its actual private reader
	// and retained policy-grant header here, before either is allocated; the
	// resolver's per-binding ownership cannot stand in for this separate call.
	close, err := w.actor.acquireOwnedRetainedBodyV1(call, int64(unsafe.Sizeof(htmlSendOrgSourceReadsV1{}))+int64(unsafe.Sizeof(applicationHTMLSendPlanPolicyGrantV1{})), 0)
	if err != nil {
		w.mu.Unlock()
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, close)
	org := w.session.state.org
	w.mu.Unlock()
	reads := &htmlSendOrgSourceReadsV1{quota: w, work: w, ctx: call}
	return engine.EnforceDocumentQuotaWithReadsV1(call, org, reads)
}
