// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

// retireInitialValidatorsV1 is cleanup at their actual last use, not another
// source or SQL dispatch. The operation still owns its independently borrowed
// initial snapshots/draft, and the final stage performs complete fresh policy.
// Caller owns an operation activity pin and the one final-attempt claim.
func (s *applicationDocumentPackageOperationStateV1) retireInitialValidatorsV1() error {
	s.mu.Lock()
	stage := s.stages[0]
	valid := !s.closed && s.initialRead && s.measuredOK && s.finalAttempted &&
		(!s.selectionAttempted || s.selection != nil)
	s.mu.Unlock()
	if !valid || !applicationContextV1(s.ctx) || stage.opening || stage.session == nil ||
		stage.admission == nil || stage.session.state == nil || stage.session.state.admission != stage.admission ||
		!stage.session.RetiredV1() || stage.session.CommitUnknownV1() || stage.selection == nil || stage.selection.state == nil {
		return ErrDocumentPackageOperationV1
	}
	initial := stage.selection.state
	initial.mu.Lock()
	// The exact private draft borrower deliberately survives this cleanup. No
	// other initial policy/validation frame may still be using the sources.
	// A closed public shell remains closed; its exact private draft borrower
	// still owns these snapshots and permits their cleanup/fresh revalidation.
	borrowers := 0
	if s.releaseDraft != nil && s.draft != nil && initial.draft == s.draft {
		borrowers = 1
	} else if s.releaseDraft != nil || s.draft != nil || initial.draft != nil {
		initial.mu.Unlock()
		return ErrDocumentPackageOperationV1
	}
	if (initial.closed.Load() && borrowers == 0) || initial.retired || !initial.sourcesValidated || initial.session != stage.session ||
		initial.ids != s.ids || initial.readActor != s.actor || initial.active != borrowers {
		initial.mu.Unlock()
		return ErrDocumentPackageOperationV1
	}
	initial.active++ // Joins a concurrently closed policy shell through cleanup.
	sources := initial.sources
	initial.mu.Unlock()
	defer initial.finishV1()
	for i, source := range sources {
		if source == nil {
			return ErrDocumentPackageOperationV1
		}
		source.mu.Lock()
		b := source.binding
		if source.self != source || source.purpose != htmlPackageSelectionSourcePurposeV1 ||
			source.closed || source.retired || source.active != 0 || source.candidate != nil || b == nil ||
			b.factory != s.factory.state || b.session != stage.session || b.admission != stage.admission ||
			b.org != s.org || b.document != s.ids[i] || source.snapshot == nil || source.snapshot != s.snapshots[i] {
			source.mu.Unlock()
			return ErrDocumentPackageOperationV1
		}
		// Claim this exact batch while active==0, rather than observing retired
		// after another finisher has claimed it but before its releases return.
		// Closed+retired also prevents a new source activity from entering.
		source.closed = true
		source.cancel()
		closes, release := source.retireLockedV1()
		source.mu.Unlock()
		for _, close := range closes {
			close()
		}
		if release != nil {
			release()
		}
		if !applicationContextV1(s.ctx) {
			return ErrDocumentPackageOperationV1
		}
	}
	// Reconcile only after both winning cleanup batches have actually returned.
	// Other native reader/snapshot/draft loans remain charged; pending need not
	// be zero. This original bounded operation context grants no new SQL scope.
	if _, err := stage.admission.ReconcileCleanupV1(s.ctx); err != nil {
		return err
	}
	if !applicationContextV1(s.ctx) {
		return ErrDocumentPackageOperationV1
	}
	return nil
}
