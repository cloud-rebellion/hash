// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import "github.com/bright-interaction/hash/internal/db/generated"

// MatchesOriginalIntentV1 compares Resume's exact private original row before
// its original legacy-version compatibility gate. An identical legacy or partial
// row may reach that gate; it is not represented as a pinned publication tuple.
// Only the genuine acknowledged native Resume operation and its returned view
// can match. This predicate advances no witness, performs no CAS and retires no
// owner. The later pinned MatchesIntentV1 and publication gates remain required.
func (r *ApplicationHistoricalFinalizationPublicationReferenceV1) MatchesOriginalIntentV1(operation *ApplicationHTMLSendOperationV1, actual *generated.DocumentFinalizationIntent) bool {
	if r == nil || r.owner == nil || operation == nil || operation.self != operation || actual == nil {
		return false
	}
	owner := r.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if owner.self != owner || owner.closed || !owner.acquired || !owner.stagePrepared || owner.factory == nil || owner.factory.state == nil || r != &owner.publicationReference || owner.publicationIntent == nil || owner.publicationGrant == nil || owner.factory != operation.factory || operation.closed || operation.original == nil || operation.original.Err() != nil || operation.org != owner.org || operation.document != owner.document || len(operation.stages) != 1 {
		return false
	}
	stage := operation.stages[0]
	if stage == nil || stage.self != stage || stage.operation != operation || stage.purpose != HTMLHistoricalFinalizationResumeV1 || stage.opening || stage.active || !stage.used || stage.work == nil || stage.session == nil || stage.session.state == nil {
		return false
	}
	work := stage.work
	work.mu.Lock()
	defer work.mu.Unlock()
	if work.self != work || work.closed || work.resourcesClosed || work.stage != stage || work.session != stage.session || work.familyRoot != nil || work.sourceDocument == nil || work.sourceDocument.ID != owner.document || work.sourceDocument.OrgID != owner.org || !historicalFinalizationStageCommitmentMatchesV1(owner.stageCommitment, work.sourceDocument) || work.finalization == nil || !work.finalization.intentRead || work.finalization.intent == nil || actual != work.finalization.intentView {
		return false
	}
	session := stage.session.state
	session.mu.Lock()
	committed := session.factory == owner.factory.state && session.org == owner.org && session.document == owner.document && session.ended && session.commitAttempted && !session.commitUnknown && !session.callbackActive && !session.sqlActive && session.active == 0
	session.mu.Unlock()
	original := work.finalization.intent
	return committed && original.DocumentID == owner.document && original.OrgID == owner.org && historicalIntentExactRowV1(original, actual) && historicalIntentExactRowV1(owner.publicationIntent, original)
}
