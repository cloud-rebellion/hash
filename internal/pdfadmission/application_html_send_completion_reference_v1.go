// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"sync"
	"unsafe"
)

// This exact witness retains independent original comparison bodies only. It
// is not a source/Current/field/evidence/SQL owner and authorizes no mutation.
// Completion must independently read and validate all actual fresh rows.
type ApplicationHTMLSendCompletionReferenceV1 struct {
	owner *applicationHTMLSendCompletionReferenceV1
}
type applicationHTMLSendCompletionReferenceV1 struct {
	mu        sync.Mutex
	self      *applicationHTMLSendCompletionReferenceV1
	operation *ApplicationHTMLSendOperationV1
	reference ApplicationHTMLSendCompletionReferenceV1
	grant     *workguard.GrantV1
	document  *generated.Document
	children  []*generated.Document
	closed    bool
}

func htmlSendCompletionDocumentResourcesV1(d *generated.Document) (int64, error) {
	if d == nil {
		return 0, ErrHTMLSendWorkV1
	}
	return htmlAuthoringSumV1(signerDocumentRawBytesV1(d), int64(len(d.BlocksJson)), int64(len(d.VariablesJson)), int64(len(d.Metadata)), int64(len(d.MetadataRedactionReport)), int64(len(d.HtmlSourceJson)), int64(len(d.HtmlCurrentSourceJson)), int64(unsafe.Sizeof(generated.Document{}))+4*int64(unsafe.Sizeof(uintptr(0))))
}

// The actual successful fields/inspection source supplies every byte and row.
// No caller Document, digest, count, reported size or later context is accepted.
func (e *ApplicationHTMLSendEvidenceV1) CaptureCompletionReferenceV1() (*ApplicationHTMLSendCompletionReferenceV1, error) {
	if e == nil || e.self != e {
		return nil, ErrHTMLSendEvidenceV1
	}
	if !e.lockV1() {
		return nil, ErrHTMLSendEvidenceV1
	}
	defer e.unlockV1()
	if e.draft || !e.bound || !e.fieldsBound || !e.inspectAttempted || e.inspectError != nil {
		return nil, ErrHTMLSendEvidenceV1
	}
	ctx, source, done, err := e.beginV1()
	if err != nil {
		return nil, err
	}
	defer done()
	w := e.work
	w.mu.Lock()
	if w.closed || w.resourcesClosed || w.stage == nil || w.stage.operation == nil || w.stage.purpose != HTMLSendSnapshotFieldsV1 || w.familyRoot != nil || w.sourceDocument == nil || source.work != w || source.owner == nil || !htmlSendDocumentExactTupleEqualV1(source.owner.snapshot.document, w.sourceDocument) {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	op := w.stage.operation
	doc := w.sourceDocument
	members := w.familyMembers
	w.mu.Unlock()
	raw, err := htmlSendCompletionDocumentResourcesV1(doc)
	if err != nil {
		return nil, err
	}
	if doc.IsEnvelope != (len(members) > 0) {
		return nil, ErrHTMLSendWorkV1
	}
	for _, member := range members {
		if member == nil {
			return nil, ErrHTMLSendWorkV1
		}
		member.mu.Lock()
		if member.closed || member.resourcesClosed || member.familyRoot != w || member.sourceDocument == nil {
			member.mu.Unlock()
			return nil, ErrHTMLSendWorkV1
		}
		n, err := htmlSendCompletionDocumentResourcesV1(member.sourceDocument)
		member.mu.Unlock()
		if err != nil || !htmlInputAddV1(&raw, n, 1) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if !htmlInputAddV1(&raw, int64(len(members)), 2*int64(unsafe.Sizeof((*generated.Document)(nil)))) || !htmlInputAddV1(&raw, 1, int64(unsafe.Sizeof(applicationHTMLSendCompletionReferenceV1{}))+2*int64(unsafe.Sizeof(workguard.GrantV1{}))) || raw > int64(^uint64(0)>>1)/8 {
		return nil, ErrHTMLSendWorkV1
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.closed || op.original == nil || op.original.Err() != nil || op.factory == nil || op.factory.state == nil || op.completionReference != nil || w.stage.active || w.stage.opening || !w.stage.used {
		return nil, ErrHTMLSendWorkV1
	}
	session := w.session.state
	session.mu.Lock()
	committed := session.ended && session.commitAttempted && !session.commitUnknown && !session.callbackActive && !session.sqlActive && session.active == 0
	session.mu.Unlock()
	if !committed {
		return nil, ErrHTMLSendWorkV1
	}
	factory := op.factory.state
	factory.mu.Lock()
	available := !factory.closing && factory.work != nil && factory.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if !available {
		return nil, ErrHTMLSendWorkV1
	}
	grant, err := coordinator.TryAcquireV1(ctx, op.org, workguard.VectorV1{ParentBytes: 8 * raw})
	if err != nil {
		return nil, err
	}
	owner := &applicationHTMLSendCompletionReferenceV1{operation: op, grant: grant, document: htmlSendCloneDocumentV1(doc), children: make([]*generated.Document, len(members))}
	owner.self = owner
	owner.reference.owner = owner
	for i, member := range members {
		member.mu.Lock()
		if member.closed || member.resourcesClosed || member.sourceDocument == nil || member.familyRoot != w {
			member.mu.Unlock()
			owner.document = nil
			owner.children = nil
			grant.Close()
			return nil, ErrHTMLSendWorkV1
		}
		owner.children[i] = htmlSendCloneDocumentV1(member.sourceDocument)
		member.mu.Unlock()
	}
	op.completionReference = owner
	return &owner.reference, nil
}
func (r *ApplicationHTMLSendCompletionReferenceV1) MatchesOperationV1(op *ApplicationHTMLSendOperationV1) bool {
	if r == nil || r.owner == nil || op == nil || op.self != op {
		return false
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	owner := r.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return !op.closed && owner.self == owner && !owner.closed && owner.operation == op && op.completionReference == owner && r == &owner.reference && owner.grant != nil
}
func (w *ApplicationHTMLSendWorkV1) CompareCompletionRootV1(call context.Context, r *ApplicationHTMLSendCompletionReferenceV1) (bool, error) {
	if w == nil || w.self != w || w.stage == nil || w.stage.operation == nil || r == nil || r.owner == nil {
		return false, ErrHTMLSendWorkV1
	}
	op := w.stage.operation
	op.mu.Lock()
	defer op.mu.Unlock()
	owner := r.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if op.closed || owner.self != owner || owner.closed || op.completionReference != owner || owner.operation != op || r != &owner.reference || !w.valid(call) || w.stage.purpose != HTMLSendCompletionV1 || w.familyRoot != nil || w.sourceDocument == nil || owner.document == nil {
		return false, ErrHTMLSendWorkV1
	}
	before, after := *owner.document, *w.sourceDocument
	before.Status, after.Status = "sealing", "sealing"
	return HTMLSendPreparedDocumentEqualV1(&before, &after), nil
}

// A zero changed ID with membershipChanged=false is the exact original child
// comparison success. Bodies remain private and charged while this compares.
func (w *ApplicationHTMLSendWorkV1) CompareCompletionChildrenV1(call context.Context, r *ApplicationHTMLSendCompletionReferenceV1) (membershipChanged bool, changed uuid.UUID, failure error) {
	if w == nil || w.self != w || w.stage == nil || w.stage.operation == nil || r == nil || r.owner == nil {
		return false, uuid.Nil, ErrHTMLSendWorkV1
	}
	op := w.stage.operation
	op.mu.Lock()
	defer op.mu.Unlock()
	owner := r.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	w.mu.Lock()
	if op.closed || owner.self != owner || owner.closed || op.completionReference != owner || owner.operation != op || r != &owner.reference || !w.valid(call) || w.stage.purpose != HTMLSendCompletionV1 || w.familyRoot != nil || w.sourceDocument == nil || !w.sourceDocument.IsEnvelope || !w.familyMembersAttempted {
		w.mu.Unlock()
		return false, uuid.Nil, ErrHTMLSendWorkV1
	}
	members := w.familyMembers
	w.mu.Unlock()
	if len(members) != len(owner.children) {
		return true, uuid.Nil, nil
	}
	for i, member := range members {
		if member == nil {
			return true, uuid.Nil, nil
		}
		member.mu.Lock()
		after := member.sourceDocument
		before := owner.children[i]
		if before == nil || after == nil || before.ID != after.ID {
			member.mu.Unlock()
			return true, uuid.Nil, nil
		}
		same := before.Name == after.Name && bytes.Equal(before.BlocksJson, after.BlocksJson) && bytes.Equal(before.VariablesJson, after.VariablesJson)
		id := before.ID
		member.mu.Unlock()
		if !same {
			return false, id, nil
		}
	}
	return false, uuid.Nil, nil
}
func (s *applicationHTMLSendCompletionReferenceV1) closeV1() {
	if s == nil || s.self != s {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	grant := s.grant
	s.grant = nil
	s.document = nil
	s.children = nil
	s.operation = nil
	s.mu.Unlock()
	if grant != nil {
		grant.Close()
	}
}
