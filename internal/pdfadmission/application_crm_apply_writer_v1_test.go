// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCRMApplyMappingOnlyCapsuleRetainsBodyUntilItsRealBorrowReturnsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, coordinator := htmlInputFactoryTestV1(t, 32<<20)
	org, actor, document := uuid.New(), uuid.New(), uuid.New()
	raw, _ := crmRevisionInputFixtureV1(t, org, actor, 0)
	input, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCRMDocumentApplyInputV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = input.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(raw))); err != nil {
		t.Fatal(err)
	}
	op, err := f.NewCRMDocumentValuesOperationV1(ctx, org, document, actor, input, nil)
	if err != nil {
		t.Fatal("explicit mapping-only request required a provider", err)
	}
	// This is only the private source-borrow lifetime oracle, not a constructed
	// writer/SQL authority. Public Apply separately refuses such empty shells.
	s := &applicationBlocksMutationStateV1{session: &ApplicationSessionV1{state: &applicationOwnedSessionV1{factory: f.state, org: org, document: document}}}
	s.reader = &ApplicationHTMLRevisionReaderV1{session: s.session}
	s.reader.self = s.reader
	op.state.stages[&applicationHTMLRevisionSQLV1{operation: op.state, purpose: HTMLRevisionMutationV1, session: s.session, reader: s.reader}] = struct{}{}
	declaration, release, err := op.state.borrowCRMApplyValuesV1(ctx, s)
	if err != nil || len(declaration.Values) != 0 {
		t.Fatal(err)
	}
	input.CloseConsumerV1()
	op.CloseConsumerV1()
	if f.PendingV1().HTMLInputProducers != 1 || coordinator.SnapshotV1(org).Global.ParentBytes == 0 {
		t.Fatal("close credited an outstanding actual declaration borrower")
	}
	release()
	release()
	if op.state.sourceUses != 0 || f.PendingV1().HTMLInputProducers != 0 || coordinator.SnapshotV1(org).Global.ParentBytes != 0 {
		t.Fatal("joined/double release did not settle exactly once")
	}
	if err = f.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCRMApplyCannotAdoptAnOrdinaryRevisionOrConstructedWriterV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, w := range []*ApplicationCRMApplyWriterV1{nil, {}, {state: &applicationBlocksMutationStateV1{}}, {state: &applicationBlocksMutationStateV1{closed: true}}} {
		if doc, changed, err := w.ApplyV1(ctx, &ApplicationHTMLRevisionOperationV1{}); !errors.Is(err, ErrBlocksWriterV1) || doc != nil || changed {
			t.Fatal("empty writer acquired source/mutation authority", err)
		}
	}
	f, _ := htmlInputFactoryTestV1(t, 32<<20)
	org, actor, document := uuid.New(), uuid.New(), uuid.New()
	input, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLDocumentRevisionInputV1)
	if err != nil {
		t.Fatal(err)
	}
	defer input.CloseConsumerV1()
	if _, err = input.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(`{"values":{"customer":"arbitrary text"}}`))); err != nil {
		t.Fatal(err)
	}
	op, err := f.NewHTMLRevisionOperationV1(ctx, org, document, actor, input)
	if err != nil {
		t.Fatal(err)
	}
	defer op.CloseConsumerV1()
	s := &applicationBlocksMutationStateV1{session: &ApplicationSessionV1{state: &applicationOwnedSessionV1{factory: f.state, org: org, document: document}}}
	if _, release, err := op.state.borrowCRMApplyValuesV1(ctx, s); !errors.Is(err, ErrBlocksWriterV1) || release != nil {
		t.Fatal("ordinary revision values substituted for protected CRM scalars", err)
	}
}

func TestCRMApplyBorrowRejectsOtherOperationForSameDocumentV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, _ := htmlInputFactoryTestV1(t, 32<<20)
	org, actor, document := uuid.New(), uuid.New(), uuid.New()
	makeOperation := func() *ApplicationHTMLRevisionOperationV1 {
		raw, _ := crmRevisionInputFixtureV1(t, org, actor, 0)
		input, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCRMDocumentApplyInputV1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = input.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(raw))); err != nil {
			t.Fatal(err)
		}
		op, err := f.NewCRMDocumentValuesOperationV1(ctx, org, document, actor, input, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(input.CloseConsumerV1)
		t.Cleanup(op.CloseConsumerV1)
		return op
	}
	a, b := makeOperation(), makeOperation()
	s := &applicationBlocksMutationStateV1{session: &ApplicationSessionV1{state: &applicationOwnedSessionV1{factory: f.state, org: org, document: document}}}
	s.reader = &ApplicationHTMLRevisionReaderV1{session: s.session}
	s.reader.self = s.reader
	stage := &applicationHTMLRevisionSQLV1{operation: a.state, purpose: HTMLRevisionMutationV1, session: s.session, reader: s.reader}
	a.state.stages[stage] = struct{}{}
	if _, release, err := b.state.borrowCRMApplyValuesV1(ctx, s); !errors.Is(err, ErrBlocksWriterV1) || release != nil || b.state.sourceUses != 0 {
		t.Fatal("same factory/org/doc substituted another operation's actual stage", err)
	}
	stage.consumerClosed = true
	if _, release, err := a.state.borrowCRMApplyValuesV1(ctx, s); !errors.Is(err, ErrBlocksWriterV1) || release != nil || a.state.sourceUses != 0 {
		t.Fatal("retired operation stage acquired the request declaration", err)
	}
}

func TestCRMValuesMutationStageIsSingleAndDoesNotBypassHTMLSequenceV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, _ := htmlInputFactoryTestV1(t, 32<<20)
	org, actor, document := uuid.New(), uuid.New(), uuid.New()
	for _, single := range []bool{false, true} {
		raw, _ := crmRevisionInputFixtureV1(t, org, actor, 0)
		input, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCRMDocumentApplyInputV1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = input.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(raw))); err != nil {
			t.Fatal(err)
		}
		var op *ApplicationHTMLRevisionOperationV1
		if single {
			op, err = f.NewCRMDocumentValuesOperationV1(ctx, org, document, actor, input, nil)
		} else {
			op, err = f.NewHTMLCRMRevisionOperationV1(ctx, org, document, actor, input, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		if single {
			if stage, err := op.OpenSQLV1(HTMLRevisionInitialReadV1); !errors.Is(err, ErrHTMLRevisionOperationV1) || stage != nil || op.state.attempted[0] {
				t.Fatal("mapping-only operation admitted an extra preflight SQL stage", err)
			}
		}
		// This factory has NO SQL-session capacity: a legitimate first mutation
		// reaches native admission and refuses before dialing. The four-stage
		// HTML operation must refuse even earlier, without marking an attempt.
		if stage, err := op.OpenSQLV1(HTMLRevisionMutationV1); err == nil || stage != nil {
			t.Fatal("zero SQL capacity produced a live stage")
		}
		if op.state.attempted[3] != single {
			t.Fatal("fixed one-stage CRM path or original HTML ordering was changed")
		}
		op.CloseConsumerV1()
		input.CloseConsumerV1()
	}
	if err := f.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}
