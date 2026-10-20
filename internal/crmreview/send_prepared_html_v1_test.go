// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package crmreview

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
)

type preparedSendTraceV1 struct {
	base           *sendStore
	calls          []string
	fail           string
	cause          error
	failOccurrence int
	occurrences    map[string]int
}

func (s *preparedSendTraceV1) step(name string) error {
	s.calls = append(s.calls, name)
	if s.occurrences == nil {
		s.occurrences = make(map[string]int)
	}
	s.occurrences[name]++
	occurrence := s.failOccurrence
	if occurrence == 0 {
		occurrence = 1
	}
	if s.fail == name && s.occurrences[name] == occurrence {
		return s.cause
	}
	return nil
}
func (s *preparedSendTraceV1) GetDocumentCRMMappingReviewForShare(ctx context.Context, a generated.GetDocumentCRMMappingReviewForShareParams) (*generated.DocumentCrmMappingReview, error) {
	if err := s.step("review"); err != nil {
		return nil, err
	}
	return s.base.GetDocumentCRMMappingReviewForShare(ctx, a)
}
func (s *preparedSendTraceV1) DocumentHasCRMBindings(ctx context.Context, a generated.DocumentHasCRMBindingsParams) (bool, error) {
	if err := s.step("exists"); err != nil {
		return false, err
	}
	return s.base.DocumentHasCRMBindings(ctx, a)
}
func (s *preparedSendTraceV1) ListCRMMappingBindingsForShare(ctx context.Context, a generated.ListCRMMappingBindingsForShareParams) ([]*generated.DocumentVariableBinding, error) {
	if err := s.step("bindings"); err != nil {
		return nil, err
	}
	return s.base.ListCRMMappingBindingsForShare(ctx, a)
}
func (s *preparedSendTraceV1) GetCRMConnectionByOrgForShare(ctx context.Context, id uuid.UUID) (*generated.CrmConnection, error) {
	if err := s.step("connection"); err != nil {
		return nil, err
	}
	return s.base.GetCRMConnectionByOrgForShare(ctx, id)
}

func preparedSendFixtureV1(t *testing.T) (*generated.Document, *sendStore, []resolver.ResolveReport) {
	t.Helper()
	input, doc, _ := testfixture.HTMLContract(t)
	input.Values["scope"] = "Reviewed title"
	input.Values["price"] = "9007199254740993.2300"
	var err error
	doc.VariablesJson, err = json.Marshal(input.Values)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson, err = htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	stamp := doc.CreatedAt
	q := &sendStore{bindings: []*generated.DocumentVariableBinding{{DocumentID: doc.ID, VariableName: "scope", SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: "title", CreatedAt: stamp, UpdatedAt: stamp}, {DocumentID: doc.ID, VariableName: "price", SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: "value", CreatedAt: stamp, UpdatedAt: stamp}}, conn: reviewConnection(doc)}
	return doc, q, freshReports(t, doc, q)
}

// This helper models the concrete native pause: source work is performed only
// after Begin reaches the original ContentCommitment branch, never as a probe.
func runPreparedSendV1(ctx context.Context, q PreparedHTMLSendReadsV1, doc *generated.Document, reports []resolver.ResolveReport, now time.Time) (error, int) {
	stage, err := beginPreparedHTMLSendCheckV1(ctx, q, doc, reports, now)
	if err != nil {
		return err, 0
	}
	defer stage.CloseV1()
	needed, err := stage.NeedsContentV1()
	if err != nil {
		return err, 0
	}
	if !needed {
		return stage.ResumeV1(nil), 0
	}
	v, err := htmlsource.NewRevisionValidationV1(doc)
	if err != nil {
		return ErrReviewRequired, 1
	}
	return stage.ResumeV1(v), 1
}
func TestPreparedHTMLSendReviewMatchesOriginalDecisionsAndFreshReadOrderV1(t *testing.T) {
	doc, base, report := preparedSendFixtureV1(t)
	now := time.Now()
	for _, kind := range []string{"mapped", "manual", "unlink", "missing_reports", "changed_report", "changed_private_fence", "changed_account", "changed_review_content", "changed_mapping", "removed_member", "all_mapped_deleted", "foreign_review", "oversized_ledger", "query_review", "query_exists", "query_bindings", "query_connection", "query_final_connection", "cancelled", "expired", "future"} {
		t.Run(kind, func(t *testing.T) {
			q := *base
			q.bindings = cloneBindings(base.bindings)
			c := *base.conn
			q.conn = &c
			r := *base.review
			q.review = &r
			rp := resolver.CloneSendReportsV1(report)
			ctx := context.Background()
			fault := ""
			occurrence := 1
			cause := errors.New("synthetic current read failure")
			at := now
			switch kind {
			case "manual":
				q.bindings = nil
				q.review = nil
				rp = nil
			case "unlink":
				q.bindings = nil
				q.review = savedReview(t, doc, nil, nil)
				rp = nil
			case "missing_reports":
				rp = nil
			case "changed_report":
				rp[0].Value = "unreviewed"
			case "changed_private_fence":
				rp[0].CRMObservation.Generation = "other"
			case "changed_account":
				q.conn.Generation++
			case "changed_review_content":
				q.review.ContentCommitment = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			case "changed_mapping":
				q.bindings[0].SourceRef = "deal_2"
			case "removed_member":
				q.bindings = q.bindings[:1]
			case "all_mapped_deleted":
				q.bindings = nil
			case "foreign_review":
				q.review.DocumentID = uuid.New()
			case "oversized_ledger":
				q.bindings = append(q.bindings, make([]*generated.DocumentVariableBinding, MaxBindings)...)
			case "query_review":
				fault = "review"
			case "query_exists":
				fault = "exists"
			case "query_bindings":
				fault = "bindings"
			case "query_connection":
				fault = "connection"
			case "query_final_connection":
				fault = "connection"
				occurrence = 2
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				at = now.Add(resolver.CRMObservationMaxAge + time.Second)
			case "future":
				at = now.Add(-time.Minute)
			}
			qa, qb := q, q
			a := &preparedSendTraceV1{base: &qa, fail: fault, cause: cause, failOccurrence: occurrence}
			b := &preparedSendTraceV1{base: &qb, fail: fault, cause: cause, failOccurrence: occurrence}
			old := checkForSend(ctx, a, doc, rp, at)
			next, compiles := runPreparedSendV1(ctx, b, doc, rp, at)
			if (old == nil) != (next == nil) || (old != nil && old.Error() != next.Error()) {
				t.Fatalf("decision differs: old=%v new=%v", old, next)
			}
			if !reflect.DeepEqual(a.calls, b.calls) {
				t.Fatalf("fresh query order differs: old=%v new=%v", a.calls, b.calls)
			}
			for _, target := range []error{ErrReviewRequired, ErrInvalid, context.Canceled, cause} {
				if errors.Is(old, target) != errors.Is(next, target) {
					t.Fatalf("error identity differs for %v: old=%v new=%v", target, old, next)
				}
			}
			if kind == "mapped" {
				if compiles != 1 || !reflect.DeepEqual(a.calls, []string{"review", "exists", "bindings", "connection", "connection"}) {
					t.Fatalf("mapped proof skipped a source/account gate: compiles=%d calls=%v", compiles, a.calls)
				}
			}
			if kind == "manual" || kind == "unlink" || kind == "query_review" || kind == "query_exists" || kind == "query_bindings" || kind == "query_connection" || kind == "changed_account" || kind == "foreign_review" || kind == "cancelled" {
				if compiles != 0 {
					t.Fatalf("source work moved before original content gate: %d", compiles)
				}
			}
		})
	}
}
func TestPreparedHTMLSendContinuationPreservesPriorFailureAndManualAbsenceV1(t *testing.T) {
	doc, base, reports := preparedSendFixtureV1(t)
	bad := *doc
	bad.HtmlSourceJson = json.RawMessage("{broken")
	for _, fault := range []string{"review", "exists", "bindings", "connection"} {
		t.Run(fault, func(t *testing.T) {
			cause := errors.New("prior dependency failure")
			q := &preparedSendTraceV1{base: base, fail: fault, cause: cause}
			err, compiles := runPreparedSendV1(context.Background(), q, &bad, reports, time.Now())
			if !errors.Is(err, cause) || compiles != 0 {
				t.Fatalf("source validation displaced prior failure: %v compiles=%d", err, compiles)
			}
		})
	}
	for _, kind := range []string{"manual", "unlink"} {
		t.Run(kind, func(t *testing.T) {
			q := &sendStore{}
			if kind == "unlink" {
				q.review = savedReview(t, doc, nil, nil)
			}
			trace := &preparedSendTraceV1{base: q}
			err, compiles := runPreparedSendV1(context.Background(), trace, &bad, nil, time.Now())
			if err != nil || compiles != 0 || !reflect.DeepEqual(trace.calls, []string{"review", "exists"}) {
				t.Fatalf("manual decision acquired source gate: %v compiles=%d calls=%v", err, compiles, trace.calls)
			}
		})
	}
	trace := &preparedSendTraceV1{base: base}
	old := checkForSend(context.Background(), trace, &bad, reports, time.Now())
	other := &preparedSendTraceV1{base: base}
	next, compiles := runPreparedSendV1(context.Background(), other, &bad, reports, time.Now())
	if !errors.Is(old, ErrReviewRequired) || !errors.Is(next, ErrReviewRequired) || compiles != 1 || !reflect.DeepEqual(trace.calls, other.calls) {
		t.Fatalf("content refusal/order differs old=%v new=%v calls=%v/%v", old, next, trace.calls, other.calls)
	}
}
func TestPreparedHTMLSendContinuationOwnsPinsAndResumesOnceV1(t *testing.T) {
	doc, base, reports := preparedSendFixtureV1(t)
	prepared, err := htmlsource.NewRevisionValidationV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	q := &preparedSendTraceV1{base: base}
	stage, err := beginPreparedHTMLSendCheckV1(context.Background(), q, doc, reports, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.CloseV1()
	if need, err := stage.NeedsContentV1(); err != nil || !need {
		t.Fatalf("missing fixed pause: %v %v", need, err)
	}
	wantPrefix := []string{"review", "exists", "bindings", "connection"}
	if !reflect.DeepEqual(q.calls, wantPrefix) {
		t.Fatalf("pause reran/moved reads: %v", q.calls)
	}
	// Source/public-report/ledger mutations after the pause cannot alter the private
	// continuation. The final account query remains genuinely fresh.
	doc.VariablesJson[0] = ' '
	doc.HtmlSourceJson[0] = ' '
	base.bindings[0].SourceRef = "deal_other"
	reports[0].Value = "changed"
	reports[0].CRMObservation.Generation = "changed"
	base.review.ContentCommitment = "changed"
	if err := stage.ResumeV1(prepared); err != nil {
		t.Fatalf("private captured inputs changed: %v", err)
	}
	first := append([]string(nil), q.calls...)
	if err := stage.ResumeV1(nil); err != nil || !reflect.DeepEqual(q.calls, first) {
		t.Fatalf("successful replay did fresh work: %v %v", err, q.calls)
	}
	copy := *stage
	if err := copy.ResumeV1(prepared); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("copied continuation accepted: %v", err)
	}
	stage.CloseV1()
	if _, err := stage.NeedsContentV1(); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("closed continuation remained usable")
	}
	if stage.document != nil || stage.report != nil || stage.sorted != nil || stage.q != nil || stage.ctx != nil || stage.failure != nil {
		t.Fatal("closed continuation retains inputs")
	}
}
func TestPreparedHTMLSendContinuationRefusesForeignPinsAndKeepsFailureV1(t *testing.T) {
	for _, kind := range []string{"missing", "different_id", "variables", "source", "review", "timestamp"} {
		t.Run(kind, func(t *testing.T) {
			doc, base, reports := preparedSendFixtureV1(t)
			q := &preparedSendTraceV1{base: base}
			stage, err := beginPreparedHTMLSendCheckV1(context.Background(), q, doc, reports, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer stage.CloseV1()
			d := clonePreparedHTMLReviewDocumentV1(doc)
			switch kind {
			case "different_id":
				_, other, _ := testfixture.HTMLContract(t)
				d = other
			case "variables":
				d.VariablesJson = append(d.VariablesJson, ' ')
			case "source":
				d.HtmlSourceJson = append(d.HtmlSourceJson, ' ')
			case "review":
				d.HtmlReviewedBy.Valid = false
			case "timestamp":
				d.UpdatedAt.Time = d.UpdatedAt.Time.Add(time.Microsecond)
			}
			var v *htmlsource.RevisionValidationV1
			if kind != "missing" {
				v, err = htmlsource.NewRevisionValidationV1(d)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := stage.ResumeV1(v); !errors.Is(err, ErrReviewRequired) {
				t.Fatalf("foreign tuple accepted: %v", err)
			}
			first := append([]string(nil), q.calls...)
			good, err := htmlsource.NewRevisionValidationV1(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := stage.ResumeV1(good); !errors.Is(err, ErrReviewRequired) || !reflect.DeepEqual(q.calls, first) {
				t.Fatalf("failed stage repaired/requeried: %v %v", err, q.calls)
			}
		})
	}
}
func TestPreparedHTMLSendContinuationFreshAccountAfterPauseV1(t *testing.T) {
	doc, base, reports := preparedSendFixtureV1(t)
	q := &preparedSendTraceV1{base: base}
	stage, err := beginPreparedHTMLSendCheckV1(context.Background(), q, doc, reports, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer stage.CloseV1()
	v, err := htmlsource.NewRevisionValidationV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	base.conn.Generation++
	if err := stage.ResumeV1(v); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("fresh account revocation bypassed: %v", err)
	}
	if !reflect.DeepEqual(q.calls, []string{"review", "exists", "bindings", "connection", "connection"}) {
		t.Fatalf("fresh account gate not reached: %v", q.calls)
	}
}
