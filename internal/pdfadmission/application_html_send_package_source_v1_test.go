// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type packageSourceFixture285 struct {
	html      bool
	variables string
	binding   string
	fallback  string
}

// Uses real native Work/source/resolver/candidate/validation/loan methods and
// the real coordinator. Only the already-open SQL/body/empty-binding receipts
// are synthetic; this does not prove factory Open, PostgreSQL, rendering or the
// public package journey. Tests never install a successful resolver result.
func withPackageSourceFixture285(t *testing.T, in packageSourceFixture285, use func(context.Context, *ApplicationHTMLSendWorkV1, *ApplicationHTMLSendSourceV1, *ApplicationHTMLSendSourceV1, *workguard.CoordinatorV1)) {
	t.Helper()
	fixture, session, coordinator := applicationRequestLoanFixtureV1(t)
	factory := &ApplicationSessionFactoryV1{state: session.state.factory}
	factory.state.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	operation, err := factory.NewHTMLSendOperationV1(ctx, fixture.scope.OrgID, fixture.scope.DocumentID)
	if err != nil {
		t.Fatal(err)
	}
	stage := &ApplicationHTMLSendSQLStageV1{operation: operation, purpose: HTMLSendAdmissionV1, ctx: ctx, cancel: func() {}, session: session, active: true}
	stage.self = stage
	operation.stages = append(operation.stages, stage)
	var work *ApplicationHTMLSendWorkV1
	defer func() {
		if work != nil {
			work.CloseConsumerV1()
		}
		operation.EndConsumerV1()
		if !applicationDoneV1(fixture.done) {
			close(fixture.done)
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := fixture.adapter.CloseV1(cleanup); err != nil {
			t.Error("synthetic physical fixture retirement failed", err)
		}
		if got := coordinator.SnapshotV1(fixture.scope.OrgID); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
			t.Error("package source fixture retained actual coordinator debt", got)
		}
	}()
	stamp := time.Date(2026, 10, 19, 0, 0, 0, 1, time.UTC)
	digest := sha256.Sum256([]byte("synthetic fixed package source PDF"))
	template, actor := uuid.New(), uuid.New()
	doc := &generated.Document{ID: fixture.scope.DocumentID, OrgID: fixture.scope.OrgID, TemplateID: pgtype.UUID{Bytes: template, Valid: true}, SenderID: actor, Name: "Package source285", Status: "draft", SourceKind: "pdf", VariablesJson: []byte(in.variables), BlocksJson: []byte("[]"), Metadata: []byte("{}"), MetadataRedactionReport: []byte("{}"), PdfStorageKey: pgtype.Text{String: "source.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "version285", Valid: true}, PdfSha256: digest[:], UpdatedAt: pgtype.Timestamptz{Time: stamp, Valid: true}}
	if in.html {
		values, e := blocks.ParseVariableValues(doc.VariablesJson)
		if e != nil {
			t.Fatal(e)
		}
		master := htmlmaster.Master{SchemaVersion: 1}
		for key := range values {
			master.Values = append(master.Values, htmlmaster.Value{Name: key, MaxChars: 1000})
			master.HTML += `<p><span data-hash-value="` + key + `"></span></p>`
		}
		wire, e := json.Marshal(master)
		if e != nil {
			t.Fatal(e)
		}
		canonical, e := htmlmaster.CanonicalTemplate(wire, []byte("{}"))
		if e != nil {
			t.Fatal(e)
		}
		doc.HtmlReviewedBy = pgtype.UUID{Bytes: actor, Valid: true}
		doc.HtmlReviewedAt = pgtype.Timestamptz{Time: stamp, Valid: true}
		doc.HtmlReviewedPdfSha256 = bytes.Clone(digest[:])
		doc.HtmlSourceJson, e = htmlsource.New(htmlsource.Input{TemplateID: template, TemplateVersion: 1, TemplateContentSHA256: canonical.SHA256, MasterJSON: canonical.MasterJSON, DefaultVarsJSON: canonical.DefaultsJSON, TemplateApprovedBy: actor, TemplateApprovedAt: stamp, Values: values}, doc)
		if e != nil {
			t.Fatal(e)
		}
	}
	err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var e error
		work, e = session.NewHTMLSendWorkV1(call, stage)
		if e != nil {
			return e
		}
		wire, e := htmlAuthoringSumV1(int64(len(doc.HtmlSourceJson)), int64(len(doc.VariablesJson)), int64(len(doc.BlocksJson)), int64(len(doc.Metadata)), int64(len(doc.MetadataRedactionReport)))
		if e != nil {
			return e
		}
		closeBody, e := work.actor.acquireOwnedRetainedBodyV1(call, signerDocumentRawBytesV1(doc), wire)
		if e != nil {
			return e
		}
		work.closes = append(work.closes, closeBody)
		work.sourceDocument = htmlSendCloneDocumentV1(doc)
		work.models = &HTMLSendModelsV1{Document: htmlSendCloneDocumentV1(doc)}
		work.modelsRead, work.bindingsRead, work.packageInitialSelectionChecked = true, true, true
		if in.binding != "" {
			// Genuine resolver static fallback, not a fabricated frozen byte view.
			binding := &generated.DocumentVariableBinding{DocumentID: doc.ID, VariableName: in.binding, SourceKind: string(resolver.SourceStatic), Fallback: in.fallback}
			work.sourceBindings = []*generated.DocumentVariableBinding{binding}
			work.models.Bindings = work.sourceBindings
		}
		source, e := work.NewSourceV1(call)
		if e != nil {
			return e
		}
		if e = source.ValidateReviewedV1(); e != nil {
			return e
		}
		if e = source.ValidateCurrentV1(); e != nil {
			return e
		}
		resolution, e := work.NewResolverV1(call, source, &resolver.Resolver{})
		if e != nil {
			return e
		}
		if e = resolution.FreezeV1(); e != nil {
			return e
		}
		candidate, e := work.NewResolvedSourceV1(resolution)
		if e != nil {
			return e
		}
		// Changed printed HTML values MUST fail this original review gate. The
		// callback can inspect that refusal without manufacturing validation.
		if e = candidate.ValidateReviewedV1(); e == nil {
			e = candidate.ValidateCurrentV1()
		}
		if e != nil && !in.html {
			return e
		}
		use(call, work, source, candidate, coordinator)
		return nil
	})
	if err != nil {
		t.Fatal("native package source fixture failed", err)
	}
}

func TestHTMLSendPackageSourceSemanticVariablesV1(t *testing.T) {
	for _, html := range []bool{false, true} {
		for _, raw := range []string{`{"scope": "Agreed terms", "amount": "9007199254740993.01", "line": "first\nsecond"}`, ` { "scope" : "Agreed \u0074erms" } `, `{"scope":"Agreed terms"}`} {
			name := "plain"
			if html {
				name = "html"
			}
			t.Run(name+"/"+raw, func(t *testing.T) {
				withPackageSourceFixture285(t, packageSourceFixture285{html: html, variables: raw}, func(call context.Context, w *ApplicationHTMLSendWorkV1, source, candidate *ApplicationHTMLSendSourceV1, c *workguard.CoordinatorV1) {
					before := bytes.Clone(source.state.owner.snapshot.document.VariablesJson)
					frozen := bytes.Clone(candidate.state.owner.snapshot.document.VariablesJson)
					strict := candidate.MatchesDocumentV1(source.state.owner.snapshot.document)
					if strict != bytes.Equal(before, frozen) {
						t.Fatal("generic raw tuple comparator changed")
					}
					matches, err := candidate.MatchesPackageOriginalV1(call, source)
					if err != nil || !matches {
						t.Fatal("same actual string values refused", matches, err)
					}
					if !bytes.Equal(before, source.state.owner.snapshot.document.VariablesJson) || !bytes.Equal(frozen, candidate.state.owner.snapshot.document.VariablesJson) || !bytes.Equal(before, w.sourceDocument.VariablesJson) {
						t.Fatal("semantic comparison rewrote an actual source tuple")
					}
					if got := c.SnapshotV1(w.session.state.org); got.Global.ParentBytes <= 0 {
						t.Fatal("native source/comparison loan disappeared before consumer close")
					}
					copyCandidate, copySource := *candidate, *source
					if ok, e := copyCandidate.MatchesPackageOriginalV1(call, &copySource); !ok || e != nil {
						t.Fatal("opaque copies lost their shared actual owner", ok, e)
					}
				})
			})
		}
	}
}

func TestHTMLSendPackageSourceChangedValuesAndShapesRefuseV1(t *testing.T) {
	for _, html := range []bool{false, true} {
		for _, binding := range []string{"scope", "extra"} {
			t.Run(binding+"/html="+map[bool]string{false: "false", true: "true"}[html], func(t *testing.T) {
				withPackageSourceFixture285(t, packageSourceFixture285{html: html, variables: `{"scope": "Agreed terms"}`, binding: binding, fallback: "Different terms"}, func(call context.Context, _ *ApplicationHTMLSendWorkV1, source, candidate *ApplicationHTMLSendSourceV1, _ *workguard.CoordinatorV1) {
					if ok, err := candidate.MatchesPackageOriginalV1(call, source); ok || (html && err == nil) || (!html && err != nil) {
						t.Fatal("actual resolver changed printed values/key membership accepted", ok, err)
					}
				})
			})
		}
	}
	// Private fault injection tests rejection only. These are not native
	// producers and cannot establish a successful map/source authority.
	for _, raw := range []string{"", "null", "[]", `{"scope":7}`, `{"scope":false}`, `{"scope":{}}`, `{"scope":"Agreed terms"} trailing`, `{"bad-name":"Agreed terms"}`, `{"scope":""}`, `{}`, `{"scope":"Agreed te\u0301rms"}`} {
		t.Run("corrupted/"+raw, func(t *testing.T) {
			withPackageSourceFixture285(t, packageSourceFixture285{variables: `{"scope": "Agreed terms"}`}, func(call context.Context, _ *ApplicationHTMLSendWorkV1, source, candidate *ApplicationHTMLSendSourceV1, _ *workguard.CoordinatorV1) {
				candidate.state.owner.snapshot.document.VariablesJson = []byte(raw)
				// A pure value oracle permits inspecting the narrower semantic test,
				// but never replaces the genuine Work/owner/validation gates above.
				if v, e := htmlsource.NewRevisionValidationV1(candidate.state.owner.snapshot.document); e == nil {
					candidate.state.owner.validation = v
				}
				if ok, err := candidate.MatchesPackageOriginalV1(call, source); ok {
					t.Fatal("corrupted/changed string map accepted", raw, err)
				}
			})
		})
	}
}

func TestHTMLSendPackageSourceEveryOtherTuplePinV1(t *testing.T) {
	withPackageSourceFixture285(t, packageSourceFixture285{variables: `{"scope": "Agreed terms"}`}, func(call context.Context, _ *ApplicationHTMLSendWorkV1, source, candidate *ApplicationHTMLSendSourceV1, _ *workguard.CoordinatorV1) {
		owner := candidate.state.owner
		baseline, validation := htmlSendCloneDocumentV1(owner.snapshot.document), owner.validation
		typ := reflect.TypeOf(*baseline)
		if typ.NumField() != 82 {
			t.Fatal("Document inventory changed", typ.NumField())
		}
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).Name == "VariablesJson" {
				continue
			}
			t.Run(typ.Field(i).Name, func(t *testing.T) {
				owner.snapshot.document = htmlSendCloneDocumentV1(baseline)
				owner.validation = validation
				defer func() { owner.snapshot.document = baseline; owner.validation = validation }()
				if !mutateHTMLSendPinFieldV1(reflect.ValueOf(owner.snapshot.document).Elem().Field(i)) {
					t.Fatal("uncovered tuple field")
				}
				if v, e := htmlsource.NewRevisionValidationV1(owner.snapshot.document); e == nil {
					owner.validation = v
				}
				if ok, err := candidate.MatchesPackageOriginalV1(call, source); ok {
					t.Fatal("non-variable tuple drift bypassed original exact matcher", err)
				}
			})
		}
	})
}

func TestHTMLSendPackageSourceOwnershipAndLifetimeRefuseV1(t *testing.T) {
	for _, mode := range []string{"unvalidated", "current-unvalidated", "original-current-failure", "foreign-work", "wrong-stage", "no-package-selection", "source-close", "candidate-close", "work-close", "cancel-original-context", "cancel-candidate-context", "nil-call", "foreign-call", "callback-ended"} {
		t.Run(mode, func(t *testing.T) {
			withPackageSourceFixture285(t, packageSourceFixture285{variables: `{"scope": "Agreed terms"}`}, func(call context.Context, w *ApplicationHTMLSendWorkV1, source, candidate *ApplicationHTMLSendSourceV1, _ *workguard.CoordinatorV1) {
				switch mode {
				case "unvalidated":
					candidate.state.attempted = false
				case "current-unvalidated":
					candidate.state.currentAttempted = false
				case "original-current-failure":
					source.state.currentFailure = errors.New("original source refusal")
				case "foreign-work":
					candidate.state.work = &ApplicationHTMLSendWorkV1{}
				case "wrong-stage":
					w.stage.purpose = HTMLSendPreparationV1
				case "no-package-selection":
					w.packageInitialSelectionChecked = false
				case "source-close":
					source.state.closeV1()
				case "candidate-close":
					candidate.state.closeV1()
				case "work-close":
					w.CloseConsumerV1()
				case "cancel-original-context":
					source.state.owner.cancel()
				case "cancel-candidate-context":
					candidate.state.owner.cancel()
				case "nil-call":
					call = nil
				case "foreign-call":
					call = applicationTestContextV1(t)
				case "callback-ended":
					w.session.state.mu.Lock()
					w.session.state.callbackActive = false
					w.session.state.mu.Unlock()
				}
				if ok, err := candidate.MatchesPackageOriginalV1(call, source); ok || err == nil {
					t.Fatal("unowned/unvalidated/ended source gained verdict", ok, err)
				}
			})
		})
	}
	for _, source := range []*ApplicationHTMLSendSourceV1{nil, {}, {state: &applicationHTMLSendSourceStateV1{}}} {
		if ok, err := source.MatchesPackageOriginalV1(applicationTestContextV1(t), source); ok || err == nil {
			t.Fatal("unowned shell gained verdict", ok, err)
		}
	}
}

func TestHTMLSendPackageSourceAdmissionAndLateCloseV1(t *testing.T) {
	t.Run("actual-parent-denial-before-parse", func(t *testing.T) {
		withPackageSourceFixture285(t, packageSourceFixture285{variables: `{"scope": "Agreed terms"}`}, func(call context.Context, w *ApplicationHTMLSendWorkV1, source, candidate *ApplicationHTMLSendSourceV1, c *workguard.CoordinatorV1) {
			org := w.session.state.org
			remaining := (1 << 30) - c.SnapshotV1(org).Global.ParentBytes
			blocker, err := c.TryAcquireV1(call, org, workguard.VectorV1{ParentBytes: remaining})
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Close()
			before := c.SnapshotV1(org)
			if candidate.state.owner.maxScratch != 0 {
				t.Fatal("plain fixture unexpectedly already funded comparison scratch")
			}
			if ok, err := candidate.MatchesPackageOriginalV1(call, source); ok || err == nil {
				t.Fatal("actual parent refusal was ignored", ok, err)
			}
			if c.SnapshotV1(org) != before || candidate.state.owner.maxScratch != 0 {
				t.Fatal("refused comparison changed actual debt or marked scratch admitted")
			}
		})
	})
	for _, closeCandidate := range []bool{false, true} {
		t.Run("final-verdict-private-close/"+map[bool]string{false: "original", true: "candidate"}[closeCandidate], func(t *testing.T) {
			withPackageSourceFixture285(t, packageSourceFixture285{variables: `{"scope": "Agreed terms"}`}, func(call context.Context, w *ApplicationHTMLSendWorkV1, source, candidate *ApplicationHTMLSendSourceV1, c *workguard.CoordinatorV1) {
				// Controlled final-verdict seam: hold the genuine registered frames
				// and borrowers exactly as the comparator does, THEN close only a
				// private source context while the actual route call stays live.
				s, a := source.state, candidate.state
				if !s.lockV1() {
					t.Fatal("source frame refused")
				}
				defer s.unlockV1()
				if !a.lockV1() {
					t.Fatal("candidate frame refused")
				}
				defer a.unlockV1()
				if err := s.owner.beginV1(); err != nil {
					t.Fatal(err)
				}
				defer s.owner.finishV1()
				if err := a.owner.beginV1(); err != nil {
					t.Fatal(err)
				}
				defer a.owner.finishV1()
				before := c.SnapshotV1(w.session.state.org)
				closed := s
				if closeCandidate {
					closed = a
				}
				closed.closeV1()
				if call.Err() != nil || closed.owner.retired || c.SnapshotV1(w.session.state.org) != before {
					t.Fatal("private Close canceled route or refunded active real source work")
				}
				if ok, err := htmlSendPackageSourceVerdictV1(call, s, a, true); ok || err == nil {
					t.Fatal("late private context Close still yielded successful verdict", ok, err)
				}
			})
		})
	}
	t.Run("refunded-owner-cannot-reenter", func(t *testing.T) {
		withPackageSourceFixture285(t, packageSourceFixture285{variables: `{"scope": "Agreed terms"}`}, func(call context.Context, _ *ApplicationHTMLSendWorkV1, source, candidate *ApplicationHTMLSendSourceV1, _ *workguard.CoordinatorV1) {
			candidate.state.closeV1()
			if !candidate.state.owner.retired {
				t.Fatal("unborrowed closed owner did not retire")
			}
			if ok, err := candidate.MatchesPackageOriginalV1(call, source); ok || err == nil {
				t.Fatal("refunded owner reentered", ok, err)
			}
		})
	})
}

func TestHTMLSendPackageSourceComparisonPricingV1(t *testing.T) {
	small, err := htmlSendPackageSourceComparisonLogicalV1(2, 2)
	large, largerErr := htmlSendPackageSourceComparisonLogicalV1(4096, 8192)
	if err != nil || largerErr != nil || small < int64(reflect.TypeOf(generated.Document{}).Size()) || large <= small || large <= 12288 {
		t.Fatal("actual parser/tuple work is unpriced", small, large, err, largerErr)
	}
	for _, pair := range [][2]int64{{-1, 1}, {1, -1}, {math.MaxInt64, 1}, {1, math.MaxInt64}, {math.MaxInt64, math.MaxInt64}} {
		if _, err := htmlSendPackageSourceComparisonLogicalV1(pair[0], pair[1]); err == nil {
			t.Fatal("negative/overflow component was accepted", pair)
		}
	}
}
