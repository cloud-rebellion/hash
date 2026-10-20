// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This fixture exercises actual Work/source/evidence/admission/coordinator
// methods with explicitly synthetic already-open SQL/body/backend receipts.
// It proves bookkeeping and first-party SDK protocol, NOT public factory Open,
// PG caches/pinning, renderer geometry, legal review or remote Object Lock.
type htmlSendEvidenceSourceFixtureV1 struct {
	sourceKind        string
	blocks, variables []byte
}

func htmlSendEvidenceFixtureV1(t *testing.T, purpose HTMLSendSQLPurposeV1, asPlain ...bool) (*ApplicationHTMLSendWorkV1, *ApplicationHTMLSendSourceV1, *ApplicationHTMLSendEvidenceV1, *applicationFixtureV1, *workguard.CoordinatorV1, context.Context) {
	t.Helper()
	var document *htmlSendEvidenceSourceFixtureV1
	if len(asPlain) > 0 && asPlain[0] {
		document = &htmlSendEvidenceSourceFixtureV1{sourceKind: "pdf"}
	}
	return htmlSendEvidenceFixtureDocumentV1(t, purpose, document)
}
func htmlSendEvidenceFixtureDocumentV1(t *testing.T, purpose HTMLSendSQLPurposeV1, plain *htmlSendEvidenceSourceFixtureV1) (*ApplicationHTMLSendWorkV1, *ApplicationHTMLSendSourceV1, *ApplicationHTMLSendEvidenceV1, *applicationFixtureV1, *workguard.CoordinatorV1, context.Context) {
	t.Helper()
	fixture, session, coordinator := applicationRequestLoanFixtureV1(t)
	factory := &ApplicationSessionFactoryV1{state: session.state.factory}
	factory.state.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	operation, err := factory.NewHTMLSendOperationV1(ctx, fixture.scope.OrgID, fixture.scope.DocumentID)
	if err != nil {
		t.Fatal(err)
	}
	stage := &ApplicationHTMLSendSQLStageV1{operation: operation, purpose: purpose, ctx: ctx, cancel: func() {}, session: session, active: true}
	stage.self = stage
	operation.stages = append(operation.stages, stage)
	payload := []byte("synthetic fixed evidence bytes")
	digest := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/send-evidence" || r.URL.Path == "/send-evidence/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("ETag", "\"fixed\"")
		w.Header().Set("Last-Modified", "Wed, 15 Oct 2025 00:00:00 GMT")
		w.Header().Set("X-Amz-Version-Id", "version-one")
		if r.Method == http.MethodGet {
			_, _ = w.Write(payload)
		}
	}))
	t.Cleanup(server.Close)
	client, err := storage.New(ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "send-evidence", AccessKey: "synthetic", SecretKey: "synthetic-secret", BucketLookup: "path", RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate([]byte("{\"schema_version\":1,\"html\":\"<p>Evidence</p>\",\"css\":\"\"}"), []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	template, actor := uuid.New(), uuid.New()
	stamp := time.Date(2026, 10, 15, 0, 0, 0, 1, time.UTC)
	doc := &generated.Document{ID: fixture.scope.DocumentID, OrgID: fixture.scope.OrgID, TemplateID: pgtype.UUID{Bytes: template, Valid: true}, SenderID: actor, Name: "Synthetic evidence tuple", Status: "draft", SourceKind: "pdf", VariablesJson: []byte("{}"), BlocksJson: []byte("[]"), Metadata: []byte("{}"), MetadataRedactionReport: []byte("{}"), PdfStorageKey: pgtype.Text{String: "object.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "version-one", Valid: true}, PdfSha256: digest[:], UpdatedAt: pgtype.Timestamptz{Time: stamp, Valid: true}, HtmlReviewedBy: pgtype.UUID{Bytes: actor, Valid: true}, HtmlReviewedAt: pgtype.Timestamptz{Time: stamp, Valid: true}, HtmlReviewedPdfSha256: bytes.Clone(digest[:])}
	if purpose == HTMLSendSnapshotV1 {
		doc.Status = "sealing"
	}
	if plain == nil {
		doc.HtmlSourceJson, err = htmlsource.New(htmlsource.Input{TemplateID: template, TemplateVersion: 1, TemplateContentSHA256: canonical.SHA256, MasterJSON: canonical.MasterJSON, DefaultVarsJSON: canonical.DefaultsJSON, TemplateApprovedBy: actor, TemplateApprovedAt: stamp}, doc)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		if plain.sourceKind != "pdf" && plain.sourceKind != "blocks" {
			t.Fatal("invalid declared test source kind")
		}
		doc.SourceKind = plain.sourceKind
		doc.HtmlReviewedBy = pgtype.UUID{}
		doc.HtmlReviewedAt = pgtype.Timestamptz{}
		doc.HtmlReviewedPdfSha256 = nil
		if plain.blocks != nil {
			doc.BlocksJson = bytes.Clone(plain.blocks)
		}
		if plain.variables != nil {
			doc.VariablesJson = bytes.Clone(plain.variables)
		}
		if doc.SourceKind == "blocks" {
			doc.PdfStorageKey = pgtype.Text{}
			doc.PdfStorageVersionID = pgtype.Text{}
			doc.PdfSha256 = nil
			doc.HtmlReviewedBy = pgtype.UUID{}
			doc.HtmlReviewedAt = pgtype.Timestamptz{}
			doc.HtmlReviewedPdfSha256 = nil
		}
	}

	var work *ApplicationHTMLSendWorkV1
	var source *ApplicationHTMLSendSourceV1
	var evidence *ApplicationHTMLSendEvidenceV1
	t.Cleanup(func() {
		if evidence != nil {
			evidence.CloseConsumerV1()
		}
		if work != nil {
			work.CloseConsumerV1()
		}
		if !applicationDoneV1(fixture.done) {
			close(fixture.done)
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = fixture.adapter.CloseV1(cleanup)
	})
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
		// Synthetic complete typed body receipt AFTER its actual positive body loan.
		work.closes = append(work.closes, closeBody)
		work.sourceDocument = htmlSendCloneDocumentV1(doc)
		work.models = &HTMLSendModelsV1{Document: htmlSendCloneDocumentV1(doc)}
		work.modelsRead = true
		source, e = work.NewSourceV1(call)
		if e != nil {
			return e
		}
		if e = source.ValidateReviewedV1(); e != nil {
			return e
		}
		if plain != nil {
			if e = source.ValidateCurrentV1(); e != nil {
				return e
			}
		}
		if purpose == HTMLSendSnapshotV1 {
			evidence, e = work.NewEvidenceV1(call, source, client)
		}
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if purpose == HTMLSendPreparationV1 {
		evidence, err = work.NewDraftEvidenceV1(source, client)
		if err != nil {
			t.Fatal(err)
		}
	}
	return work, source, evidence, fixture, coordinator, ctx
}
func TestHTMLSendEvidenceActualConsumerJoinsSourceAndPhysicalDebtV1(t *testing.T) {
	for _, physicalFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(physicalFirst), func(t *testing.T) {
			work, source, evidence, fixture, coordinator, ctx := htmlSendEvidenceFixtureV1(t, HTMLSendPreparationV1)
			owner := source.state.owner
			owner.mu.Lock()
			uses := owner.active
			owner.mu.Unlock()
			if uses != 1 {
				t.Fatal("evidence did not retain a genuine original source consumer", uses)
			}
			if !evidence.lockV1() {
				t.Fatal("actual evidence entry refused")
			}
			original, s, done, err := evidence.beginV1()
			if err != nil {
				evidence.unlockV1()
				t.Fatal(err)
			}
			joined := false
			t.Cleanup(func() {
				if !joined {
					done()
					evidence.unlockV1()
				}
			})
			stream, err := evidence.providerV1(original)
			if err != nil {
				done()
				evidence.unlockV1()
				joined = true
				t.Fatal(err)
			}
			streamClosed := false
			t.Cleanup(func() {
				if !streamClosed {
					stream.Close()
				}
			})
			before := coordinator.SnapshotV1(work.session.state.org)
			if before.Global.ProviderStreams != 1 || before.Global.ParentBytes <= 512<<20 {
				t.Fatal("actual source scratch/stream missing", before)
			}
			if physicalFirst {
				close(fixture.done)
				if _, err = fixture.adapter.ReconcileCleanupV1(ctx); err != nil {
					t.Fatal(err)
				}
			}
			copied := &ApplicationHTMLSendEvidenceV1{self: evidence}
			copied.CloseConsumerV1()
			if evidence.closeRequested.Load() {
				t.Fatal("copied shell closed original consumer")
			}
			work.CloseConsumerV1()
			if work.resourcesClosed || owner.retired || coordinator.SnapshotV1(work.session.state.org) != before || evidence.original == nil {
				t.Fatal("consumer/cancellation refunded in-flight concrete source work")
			}
			if !s.closeRequested.Load() {
				t.Fatal("source consumer close was not requested")
			}
			// End the explicitly synthetic provider/call witness. No test claim that a
			// boolean retires a real remote provider; concrete HTTP Close is tested in
			// storage separately, and public actual PG/SDK journeys remain root-owned.
			stream.Close()
			streamClosed = true
			done()
			evidence.unlockV1()
			joined = true
			if evidence.original != nil || evidence.source != nil || evidence.work != nil || evidence.releaseSource != nil || !owner.retired || !work.resourcesClosed {
				t.Fatal("final join retained original variable model references")
			}
			if !physicalFirst {
				if coordinator.SnapshotV1(fixture.scope.OrgID) == (workguard.SnapshotV1{}) {
					t.Fatal("consumer-only closure credited synthetic unretired backend")
				}
				close(fixture.done)
			}
			if pending, err := fixture.adapter.ReconcileCleanupV1(ctx); err != nil || pending != 0 {
				t.Fatal("same physical+consumer conjunction did not settle", pending, err)
			}
			if coordinator.SnapshotV1(fixture.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("joined native evidence debt remains")
			}
		})
	}
}
func TestHTMLSendEvidencePurposeAndActualProviderCapacityRefuseV1(t *testing.T) {
	work, _, evidence, fixture, coordinator, ctx := htmlSendEvidenceFixtureV1(t, HTMLSendPreparationV1)
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	if err := evidence.PreparePinsV1(); err == nil {
		t.Fatal("draft evidence acquired pin authority")
	}
	if err := evidence.RetainReadyV1(time.Now().Add(time.Hour)); err == nil {
		t.Fatal("draft evidence acquired retention authority")
	}
	if coordinator.SnapshotV1(fixture.scope.OrgID) != before {
		t.Fatal("unsupported draft purpose acquired extra credit")
	}
	occupied, err := coordinator.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if !evidence.lockV1() {
		t.Fatal("actual evidence entry refused")
	}
	grant, err := evidence.providerV1(ctx)
	evidence.unlockV1()
	if err == nil || grant != nil {
		if grant != nil {
			grant.Close()
		}
		t.Fatal("real exhausted shared provider dimension admitted another stream")
	}
	work.CloseConsumerV1()
	var zero ApplicationHTMLSendEvidenceV1
	zero.CloseConsumerV1()
	if err = zero.PreparePinsV1(); err == nil {
		t.Fatal("zero evidence prepared pins")
	}
	if _, err = zero.InspectPDFV1(); err == nil {
		t.Fatal("zero evidence inspected")
	}
	if err = zero.BindPinnedV1(nil); err == nil {
		t.Fatal("zero evidence rebound")
	}
}

// A Fields handoff cannot inherit pinning's broader mutation exception. The
// UpdatedAt refresh is the sole permitted difference; evidence pins and the
// requirement bit are part of the immutable identity at this later phase.
func TestHTMLSendEvidenceFieldTuplePreservesPinsAndLegalIdentityV1(t *testing.T) {
	a := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Status: "sealing", SourceKind: "pdf", Name: "Reviewed contract", EvidenceVersionPinsRequired: true, PdfStorageKey: pgtype.Text{String: "contract.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "version-one", Valid: true}, PdfSha256: []byte{1, 2, 3}, HtmlSourceJson: []byte("reviewed source"), Metadata: []byte("{}"), UpdatedAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}}
	b := htmlSendCloneDocumentV1(a)
	b.UpdatedAt.Time = b.UpdatedAt.Time.Add(time.Second)
	if !htmlSendEvidenceFieldTupleEqualV1(a, b) {
		t.Fatal("sole timestamp refresh refused")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"pin requirement", func(d *generated.Document) { d.EvidenceVersionPinsRequired = false }},
		{"source version", func(d *generated.Document) { d.PdfStorageVersionID.String = "other-version" }},
		{"rendered version", func(d *generated.Document) {
			d.RenderedPdfVersionID = pgtype.Text{String: "other-version", Valid: true}
		}},
		{"source digest", func(d *generated.Document) { d.PdfSha256[0]++ }},
		{"reviewed source", func(d *generated.Document) { d.HtmlSourceJson[0]++ }},
		{"metadata", func(d *generated.Document) { d.Metadata = []byte("null") }},
		{"signature requirement", func(d *generated.Document) { d.RequiresSignature = true }},
		{"expiry", func(d *generated.Document) { d.ExpiresAt = pgtype.Timestamptz{Time: time.Now(), Valid: true} }},
		{"legal basis", func(d *generated.Document) { d.LawfulBasis = "consent" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := htmlSendCloneDocumentV1(b)
			tc.mutate(changed)
			if htmlSendEvidenceFieldTupleEqualV1(a, changed) {
				t.Fatal("different contract/evidence identity transferred")
			}
		})
	}
	if htmlSendEvidenceFieldTupleEqualV1(nil, b) || htmlSendEvidenceFieldTupleEqualV1(a, nil) {
		t.Fatal("missing tuple transferred")
	}
}

// SQL and provider inspection witnesses here are deliberately synthetic. The
// actual Work/source constructors, reviewed/Current/party policies, positive
// shared source/body loans, transfer and consumer joins are real methods. This
// does not claim that PG pin SQL or external PDF inspection occurred.
func TestHTMLSendEvidenceFieldsRequiresInspectedSourceAndTransfersActualBorrowerV1(t *testing.T) {
	oldWork, oldSource, evidence, fixture, coordinator, ctx := htmlSendEvidenceFixtureV1(t, HTMLSendSnapshotV1)
	operation := oldWork.stage.operation
	session := oldWork.session
	stage := &ApplicationHTMLSendSQLStageV1{operation: operation, purpose: HTMLSendSnapshotFieldsV1, ctx: ctx, cancel: func() {}, session: session, active: true}
	stage.self = stage
	operation.stages = append(operation.stages, stage)
	var work *ApplicationHTMLSendWorkV1
	var source *ApplicationHTMLSendSourceV1
	t.Cleanup(func() {
		if work != nil {
			work.CloseConsumerV1()
		}
	})
	err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		work, err = session.NewHTMLSendWorkV1(call, stage)
		if err != nil {
			return err
		}
		doc := htmlSendCloneDocumentV1(oldSource.state.owner.snapshot.document)
		doc.UpdatedAt.Time = doc.UpdatedAt.Time.Add(time.Second)
		wire, err := htmlAuthoringSumV1(int64(len(doc.HtmlSourceJson)), int64(len(doc.VariablesJson)), int64(len(doc.BlocksJson)), int64(len(doc.Metadata)), int64(len(doc.MetadataRedactionReport)))
		if err != nil {
			return err
		}
		closeBody, err := work.actor.acquireOwnedRetainedBodyV1(call, signerDocumentRawBytesV1(doc), wire)
		if err != nil {
			return err
		}
		// Explicit typed SQL body/empty collection witness after the real body loan.
		work.closes = append(work.closes, closeBody)
		work.sourceDocument = htmlSendCloneDocumentV1(doc)
		work.models = &HTMLSendModelsV1{Document: doc}
		work.modelsRead = true
		work.recipientsRead = true
		work.fieldsRead = true
		source, err = work.NewSourceV1(call)
		if err != nil {
			return err
		}
		if err = source.ValidateReviewedV1(); err != nil {
			return err
		}
		if err = source.ValidateCurrentV1(); err != nil {
			return err
		}
		return source.ValidatePartiesV1(doc, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic witness of the prior pin phase; actual external inspection must
	// still precede handoff. The missing inspection must not acquire more debt.
	evidence.bound = true
	before := coordinator.SnapshotV1(fixture.scope.OrgID)
	if err = evidence.BindFieldsV1(source); err == nil {
		t.Fatal("uninspected source transferred")
	}
	if coordinator.SnapshotV1(fixture.scope.OrgID) != before {
		t.Fatal("refused transfer changed debt")
	}
	evidence.inspectAttempted = true
	evidence.pages = 1
	oldOwner, newOwner := oldSource.state.owner, source.state.owner
	oldOwner.mu.Lock()
	oldUses := oldOwner.active
	oldOwner.mu.Unlock()
	newOwner.mu.Lock()
	newUses := newOwner.active
	newOwner.mu.Unlock()
	if oldUses != 1 || newUses != 0 {
		t.Fatal("unexpected original source consumer counts", oldUses, newUses)
	}
	originalRequirement := work.sourceDocument.EvidenceVersionPinsRequired
	work.sourceDocument.EvidenceVersionPinsRequired = !originalRequirement
	if err = evidence.BindFieldsV1(source); err == nil {
		t.Fatal("changed pin requirement transferred")
	}
	work.sourceDocument.EvidenceVersionPinsRequired = originalRequirement
	if evidence.source != oldSource.state {
		t.Fatal("refused transfer replaced old source")
	}
	if err = evidence.BindFieldsV1(source); err != nil {
		t.Fatal(err)
	}
	oldOwner.mu.Lock()
	oldUses = oldOwner.active
	oldOwner.mu.Unlock()
	newOwner.mu.Lock()
	newUses = newOwner.active
	newOwner.mu.Unlock()
	if oldUses != 0 || newUses != 1 || evidence.source != source.state || evidence.work != work || !evidence.fieldsBound {
		t.Fatal("actual source consumer did not transfer", oldUses, newUses)
	}
	if err = evidence.BindFieldsV1(oldSource); err == nil {
		t.Fatal("second fields handoff admitted")
	}
	if oldWork.evidence != nil || work.evidence != evidence {
		t.Fatal("evidence remained registered to superseded work")
	}
	oldWork.CloseConsumerV1()
	if evidence.closeRequested.Load() {
		t.Fatal("superseded work closed the transferred evidence")
	}
	if pages, err := evidence.InspectPDFV1(); err != nil || pages != 1 {
		t.Fatal("handoff lost the prior exact inspection", pages, err)
	}
	work.CloseConsumerV1()
	if !evidence.closeRequested.Load() {
		t.Fatal("current work did not close its actual evidence consumer")
	}
	newOwner.mu.Lock()
	newUses = newOwner.active
	newOwner.mu.Unlock()
	if newUses != 0 {
		t.Fatal("consumer closure retained active source use", newUses)
	}
}
