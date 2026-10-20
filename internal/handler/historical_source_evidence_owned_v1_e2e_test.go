//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Actual creator/recipient/field/Send/Sign/worker/nativeSQL are real. Only the
// renderer and concrete S3 protocol peers are synthetic. This proves original
// exact input bytes and actual copied-Close/SDK/body joins, not provider Object
// Lock efficacy, legacy fixture migration or production capacity.
func TestOwnedHistoricalSourceInputsKeepBodyThroughActualCopiedCloseE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Native source body consumer")))
	if response.Code != http.StatusCreated {
		t.Fatalf("actual source upload=%d %s", response.Code, response.Body.String())
	}
	var imported struct {
		Document documentResponse `json:"document"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &imported); err != nil || imported.Document.ID == uuid.Nil {
		t.Fatal("actual source upload omitted document", err)
	}
	id := imported.Document.ID
	base := "/api/v1/documents/" + id.String()
	response = submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", `{"email":"source-input@example.test","name":"Native input signer","role":"buyer","locale":"en"}`, q.cookie)
	var recipient recipientResponse
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &recipient) != nil || recipient.ID == uuid.Nil {
		t.Fatalf("actual source participant=%d %s", response.Code, response.Body.String())
	}
	field, _ := json.Marshal(map[string]any{"recipient_id": recipient.ID.String(), "type": "signature", "page": 1, "x_pct": 15, "y_pct": 55, "w_pct": 30, "h_pct": 8, "required": true})
	response = submitSessionOperationE2E(f.s, http.MethodPost, base+"/fields", string(field), q.cookie)
	if response.Code != http.StatusCreated {
		t.Fatalf("actual source field=%d %s", response.Code, response.Body.String())
	}
	response = submitSessionOperationE2E(f.s, http.MethodPost, base+"/send", `{"lawful_basis":"contract"}`, q.cookie)
	var sent sendDocumentResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sent) != nil || len(sent.Links) != 1 {
		t.Fatalf("actual source Send=%d %s", response.Code, response.Body.String())
	}
	ownedPlainAssertDrainedV1(t, q)
	brokenRenderer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "synthetic render outage after actual signature claim", http.StatusServiceUnavailable)
	}))
	t.Cleanup(brokenRenderer.Close)
	f.s.Sign.PDF = render.NewGotenberg(brokenRenderer.URL)
	link, err := url.Parse(sent.Links[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimPrefix(link.Path, "/sign/")
	rc := q.lookupV1(t, token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: sent.Links[0].Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "actual source retained callback"})
	if err != nil || result == nil || result.Completed {
		t.Fatal("actual interrupted finalizer boundary changed", err)
	}
	if err = rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	ownedPlainAssertDrainedV1(t, q)
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil || doc.Status != "finalizing" || !doc.CompletionEffectiveAtBound {
		t.Fatal("actual public signature did not leave genuine recoverable finalizing source", err)
	}
	operation, err := q.runtime.SessionsV1().NewHTMLSendOperationV1(f.ctx, f.org, id)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { operation.CloseConsumerV1(); q.reconcileV1(t) }()
	stage, err := operation.OpenSQLV1(pdfadmission.HTMLHistoricalFinalizationSourceV1)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.CloseSQLV1()
	session := stage.SessionV1()
	if _, err = session.NewAdmissionV1(stage.ContextV1()); err != nil {
		t.Fatal(err)
	}
	var source *pdfadmission.ApplicationHistoricalFinalizationSourceEvidenceV1
	err = stage.WithTxV1(func(call context.Context, _ generated.DBTX) error {
		work, e := session.NewHTMLSendWorkV1(call, stage)
		if e != nil {
			return e
		}
		if _, e = work.StateV1(call); e != nil {
			return e
		}
		if _, e = work.ReadModelsV1(call); e != nil {
			return e
		}
		source, e = work.NewHistoricalFinalizationSourceEvidenceV1(call, f.s.Storage)
		if e != nil {
			return e
		}
		actual, e := source.EnsureSourceVersionsV1(call)
		if e != nil {
			return e
		}
		if actual.ID != id || !source.MatchesDocumentV1(actual) {
			t.Error("actual private source equality lost")
		}
		return source.EnsureSignatureVersionsV1(call)
	})
	if err != nil {
		t.Fatal("actual native source/version/signature inputs", err)
	}
	if err = session.CommitV1(stage.ContextV1()); err != nil {
		t.Fatal(err)
	}
	if err = stage.CloseSQLV1(); err != nil {
		t.Fatal(err)
	}
	rows, err := source.SignatureRowsV1()
	if err != nil || len(rows) != 1 {
		t.Fatal("actual retained signature inventory missing", err)
	}
	if err = source.WithSignatureBodyV1(rows[0].ID, func(body []byte) error {
		sum := sha256.Sum256(body)
		if len(body) == 0 || !bytes.Equal(sum[:], rows[0].ImageSha256) {
			t.Error("actual pinned signature bytes changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A fresh actual render continuation reuses only its own original private
	// source under a new native scalar row lock. The separately priced public
	// view cannot change the actual source, rows or future child source authority.
	renderStage, err := operation.OpenSQLV1(pdfadmission.HTMLHistoricalFinalizationSourceV1)
	if err != nil {
		t.Fatal(err)
	}
	renderSession := renderStage.SessionV1()
	if _, err = renderSession.NewAdmissionV1(renderStage.ContextV1()); err != nil {
		t.Fatal(err)
	}
	err = renderStage.WithTxV1(func(call context.Context, _ generated.DBTX) error {
		work, e := renderSession.NewHTMLSendWorkV1(call, renderStage)
		if e != nil {
			return e
		}
		if _, e = work.StateV1(call); e != nil {
			return e
		}
		view, e := source.NewHistoricalRenderContinuationV1(call, work)
		if e != nil {
			return e
		}
		if view.ID != id || view.OrgID != f.org || !source.MatchesDocumentV1(view) {
			return sign.ErrDocumentRevisedDuringFinalize
		}
		beforeView := *view
		beforeView.PdfSha256 = bytes.Clone(view.PdfSha256)
		view.Name = "caller-only changed view"
		if len(view.PdfSha256) > 0 {
			view.PdfSha256[0] ^= 0xff
		}
		if !source.MatchesDocumentV1(&beforeView) {
			return sign.ErrDocumentRevisedDuringFinalize
		}
		participants, e := work.ReadRecipientsV1(call)
		if e != nil {
			return e
		}
		if len(participants) != 1 || participants[0].ID != recipient.ID {
			return sign.ErrDocumentRevisedDuringFinalize
		}
		fields, e := work.ReadFieldsV1(call)
		if e != nil {
			return e
		}
		if len(fields) != 1 || fields[0].DocumentID != id {
			return sign.ErrDocumentRevisedDuringFinalize
		}
		nativeSource, e := work.NewSourceV1(call)
		if e != nil {
			return e
		}
		if e = nativeSource.ValidateReviewedV1(); e != nil {
			return e
		}
		if !nativeSource.MatchesDocumentV1(&beforeView) {
			return sign.ErrDocumentRevisedDuringFinalize
		}
		nativeSource = nil
		work.CloseConsumerV1()
		return nil
	})
	if err != nil {
		t.Fatal("actual render continuation/native collections/private source", err)
	}
	if err = renderSession.CommitV1(renderStage.ContextV1()); err != nil {
		t.Fatal(err)
	}
	if err = renderStage.CloseSQLV1(); err != nil {
		t.Fatal(err)
	}
	before, err := q.runtime.SnapshotV1(f.org)
	if err != nil {
		t.Fatal(err)
	}
	entered, release, returned, done := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Error("actual source body consumer failed to join cleanup")
		}
	}()
	go func() {
		defer close(done)
		returned <- source.WithSourcePDFV1(func(body []byte) error {
			sum := sha256.Sum256(body)
			if !bytes.HasPrefix(body, []byte("%PDF-")) || !bytes.Equal(sum[:], doc.PdfSha256) {
				return sign.ErrDocumentRevisedDuringFinalize
			}
			if err := source.WithSignatureBodyV1(rows[0].ID, func(span []byte) error {
				signatureSum := sha256.Sum256(span)
				if len(span) == 0 || !bytes.Equal(signatureSum[:], rows[0].ImageSha256) || !bytes.HasPrefix(body, []byte("%PDF-")) || !bytes.Equal(sum[:], doc.PdfSha256) {
					return sign.ErrDocumentRevisedDuringFinalize
				}
				return nil
			}); err != nil {
				return err
			}
			close(entered)
			<-release
			return nil
		})
	}()
	ownedPlainAwaitV1(t, entered, "actual pinned PDF body callback")
	source.CloseConsumerV1() // copied Close while the genuine callback is active
	q.reconcileV1(t)
	during, err := q.runtime.SnapshotV1(f.org)
	if err != nil || during.Global.ParentBytes <= before.Global.ParentBytes || during.Global.ProviderStreams != 0 || during.Organisation.ProviderStreams != 0 {
		t.Fatal("copied Close or SDK stream retirement credited an active input body", err)
	}
	select {
	case err := <-returned:
		t.Fatal("actual callback ended before its own last use", err)
	default:
	}
	close(release)
	if err = <-returned; err != nil {
		t.Fatal(err)
	}
	operation.CloseConsumerV1()
	ownedPlainAssertDrainedV1(t, q)
}
