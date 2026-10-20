//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
)

func TestOwnedSignerReadRecheckPurposePreservesPolicyAndRejectsMutationE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	bootstrap := q.lookupV1(t, parties[0].Token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(parties[0].Token, ""), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(bootstrap, notice)
	if err != nil {
		t.Fatal(err)
	}
	commentInput, _, closeCommentInput := nativePublicCommentInput164V1(t, q, f.ctx, bootstrap, parties[0].Token)
	if err := bootstrap.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.reconcileV1(t)
	factory := q.runtime.SessionsV1()
	scope, err := factory.ProbeSignerScopeV1(f.ctx, auth.HashMagicToken(parties[0].Token))
	var readers []*pdfadmission.ApplicationSignerReaderV1
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, r := range readers {
			if err := r.CloseV1(cleanup); err != nil {
				t.Error(err)
			}
		}
		if scope != nil {
			scope.CloseConsumerV1()
		}
		if err := factory.ReconcileCleanupV1(cleanup); err != nil {
			t.Error(err)
		}
	})
	if err != nil || scope == nil {
		t.Fatal("actual shared signer scope did not resolve", err)
	}
	baseline := q.snapshotV1(t)
	for _, mode := range []pdfadmission.SignerReadModeV1{"", "unknown-purpose", "active-response-v2"} {
		before, pending := q.snapshotV1(t), factory.PendingV1()
		r, err := factory.NewSignerReaderV1(f.ctx, scope, mode)
		if r != nil || !errors.Is(err, pdfadmission.ErrSignerReadV1) || q.snapshotV1(t) != before || factory.PendingV1() != pending {
			t.Fatal("unknown purpose registered or acquired native resources", mode, err)
		}
	}
	var models [3]*pdfadmission.ApplicationSignerReadModelsV1
	var callbackSnapshots [3]workguard.SnapshotV1
	snapshots := [3]struct{ parent, db, globalGrants, orgGrants int64 }{}
	for i, mode := range []pdfadmission.SignerReadModeV1{pdfadmission.SignerReadActiveV1, pdfadmission.SignerReadActiveRecheckV1, pdfadmission.SignerReadActiveResponseV1} {
		r, err := factory.NewSignerReaderV1(f.ctx, scope, mode)
		if r != nil {
			readers = append(readers, r)
		}
		if err != nil {
			t.Fatal("genuine purpose reader did not open", mode, err)
		}
		err = r.WithModelsV1(f.ctx, func(a pdfadmission.ApplicationSignerReadAccessV1) error {
			now := time.Now()
			if !a.ActiveCeremony || a.CompletedCeremony || (a.DocumentExpiresAt.Valid && !now.Before(a.DocumentExpiresAt.Time)) || (a.RecipientExpiresAt.Valid && !now.Before(a.RecipientExpiresAt.Time)) {
				return errSignerReadChanged
			}
			return nil
		}, func(_ context.Context, m *pdfadmission.ApplicationSignerReadModelsV1) error {
			if m == nil || m.Document == nil || m.Document.ID != doc.ID || m.Document.OrgID != f.org || m.Recipient == nil || m.Recipient.ID != parties[0].RecipientID || m.ControllerOrg == nil || m.ControllerOrg.ID != f.org || m.LawfulBasisConfirmation == nil || m.Current == nil ||
				m.Document.SourceKind != "pdf" || len(m.Document.HtmlSourceJson) == 0 || len(m.Document.HtmlCurrentSourceJson) == 0 || len(m.Document.VariablesJson) == 0 || len(m.Document.MetadataRedactionReport) == 0 {
				return errSignerReadChanged
			}
			models[i] = m // Both genuine consumers stay live through comparison.
			callbackSnapshots[i] = q.snapshotV1(t)
			return nil
		})
		if err != nil {
			t.Fatal("full actual policy projection failed", mode, err)
		}
		if s := q.snapshotV1(t); s != callbackSnapshots[i] {
			t.Fatal("ending scalar-header consumption credited live SQL", s, callbackSnapshots[i])
		}
		if err := r.CommitReadV1(f.ctx); err != nil {
			t.Fatal(err)
		}
		beforeClose := q.snapshotV1(t)
		if beforeClose != callbackSnapshots[i] {
			t.Fatal("logical read commit credited an unretired client", beforeClose, callbackSnapshots[i])
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		err = r.CloseSQLV1(cleanup)
		stop()
		if err != nil {
			t.Fatal(err)
		}
		s := q.snapshotV1(t)
		want := beforeClose
		want.Global.ParentBytes -= 32 << 20
		want.Organisation.ParentBytes -= 32 << 20
		want.Global.DBStagingBytes -= 32 << 20
		want.Organisation.DBStagingBytes -= 32 << 20
		want.Global.SQLSessions--
		want.Organisation.SQLSessions--
		want.GlobalGrants -= 2
		want.OrganisationGrants -= 2
		if s != want {
			t.Fatal("physical retirement did not release exactly finished header and SQL while retaining bodies", s, want)
		}
		if s.Global.SQLSessions != 2 || s.Organisation.SQLSessions != 1 {
			t.Fatal("purpose reader physical SQL did not retire", s)
		}
		snapshots[i] = struct{ parent, db, globalGrants, orgGrants int64 }{s.Global.ParentBytes, s.Global.DBStagingBytes, s.GlobalGrants, s.OrganisationGrants}
	}
	if !reflect.DeepEqual(models[0], models[1]) || !reflect.DeepEqual(models[0], models[2]) {
		t.Fatal("read-only purpose omitted or changed actual legal/current policy projection")
	}
	activeParent, activeDB := snapshots[0].parent-baseline.Global.ParentBytes, snapshots[0].db-baseline.Global.DBStagingBytes
	readParent, readDB := snapshots[1].parent-snapshots[0].parent, snapshots[1].db-snapshots[0].db
	responseParent, responseDB := snapshots[2].parent-snapshots[1].parent, snapshots[2].db-snapshots[1].db
	d, rec := models[0].Document, models[0].Recipient
	sourceBytes := int64(len(d.BlocksJson) + len(d.VariablesJson) + len(rec.Role) + len(d.SourceKind) + len(d.PdfStorageKey.String) + len(d.PdfStorageVersionID.String) + len(d.PdfSha256))
	if activeDB-readDB != 32<<20+16*sourceBytes || activeParent-readParent != 32<<20+24*sourceBytes ||
		responseDB != readDB || responseParent != readParent ||
		snapshots[0].globalGrants-baseline.GlobalGrants != 2 || snapshots[0].orgGrants-baseline.OrganisationGrants != 2 ||
		snapshots[1].globalGrants-snapshots[0].globalGrants != 1 || snapshots[1].orgGrants-snapshots[0].orgGrants != 1 ||
		snapshots[2].globalGrants-snapshots[1].globalGrants != 1 || snapshots[2].orgGrants-snapshots[1].orgGrants != 1 {
		t.Fatal("actual purpose did not omit exactly one retained source-copy loan", sourceBytes, snapshots, baseline)
	}
	const ip, userAgent = "127.0.0.1", "Synthetic recheck purpose"
	controls := []struct {
		name        string
		unavailable error
		open        func(*pdfadmission.ApplicationSignerReaderV1) (func(), error)
	}{
		{"block signature", pdfadmission.ErrBlockSignatureRequestV1, func(r *pdfadmission.ApplicationSignerReaderV1) (func(), error) {
			request, err := factory.NewBlockSignatureRequestV1(f.ctx, r, parties[0].Name, "Caveat", ip, userAgent)
			if request == nil {
				return nil, err
			}
			return request.CloseConsumerV1, err
		}},
		{"acknowledgement", pdfadmission.ErrAcknowledgementRequestV1, func(r *pdfadmission.ApplicationSignerReaderV1) (func(), error) {
			request, err := factory.NewAcknowledgementRequestV1(f.ctx, r, ip, userAgent, evidence)
			if request == nil {
				return nil, err
			}
			return request.CloseConsumerV1, err
		}},
		{"view", pdfadmission.ErrSignerViewRequestV1, func(r *pdfadmission.ApplicationSignerReaderV1) (func(), error) {
			request, err := factory.NewSignerViewRequestV1(f.ctx, r, ip, userAgent, evidence)
			if request == nil {
				return nil, err
			}
			return request.CloseConsumerV1, err
		}},
		{"field submission", pdfadmission.ErrSignerFieldsRequestV1, func(r *pdfadmission.ApplicationSignerReaderV1) (func(), error) {
			request, err := factory.NewSignerFieldsRequestV1(f.ctx, r, ip, userAgent, evidence)
			if request == nil {
				return nil, err
			}
			return request.CloseConsumerV1, err
		}},
		{"comment", pdfadmission.ErrCommentRequestV1, func(r *pdfadmission.ApplicationSignerReaderV1) (func(), error) {
			request, err := factory.NewSignerCommentRequestV1(r, commentInput, ip, userAgent, evidence)
			if request == nil {
				return nil, err
			}
			return request.CloseConsumerV1, err
		}},
	}
	for _, control := range controls {
		before, pending := q.snapshotV1(t), factory.PendingV1()
		for _, r := range readers[1:] {
			closeRequest, err := control.open(r)
			if closeRequest != nil {
				closeRequest()
			}
			if closeRequest != nil || !errors.Is(err, control.unavailable) || q.snapshotV1(t) != before || factory.PendingV1() != pending {
				t.Fatal("read-only purpose acquired native mutation input or resource debt", control.name, err)
			}
		}
		// Same valid arguments on the actual Active reader must be admissible.
		// Close unused consumers immediately; no binding, preparation or mutation.
		closeRequest, err := control.open(readers[0])
		if closeRequest != nil {
			defer closeRequest()
		}
		if err != nil || closeRequest == nil {
			t.Fatal("active constructor control did not accept valid actual inputs", control.name, err)
		}
		if current := q.snapshotV1(t); current.GlobalGrants != before.GlobalGrants+1 || current.OrganisationGrants != before.OrganisationGrants+1 || current.Global.DBStagingBytes != before.Global.DBStagingBytes {
			t.Fatal("active control grant not genuinely retained", control.name, current, before)
		}
		closeRequest()
		if q.snapshotV1(t) != before || factory.PendingV1() != pending {
			t.Fatal("actual unused active request did not retire", control.name)
		}
	}
	beforePage, beforePending := q.snapshotV1(t), factory.PendingV1()
	page, pageErr := factory.NewSignerCommentPageInputV1(f.ctx, readers[1], "")
	if page != nil || !errors.Is(pageErr, pdfadmission.ErrCommentPageV1) || q.snapshotV1(t) != beforePage || factory.PendingV1() != beforePending {
		t.Fatal("recheck purpose acquired response input", pageErr)
	}
	page, pageErr = factory.NewSignerCommentPageInputV1(f.ctx, readers[2], "")
	if pageErr != nil || page == nil {
		t.Fatal("actual response purpose could not create its bounded page input", pageErr)
	}
	page.CloseConsumerV1()
	if q.snapshotV1(t) != beforePage || factory.PendingV1() != beforePending {
		t.Fatal("unused actual response input did not restore its retained model baseline")
	}
	t.Logf("genuine Active/recheck/response full policy projections equal; exactly one snapshot loan omitted: DB=%d Parent=%d; all five native mutation constructors refused without grants", activeDB-readDB, activeParent-readParent)
	models = [3]*pdfadmission.ApplicationSignerReadModelsV1{}
	for _, r := range readers {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		err := r.CloseV1(cleanup)
		stop()
		if err != nil {
			t.Fatal(err)
		}
	}
	readers = nil
	if got := q.snapshotV1(t); got != baseline {
		t.Fatal("retired model consumers did not restore the still-owned original scope", got, baseline)
	}
	scope.CloseConsumerV1()
	scope = nil
	closeCommentInput()
	q.assertObserversOnlyV1(t)
	t.Log("genuine recheck-purpose readers, scope and request controls retired to observers only")
}
