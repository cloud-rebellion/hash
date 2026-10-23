//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func sentLaterAmendment483(t *testing.T, mode amendments.ModeV1) (laterAmendmentFixture483, string) {
	t.Helper()
	f := newLaterAmendmentFixture483(t, mode)
	actor := packageActor220(t, f.q)
	sent, e := f.q.f.s.Send.Send(f.q.f.ctx, send.Actor{OrgID: actor.OrgID, UserID: &actor.UserID, Via: "rest", LawfulBasis: "contract", Authorize: actor.Authorize}, f.candidate.ID)
	defer sent.CloseConsumerV1()
	if e != nil || sent.Status != "sent" || len(sent.Links) != 1 {
		t.Fatal("real independent amendment Send", e)
	}
	u, e := url.Parse(sent.Links[0].URL)
	if e != nil {
		t.Fatal(e)
	}
	token := strings.TrimPrefix(u.Path, "/sign/")
	sent.CloseConsumerV1()
	f.q.assertObserversOnlyV1(t)
	return f, token
}
func TestLaterAmendmentSignerContextNativeOriginalPinsAndNoOriginalLockV1E2E(t *testing.T) {
	for _, mode := range []amendments.ModeV1{amendments.SignatureV1, amendments.AcknowledgementV1} {
		t.Run(string(mode), func(t *testing.T) {
			f, token := sentLaterAmendment483(t, mode)
			var name, final, report, reportPDF string
			e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT p->>'original_name',p->'final_pdf'->>'sha256',p->>'report_sha256',p->'report_pdf'->>'sha256' FROM document_amendments_v1 a CROSS JOIN LATERAL (SELECT convert_from(a.original_pins,'UTF8')::jsonb p) saved WHERE a.id=$1`, f.record.ID).Scan(&name, &final, &report, &reportPDF)
			if e != nil {
				t.Fatal(e)
			}
			// This actual original row lock would block any candidate->original late
			// SHARE lock. The public reader must use immutable captured pins instead.
			lock, e := f.q.f.pool.Begin(f.q.f.ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer lock.Rollback(context.Background())
			if _, e = lock.Exec(f.q.f.ctx, `SELECT id FROM documents WHERE id=$1 FOR UPDATE NOWAIT`, f.original.ID); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(f.q.f.ctx, 2*time.Second)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, f.q.f.s.PublicURL+"/sign/"+token, nil).WithContext(ctx)
			f.q.f.s.Routes().ServeHTTP(w, r)
			cancel()
			if e = lock.Rollback(f.q.f.ctx); e != nil {
				t.Fatal(e)
			}
			var response struct {
				Context           *amendments.SignerContextV1 `json:"amendment_context"`
				RequiresSignature bool                        `json:"requires_signature"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Context == nil {
				t.Fatal("actual native public disclosure", w.Code, w.Body.String())
			}
			c := response.Context
			if c.ValidateV1(f.candidate.ID, mode == amendments.SignatureV1) != nil || c.AmendmentID != f.record.ID || c.Revision != "1" || c.OriginalDocumentID != f.original.ID || c.OriginalName != name || c.OriginalFinalPDFSHA256 != final || c.OriginalReportSHA256 != report || c.OriginalReportPDFSHA256 != reportPDF || c.FileCommitmentSHA256 != f.record.FileCommitmentSHA256 || c.Mode != mode || response.RequiresSignature != (mode == amendments.SignatureV1) {
				t.Fatal("saved-original context substituted current proposal/report", c)
			}
			var wire map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &wire) != nil {
				t.Fatal("context JSON")
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(wire["amendment_context"], &fields) != nil || len(fields) != 11 {
				t.Fatal("disclosure widened to original private artifacts or missing typed fields", fields)
			}
			if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
				t.Fatal("public context changed completed original")
			}
			f.q.assertObserversOnlyV1(t)
		})
	}
	ordinary := newOwnedPublicReadFixtureV1(t)
	_, parties := ordinary.createSentV1(t)
	w := ordinary.requestV1(parties[0].Token, "")
	var response map[string]json.RawMessage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response["amendment_context"]) != 0 {
		t.Fatal("ordinary ceremony gained amendment authority", w.Code, w.Body.String())
	}
	ordinary.assertObserversOnlyV1(t)
}
func TestLaterAmendmentSignerContextRetainedFreshAndJoinedConsumerV1E2E(t *testing.T) {
	f, token := sentLaterAmendment483(t, amendments.AcknowledgementV1)
	rc := f.q.lookupV1(t, token)
	if rc.AmendmentContext == nil {
		t.Fatal("native reader omitted amendment context")
	}
	saved := amendments.CloneSignerContextV1(rc.AmendmentContext)
	before := f.q.snapshotV1(t)
	pending := f.q.runtime.SessionsV1().PendingV1()
	if before.Global.ParentBytes <= 0 || before.Global.DBStagingBytes <= 0 || pending.SignerReaders != 1 {
		t.Fatal("context body has no retained actual loan", before, pending)
	}
	rc.AmendmentContext.OriginalName += " caller changed"
	if e := f.q.f.s.Sign.RecheckRecipientReadV1(f.q.f.ctx, rc, func(*sign.RecipientContext) error { t.Error("changed caller reached fresh callback"); return nil }); e == nil || f.q.snapshotV1(t) != before || f.q.runtime.SessionsV1().PendingV1() != pending {
		t.Fatal("forged caller context used or opened new native work", e)
	}
	rc.AmendmentContext = amendments.CloneSignerContextV1(saved)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- f.q.f.s.Sign.RecheckRecipientReadV1(f.q.f.ctx, rc, func(fresh *sign.RecipientContext) error {
			if !amendments.EqualSignerContextV1(saved, fresh.AmendmentContext) {
				return errors.New("fresh actual context differs")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case e := <-done:
		t.Fatal("fresh native context failed", e)
	case <-time.After(5 * time.Second):
		t.Fatal("fresh context did not reach actual callback")
	}
	during := f.q.snapshotV1(t)
	if e := rc.CloseReadV1(); !errors.Is(e, sign.ErrSigningAdmissionUnavailableV1) {
		close(release)
		<-done
		t.Fatal("last logical close escaped live borrowed context", e)
	}
	if f.q.snapshotV1(t) != during {
		close(release)
		<-done
		t.Fatal("live native context body credited before joined recheck")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal("original allowed recheck did not join", e)
	}
	if e := f.q.f.s.Sign.RecheckRecipientReadV1(f.q.f.ctx, rc, func(*sign.RecipientContext) error { return nil }); e == nil {
		t.Fatal("closed context reused as authority")
	}
	f.q.assertObserversOnlyV1(t)
	if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
		t.Fatal("read lifetime changed original")
	}
}
func TestLaterAmendmentSignerContextRejectsCorruptCapturedRelationV1E2E(t *testing.T) {
	for _, mutation := range []string{"missing_name", "bad_report", "changed_file_version", "notice_mode"} {
		t.Run(mutation, func(t *testing.T) {
			f, token := sentLaterAmendment483(t, amendments.SignatureV1)
			// An explicit isolated damaged-state fixture. The real immutable trigger is
			// first proven to reject a mutation; only this fixture then disables that
			// one guard in a transaction, preserving ALL CHECK/FK constraints. This is
			// a negative reader test, never a supported authoring or historical proof.
			if _, e := f.q.f.pool.Exec(f.q.f.ctx, `UPDATE document_amendments_v1 SET mode='acknowledgement' WHERE id=$1`, f.record.ID); e == nil {
				t.Fatal("actual immutable relation guard absent")
			}
			tx, e := f.q.f.pool.Begin(f.q.f.ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(context.Background())
			if _, e = tx.Exec(f.q.f.ctx, `ALTER TABLE document_amendments_v1 DISABLE TRIGGER amendment_immutable_v1`); e != nil {
				t.Fatal(e)
			}
			switch mutation {
			case "missing_name":
				_, e = tx.Exec(f.q.f.ctx, `UPDATE document_amendments_v1 SET original_pins=convert_to((convert_from(original_pins,'UTF8')::jsonb-'original_name')::text,'UTF8'),original_pins_sha256=sha256(convert_to((convert_from(original_pins,'UTF8')::jsonb-'original_name')::text,'UTF8')) WHERE id=$1`, f.record.ID)
			case "bad_report":
				_, e = tx.Exec(f.q.f.ctx, `UPDATE document_amendments_v1 SET original_pins=convert_to(jsonb_set(convert_from(original_pins,'UTF8')::jsonb,'{report_sha256}','"unverified"'::jsonb)::text,'UTF8'),original_pins_sha256=sha256(convert_to(jsonb_set(convert_from(original_pins,'UTF8')::jsonb,'{report_sha256}','"unverified"'::jsonb)::text,'UTF8')) WHERE id=$1`, f.record.ID)
			case "changed_file_version":
				_, e = tx.Exec(f.q.f.ctx, `UPDATE document_amendments_v1 SET file_set=convert_to(jsonb_set(convert_from(file_set,'UTF8')::jsonb,'{files,0,version_id}','"wrong-exact-version"'::jsonb)::text,'UTF8'),file_commitment_sha256=sha256(convert_to('hash:later-amendment-files:v1','UTF8')||decode('00','hex')||convert_to(jsonb_set(convert_from(file_set,'UTF8')::jsonb,'{files,0,version_id}','"wrong-exact-version"'::jsonb)::text,'UTF8')) WHERE id=$1`, f.record.ID)
			case "notice_mode":
				_, e = tx.Exec(f.q.f.ctx, `UPDATE document_amendments_v1 SET mode='agreed_notice' WHERE id=$1`, f.record.ID)
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = tx.Exec(f.q.f.ctx, `ALTER TABLE document_amendments_v1 ENABLE TRIGGER amendment_immutable_v1`); e != nil {
				t.Fatal(e)
			}
			if e = tx.Commit(f.q.f.ctx); e != nil {
				t.Fatal(e)
			}
			rc, e := f.q.f.s.Sign.LookupByToken(f.q.f.ctx, auth.HashMagicToken(token))
			if rc != nil {
				rc.CloseReadV1()
				t.Fatal("damaged relation became public ceremony")
			}
			if e == nil {
				t.Fatal("missing/corrupt saved relation silently became ordinary")
			}
			w := f.q.requestV1(token, "")
			if w.Code == 200 || strings.Contains(w.Body.String(), "amendment_context") {
				t.Fatal("failed native context leaked saved body", w.Code, w.Body.String())
			}
			f.q.assertObserversOnlyV1(t)
			if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
				t.Fatal("refusal mutated completed original")
			}
		})
	}
}
