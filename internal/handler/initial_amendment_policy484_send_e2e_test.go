//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Real native PostgreSQL, allocated WorkRuntime, authenticated authoring routes
// and source-built isolated PDF worker, with the EXISTING synthetic A4 renderer
// and versioned S3/retention protocol peers. These tests prove exact visible
// HTML-source/review/PDF bindings and SQL atomicity, not Chromium text layout,
// real Object Lock, SMTP acceptance, legal effectiveness or deployment readiness.
// The fixture fails rather than skipping if its explicit native dependencies are
// absent. No production guard, source cache, intent or retention receipt is forged.
const policy484OriginalClause = "Section 12. Later changes may use a fresh signature, explicit acknowledgement or email notice after 30 days. Original reviewed terms."
const policy484EditedClause = "Section 12. Later changes may use a fresh signature, explicit acknowledgement or email notice after 30 days. Newly reviewed revised terms."

func policy484Fixture(t *testing.T) (*ownedPublicReadFixtureV1, *generated.Document) {
	t.Helper()
	// Reuse the actual shared allocation selected before target design/document
	// birth. The false lifecycle-document variant keeps this database's outbox
	// witness unambiguous without raising any resource limit or adding a pool.
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	template := createBrandedDesignVariantE2E(t, q.f, q.cookie, func(master *htmlmaster.Master, values map[string]string) {
		master.ContractProfile.AmendmentPolicy = &htmlmaster.AmendmentPolicyV1{
			Term: "scope", ClauseReference: "Section 12",
			AllowedModes:    []string{"signature", "acknowledgement", "agreed_notice"},
			AllowedChannels: []string{"email"}, EffectiveCondition: "after 30 days",
		}
		values["scope"] = policy484OriginalClause
	})
	approveBrandedDesignE2E(t, q.f, template, q.storagePeer, q.cookie)
	doc := createBrandedDocumentE2E(t, q.f, template, q.cookie)
	doc = reviewPackageHTML221(t, q, doc)
	policy484Presented(t, doc, policy484OriginalClause)
	policy484NoFreeze(t, q, doc.ID)
	return q, doc
}

// This fixture exercises native tenant authoring/Send, without any public
// signer-token lookup. Its actual tenant observer remains; a signer process
// observer has never been created. Preserve the existing public-signer fixture's
// separate exact two-observer assertion rather than manufacture that scope.
func policy484AssertNativeRetired(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	q.reconcileV1(t)
	pending := q.runtime.SessionsV1().PendingV1()
	if pending != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 1}) {
		t.Fatalf("native Send left work or changed its actual tenant-observer ownership: %+v", pending)
	}
	current := q.snapshotV1(t)
	global, err := q.runtime.SnapshotV1(uuid.Nil)
	want := workguard.VectorV1{SQLSessions: 1}
	if err != nil || current.Global != want || current.Organisation != want || current.GlobalGrants != 1 || current.OrganisationGrants != 1 || current.ActiveOrganisations != 1 || global.Global != current.Global || global.GlobalGrants != 1 || global.Organisation != (workguard.VectorV1{}) || global.OrganisationGrants != 0 || global.ActiveOrganisations != 1 {
		t.Fatalf("native Send observer-only debt differs from the actual tenant scope: org=%+v global=%+v err=%v", current, global, err)
	}
}

func policy484Actor(q *ownedPublicReadFixtureV1) sendengine.Actor {
	return sendengine.Actor{OrgID: q.f.org, UserID: &q.f.user.ID, Via: "rest", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != q.f.user.ID || user.OrgID != q.f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
}

func policy484Reload(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) *generated.Document {
	t.Helper()
	doc, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: id, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func policy484Presented(t *testing.T, doc *generated.Document, clause string) *htmlmaster.PresentedAmendmentPolicyV1 {
	t.Helper()
	if err := htmlsource.Validate(doc, true); err != nil {
		t.Fatal("genuine exact current PDF review missing", err)
	}
	in, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		t.Fatal(err)
	}
	master, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	input := htmlmaster.Input{Values: in.Values, Sections: in.Sections}
	presented, err := compiled.PresentedAmendmentPolicyV1(input)
	if err != nil || presented == nil || presented.Term != "scope" || presented.ClauseReference != "Section 12" || presented.EffectiveCondition != "after 30 days" || presented.ReviewedClause != clause || !reflect.DeepEqual(presented.AllowedModes, []string{"acknowledgement", "agreed_notice", "signature"}) || !reflect.DeepEqual(presented.AllowedChannels, []string{"email"}) {
		t.Fatal("policy is not the exact declared term in the actual reviewed source", err)
	}
	materialized, err := compiled.Materialize(input)
	if err != nil || !strings.Contains(materialized.HTML, clause) {
		t.Fatal("declared policy is absent from actual materialized HTML", err)
	}
	return presented
}

func policy484NoFreeze(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) {
	t.Helper()
	var n int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*) FROM document_amendment_policies_v1 WHERE document_id=$1 AND org_id=$2", id, q.f.org).Scan(&n); err != nil || n != 0 {
		t.Fatal("policy was frozen outside successful native completion", n, err)
	} //nolint:rawsql -- read-only exact target row oracle, never a replacement policy
}

func policy484AssertSource(t *testing.T, before, after *generated.Document) {
	t.Helper()
	if !sameSignerDocumentSource(before, after) || before.HtmlReviewedBy != after.HtmlReviewedBy || before.HtmlReviewedAt != after.HtmlReviewedAt || before.HtmlReviewedMaterializationID != after.HtmlReviewedMaterializationID || !bytes.Equal(before.HtmlReviewedPdfSha256, after.HtmlReviewedPdfSha256) || !bytes.Equal(before.MetadataRedactionReport, after.MetadataRedactionReport) || before.FinalPdfKey != after.FinalPdfKey || before.FinalPdfVersionID != after.FinalPdfVersionID || !bytes.Equal(before.FinalPdfSha, after.FinalPdfSha) || before.AuditCertKey != after.AuditCertKey || before.AuditCertVersionID != after.AuditCertVersionID || !bytes.Equal(before.AuditCertSha256, after.AuditCertSha256) || before.AuditPayloadKey != after.AuditPayloadKey || before.AuditPayloadVersionID != after.AuditPayloadVersionID || !bytes.Equal(before.AuditPayloadSha256, after.AuditPayloadSha256) || before.AuditSignatureKey != after.AuditSignatureKey || before.AuditSignatureVersionID != after.AuditSignatureVersionID || !bytes.Equal(before.AuditSignatureSha256, after.AuditSignatureSha256) {
		t.Fatal("Send/failure changed original reviewed source, intake proof or existing evidence artifact pins")
	}
}

// The complete final-visible row collections are compared without printing
// tokens/messages into diagnostics. updated_at may truthfully advance in the
// earlier durable pin/retention phases. The intent is checked separately because
// retention progress must survive a rejected completion; it must not be erased.
func policy484CompletionState(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) []byte {
	t.Helper()
	var raw []byte
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
 'document',(SELECT to_jsonb(d)-'updated_at' FROM documents d WHERE d.id=$1 AND d.org_id=$2),
 'policies',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM document_amendment_policies_v1 x WHERE document_id=$1 AND org_id=$2),
 'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM recipients x WHERE document_id=$1),
 'fields',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM document_fields x WHERE document_id=$1),
 'versions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM document_versions x WHERE document_id=$1 AND org_id=$2),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM events x WHERE document_id=$1 AND org_id=$2),
 'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM signatures x WHERE document_id=$1),
 'reports',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY document_id),'[]'::jsonb) FROM document_participant_reports_v1 x WHERE document_id=$1 AND org_id=$2),
 'reminders',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY document_id),'[]'::jsonb) FROM reminders x WHERE document_id=$1),
 'email',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb) FROM email_deliveries x)
)`, id, q.f.org).Scan(&raw) //nolint:rawsql -- entire disposable native target/output rollback oracle
	if err != nil || len(raw) == 0 {
		t.Fatal("read complete native completion state", err)
	}
	return raw
}

// Separate whole collection comparison permits only the truthful parent draft
// status/deadline change in pre-retention abort; evidence/party rows stay exact.
func policy484Collections(t *testing.T, raw []byte) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "document")
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func policy484AssertFrozen(t *testing.T, q *ownedPublicReadFixtureV1, reviewed *generated.Document, clause string) uuid.UUID {
	t.Helper()
	presented := policy484Presented(t, reviewed, clause)
	commitment, err := htmlsource.Commitment(reviewed)
	if err != nil {
		t.Fatal(err)
	}
	var id, actor uuid.UUID
	var basis, basisSHA, sourceSHA, pdfSHA []byte
	var version string
	var frozenAt time.Time
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT id,basis,basis_sha256,presented_source_sha256,presented_pdf_sha256,presented_pdf_version_id,frozen_by,frozen_at FROM document_amendment_policies_v1 WHERE document_id=$1 AND org_id=$2`, reviewed.ID, q.f.org).Scan(&id, &basis, &basisSHA, &sourceSHA, &pdfSHA, &version, &actor, &frozenAt) //nolint:rawsql -- actual producer row, never source authority supplied by test
	if err != nil || id == uuid.Nil || actor != q.f.user.ID || frozenAt.IsZero() || hex.EncodeToString(sourceSHA) != commitment || !bytes.Equal(pdfSHA, reviewed.PdfSha256) || version != reviewed.PdfStorageVersionID.String {
		t.Fatal("frozen row does not bind actual reviewed source/PDF/version/actor", err)
	}
	expected := amendments.BasisV1{Kind: "frozen_agreement_policy", FrozenPolicyID: &id, ClauseReference: presented.ClauseReference, ReviewedClause: presented.ReviewedClause, AllowedChannels: presented.AllowedChannels, EffectiveCondition: presented.EffectiveCondition}
	for _, mode := range presented.AllowedModes {
		expected.AllowedModes = append(expected.AllowedModes, amendments.ModeV1(mode))
	}
	want, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := amendments.DigestV1("hash:later-amendment-basis:v1", expected)
	if err != nil || !bytes.Equal(basis, want) || hex.EncodeToString(basisSHA) != digest {
		t.Fatal("frozen clause/modes/condition or canonical commitment differs from reviewed source", err)
	}
	return id
}

func policy484AssertSentEffects(t *testing.T, q *ownedPublicReadFixtureV1, reviewed *generated.Document) {
	t.Helper()
	doc := policy484Reload(t, q, reviewed.ID)
	policy484AssertSource(t, reviewed, doc)
	if doc.Status != "sent" || !doc.SentAt.Valid || !doc.Article13NoticeEpochAt.Valid || !doc.SentAt.Time.Equal(doc.Article13NoticeEpochAt.Time) || !doc.Article13NoticeEpochV61Committed {
		t.Fatal("actual native sent/notice epoch not committed together")
	}
	var recipients, sentRecipients, invites, sentEvents, queued, intents, reminders int
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT
 (SELECT count(*) FROM recipients WHERE document_id=$1),
 (SELECT count(*) FROM recipients WHERE document_id=$1 AND status='sent' AND magic_token_hash IS NOT NULL),
 (SELECT count(*) FROM events WHERE document_id=$1 AND org_id=$2 AND kind='recipient.invited'),
 (SELECT count(*) FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.sent'),
 (SELECT count(*) FROM email_deliveries WHERE status='pending' AND attempts=0),
 (SELECT count(*) FROM send_sealing_intents WHERE document_id=$1 AND org_id=$2),
 (SELECT count(*) FROM reminders WHERE document_id=$1 AND fires_remaining=2)`, reviewed.ID, q.f.org).Scan(&recipients, &sentRecipients, &invites, &sentEvents, &queued, &intents, &reminders) //nolint:rawsql -- real committed effects, no dispatcher/provider receipt inference
	if err != nil || recipients != 2 || sentRecipients != 2 || invites != 2 || sentEvents != 1 || queued != 2 || intents != 0 || reminders != 1 {
		t.Fatal("native frozen-policy Send effects differ", recipients, sentRecipients, invites, sentEvents, queued, intents, reminders, err)
	}
}

func TestInitialAmendmentPolicyNativeSendFreezesExactReviewedSourceV484E2E(t *testing.T) {
	q, reviewed := policy484Fixture(t)
	defer policy484AssertNativeRetired(t, q)
	sent, err := q.f.s.Send.Send(q.f.ctx, policy484Actor(q), reviewed.ID)
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatal("real declared-policy Send did not return genuine fresh invitation links", err)
	}
	id := policy484AssertFrozen(t, q, reviewed, policy484OriginalClause)
	policy484AssertSentEffects(t, q, reviewed)
	sent.CloseConsumerV1()
	beforeReplay := policy484CompletionState(t, q, reviewed.ID)
	// The actual completed recovery path is status-only, not a second Send or
	// another usable set of magic links. Its original immutable row must survive.
	replay, err := q.f.s.Send.ResumeSendSealing(q.f.ctx, reviewed.ID, q.f.org)
	defer replay.CloseConsumerV1()
	if err != nil || replay.Status != "sent" || len(replay.Links) != 0 || policy484AssertFrozen(t, q, reviewed, policy484OriginalClause) != id || !bytes.Equal(beforeReplay, policy484CompletionState(t, q, reviewed.ID)) {
		t.Fatal("terminal replay replaced policy or repeated final effects", err)
	}
	replay.CloseConsumerV1()
}

func TestInitialAmendmentPolicyEarlyFailureThenReviewedEditedRetryV484E2E(t *testing.T) {
	q, original := policy484Fixture(t)
	defer policy484AssertNativeRetired(t, q)
	if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=clock_timestamp()+interval '4 minutes' WHERE id=$1 AND org_id=$2 AND status='draft'", original.ID, q.f.org); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- explicit controlled deadline input, no receipt/guard bypass
	before := policy484CompletionState(t, q, original.ID)
	failed, err := q.f.s.Send.Send(q.f.ctx, policy484Actor(q), original.ID)
	defer failed.CloseConsumerV1()
	if !errors.Is(err, sendengine.ErrExpiryTooSoon) || len(failed.Links) != 0 {
		t.Fatal("genuine early Send did not refuse too-close expiry", err)
	}
	failed.CloseConsumerV1()
	policy484NoFreeze(t, q, original.ID)
	if !bytes.Equal(before, policy484CompletionState(t, q, original.ID)) {
		t.Fatal("early failure committed policy, document, audit or outbox effects")
	}
	policy484AssertSource(t, original, policy484Reload(t, q, original.ID))
	var intents int
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*) FROM send_sealing_intents WHERE document_id=$1 AND org_id=$2", original.ID, q.f.org).Scan(&intents); err != nil || intents != 0 {
		t.Fatal("early failure left an intent", err)
	} //nolint:rawsql -- actual native failure oracle
	policy484AssertNativeRetired(t, q)
	policy484ReviewedEditedRetry(t, q, original)
}

func policy484ReviewedEditedRetry(t *testing.T, q *ownedPublicReadFixtureV1, original *generated.Document) {
	t.Helper()
	if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=clock_timestamp()+interval '1 day' WHERE id=$1 AND org_id=$2 AND status='draft'", original.ID, q.f.org); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- restore controlled draft deadline for genuine user revision/retry
	draft := policy484Reload(t, q, original.ID)
	oldCommitment, err := htmlsource.Commitment(draft)
	if err != nil {
		t.Fatal(err)
	}
	input := htmlDocumentRevisionInput{ExpectedUpdatedAt: draft.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: oldCommitment, Values: htmlStringMap{"scope": policy484EditedClause}, Summary: "Owner-reviewed later-change clause revision"}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+draft.ID.String()+"/html/revisions", string(raw), q.cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("real draft policy-text revision=%d %s", w.Code, w.Body.String())
	}
	revised := policy484Reload(t, q, original.ID)
	if !bytes.Equal(revised.HtmlSourceJson, original.HtmlSourceJson) || revised.HtmlReviewedAt.Valid || revised.HtmlReviewedBy.Valid || revised.HtmlReviewedMaterializationID.Valid {
		t.Fatal("real edited revision overwrote origin or inherited a stale human review")
	}
	newCommitment, err := htmlsource.Commitment(revised)
	if err != nil || newCommitment == oldCommitment {
		t.Fatal("actual revision did not create a distinct current source commitment", err)
	}
	policy484NoFreeze(t, q, original.ID)
	reviewed := reviewPackageHTML221(t, q, revised)
	policy484Presented(t, reviewed, policy484EditedClause)
	sent, err := q.f.s.Send.Send(q.f.ctx, policy484Actor(q), reviewed.ID)
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatal("genuine reviewed edited retry failed", err)
	}
	policy484AssertFrozen(t, q, reviewed, policy484EditedClause)
	policy484AssertSentEffects(t, q, reviewed)
	sent.CloseConsumerV1()
}

// Controlled recovery setup uses the original native admission APIs and their
// actual SQL/consumer retirement. It commits only the legitimate pre-retention
// stage; it is not claimed as a full public Send journey. Unlike the older
// blocks-only recovery helper, it verifies this real reviewed HTML-origin PDF.
func policy484StageSealing(ctx context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, org, document, user uuid.UUID) (failure error) {
	operation, err := factory.NewHTMLSendOperationV1(ctx, org, document)
	if err != nil {
		return err
	}
	defer operation.CloseConsumerV1()
	stage, err := operation.OpenSQLV1(pdfadmission.HTMLSendAdmissionV1)
	if err != nil {
		return err
	}
	var reconcileAdmission func(context.Context) error
	defer func() {
		failure = errors.Join(failure, stage.CloseSQLV1())
		operation.CloseConsumerV1()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if reconcileAdmission != nil {
			failure = errors.Join(failure, reconcileAdmission(cleanup))
		}
		failure = errors.Join(failure, factory.ReconcileCleanupV1(cleanup))
	}()
	session := stage.SessionV1()
	admission, err := session.NewAdmissionV1(stage.ContextV1())
	if err != nil {
		return err
	}
	reconcileAdmission = func(cleanup context.Context) error { _, err := admission.ReconcileCleanupV1(cleanup); return err }
	err = stage.WithTxV1(func(call context.Context, _ generated.DBTX) error {
		work, err := session.NewHTMLSendWorkV1(call, stage)
		if err != nil {
			return err
		}
		state, err := work.StateV1(call)
		if err != nil {
			return err
		}
		if state == nil || state.ID != document || state.OrgID != org || state.BoundedStatus != "draft" {
			return errors.New("controlled policy recovery source is not the actual draft")
		}
		models, err := work.ReadModelsV1(call)
		if err != nil {
			return err
		}
		if models == nil || models.Document == nil || models.Document.ID != document || models.Document.OrgID != org || models.Document.SourceKind != "pdf" || len(models.Document.HtmlSourceJson) == 0 || models.Document.Status != "draft" {
			return errors.New("controlled policy recovery body differs")
		}
		member, err := work.ReadActorV1(call, user)
		if err != nil {
			return err
		}
		if member == nil || member.ID != user || member.OrgID != org || member.Role != "owner" {
			return errors.New("controlled policy recovery owner differs")
		}
		source, err := work.NewSourceV1(call)
		if err != nil {
			return err
		}
		if err = source.ValidateReviewedV1(); err != nil {
			return err
		}
		if err = source.ValidateCurrentV1(); err != nil {
			return err
		}
		if _, err = work.ConfirmLawfulBasisV1(call, "contract", "rest"); err != nil {
			return err
		}
		if _, err = work.FreezeBrandingV1(call); err != nil {
			return err
		}
		if err = work.ValidateFrozenBrandingV1(call, source); err != nil {
			return err
		}
		if err = work.CreateIntentV1(call, pdfadmission.HTMLSendIntentActorV1{IP: "127.0.0.1", Via: "rest"}); err != nil {
			return err
		}
		return work.BeginSendSealingV1(call)
	})
	if err != nil {
		return err
	}
	return session.CommitV1(stage.ContextV1())
}

func TestInitialAmendmentPolicyMissingFreezeGuardAndPreRetentionAbortV484E2E(t *testing.T) {
	q, reviewed := policy484Fixture(t)
	defer policy484AssertNativeRetired(t, q)
	if err := policy484StageSealing(q.f.ctx, q.f.s.HTMLCreationSessions, q.f.org, reviewed.ID, q.f.user.ID); err != nil {
		t.Fatal("real native controlled pre-retention admission", err)
	}
	policy484AssertNativeRetired(t, q)
	policy484NoFreeze(t, q, reviewed.ID)
	var preRetention bool
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT retention_started_at IS NULL AND retention_completed_at IS NULL FROM send_sealing_intents WHERE document_id=$1 AND org_id=$2", reviewed.ID, q.f.org).Scan(&preRetention); err != nil || !preRetention {
		t.Fatal("controlled fixture is not genuinely pre-retention", err)
	} //nolint:rawsql -- observe native intent, never construct a receipt
	before := policy484CompletionState(t, q, reviewed.ID)
	tx, err := q.f.pool.Begin(q.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	// Deliberate bypass attempt with no replacement policy row. The exact M115
	// error distinguishes this negative control from unrelated lifecycle guards.
	_, err = tx.Exec(q.f.ctx, "UPDATE documents SET status='sent' WHERE id=$1 AND org_id=$2 AND status='sealing'", reviewed.ID, q.f.org) //nolint:rawsql -- deliberate forbidden transition, expected rejected and rolled back
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "23514" || denied.Message != "declared later-change policy requires exact retained native freeze before Send" {
		t.Fatal("missing freeze did not reach the mandatory exact M115 refusal", err)
	}
	if err = tx.Rollback(q.f.ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, policy484CompletionState(t, q, reviewed.ID)) {
		t.Fatal("refused direct transition left policy/send/evidence/output effects")
	}
	if _, err = q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=clock_timestamp()+interval '4 minutes' WHERE id=$1 AND org_id=$2 AND status='sealing'", reviewed.ID, q.f.org); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- genuine delayed pre-retention recovery deadline stimulus
	aborted, err := q.f.s.Send.ResumeSendSealing(q.f.ctx, reviewed.ID, q.f.org)
	defer aborted.CloseConsumerV1()
	if !errors.Is(err, sendengine.ErrExpiryTooSoon) || len(aborted.Links) != 0 {
		t.Fatal("actual pre-retention recovery did not refuse and abort", err)
	}
	aborted.CloseConsumerV1()
	policy484NoFreeze(t, q, reviewed.ID)
	fresh := policy484Reload(t, q, reviewed.ID)
	policy484AssertSource(t, reviewed, fresh)
	var intents, queued, sentEvents int
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT (SELECT count(*) FROM send_sealing_intents WHERE document_id=$1 AND org_id=$2),(SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM events WHERE document_id=$1 AND org_id=$2 AND kind IN ('document.sent','recipient.invited'))`, reviewed.ID, q.f.org).Scan(&intents, &queued, &sentEvents) //nolint:rawsql -- actual abort leaves no invitations or final receipt
	if err != nil || fresh.Status != "draft" || intents != 0 || queued != 0 || sentEvents != 0 || fresh.SentAt.Valid || fresh.Article13NoticeEpochAt.Valid {
		t.Fatal("pre-retention abort left final policy/send/outbox effects", err)
	}
	if !bytes.Equal(policy484Collections(t, before), policy484Collections(t, policy484CompletionState(t, q, reviewed.ID))) {
		t.Fatal("pre-retention abort changed original parties, fields, versions, audit or evidence collections")
	}
	policy484AssertNativeRetired(t, q)
	// A true reversible abort also remains editable: use the ordinary revision,
	// exact new PDF review and native Send, not a manufactured recovery policy.
	policy484ReviewedEditedRetry(t, q, reviewed)
}

func policy484RejectFinalCommit(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) {
	t.Helper()
	// This additional deferred test constraint never disables an application
	// constraint. It observes the REAL pending final transaction after its policy,
	// recipient rotations, sent epoch, queued invitations, audit and intent delete,
	// then rejects COMMIT. A separate marker refuses a false early witness.
	ddl := fmt.Sprintf(`CREATE FUNCTION hash_test_policy484_commit_reject() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM documents d JOIN document_amendment_policies_v1 p ON p.document_id=d.id AND p.org_id=d.org_id
 WHERE d.id=NEW.id AND d.org_id=NEW.org_id AND d.status='sent' AND d.sent_at IS NOT NULL
 AND d.article13_notice_epoch_at=d.sent_at AND d.article13_notice_epoch_v61_committed
 AND p.presented_source_sha256=decode(COALESCE(d.html_current_source_json,d.html_source_json)->>'commitment','hex')
 AND p.presented_pdf_sha256=d.pdf_sha256 AND p.presented_pdf_version_id=d.pdf_storage_version_id
 AND hash_amendment_policy_source_matches_v1(COALESCE(d.html_current_source_json,d.html_source_json),convert_from(p.basis,'UTF8')::jsonb) IS TRUE)
 OR (SELECT count(*) FROM recipients WHERE document_id=NEW.id)<>2
 OR (SELECT count(*) FROM recipients WHERE document_id=NEW.id AND status='sent' AND magic_token_hash IS NOT NULL)<>2
 OR (SELECT count(*) FROM email_deliveries WHERE status='pending' AND attempts=0)<>2
 OR (SELECT count(*) FROM events WHERE document_id=NEW.id AND org_id=NEW.org_id AND kind='recipient.invited')<>2
 OR (SELECT count(*) FROM events WHERE document_id=NEW.id AND org_id=NEW.org_id AND kind='document.sent')<>1
 OR (SELECT count(*) FROM reminders WHERE document_id=NEW.id AND fires_remaining=2)<>1
 OR EXISTS(SELECT 1 FROM send_sealing_intents WHERE document_id=NEW.id AND org_id=NEW.org_id)
 THEN RAISE EXCEPTION 'policy484_missing_real_completion_effects' USING ERRCODE='P0001';END IF;
 RAISE EXCEPTION 'policy484_completion_rollback_after_effects' USING ERRCODE='P0001';
END $$;
CREATE CONSTRAINT TRIGGER hash_test_policy484_commit_reject AFTER UPDATE ON documents
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
WHEN (NEW.id='%s'::uuid AND OLD.status='sealing' AND NEW.status='sent')
EXECUTE FUNCTION hash_test_policy484_commit_reject();`, id.String())
	if _, err := q.f.pool.Exec(q.f.ctx, ddl); err != nil {
		t.Fatal("install isolated real deferred completion rejection", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
		defer cancel()
		if _, err := q.f.pool.Exec(cleanup, "DROP TRIGGER hash_test_policy484_commit_reject ON documents; DROP FUNCTION hash_test_policy484_commit_reject()"); err != nil {
			t.Error("remove only isolated completion test constraint", err)
		}
	})
}

func TestInitialAmendmentPolicyFinalCommitFailureRollsBackAllEffectsV484E2E(t *testing.T) {
	q, reviewed := policy484Fixture(t)
	defer policy484AssertNativeRetired(t, q)
	if err := policy484StageSealing(q.f.ctx, q.f.s.HTMLCreationSessions, q.f.org, reviewed.ID, q.f.user.ID); err != nil {
		t.Fatal("real native controlled pre-retention admission", err)
	}
	policy484AssertNativeRetired(t, q)
	sealing := policy484Reload(t, q, reviewed.ID)
	before := policy484CompletionState(t, q, reviewed.ID)
	var epoch, retainUntil time.Time
	var actor uuid.UUID
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT article13_notice_epoch_at,retain_until,actor_user_id FROM send_sealing_intents WHERE document_id=$1 AND org_id=$2 AND retention_started_at IS NULL AND retention_completed_at IS NULL", reviewed.ID, q.f.org).Scan(&epoch, &retainUntil, &actor); err != nil || actor != q.f.user.ID {
		t.Fatal("real original actor/epoch pre-retention intent absent", err)
	} //nolint:rawsql -- exact original native intent witness
	policy484RejectFinalCommit(t, q, reviewed.ID)
	failed, err := q.f.s.Send.ResumeSendSealing(q.f.ctx, reviewed.ID, q.f.org)
	defer failed.CloseConsumerV1()
	var rejected *pgconn.PgError
	if !errors.As(err, &rejected) || rejected.Code != "P0001" || rejected.Message != "policy484_completion_rollback_after_effects" || failed.Status != "" || len(failed.Links) != 0 {
		t.Fatal("actual Send did not reach the intended real final COMMIT rejection", err)
	}
	failed.CloseConsumerV1()
	policy484NoFreeze(t, q, reviewed.ID)
	if !bytes.Equal(before, policy484CompletionState(t, q, reviewed.ID)) {
		t.Fatal("rejected final COMMIT left a policy, sent epoch, rotated recipient, audit, outbox or evidence effect")
	}
	fresh := policy484Reload(t, q, reviewed.ID)
	policy484AssertSource(t, reviewed, fresh)
	if fresh.Status != "sealing" || fresh.SentAt != sealing.SentAt || fresh.Article13NoticeEpochAt != sealing.Article13NoticeEpochAt {
		t.Fatal("rejected completion falsely returned retained source to draft or published sent epoch")
	}
	var actualEpoch, actualRetainUntil time.Time
	var actualActor uuid.UUID
	var durableRetention bool
	err = q.f.pool.QueryRow(q.f.ctx, "SELECT article13_notice_epoch_at,retain_until,actor_user_id,retention_started_at IS NOT NULL AND retention_completed_at IS NOT NULL FROM send_sealing_intents WHERE document_id=$1 AND org_id=$2", reviewed.ID, q.f.org).Scan(&actualEpoch, &actualRetainUntil, &actualActor, &durableRetention) //nolint:rawsql -- actual earlier durable retention survives; never repaired or fabricated
	if err != nil || actualActor != actor || !actualEpoch.Equal(epoch) || !actualRetainUntil.Equal(retainUntil) || !durableRetention {
		t.Fatal("final transaction failure lost truthful durable original retention progress", err)
	}
}
