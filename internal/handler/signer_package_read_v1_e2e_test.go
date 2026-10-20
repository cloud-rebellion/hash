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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This is actual main-only native package Send under the unchanged M99 gate.
// Annex projection has separate canonical unit coverage; this fixture does not
// authorize a nonempty package Send, package consent or a signature ceremony.
func signerPackageToken242(t *testing.T, q *ownedPublicReadFixtureV1, recipient uuid.UUID) string {
	t.Helper()
	var body string
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT e.text_body FROM email_deliveries e JOIN document_package_send_initial_invite_receipts_v1 i ON i.email_delivery_id=e.id WHERE i.recipient_id=$1", recipient).Scan(&body); err != nil {
		t.Fatal("actual committed invitation absent", err)
	}
	match := regexp.MustCompile(`/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("actual invitation omitted token")
	}
	return match[1]
}
func signerPackageExact242(t *testing.T, q *ownedPublicReadFixtureV1, token string, m pdfadmission.HTMLSendPackageIntentMetadataV1) {
	t.Helper()
	root := packageLatest223(t, q, m.Capture.DocumentID)
	before := packageCompletionNativeState241(t, q, m)
	response := q.requestV1(token, "/package")
	q.assertObserversOnlyV1(t)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated package projection failed", response.Code)
	}
	var got struct {
		Package *pdfadmission.SignerPackagePresentationV1 `json:"package"`
	}
	if json.Unmarshal(response.Body.Bytes(), &got) != nil || got.Package == nil {
		t.Fatal("captured package descriptor absent")
	}
	want := pdfadmission.SignerPackagePresentationV1{Schema: pdfadmission.SignerPackagePresentationSchemaV1, Incorporation: documentpackage.IncorporationCopyV1(), PackageID: m.Capture.PackageID, Revision: strconv.FormatInt(m.Capture.Revision, 10), ManifestSHA256: hex.EncodeToString(m.Capture.CanonicalSHA256[:]), LegalCommitmentSHA256: hex.EncodeToString(m.Capture.CommitmentSHA256[:]), Main: pdfadmission.SignerPackageMemberPresentationV1{Title: root.Name, PDFSHA256: hex.EncodeToString(root.PdfSha256), Bytes: m.Capture.PDFBytes, Pages: m.Capture.PDFPages}, Annexes: []pdfadmission.SignerPackageMemberPresentationV1{}}
	raw, _ := json.Marshal(want)
	actual, _ := json.Marshal(got.Package)
	if !bytes.Equal(raw, actual) {
		t.Fatal("public tuple differs from actual frozen capture")
	}
	for _, private := range []string{root.PdfStorageKey.String, root.PdfStorageVersionID.String, root.OrgID.String(), root.ID.String(), "document_id", "version_id", "source", "actor"} {
		if private != "" && bytes.Contains(response.Body.Bytes(), []byte(private)) {
			t.Fatal("package descriptor exposed private capture data")
		}
	}
	if packageCompletionNativeState241(t, q, m) != before {
		t.Fatal("package GET changed original ceremony or durable effects")
	}
}
func TestSignerCapturedPackageReadV1E2E(t *testing.T) {
	t.Run("actual completed capture exact tuple and immutable payload", func(t *testing.T) {
		q, _, client, m, recipient := packageCompletionNativeFixture241(t)
		packageCompletionRun241(t, q, client, m, "sent")
		token := signerPackageToken242(t, q, recipient)
		signerPackageExact242(t, q, token, m)
		before := packageCompletionNativeState241(t, q, m)
		_, err := q.f.pool.Exec(q.f.ctx, "UPDATE document_package_captures_v1 SET manifest=convert_to('{}','UTF8') WHERE package_id=$1 AND org_id=$2 AND document_id=$3 AND revision=$4", m.Capture.PackageID, m.Capture.OrgID, m.Capture.DocumentID, m.Capture.Revision)
		packageExpectPG218(t, err, "23514")
		if packageCompletionNativeState241(t, q, m) != before {
			t.Fatal("rejected capture mutation changed package")
		}
		signerPackageExact242(t, q, token, m)
		if w := q.requestV1(strings.Repeat("x", 43), "/package"); w.Code != http.StatusNotFound || bytes.Contains(w.Body.Bytes(), []byte("manifest_sha256")) {
			t.Fatal("unknown token exposed capture", w.Code)
		}
		q.assertObserversOnlyV1(t)
	})
	t.Run("copied context cannot change package authority and token rotation revokes old read", func(t *testing.T) {
		q, _, client, m, recipient := packageCompletionNativeFixture241(t)
		packageCompletionRun241(t, q, client, m, "sent")
		token := signerPackageToken242(t, q, recipient)
		rc, err := q.f.s.Sign.LookupSignerPackageByTokenV1(q.f.ctx, auth.HashMagicToken(token))
		if err != nil {
			t.Fatal(err)
		}
		defer rc.CloseReadV1()
		forged := *rc
		doc := *rc.Document
		doc.ID = uuid.New()
		forged.Document = &doc
		if result, err := q.f.s.Sign.SignerPackagePresentationV1(q.f.ctx, &forged); err == nil || result != nil {
			if result != nil {
				result.CloseConsumerV1()
			}
			t.Fatal("copied caller root became package authority")
		}
		replacement := strings.Repeat("r", 43)
		if err = q.f.q.RotateRecipientMagicToken(q.f.ctx, generated.RotateRecipientMagicTokenParams{ID: recipient, DocumentID: m.Capture.DocumentID, MagicTokenHash: auth.HashMagicToken(replacement), MagicTokenExpiresAt: rc.Recipient.MagicTokenExpiresAt}); err != nil {
			t.Fatal(err)
		}
		if result, err := q.f.s.Sign.SignerPackagePresentationV1(q.f.ctx, rc); err == nil || result != nil {
			if result != nil {
				result.CloseConsumerV1()
			}
			t.Fatal("revoked original token recovered captured package")
		}
		if err = rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		if w := q.requestV1(token, "/package"); w.Code != http.StatusNotFound {
			t.Fatal("revoked token still authenticated", w.Code)
		}
		// The initial invite receipt binds the recipient, not the current token bytes.
		signerPackageExact242(t, q, replacement, m)
	})
	t.Run("cross tenant duplicate token refuses before package projection", func(t *testing.T) {
		q, _, client, m, recipient := packageCompletionNativeFixture241(t)
		packageCompletionRun241(t, q, client, m, "sent")
		token := signerPackageToken242(t, q, recipient)
		org, err := q.f.q.CreateOrg(q.f.ctx, generated.CreateOrgParams{Name: "Synthetic negative package duplicate", Plan: "pro"})
		if err != nil {
			t.Fatal(err)
		}
		owner, err := q.f.q.CreateUser(q.f.ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@negative.example.test", Name: "Synthetic negative owner", Role: "owner"})
		if err != nil {
			t.Fatal(err)
		}
		doc, err := q.f.q.CreateBlocksDocument(q.f.ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, SenderID: owner.ID, Name: "Negative duplicate draft only", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage("{}")})
		if err != nil {
			t.Fatal(err)
		}
		_, err = q.f.q.CreateRecipient(q.f.ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Name: "Negative recipient", Email: uuid.NewString() + "@negative.example.test", Locale: "en", MagicTokenHash: auth.HashMagicToken(token), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
		if err != nil {
			t.Fatal(err)
		}
		response := q.requestV1(token, "/package")
		if response.Code != http.StatusNotFound || bytes.Contains(response.Body.Bytes(), []byte("manifest_sha256")) {
			t.Fatal("foreign duplicate selected one package", response.Code)
		}
		q.assertObserversOnlyV1(t)
	})
	for _, scenario := range []string{"expired credential", "current privacy request", "changed current sent epoch"} {
		label := scenario + " refuses captured package"
		if scenario == "changed current sent epoch" {
			label = "current sent epoch guard preserves original captured package"
		}
		t.Run(label, func(t *testing.T) {
			q, _, client, m, recipient := packageCompletionNativeFixture241(t)
			packageCompletionRun241(t, q, client, m, "sent")
			token := signerPackageToken242(t, q, recipient)
			want := http.StatusServiceUnavailable
			switch scenario {
			case "expired credential":
				want = http.StatusGone
				_, err := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1 AND document_id=$2", recipient, m.Capture.DocumentID)
				if err != nil {
					t.Fatal(err)
				}
			case "current privacy request":
				_, err := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: m.Capture.DocumentID, Valid: true}, SubjectEmail: "package-read-privacy@example.test", Kind: "access", RequestedVia: "sender", PayloadJson: []byte("{}")})
				if err != nil {
					t.Fatal(err)
				}
			case "changed current sent epoch":
				// The real ceremony guard refuses mutation. Do not disable it to
				// manufacture a stale source: verify the refusal and original read.
				before := packageCompletionNativeState241(t, q, m)
				_, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET sent_at=sent_at+interval '1 microsecond' WHERE id=$1 AND org_id=$2", m.Capture.DocumentID, m.Capture.OrgID)
				packageExpectPG218(t, err, "P0001")
				if packageCompletionNativeState241(t, q, m) != before {
					t.Fatal("rejected epoch rewrite changed original ceremony")
				}
				signerPackageExact242(t, q, token, m)
				return
			}
			before := packageCompletionNativeState241(t, q, m)
			response := q.requestV1(token, "/package")
			if response.Code != want || bytes.Contains(response.Body.Bytes(), []byte(`"package"`)) {
				t.Fatal("stale/current policy became legacy absence or disclosed package", scenario, response.Code)
			}
			q.assertObserversOnlyV1(t)
			if packageCompletionNativeState241(t, q, m) != before {
				t.Fatal("refused package read mutated state")
			}
		})
	}
}
func TestSignerPackageLegacyEpochAbsenceV1E2E(t *testing.T) {
	t.Run("ordinary actual Send has explicit null package", func(t *testing.T) {
		q := newOwnedPublicReadFixtureV1(t)
		_, parties := q.createSentV1(t)
		response := q.requestV1(parties[0].Token, "/package")
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || strings.TrimSpace(response.Body.String()) != `{"package":null}` {
			t.Fatal("actual legacy ceremony acquired package history", response.Code)
		}
		q.assertObserversOnlyV1(t)
	})
	t.Run("older genuine aborted attempt does not poison later ordinary Send", func(t *testing.T) {
		q, peer, client, m, _ := packageCompletionNativeFixture241(t)
		if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", m.Capture.DocumentID); err != nil {
			t.Fatal(err)
		}
		counts := peer.counts240()
		batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
		called := false
		more, err := batch.WithNextSendV1(client, packageCompletionConfig241(t, q), func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
			called = true
			if v.Attempt.Outcome != pdfadmission.HTMLSendPackageAttemptAbortedV1 || v.Status != "draft" || v.RetentionVerified || v.CompletionVerified {
				return errors.New("actual reversible abort differs")
			}
			return nil
		})
		batch.CloseConsumerV1()
		packageWorkerDrained239(t, q)
		if !more || !called || err != nil || peer.counts240() != counts {
			t.Fatal("genuine reversible abort failed", more, called, err)
		}
		packageAttemptInspect235(t, q, m, false, "aborted")
		if _, err = q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=clock_timestamp()+interval '7 days' WHERE id=$1 AND status='draft'", m.Capture.DocumentID); err != nil {
			t.Fatal(err)
		}
		actor := sendengine.Actor{UserID: &q.f.user.ID, OrgID: q.f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, u *generated.User) error {
			if u == nil || u.ID != q.f.user.ID || u.OrgID != q.f.org || u.Role != "owner" {
				return auth.ErrMutationPermissionRevoked
			}
			return nil
		}}
		sent, err := q.f.s.Send.Send(q.f.ctx, actor, m.Capture.DocumentID)
		defer sent.CloseConsumerV1()
		if err != nil || sent.Status != "sent" || len(sent.Links) != 1 {
			t.Fatal("permitted genuine later ordinary Send failed", err)
		}
		invitation, err := url.Parse(sent.Links[0].URL)
		if err != nil {
			t.Fatal(err)
		}
		token := strings.TrimPrefix(invitation.Path, "/sign/")
		sent.CloseConsumerV1()
		q.assertObserversOnlyV1(t)
		root := packageLatest223(t, q, m.Capture.DocumentID)
		if !root.SentAt.Valid || root.SentAt.Time.Equal(m.Article13NoticeEpochAt) {
			t.Fatal("later Send reused aborted epoch")
		}
		response := q.requestV1(token, "/package")
		if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"package":null}` {
			t.Fatal("unrelated old aborted epoch poisoned genuine later legacy ceremony", response.Code)
		}
		q.assertObserversOnlyV1(t)
		packageAttemptInspect235(t, q, m, false, "aborted")
	})
}
func TestSignerPackageResponseLifetimeV1E2E(t *testing.T) {
	q, _, client, m, recipient := packageCompletionNativeFixture241(t)
	packageCompletionRun241(t, q, client, m, "sent")
	token := signerPackageToken242(t, q, recipient)
	ctx, cancel := context.WithCancel(q.f.ctx)
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+"/sign/"+token+"/package", nil).WithContext(ctx)
	writer := &ownedCommentPageWriter166V1{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{}), life: q.f.ctx}
	done := make(chan struct{})
	var release sync.Once
	defer func() {
		release.Do(func() { close(writer.release) })
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("package writer did not join")
		}
	}()
	go func() { defer close(done); q.f.s.Routes().ServeHTTP(writer, request) }()
	select {
	case <-writer.entered:
	case <-done:
		t.Fatal("package read ended before actual Write")
	case <-time.After(5 * time.Second):
		t.Fatal("package did not reach writer")
	}
	snapshot, pending := q.snapshotV1(t), q.runtime.SessionsV1().PendingV1()
	if writer.Code != http.StatusOK || pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLInputProducers != 1 || pending.SignerReaders != 1 || pending.SignerScopes != 1 || snapshot.Organisation.ParentBytes <= 0 || snapshot.Organisation.DBStagingBytes <= 32<<20 {
		t.Fatal("actual writer lost original input/body loans", pending)
	}
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
	err := q.runtime.ReconcileCleanupV1(cleanup)
	stop()
	if err != nil || q.snapshotV1(t) != snapshot || q.runtime.SessionsV1().PendingV1() != pending {
		t.Fatal("cancellation refunded still-writing package output", err)
	}
	release.Do(func() { close(writer.release) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("package writer did not join after release")
	}
	if writer.timedOut.Load() || !bytes.Contains(writer.Body.Bytes(), []byte(hex.EncodeToString(m.Capture.CommitmentSHA256[:]))) {
		t.Fatal("actual retained writer lost captured commitment")
	}
	q.assertObserversOnlyV1(t)
}
func TestSignerPackageReadBodyAdmissionRefusalV1E2E(t *testing.T) {
	q, _, client, m, recipient := packageCompletionNativeFixture241(t)
	packageCompletionRun241(t, q, client, m, "sent")
	token := signerPackageToken242(t, q, recipient)
	factory := q.runtime.SessionsV1()
	var leases []*sign.RecipientContext
	var extras []*pdfadmission.ApplicationSignerScopeV1
	defer func() {
		for _, rc := range leases {
			_ = rc.CloseReadV1()
		}
		for _, extra := range extras {
			extra.CloseConsumerV1()
		}
		q.reconcileV1(t)
	}()
	// Genuine retained public readers establish the original 384MiB DB body-only
	// window. No limit, deadline, coordinator or authority is replaced.
	for i := 0; i < 7; i++ {
		rc, err := q.f.s.Sign.LookupSignerPDFByTokenV1(q.f.ctx, auth.HashMagicToken(token))
		if err != nil {
			t.Fatal("actual body holder failed", err)
		}
		leases = append(leases, rc)
	}
	for i := 0; i < 5; i++ {
		scope, err := factory.ProbeSignerScopeV1(q.f.ctx, auth.HashMagicToken(token))
		if err != nil {
			t.Fatal("actual scope holder failed", err)
		}
		extras = append(extras, scope)
	}
	before, pending := q.snapshotV1(t), factory.PendingV1()
	const header, limit = int64(32 << 20), int64(384 << 20)
	if pending.SignerReaders != 7 || pending.SignerScopes != 12 || before.Global.DBStagingBytes+header > limit || before.Global.DBStagingBytes+2*header <= limit {
		t.Fatal("genuine holder body window differs", pending, before)
	}
	sink := &ownedSignerDiagnosticSinkV1{started: make(chan struct{}), release: make(chan struct{})}
	close(sink.release)
	previous := slog.Default()
	slog.SetDefault(slog.New(sink))
	defer slog.SetDefault(previous)
	response := q.requestV1(token, "/package")
	// The sink validates exactly the original 27 numeric/bool keys in order.
	// Check the actual route/model decision and real DB capacity facts, without
	// treating private grant-count bookkeeping as a separate resource contract.
	if response.Code != http.StatusServiceUnavailable || bytes.Contains(response.Body.Bytes(), []byte(`"package"`)) ||
		sink.count != 27 || !sink.valid ||
		sink.values[0] != int64(pdfadmission.SignerReadDiagnosticPackageV1) || sink.values[1] != int64(pdfadmission.SignerReadDiagnosticLookupV1) || sink.values[2] != int64(pdfadmission.SignerReadDiagnosticModelsV1) ||
		sink.values[3] != 1 || sink.values[4] != int64(workguard.AdmissionGlobalResourceV1) || sink.values[5] != int64(workguard.AdmissionDBStagingBytesV1) ||
		sink.values[6] != 0 || sink.values[7] <= before.Global.SQLSessions || sink.values[7] > 8 || sink.values[8] <= before.Organisation.SQLSessions || sink.values[8] > 4 || sink.values[9] != 8 || sink.values[10] != 4 ||
		sink.values[13] != 128 || sink.values[14] != 64 || sink.values[15] != 10 || sink.values[16] != 2 ||
		sink.values[17] <= header || sink.values[18] < before.Global.DBStagingBytes+header || sink.values[19] < before.Organisation.DBStagingBytes+header ||
		sink.values[20] != limit || sink.values[21] != limit || sink.values[18] > limit || sink.values[19] > limit ||
		sink.values[18]+sink.values[17] <= limit || sink.values[19]+sink.values[17] > limit ||
		sink.values[22] != 23 || sink.values[23] != 2 || sink.values[24] != 0 || sink.values[25] != 0 || sink.values[26] != 0 {
		t.Fatal("actual package lookup body DB admission diagnostic differs", response.Code, sink.count, sink.valid, sink.values)
	}
	q.reconcileV1(t)
	if q.snapshotV1(t) != before || factory.PendingV1() != pending {
		t.Fatal("refused read refunded original holders or leaked new ownership")
	}
	for _, rc := range leases {
		if err := rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
	}
	leases = nil
	for _, extra := range extras {
		extra.CloseConsumerV1()
	}
	extras = nil
	slog.SetDefault(previous)
	q.assertObserversOnlyV1(t)
}
