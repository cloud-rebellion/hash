//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
)

// A genuine two-party ceremony already retains its first acceptance. The final
// acceptance must report its own completed outcome while a separate, physically
// retired reader still has one real view-request consumer. That foreign pending
// consumer remains charged and unknown to factory cleanup until its actual last
// use; it supplies no response, finalization, or retirement authority.
func TestAcknowledgementCompletesDespiteUnrelatedReaderCleanupV1E2E(t *testing.T) {
	q, doc, parties := participantCapacityAcknowledgement253(t)
	if len(parties) != 2 {
		t.Fatal("scoped acknowledgement requires two genuinely sent parties")
	}
	first, err := participantCapacityRespond253(t, q, parties[0], "acknowledgement")
	if err != nil || first == nil || first.Completed || first.Status != "in_progress" {
		t.Fatal("first genuine acceptance did not leave the two-party ceremony active", err)
	}
	party := parties[1]
	bootstrap := q.lookupV1(t, party.Token)
	t.Cleanup(func() {
		if err := bootstrap.CloseReadV1(); err != nil {
			t.Error("original bootstrap lease did not retire on cleanup", err)
		}
	})
	notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), bootstrap)
	if err != nil {
		t.Fatal("genuine remaining-party notice unavailable", err)
	}
	noticeEvidence, err := signerArticle13NoticeEvidence(bootstrap, notice)
	if err != nil {
		t.Fatal("genuine remaining-party notice evidence unavailable", err)
	}
	if err := bootstrap.CloseReadV1(); err != nil {
		t.Fatal("bootstrap original read did not retire", err)
	}
	q.assertObserversOnlyV1(t)
	factory := q.runtime.SessionsV1()
	scope, err := factory.ProbeSignerScopeV1(q.f.ctx, auth.HashMagicToken(party.Token))
	var sibling *pdfadmission.ApplicationSignerReaderV1
	var retained *pdfadmission.ApplicationSignerViewRequestV1
	released := false
	release := func() {
		t.Helper()
		if released {
			return
		}
		if retained != nil {
			retained.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if sibling != nil {
			if err := sibling.CloseV1(cleanup); err != nil {
				t.Error("actual sibling reader did not join after original last use", err)
			}
		}
		if scope != nil {
			scope.CloseConsumerV1()
		}
		if err := factory.ReconcileCleanupV1(cleanup); err != nil {
			t.Error("actual sibling ownership did not reconcile", err)
		}
		released = true
	}
	t.Cleanup(release)
	if err != nil {
		t.Fatal("genuine sibling scope unavailable", err)
	}
	sibling, err = factory.NewSignerReaderV1(q.f.ctx, scope, pdfadmission.SignerReadActiveV1)
	if err != nil {
		t.Fatal("genuine independent sibling reader unavailable", err)
	}
	err = sibling.WithModelsV1(q.f.ctx, func(a pdfadmission.ApplicationSignerReadAccessV1) error {
		now := time.Now()
		if !a.ActiveCeremony || (a.DocumentExpiresAt.Valid && !now.Before(a.DocumentExpiresAt.Time)) || (a.RecipientExpiresAt.Valid && !now.Before(a.RecipientExpiresAt.Time)) {
			return fmt.Errorf("genuine sibling access is no longer active")
		}
		return nil
	}, func(_ context.Context, models *pdfadmission.ApplicationSignerReadModelsV1) error {
		if models == nil || models.Document == nil || models.Recipient == nil || models.Document.ID != doc.ID || models.Document.OrgID != q.f.org || models.Recipient.ID != party.RecipientID || models.Recipient.DocumentID != doc.ID || models.Document.Status != "in_progress" || models.Recipient.Status == "accepted" {
			return fmt.Errorf("genuine partly accepted sibling scope differs")
		}
		return nil
	})
	if err != nil {
		t.Fatal("genuine sibling source read failed", err)
	}
	if err = sibling.CommitReadV1(q.f.ctx); err != nil {
		t.Fatal("genuine sibling read did not commit", err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	err = sibling.CloseSQLV1(cleanup)
	stop()
	if err != nil {
		t.Fatal("genuine sibling SQL did not physically retire", err)
	}
	retained, err = factory.NewSignerViewRequestV1(q.f.ctx, sibling, "127.0.0.1", "Synthetic retained sibling consumer during final acknowledgement", noticeEvidence)
	if err != nil {
		t.Fatal("actual sibling view consumer was not admitted", err)
	}
	before := q.snapshotV1(t)
	cleanup, stop = context.WithTimeout(context.Background(), 5*time.Second)
	err = sibling.CloseV1(cleanup)
	stop()
	if !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || q.snapshotV1(t) != before {
		t.Fatal("genuine sibling consumer was credited or reported joined before last use", err)
	}
	pending := factory.PendingV1()
	if pending.SignerReaders != 1 || pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.ObserverSessions != 2 || before.Global.SQLSessions != 2 || before.Organisation.SQLSessions != 1 || before.Global.ParentBytes <= 0 || before.Global.DBStagingBytes <= 0 {
		t.Fatal("sibling is not a real physically retired source consumer", pending, before)
	}
	cleanup, stop = context.WithTimeout(context.Background(), 5*time.Second)
	err = factory.ReconcileCleanupV1(cleanup)
	stop()
	if !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || q.snapshotV1(t) != before {
		t.Fatal("factory cleanup did not preserve the actual foreign pending consumer", err)
	}

	// This fresh original reader still performs the real locked deadline, notice,
	// eligibility, capacity/family freeze, response, report and completion checks.
	last := q.lookupV1(t, party.Token)
	t.Cleanup(func() {
		if err := last.CloseReadV1(); err != nil {
			t.Error("original final acknowledgement lease did not retire on cleanup", err)
		}
	})
	currentNotice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), last)
	if err != nil {
		t.Fatal("final genuine current notice unavailable", err)
	}
	currentEvidence, err := signerArticle13NoticeEvidence(last, currentNotice)
	if err != nil {
		t.Fatal("final genuine current notice evidence unavailable", err)
	}
	result, err := q.f.s.Sign.Accept(q.f.ctx, last, sign.ParticipantResponseEvidence{Notice: currentEvidence, IP: "127.0.0.1", UserAgent: "Synthetic actual final acknowledgement with retained foreign cleanup"})
	if err != nil || result == nil || !result.Completed || result.Status != "completed" || result.DocumentID != doc.ID || result.FinalPDFURL == "" || result.AuditCertURL == "" {
		t.Fatal("final actual acknowledgement inherited foreign pending cleanup or lost completion", err)
	}
	current, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
	if err != nil || current.Status != "completed" || !current.CompletionEffectiveAtBound || !current.CompletionEffectiveAt.Valid || !current.AuditPayloadKey.Valid || !current.AuditSignatureKey.Valid {
		t.Fatal("actual acknowledgement ceremony did not complete durably", err)
	}
	var reportSchema, reportSHA string
	var cutoff time.Time
	var rows int64
	var associated bool
	var accepted, measured, completion, deliveries int
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT r.schema_version,encode(r.report_sha256,'hex'),r.cutoff,r.history_rows,
 r.completion_effective_at=d.completion_effective_at AND r.final_pdf_sha256=d.final_pdf_sha
 AND r.audit_cert_sha256=d.audit_cert_sha256 AND r.audit_payload_sha256=d.audit_payload_sha256
 AND r.audit_signature_sha256=d.audit_signature_sha256,
 (SELECT count(*)::integer FROM recipients p WHERE p.document_id=d.id AND p.role<>'cc' AND p.status='accepted'),
 (SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer WHERE e.document_id=d.id AND e.org_id=d.org_id AND e.kind='document.accepted'),
 (SELECT count(*)::integer FROM events e WHERE e.document_id=d.id AND e.org_id=d.org_id AND e.kind='document.completed'),
 (SELECT count(*)::integer FROM document_participant_report_deliveries_v1 x WHERE x.document_id=d.id AND x.org_id=d.org_id AND x.completion_effective_at=d.completion_effective_at)
 FROM documents d JOIN document_participant_reports_v1 r ON r.document_id=d.id AND r.org_id=d.org_id AND r.completion_effective_at=d.completion_effective_at
 WHERE d.id=$1 AND d.org_id=$2`, doc.ID, q.f.org).Scan(&reportSchema, &reportSHA, &cutoff, &rows, &associated, &accepted, &measured, &completion, &deliveries)
	if err != nil || reportSchema != render.ParticipantReportSchemaV2 || len(reportSHA) != 64 || rows <= 0 || !associated || accepted != 2 || measured != 2 || completion != 1 || deliveries != 3 {
		t.Fatal("mandatory participant report or exact acceptance/completion effects differ", err, accepted, measured, completion, deliveries)
	} //nolint:rawsql -- actual original receipt/outbox/measurement association, never authority
	payload, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, current.AuditPayloadKey.String, current.AuditPayloadSha256, current.AuditPayloadVersionID)
	if err != nil {
		t.Fatal("actual retained participant payload unavailable", err)
	}
	signature, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, current.AuditSignatureKey.String, current.AuditSignatureSha256, current.AuditSignatureVersionID)
	if err != nil {
		t.Fatal("actual retained certificate signature unavailable", err)
	}
	claims, err := evidence.ParseCertificateCommitments(payload)
	if err != nil || !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) || claims.ParticipantReportSchema != reportSchema || claims.ParticipantReportSHA256 != reportSHA || claims.ParticipantReportCutoff != cutoff.UTC().Format(time.RFC3339Nano) || claims.ParticipantReportRows != rows || claims.FinalPDFSHA256 != hex.EncodeToString(current.FinalPdfSha) {
		t.Fatal("published mandatory report differs from its actual signed receipt", err)
	}
	assertFreshParticipantReport406(t, q.f, current, payload)
	// End this exact final response lease only after every result/payload view's
	// last use. Its scoped cleanup must not forgive the unrelated reader either.
	result, payload, signature = nil, nil, nil
	if err = last.CloseReadV1(); err != nil {
		t.Fatal("own final acknowledgement response did not join", err)
	}
	cleanup, stop = context.WithTimeout(context.Background(), 5*time.Second)
	err = factory.ReconcileCleanupV1(cleanup)
	stop()
	if !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || q.snapshotV1(t) != before || factory.PendingV1().SignerReaders != 1 || factory.PendingV1().WorkSessions != 0 {
		t.Fatal("successful final acknowledgement swallowed or credited the unrelated pending debt", err)
	}
	release()
	q.assertObserversOnlyV1(t)
}

// Ownership-component qualification only: a genuine native stage holds its
// original callback after actual measured source reads, without any mutation,
// acceptance, audit append or attempted COMMIT. Scoped Close must refuse while
// that original tracked activity is still held. Cancellation is an observation,
// never a retirement proof; explicit release and real physical join come last.
func TestAcknowledgementScopedClosePreservesOwnActiveStageUncertaintyV1E2E(t *testing.T) {
	q, doc, _ := participantCapacityAcknowledgement253(t)
	factory := q.runtime.SessionsV1()
	q.assertObserversOnlyV1(t)
	beforeLegal := participantCapacityLegalState253(t, q, doc.ID)
	op, err := factory.NewHTMLSendOperationV1(q.f.ctx, q.f.org, doc.ID)
	if err != nil {
		t.Fatal("actual finite native operation unavailable", err)
	}
	release := make(chan struct{})
	entered := make(chan context.Context, 1)
	done := make(chan error, 1)
	var once sync.Once
	var closeCancel context.CancelFunc
	started, joined := false, false
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		if closeCancel != nil {
			closeCancel()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if started && !joined {
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("original held native callback did not join before cleanup")
			}
		}
		if err := op.CloseV1(cleanup); err != nil {
			t.Error("actual own operation did not physically retire after callback release", err)
		}
	})
	stage, err := op.OpenSQLV1(pdfadmission.HTMLAcknowledgementMutationV1)
	if err != nil {
		t.Fatal("actual original acknowledgement stage unavailable", err)
	}
	call, session := stage.ContextV1(), stage.SessionV1()
	if call == nil || session == nil {
		t.Fatal("actual original stage lacks its context/session")
	}
	if _, err = session.NewAdmissionV1(call); err != nil {
		t.Fatal("actual original stage admission unavailable", err)
	}
	started = true
	go func() {
		done <- stage.WithTxV1(func(actual context.Context, _ generated.DBTX) error {
			work, err := session.NewHTMLSendWorkV1(actual, stage)
			if err != nil {
				return err
			}
			if _, err = work.StateV1(actual); err != nil {
				return err
			}
			models, err := work.ReadModelsV1(actual)
			if err != nil {
				return err
			}
			if models == nil || models.Document == nil || models.Document.ID != doc.ID || models.Document.OrgID != q.f.org || models.Document.Status != "sent" || models.Document.RequiresSignature {
				return fmt.Errorf("actual owned acknowledgement source differs")
			}
			entered <- actual
			<-release
			return actual.Err()
		})
	}()
	observe, stopObserve := context.WithTimeout(q.f.ctx, 3*time.Second)
	var original context.Context
	select {
	case original = <-entered:
	case err := <-done:
		joined = true
		stopObserve()
		t.Fatal("actual native stage refused before genuine measured reads", err)
	case <-observe.Done():
		stopObserve()
		t.Fatal("actual measured native callback did not reach its owned barrier", observe.Err())
	}
	stopObserve()
	held := q.snapshotV1(t)
	if held.Global.ParentBytes <= 0 || held.Global.DBStagingBytes <= 0 || factory.PendingV1().WorkSessions != 1 || factory.PendingV1().HTMLAdmissions != 1 {
		t.Fatal("real held callback has no original native source/session debt", held, factory.PendingV1())
	}
	// The actual callback stays held through this smaller finite cleanup budget.
	// Let that budget expire inside the real join; do not cancel cleanup merely
	// because logical operation cancellation has preceded the physical join.
	cleanup, stopCleanup := context.WithTimeout(context.Background(), 500*time.Millisecond)
	closeCancel = stopCleanup
	err = op.CloseV1(cleanup)
	stopCleanup()
	if !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(original.Err(), context.Canceled) || q.f.ctx.Err() != nil || q.snapshotV1(t) != held || factory.PendingV1().WorkSessions != 1 || factory.PendingV1().HTMLAdmissions != 1 {
		t.Fatal("own active-stage uncertainty was accepted or native debt was credited before original last use", err)
	}
	once.Do(func() { close(release) })
	join, stopJoin := context.WithTimeout(q.f.ctx, 3*time.Second)
	select {
	case err = <-done:
		joined = true
	case <-join.Done():
		stopJoin()
		t.Fatal("original native callback did not join after explicit release", join.Err())
	}
	stopJoin()
	if !errors.Is(err, context.Canceled) {
		t.Fatal("actual original callback lost its cancellation result", err)
	}
	cleanup, stopCleanup = context.WithTimeout(context.Background(), 5*time.Second)
	err = op.CloseV1(cleanup)
	stopCleanup()
	if err != nil {
		t.Fatal("same actual scoped owner did not retire after original callback last use", err)
	}
	if participantCapacityLegalState253(t, q, doc.ID) != beforeLegal {
		t.Fatal("ownership-only close regression changed legal application state")
	}
	q.assertObserversOnlyV1(t)
}
