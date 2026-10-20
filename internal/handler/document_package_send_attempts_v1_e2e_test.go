//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/recoveryinventory"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
)

func packageAttemptMatch235(m pdfadmission.HTMLSendPackageIntentMetadataV1) generated.DeleteDocumentPackageSealingIntentV1Params {
	return generated.DeleteDocumentPackageSealingIntentV1Params{AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:]}
}
func packageAttemptBirth235(t *testing.T, q *ownedPublicReadFixtureV1, withAnnex bool) (*generated.Document, *generated.DocumentPackagesV1, pdfadmission.HTMLSendPackageIntentMetadataV1, error) {
	t.Helper()
	root := packageImported220(t, q, "Actual package Send identity")
	var annexes []*generated.Document
	if withAnnex {
		annexes = append(annexes, packageImported220(t, q, "Actual selected business annex"))
	}
	p := packageCreate223(t, q, root, annexes...)
	root = packageLatest223(t, q, root.ID)
	var meta pdfadmission.HTMLSendPackageIntentMetadataV1
	var op *pdfadmission.ApplicationHTMLSendOperationV1
	err := packageCaptureRun234(t, q, root, p, func(original *pdfadmission.ApplicationHTMLSendOperationV1, _ *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ authoring.Actor) error {
		op = original
		return nil
	}, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
		if _, e := packageCaptureAppend234(t, call, work, prior); e != nil {
			return e
		}
		actor := pdfadmission.HTMLSendIntentActorV1{IP: "127.0.0.1", Via: "synthetic-owned-test", Tool: "exact-package-attempt"}
		if e := work.CreateIntentV1(call, actor); !errors.Is(e, pdfadmission.ErrHTMLSendWorkV1) {
			t.Fatal("legacy intent adopted a private package capture", e)
		}
		var e error
		meta, e = work.CreatePackageIntentV1(call, actor)
		if e != nil {
			return e
		}
		if id, present := op.PackageSendAttemptIDV1(); !present || id != meta.AttemptID {
			t.Fatal("original operation lost its single attempt identity")
		}
		if again, e := work.CreatePackageIntentV1(call, actor); !errors.Is(e, pdfadmission.ErrHTMLSendPackageIntentV1) || again != (pdfadmission.HTMLSendPackageIntentMetadataV1{}) {
			t.Fatal("package intent replay accepted", e)
		}
		if _, e := work.FreezeBrandingV1(call); e != nil {
			return e
		}
		return work.BeginSendSealingV1(call)
	})
	if op != nil && meta.AttemptID != uuid.Nil {
		if id, present := op.PackageSendAttemptIDV1(); !present || id != meta.AttemptID {
			t.Fatal("SQL/Work close erased diagnostic attempt identity")
		}
	}
	return root, p, meta, err
}
func packageAttemptInspect235(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, active bool, outcome string) {
	t.Helper()
	row, e := q.f.q.InspectDocumentPackageSendAttemptV1(q.f.ctx, generated.InspectDocumentPackageSendAttemptV1Params{AttemptID: m.AttemptID, OrgID: q.f.org, DocumentID: m.Capture.DocumentID})
	if e != nil || row.AttemptID != m.AttemptID || row.OrgID != q.f.org || row.DocumentID != m.Capture.DocumentID || row.PackageID != m.Capture.PackageID || row.CaptureRevision != m.Capture.Revision || row.PreviousRevision != m.Capture.PreviousRevision || row.ManifestBytes != m.Capture.ManifestBytes || row.MemberCount != m.Capture.MemberCount || row.PdfBytes != m.Capture.PDFBytes || row.PdfPages != m.Capture.PDFPages || row.CapturedDraftGeneration != m.Capture.DraftGeneration || !row.CapturedRootUpdatedAt.Time.Equal(m.Capture.RootUpdatedAt) || row.HasActiveIntent != active || row.TerminalOutcome.String != outcome || row.TerminalOutcome.Valid != (outcome != "") || !row.Article13NoticeEpochAt.Time.Equal(m.Article13NoticeEpochAt) || !row.RetainUntil.Time.Equal(m.RetainUntil) {
		t.Fatal("exact attempt inspection differs", row, e)
	}
	if !active && !row.TerminalAt.Valid {
		t.Fatal("terminal history lost")
	}
	wrong := generated.InspectDocumentPackageSendAttemptV1Params{AttemptID: uuid.New(), OrgID: q.f.org, DocumentID: m.Capture.DocumentID}
	if _, e = q.f.q.InspectDocumentPackageSendAttemptV1(q.f.ctx, wrong); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("missing exact attempt inspected as an existing winner", e)
	}
	wrong.AttemptID = m.AttemptID
	wrong.OrgID = uuid.New()
	if _, e = q.f.q.InspectDocumentPackageSendAttemptV1(q.f.ctx, wrong); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("foreign tenant read attempt history", e)
	}
}
func packageAttemptTransition235(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, outcome string, expire bool, afterTerminal ...func(pgx.Tx) error) error {
	t.Helper()
	tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
	defer rollbackHTMLQueryFixtureV1(t, tx)
	db := generated.New(tx)
	match := packageAttemptMatch235(m)
	if _, e := db.GetDocumentForUpdate(q.f.ctx, generated.GetDocumentForUpdateParams{ID: m.Capture.DocumentID, OrgID: q.f.org}); e != nil {
		return e
	}
	if outcome == "aborted" {
		if n, e := db.AbortDocumentPackageSendSealingV1(q.f.ctx, generated.AbortDocumentPackageSendSealingV1Params(match)); e != nil || n != 1 {
			t.Fatal("package abort", n, e)
		}
	} else {
		if _, e := db.MarkDocumentPackageSendRetentionStartedV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionStartedV1Params(match)); e != nil {
			return e
		}
		if _, e := db.SynchronizeDocumentPackageSendRetentionV1(q.f.ctx, generated.SynchronizeDocumentPackageSendRetentionV1Params(match)); e != nil {
			return e
		}
		// Explicit synthetic SQL acknowledgements exercise the M105 protocol;
		// this fixture makes no claim of actual provider retention verification.
		if e := packageMemberRetentionSQLReceipts240(q.f.ctx, db, m); e != nil {
			return e
		}
		if _, e := db.MarkDocumentPackageSendRetentionCompleteV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionCompleteV1Params(match)); e != nil {
			return e
		}
		if _, e := db.SynchronizeDocumentPackageSendRetentionV1(q.f.ctx, generated.SynchronizeDocumentPackageSendRetentionV1Params(match)); e != nil {
			return e
		}
		root := packageLatest223(t, q, m.Capture.DocumentID)
		if _, e := db.PinDocumentSendEvidenceVersions(q.f.ctx, generated.PinDocumentSendEvidenceVersionsParams{ID: root.ID, OrgID: q.f.org, PdfStorageVersionID: root.PdfStorageVersionID, RenderedPdfVersionID: root.RenderedPdfVersionID}); e != nil {
			return e
		}
		sent, e := db.CompleteDocumentPackageSendSealingV1(q.f.ctx, generated.CompleteDocumentPackageSendSealingV1Params(match))
		if e != nil {
			return e
		}
		epoch, e := article13.CanonicalSentAt(sent.SentAt.Time)
		if e != nil {
			return e
		}
		payload := map[string]any{article13.AuditRequiredNoticeSchemaKey: sent.Article13NoticeSchema, article13.AuditRequiredNoticeSentAtKey: epoch}
		completionSchema, e := packageCompletionVersionPresent241(q.f.ctx, tx)
		if e != nil {
			return e
		}
		if completionSchema {
			payload = packageCompletionPayload241(m, payload)
			payload["recipient_count"] = 0
		}
		if _, e = q.f.s.Audit.LogTx(q.f.ctx, tx, audit.Entry{OrgID: q.f.org, DocumentID: &sent.ID, ActorUserID: &q.f.user.ID, Kind: audit.KindDocumentSent, Payload: payload}); e != nil {
			return e
		}
		if expire {
			if _, e = tx.Exec(q.f.ctx, "UPDATE documents SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", sent.ID); e != nil {
				return e
			}
			ended, e := db.ExpireDocumentIfActive(q.f.ctx, generated.ExpireDocumentIfActiveParams{ID: sent.ID, OrgID: q.f.org})
			if e != nil || ended.Status != "expired" {
				t.Fatal("expire sealed fixture", e)
			}
			if completionSchema {
				if _, e = q.f.s.Audit.LogTx(q.f.ctx, tx, audit.Entry{OrgID: q.f.org, DocumentID: &sent.ID, Kind: audit.KindDocumentExpired, Payload: packageCompletionPayload241(m, map[string]any{"before_invite": true, "irreversible_sealing_recovery": true})}); e != nil {
					return e
				}
			}
		}
		// Explicit synthetic SQL effect acknowledgement, never provider/native proof.
		// Original audits precede the receipt; terminalization and deletion follow.
		if completionSchema {
			if _, e := db.RecordDocumentPackageSendCompletionV1(q.f.ctx, packageCompletionRecordParams241(m)); e != nil {
				return e
			}
		}
	}
	if _, e := db.TerminalizeDocumentPackageSendAttemptV1(q.f.ctx, generated.TerminalizeDocumentPackageSendAttemptV1Params{Outcome: outcome, AttemptID: m.AttemptID, OrgID: q.f.org, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:]}); e != nil {
		return e
	}
	if n, e := db.DeleteDocumentPackageSealingIntentV1(q.f.ctx, match); e != nil || n != 1 {
		t.Fatal("exact terminal intent deletion", n, e)
	}
	if len(afterTerminal) > 1 {
		t.Fatal("invalid terminal hook count")
	}
	if len(afterTerminal) == 1 {
		if e := afterTerminal[0](tx); e != nil {
			return e
		}
	}
	if _, e := tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE"); e != nil {
		return e
	}
	return tx.Commit(q.f.ctx)
}
func packageAttemptInventory235(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, root *generated.Document, legal bool) {
	t.Helper()
	raw, e := os.ReadFile("../../ops/recovery-object-inventory.sql")
	if e != nil {
		t.Fatal(e)
	}
	query := "SELECT legal_evidence,expected_retain_until,expected_version_id,reference_classes::text,owners::text,version_conflict FROM (" + strings.TrimSuffix(strings.TrimSpace(string(raw)), ";") + ") inventory WHERE object_key_b64=$1"
	var gotLegal, conflict bool
	var until, version, classes, owners string
	inventoryTx, e := recoveryinventory.Begin(q.f.ctx, q.f.pool)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if err := recoveryinventory.Rollback(inventoryTx); err != nil {
			t.Error("close canonical inventory snapshot", err)
		}
	}()
	e = inventoryTx.QueryRow(q.f.ctx, query, base64.StdEncoding.EncodeToString([]byte(root.PdfStorageKey.String))).Scan(&gotLegal, &until, &version, &classes, &owners, &conflict)
	want := "-"
	if legal {
		want = m.RetainUntil.UTC().Format(time.RFC3339)
	}
	if e != nil || gotLegal != legal || until != want || version != root.PdfStorageVersionID.String || conflict || !strings.Contains(classes, "package_send_capture_pdf") || !strings.Contains(owners, m.AttemptID.String()) {
		t.Fatal("exact historical package recovery reference", gotLegal, until, version, classes, owners, conflict, e)
	}
}

// Native birth is real owned PG/auth/PDF measurement. Retention/completion
// checkpoints below model provider success; they are not Object Lock receipts.
func TestDocumentPackageSendAttemptV1E2E(t *testing.T) {
	q := newOwnedDocumentPackageMeasurementFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if e := malwarescan.Configure(q.f.ctx, "", "development"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := malwarescan.Configure(context.Background(), "", "development"); e != nil {
			t.Error(e)
		}
	})
	t.Run("genuine measured main commits exact attempt and reversible history", func(t *testing.T) {
		root, _, m, e := packageAttemptBirth235(t, q, false)
		if e != nil {
			t.Fatal(e)
		}
		packageAttemptInspect235(t, q, m, true, "")
		before := packageMeasurementState232(t, q)
		for _, change := range []func() (int64, error){
			func() (int64, error) {
				return q.f.q.MarkSendSealingRetentionStarted(q.f.ctx, generated.MarkSendSealingRetentionStartedParams{DocumentID: root.ID, OrgID: q.f.org})
			},
			func() (int64, error) {
				return q.f.q.MarkSendSealingRetentionComplete(q.f.ctx, generated.MarkSendSealingRetentionCompleteParams{DocumentID: root.ID, OrgID: q.f.org})
			},
			func() (int64, error) {
				return q.f.q.MarkSendSealingAttemptFailed(q.f.ctx, generated.MarkSendSealingAttemptFailedParams{DocumentID: root.ID, OrgID: q.f.org, LastError: pgtype.Text{String: "wrong legacy path", Valid: true}})
			},
			func() (int64, error) {
				return q.f.q.AbortDocumentSendSealing(q.f.ctx, generated.AbortDocumentSendSealingParams{ID: root.ID, OrgID: q.f.org})
			},
			func() (int64, error) {
				return q.f.q.DeleteSendSealingIntent(q.f.ctx, generated.DeleteSendSealingIntentParams{DocumentID: root.ID, OrgID: q.f.org})
			},
		} {
			if n, e := change(); e != nil || n != 0 {
				t.Fatal("legacy mutation touched bound intent", n, e)
			}
		}
		if _, e = q.f.q.CompleteDocumentSendSealing(q.f.ctx, generated.CompleteDocumentSendSealingParams{ID: root.ID, OrgID: q.f.org}); !errors.Is(e, pgx.ErrNoRows) {
			t.Fatal("legacy completion adopted package", e)
		}
		if packageMeasurementState232(t, q) != before {
			t.Fatal("legacy path changed bound state")
		}
		ctx, stop := context.WithTimeout(q.f.ctx, 5*time.Second)
		defer stop()
		op, e := q.runtime.SessionsV1().NewHTMLSendOperationV1(ctx, q.f.org, root.ID)
		if e != nil {
			t.Fatal(e)
		}
		func() {
			defer func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				if e := op.CloseV1(cleanup); e != nil {
					t.Error(e)
				}
			}()
			stage, e := op.OpenSQLV1(pdfadmission.HTMLSendIntentReadV1)
			if e != nil {
				t.Fatal(e)
			}
			session := stage.SessionV1()
			if _, e = session.NewAdmissionV1(stage.ContextV1()); e != nil {
				t.Fatal(e)
			}
			e = stage.WithTxV1(func(call context.Context, _ generated.DBTX) error {
				work, e := session.NewHTMLSendWorkV1(call, stage)
				if e != nil {
					return e
				}
				if _, e = work.StateV1(call); e != nil {
					return e
				}
				if _, e = work.ReadIntentV1(call); !errors.Is(e, pdfadmission.ErrHTMLSendPackagePathRequiredV1) {
					t.Fatal("legacy native reader lost attempt binding", e)
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		}()
		ownedCreationAssertDrainedV1(t, q, 2)
		if e = packageAttemptTransition235(t, q, m, "aborted", false); e != nil {
			t.Fatal(e)
		}
		packageAttemptInspect235(t, q, m, false, "aborted")
		packageAttemptInventory235(t, q, m, root, false)
	})
	t.Run("refused intent funding cannot authorize sealing or mint identity", func(t *testing.T) {
		root := packageImported220(t, q, "Budget refused package main")
		p := packageCreate223(t, q, root)
		before := packageMeasurementState232(t, q)
		var op *pdfadmission.ApplicationHTMLSendOperationV1
		checked := false
		stop := errors.New("synthetic funding-refusal rollback")
		e := packageCaptureRun234(t, q, root, p, func(original *pdfadmission.ApplicationHTMLSendOperationV1, _ *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ authoring.Actor) error {
			op = original
			return nil
		}, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
			if _, e := packageCaptureAppend234(t, call, work, prior); e != nil {
				return e
			}
			if _, e := work.FreezeBrandingV1(call); e != nil {
				return e
			}
			// Actual actor bytes drive the genuine resource admission. This small
			// input quotes beyond its fixed hard ceiling without allocating the
			// quoted work, changing limits or sending it to SQL/provider services.
			actor := pdfadmission.HTMLSendIntentActorV1{Via: "synthetic-owned-test", Tool: strings.Repeat("x", 1<<20)}
			budgetBefore := q.snapshotV1(t)
			meta, e := work.CreatePackageIntentV1(call, actor)
			if !errors.Is(e, pdfadmission.ErrHTMLSendPackageIntentV1) || !errors.Is(e, pdfadmission.ErrHTMLAuthoringReadV1) || !errors.Is(e, pdfadmission.ErrApplicationAdmissionV1) || meta != (pdfadmission.HTMLSendPackageIntentMetadataV1{}) || call.Err() != nil {
				t.Fatal("expected live pre-SQL pricing refusal", e)
			}
			if q.snapshotV1(t) != budgetBefore {
				t.Fatal("refused pricing changed retained resource counters")
			}
			if id, present := op.PackageSendAttemptIDV1(); present || id != uuid.Nil {
				t.Fatal("refused funding minted an attempt identity")
			}
			if meta, e = work.CreatePackageIntentV1(call, pdfadmission.HTMLSendIntentActorV1{Via: "synthetic-owned-test"}); !errors.Is(e, pdfadmission.ErrHTMLSendPackageIntentV1) || meta != (pdfadmission.HTMLSendPackageIntentMetadataV1{}) {
				t.Fatal("failed one-shot intent retried", e)
			}
			if id, present := op.PackageSendAttemptIDV1(); present || id != uuid.Nil {
				t.Fatal("refused one-shot replay minted an identity")
			}
			if e = work.BeginSendSealingV1(call); !errors.Is(e, pdfadmission.ErrHTMLSendWorkV1) {
				t.Fatal("failed intent authorized sealing", e)
			}
			checked = true
			return stop
		})
		if !errors.Is(e, stop) || !checked || packageMeasurementState232(t, q) != before {
			t.Fatal("funding refusal failed to preserve full state", checked, e)
		}
	})
	t.Run("nonempty package requires its forward lifecycle gate", func(t *testing.T) {
		var rootID uuid.UUID
		// Full state baseline is taken after fixture document/package creation.
		root := packageImported220(t, q, "M99 guarded package")
		a := packageImported220(t, q, "M99 guarded annex")
		p := packageCreate223(t, q, root, a)
		rootID = root.ID
		before := packageMeasurementState232(t, q)
		bound := false
		var meta pdfadmission.HTMLSendPackageIntentMetadataV1
		e := packageCaptureRun234(t, q, root, p, nil, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
			if _, e := work.AppendDocumentPackageCaptureV1(call, prior); e != nil {
				return e
			}
			var e error
			if meta, e = work.CreatePackageIntentV1(call, pdfadmission.HTMLSendIntentActorV1{Via: "synthetic-owned-test"}); e != nil {
				return e
			}
			if _, e := work.FreezeBrandingV1(call); e != nil {
				return e
			}
			bound = true
			return work.BeginSendSealingV1(call)
		})
		var forward bool
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT to_regprocedure('hash_package_lifecycle_version_v1()') IS NOT NULL").Scan(&forward); err != nil {
			t.Fatal(err)
		}
		if forward {
			if e != nil || !bound || meta.AttemptID == uuid.Nil || packageLatest223(t, q, rootID).Status != "sealing" {
				t.Fatal("forward lifecycle refused exact genuine package attempt", rootID, bound, e)
			}
			packageAttemptInspect235(t, q, meta, true, "")
			if err := packageAttemptTransition235(t, q, meta, "aborted", false); err != nil {
				t.Fatal("genuine package pre-retention abort failed", err)
			}
			return
		}
		if e == nil || !bound || packageMeasurementState232(t, q) != before {
			t.Fatal("unqualified nonempty package activated or binding survived", rootID, bound, e)
		}
	})
	t.Run("reviewed HTML main binds native source without annex wrapper", func(t *testing.T) {
		root := reviewPackageHTML221(t, q, createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie))
		p := packageCreate223(t, q, root)
		root = packageLatest223(t, q, root.ID)
		var m pdfadmission.HTMLSendPackageIntentMetadataV1
		e := packageCaptureRun234(t, q, root, p, nil, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
			if _, e := work.AppendDocumentPackageCaptureV1(call, prior); e != nil {
				return e
			}
			var e error
			m, e = work.CreatePackageIntentV1(call, pdfadmission.HTMLSendIntentActorV1{Via: "synthetic-owned-test"})
			if e != nil {
				return e
			}
			return work.BeginSendSealingV1(call)
		})
		if e != nil || m.Capture.PDFPages != 2 {
			t.Fatal("native HTML package binding", m, e)
		}
		packageAttemptInspect235(t, q, m, true, "")
		if e = packageAttemptTransition235(t, q, m, "aborted", false); e != nil {
			t.Fatal(e)
		}
	})
	for _, expired := range []bool{false, true} {
		name := "sent"
		if expired {
			name = "expired"
		}
		t.Run("completed "+name+" retains history after intent deletion", func(t *testing.T) {
			root, _, m, e := packageAttemptBirth235(t, q, false)
			if e != nil {
				t.Fatal(e)
			}
			if e = packageAttemptTransition235(t, q, m, "completed", expired); e != nil {
				t.Fatal(e)
			}
			packageAttemptInspect235(t, q, m, false, "completed")
			packageAttemptInventory235(t, q, m, root, true)
			state, e := q.f.q.GetHTMLSendDocumentStateHeaderV1(q.f.ctx, generated.GetHTMLSendDocumentStateHeaderV1Params{DocumentID: root.ID, OrgID: q.f.org})
			if e != nil || !state.HasPackageSendHistory {
				t.Fatal("completed legacy fallback lost exact history", e)
			}
			before := packageMeasurementState232(t, q)
			for _, sql := range []string{"UPDATE document_package_send_attempts_v1 SET terminal_outcome=NULL,terminal_at=NULL WHERE attempt_id=$1", "DELETE FROM document_package_send_attempts_v1 WHERE attempt_id=$1", "UPDATE document_package_send_attempts_v1 SET retain_until=retain_until+interval '1 day' WHERE attempt_id=$1"} {
				_, e = q.f.pool.Exec(q.f.ctx, sql, m.AttemptID)
				packageExpectPG218(t, e, "23514")
				if packageMeasurementState232(t, q) != before {
					t.Fatal("terminal rewrite changed history")
				}
			}
		})
	}
	for _, kind := range []string{"identity rewrite", "intent rebind", "active intent deletion", "retention mismatch", "main drift", "terminal root drift", "terminal source drift", "pending privacy"} {
		t.Run(kind+" refuses atomically", func(t *testing.T) {
			root, _, m, e := packageAttemptBirth235(t, q, false)
			if e != nil {
				t.Fatal(e)
			}
			var dsr *generated.DataSubjectRequest
			if kind == "pending privacy" {
				dsr, e = q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: root.ID, Valid: true}, SubjectEmail: "synthetic@hash.example.test", SubjectName: "Synthetic", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
				if e != nil {
					t.Fatal(e)
				}
			}
			before := packageMeasurementState232(t, q)
			func() {
				tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
				defer rollbackHTMLQueryFixtureV1(t, tx)
				db := generated.New(tx)
				match := packageAttemptMatch235(m)
				switch kind {
				case "identity rewrite":
					_, e = tx.Exec(q.f.ctx, "UPDATE document_package_send_attempts_v1 SET manifest_bytes=manifest_bytes+1 WHERE attempt_id=$1", m.AttemptID)
				case "intent rebind":
					_, e = tx.Exec(q.f.ctx, "UPDATE send_sealing_intents SET package_send_attempt_id=NULL WHERE document_id=$1", root.ID)
				case "active intent deletion":
					_, e = tx.Exec(q.f.ctx, "DELETE FROM send_sealing_intents WHERE document_id=$1", root.ID)
				case "retention mismatch":
					_, e = db.MarkDocumentPackageSendRetentionStartedV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionStartedV1Params(match))
					if e != nil {
						t.Fatal(e)
					}
					_, e = tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE")
				case "main drift":
					_, e = tx.Exec(q.f.ctx, "UPDATE documents SET name='Different signed name' WHERE id=$1", root.ID)
					if e != nil {
						t.Fatal(e)
					}
					_, e = tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE")
				case "terminal root drift", "terminal source drift":
					// A reversible terminal transition is valid initially, but changing its
					// final state in this transaction must be caught by deferred validation.
					if n, x := db.AbortDocumentPackageSendSealingV1(q.f.ctx, generated.AbortDocumentPackageSendSealingV1Params(match)); x != nil || n != 1 {
						t.Fatal(x)
					}
					if _, x := db.TerminalizeDocumentPackageSendAttemptV1(q.f.ctx, generated.TerminalizeDocumentPackageSendAttemptV1Params{Outcome: "aborted", AttemptID: m.AttemptID, OrgID: q.f.org, DocumentID: root.ID, ExpectedManifestSha256: match.ExpectedManifestSha256, ExpectedLegalCommitmentSha256: match.ExpectedLegalCommitmentSha256}); x != nil {
						t.Fatal(x)
					}
					if _, x := db.DeleteDocumentPackageSealingIntentV1(q.f.ctx, match); x != nil {
						t.Fatal(x)
					}
					if kind == "terminal root drift" {
						_, e = tx.Exec(q.f.ctx, "UPDATE documents SET status='sealing' WHERE id=$1", root.ID)
					} else {
						// No terminal-completed source proof is manufactured here; while active,
						// same-transaction PDF drift is independently refused.
						_, e = tx.Exec(q.f.ctx, "UPDATE documents SET status='sealing',pdf_storage_version_id='wrong-selected-version' WHERE id=$1", root.ID)
					}
					if e != nil {
						t.Fatal(e)
					}
					_, e = tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE")
				case "pending privacy":
					_, e = db.MarkDocumentPackageSendRetentionStartedV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionStartedV1Params(match))
					if e != nil {
						t.Fatal(e)
					}
					_, e = db.SynchronizeDocumentPackageSendRetentionV1(q.f.ctx, generated.SynchronizeDocumentPackageSendRetentionV1Params(match))
				}
				packageExpectPG218(t, e, "23514")
			}()
			if packageMeasurementState232(t, q) != before {
				t.Fatal("refusal changed durable pair", kind)
			}
			if dsr != nil {
				if _, e = q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: dsr.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); e != nil {
					t.Fatal(e)
				}
			}
			if e = packageAttemptTransition235(t, q, m, "aborted", false); e != nil {
				t.Fatal(e)
			}
		})
	}

	t.Run("completed source drift at commit refuses and rolls back publication", func(t *testing.T) {
		root, _, m, e := packageAttemptBirth235(t, q, false)
		if e != nil {
			t.Fatal(e)
		}
		before := packageMeasurementState232(t, q)
		e = packageAttemptTransition235(t, q, m, "completed", false, func(tx pgx.Tx) error {
			_, e := tx.Exec(q.f.ctx, "UPDATE documents SET name='Changed after terminalization' WHERE id=$1", root.ID)
			return e
		})
		packageExpectPG218(t, e, "23514")
		if packageMeasurementState232(t, q) != before {
			t.Fatal("invalid completed source drift survived")
		}
		if e = packageAttemptTransition235(t, q, m, "aborted", false); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("retention started cannot become reversible abort", func(t *testing.T) {
		root, _, m, e := packageAttemptBirth235(t, q, false)
		if e != nil {
			t.Fatal(e)
		}
		func() {
			tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
			defer rollbackHTMLQueryFixtureV1(t, tx)
			db := generated.New(tx)
			match := packageAttemptMatch235(m)
			if _, e = db.MarkDocumentPackageSendRetentionStartedV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionStartedV1Params(match)); e != nil {
				t.Fatal(e)
			}
			if _, e = db.SynchronizeDocumentPackageSendRetentionV1(q.f.ctx, generated.SynchronizeDocumentPackageSendRetentionV1Params(match)); e != nil {
				t.Fatal(e)
			}
			if e = tx.Commit(q.f.ctx); e != nil {
				t.Fatal(e)
			}
		}()
		before := packageMeasurementState232(t, q)
		if n, e := q.f.q.AbortDocumentPackageSendSealingV1(q.f.ctx, generated.AbortDocumentPackageSendSealingV1Params(packageAttemptMatch235(m))); e != nil || n != 0 {
			t.Fatal("retained abort query accepted", n, e)
		}
		_, e = q.f.q.TerminalizeDocumentPackageSendAttemptV1(q.f.ctx, generated.TerminalizeDocumentPackageSendAttemptV1Params{Outcome: "aborted", AttemptID: m.AttemptID, OrgID: q.f.org, DocumentID: root.ID, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:]})
		packageExpectPG218(t, e, "23514")
		if packageMeasurementState232(t, q) != before {
			t.Fatal("retained evidence reopened")
		}
		if e = packageAttemptTransition235(t, q, m, "completed", false); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("occupied rollback refuses terminal history with no intent", func(t *testing.T) {
		// Keep the original independent M103 rollback oracle on terminal history
		// without M105 member progress. The parent fixture's completed receipts
		// remain intact; the separate M105 suite checks their occupied rollback.
		q := inspectionFixturePG236(t)
		_, _, m, e := packageAttemptBirth235(t, q, false)
		if e != nil {
			t.Fatal(e)
		}
		if e = packageAttemptTransition235(t, q, m, "aborted", false); e != nil {
			t.Fatal(e)
		}
		before := packageMeasurementState232(t, q)
		cfg, e := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
		if e != nil {
			t.Fatal(e)
		}
		db := stdlib.OpenDB(*cfg)
		defer db.Close()
		if e = mdb.RunMigrationsDownToContext(q.f.ctx, db, 102); e == nil {
			t.Fatal("rollback erased terminal attempt history")
		}
		if version, x := mdb.GetMigrationVersionContext(q.f.ctx, db); x != nil || version != 103 || packageMeasurementState232(t, q) != before {
			t.Fatal("occupied rollback changed current state", version, x)
		}
	})
}

func packageCaptureOnly235(t *testing.T, q *ownedPublicReadFixtureV1, withAnnex bool) (*generated.Document, pdfadmission.HTMLSendPackageCaptureMetadataV1, []*generated.Document) {
	t.Helper()
	root := packageImported220(t, q, "Capture for SQL binding controls")
	var annexes []*generated.Document
	if withAnnex {
		annexes = append(annexes, packageImported220(t, q, "Frozen SQL binding annex"))
	}
	p := packageCreate223(t, q, root, annexes...)
	root = packageLatest223(t, q, root.ID)
	var cap pdfadmission.HTMLSendPackageCaptureMetadataV1
	e := packageCaptureRun234(t, q, root, p, nil, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
		var e error
		cap, e = work.AppendDocumentPackageCaptureV1(call, prior)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	return root, cap, annexes
}
func packageAttemptInput235(c pdfadmission.HTMLSendPackageCaptureMetadataV1) generated.CreateDocumentPackageSendAttemptV1Params {
	return generated.CreateDocumentPackageSendAttemptV1Params{AttemptID: uuid.New(), PackageID: c.PackageID, CaptureRevision: c.Revision, OrgID: c.OrgID, DocumentID: c.DocumentID, ExpectedRootUpdatedAt: pgtype.Timestamptz{Time: c.RootUpdatedAt, Valid: true}, ExpectedDraftGeneration: c.DraftGeneration, ExpectedPreviousRevision: c.PreviousRevision, ExpectedManifestBytes: c.ManifestBytes, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], ExpectedMemberCount: c.MemberCount, ExpectedPdfBytes: c.PDFBytes, ExpectedPdfPages: c.PDFPages, ActorUserID: c.CreatedBy}
}
func TestDocumentPackageSendAttemptBindingGuardsV1E2E(t *testing.T) {
	q := newOwnedDocumentPackageMeasurementFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if e := malwarescan.Configure(q.f.ctx, "", "development"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := malwarescan.Configure(context.Background(), "", "development"); e != nil {
			t.Error(e)
		}
	})
	root, cap, _ := packageCaptureOnly235(t, q, false)
	for _, field := range []string{"org", "root", "package", "revision", "clock", "generation", "previous", "length", "member count", "bytes", "pages", "raw hash", "legal hash", "actor"} {
		t.Run("different "+field+" cannot bind capture", func(t *testing.T) {
			in := packageAttemptInput235(cap)
			switch field {
			case "org":
				in.OrgID = uuid.New()
			case "root":
				in.DocumentID = uuid.New()
			case "package":
				in.PackageID = uuid.New()
			case "revision":
				in.CaptureRevision++
			case "clock":
				in.ExpectedRootUpdatedAt.Time = in.ExpectedRootUpdatedAt.Time.Add(time.Microsecond)
			case "generation":
				in.ExpectedDraftGeneration++
			case "previous":
				in.ExpectedPreviousRevision++
			case "length":
				in.ExpectedManifestBytes++
			case "member count":
				in.ExpectedMemberCount++
			case "bytes":
				in.ExpectedPdfBytes++
			case "pages":
				in.ExpectedPdfPages++
			case "raw hash":
				in.ExpectedManifestSha256 = make([]byte, 32)
			case "legal hash":
				in.ExpectedLegalCommitmentSha256 = make([]byte, 32)
			case "actor":
				in.ActorUserID = uuid.New()
			}
			before := packageMeasurementState232(t, q)
			tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
			_, e := generated.New(tx).CreateDocumentPackageSendAttemptV1(q.f.ctx, in)
			if !errors.Is(e, pgx.ErrNoRows) {
				rollbackHTMLQueryFixtureV1(t, tx)
				t.Fatal("different capture binding accepted", field, e)
			}
			rollbackHTMLQueryFixtureV1(t, tx)
			if packageMeasurementState232(t, q) != before {
				t.Fatal("binding refusal changed state")
			}
		})
	}
	for _, withIntent := range []bool{false, true} {
		name := "missing intent"
		if withIntent {
			name = "root not sealing"
		}
		t.Run(name+" prevents orphan commit", func(t *testing.T) {
			before := packageMeasurementState232(t, q)
			func() {
				tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
				defer rollbackHTMLQueryFixtureV1(t, tx)
				db := generated.New(tx)
				in := packageAttemptInput235(cap)
				row, e := db.CreateDocumentPackageSendAttemptV1(q.f.ctx, in)
				if e != nil {
					t.Fatal(e)
				}
				if withIntent {
					if _, e = db.CreateDocumentPackageSealingIntentV1(q.f.ctx, generated.CreateDocumentPackageSealingIntentV1Params{AttemptID: row.AttemptID, OrgID: q.f.org, DocumentID: root.ID, Via: "synthetic-SQL-control"}); e != nil {
						t.Fatal(e)
					}
				}
				_, e = tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE")
				packageExpectPG218(t, e, "23514")
			}()
			if packageMeasurementState232(t, q) != before {
				t.Fatal("orphan commit changed state")
			}
		})
	}
	t.Run("actual reverse root lock refuses NOWAIT without side effects", func(t *testing.T) {
		before := packageMeasurementState232(t, q)
		holder := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, holder)
		if _, e := holder.Exec(q.f.ctx, "SELECT id FROM documents WHERE id=$1 FOR UPDATE", root.ID); e != nil {
			t.Fatal(e)
		}
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		_, e := generated.New(tx).CreateDocumentPackageSendAttemptV1(q.f.ctx, packageAttemptInput235(cap))
		packageExpectPG218(t, e, "55P03")
		rollbackHTMLQueryFixtureV1(t, tx)
		if packageMeasurementState232(t, q) != before {
			t.Fatal("NOWAIT refusal changed state")
		}
	})
	t.Run("pending deleted frozen member privacy refuses binding", func(t *testing.T) {
		_, selected, members := packageCaptureOnly235(t, q, true)
		if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1", members[0].ID); e != nil {
			t.Fatal(e)
		}
		request, e := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: members[0].ID, Valid: true}, SubjectEmail: "synthetic@hash.example.test", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
		if e != nil {
			t.Fatal(e)
		}
		before := packageMeasurementState232(t, q)
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		_, e = generated.New(tx).CreateDocumentPackageSendAttemptV1(q.f.ctx, packageAttemptInput235(selected))
		packageExpectPG218(t, e, "23514")
		rollbackHTMLQueryFixtureV1(t, tx)
		if packageMeasurementState232(t, q) != before {
			t.Fatal("old-member privacy refusal changed package")
		}
		if _, e = q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: request.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("empty history down up preserves nullable legacy intent", func(t *testing.T) {
		legacy := packageImported220(t, q, "Legacy unbound main")
		header, e := q.f.q.GetHTMLSendBrandingInputHeaderV1(q.f.ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: legacy.ID, OrgID: q.f.org})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = q.f.q.FreezeHTMLSendBrandingV1(q.f.ctx, htmlSendFreezeFixtureV1(header)); e != nil {
			t.Fatal(e)
		}
		if _, e := q.f.q.CreateSendSealingIntent(q.f.ctx, generated.CreateSendSealingIntentParams{DocumentID: legacy.ID, OrgID: q.f.org, ActorUserID: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}, ActorEmail: q.f.user.Email, Via: "synthetic-legacy"}); e != nil {
			t.Fatal(e)
		}
		if _, e := q.f.q.BeginDocumentSendSealing(q.f.ctx, generated.BeginDocumentSendSealingParams{ID: legacy.ID, OrgID: q.f.org}); e != nil {
			t.Fatal(e)
		}
		var before, after string
		if e := q.f.pool.QueryRow(q.f.ctx, "SELECT (to_jsonb(i)-'package_send_attempt_id')::text FROM send_sealing_intents i WHERE document_id=$1", legacy.ID).Scan(&before); e != nil {
			t.Fatal(e)
		}
		cfg, e := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
		if e != nil {
			t.Fatal(e)
		}
		db := stdlib.OpenDB(*cfg)
		defer db.Close()
		if e = mdb.RunMigrationsDownToContext(q.f.ctx, db, 102); e != nil {
			t.Fatal(e)
		}
		if e = q.f.pool.QueryRow(q.f.ctx, "SELECT to_jsonb(i)::text FROM send_sealing_intents i WHERE document_id=$1", legacy.ID).Scan(&after); e != nil || after != before {
			t.Fatal("legacy row changed during Down103", e)
		}
		if e = mdb.RunMigrationsContext(q.f.ctx, db); e != nil {
			t.Fatal(e)
		}
		row, e := q.f.q.GetSendSealingIntent(q.f.ctx, generated.GetSendSealingIntentParams{DocumentID: legacy.ID, OrgID: q.f.org})
		if e != nil || row.PackageSendAttemptID.Valid {
			t.Fatal("reapply invented package identity", e)
		}
		if n, e := q.f.q.AbortDocumentSendSealing(q.f.ctx, generated.AbortDocumentSendSealingParams{ID: legacy.ID, OrgID: q.f.org}); e != nil || n != 1 {
			t.Fatal("legacy abort no longer works", n, e)
		}
		if n, e := q.f.q.DeleteSendSealingIntent(q.f.ctx, generated.DeleteSendSealingIntentParams{DocumentID: legacy.ID, OrgID: q.f.org}); e != nil || n != 1 {
			t.Fatal("legacy intent deletion no longer works", n, e)
		}
	})
}
