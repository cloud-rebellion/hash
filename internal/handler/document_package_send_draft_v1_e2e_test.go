//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Actual native Send Work/PG/body loans and original session authorization.
// Synthetic import storage/renderer peers; this read does not measure PDFs,
// append captures, create Send intents, retain evidence or accept signatures.
func withPackageSendDraft231(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID, expected pdfadmission.DocumentPackageDraftExpectedV1, mutateDTO bool, after func(*pdfadmission.ApplicationHTMLSendPackageDraftV1, *pdfadmission.ApplicationHTMLSendWorkV1) error, before ...func(*pdfadmission.ApplicationHTMLSendPackageDraftV1, *pdfadmission.ApplicationHTMLSendWorkV1) error) (failure error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(q.f.ctx, 15*time.Second)
	defer cancel()
	op, err := q.runtime.SessionsV1().NewHTMLSendOperationV1(ctx, q.f.org, root)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		failure = errors.Join(failure, op.CloseV1(cleanup))
		ownedCreationAssertDrainedV1(t, q, 2)
	}()
	stage, err := op.OpenSQLV1(pdfadmission.HTMLSendPreparationV1)
	if err != nil {
		return err
	}
	session := stage.SessionV1()
	if session == nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	if _, err = session.NewAdmissionV1(stage.ContextV1()); err != nil {
		return err
	}
	actor := packageActor220(t, q)
	var work *pdfadmission.ApplicationHTMLSendWorkV1
	var draft *pdfadmission.ApplicationHTMLSendPackageDraftV1
	var pid int32
	var backendStart time.Time
	err = stage.WithTxV1(func(call context.Context, db generated.DBTX) error {
		work, err = session.NewHTMLSendWorkV1(call, stage)
		if err != nil {
			return err
		}
		state, err := work.StateV1(call)
		if err != nil {
			return err
		}
		user, err := work.ReadActorV1(call, actor.UserID)
		if err != nil {
			return err
		}
		if user.Role != "owner" && (user.Role != "sender" || state.SenderID != user.ID) {
			return auth.ErrMutationPermissionRevoked
		}
		if err = actor.Authorize(call, &htmlCreationPolicyTxV1{DBTX: db}, user); err != nil {
			return err
		}
		models, err := work.ReadModelsV1(call)
		if err != nil {
			return err
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
		if mutateDTO {
			models.Document.ID, models.Document.OrgID = uuid.New(), uuid.New()
			models.Document.PdfStorageKey.String = "caller-mutated.pdf"
			models.Document.PdfStorageVersionID.String = "caller-mutated-version"
			clear(models.Document.PdfSha256)
			models.Document.MetadataRedactionReport = json.RawMessage(`{"caller":true}`)
		}
		draft, err = work.ReadDocumentPackageDraftV1(call, source, expected)
		if err != nil {
			return err
		}
		if err = db.QueryRow(call, "SELECT pid,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()").Scan(&pid, &backendStart); err != nil {
			return err
		}
		if _, e := work.ReadDocumentPackageDraftV1(call, source, expected); !errors.Is(e, pdfadmission.ErrDocumentPackageDraftV1) {
			t.Fatal("second root draft read accepted", e)
		}
		if len(before) > 1 {
			t.Fatal("invalid fixture callback count")
		}
		if len(before) == 1 {
			return before[0](draft, work)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err = stage.CloseSQLV1(); err != nil {
		return err
	}
	if !session.RetiredV1() || session.CommitUnknownV1() {
		t.Fatal("read did not physically retire original SQL")
	}
	var live int
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2", pid, backendStart).Scan(&live); err != nil || live != 0 {
		t.Fatal("original native Send backend survived retirement", live, err)
	}
	return after(draft, work)
}

func TestDocumentPackageSendRootDraftV1E2E(t *testing.T) {
	q := newOwnedDocumentPackageMeasurementFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if err := malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	root := packageImported220(t, q, "Root-only Send preparation")
	check := func(want pdfadmission.HTMLSendPackageDraftMetadataV1) func(*pdfadmission.ApplicationHTMLSendPackageDraftV1, *pdfadmission.ApplicationHTMLSendWorkV1) error {
		return func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, work *pdfadmission.ApplicationHTMLSendWorkV1) error {
			got, err := draft.MetadataV1()
			if err != nil || got != want {
				t.Fatal("root draft metadata", got, want, err)
			}
			got.Annexes, got.Generation = 16, 999
			again, err := draft.MetadataV1()
			if err != nil || again != want {
				t.Fatal("copied observations changed retained draft", again, err)
			}
			work.CloseConsumerV1()
			if _, err = draft.MetadataV1(); !errors.Is(err, pdfadmission.ErrDocumentPackageDraftV1) {
				t.Fatal("Work close did not close owned draft", err)
			}
			draft.CloseConsumerV1()
			return nil
		}
	}
	t.Run("absent package needs only actual root", func(t *testing.T) {
		before := packageFullState223(t, q)
		if err := withPackageSendDraft231(t, q, root.ID, pdfadmission.DocumentPackageDraftExpectedV1{}, false, check(pdfadmission.HTMLSendPackageDraftMetadataV1{})); err != nil {
			t.Fatal(err)
		}
		if packageFullState223(t, q) != before {
			t.Fatal("read mutated original root or package")
		}
	})
	a := packageImported220(t, q, "Selected DPA")
	b := packageImported220(t, q, "Selected specifications")
	p := packageCreate223(t, q, packageLatest223(t, q, root.ID), a, b)
	expected := pdfadmission.DocumentPackageDraftExpectedV1{PackageID: p.ID, Generation: p.DraftGeneration}
	want := pdfadmission.HTMLSendPackageDraftMetadataV1{Present: true, PackageID: p.ID, Generation: p.DraftGeneration, Annexes: 2}
	t.Run("frozen sparse annexes ignore mutable views and live source locks", func(t *testing.T) {
		if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Later source',metadata_redaction_report='{\"later\":true}',deleted_at=clock_timestamp() WHERE id=$1 AND org_id=$2", a.ID, q.f.org); err != nil {
			t.Fatal(err)
		}
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		if _, err := tx.Exec(q.f.ctx, "SELECT id FROM documents WHERE id=ANY($1::uuid[]) FOR UPDATE", []uuid.UUID{a.ID, b.ID}); err != nil {
			t.Fatal(err)
		}
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		if err := withPackageSendDraft231(t, q, root.ID, expected, true, check(want)); err != nil {
			t.Fatal(err)
		}
		if packageFullState223(t, q) != before || q.storagePeer.requests.Load() != requests {
			t.Fatal("owned draft read mutated state or performed provider work")
		}
	})
	t.Run("stale or missing header observations refuse", func(t *testing.T) {
		before := packageFullState223(t, q)
		for _, wrong := range []pdfadmission.DocumentPackageDraftExpectedV1{{}, {PackageID: p.ID, Generation: p.DraftGeneration - 1}, {PackageID: uuid.New(), Generation: p.DraftGeneration}} {
			err := withPackageSendDraft231(t, q, root.ID, wrong, false, check(want))
			if !errors.Is(err, pdfadmission.ErrDocumentPackageSourceChangedV1) {
				t.Fatal("stale package accepted or wrong refusal", err)
			}
		}
		if packageFullState223(t, q) != before {
			t.Fatal("stale read mutated package")
		}
	})
	t.Run("pending selected-member privacy review refuses", func(t *testing.T) {
		r, err := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: b.ID, Valid: true}, SubjectEmail: "synthetic@hash.example.test", SubjectName: "Synthetic participant", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
		if err != nil {
			t.Fatal(err)
		}
		before := packageFullState223(t, q)
		err = withPackageSendDraft231(t, q, root.ID, expected, false, check(want))
		if !errors.Is(err, pdfadmission.ErrDocumentPackagePendingPrivacyV1) || packageFullState223(t, q) != before {
			t.Fatal("pending member request accepted or state changed", err)
		}
		if _, err = q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: r.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("revoked original credential refuses", func(t *testing.T) {
		if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE users SET session_generation=session_generation+1 WHERE id=$1", q.f.user.ID); err != nil {
			t.Fatal(err)
		}
		before := packageFullState223(t, q)
		err := withPackageSendDraft231(t, q, root.ID, expected, false, check(want))
		if !errors.Is(err, auth.ErrMutationCredentialExpired) && !errors.Is(err, auth.ErrMutationPermissionRevoked) {
			t.Fatal("revoked original credential accepted", err)
		}
		if packageFullState223(t, q) != before {
			t.Fatal("revoked read mutated state")
		}
	})
}
