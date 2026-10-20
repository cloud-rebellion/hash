//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Same actual preparation/physical retirement witness as231; retain the
// original operation and credential for the fresh native capture stage.
func withPackageSendDraft234(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID, expected pdfadmission.DocumentPackageDraftExpectedV1, mutateDTO bool, after func(*pdfadmission.ApplicationHTMLSendOperationV1, *pdfadmission.ApplicationHTMLSendPackageDraftV1, authoring.Actor) error, before ...func(*pdfadmission.ApplicationHTMLSendPackageDraftV1, *pdfadmission.ApplicationHTMLSendWorkV1) error) (failure error) {
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
	return after(op, draft, actor)
}

func withPackageCaptureAdmission234(t *testing.T, q *ownedPublicReadFixtureV1, op *pdfadmission.ApplicationHTMLSendOperationV1, actor authoring.Actor, apply func(context.Context, *pdfadmission.ApplicationHTMLSendWorkV1) error) error {
	t.Helper()
	stage, err := op.OpenSQLV1(pdfadmission.HTMLSendAdmissionV1)
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
	err = stage.WithTxV1(func(call context.Context, db generated.DBTX) error {
		work, e := session.NewHTMLSendWorkV1(call, stage)
		if e != nil {
			return e
		}
		state, e := work.StateV1(call)
		if e != nil {
			return e
		}
		user, e := work.ReadActorV1(call, actor.UserID)
		if e != nil {
			return e
		}
		if user.Role != "owner" && (user.Role != "sender" || state.SenderID != user.ID) {
			return auth.ErrMutationPermissionRevoked
		}
		if e = actor.Authorize(call, &htmlCreationPolicyTxV1{DBTX: db}, user); e != nil {
			return e
		}
		if _, e = work.ReadModelsV1(call); e != nil {
			return e
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
		if e = apply(call, work); e != nil {
			return e
		}
		return actor.Authorize(call, &htmlCreationPolicyTxV1{DBTX: db}, user)
	})
	if err != nil {
		return err
	}
	// WithTx joins its borrow; it does not acknowledge native COMMIT.
	if err = session.CommitV1(stage.ContextV1()); err != nil {
		return err
	}
	return stage.CloseSQLV1()
}
func packageCaptureExpected234(p *generated.DocumentPackagesV1) pdfadmission.DocumentPackageDraftExpectedV1 {
	if p == nil {
		return pdfadmission.DocumentPackageDraftExpectedV1{}
	}
	return pdfadmission.DocumentPackageDraftExpectedV1{PackageID: p.ID, Generation: p.DraftGeneration}
}
func packageCaptureRun234(t *testing.T, q *ownedPublicReadFixtureV1, root *generated.Document, p *generated.DocumentPackagesV1, between func(*pdfadmission.ApplicationHTMLSendOperationV1, *pdfadmission.ApplicationHTMLSendPackageDraftV1, authoring.Actor) error, apply func(context.Context, *pdfadmission.ApplicationHTMLSendWorkV1, *pdfadmission.ApplicationHTMLSendPackageDraftV1) error) error {
	t.Helper()
	return withPackageSendDraft234(t, q, root.ID, packageCaptureExpected234(p), true, func(op *pdfadmission.ApplicationHTMLSendOperationV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1, actor authoring.Actor) error {
		if err := prior.MeasurePDFsV1(q.f.s.Storage); err != nil {
			return err
		}
		requests := q.storagePeer.requests.Load()
		if between != nil {
			if err := between(op, prior, actor); err != nil {
				return err
			}
		}
		err := withPackageCaptureAdmission234(t, q, op, actor, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1) error {
			return apply(call, work, prior)
		})
		if q.storagePeer.requests.Load() != requests {
			t.Fatal("fresh native capture performed provider work after measurement")
		}
		return err
	})
}
func packageCaptureAppend234(t *testing.T, call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) (pdfadmission.HTMLSendPackageCaptureMetadataV1, error) {
	t.Helper()
	meta, err := work.AppendDocumentPackageCaptureV1(call, prior)
	if err != nil {
		if meta != (pdfadmission.HTMLSendPackageCaptureMetadataV1{}) {
			t.Fatal("refusal exposed capture metadata")
		}
		return meta, err
	}
	if again, e := work.AppendDocumentPackageCaptureV1(call, prior); !errors.Is(e, pdfadmission.ErrHTMLSendPackageCaptureV1) || again != (pdfadmission.HTMLSendPackageCaptureMetadataV1{}) {
		t.Fatal("capture replay accepted", again, e)
	}
	return meta, nil
}
func packageCaptureReadback234(t *testing.T, q *ownedPublicReadFixtureV1, root *generated.Document, p *generated.DocumentPackagesV1, meta pdfadmission.HTMLSendPackageCaptureMetadataV1, selected ...*generated.Document) {
	t.Helper()
	c, rows := captureLoad219(t, q.f, p, meta.Revision)
	h := c.Header()
	canonical := c.Manifest().CanonicalJSON()
	sum := sha256.Sum256(canonical)
	if !meta.Present || meta.OrgID != q.f.org || meta.DocumentID != root.ID || meta.PackageID != p.ID || meta.CreatedBy != q.f.user.ID || meta.Revision != 1 || meta.PreviousRevision != 0 || meta.DraftGeneration != p.DraftGeneration || !meta.RootUpdatedAt.Equal(root.UpdatedAt.Time) || meta.CanonicalSHA256 != sum || hex.EncodeToString(meta.CommitmentSHA256[:]) != h.CommitmentSHA256 || int(meta.ManifestBytes) != len(canonical) || meta.PDFBytes != h.PDFBytes || meta.PDFPages != h.PDFPages || meta.MemberCount != h.MemberCount || meta.CreatedAt.IsZero() {
		t.Fatal("committed native metadata differs from independent capture", meta, h)
	}
	drafts, e := q.f.q.ListDocumentAttachmentDraftsV1(q.f.ctx, generated.ListDocumentAttachmentDraftsV1Params{PackageID: p.ID, OrgID: q.f.org, ExpectedGeneration: p.DraftGeneration})
	if e != nil {
		t.Fatal(e)
	}
	all := append([]*generated.Document{root}, selected...)
	if len(rows) != len(all) {
		t.Fatal("native member count", len(rows), len(all))
	}
	var total int64
	for i, d := range all {
		r := rows[i]
		title := d.Name
		if i > 0 {
			title = drafts[i-1].Title
		}
		q.storagePeer.mu.Lock()
		size := int64(len(q.storagePeer.objects[d.PdfStorageKey.String]))
		q.storagePeer.mu.Unlock()
		report := packageReportBytes222(t, q.f, root.ID)
		if i > 0 {
			report = drafts[i-1].PdfIntakeReport
		}
		reportSHA := sha256.Sum256(report)
		if r.MemberPosition != int16(i) || r.MemberDocumentID != d.ID || r.Title != title || r.PdfKey != d.PdfStorageKey.String || r.PdfVersionID != d.PdfStorageVersionID.String || !bytes.Equal(r.PdfSha256, d.PdfSha256) || r.PdfBytes != size || r.PdfPages < 1 || !bytes.Equal(r.PdfIntakeReport, report) || !bytes.Equal(r.PdfIntakeReportSha256, reportSHA[:]) {
			t.Fatal("capture switched actual member pin/measurement/report", i, r)
		}
		total += size
	}
	if total != meta.PDFBytes {
		t.Fatal("capture aggregate bytes")
	}
	var intents int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM send_sealing_intents WHERE org_id=$1", q.f.org).Scan(&intents); err != nil || intents != 0 {
		t.Fatal("capture invented a sealing intent", intents, err)
	}
}

// Genuine native Preparation -> physical retirement -> strict PDF worker ->
// same-operation Admission/COMMIT. Synthetic S3/HTML renderer peers only.
// This qualifies capture append, not durable Send binding or signing consent.
func TestDocumentPackageSendCaptureV1E2E(t *testing.T) {
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
	rollback := errors.New("controlled native capture rollback")
	t.Run("frozen sparse imported package commits after foreign operation refuses", func(t *testing.T) {
		root := packageImported220(t, q, "Captured main agreement")
		a := packageImported220(t, q, "Frozen DPA")
		b := packageImported220(t, q, "Frozen specifications")
		p := packageCreate223(t, q, root, a, b)
		reports := [][]byte{packageReportBytes222(t, q.f, root.ID), packageReportBytes222(t, q.f, a.ID), packageReportBytes222(t, q.f, b.ID)}
		if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Later source',metadata_redaction_report=$3::jsonb,deleted_at=clock_timestamp() WHERE id=$1 AND org_id=$2", a.ID, q.f.org, []byte("{\"later\":true}")); err != nil {
			t.Fatal(err)
		}
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		if _, err := tx.Exec(q.f.ctx, "SELECT id FROM documents WHERE id=ANY($1::uuid[]) FOR UPDATE", []uuid.UUID{a.ID, b.ID}); err != nil {
			t.Fatal(err)
		}
		before := packageFullState223(t, q)
		var meta pdfadmission.HTMLSendPackageCaptureMetadataV1
		err := packageCaptureRun234(t, q, root, p, func(_ *pdfadmission.ApplicationHTMLSendOperationV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1, actor authoring.Actor) error {
			ctx, cancel := context.WithTimeout(q.f.ctx, 5*time.Second)
			defer cancel()
			foreign, e := q.runtime.SessionsV1().NewHTMLSendOperationV1(ctx, q.f.org, root.ID)
			if e != nil {
				return e
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer stop()
				if e := foreign.CloseV1(cleanup); e != nil {
					t.Error("foreign operation close", e)
				}
			}()
			e = withPackageCaptureAdmission234(t, q, foreign, actor, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1) error {
				_, e := packageCaptureAppend234(t, call, work, prior)
				if !errors.Is(e, pdfadmission.ErrHTMLSendPackageCaptureV1) {
					t.Fatal("foreign operation borrowed genuine original draft", e)
				}
				return rollback
			})
			if !errors.Is(e, rollback) {
				t.Fatal("foreign operation did not refuse", e)
			}
			return nil
		}, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
			var e error
			meta, e = packageCaptureAppend234(t, call, work, prior)
			return e
		})
		if err != nil || packageFullState223(t, q) != before {
			t.Fatal("native capture failed or mutated draft/root", err)
		}
		c, rows := captureLoad219(t, q.f, p, 1)
		if !meta.Present || meta.MemberCount != 3 || meta.PDFPages != 3 || meta.Revision != 1 || meta.PreviousRevision != 0 || meta.DraftGeneration != p.DraftGeneration || hex.EncodeToString(meta.CanonicalSHA256[:]) != c.Header().CanonicalSHA256 || hex.EncodeToString(meta.CommitmentSHA256[:]) != c.Header().CommitmentSHA256 {
			t.Fatal("native imported metadata", meta)
		}
		var total int64
		for i, d := range []*generated.Document{root, a, b} {
			r := rows[i]
			q.storagePeer.mu.Lock()
			size := int64(len(q.storagePeer.objects[d.PdfStorageKey.String]))
			q.storagePeer.mu.Unlock()
			sum := sha256.Sum256(reports[i])
			if r.MemberPosition != int16(i) || r.MemberDocumentID != d.ID || r.Title != d.Name || r.PdfKey != d.PdfStorageKey.String || r.PdfVersionID != d.PdfStorageVersionID.String || !bytes.Equal(r.PdfSha256, d.PdfSha256) || r.PdfBytes != size || r.PdfPages != 1 || r.SourceKind != "pdf-import" || !bytes.Equal(r.PdfIntakeReport, reports[i]) || !bytes.Equal(r.PdfIntakeReportSha256, sum[:]) {
				t.Fatal("native sparse capture lost actual frozen pin/report", i, r)
			}
			total += size
		}
		if meta.PDFBytes != total {
			t.Fatal("native root-inclusive aggregate", meta.PDFBytes, total)
		}
	})
	for _, header := range []bool{false, true} {
		name := "absent"
		if header {
			name = "empty header"
		}
		t.Run(name+" captures actual main without dummy annex", func(t *testing.T) {
			root := packageImported220(t, q, "Main only "+name)
			var p *generated.DocumentPackagesV1
			if header {
				p = packageCreate223(t, q, root)
				root = packageLatest223(t, q, root.ID)
			}
			before := packageMeasurementState232(t, q)
			base := packageFullState223(t, q)
			var meta pdfadmission.HTMLSendPackageCaptureMetadataV1
			err := packageCaptureRun234(t, q, root, p, nil, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
				var e error
				meta, e = packageCaptureAppend234(t, call, work, prior)
				return e
			})
			if err != nil || packageFullState223(t, q) != base {
				t.Fatal("main-only capture", err)
			}
			if header {
				packageCaptureReadback234(t, q, root, p, meta)
				if meta.MemberCount != 1 || meta.PDFPages != 1 {
					t.Fatal(meta)
				}
			} else if meta != (pdfadmission.HTMLSendPackageCaptureMetadataV1{}) || packageMeasurementState232(t, q) != before {
				t.Fatal("absent package invented capture", meta)
			}
		})
	}
	t.Run("native append rolls back without commit acknowledgement", func(t *testing.T) {
		root := packageImported220(t, q, "Rollback main")
		a := packageImported220(t, q, "Rollback annex")
		p := packageCreate223(t, q, root, a)
		before := packageMeasurementState232(t, q)
		appended := false
		err := packageCaptureRun234(t, q, root, p, nil, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
			meta, e := packageCaptureAppend234(t, call, work, prior)
			if e != nil {
				return e
			}
			if !meta.Present {
				t.Fatal("rollback did not append")
			}
			appended = true
			return rollback
		})
		if !errors.Is(err, rollback) || !appended || packageMeasurementState232(t, q) != before {
			t.Fatal("tentative capture survived rollback", appended, err)
		}
	})
	for _, mode := range []string{"root", "relabel", "reorder", "detach", "head", "root privacy", "member privacy", "global privacy", "credential"} {
		t.Run("fresh "+mode+" change refuses measured owner", func(t *testing.T) {
			root := packageImported220(t, q, "Stale "+mode)
			a := packageImported220(t, q, "Selected "+mode)
			p := packageCreate223(t, q, root, a)
			var before string
			var dsr *generated.DataSubjectRequest
			err := packageCaptureRun234(t, q, root, p, func(_ *pdfadmission.ApplicationHTMLSendOperationV1, _ *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ authoring.Actor) error {
				switch mode {
				case "root":
					_, e := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Changed root',updated_at=GREATEST(clock_timestamp(),updated_at+interval '1 microsecond') WHERE id=$1", root.ID)
					if e != nil {
						return e
					}
				case "relabel", "reorder":
					title := a.Name
					ordinal := int16(3)
					if mode == "relabel" {
						title = "New selected terms"
					} else {
						ordinal = 11
					}
					_, e := q.f.q.UpdateDocumentAttachmentLabelsV1(q.f.ctx, generated.UpdateDocumentAttachmentLabelsV1Params{PackageID: p.ID, OrgID: q.f.org, MemberDocumentID: a.ID, ExpectedGeneration: p.DraftGeneration, Ordinal: ordinal, Title: title, Category: "Business annex"})
					if e != nil {
						return e
					}
				case "detach":
					if _, e := q.f.q.DeleteDocumentAttachmentDraftV1(q.f.ctx, generated.DeleteDocumentAttachmentDraftV1Params{PackageID: p.ID, OrgID: q.f.org, MemberDocumentID: a.ID, ExpectedGeneration: p.DraftGeneration}); e != nil {
						return e
					}
				case "head":
					// Deliberate independent SQL competitor, not the native success oracle.
					if _, e := q.f.q.AppendDocumentPackageCaptureV1(q.f.ctx, captureInput219(t, q.f, p, 1, 0)); e != nil {
						return e
					}
				case "root privacy", "member privacy", "global privacy":
					doc := pgtype.UUID{}
					if mode == "root privacy" {
						doc = pgtype.UUID{Bytes: root.ID, Valid: true}
					}
					if mode == "member privacy" {
						doc = pgtype.UUID{Bytes: a.ID, Valid: true}
					}
					var e error
					dsr, e = q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: doc, SubjectEmail: "synthetic@hash.example.test", SubjectName: "Synthetic participant", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
					if e != nil {
						return e
					}
				case "credential":
					if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE users SET session_generation=session_generation+1 WHERE id=$1", q.f.user.ID); e != nil {
						return e
					}
				}
				before = packageMeasurementState232(t, q)
				return nil
			}, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
				_, e := packageCaptureAppend234(t, call, work, prior)
				if e == nil {
					t.Fatal("changed state accepted native capture")
				}
				return e
			})
			valid := errors.Is(err, pdfadmission.ErrDocumentPackageSourceChangedV1)
			if mode == "root privacy" || mode == "member privacy" || mode == "global privacy" {
				valid = errors.Is(err, pdfadmission.ErrDocumentPackagePendingPrivacyV1)
			}
			if mode == "credential" {
				valid = errors.Is(err, auth.ErrMutationCredentialExpired) || errors.Is(err, auth.ErrMutationPermissionRevoked)
			}
			if !valid || before == "" || packageMeasurementState232(t, q) != before {
				t.Fatal("fresh refusal missing or changed state", mode, err)
			}
			if dsr != nil {
				if _, e := q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: dsr.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestDocumentPackageSendHTMLCaptureV1E2E(t *testing.T) {
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
	main := reviewPackageHTML221(t, q, createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie))
	annex := reviewPackageHTML221(t, q, createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie))
	var reply map[string]any
	packageAPIReply225(t, packageAPISubmit225(q, "REST", "add_document_attachment", main.ID, "", packageAPIArguments225(t, [2]*generated.Document{main, annex}, "REST")), "REST", http.StatusCreated, &reply)
	id, err := uuid.Parse(packageLayoutView226(t, q, main.ID).PackageID)
	if err != nil {
		t.Fatal(err)
	}
	p := packageFresh218(t, q.f, id)
	main = packageLatest223(t, q, main.ID)
	check := func(t *testing.T) {
		before := packageFullState223(t, q)
		var meta pdfadmission.HTMLSendPackageCaptureMetadataV1
		err := packageCaptureRun234(t, q, main, p, nil, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
			var e error
			meta, e = packageCaptureAppend234(t, call, work, prior)
			return e
		})
		if err != nil || packageFullState223(t, q) != before {
			t.Fatal("genuine HTML capture", err)
		}
		packageCaptureReadback234(t, q, main, p, meta, annex)
		_, rows := captureLoad219(t, q.f, p, meta.Revision)
		for i, d := range []*generated.Document{main, annex} {
			source, e := htmlsource.Commitment(d)
			if e != nil {
				t.Fatal(e)
			}
			origin, e := htmlsource.OriginCommitment(d)
			if e != nil {
				t.Fatal(e)
			}
			r := rows[i]
			kind := "html-origin"
			if d.HtmlCurrentMaterializationID.Valid {
				kind = "html-materialization"
			}
			if r.SourceKind != kind || hex.EncodeToString(r.SourceCommitment) != source || hex.EncodeToString(r.OriginCommitment) != origin || r.MaterializationID != d.HtmlCurrentMaterializationID || r.MaterializationSequence != d.HtmlCurrentMaterializationSequence || r.PdfPages != 2 {
				t.Fatal("HTML source lineage switched", i, r)
			}
		}
	}
	t.Run("reviewed initial HTML materialization", func(t *testing.T) { check(t) })
	// A separate root proves normalized revisions without reusing an already
	// captured package or treating an old capture as current Send authority.
	main = reviewPackageHTML221(t, q, createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie))
	main = packageReviseHTML232(t, q, main, "Revised captured agreement")
	packageAPIReply225(t, packageAPISubmit225(q, "REST", "add_document_attachment", main.ID, "", packageAPIArguments225(t, [2]*generated.Document{main, annex}, "REST")), "REST", http.StatusCreated, &reply)
	id, err = uuid.Parse(packageLayoutView226(t, q, main.ID).PackageID)
	if err != nil {
		t.Fatal(err)
	}
	p = packageFresh218(t, q.f, id)
	main = packageLatest223(t, q, main.ID)
	later := packageReviseHTML232(t, q, packageLatest223(t, q, annex.ID), "Later unselected annex")
	if later.HtmlCurrentMaterializationID == annex.HtmlCurrentMaterializationID {
		t.Fatal("live annex did not change")
	}
	t.Run("revised main retains selected old HTML annex", func(t *testing.T) { check(t) })
}
