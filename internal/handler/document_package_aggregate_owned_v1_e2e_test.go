//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Small structurally complete page objects for strict parser limits only.
// This is not canvas, workload, RSS or capacity qualification.
func packagePagesPDF223(count int) []byte {
	var kids strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&kids, "%d 0 R ", i+3)
	}
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), count)}
	for i := 0; i < count; i++ {
		objects = append(objects, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", count+4, count+3))
	}
	stream := "BT /F1 10 Tf 30 30 Td (Bounded page proof) Tj ET\n"
	objects = append(objects, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream), "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}
func packageImportPDF223(t *testing.T, q *ownedPublicReadFixtureV1, body []byte) *generated.Document {
	t.Helper()
	response := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, body))
	if response.Code != http.StatusCreated {
		t.Fatalf("actual bounded PDF import=%d %s", response.Code, response.Body.String())
	}
	var out struct{ Document documentResponse }
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil || out.Document.ID == uuid.Nil {
		t.Fatal(err)
	}
	ownedPlainFreshDocumentV1(t, q, out.Document.ID)
	return packageLatest223(t, q, out.Document.ID)
}

func packageLatest223(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) *generated.Document {
	t.Helper()
	d, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: id, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func packageCreate223(t *testing.T, q *ownedPublicReadFixtureV1, root *generated.Document, annexes ...*generated.Document) *generated.DocumentPackagesV1 {
	t.Helper()
	p, err := q.f.q.CreateDocumentPackageV1(q.f.ctx, generated.CreateDocumentPackageV1Params{PackageID: uuid.New(), DocumentID: root.ID, OrgID: q.f.org, CreatedBy: q.f.user.ID, ExpectedUpdatedAt: root.UpdatedAt})
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range annexes {
		q.storagePeer.mu.Lock()
		size := int64(len(q.storagePeer.objects[d.PdfStorageKey.String]))
		q.storagePeer.mu.Unlock()
		if size < 1 {
			t.Fatal("actual imported object absent")
		}
		_, err = q.f.q.InsertDocumentAttachmentDraftV1(q.f.ctx, generated.InsertDocumentAttachmentDraftV1Params{PackageID: p.ID, OrgID: q.f.org, ExpectedGeneration: p.DraftGeneration, MemberDocumentID: d.ID, Ordinal: int16(3 + 6*i), Title: d.Name, Category: "Business annex", PdfKey: d.PdfStorageKey.String, PdfVersionID: d.PdfStorageVersionID.String, PdfSha256: d.PdfSha256, PdfBytes: size, PdfPages: 1, SourceKind: "pdf-import"})
		if err != nil {
			t.Fatal(err)
		}
		p = packageFresh218(t, q.f, p.ID)
	}
	return p
}
func packageFullState223(t *testing.T, q *ownedPublicReadFixtureV1) string {
	t.Helper()
	var state string
	err := q.f.pool.QueryRow(q.f.ctx, "SELECT jsonb_build_object('documents',(SELECT jsonb_agg(to_jsonb(d) ORDER BY id) FROM documents d WHERE org_id=$1),'packages',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM document_packages_v1 p WHERE org_id=$1),'members',(SELECT jsonb_agg(to_jsonb(a) ORDER BY package_id,ordinal) FROM document_attachment_drafts_v1 a WHERE org_id=$1),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM events e WHERE org_id=$1),'dsr',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM data_subject_requests r WHERE org_id=$1))::text", q.f.org).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func withPackageDraftOperation223(t *testing.T, q *ownedPublicReadFixtureV1, pair [2]*generated.Document, expected pdfadmission.DocumentPackageDraftExpectedV1, closeInitial bool, run func(*pdfadmission.ApplicationDocumentPackageOperationV1, pdfadmission.DocumentPackageSourcePolicyV1, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(q.f.ctx, 30*time.Second)
	defer cancel()
	actor := packageActor220(t, q)
	var original *pdfadmission.ApplicationDocumentPackageSelectionV1
	policy := func(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1) (func(context.Context) error, error) {
		_, guards, err := readDocumentPackageDraftSelectionV1(call, db, owner, actor, [2]uuid.UUID{pair[0].ID, pair[1].ID}, [2]time.Time{pair[0].UpdatedAt.Time, pair[1].UpdatedAt.Time}, expected)
		if err != nil {
			return nil, err
		}
		if original == nil {
			original = owner
		}
		return func(c context.Context) error {
			for _, g := range guards {
				if err := g.Recheck(c); err != nil {
					return err
				}
			}
			return nil
		}, nil
	}
	op, err := q.runtime.SessionsV1().NewDocumentPackageOperationV1(ctx, q.f.org, pair[0].ID, pair[1].ID, actor.UserID, q.f.s.Storage)
	defer func() {
		if op != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			if err := op.CloseV1(cleanup); err != nil {
				t.Error("actual package owner cleanup", err)
			}
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	}()
	if err != nil {
		t.Fatal(err)
	}
	err = op.ReadSourcesV1(policy)
	if err == nil && closeInitial {
		before, e := q.runtime.SnapshotV1(q.f.org)
		if e != nil {
			t.Fatal(e)
		}
		original.CloseConsumerV1()
		after, e := q.runtime.SnapshotV1(q.f.org)
		if e != nil || before.Organisation.ParentBytes != after.Organisation.ParentBytes || before.Organisation.DBStagingBytes != after.Organisation.DBStagingBytes {
			t.Fatal("selection shell close refunded live package data", before, after, e)
		}
	}
	run(op, policy, err)
}

// Actual native PG/auth/isolated worker; synthetic S3/renderer. Test fixture
// inserts establish selected rows, not a qualified fixed application writer.
func TestDocumentPackageOwnedAggregateMeasurementV1E2E(t *testing.T) {
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
	root := packageImported220(t, q, "Main ordered package")
	candidate := packageImported220(t, q, "New NDA")
	old := packageImported220(t, q, "Frozen DPA")
	other := packageImported220(t, q, "Frozen SLA")
	p := packageCreate223(t, q, root, old, other)
	expected := pdfadmission.DocumentPackageDraftExpectedV1{PackageID: p.ID, Generation: p.DraftGeneration}
	pair := func() [2]*generated.Document {
		return [2]*generated.Document{packageLatest223(t, q, root.ID), packageLatest223(t, q, candidate.ID)}
	}
	t.Run("ordered frozen annexes survive live source report edits and shell close", func(t *testing.T) {
		if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Changed live source',metadata_redaction_report='{\"changed\":true}',deleted_at=clock_timestamp() WHERE id=$1 AND org_id=$2", old.ID, q.f.org); err != nil {
			t.Fatal(err)
		}
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		withPackageDraftOperation223(t, q, pair(), expected, true, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, policy pdfadmission.DocumentPackageSourcePolicyV1, err error) {
			if err != nil {
				t.Fatal("native ordered read", err)
			}
			if err = op.MeasurePDFsV1(); err != nil {
				t.Fatal("all frozen exact PDFs", err)
			}
			got, count, err := op.PackageMeasurementsV1()
			if err != nil || count != 4 || got[0].DocumentID != root.ID || got[1].DocumentID != candidate.ID || got[2].DocumentID != old.ID || got[3].DocumentID != other.ID {
				t.Fatal("ordered immutable measurement differs", got, count, err)
			}
			if q.storagePeer.requests.Load() != requests+8 {
				t.Fatal("not exactly four HEAD/four GET")
			}
			if err = op.RevalidateSourcesV1(policy); err != nil {
				t.Fatal("fresh complete package boundary", err)
			}
			if !op.CommitDispatchedV1() || packageFullState223(t, q) != before {
				t.Fatal("read-only final stage changed package or did not commit")
			}
		})
	})
	t.Run("stale observed package generation makes no provider call", func(t *testing.T) {
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		bad := expected
		bad.Generation--
		withPackageDraftOperation223(t, q, pair(), bad, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, _ pdfadmission.DocumentPackageSourcePolicyV1, err error) {
			if !errors.Is(err, pdfadmission.ErrDocumentPackageSourceChangedV1) || op.CommitDispatchedV1() || q.storagePeer.requests.Load() != requests || packageFullState223(t, q) != before {
				t.Fatal("stale package observation accepted", err)
			}
		})
	})
	t.Run("already selected candidate makes no provider call", func(t *testing.T) {
		requests := q.storagePeer.requests.Load()
		withPackageDraftOperation223(t, q, [2]*generated.Document{packageLatest223(t, q, root.ID), other}, expected, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, _ pdfadmission.DocumentPackageSourcePolicyV1, err error) {
			if !errors.Is(err, pdfadmission.ErrDocumentPackageDraftV1) || op.CommitDispatchedV1() || q.storagePeer.requests.Load() != requests {
				t.Fatal("duplicate candidate accepted", err)
			}
		})
	})
	t.Run("later pending old-member request refuses final commit", func(t *testing.T) {
		withPackageDraftOperation223(t, q, pair(), expected, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, policy pdfadmission.DocumentPackageSourcePolicyV1, err error) {
			if err != nil {
				t.Fatal(err)
			}
			if err = op.MeasurePDFsV1(); err != nil {
				t.Fatal(err)
			}
			request, err := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: old.ID, Valid: true}, SubjectEmail: "synthetic@hash.example.test", SubjectName: "Synthetic participant", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
			if err != nil {
				t.Fatal("privacy request after actual initial transaction retirement", err)
			}
			before := packageFullState223(t, q)
			if err = op.RevalidateSourcesV1(policy); !errors.Is(err, authoring.ErrPendingPrivacyReview) || op.CommitDispatchedV1() || packageFullState223(t, q) != before {
				t.Fatal("pending immutable member slipped into commit", err)
			}
			if _, err = q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: request.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("per-member privacy contention refuses without old source lock", func(t *testing.T) {
		tx, err := q.f.pool.Begin(q.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(q.f.ctx)
		if _, err = tx.Exec(q.f.ctx, "SELECT pg_advisory_xact_lock(hashtextextended('hash:document-package:privacy:'||$1::uuid::text||':'||$2::uuid::text,0))", q.f.org, other.ID); err != nil {
			t.Fatal(err)
		}
		requests := q.storagePeer.requests.Load()
		withPackageDraftOperation223(t, q, pair(), expected, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, _ pdfadmission.DocumentPackageSourcePolicyV1, err error) {
			if !errors.Is(err, authoring.ErrPrivacyReviewChanging) || op.CommitDispatchedV1() || q.storagePeer.requests.Load() != requests {
				t.Fatal("contended old member accepted", err)
			}
		})
	})
	t.Run("HEAD aggregate overflow precedes every PDF allocation GET", func(t *testing.T) {
		base := q.f.s.Storage
		var heads, gets atomic.Int32
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, "/hash-import-fixture/org/") {
				heads.Add(1)
				rr := httptest.NewRecorder()
				q.storagePeer.ServeHTTP(rr, r)
				for k, values := range rr.Header() {
					for _, v := range values {
						w.Header().Add(k, v)
					}
				}
				if strings.HasSuffix(r.URL.Path, root.PdfStorageKey.String) || strings.HasSuffix(r.URL.Path, candidate.PdfStorageKey.String) {
					w.Header().Set("Content-Length", "26214400")
				}
				w.WriteHeader(rr.Code)
				return
			}
			if r.Method == http.MethodGet {
				gets.Add(1)
			}
			q.storagePeer.ServeHTTP(w, r)
		}))
		defer peer.Close()
		var err error
		q.f.s.Storage, err = storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(peer.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-package", SecretKey: "synthetic-package-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { q.f.s.Storage = base }()
		withPackageDraftOperation223(t, q, pair(), expected, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, _ pdfadmission.DocumentPackageSourcePolicyV1, err error) {
			if err != nil {
				t.Fatal(err)
			}
			if err = op.MeasurePDFsV1(); !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) || heads.Load() != 3 || gets.Load() != 0 || op.CommitDispatchedV1() {
				t.Fatal("aggregate HEAD overflow allocated/read PDF", heads.Load(), gets.Load(), err)
			}
		})
	})
	t.Run("native member fence refuses linked create reopen and move without locking old source", func(t *testing.T) {
		outside := packageImported220(t, q, "Unselected privacy scope")
		makeRequest := func(id uuid.UUID) *generated.DataSubjectRequest {
			t.Helper()
			r, err := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: id, Valid: true}, SubjectEmail: "synthetic@hash.example.test", SubjectName: "Synthetic participant", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		closed := makeRequest(other.ID)
		if _, err := q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: closed.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); err != nil {
			t.Fatal(err)
		}
		moving := makeRequest(outside.ID)
		currentPair := pair()
		err := withPackageSelection220(t, q, root.ID, candidate.ID, func(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1, actor authoring.Actor) error {
			if _, _, err := readDocumentPackageDraftSelectionV1(call, db, owner, actor, [2]uuid.UUID{root.ID, candidate.ID}, [2]time.Time{currentPair[0].UpdatedAt.Time, currentPair[1].UpdatedAt.Time}, expected); err != nil {
				return err
			}
			// Independent live source edit must not block on a source document lock.
			if tag, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name=name||' after selection' WHERE id=$1 AND org_id=$2", other.ID, q.f.org); err != nil || tag.RowsAffected() != 1 {
				t.Fatal("immutable member still requires live source lock", err)
			}
			before := packageFullState223(t, q)
			_, err := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: other.ID, Valid: true}, SubjectEmail: "synthetic@hash.example.test", SubjectName: "Synthetic participant", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")})
			packageExpectPG218(t, err, "55P03")
			_, err = q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: closed.ID, OrgID: q.f.org, ExpectedStatus: "withdrawn", Status: "open"})
			packageExpectPG218(t, err, "55P03")
			_, err = q.f.pool.Exec(q.f.ctx, "UPDATE data_subject_requests SET document_id=$1 WHERE id=$2 AND org_id=$3", other.ID, moving.ID, q.f.org)
			packageExpectPG218(t, err, "55P03")
			body, err := json.Marshal(senderDSRInput{Kind: "access", SubjectEmail: "synthetic@hash.example.test", DocumentID: other.ID.String()})
			if err != nil {
				t.Fatal(err)
			}
			response := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/dsr", string(body), q.cookie)
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "retry the request") {
				t.Fatal("linked contention not mapped to actionable409", response.Code, response.Body.String())
			}
			if packageFullState223(t, q) != before {
				t.Fatal("refused privacy writes left partial rows/events")
			}
			return nil
		})
		if err != nil {
			t.Fatal("actual native member fence", err)
		}
		ownedCreationAssertDrainedV1(t, q, 2)
		// The actual native transaction has retired, so the same new obligation may
		// now be recorded; a later package stage must observe it.
		reopened, err := q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: closed.ID, OrgID: q.f.org, ExpectedStatus: "withdrawn", Status: "open"})
		if err != nil || reopened.Status != "open" {
			t.Fatal("fence survived real retirement", err)
		}
	})

	for _, annexPages := range []int32{498, 499} {
		t.Run(fmt.Sprintf("actual_%d_total_pages", annexPages+2), func(t *testing.T) {
			main := packageImported220(t, q, fmt.Sprintf("Aggregate page boundary %d", annexPages))
			annex := packageImportPDF223(t, q, packagePagesPDF223(int(annexPages)))
			p := packageHeader218(t, q.f, main)
			q.storagePeer.mu.Lock()
			size := int64(len(q.storagePeer.objects[annex.PdfStorageKey.String]))
			q.storagePeer.mu.Unlock()
			_, err := q.f.q.InsertDocumentAttachmentDraftV1(q.f.ctx, generated.InsertDocumentAttachmentDraftV1Params{PackageID: p.ID, OrgID: q.f.org, ExpectedGeneration: p.DraftGeneration, MemberDocumentID: annex.ID, Ordinal: 16, Title: "Actual multi-page annex", PdfKey: annex.PdfStorageKey.String, PdfVersionID: annex.PdfStorageVersionID.String, PdfSha256: annex.PdfSha256, PdfBytes: size, PdfPages: annexPages, SourceKind: "pdf-import"})
			if err != nil {
				t.Fatal(err)
			}
			p = packageFresh218(t, q.f, p.ID)
			expected := pdfadmission.DocumentPackageDraftExpectedV1{PackageID: p.ID, Generation: p.DraftGeneration}
			before := packageFullState223(t, q)
			withPackageDraftOperation223(t, q, [2]*generated.Document{packageLatest223(t, q, main.ID), packageLatest223(t, q, candidate.ID)}, expected, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, policy pdfadmission.DocumentPackageSourcePolicyV1, err error) {
				if err != nil {
					t.Fatal(err)
				}
				err = op.MeasurePDFsV1()
				if annexPages == 498 {
					if err != nil {
						t.Fatal("exact actual500-page bound refused", err)
					}
					got, count, e := op.PackageMeasurementsV1()
					if e != nil || count != 3 || got[2].Pages != 498 {
						t.Fatal("actual page total not measured", got, count, e)
					}
					if err = op.RevalidateSourcesV1(policy); err != nil {
						t.Fatal(err)
					}
				} else {
					if !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) {
						t.Fatal("actual501-page aggregate accepted", err)
					}
					if err = op.RevalidateSourcesV1(policy); !errors.Is(err, pdfadmission.ErrDocumentPackageOperationV1) || op.CommitDispatchedV1() {
						t.Fatal("overflow reached final SQL", err)
					}
				}
				if packageFullState223(t, q) != before {
					t.Fatal("page bound changed package state")
				}
			})
		})
	}

}
