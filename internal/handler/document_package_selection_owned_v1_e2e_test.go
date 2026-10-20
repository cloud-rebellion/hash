//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Actual native PostgreSQL sessions/M94 grants and isolated worker creation;
// synthetic renderer/storage peers. This is paired read/source qualification,
// not enabled attachment selection, PDF measurement admission or package Send.
func packageImported220(t *testing.T, q *ownedPublicReadFixtureV1, label string) *generated.Document {
	t.Helper()
	response := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF(label)))
	if response.Code != http.StatusCreated {
		t.Fatalf("genuine import=%d %s", response.Code, response.Body.String())
	}
	var out struct{ Document documentResponse }
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil || out.Document.ID == uuid.Nil {
		t.Fatal(err)
	}
	ownedPlainFreshDocumentV1(t, q, out.Document.ID)
	d, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: out.Document.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func packageActor220(t *testing.T, q *ownedPublicReadFixtureV1) authoring.Actor {
	t.Helper()
	raw, err := q.f.s.Cookies.Verify(q.cookie)
	if err != nil {
		t.Fatal(err)
	}
	var payload auth.SessionPayload
	if err = json.Unmarshal(raw, &payload); err != nil || payload.UserID != q.f.user.ID {
		t.Fatal(err)
	}
	return authoring.Actor{OrgID: q.f.org, UserID: q.f.user.ID, Authorize: auth.SessionTransactionAuthorization(q.f.s.Cookies, q.cookie, payload, q.f.org)}
}
func withPackageSelection220(t *testing.T, q *ownedPublicReadFixtureV1, root, source uuid.UUID, run func(context.Context, generated.DBTX, *pdfadmission.ApplicationDocumentPackageSelectionV1, authoring.Actor) error) (failure error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
	defer cancel()
	session, err := q.runtime.SessionsV1().OpenV1(ctx, q.f.org, root)
	var owner *pdfadmission.ApplicationDocumentPackageSelectionV1
	var admission *pdfadmission.ApplicationAdmissionV1
	defer func() {
		if owner != nil {
			owner.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if session != nil {
			failure = errors.Join(failure, session.CloseV1(cleanup))
		}
		if admission != nil {
			_, err := admission.ReconcileCleanupV1(cleanup)
			failure = errors.Join(failure, err)
		}
	}()
	// OpenV1 may retain a nonnil partial owner on an uncertain open error.
	// Install the same bounded close before inspecting that error.
	if err != nil {
		return err
	}
	admission, err = session.NewAdmissionV1(ctx)
	if err != nil {
		return err
	}
	actor := packageActor220(t, q)
	return session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		owner, err = session.NewDocumentPackageSelectionV1(call, source)
		if err != nil {
			return err
		}
		return run(call, db, owner, actor)
	})
}
func packageState220(t *testing.T, q *ownedPublicReadFixtureV1) string {
	t.Helper()
	var out string
	err := q.f.pool.QueryRow(q.f.ctx, "SELECT jsonb_build_object('documents',(SELECT jsonb_agg(to_jsonb(d) ORDER BY id) FROM documents d WHERE org_id=$1),'packages',(SELECT coalesce(jsonb_agg(to_jsonb(p)),'[]'::jsonb) FROM document_packages_v1 p WHERE org_id=$1),'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1))::text", q.f.org).Scan(&out)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func TestDocumentPackageNativePairedSourceOwnerV1E2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if err := malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	imported := packageImported220(t, q, "Main package terms")
	other := packageImported220(t, q, "Imported DPA")
	html := createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)
	t.Run("unreviewed HTML refuses actual paired source", func(t *testing.T) {
		before := packageState220(t, q)
		err := withPackageSelection220(t, q, imported.ID, html.ID, func(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1, actor authoring.Actor) error {
			_, _, err := readDocumentPackageSelectionV1(call, db, owner, actor, [2]uuid.UUID{imported.ID, html.ID}, [2]time.Time{imported.UpdatedAt.Time, html.UpdatedAt.Time})
			return err
		})
		if !errors.Is(err, htmlsource.ErrReviewRequired) {
			t.Fatal("unreviewed source accepted or wrong refusal", err)
		}
		if packageState220(t, q) != before {
			t.Fatal("source refusal mutated documents/package/events")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	commitment, err := htmlsource.Commitment(html)
	if err != nil {
		t.Fatal(err)
	}
	review, err := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: html.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(html.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
	if err != nil {
		t.Fatal(err)
	}
	if w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+html.ID.String()+"/html/review", string(review), q.cookie); w.Code != http.StatusOK {
		t.Fatalf("genuine review=%d %s", w.Code, w.Body.String())
	}
	html, err = q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: html.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("genuine imported and reviewed HTML both root directions", func(t *testing.T) {
		for _, pair := range [][2]*generated.Document{{imported, other}, {imported, html}, {html, imported}} {
			before := packageState220(t, q)
			err := withPackageSelection220(t, q, pair[0].ID, pair[1].ID, func(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1, actor authoring.Actor) error {
				docs, guards, err := readDocumentPackageSelectionV1(call, db, owner, actor, [2]uuid.UUID{pair[0].ID, pair[1].ID}, [2]time.Time{pair[0].UpdatedAt.Time, pair[1].UpdatedAt.Time})
				if err != nil {
					return err
				}
				for i, d := range docs {
					if d.ID != pair[i].ID || d.OrgID != q.f.org || d.PdfStorageVersionID != pair[i].PdfStorageVersionID {
						t.Fatal("logical native source switched subjects")
					}
					if err = guards[i].Recheck(call); err != nil {
						return err
					}
				}
				if err = owner.ValidateSourcesV1(call); !errors.Is(err, pdfadmission.ErrDocumentPackageSelectionV1) {
					t.Fatal("source one-shot guard failed", err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if packageState220(t, q) != before {
				t.Fatal("paired inspection mutated state")
			}
			ownedCreationAssertDrainedV1(t, q, 2)
		}
	})
	t.Run("stale independent source clock refuses without mutation", func(t *testing.T) {
		before := packageState220(t, q)
		err := withPackageSelection220(t, q, imported.ID, other.ID, func(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1, actor authoring.Actor) error {
			_, _, err := readDocumentPackageSelectionV1(call, db, owner, actor, [2]uuid.UUID{imported.ID, other.ID}, [2]time.Time{imported.UpdatedAt.Time, other.UpdatedAt.Time.Add(-time.Microsecond)})
			return err
		})
		if !errors.Is(err, errDocumentPackageChangedV1) {
			t.Fatal("stale source gate", err)
		}
		if packageState220(t, q) != before {
			t.Fatal("stale refusal changed state")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	t.Run("absent scoped source cannot read actor or body", func(t *testing.T) {
		reached := false
		before := packageState220(t, q)
		err := withPackageSelection220(t, q, imported.ID, uuid.New(), func(context.Context, generated.DBTX, *pdfadmission.ApplicationDocumentPackageSelectionV1, authoring.Actor) error {
			reached = true
			return nil
		})
		if !errors.Is(err, pgx.ErrNoRows) || reached {
			t.Fatal("absent source bypassed native header", err)
		}
		if packageState220(t, q) != before {
			t.Fatal("absent source mutated state")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	t.Run("revoked original cookie refuses before body", func(t *testing.T) {
		if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE users SET session_generation=session_generation+1 WHERE id=$1", q.f.user.ID); err != nil {
			t.Fatal(err)
		}
		before := packageState220(t, q)
		err := withPackageSelection220(t, q, imported.ID, other.ID, func(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1, actor authoring.Actor) error {
			_, _, err := readDocumentPackageSelectionV1(call, db, owner, actor, [2]uuid.UUID{imported.ID, other.ID}, [2]time.Time{imported.UpdatedAt.Time, other.UpdatedAt.Time})
			return err
		})
		if !errors.Is(err, auth.ErrMutationCredentialExpired) && !errors.Is(err, auth.ErrMutationPermissionRevoked) {
			t.Fatal("original cookie revocation ignored", err)
		}
		if packageState220(t, q) != before {
			t.Fatal("revocation changed draft/package/events")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
}
