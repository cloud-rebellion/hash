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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

func packageWrite224(t *testing.T, q *ownedPublicReadFixtureV1, pair [2]*generated.Document, expected pdfadmission.DocumentPackageDraftExpectedV1, intent pdfadmission.DocumentPackageAttachmentIntentV1) pdfadmission.DocumentPackageAttachmentResultV1 {
	t.Helper()
	var result pdfadmission.DocumentPackageAttachmentResultV1
	withPackageDraftOperation223(t, q, pair, expected, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, policy pdfadmission.DocumentPackageSourcePolicyV1, e error) {
		if e != nil {
			t.Fatal(e)
		}
		result, e = ownedaudit.SelectDocumentPackageAttachmentV1(q.f.s.Audit, op, policy, intent, audit.Entry{OrgID: q.f.org, DocumentID: &pair[0].ID, IP: "127.0.0.1", UserAgent: "Hash selection fixture"})
		if e != nil {
			t.Fatal("actual fixed selection", e)
		}
		if !op.CommitDispatchedV1() {
			t.Fatal("no native COMMIT dispatched")
		}
		state := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		if _, e = ownedaudit.SelectDocumentPackageAttachmentV1(q.f.s.Audit, op, policy, intent, audit.Entry{OrgID: q.f.org, DocumentID: &pair[0].ID}); e == nil {
			t.Fatal("one-shot writer replayed")
		}
		if state != packageFullState223(t, q) || requests != q.storagePeer.requests.Load() {
			t.Fatal("replayed provider or mutation")
		}
	})
	root := packageLatest223(t, q, pair[0].ID)
	candidate := packageLatest223(t, q, pair[1].ID)
	p := packageFresh218(t, q.f, result.PackageID)
	if p.DocumentID != root.ID || p.OrgID != q.f.org || p.DraftGeneration != result.Generation ||
		!root.UpdatedAt.Time.Equal(result.UpdatedAt) || !root.UpdatedAt.Time.After(pair[0].UpdatedAt.Time) ||
		!candidate.UpdatedAt.Time.Equal(pair[1].UpdatedAt.Time) || result.MemberDocumentID != candidate.ID || result.Ordinal != intent.Ordinal {
		t.Fatal("actual post-trigger clock/identity differs", result, p)
	}
	rows, e := q.f.q.ListDocumentAttachmentDraftsV1(q.f.ctx, generated.ListDocumentAttachmentDraftsV1Params{PackageID: p.ID, OrgID: q.f.org, ExpectedGeneration: p.DraftGeneration})
	if e != nil {
		t.Fatal(e)
	}
	var selected *generated.DocumentAttachmentDraftsV1
	for _, r := range rows {
		if r.MemberDocumentID == candidate.ID {
			selected = r
		}
	}
	if selected == nil || selected.PdfKey != candidate.PdfStorageKey.String || selected.PdfVersionID != candidate.PdfStorageVersionID.String ||
		!bytes.Equal(selected.PdfSha256, candidate.PdfSha256) || !bytes.Equal(selected.PdfIntakeReport, candidate.MetadataRedactionReport) ||
		selected.Title != intent.Title || selected.Category != intent.Category {
		t.Fatal("selected exact pins/proof/labels differ", selected)
	}
	event, e := q.f.q.GetEventByID(q.f.ctx, result.EventID)
	if e != nil || event.Kind != "document.attachment_added" || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != q.f.user.ID ||
		!event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != root.ID || len(event.PayloadHashed) == 0 {
		t.Fatal("dedicated audit event", event, e)
	}
	var payload map[string]any
	if e = json.Unmarshal(event.PayloadHashed, &payload); e != nil || payload["schema"] != "hash-attachment-selection-v1" ||
		payload["member_document_id"] != candidate.ID.String() || payload["pdf_sha256"] != hex.EncodeToString(candidate.PdfSha256) {
		t.Fatal("fixed audit payload", payload, e)
	}
	all, e := q.f.q.ListChainedEventsPageForOrg(q.f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: q.f.org, PageLimit: 1000})
	if e != nil || len(all) >= 1000 {
		t.Fatal(e)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(all)
	if verified := verifier.Result(); !verified.OK {
		t.Fatal("actual org chain failed", verified)
	}
	return result
}

func TestDocumentPackageOwnedSelectionWriteV1E2E(t *testing.T) {
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
	var published atomic.Int64
	q.f.s.Audit.Subscribe(func(_ context.Context, _ uuid.UUID, e audit.Entry) {
		if e.Kind == "document.attachment_added" {
			published.Add(1)
		}
	})
	intent := pdfadmission.DocumentPackageAttachmentIntentV1{Ordinal: 16, Title: "Additional terms", Category: "Custom business document"}
	pair := func() [2]*generated.Document {
		return [2]*generated.Document{packageImported220(t, q, "Main agreement"), packageImported220(t, q, "Candidate annex")}
	}
	t.Run("first member commits generation two exact proof and chained audit", func(t *testing.T) {
		before := published.Load()
		result := packageWrite224(t, q, pair(), pdfadmission.DocumentPackageDraftExpectedV1{}, intent)
		if result.Generation != 2 || published.Load() != before+1 {
			t.Fatal("header/member generation or joined publication", result, published.Load())
		}
	})
	t.Run("sparse existing members stay frozen after source deletion", func(t *testing.T) {
		docs := pair()
		old := packageImported220(t, q, "Existing DPA")
		other := packageImported220(t, q, "Existing SLA")
		p := packageCreate223(t, q, docs[0], old, other)
		oldRows, e := q.f.q.ListDocumentAttachmentDraftsV1(q.f.ctx, generated.ListDocumentAttachmentDraftsV1Params{PackageID: p.ID, OrgID: q.f.org, ExpectedGeneration: p.DraftGeneration})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Later live source',metadata_redaction_report='{\"later\":true}',deleted_at=clock_timestamp() WHERE id=$1 AND org_id=$2", old.ID, q.f.org); e != nil {
			t.Fatal(e)
		}
		docs[0] = packageLatest223(t, q, docs[0].ID)
		result := packageWrite224(t, q, docs, pdfadmission.DocumentPackageDraftExpectedV1{PackageID: p.ID, Generation: p.DraftGeneration}, intent)
		if result.PackageID != p.ID || result.Generation != p.DraftGeneration+1 {
			t.Fatal(result)
		}
		rows, e := q.f.q.ListDocumentAttachmentDraftsV1(q.f.ctx, generated.ListDocumentAttachmentDraftsV1Params{PackageID: p.ID, OrgID: q.f.org, ExpectedGeneration: result.Generation})
		if e != nil || len(rows) != 3 {
			t.Fatal(rows, e)
		}
		for i := 0; i < 2; i++ {
			before, _ := json.Marshal(oldRows[i])
			after, _ := json.Marshal(rows[i])
			if !bytes.Equal(before, after) {
				t.Fatal("old immutable selected row changed")
			}
		}
	})
	t.Run("reviewed HTML stores validated source commitments", func(t *testing.T) {
		docs := pair()
		docs[1] = reviewPackageHTML221(t, q, createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie))
		result := packageWrite224(t, q, docs, pdfadmission.DocumentPackageDraftExpectedV1{}, intent)
		rows, e := q.f.q.ListDocumentAttachmentDraftsV1(q.f.ctx, generated.ListDocumentAttachmentDraftsV1Params{PackageID: result.PackageID, OrgID: q.f.org, ExpectedGeneration: result.Generation})
		want, e2 := htmlsource.Commitment(docs[1])
		if e != nil || e2 != nil || len(rows) != 1 || hex.EncodeToString(rows[0].SourceCommitment) != want ||
			rows[0].MaterializationID != docs[1].HtmlCurrentMaterializationID || rows[0].MaterializationSequence != docs[1].HtmlCurrentMaterializationSequence {
			t.Fatal("actual HTML source pins", rows, e, e2)
		}
	})
	for _, bad := range []struct {
		name string
		in   pdfadmission.DocumentPackageAttachmentIntentV1
	}{
		{"blank title", pdfadmission.DocumentPackageAttachmentIntentV1{Ordinal: 1}},
		{"long category", pdfadmission.DocumentPackageAttachmentIntentV1{Ordinal: 1, Title: "DPA", Category: strings.Repeat("x", 129)}},
		{"control label", pdfadmission.DocumentPackageAttachmentIntentV1{Ordinal: 1, Title: "DPA\n"}},
		{"invalid ordinal", pdfadmission.DocumentPackageAttachmentIntentV1{Ordinal: 17, Title: "DPA"}},
	} {
		t.Run(bad.name+" refuses before provider", func(t *testing.T) {
			docs := pair()
			withPackageDraftOperation223(t, q, docs, pdfadmission.DocumentPackageDraftExpectedV1{}, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, policy pdfadmission.DocumentPackageSourcePolicyV1, e error) {
				if e != nil {
					t.Fatal(e)
				}
				before := packageFullState223(t, q)
				requests := q.storagePeer.requests.Load()
				_, e = ownedaudit.SelectDocumentPackageAttachmentV1(q.f.s.Audit, op, policy, bad.in, audit.Entry{OrgID: q.f.org, DocumentID: &docs[0].ID})
				if !errors.Is(e, pdfadmission.ErrDocumentPackageWriteV1) || op.CommitDispatchedV1() ||
					before != packageFullState223(t, q) || requests != q.storagePeer.requests.Load() {
					t.Fatal("early refusal mutated or fetched", e)
				}
			})
		})
	}
	t.Run("occupied sparse ordinal refuses before provider", func(t *testing.T) {
		docs := pair()
		old := packageImported220(t, q, "Existing NDA")
		p := packageCreate223(t, q, docs[0], old)
		docs[0] = packageLatest223(t, q, docs[0].ID)
		withPackageDraftOperation223(t, q, docs, pdfadmission.DocumentPackageDraftExpectedV1{PackageID: p.ID, Generation: p.DraftGeneration}, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, policy pdfadmission.DocumentPackageSourcePolicyV1, e error) {
			if e != nil {
				t.Fatal(e)
			}
			before := packageFullState223(t, q)
			requests := q.storagePeer.requests.Load()
			bad := intent
			bad.Ordinal = 3
			_, e = ownedaudit.SelectDocumentPackageAttachmentV1(q.f.s.Audit, op, policy, bad, audit.Entry{OrgID: q.f.org, DocumentID: &docs[0].ID})
			if !errors.Is(e, pdfadmission.ErrDocumentPackageWriteV1) || before != packageFullState223(t, q) || requests != q.storagePeer.requests.Load() {
				t.Fatal(e)
			}
		})
	})
	for _, mode := range []string{"missing append", "wrong audit scope", "post-audit credential refusal", "stale candidate"} {
		t.Run(mode+" rolls back entire selection", func(t *testing.T) {
			docs := pair()
			withPackageDraftOperation223(t, q, docs, pdfadmission.DocumentPackageDraftExpectedV1{}, false, func(op *pdfadmission.ApplicationDocumentPackageOperationV1, policy pdfadmission.DocumentPackageSourcePolicyV1, e error) {
				if e != nil {
					t.Fatal(e)
				}
				if mode == "stale candidate" {
					if _, e = q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Changed after initial read',updated_at=clock_timestamp() WHERE id=$1 AND org_id=$2", docs[1].ID, q.f.org); e != nil {
						t.Fatal(e)
					}
				}
				before := packageFullState223(t, q)
				beforePublished := published.Load()
				checkedAfterAudit := false
				currentPolicy := policy
				sentinel := errors.New("original credential revoked after audit")
				if mode == "post-audit credential refusal" {
					currentPolicy = func(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1) (func(context.Context) error, error) {
						guard, e := policy(call, db, owner)
						if e != nil {
							return nil, e
						}
						return func(c context.Context) error {
							if e := guard(c); e != nil {
								return e
							}
							var count int
							if e := db.QueryRow(c, "SELECT count(*) FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.attachment_added'", docs[0].ID, q.f.org).Scan(&count); e != nil {
								return e
							}
							if count != 1 {
								t.Error("credential check was not after real audit append", count)
							}
							checkedAfterAudit = count == 1
							return sentinel
						}, nil
					}
				}
				switch mode {
				case "missing append":
					_, e = op.SelectAttachmentV1(currentPolicy, intent, "", "", func(context.Context, *pdfadmission.ApplicationHTMLAuditEventConsumerV1) error { return nil })
				default:
					target := docs[0].ID
					if mode == "wrong audit scope" {
						target = uuid.New()
					}
					_, e = ownedaudit.SelectDocumentPackageAttachmentV1(q.f.s.Audit, op, currentPolicy, intent, audit.Entry{OrgID: q.f.org, DocumentID: &target})
				}
				if e == nil || op.CommitDispatchedV1() || before != packageFullState223(t, q) || published.Load() != beforePublished {
					t.Fatal("failed writer partially committed/published", e)
				}
				if mode == "post-audit credential refusal" && (!errors.Is(e, sentinel) || !checkedAfterAudit) {
					t.Fatal("original final credential guard absent", e)
				}
			})
		})
	}
}
