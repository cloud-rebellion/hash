//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/jackc/pgx/v5/pgtype"
)

type participantReportDirectMailerSpyV1 struct{ calls atomic.Int64 }

func (s *participantReportDirectMailerSpyV1) Send(context.Context, dispatch.Message) error {
	s.calls.Add(1)
	return nil
}

// Genuine ordinary approved-HTML two-party completion proves the report is
// mandatory even without annexes, an optional export entitlement or a mailer.
// The fixture's actual native PostgreSQL/worker owners are used; its external
// renderer/S3 protocol peers remain synthetic and are not provider acceptance.
func TestParticipantReportMandatoryWithoutOptionalExportV1E2E(t *testing.T) {
	for _, mode := range []string{"no-mailer", "direct-test-mailer"} {
		t.Run(mode, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			f := q.f
			f.s.Sign.Storage = f.s.Storage
			doc, parties := q.createSentV1(t)
			f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: "free", ReviewRef: "synthetic mandatory report without optional export"}})
			if err := f.s.Billing.ValidateOperatorPlans(f.ctx); err != nil {
				t.Fatal(err)
			}
			allowed, err := f.s.Billing.HasFeature(f.ctx, f.org, "evidence_bundle")
			if err != nil || allowed {
				t.Fatal("fixture did not genuinely lack optional evidence export", err)
			}
			bootstrap := q.requestV1(parties[0].Token, "")
			var page signerContextResponse
			if bootstrap.Code != http.StatusOK || json.Unmarshal(bootstrap.Body.Bytes(), &page) != nil {
				t.Fatal("original signer bootstrap unavailable")
			}
			sharedComment := participantReportSharedCommentV1(t, q, doc, parties[0].Token, page.Privacy.NoticeDigest)
			spy := &participantReportDirectMailerSpyV1{}
			// Only completion delivery is under test here. The preceding genuine
			// comment used its normal configured transactional notification owner.
			f.s.Sign.Mailer = nil
			if mode == "direct-test-mailer" {
				f.s.Sign.Mailer = spy
			}
			var before int64
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*)::bigint FROM email_deliveries").Scan(&before); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- isolated exact outbox witness
			var terminal *sign.Result
			for index, party := range parties {
				rc := q.lookupV1(t, party.Token)
				notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
				if err != nil {
					t.Fatal(err)
				}
				a13, err := signerArticle13NoticeEvidence(rc, notice)
				if err != nil {
					t.Fatal(err)
				}
				result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: a13, IP: "127.0.0.1", UserAgent: "Synthetic mandatory participant report"})
				if closeErr := rc.CloseReadV1(); closeErr != nil {
					t.Fatal(closeErr)
				}
				if err != nil || result == nil || result.Completed != (index == len(parties)-1) {
					t.Fatal("ordinary mandatory report completion failed", err)
				}
				terminal = result
			}
			current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
			if err != nil || current.Status != "completed" {
				t.Fatal("actual completion absent", err)
			}
			payload, err := readDocumentArtifact(f.ctx, f.s.Storage, current, current.AuditPayloadKey.String, current.AuditPayloadSha256, current.AuditPayloadVersionID)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := readDocumentArtifact(f.ctx, f.s.Storage, current, current.AuditSignatureKey.String, current.AuditSignatureSha256, current.AuditSignatureVersionID)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := evidence.ParseCertificateCommitments(payload)
			if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || claims.ParticipantReportRows < 3 || !strings.Contains(string(payload), sharedComment) || !strings.Contains(string(payload), "body-and-actor-associated") || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
				t.Fatal("actual detached report evidence failed", err)
			}
			report := assertFreshParticipantReport406(t, f, current, payload)
			if len(report.Comments) != 1 || report.Comments[0].Body != sharedComment || report.Comments[0].Side != "signer" || report.Comments[0].ActorID != parties[0].RecipientID.String() || report.Comments[0].Evidence != "body-and-actor-associated" || report.Comments[0].EventID == "" || report.Comments[0].EventRowSHA256 == "" {
				t.Fatal("fresh report lost original shared comment/body/recipient association")
			}
			var reportCount, deliveryCount, after int64
			var exact bool
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*)::bigint,coalesce(bool_and(encode(report_sha256,'hex')=$3 AND final_pdf_sha256=$4 AND audit_payload_sha256=$5),false) FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, f.org, claims.ParticipantReportSHA256, current.FinalPdfSha, current.AuditPayloadSha256).Scan(&reportCount, &exact); err != nil || reportCount != 1 || !exact {
				t.Fatal("exact mandatory report receipt absent", err)
			} //nolint:rawsql -- real retained receipt witness
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*)::bigint FROM document_participant_report_deliveries_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, f.org).Scan(&deliveryCount); err != nil || deliveryCount != int64(len(parties)+1) {
				t.Fatal("contract/report references not atomically queued", deliveryCount, err)
			} //nolint:rawsql -- exact all participant/sender delivery witness
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*)::bigint FROM email_deliveries").Scan(&after); err != nil || after-before != int64(len(parties)+1) || spy.calls.Load() != 0 {
				t.Fatal("completion queue missing or direct delivery duplicated", before, after, spy.calls.Load(), err)
			} //nolint:rawsql -- exact sole delivery ownership witness
			if terminal == nil || terminal.AuditCertURL == "" {
				t.Fatal("recipient report delivery URL missing")
			}
			w := httptest.NewRecorder()
			f.s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, terminal.AuditCertURL, nil).WithContext(f.ctx))
			if w.Code != http.StatusOK || !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) {
				t.Fatalf("mandatory report download required optional plan or failed: %d %s", w.Code, w.Body.String())
			}
			ownedRevisionConsumedV1(t, q)
		})
	}
}

// These are the actual deferred guard's SQL credential boundary cases, not
// a supported CC/viewer Send or completion journey. Current production Send
// rejects both roles, including retained legacy rows; no recipient feature or
// fabricated completed-document evidence is introduced for this regression.
// Genuine two-party completion and exact signer delivery references are tested
// above. The SQL helper consumes the native owner's actually issued credential
// effect; it does not independently derive the required signature role set.
func TestParticipantReportCompletionIssuedCredentialPredicateV1E2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	cases := []struct {
		name, role, status string
		requiresSignature  bool
		expiryDelta        *int64
		want               bool
	}{
		{"signed-required-fresh", "buyer", "signed", true, participantReportSecondsV1(60), true},
		{"second-signed-required-fresh", "seller", "signed", true, participantReportSecondsV1(60), true},
		{"accepted-fresh", "buyer", "accepted", false, participantReportSecondsV1(60), true},
		{"signed-unrequired-not-reissued", "observer", "signed", true, participantReportSecondsV1(0), false},
		{"cc-fresh-not-entitled", "cc", "signed", true, participantReportSecondsV1(60), false},
		{"cc-accepted-fresh-not-entitled", "cc", "accepted", false, participantReportSecondsV1(60), false},
		{"viewer-no-response", "viewer", "pending", true, participantReportSecondsV1(60), false},
		{"signed-null-expiry", "buyer", "signed", true, nil, false},
		{"signed-expired", "buyer", "signed", true, participantReportSecondsV1(-1), false},
		{"signed-exact-invalidation-boundary", "buyer", "signed", true, participantReportSecondsV1(0), false},
		{"accepted-expired", "buyer", "accepted", false, participantReportSecondsV1(-1), false},
		{"accepted-null-expiry", "buyer", "accepted", false, nil, false},
		{"signature-mode-accepted", "buyer", "accepted", true, participantReportSecondsV1(60), false},
		{"acknowledgement-mode-signed", "buyer", "signed", false, participantReportSecondsV1(60), false},
		{"invitation-alone", "buyer", "sent", true, participantReportSecondsV1(60), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got bool
			err := q.f.pool.QueryRow(q.f.ctx, `SELECT hash_report_delivery_for_issued_credential_v1($1::boolean,$2::text,$3::text,CASE WHEN $4::bigint IS NULL THEN NULL ELSE transaction_timestamp()+$4::bigint*interval '1 second' END)`, tc.requiresSignature, tc.role, tc.status, tc.expiryDelta).Scan(&got)
			if err != nil || got != tc.want {
				t.Fatalf("actual completion delivery predicate=%v want=%v err=%v", got, tc.want, err)
			} //nolint:rawsql -- executes the exact helper used by the deferred native completion guard
		})
	}
	// This fixture never opens a signer or catalog operation, so only its
	// original tenant observer exists. Assert exact zero work debt and that
	// single observer with the existing native fixture lifecycle checker.
	ownedCreationAssertDrainedV1(t, q, 1)
}

func participantReportSecondsV1(n int64) *int64 { return &n }

// This helper asserts only the report's genuine shared-comment source and its
// body/actor audit binding. Notification routing/counts belong to their own
// integration tests and do not become a prerequisite for report qualification.
func participantReportSharedCommentV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, token, notice string) string {
	t.Helper()
	const body = "Synthetic participant statement included in the mandatory separate report"
	rc := q.lookupV1(t, token)
	if rc.Document.ID != doc.ID {
		t.Fatal("original comment scope differs")
	}
	recipient, name := rc.Recipient.ID, strings.Clone(rc.Recipient.Name)
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(createCommentInput{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/sign/"+token+"/comments", bytes.NewReader(raw)).WithContext(q.f.ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", q.f.s.PublicURL)
	request.Header.Set(signerNoticeDigestHeader, notice)
	response := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, request)
	var actual commentResponse
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &actual) != nil || actual.Body != body || actual.AuthorSide != "signer" || actual.AuthorName != name {
		t.Fatalf("genuine shared comment=%d %s", response.Code, response.Body.String())
	}
	rows, err := q.f.q.ListComments(q.f.ctx, doc.ID)
	if err != nil || len(rows) != 1 || rows[0].ID.String() != actual.ID || rows[0].DocumentID != doc.ID || rows[0].Body != body || !rows[0].RecipientID.Valid || rows[0].RecipientID.Bytes != recipient || rows[0].UserID.Valid {
		t.Fatal("actual committed shared comment differs", err)
	}
	events, err := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	bound := 0
	for _, event := range events {
		if event.Kind != "document.comment_posted" {
			continue
		}
		matches, err := sign.CommentAuditEvidenceMatchesV1(event, rows[0])
		if err != nil || !matches {
			t.Fatal("actual shared comment lost body/actor evidence", err)
		}
		bound++
	}
	if bound != 1 {
		t.Fatal("shared comment evidence association is not unique", bound)
	}
	q.assertObserversOnlyV1(t)
	return body
}
