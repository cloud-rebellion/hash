//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
)

// Actual owner HTTP preferences and actual recipient event producers share the
// original native runtime, transaction, audit and outbox. No business/cache,
// notification receipt, source measurement or work grant is inserted by hand.
func TestAutomationSenderEvents766NativeViewSignOptInAndDedupeE2E(t *testing.T) {
	for _, mode := range []string{"default-off", "enabled", "opt-out-before-second-party"} {
		t.Run(mode, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			f := q.f
			f.s.Sign.Storage = f.s.Storage
			setPreference := func(revision int, enabled bool) {
				t.Helper()
				response := ownedBlocksTemplateCallV1(t, f, q.cookie, http.MethodPut,
					"/api/v1/automation-preferences", map[string]any{"expected_revision": revision, "notify_viewed": enabled, "notify_signed": enabled})
				if response.Code != http.StatusOK {
					t.Fatalf("native preference CAS=%d", response.Code)
				}
				q.assertObserversOnlyV1(t)
			}
			if mode != "default-off" {
				setPreference(0, true)
			}
			doc, parties := q.createSentV1(t)
			if len(parties) != 2 || doc.SenderID != f.user.ID {
				t.Fatal("fixture lost genuine two-party document sender")
			}
			router := f.s.Routes()
			for index, party := range parties {
				if mode == "opt-out-before-second-party" && index == 1 {
					setPreference(1, false)
				}
				rc := q.lookupV1(t, party.Token)
				notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
				if err != nil {
					t.Fatal(err)
				}
				evidence, err := signerArticle13NoticeEvidence(rc, notice)
				if err != nil {
					t.Fatal(err)
				}
				if err = rc.CloseReadV1(); err != nil {
					t.Fatal(err)
				}
				q.assertObserversOnlyV1(t)
				// Genuine simultaneous first-view requests exercise the parent/recipient
				// lock and first-view receipt rather than manually invoking claim helpers.
				codes := make(chan int, 2)
				var joined sync.WaitGroup
				for attempt := 0; attempt < 2; attempt++ {
					joined.Add(1)
					go func() {
						defer joined.Done()
						request := httptest.NewRequest(http.MethodPost, "/sign/"+party.Token+"/view", strings.NewReader(`{}`)).WithContext(f.ctx)
						request.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
						response := httptest.NewRecorder()
						router.ServeHTTP(response, request)
						codes <- response.Code
					}()
				}
				joined.Wait()
				close(codes)
				for code := range codes {
					if code != http.StatusOK {
						t.Fatalf("native concurrent view=%d", code)
					}
				}
				q.assertObserversOnlyV1(t)
				rc = q.lookupV1(t, party.Token)
				result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic sender-notice PostgreSQL acceptance"})
				if closeErr := rc.CloseReadV1(); closeErr != nil {
					t.Fatal(closeErr)
				}
				q.assertObserversOnlyV1(t)
				if err != nil || result == nil || result.Completed != (index == len(parties)-1) {
					t.Fatal("native required-party signing failed", err)
				}
			}
			current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
			if err != nil || current.Status != "completed" || !sameSignerDocumentSource(doc, current) {
				t.Fatal("notification changed completion/source", err)
			}
			var viewed, signed int
			err = f.pool.QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE kind='document.viewed'),count(*) FILTER(WHERE kind='document.signed') FROM events WHERE org_id=$1 AND document_id=$2`, f.org, doc.ID).Scan(&viewed, &signed) //nolint:rawsql -- actual committed producer oracle only
			if err != nil || viewed != 2 || signed != 2 {
				t.Fatal("view/sign audit dedupe changed", viewed, signed, err)
			}
			expected := 0
			if mode == "enabled" {
				expected = 4
			}
			if mode == "opt-out-before-second-party" {
				expected = 2
			}
			var receipts, exact int
			err = f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE r.sender_user_id=d.sender_id AND r.sender_user_id=$3 AND r.sent_at=d.sent_at AND e.org_id=r.org_id AND e.document_id=r.document_id AND e.recipient_id=r.recipient_id AND e.kind=r.event_kind AND e.created_at>=r.sent_at AND m.smtp_org_id=r.org_id AND m.smtp_purpose='workspace' AND m.to_email=u.email AND octet_length(m.html_body)>0 AND octet_length(m.text_body)>0 AND ((r.event_kind='document.viewed' AND r.signature_id IS NULL) OR (r.event_kind='document.signed' AND s.id=r.signature_id AND s.document_id=r.document_id AND s.recipient_id=r.recipient_id)))
 FROM sender_event_notice_receipts_v1 r
 JOIN documents d ON d.id=r.document_id AND d.org_id=r.org_id
 JOIN users u ON u.id=r.sender_user_id AND u.org_id=r.org_id
 JOIN events e ON e.id=r.audit_event_id
 JOIN email_deliveries m ON m.id=r.email_delivery_id
 LEFT JOIN signatures s ON s.id=r.signature_id
 WHERE r.org_id=$1 AND r.document_id=$2`, f.org, doc.ID, f.user.ID).Scan(&receipts, &exact) //nolint:rawsql -- independent exact receipt/event/outbox/signature/sender binding; no fake rows
			if err != nil || receipts != expected || exact != expected {
				t.Fatalf("native %s notices=%d exact=%d want=%d err=%v", mode, receipts, exact, expected, err)
			}
			var groups int
			err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM (SELECT recipient_id,event_kind,count(*) AS n FROM sender_event_notice_receipts_v1 WHERE org_id=$1 AND document_id=$2 GROUP BY recipient_id,event_kind HAVING count(*)<>1) x`, f.org, doc.ID).Scan(&groups) //nolint:rawsql -- verifies real event-specific uniqueness after concurrent requests
			if err != nil || groups != 0 {
				t.Fatal("duplicate sender notices", groups, err)
			}
			if mode == "opt-out-before-second-party" {
				var later int
				err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM sender_event_notice_receipts_v1 WHERE org_id=$1 AND document_id=$2 AND recipient_id=$3`, f.org, doc.ID, parties[1].RecipientID).Scan(&later) //nolint:rawsql -- actual opt-out-before-next-event delivery oracle
				if err != nil || later != 0 {
					t.Fatal("current opt-out ignored", later, err)
				}
			}
			q.assertObserversOnlyV1(t)
		})
	}
}
