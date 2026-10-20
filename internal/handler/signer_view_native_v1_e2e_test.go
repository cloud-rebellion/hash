//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestOwnedSignerViewNativeMeasurementAndCompletionE2E(t *testing.T) {
	for _, state := range []string{"sent", "changes_requested"} {
		t.Run(state, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			f := q.f
			f.s.Sign.Storage = f.s.Storage
			doc, parties := q.createSentV1(t)
			if state != "sent" {
				if _, err := f.pool.Exec(f.ctx, "UPDATE documents SET status=$3 WHERE id=$1 AND org_id=$2", doc.ID, f.org, state); err != nil { //nolint:rawsql -- controlled paused-ceremony boundary, no cache or credential writes
					t.Fatal(err)
				}
			}
			for index, party := range parties {
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
				for attempt := 0; attempt < 2; attempt++ {
					r := httptest.NewRequest(http.MethodPost, "/sign/"+party.Token+"/view", strings.NewReader(`{}`)).WithContext(f.ctx)
					r.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
					w := httptest.NewRecorder()
					f.s.Routes().ServeHTTP(w, r)
					if w.Code != http.StatusOK {
						t.Fatalf("native %s view attempt%d=%d", state, attempt, w.Code)
					}
					q.assertObserversOnlyV1(t)
				}
				var events, measured int
				var noticeMatches bool
				err = f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer),bool_and(e.payload_json->>'notice_digest'=$4)
 FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id
 WHERE e.document_id=$1 AND e.org_id=$2 AND e.recipient_id=$3 AND e.kind='document.viewed'`, doc.ID, f.org, party.RecipientID, evidence.Digest).Scan(&events, &measured, &noticeMatches) //nolint:rawsql -- actual atomic event/measurement/idempotency oracle only
				if err != nil || events != 1 || measured != 1 || !noticeMatches {
					t.Fatalf("native view event/measurement/notice=%d/%d/%t err=%v", events, measured, noticeMatches, err)
				}
				if state != "sent" {
					continue
				}
				rc = q.lookupV1(t, party.Token)
				result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic native view completion"})
				if closeErr := rc.CloseReadV1(); closeErr != nil {
					t.Fatal(closeErr)
				}
				q.assertObserversOnlyV1(t)
				if err != nil || result == nil || result.Completed != (index == len(parties)-1) {
					t.Fatal("viewed contract did not retain original every-party completion", err)
				}
			}
			current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			if state != "sent" {
				if current.Status != state {
					t.Fatal("view changed paused negotiation status")
				}
				return
			}
			if current.Status != "completed" || !sameSignerDocumentSource(doc, current) {
				t.Fatal("viewed completion changed approved source or remained incomplete")
			}
			type pin struct {
				key, version pgtype.Text
				digest       []byte
			}
			var artifacts [][]byte
			for _, p := range []pin{{current.FinalPdfKey, current.FinalPdfVersionID, current.FinalPdfSha}, {current.AuditCertKey, current.AuditCertVersionID, current.AuditCertSha256}, {current.AuditPayloadKey, current.AuditPayloadVersionID, current.AuditPayloadSha256}, {current.AuditSignatureKey, current.AuditSignatureVersionID, current.AuditSignatureSha256}} {
				if !p.key.Valid || !p.version.Valid || p.version.String == "" || len(p.digest) != sha256.Size {
					t.Fatal("viewed completion omitted exact artifact pins")
				}
				b, err := readDocumentArtifact(f.ctx, f.s.Storage, current, p.key.String, p.digest, p.version)
				if err != nil {
					t.Fatal(err)
				}
				artifacts = append(artifacts, b)
			}
			if !bytes.HasPrefix(artifacts[0], []byte("%PDF-")) || !bytes.HasPrefix(artifacts[1], []byte("%PDF-")) || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(artifacts[2]), string(artifacts[3])) {
				t.Fatal("viewed completion artifact verification failed")
			}
		})
	}
}
