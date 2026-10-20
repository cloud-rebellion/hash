//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

func completedCompanionOutboxIDsV1(t *testing.T, q *ownedPublicReadFixtureV1) map[uuid.UUID]struct{} {
	t.Helper()
	rows, err := q.f.pool.Query(q.f.ctx, "SELECT id FROM email_deliveries LIMIT 501")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	ids := make(map[uuid.UUID]struct{})
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids[id] = struct{}{}
	}
	if rows.Err() != nil || len(ids) > 500 {
		t.Fatal("unexpected fixture outbox inventory", rows.Err())
	}
	return ids
}

// Observe actual committed outbox rows, not re-rendered templates or captures.
// Every advertised recipient capability must match its persisted rotation.
func assertCompletedCompanionOutboxV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, before map[uuid.UUID]struct{}, certificate []byte) {
	t.Helper()
	old := make([]uuid.UUID, 0, len(before))
	for id := range before {
		old = append(old, id)
	}
	rows, err := q.f.pool.Query(q.f.ctx, "SELECT id,to_email,html_body,text_body FROM email_deliveries WHERE NOT (id=ANY($1::uuid[])) ORDER BY id LIMIT 4", old)
	if err != nil {
		t.Fatal(err)
	}
	type delivery struct {
		id             uuid.UUID
		to, html, text string
	}
	var deliveries []delivery
	for rows.Next() {
		var d delivery
		if err := rows.Scan(&d.id, &d.to, &d.html, &d.text); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		deliveries = append(deliveries, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(deliveries) != 3 {
		t.Fatal("expected exactly two recipient and one sender completion outbox rows", err)
	}
	recipients, err := q.f.q.ListRecipientsByDocument(q.f.ctx, doc.ID)
	if err != nil || len(recipients) != 2 {
		t.Fatal("actual completion recipient inventory differs", err)
	}
	sender, err := q.f.q.GetUser(q.f.ctx, doc.SenderID)
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimRight(q.f.s.PublicURL, "/")
	seen := make(map[string]bool)
	for _, d := range deliveries {
		if seen[d.to] {
			t.Fatal("duplicate completion outbox recipient")
		}
		seen[d.to] = true
		var recipient *generated.Recipient
		for _, r := range recipients {
			if r.Email == d.to {
				recipient = r
			}
		}
		if recipient == nil {
			if d.to != sender.Email {
				t.Fatal("completion outbox addressed an unrelated person")
			}
			for _, body := range []string{d.html, d.text} {
				for _, suffix := range []string{"/final-pdf", "/audit-cert"} {
					if !strings.Contains(body, base+"/api/v1/documents/"+doc.ID.String()+suffix) {
						t.Fatal("sender completion omitted an authenticated artifact link")
					}
				}
				if strings.Contains(body, "/sign/") {
					t.Fatal("sender completion exposed a recipient capability")
				}
			}
			continue
		}
		prefix := base + "/sign/"
		start := strings.Index(d.text, prefix)
		if start < 0 {
			t.Fatal("recipient completion omitted its download capability")
		}
		tail := d.text[start+len(prefix):]
		end := strings.Index(tail, "/final-pdf")
		if end != 43 {
			t.Fatal("recipient completion capability shape differs")
		}
		token := tail[:end]
		actual, err := q.f.q.GetRecipientByTokenHash(q.f.ctx, auth.HashMagicToken(token))
		if err != nil || actual.ID != recipient.ID || actual.DocumentID != doc.ID {
			t.Fatal("completion email token does not match the actual recipient rotation", err)
		}
		for _, body := range []string{d.html, d.text} {
			for _, suffix := range []string{"/final-pdf", "/audit-cert"} {
				if !strings.Contains(body, prefix+token+suffix) {
					t.Fatal("recipient completion omitted a paired artifact link")
				}
			}
			if strings.Contains(body, "/api/v1/documents/") {
				t.Fatal("recipient completion requires staff authentication")
			}
		}
		response := q.requestV1(token, "/audit-cert")
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), certificate) {
			t.Fatalf("recipient certificate download status=%d exact=%v", response.Code, bytes.Equal(response.Body.Bytes(), certificate))
		}
		q.assertObserversOnlyV1(t)
	}
}

// Only this genuine non-fitted manual completion is fault-injected. Keep the
// fitted immutable-pin trigger intact. Real storage GET and private-original
// owned DB rechecks must join before bytes can be exposed.
func assertCompletedCompanionAwaitFencesV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, token string, certificate []byte) {
	t.Helper()
	recipient, err := q.f.q.GetRecipientByTokenHash(q.f.ctx, auth.HashMagicToken(token))
	if err != nil {
		t.Fatal(err)
	}
	if doc.SigningAdmissionPolicy != "historical" {
		t.Fatal("certificate fault injection requires the genuine historical manual path")
	}
	for _, scenario := range []string{"unchanged", "certificate-key", "certificate-version", "certificate-hash", "expired-token", "rotated-token"} {
		if !t.Run(scenario, func(t *testing.T) {
			requestStarted, handlerJoined := false, false
			// Restore only the exact owned fault-injection columns after the
			// request has joined; no source/history/cache rows are fabricated.
			defer func() {
				if requestStarted && !handlerJoined {
					return
				} // unjoined state stays quarantined
				tag, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET audit_cert_key=$3,audit_cert_sha256=$4,audit_cert_version_id=$5 WHERE id=$1 AND org_id=$2", doc.ID, doc.OrgID, doc.AuditCertKey, doc.AuditCertSha256, doc.AuditCertVersionID)
				if err != nil || tag.RowsAffected() != 1 {
					t.Error("restore owned certificate fault", err)
				}
				tag, err = q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_hash=$3,magic_token_expires_at=$4 WHERE id=$1 AND document_id=$2", recipient.ID, doc.ID, recipient.MagicTokenHash, recipient.MagicTokenExpiresAt)
				if err != nil || tag.RowsAffected() != 1 {
					t.Error("restore owned recipient fault", err)
				}
			}()
			peer := &originalPDFPreviewPeerE2E{importStoragePeer: q.storagePeer.importStoragePeer, key: doc.AuditCertKey.String, entered: make(chan string, 1), release: make(chan struct{})}
			server := httptest.NewServer(peer)
			oldStore := q.f.s.Storage
			defer func() {
				if !requestStarted || handlerJoined {
					q.f.s.Storage = oldStore
					server.Close()
				}
			}()
			client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-certificate-await", SecretKey: "synthetic-certificate-await-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
			if err != nil {
				peer.unblock()
				t.Fatal(err)
			}
			q.f.s.Storage = client
			ctx, cancel := context.WithTimeout(q.f.ctx, 8*time.Second)
			result, done := make(chan *httptest.ResponseRecorder, 1), make(chan struct{})
			request := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+"/sign/"+token+"/audit-cert", nil).WithContext(ctx)
			requestStarted = true
			go func() {
				defer close(done)
				w := httptest.NewRecorder()
				q.f.s.Routes().ServeHTTP(w, request)
				result <- w
			}()
			defer func() {
				cancel()
				peer.unblock()
				select {
				case <-done:
					handlerJoined = true
				case <-time.After(4 * time.Second):
					t.Error("certificate request did not join before provider cleanup")
				}
			}()
			select {
			case version := <-peer.entered:
				if version != doc.AuditCertVersionID.String {
					t.Fatal("certificate did not request its exact stored version")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("certificate download did not reach storage wait")
			}
			var affected int64 = 1
			switch scenario {
			case "certificate-key":
				key := []byte(doc.AuditCertKey.String)
				if len(key) < 5 {
					t.Fatal("certificate key shape")
				}
				if key[len(key)-5] == '0' {
					key[len(key)-5] = '1'
				} else {
					key[len(key)-5] = '0'
				}
				tag, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET audit_cert_key=$3 WHERE id=$1 AND org_id=$2", doc.ID, doc.OrgID, string(key))
				if err != nil {
					t.Fatal(err)
				}
				affected = tag.RowsAffected()
			case "certificate-version":
				version := []byte(doc.AuditCertVersionID.String)
				if len(version) == 0 {
					t.Fatal("certificate version missing")
				}
				if version[0] == 'x' {
					version[0] = 'y'
				} else {
					version[0] = 'x'
				}
				tag, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET audit_cert_version_id=$3 WHERE id=$1 AND org_id=$2", doc.ID, doc.OrgID, string(version))
				if err != nil {
					t.Fatal(err)
				}
				affected = tag.RowsAffected()
			case "certificate-hash":
				sum := bytes.Clone(doc.AuditCertSha256)
				sum[0]++
				tag, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET audit_cert_sha256=$3 WHERE id=$1 AND org_id=$2", doc.ID, doc.OrgID, sum)
				if err != nil {
					t.Fatal(err)
				}
				affected = tag.RowsAffected()
			case "expired-token":
				tag, err := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_expires_at=$3 WHERE id=$1 AND document_id=$2", recipient.ID, doc.ID, time.Now().Add(-time.Second))
				if err != nil {
					t.Fatal(err)
				}
				affected = tag.RowsAffected()
			case "rotated-token":
				tag, err := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_hash=$3 WHERE id=$1 AND document_id=$2", recipient.ID, doc.ID, auth.HashMagicToken("synthetic-revoked-completion-token"))
				if err != nil {
					t.Fatal(err)
				}
				affected = tag.RowsAffected()
			}
			if affected != 1 {
				t.Fatal("fault injection did not affect exactly one owned row")
			}
			fresh, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: doc.OrgID})
			if err != nil || fresh.FinalPdfKey != doc.FinalPdfKey || fresh.FinalPdfVersionID != doc.FinalPdfVersionID || !bytes.Equal(fresh.FinalPdfSha, doc.FinalPdfSha) {
				t.Fatal("certificate-only fault changed final-PDF commitment", err)
			}
			peer.unblock()
			select {
			case response := <-result:
				if scenario == "unchanged" {
					if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), certificate) {
						t.Fatal("healthy certificate await control failed")
					}
				} else if response.Code != http.StatusNotFound || bytes.Contains(response.Body.Bytes(), []byte("%PDF-")) || response.Header().Get("Content-Disposition") != "" {
					t.Fatalf("certificate await fence did not refuse without PDF bytes: status=%d", response.Code)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("certificate response did not finish after storage release")
			}
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				t.Fatal("certificate handler did not join")
			}
			q.assertObserversOnlyV1(t)
		}) {
			t.FailNow() // never reuse a failed or unjoined fixture
		}
	}
}
