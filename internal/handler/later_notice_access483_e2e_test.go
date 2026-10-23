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
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/noticeaccess"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Actual native issuance and actual TLS response deadlines/cookies. Provider
// object bytes/retention use the same authenticated version-aware fixture as
// the completed original; no synthetic positive receipt/response is injected.
type noticeAccessFixture483 struct {
	f        laterAmendmentFixture483
	notice   amendments.NoticeV1
	server   *httptest.Server
	client   *http.Client
	rawToken string
	cookie   *http.Cookie
}

func newNoticeAccessFixture483(t *testing.T) noticeAccessFixture483 {
	t.Helper()
	f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
	notice, _ := issueLaterNotice483(t, f)
	if len(notice.Deliveries) < 1 {
		t.Fatal("actual notice has no outbox recipient")
	}
	var text string
	if e := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT text_body FROM email_deliveries WHERE id=$1`, notice.Deliveries[0].EmailDeliveryID).Scan(&text); e != nil {
		t.Fatal(e)
	}
	rawToken := ""
	for _, part := range strings.Fields(text) {
		u, e := url.Parse(part)
		if e == nil && u.Path == "/notice/"+notice.ID.String() && strings.HasPrefix(u.Fragment, "access=") {
			rawToken = strings.TrimPrefix(u.Fragment, "access=")
		}
	}
	if _, e := noticeaccess.TokenDigestV1(rawToken); e != nil {
		t.Fatal("actual outbox lacks bounded notice entrypoint")
	}
	server := httptest.NewTLSServer(f.q.f.s.Routes())
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 5 * time.Second
	return noticeAccessFixture483{f: f, notice: notice, server: server, client: client, rawToken: rawToken}
}
func (f *noticeAccessFixture483) request483(t *testing.T, method, path string, body []byte, cookie *http.Cookie, origin string, headers map[string]string) (int, http.Header, []byte) {
	t.Helper()
	req, e := http.NewRequestWithContext(f.f.q.f.ctx, method, f.server.URL+path, bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, e := f.client.Do(req)
	if e != nil {
		t.Fatal("actual notice HTTP request failed")
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, (50<<20)+1))
	if e != nil || len(raw) > 50<<20 {
		t.Fatal("actual notice response was not bounded")
	}
	return res.StatusCode, res.Header.Clone(), raw
}
func (f *noticeAccessFixture483) exchange483(t *testing.T) {
	t.Helper()
	raw, _ := json.Marshal(struct {
		Token string `json:"token"`
	}{f.rawToken})
	status, h, body := f.request483(t, http.MethodPost, "/api/v1/notices/"+f.notice.ID.String()+"/access", raw, nil, f.f.q.f.s.PublicURL, nil)
	clear(raw)
	defer clear(body)
	if status != 200 {
		t.Fatal("actual purpose exchange refused", status)
	}
	response := http.Response{Header: h}
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatal("notice exchange cookie count")
	}
	c := cookies[0]
	if c.Name != "__Secure-hash_notice_"+f.notice.ID.String() || c.Path != "/api/v1/notices/"+f.notice.ID.String() || !c.Secure || !c.HttpOnly || c.Domain != "" || c.SameSite != http.SameSiteStrictMode || c.MaxAge < 1 || c.MaxAge > 600 || strings.Contains(c.Value, f.rawToken) {
		t.Fatal("notice cookie purpose/isolation bounds")
	}
	f.cookie = c
	if h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("private exchange cache policy")
	}
}
func TestNotice483ActualNativeOutboxTLSExactFilesAndNoResponseE2E(t *testing.T) {
	f := newNoticeAccessFixture483(t)
	f.exchange483(t)
	path := "/api/v1/notices/" + f.notice.ID.String()
	status, h, raw := f.request483(t, http.MethodGet, path, nil, f.cookie, "", nil)
	defer clear(raw)
	var public noticeaccess.PublicV1
	if status != 200 || json.Unmarshal(raw, &public) != nil || public.Schema != noticeaccess.SchemaV1 || public.NoticeID != f.notice.ID || public.DocumentID != f.f.candidate.ID || public.OriginalDocumentID != f.f.original.ID || public.FileCommitmentSHA256 != f.notice.FileCommitmentSHA256 || len(public.Files) < 1 {
		t.Fatal("actual notice metadata binding", status)
	}
	if h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" || strings.Contains(string(raw), f.rawToken) || strings.Contains(string(raw), "version_id") || strings.Contains(string(raw), "storage_key") || strings.Contains(string(raw), "recipient_email") {
		t.Fatal("public metadata secrecy/cache boundary")
	}
	for _, file := range public.Files {
		exact := noticeaccess.ExpectedFileETagV1(public.FileCommitmentSHA256, file.PDFSHA256)
		route := path + "/files/" + strconv.Itoa(int(file.Position))
		status, _, refused := f.request483(t, http.MethodGet, route, nil, f.cookie, "", map[string]string{"If-Match": "\"wrong\""})
		clear(refused)
		if status != 412 {
			t.Fatal("wrong exact file precondition accepted", status)
		}
		status, _, refused = f.request483(t, http.MethodGet, route, nil, f.cookie, "", map[string]string{"If-Match": exact, "Range": "bytes=0-1"})
		clear(refused)
		if status != 412 {
			t.Fatal("partial range admitted without whole-file proof", status)
		}
		status, headers, pdf := f.request483(t, http.MethodGet, route, nil, f.cookie, "", map[string]string{"If-Match": exact})
		sum := sha256.Sum256(pdf)
		clear(pdf)
		if status != 200 || hex.EncodeToString(sum[:]) != file.PDFSHA256 || headers.Get("ETag") != exact || headers.Get("X-Hash-Notice-Id") != f.notice.ID.String() || headers.Get("X-Hash-Notice-File-Commitment-SHA256") != public.FileCommitmentSHA256 || headers.Get("X-Hash-PDF-SHA256") != file.PDFSHA256 || headers.Get("Content-Length") != strconv.FormatInt(file.PDFBytes, 10) || headers.Get("X-Hash-PDF-Bytes") != strconv.FormatInt(file.PDFBytes, 10) || headers.Get("X-Hash-PDF-Pages") != strconv.Itoa(int(file.PDFPages)) || headers.Get("X-Hash-Notice-File-Position") != strconv.Itoa(int(file.Position)) || headers.Get("X-Hash-Notice-File-Version-SHA256") != file.FileVersionSHA256 || headers.Get("Content-Type") != "application/pdf" || headers.Get("Cache-Control") != "no-store" || headers.Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("actual provider bytes/header binding", status)
		}
	}
	var emails, access, responses, reports, leaks int
	var statusDoc string
	e := f.f.q.f.pool.QueryRow(f.f.q.f.ctx, `SELECT (SELECT count(*) FROM document_amendment_notice_deliveries_v1 WHERE notice_id=$1),
 (SELECT count(*) FROM document_amendment_notice_access_v1 WHERE notice_id=$1),
 (SELECT count(*) FROM signatures WHERE document_id=$2),(SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$2),
 (SELECT count(*) FROM events WHERE payload_json::text LIKE '%'||$3||'%'),(SELECT status FROM documents WHERE id=$2)`, f.notice.ID, f.f.candidate.ID, f.rawToken).Scan(&emails, &access, &responses, &reports, &leaks, &statusDoc)
	if e != nil || emails != len(f.notice.Deliveries) || access != emails || responses != 0 || reports != 0 || leaks != 0 || statusDoc != "draft" {
		t.Fatal("read invented response/evidence or leaked raw token", e)
	}
	var retainedUntil time.Time
	if e = f.f.q.f.pool.QueryRow(f.f.q.f.ctx, `SELECT retain_until FROM document_amendment_notices_v1 WHERE id=$1`, f.notice.ID).Scan(&retainedUntil); e != nil {
		t.Fatal(e)
	}
	f.f.completed.peer.mu.Lock()
	observedUntil := f.f.completed.peer.until[f.f.candidate.PdfStorageKey.String]
	f.f.completed.peer.mu.Unlock()
	if observedUntil.Before(retainedUntil) {
		t.Fatal("actual versioned provider retention did not reach persisted new notice deadline")
	}
	var parity bool
	e = f.f.q.f.pool.QueryRow(f.f.q.f.ctx, `SELECT bool_and(d.message_sha256=hash_package_send_message_sha256_v1(d.email_delivery_id)) FROM document_amendment_notice_deliveries_v1 d WHERE d.notice_id=$1`, f.notice.ID).Scan(&parity)
	if e != nil || !parity {
		t.Fatal("actual queue body/SQL digest parity", e)
	}
	if laterAmendmentOriginalSnapshot483(t, f.f.q, f.f.original.ID) != f.f.before {
		t.Fatal("notice access rewrote completed original")
	}
	f.f.q.assertObserversOnlyV1(t)
}
func TestNotice483OriginForeignCredentialAndDuplicateInputRefuseE2E(t *testing.T) {
	f := newNoticeAccessFixture483(t)
	path := "/api/v1/notices/" + f.notice.ID.String()
	raw, _ := json.Marshal(struct {
		Token string `json:"token"`
	}{f.rawToken})
	defer clear(raw)
	for _, origin := range []string{"", "https://foreign.example.test"} {
		status, h, b := f.request483(t, http.MethodPost, path+"/access", raw, nil, origin, nil)
		clear(b)
		if status != 404 || len(h.Values("Set-Cookie")) != 0 {
			t.Fatal("foreign/missing origin exchanged authority", status)
		}
	}
	old, _ := json.Marshal(struct {
		Token string `json:"token"`
	}{f.f.completed.token})
	status, h, b := f.request483(t, http.MethodPost, path+"/access", old, nil, f.f.q.f.s.PublicURL, nil)
	clear(old)
	clear(b)
	if status != 404 || len(h.Values("Set-Cookie")) != 0 {
		t.Fatal("completed/signer credential reused for notice", status)
	}
	duplicate := []byte(`{"token":"` + f.rawToken + `","token":"` + f.rawToken + `"}`)
	status, h, b = f.request483(t, http.MethodPost, path+"/access", duplicate, nil, f.f.q.f.s.PublicURL, nil)
	clear(duplicate)
	clear(b)
	if status != 404 || len(h.Values("Set-Cookie")) != 0 {
		t.Fatal("duplicate input exchanged authority", status)
	}
	oversized := bytes.Repeat([]byte(" "), 129)
	status, h, b = f.request483(t, http.MethodPost, path+"/access", oversized, nil, f.f.q.f.s.PublicURL, nil)
	clear(oversized)
	clear(b)
	if status != 404 || len(h.Values("Set-Cookie")) != 0 {
		t.Fatal("oversized capability request admitted", status)
	}
	f.exchange483(t)
	foreign := "/api/v1/notices/" + uuid.NewString()
	status, _, b = f.request483(t, http.MethodGet, foreign, nil, f.cookie, "", nil)
	clear(b)
	if status != 404 {
		t.Fatal("notice cookie crossed notice boundary", status)
	}
	status, _, b = f.request483(t, http.MethodGet, path, nil, &http.Cookie{Name: "__Secure-hash_notice_" + f.notice.ID.String(), Value: f.f.q.cookie}, "", nil)
	clear(b)
	if status != 404 {
		t.Fatal("staff session reused for notice", status)
	}
}
func TestNotice483OwnerRevokeIsIdempotentAndDoesNotReleaseRetentionE2E(t *testing.T) {
	f := newNoticeAccessFixture483(t)
	f.exchange483(t)
	access := f.notice.Deliveries[0].AccessID
	if access == uuid.Nil {
		t.Fatal("native owner inventory lacks access identity")
	}
	route := "/api/v1/documents/" + f.f.original.ID.String() + "/amendments/" + f.f.record.ID.String() + "/notice/access/" + access.String() + "/revoke"
	first := submitSessionOperationE2E(f.f.q.f.s, http.MethodPost, route, "", f.f.q.cookie)
	var one amendments.RevokeOutcomeV1
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &one) != nil || one.RevokedAt == nil || one.State != "committed" {
		t.Fatal("actual owner revoke", first.Code)
	}
	second := submitSessionOperationE2E(f.f.q.f.s, http.MethodPost, route, "", f.f.q.cookie)
	var two amendments.RevokeOutcomeV1
	if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &two) != nil || two.State != "unchanged" || two.RevokedAt == nil || !one.RevokedAt.Equal(*two.RevokedAt) {
		t.Fatal("revoke did not retain original immutable timestamp", second.Code)
	}
	status, _, b := f.request483(t, http.MethodGet, "/api/v1/notices/"+f.notice.ID.String(), nil, f.cookie, "", nil)
	clear(b)
	if status != 404 {
		t.Fatal("revoked cookie still reads", status)
	}
	raw, _ := json.Marshal(struct {
		Token string `json:"token"`
	}{f.rawToken})
	status, h, b := f.request483(t, http.MethodPost, "/api/v1/notices/"+f.notice.ID.String()+"/access", raw, nil, f.f.q.f.s.PublicURL, nil)
	clear(raw)
	clear(b)
	if status != 404 || len(h.Values("Set-Cookie")) != 0 {
		t.Fatal("revoked link reminted read authority", status)
	}
	var retain, issued time.Time
	e := f.f.q.f.pool.QueryRow(f.f.q.f.ctx, `SELECT retain_until,issued_at FROM document_amendment_notices_v1 WHERE id=$1`, f.notice.ID).Scan(&retain, &issued)
	if e != nil || retain.Before(issued.AddDate(7, 0, 0)) {
		t.Fatal("revoke shortened evidence retention", e)
	}
	guarded, e := f.f.q.f.q.HasRetainedDraftEvidenceForPurge(f.f.q.f.ctx, generated.HasRetainedDraftEvidenceForPurgeParams{DocumentID: f.f.candidate.ID, OrgID: f.f.q.f.org})
	if e != nil || !guarded {
		t.Fatal("revoked notice source became purgeable", e)
	}
	if laterAmendmentOriginalSnapshot483(t, f.f.q, f.f.original.ID) != f.f.before {
		t.Fatal("revoke mutated completed original")
	}
}
func TestNotice483AbsoluteCapabilityExpiryRefusesExistingCookieAndOriginalLinkE2E(t *testing.T) {
	f := newNoticeAccessFixture483(t)
	f.exchange483(t)
	// Controlled NEGATIVE authorization fixture only: shift a coherent persisted
	// notice/access pair into the past. This is not a claim that the native issuer
	// created an old receipt. Schema-owner test setup temporarily disables ONLY
	// these immutable USER guards; CHECK/FK remain, restore is in the same tx.
	tx, e := f.f.q.f.pool.Begin(f.f.q.f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	for _, sql := range []string{`ALTER TABLE document_amendment_notices_v1 DISABLE TRIGGER USER`, `ALTER TABLE document_amendment_notice_access_v1 DISABLE TRIGGER USER`} {
		if _, e = tx.Exec(f.f.q.f.ctx, sql); e != nil {
			t.Fatal("schema-owner negative expiry setup unavailable", e)
		}
	}
	old := time.Now().UTC().Add(-8 * 24 * time.Hour).Truncate(time.Microsecond)
	if _, e = tx.Exec(f.f.q.f.ctx, `UPDATE document_amendment_notices_v1 SET issued_at=$2::timestamptz,retain_until=hash_evidence_retain_until($2::timestamptz,7) WHERE id=$1`, f.notice.ID, old); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(f.f.q.f.ctx, `UPDATE document_amendment_notice_access_v1 SET created_at=$2::timestamptz,expires_at=$2::timestamptz+interval '7 days' WHERE notice_id=$1`, f.notice.ID, old); e != nil {
		t.Fatal(e)
	}
	for _, sql := range []string{`ALTER TABLE document_amendment_notices_v1 ENABLE TRIGGER USER`, `ALTER TABLE document_amendment_notice_access_v1 ENABLE TRIGGER USER`} {
		if _, e = tx.Exec(f.f.q.f.ctx, sql); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(f.f.q.f.ctx); e != nil {
		t.Fatal(e)
	}
	path := "/api/v1/notices/" + f.notice.ID.String()
	status, _, b := f.request483(t, http.MethodGet, path, nil, f.cookie, "", nil)
	clear(b)
	if status != 404 {
		t.Fatal("absolute expiry ignored by cookie read", status)
	}
	raw, _ := json.Marshal(struct {
		Token string `json:"token"`
	}{f.rawToken})
	status, h, b := f.request483(t, http.MethodPost, path+"/access", raw, nil, f.f.q.f.s.PublicURL, nil)
	clear(raw)
	clear(b)
	if status != 404 || len(h.Values("Set-Cookie")) != 0 {
		t.Fatal("expired original link still exchanges", status)
	}
}

func TestNotice483ProviderHashOrMissingVersionRefusesAllBytesE2E(t *testing.T) {
	f := newNoticeAccessFixture483(t)
	f.exchange483(t)
	path := "/api/v1/notices/" + f.notice.ID.String()
	status, _, raw := f.request483(t, http.MethodGet, path, nil, f.cookie, "", nil)
	var public noticeaccess.PublicV1
	if status != 200 || json.Unmarshal(raw, &public) != nil || len(public.Files) < 1 {
		t.Fatal("metadata before controlled provider fault")
	}
	clear(raw)
	file := public.Files[0]
	route := path + "/files/0"
	etag := noticeaccess.ExpectedFileETagV1(public.FileCommitmentSHA256, file.PDFSHA256)
	key := f.f.candidate.PdfStorageKey.String
	peer := f.f.q.storagePeer.importStoragePeer
	peer.mu.Lock()
	original := append([]byte(nil), peer.objects[key]...)
	changed := append([]byte(nil), original...)
	if len(changed) < 1 {
		peer.mu.Unlock()
		t.Fatal("actual imported fixture bytes absent")
	}
	changed[len(changed)-1] ^= 1
	peer.objects[key] = changed
	peer.mu.Unlock()
	defer func() { peer.mu.Lock(); peer.objects[key] = original; peer.mu.Unlock() }()
	status, h, body := f.request483(t, http.MethodGet, route, nil, f.cookie, "", map[string]string{"If-Match": etag})
	clear(body)
	if status != 503 || h.Get("Content-Type") == "application/pdf" || h.Get("X-Hash-PDF-SHA256") != "" {
		t.Fatal("provider digest mismatch exposed PDF bytes", status)
	}
	peer.mu.Lock()
	delete(peer.objects, key)
	peer.mu.Unlock()
	status, h, body = f.request483(t, http.MethodGet, route, nil, f.cookie, "", map[string]string{"If-Match": etag})
	clear(body)
	if status != 503 || h.Get("Content-Type") == "application/pdf" {
		t.Fatal("absent pinned provider object fell back to another source", status)
	}
}
