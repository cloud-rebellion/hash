//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/bright-interaction/hash/internal/emailtemplates"
)

func email720Body(revision int64, subject, html, text string) string {
	raw, _ := json.Marshal(emailtemplates.Input{ExpectedRevision: revision, SubjectTemplate: subject, HTMLTemplate: html, TextTemplate: text})
	return string(raw)
}
func email720Counts(t *testing.T, f folderFixture695) (int64, int64) {
	t.Helper()
	var revisions, events int64
	if e := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM org_email_template_revisions_v1 WHERE org_id=$1),(SELECT count(*) FROM events WHERE org_id=$1)`, f.org).Scan(&revisions, &events); e != nil {
		t.Fatal(e)
	}
	return revisions, events
}
func TestEmailTemplate720OwnerRevisionPreviewAndTenantE2E(t *testing.T) {
	f := folderSetup695(t)
	path := "/api/v1/email-templates/email.invite"
	r, e := email720Counts(t, f)
	if r != 0 {
		t.Fatal("fixture already contains editions")
	}
	body := email720Body(0, "For {{recipient_name}}", "<h2>For {{org_name}}</h2>", "For {{recipient_name}}")
	preview := f.request(http.MethodPost, path+"/preview", body)
	if preview.Code != 200 || preview.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("preview=%d %s", preview.Code, preview.Body.String())
	}
	var p emailtemplates.Preview
	if err := json.Unmarshal(preview.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Synthetic || !p.MandatoryContentPreserved || p.Revision != 0 || !strings.Contains(p.HTML, "https://example.invalid/sign/preview") {
		t.Fatal("preview lacks fixed synthetic/native protected content")
	}
	if rr, ee := email720Counts(t, f); rr != r || ee != e {
		t.Fatal("preview persisted settings/audit/mail")
	}
	save := f.request(http.MethodPut, path, body)
	if save.Code != 200 {
		t.Fatalf("save=%d %s", save.Code, save.Body.String())
	}
	var saved emailtemplates.Template
	if err := json.Unmarshal(save.Body.Bytes(), &saved); err != nil || saved.Revision != 1 {
		t.Fatal("save revision", err)
	}
	if w := f.request(http.MethodPut, path, body); w.Code != 409 {
		t.Fatal("stale save accepted", w.Code)
	}
	if w := f.request(http.MethodPost, path+"/preview", body); w.Code != 409 {
		t.Fatal("stale preview accepted", w.Code)
	}
	if rr, ee := email720Counts(t, f); rr != 1 || ee != e+1 {
		t.Fatal("CAS failure wrote an edition/audit")
	}
	var truthful bool
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*)=1 AND bool_and(document_id IS NULL AND actor_user_id=$2 AND payload_json->>'kind'='email.invite' AND payload_json->>'revision'='1') FROM events WHERE org_id=$1 AND kind='email_template.updated'`, f.org, f.user.ID).Scan(&truthful); err != nil || !truthful {
		t.Fatal("email settings audit lost kind/org/actor/revision", err)
	}
	other := folderSetup695(t)
	if w := other.request(http.MethodGet, "/api/v1/email-templates", ""); w.Code != 200 || strings.Contains(w.Body.String(), "For {{org_name}}") {
		t.Fatal("other organization read source", w.Code)
	}
	if w := other.request(http.MethodPut, path, email720Body(1, "foreign", "", "")); w.Code != 409 {
		t.Fatal("other org borrowed revision", w.Code)
	}
	if rr, _ := email720Counts(t, other); rr != 0 {
		t.Fatal("other org mutation created edition")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET role='viewer' WHERE id=$1`, f.user.ID); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPost} {
		url := path
		request := email720Body(1, "revoked", "", "")
		if method == http.MethodGet {
			url = "/api/v1/email-templates"
			request = ""
		}
		if method == http.MethodPost {
			url += "/preview"
		}
		if w := f.request(method, url, request); w.Code != 403 {
			t.Fatal("revoked/non-owner request accepted", method, w.Code)
		}
	}
	if rr, ee := email720Counts(t, f); rr != 1 || ee != e+1 {
		t.Fatal("revocation changed source/audit")
	}
}
func TestEmailTemplate720ConcurrentCASAndImmutableHistoryE2E(t *testing.T) {
	f := folderSetup695(t)
	path := "/api/v1/email-templates/email.invite"
	var wait sync.WaitGroup
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			results <- f.request(http.MethodPut, path, email720Body(0, fmt.Sprintf("Edition %d", i), "", "")).Code
		}(i)
	}
	wait.Wait()
	close(results)
	success, conflict := 0, 0
	for code := range results {
		switch code {
		case 200:
			success++
		case 409:
			conflict++
		default:
			t.Fatal("unexpected concurrent outcome", code)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent CAS did not serialize")
	}
	if r, _ := email720Counts(t, f); r != 1 {
		t.Fatal("duplicate editions")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE org_email_template_revisions_v1 SET subject_template='rewritten' WHERE org_id=$1`, f.org); err == nil {
		t.Fatal("historical source was mutable")
	}
	if w := f.request(http.MethodPut, path, email720Body(1, "", "", "")); w.Code != 200 {
		t.Fatal("reset failed", w.Code)
	}
	if r, _ := email720Counts(t, f); r != 2 {
		t.Fatal("reset destroyed history")
	}
}
