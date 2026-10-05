//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"net/http"
	"strings"
	"testing"
)

func TestDocumentSoftDeleteRefusesCapturedDraftEvidenceE2E(t *testing.T) {
	ctx, pool, q, s, org, user, cookie := documentDeleteFixture(t)
	doc := seedDocumentDeleteDraft(t, ctx, q, org, user)
	// An empty string is still a captured field value. Normal revision already
	// rejects this state; deletion must not hide it and start retirement.
	if _, err := pool.Exec(ctx, `INSERT INTO document_fields(document_id,type,page,x_pct,y_pct,w_pct,h_pct,required,value,options_json) VALUES($1,'text',1,0,0,20,5,false,'','[]')`, doc.ID); err != nil {
		t.Fatal(err)
	}
	res := submitDocumentDelete(t, s, doc.ID, cookie)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "evidence or sealing state") {
		t.Fatalf("captured draft deletion status=%d body=%s", res.Code, res.Body.String())
	}
	assertDocumentDeleteNotCommitted(t, ctx, q, doc.ID)
	var deletionEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.deleted'`, doc.ID).Scan(&deletionEvents); err != nil || deletionEvents != 0 {
		t.Fatalf("refused deletion audit=%d err=%v", deletionEvents, err)
	}
}
