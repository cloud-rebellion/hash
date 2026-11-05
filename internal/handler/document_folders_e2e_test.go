//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentfolders"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type folderFixture695 struct {
	lifecycleAuthorizationFixture
	cookie string
}

func folderSetup695(t *testing.T) folderFixture695 {
	t.Helper()
	ctx, pool, q, s, org, userID := setupDSRE2E(t)
	user, err := q.GetUser(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanup, `DELETE FROM orgs WHERE id=$1`, org); err != nil {
			t.Error(err)
		}
	})
	return folderFixture695{lifecycleAuthorizationFixture: lifecycleAuthorizationFixture{ctx: ctx, pool: pool, q: q, s: s, org: org, user: user}, cookie: dsrSessionCookieE2E(t, s, userID, user.SessionGeneration, time.Hour)}
}
func (f folderFixture695) request(method, path, body string) *httptest.ResponseRecorder {
	return submitSessionOperationContextE2E(f.ctx, f.s, method, path, body, f.cookie)
}
func (f folderFixture695) folder(t *testing.T, name string) documentfolders.Folder {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"name": name})
	w := f.request(http.MethodPost, "/api/v1/document-folders", string(raw))
	if w.Code != 201 {
		t.Fatalf("create folder=%d %s", w.Code, w.Body.String())
	}
	var out struct {
		Folder documentfolders.Folder `json:"folder"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Folder
}
func (f folderFixture695) document(t *testing.T, name, status string) *generated.Document {
	t.Helper()
	d, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: name, BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if status != "draft" {
		t.Fatal("non-draft filing fixtures must use genuine send and completion")
	}
	return d
}
func (f folderFixture695) move(t *testing.T, doc uuid.UUID, folder *uuid.UUID, intended int) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"folder_id": folder})
	w := f.request(http.MethodPut, "/api/v1/documents/"+doc.String()+"/folder", string(raw))
	if w.Code != intended {
		t.Fatalf("move=%d want%d %s", w.Code, intended, w.Body.String())
	}
}
func (f folderFixture695) list(t *testing.T, query string) ([]documentWithFolderResponse, int64) {
	t.Helper()
	w := f.request(http.MethodGet, "/api/v1/documents"+query, "")
	if w.Code != 200 {
		t.Fatalf("list=%d %s", w.Code, w.Body.String())
	}
	var out struct {
		Documents []documentWithFolderResponse `json:"documents"`
		Total     int64                        `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Documents, out.Total
}

func TestDocumentFoldersCRUDAndSQLPaginationE2E(t *testing.T) {
	f := folderSetup695(t)
	a := f.folder(t, "A customers")
	b := f.folder(t, "B partners")
	if w := f.request(http.MethodPost, "/api/v1/document-folders", `{"name":"a CUSTOMERS"}`); w.Code != 409 {
		t.Fatalf("duplicate=%d", w.Code)
	}
	var docs []*generated.Document
	for i := 0; i < 5; i++ {
		docs = append(docs, f.document(t, fmt.Sprintf("Folder fixture%d", i), "draft"))
	}
	for _, d := range docs[:3] {
		f.move(t, d.ID, &a.ID, 200)
	}
	f.move(t, docs[3].ID, &b.ID, 200)
	for _, tc := range []struct {
		query  string
		total  int64
		length int
		folder *uuid.UUID
	}{
		{"", 5, 5, nil}, {"?folder_id=unfiled", 1, 1, nil},
		{"?folder_id=" + a.ID.String() + "&limit=1&offset=1", 3, 1, &a.ID},
		{"?folder_id=" + a.ID.String() + "&status=completed", 0, 0, &a.ID},
		{"?folder_id=" + b.ID.String(), 1, 1, &b.ID},
	} {
		rows, total := f.list(t, tc.query)
		if total != tc.total || len(rows) != tc.length {
			t.Fatalf("filter pagination count mismatch: %s", tc.query)
		}
		if tc.folder != nil {
			for _, row := range rows {
				if row.FolderID == nil || *row.FolderID != *tc.folder {
					t.Fatal("page leaked another folder")
				}
			}
		}
	}
	if w := f.request(http.MethodPatch, "/api/v1/document-folders/"+a.ID.String(), `{"name":"Signed customers"}`); w.Code != 200 {
		t.Fatalf("rename=%d", w.Code)
	}
	if w := f.request(http.MethodDelete, "/api/v1/document-folders/"+a.ID.String(), ""); w.Code != 409 {
		t.Fatalf("nonempty delete=%d", w.Code)
	}
	for _, d := range docs[:3] {
		f.move(t, d.ID, nil, 200)
	}
	if w := f.request(http.MethodDelete, "/api/v1/document-folders/"+a.ID.String(), ""); w.Code != 204 {
		t.Fatalf("empty delete=%d %s", w.Code, w.Body.String())
	}
	_, total := f.list(t, "")
	if total != 5 {
		t.Fatal("folder deletion removed documents")
	}
	for _, query := range []string{"?folder_id=", "?folder_id=not-a-uuid", "?folder_id=unfiled&folder_id=" + b.ID.String()} {
		if w := f.request(http.MethodGet, "/api/v1/documents"+query, ""); w.Code != 400 {
			t.Fatalf("ambiguous query=%d", w.Code)
		}
	}
	if w := f.request(http.MethodPut, "/api/v1/documents/"+docs[0].ID.String()+"/folder", `{}`); w.Code != 400 {
		t.Fatal("omitted folder_id silently unfiled document")
	}
}

func TestDocumentFoldersEnforceTenantAndCompositeForeignKeysE2E(t *testing.T) {
	a, b := folderSetup695(t), folderSetup695(t)
	af, bf := a.folder(t, "Customers"), b.folder(t, "Customers")
	ad, bd := a.document(t, "Owned", "draft"), b.document(t, "Foreign", "draft")
	a.move(t, ad.ID, &bf.ID, 404)
	a.move(t, bd.ID, &af.ID, 404)
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/documents?folder_id=" + bf.ID.String(), ""},
		{http.MethodPatch, "/api/v1/document-folders/" + bf.ID.String(), `{"name":"Changed"}`},
		{http.MethodDelete, "/api/v1/document-folders/" + bf.ID.String(), ""},
	} {
		if w := a.request(tc.method, tc.path, tc.body); w.Code != 404 {
			t.Fatalf("foreign access=%d", w.Code)
		}
	}
	rows, total := a.list(t, "")
	if total != 1 || len(rows) != 1 || rows[0].ID != ad.ID {
		t.Fatal("foreign document leaked")
	}
	for _, args := range [][]any{{ad.ID, a.org, bf.ID}, {bd.ID, a.org, af.ID}} {
		if _, err := a.pool.Exec(a.ctx, `INSERT INTO document_folder_memberships(document_id,org_id,folder_id) VALUES($1,$2,$3)`, args...); err == nil {
			t.Fatal("database accepted cross-tenant sidecar")
		}
	}
}

func TestDocumentFoldersViewerReadsSenderWritesE2E(t *testing.T) {
	f := folderSetup695(t)
	folder := f.folder(t, "Shared")
	doc := f.document(t, "Shared doc", "draft")
	for _, role := range []string{"viewer", "sender"} {
		u, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@folder.test", Name: "Synthetic member", Role: role})
		if err != nil {
			t.Fatal(err)
		}
		member := f
		member.cookie = dsrSessionCookieE2E(t, f.s, u.ID, u.SessionGeneration, time.Hour)
		if w := member.request(http.MethodGet, "/api/v1/document-folders", ""); w.Code != 200 {
			t.Fatalf("%s read=%d", role, w.Code)
		}
		status := 200
		if role == "viewer" {
			status = 403
		}
		member.move(t, doc.ID, &folder.ID, status)
		if role == "viewer" {
			for _, tc := range []struct{ method, path, body string }{{http.MethodPost, "/api/v1/document-folders", `{"name":"Forbidden"}`}, {http.MethodPatch, "/api/v1/document-folders/" + folder.ID.String(), `{"name":"Forbidden"}`}, {http.MethodDelete, "/api/v1/document-folders/" + folder.ID.String(), ""}} {
				if w := member.request(tc.method, tc.path, tc.body); w.Code != 403 {
					t.Fatalf("viewer write=%d", w.Code)
				}
			}
		}
	}
}

func folderPreservedState695(t *testing.T, f folderFixture695, id uuid.UUID) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object('document',to_jsonb(d),
 'policy',(SELECT to_jsonb(p) FROM document_signing_policy_sizes_v1 p WHERE p.document_id=d.id),
 'response',(SELECT to_jsonb(p) FROM html_creation_response_sizes_v1 p WHERE p.document_id=d.id),
 'report',(SELECT to_jsonb(p) FROM document_read_report_sizes_v1 p WHERE p.document_id=d.id),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e WHERE e.document_id=d.id))::text
 FROM documents d WHERE d.id=$1 AND d.org_id=$2`, id, f.org).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func TestDocumentFolderFilingPreservesCompletedSourceCachesAndEventsE2E(t *testing.T) {
	// Completion must pass the real immutable output/publication guards. A
	// synthetic status change cannot establish a completed source/cache tuple.
	q := newOwnedPublicReadFixtureV1(t)
	q.f.s.Sign.Storage = q.f.s.Storage
	sent, parties := q.createSentV1(t)
	ownedCreationAssertDrainedV1(t, q, 1)
	for index, party := range parties {
		rc := q.lookupV1(t, party.Token)
		notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := signerArticle13NoticeEvidence(rc, notice)
		if err != nil {
			t.Fatal(err)
		}
		result, err := q.f.s.Sign.Sign(q.f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic completed filing qualifier"})
		if closeErr := rc.CloseReadV1(); closeErr != nil {
			t.Fatal(closeErr)
		}
		q.assertObserversOnlyV1(t)
		if err != nil || result == nil || result.Completed != (index == len(parties)-1) {
			t.Fatal("genuine filing fixture failed all-party completion", err)
		}
	}
	f := folderFixture695{lifecycleAuthorizationFixture: q.f, cookie: q.cookie}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: sent.ID, OrgID: f.org})
	if err != nil || doc.Status != "completed" || !sameSignerDocumentSource(sent, doc) || !doc.CompletionEffectiveAtBound || !doc.CompletionEffectiveAt.Valid || !doc.CompletedAt.Valid || doc.CompletedAt != doc.CompletionEffectiveAt || !doc.FinalizationRetainUntil.Valid {
		t.Fatal("filing fixture lacks genuine frozen completion/source", err)
	}
	folder := f.folder(t, "Completed")
	before := folderPreservedState695(t, f, doc.ID)
	f.move(t, doc.ID, &folder.ID, 200)
	f.move(t, doc.ID, nil, 200)
	if after := folderPreservedState695(t, f, doc.ID); after != before {
		t.Fatal("filing changed completed document, timestamp, source caches or document event set")
	}
}

func TestDocumentFolderCredentialRecheckRollsBackWriteAndAuditE2E(t *testing.T) {
	f := folderSetup695(t)
	original := auth.SessionTransactionAuthorization(f.s.Cookies, f.cookie, auth.SessionPayload{UserID: f.user.ID, Generation: f.user.SessionGeneration}, f.org)
	calls := 0
	authorize := func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
		calls++
		if err := original(ctx, tx, user); err != nil {
			return err
		}
		if calls > 1 {
			return auth.ErrMutationCredentialExpired
		}
		return nil
	}
	_, err := f.s.folderService().Create(f.ctx, authoring.Actor{OrgID: f.org, UserID: f.user.ID, Authorize: authorize}, "Must roll back")
	if !errors.Is(err, auth.ErrMutationCredentialExpired) || calls != 2 {
		t.Fatal("original credential was not rechecked after mutation/audit")
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM document_folders WHERE org_id=$1)+(SELECT count(*) FROM events WHERE org_id=$1 AND kind='document_folder.created')`, f.org).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed credential left folder or audit")
	}
}

func TestDocumentFolderDeleteMoveRaceNeverDeletesDocumentsE2E(t *testing.T) {
	f := folderSetup695(t)
	doc := f.document(t, "Race fixture", "draft")
	authorize := auth.SessionTransactionAuthorization(f.s.Cookies, f.cookie, auth.SessionPayload{UserID: f.user.ID, Generation: f.user.SessionGeneration}, f.org)
	actor := authoring.Actor{OrgID: f.org, UserID: f.user.ID, Authorize: authorize}
	for i := 0; i < 4; i++ {
		folder := f.folder(t, fmt.Sprintf("Race%d", i))
		start := make(chan struct{})
		var wg sync.WaitGroup
		var removed, moved error
		wg.Add(2)
		go func() { defer wg.Done(); <-start; removed = f.s.folderService().Delete(f.ctx, actor, folder.ID) }()
		go func() { defer wg.Done(); <-start; moved = f.s.folderService().Move(f.ctx, actor, doc.ID, &folder.ID) }()
		close(start)
		wg.Wait()
		if !((removed == nil && errors.Is(moved, documentfolders.ErrNotFound)) || (moved == nil && errors.Is(removed, documentfolders.ErrNotEmpty))) {
			t.Fatalf("unexpected race result delete=%v move=%v", removed, moved)
		}
		if _, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org}); err != nil {
			t.Fatal("race deleted document")
		}
		if moved == nil {
			f.move(t, doc.ID, nil, 200)
			if err := f.s.folderService().Delete(f.ctx, actor, folder.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
}
