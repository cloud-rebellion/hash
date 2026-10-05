//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestRenderedDSRDeletedArchiveReviewE2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Skip("set HASH_BROWSER_E2E=1 with built frontend and cached Chromium")
	}
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	var err error
	s.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(bytes.Repeat([]byte{41}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.Collab = collab.NewHub(q)
	s.Collab.FlushEvery = 0
	defer s.Collab.Shutdown(context.Background())

	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org, SenderID: user, Name: "Deleted DSR archive fixture",
		BlocksJson:    json.RawMessage(`{"version":1,"blocks":[{"id":"privacy-seed","type":"paragraph","text":"Current fixture document"}]}`),
		VariablesJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Recovery exports opaque bytes without decoding or inventing a legacy
	// generation. The embedded zero/non-UTF8 bytes catch text-based export loss.
	history := []byte{1, 42, 0, 255, 0, 7, 13, 10}
	var archive uuid.UUID
	if err = pool.QueryRow(ctx, `INSERT INTO collab_recovery_archives
		(document_id,observed_canonical_generation,origin,ydoc_state,recovered_by)
		VALUES($1,1,'persisted',$2,$3) RETURNING id`, doc.ID, history, user).Scan(&archive); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
		OrgID: org, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true},
		SubjectEmail: "archive-fixture@example.test", SubjectName: "Archive fixture",
		Kind: "access", RequestedVia: "sender", RequestedNote: "Review the retained document archive before closing this access request.",
		PayloadJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = q.DeleteDraftDocument(ctx, generated.DeleteDraftDocumentParams{ID: doc.ID, OrgID: org}); err != nil {
		t.Fatal(err)
	}
	deleted, err := q.GetDocumentByID(ctx, doc.ID)
	if err != nil || !deleted.DeletedAt.Valid {
		t.Fatalf("fixture draft was not soft-deleted: err=%v", err)
	}

	root, err := filepath.Abs("../../frontend/build")
	if err != nil {
		t.Fatal(err)
	}
	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("build frontend before browser test")
	}
	s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(root))
	s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if info, err := os.Stat(filepath.Join(root, clean)); err == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	server := httptest.NewUnstartedServer(nil)
	s.PublicURL = "https://" + server.Listener.Addr().String()
	server.Config.Handler = s.Routes()
	server.StartTLS()
	defer server.Close()
	mint := func(userID uuid.UUID) string {
		payload, err := json.Marshal(auth.SessionPayload{UserID: userID})
		if err != nil {
			t.Fatal(err)
		}
		return s.Cookies.Mint(payload, time.Hour)
	}
	fixture, err := json.Marshal(map[string]any{
		"base": server.URL, "documentID": doc.ID.String(), "archiveID": archive.String(),
		"cookieName": SessionCookieName, "cookie": mint(user), "requestID": dsr.ID.String(),
		"archiveBytesBase64": base64.StdEncoding.EncodeToString(history),
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "bun", "scripts/verify-dsr-archives.ts")
	cmd.Dir = "../../frontend"
	cmd.Stdin = bytes.NewReader(fixture)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("rendered deleted-document archive acceptance: %v", err)
	}

	var retained []byte
	var historyGeneration pgtype.Int8
	if err = pool.QueryRow(ctx, `SELECT ydoc_state,history_generation FROM collab_recovery_archives
		WHERE id=$1 AND document_id=$2`, archive, doc.ID).Scan(&retained, &historyGeneration); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if !bytes.Equal(retained, history) || historyGeneration.Valid {
		t.Fatal("privacy-deferred deletion changed opaque bytes or invented a history generation")
	}
	request, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: dsr.ID, OrgID: org})
	if err != nil || request.Status != "open" {
		t.Fatalf("archive review changed the access request: err=%v", err)
	}
	generation, err := q.GetDocumentCollabGeneration(ctx, generated.GetDocumentCollabGenerationParams{ID: doc.ID, OrgID: org})
	if err != nil || generation != 1 {
		t.Fatalf("archive review restarted deleted shared editing: generation=%d err=%v", generation, err)
	}
	var downloads, deletions, recoveries int
	if err = pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind=$2),count(*) FILTER (WHERE kind=$3),
		count(*) FILTER (WHERE kind=$4) FROM events WHERE document_id=$1`, doc.ID,
		audit.KindCollabArchiveDownloaded, audit.KindCollabArchiveDeleted, audit.KindCollabRecovered).Scan(&downloads, &deletions, &recoveries); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if downloads != 1 || deletions != 0 || recoveries != 0 {
		t.Fatalf("archive review audit counts: downloads=%d deletions=%d recoveries=%d", downloads, deletions, recoveries)
	}

	viewer, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org, Email: uuid.NewString() + "@viewer.test", Name: "Archive viewer", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	foreignOrg, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Foreign archive fixture " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	foreignOwner, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Email: uuid.NewString() + "@owner.test", Name: "Foreign owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []struct {
		name string
		id   uuid.UUID
		want int
	}{{"viewer", viewer.ID, http.StatusForbidden}, {"foreign-owner", foreignOwner.ID, http.StatusNotFound}} {
		for _, suffix := range []string{"", "/archives/" + archive.String()} {
			t.Run(identity.name+suffix, func(t *testing.T) {
				requestCtx, stop := context.WithTimeout(ctx, 10*time.Second)
				defer stop()
				req, err := http.NewRequestWithContext(requestCtx, http.MethodGet,
					server.URL+"/api/v1/documents/"+doc.ID.String()+"/collab/recovery"+suffix, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: mint(identity.id)})
				response, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != identity.want || bytes.Contains(body, history) {
					t.Fatalf("archive permission status=%d want=%d", response.StatusCode, identity.want)
				}
			})
		}
	}
}
