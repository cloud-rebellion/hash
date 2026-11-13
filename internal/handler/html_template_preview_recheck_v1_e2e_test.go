//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func htmlPreviewRecheckActorE2E(t *testing.T, f lifecycleAuthorizationFixture) authoring.Actor {
	t.Helper()
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	raw, err := f.s.Cookies.Verify(cookie)
	if err != nil {
		t.Fatal(err)
	}
	var credential auth.SessionPayload
	if err := json.Unmarshal(raw, &credential); err != nil {
		t.Fatal(err)
	}
	return authoring.Actor{OrgID: f.org, UserID: f.user.ID,
		Authorize: auth.SessionTransactionAuthorization(f.s.Cookies, cookie, credential, f.org)}
}

// A generated image, rich source and CSS exercise real immutable-model work
// without copying a customer's document or artwork into the test fixture. The
// ordinary native factory keeps its unchanged 2GiB parent limit. No renderer,
// fake admission, caller-supplied resource credit or PDF worker is involved.
func htmlPreviewRecheckRichTemplateE2E(t *testing.T, f lifecycleAuthorizationFixture) *generated.Template {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 384, 384))
	state := uint32(1)
	for y := 0; y < 384; y++ {
		for x := 0; x < 384; x++ {
			state ^= state << 13
			state ^= state >> 17
			state ^= state << 5
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(state), G: uint8(state >> 8), B: uint8(state >> 16), A: 255})
		}
	}
	var imageBytes bytes.Buffer
	if err := png.Encode(&imageBytes, img); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(imageBytes.Bytes())
	var css strings.Builder
	for i := 0; i < 128; i++ {
		fmt.Fprintf(&css, ".preview-%03d{color:#151515;font-size:10pt;margin:0 0 3px;}\n", i)
	}
	master, err := json.Marshal(htmlmaster.Master{SchemaVersion: 1,
		HTML: `<main><img src="hash-asset:preview_image" alt="Synthetic preview image">` +
			strings.Repeat(`<p>Retained preview source verification.</p>`, 388) + `</main>`,
		CSS: css.String(), Assets: []htmlmaster.Asset{{Name: "preview_image", MediaType: "image/png",
			SHA256: hex.EncodeToString(digest[:]), DataBase64: base64.StdEncoding.EncodeToString(imageBytes.Bytes())}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{
		Name: "Synthetic rich preview", HTMLMasterJSON: master, VariablesJSON: json.RawMessage(`{}`),
	}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create rich preview template=%d %s", w.Code, w.Body.String())
	}
	var response templateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	template, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: response.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func assertHTMLPreviewRecheckConsumersClosedE2E(t *testing.T, f lifecycleAuthorizationFixture) {
	t.Helper()
	pending := f.s.HTMLCreationSessions.PendingV1()
	snapshot := htmlAuthoringNativeSnapshotE2E(t, f.s)
	if pending.HTMLCanonicalConsumers != 0 || pending.HTMLInputProducers != 0 || pending.WorkSessions != 0 ||
		snapshot.Organisation.ParentBytes != 0 || snapshot.Organisation.DBStagingBytes != 0 {
		t.Fatalf("preview recheck retained source work: pending=%+v resources=%+v", pending, snapshot)
	}
}

func TestHTMLTemplatePreviewFinalRecheckFitsTwoGiBWithoutPreparingAgainE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := htmlPreviewRecheckRichTemplateE2E(t, f)
	actor := htmlPreviewRecheckActorE2E(t, f)
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	digest := hex.EncodeToString(template.HtmlContentSha256)
	content, closeContent, err := f.s.loadHTMLTemplatePreview(ctx, actor, template.ID, template.Version, digest, nil, nil)
	if err != nil {
		t.Fatal("initial materialization preparation:", err)
	}
	defer closeContent()
	held := htmlAuthoringNativeSnapshotE2E(t, f.s)
	if content.SHA256 != digest || held.Organisation.ParentBytes < 1<<30 {
		t.Fatalf("rich fixture did not retain its real preparation: %+v", held)
	}
	// The old final call duplicated full preparation while the PDF's original
	// content remained live. It must still be refused; the limit is not raised.
	_, closeDuplicate, duplicateErr := f.s.loadHTMLTemplatePreview(ctx, actor, template.ID, template.Version, digest, nil, nil)
	if closeDuplicate != nil {
		closeDuplicate()
	}
	if !errors.Is(duplicateErr, workguard.ErrUnavailableV1) {
		t.Fatalf("duplicate full preparation did not hit the original cap: %v", duplicateErr)
	}
	if after := htmlAuthoringNativeSnapshotE2E(t, f.s); after.Organisation.ParentBytes != held.Organisation.ParentBytes {
		t.Fatal("failed duplicate changed the original content reservation")
	}
	closeRecheck, err := f.s.recheckHTMLTemplatePreview(ctx, actor, template.ID, template.Version, digest)
	if err != nil {
		t.Fatal("source-only final recheck:", err)
	}
	closeRecheck()
	if after := htmlAuthoringNativeSnapshotE2E(t, f.s); after.Organisation.ParentBytes != held.Organisation.ParentBytes ||
		f.s.HTMLCreationSessions.PendingV1().HTMLCanonicalConsumers == 0 {
		t.Fatal("final recheck released or replaced the live original content")
	}
	closeContent()
	assertHTMLPreviewRecheckConsumersClosedE2E(t, f)
}

func TestHTMLTemplatePreviewFinalRecheckKeepsSourceAndAuthorityGuardsE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	for _, change := range []string{"revision", "archive", "revocation", "other_organisation"} {
		t.Run(change, func(t *testing.T) {
			f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
			template := createHTMLTemplateE2E(t, f)
			actor := htmlPreviewRecheckActorE2E(t, f)
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			digest := hex.EncodeToString(template.HtmlContentSha256)
			_, closeContent, err := f.s.loadHTMLTemplatePreview(ctx, actor, template.ID, template.Version, digest, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer closeContent()
			switch change {
			case "revision":
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				updated := submitHTMLTemplateE2E(t, f, "update", template.ID, htmlTemplateInputE2E(t, template.Version, "Changed during preview"), cookie)
				if updated.Code != http.StatusOK {
					t.Fatalf("change source while original content is live=%d %s", updated.Code, updated.Body.String())
				}
			case "archive":
				err = f.q.ArchiveTemplate(ctx, generated.ArchiveTemplateParams{ID: template.ID, OrgID: f.org})
			case "revocation":
				_, err = f.q.RevokeUserSessions(ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
			case "other_organisation":
				actor.OrgID = uuid.New()
			}
			if err != nil {
				t.Fatal(err)
			}
			closeRecheck, err := f.s.recheckHTMLTemplatePreview(ctx, actor, template.ID, template.Version, digest)
			if closeRecheck != nil {
				closeRecheck()
			}
			if err == nil {
				t.Fatal("final recheck accepted changed source or revoked authority")
			}
			closeContent()
			assertHTMLPreviewRecheckConsumersClosedE2E(t, f)
		})
	}
}
