// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func signerLocalizedPrivacyFixtureV1() (*Server, *sign.RecipientContext) {
	org, document := uuid.New(), uuid.New()
	epoch := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	return &Server{OperatorName: "Operator AB", PrivacyContact: "privacy@operator.example", SupervisoryAuthority: "Configured authority", PrivacyPolicyURL: "https://operator.example/privacy"},
		&sign.RecipientContext{
			Recipient:     &generated.GetRecipientByTokenHashRow{ID: uuid.New(), Locale: "en"},
			Document:      boundArticle13TestDocument(document, org, "Example agreement", epoch),
			ControllerOrg: &generated.Org{ID: org, Name: "Controller AB"},
			LawfulBasisConfirmation: &generated.DocumentLawfulBasisConfirmation{DocumentID: document, OrgID: org, LawfulBasis: "contract",
				ConfirmedAt: pgtype.Timestamptz{Time: epoch, Valid: true}, ControllerName: "Controller AB", ControllerContact: "controller@example.test"},
		}
}

func signerLocalizedPrivacyRequestV1(action string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/sign/example/"+action+"?locale=en", nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("token", "example")
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
}

func TestSignerPrivacyLocaleV1UsesSavedRecipientNotBrowserHints(t *testing.T) {
	server, rc := signerLocalizedPrivacyFixtureV1()
	req := signerLocalizedPrivacyRequestV1("context")
	req.Header.Set("Accept-Language", "sv-SE,sv;q=0.9")
	req.AddCookie(&http.Cookie{Name: "hash_staff_locale", Value: "sv"})
	en, err := server.signerPrivacyNotice(req, rc)
	if err != nil || en.CopyLocale != "en" || en.Copy != article13.RenderedCopyV1(rc.Document.Name) {
		t.Fatal("browser hints changed server-bound English notice", err)
	}
	rc.Recipient.Locale = "sv"
	sv, err := server.signerPrivacyNotice(req, rc)
	material, _ := article13.LocalizedNoticeV1(rc.Document.Name, rc.Document.LawfulBasis, "sv")
	if err != nil || sv.CopyLocale != "sv" || sv.PurposeSummary != material.PurposeSummary || sv.LegalBasis != material.LegalBasisDisclosure || sv.Copy != material.Copy || sv.NoticeDigest == en.NoticeDigest {
		t.Fatal("server-selected Swedish material or fresh digest missing", err)
	}
	encoded, err := json.Marshal(sv)
	if err != nil || !strings.Contains(string(encoded), `"copy_locale":"sv"`) {
		t.Fatal("view-only locale metadata missing", err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, sv)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := evidence.Snapshot.CanonicalJSON()
	if err != nil || strings.Contains(string(canonical), `"copy_locale"`) {
		t.Fatal("view metadata changed canonical snapshot shape", err)
	}
	for _, locale := range []string{"", "fi", "sv-SE", "SV"} {
		rc.Recipient.Locale = locale
		notice, err := server.signerPrivacyNotice(req, rc)
		if err != nil || notice.CopyLocale != "en" || notice.NoticeDigest != en.NoticeDigest {
			t.Fatalf("unknown locale %q did not retain exact EN fallback: %v", locale, err)
		}
	}
}

func TestSignerPrivacyLocaleV1StaleEnglishAcknowledgementCannotAuthorizeSwedishAction(t *testing.T) {
	server, rc := signerLocalizedPrivacyFixtureV1()
	en, err := server.signerPrivacyNotice(signerLocalizedPrivacyRequestV1("context"), rc)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := signerArticle13NoticeEvidence(rc, en)
	if err != nil {
		t.Fatal(err)
	}
	rc.Recipient.Locale = "sv"
	sv, err := server.signerPrivacyNotice(signerLocalizedPrivacyRequestV1("context"), rc)
	if err != nil {
		t.Fatal(err)
	}
	// These public action builders share this exact server notice/header gate.
	for _, action := range []string{"sign", "accept", "decline", "comments", "view", "fields", "ai"} {
		req := signerLocalizedPrivacyRequestV1(action)
		req.Header.Set(signerNoticeDigestHeader, en.NoticeDigest)
		response := httptest.NewRecorder()
		if _, ok := server.requireSignerNoticeAcknowledgement(response, req, rc); ok || response.Code != http.StatusPreconditionRequired {
			t.Fatalf("stale English header admitted %s", action)
		}
		req.Header.Set(signerNoticeDigestHeader, sv.NoticeDigest)
		accepted, ok := server.requireSignerNoticeAcknowledgement(httptest.NewRecorder(), req, rc)
		if !ok || accepted.Digest != sv.NoticeDigest || accepted.Snapshot.Copy != sv.Copy {
			t.Fatalf("current Swedish header was not bound to actual copy for %s", action)
		}
	}
	if err := historical.Validate(); err != nil {
		t.Fatal("previously captured English evidence no longer verifies", err)
	}
}
