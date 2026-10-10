// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
)

func htmlPreviewReceiptFixture(t *testing.T) (*Server, *http.Request, auth.SessionUser, htmlTemplatePreviewReceipt) {
	t.Helper()
	cookies, err := auth.NewSignedCookie(strings.Repeat("14", 32))
	if err != nil {
		t.Fatal(err)
	}
	user := auth.SessionUser{UserID: uuid.New(), OrgID: uuid.New(), Role: string(auth.RoleOwner)}
	payload, _ := json.Marshal(auth.SessionPayload{UserID: user.UserID})
	cookie := cookies.Mint(payload, time.Hour)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	now := time.Now().UTC().Add(-time.Second)
	receipt := htmlTemplatePreviewReceipt{SchemaVersion: 1, PreviewID: uuid.New(), OrgID: user.OrgID,
		ReviewerID: user.UserID, TemplateID: uuid.New(), Version: 3,
		TemplateContentSHA256: strings.Repeat("a", 64), MaterializationSHA256: strings.Repeat("b", 64),
		PDFSHA256: strings.Repeat("c", 64), PageCount: 2, SessionSHA256: htmlPreviewSessionSHA256(cookie),
		IssuedAt: now, ExpiresAt: now.Add(htmlTemplatePreviewTTL)}
	return &Server{Cookies: cookies}, r, user, receipt
}

func purposeMintHTMLPreviewPayload(t *testing.T, s *Server, payload []byte) string {
	t.Helper()
	token, err := s.Cookies.MintPurpose(htmlTemplatePreviewPurpose, payload, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestHTMLTemplatePreviewReceiptBindsOriginalSessionAndArtifact(t *testing.T) {
	s, r, user, receipt := htmlPreviewReceiptFixture(t)
	token, err := s.mintHTMLTemplatePreviewReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	validate := func(request *http.Request, actor auth.SessionUser, template uuid.UUID, version int32, content, pdf, proof string) error {
		_, err := s.validateHTMLTemplatePreviewReceipt(request, actor, template, version, content, pdf, proof)
		return err
	}
	if err := validate(r, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token); err != nil {
		t.Fatal("valid preview receipt was refused")
	}
	cases := map[string]func() error{
		"different tenant": func() error {
			changed := user
			changed.OrgID = uuid.New()
			return validate(r, changed, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token)
		},
		"different owner": func() error {
			changed := user
			changed.UserID = uuid.New()
			return validate(r, changed, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token)
		},
		"sender cannot approve": func() error {
			changed := user
			changed.Role = string(auth.RoleSender)
			return validate(r, changed, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token)
		},
		"different template": func() error {
			return validate(r, user, uuid.New(), receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token)
		},
		"different revision": func() error {
			return validate(r, user, receipt.TemplateID, receipt.Version+1, receipt.TemplateContentSHA256, receipt.PDFSHA256, token)
		},
		"different master and defaults": func() error {
			return validate(r, user, receipt.TemplateID, receipt.Version, strings.Repeat("d", 64), receipt.PDFSHA256, token)
		},
		"different PDF": func() error {
			return validate(r, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, strings.Repeat("e", 64), token)
		},
		"new login cookie": func() error {
			next := httptest.NewRequest(http.MethodPost, "/", nil)
			next.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "different-admitted-cookie"})
			return validate(next, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token)
		},
		"missing cookie": func() error {
			return validate(httptest.NewRequest(http.MethodPost, "/", nil), user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token)
		},
		"ordinary session token": func() error {
			cookie, _ := r.Cookie(SessionCookieName)
			return validate(r, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, cookie.Value)
		},
		"different token purpose": func() error {
			payload, _ := json.Marshal(receipt)
			proof, err := s.Cookies.MintPurpose("hash.other-preview.v1", payload, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			return validate(r, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, proof)
		},
		"oversized token": func() error {
			return validate(r, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, strings.Repeat("x", maxHTMLPreviewReceipt+1))
		},
		"corrupt signature": func() error {
			return validate(r, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token+"x")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(run(), errHTMLTemplatePreviewReceipt) {
				t.Fatal("mismatched proof was accepted")
			}
		})
	}
}

func TestHTMLTemplatePreviewReceiptRefusesSignedAmbiguousOrInvalidPayload(t *testing.T) {
	s, r, user, receipt := htmlPreviewReceiptFixture(t)
	canonical, _ := json.Marshal(receipt)
	invalidJSON := map[string][]byte{
		"unknown field": append(bytes.TrimSuffix(bytes.Clone(canonical), []byte("}")), []byte(`,"extra":true}`)...),
		"case alias":    append(bytes.TrimSuffix(bytes.Clone(canonical), []byte("}")), []byte(`,"VERSION":3}`)...),
		"duplicate":     append(bytes.TrimSuffix(bytes.Clone(canonical), []byte("}")), []byte(`,"version":3}`)...),
		"trailing JSON": append(bytes.Clone(canonical), []byte(`{}`)...),
		"null digest":   bytes.Replace(canonical, []byte(`"pdf_sha256":"`+receipt.PDFSHA256+`"`), []byte(`"pdf_sha256":null`), 1),
	}
	for name, payload := range invalidJSON {
		t.Run(name, func(t *testing.T) {
			token := purposeMintHTMLPreviewPayload(t, s, payload)
			if _, err := s.validateHTMLTemplatePreviewReceipt(r, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token); !errors.Is(err, errHTMLTemplatePreviewReceipt) {
				t.Fatal("ambiguous signed receipt was accepted")
			}
		})
	}
	mutations := map[string]func(*htmlTemplatePreviewReceipt){
		"schema":                       func(p *htmlTemplatePreviewReceipt) { p.SchemaVersion = 2 },
		"nil preview":                  func(p *htmlTemplatePreviewReceipt) { p.PreviewID = uuid.Nil },
		"nil tenant":                   func(p *htmlTemplatePreviewReceipt) { p.OrgID = uuid.Nil },
		"nil reviewer":                 func(p *htmlTemplatePreviewReceipt) { p.ReviewerID = uuid.Nil },
		"nil template":                 func(p *htmlTemplatePreviewReceipt) { p.TemplateID = uuid.Nil },
		"version":                      func(p *htmlTemplatePreviewReceipt) { p.Version = 0 },
		"no pages":                     func(p *htmlTemplatePreviewReceipt) { p.PageCount = 0 },
		"too many pages":               func(p *htmlTemplatePreviewReceipt) { p.PageCount = 501 },
		"uppercase materialization":    func(p *htmlTemplatePreviewReceipt) { p.MaterializationSHA256 = strings.Repeat("B", 64) },
		"malformed session commitment": func(p *htmlTemplatePreviewReceipt) { p.SessionSHA256 = strings.Repeat("z", 64) },
		"future issued": func(p *htmlTemplatePreviewReceipt) {
			p.IssuedAt = time.Now().Add(time.Hour)
			p.ExpiresAt = p.IssuedAt.Add(time.Minute)
		},
		"zero issued":            func(p *htmlTemplatePreviewReceipt) { p.IssuedAt = time.Time{} },
		"expired inner deadline": func(p *htmlTemplatePreviewReceipt) { p.ExpiresAt = time.Now().Add(-time.Millisecond) },
		"overlong inner lifetime": func(p *htmlTemplatePreviewReceipt) {
			p.ExpiresAt = p.IssuedAt.Add(htmlTemplatePreviewTTL + time.Nanosecond)
		},
		"deadline before issued": func(p *htmlTemplatePreviewReceipt) { p.ExpiresAt = p.IssuedAt.Add(-time.Second) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			mutate(&changed)
			payload, _ := json.Marshal(changed)
			token := purposeMintHTMLPreviewPayload(t, s, payload)
			if _, err := s.validateHTMLTemplatePreviewReceipt(r, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token); !errors.Is(err, errHTMLTemplatePreviewReceipt) {
				t.Fatal("invalid signed receipt was accepted")
			}
		})
	}
}

func TestHTMLTemplatePreviewReceiptDeadlineIsStrictAndRetainedThroughAuthorization(t *testing.T) {
	_, _, _, receipt := htmlPreviewReceiptFixture(t)
	if !errors.Is(receipt.validate(receipt.ExpiresAt), errHTMLTemplatePreviewReceipt) || receipt.validate(receipt.ExpiresAt.Add(-time.Nanosecond)) != nil {
		t.Fatal("exact deadline was not refused")
	}
	called := false
	receipt.ExpiresAt = time.Now().Add(40 * time.Millisecond)
	original := func(context.Context, pgx.Tx, *generated.User) error {
		called = true
		time.Sleep(time.Until(receipt.ExpiresAt) + time.Millisecond)
		return nil
	}
	if err := htmlTemplatePreviewReceiptAuthorization(original, receipt)(context.Background(), nil, nil); !errors.Is(err, errHTMLTemplatePreviewReceipt) || !called {
		t.Fatal("expiry during the original authorization callback was accepted")
	}
	called = false
	if err := htmlTemplatePreviewReceiptAuthorization(original, receipt)(context.Background(), nil, nil); !errors.Is(err, errHTMLTemplatePreviewReceipt) || called {
		t.Fatal("expired proof entered the original authorization callback")
	}
}

func TestHTMLTemplatePreviewReceiptMissingDependenciesRefuseWithoutPanic(t *testing.T) {
	s, r, user, receipt := htmlPreviewReceiptFixture(t)
	token, err := s.mintHTMLTemplatePreviewReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range []*Server{nil, {}} {
		if _, err := server.validateHTMLTemplatePreviewReceipt(r, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token); !errors.Is(err, errHTMLTemplatePreviewReceipt) {
			t.Fatal("missing signer accepted a receipt")
		}
		if _, err := server.mintHTMLTemplatePreviewReceipt(receipt); !errors.Is(err, errHTMLTemplatePreviewReceipt) {
			t.Fatal("missing signer minted a receipt")
		}
	}
	if _, err := s.validateHTMLTemplatePreviewReceipt(nil, user, receipt.TemplateID, receipt.Version, receipt.TemplateContentSHA256, receipt.PDFSHA256, token); !errors.Is(err, errHTMLTemplatePreviewReceipt) {
		t.Fatal("missing request accepted a receipt")
	}
	if err := htmlTemplatePreviewReceiptAuthorization(nil, receipt)(context.Background(), nil, nil); !errors.Is(err, errHTMLTemplatePreviewReceipt) {
		t.Fatal("missing retained authority accepted a receipt")
	}
}

func TestHTMLTemplatePreviewSamplesDoNotChangeApprovedDefaultsOrSections(t *testing.T) {
	master, _ := json.Marshal(htmlmaster.Master{SchemaVersion: 1,
		HTML:     `<p><span data-hash-value="customer"></span></p><div data-hash-section="scope"></div>`,
		Values:   []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 120}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Saved approved terms", MaxChars: 240}}})
	content, err := htmlmaster.CanonicalTemplate(master, []byte(`{"customer":"Saved default AB"}`))
	if err != nil {
		t.Fatal(err)
	}
	defaultsBefore := bytes.Clone(content.DefaultsJSON)
	baseline, err := materializeHTMLTemplatePreview(content, nil)
	if err != nil {
		t.Fatal(err)
	}
	sampled, err := materializeHTMLTemplatePreview(content, htmlStringMap{"customer": `<script>sample & co</script>`})
	if err != nil || !strings.Contains(sampled.HTML, "&lt;script&gt;sample &amp; co&lt;/script&gt;") ||
		!strings.Contains(sampled.HTML, "Saved approved terms") || sampled.ContentDigest == baseline.ContentDigest ||
		!bytes.Equal(content.DefaultsJSON, defaultsBefore) {
		t.Fatal("samples mutated approved defaults/sections or escaped the inert output")
	}
	if _, err := materializeHTMLTemplatePreview(content, htmlStringMap{"undeclared": "sample"}); !errors.Is(err, htmlmaster.ErrInvalid) {
		t.Fatal("undeclared sample was accepted")
	}
	blank, err := htmlmaster.CanonicalTemplate(master, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := materializeHTMLTemplatePreview(blank, nil); !errors.Is(err, htmlmaster.ErrMissingValues) {
		t.Fatal("required blank default silently became sample prose")
	}
	if _, err := materializeHTMLTemplatePreview(blank, htmlStringMap{"customer": "Explicit sample AB"}); err != nil || string(blank.DefaultsJSON) != "{}" {
		t.Fatal("explicit required sample could not preview without mutating defaults")
	}
}

func TestHTMLTemplatePreviewInputRefusesProseOverridesAndTextCoercion(t *testing.T) {
	for _, body := range []string{
		`{"expected_version":3,"expected_content_sha256":"a","sections":{"scope":"changed"}}`,
		`{"expected_version":3,"expected_content_sha256":"a","values":null}`,
		`{"expected_version":3,"expected_content_sha256":"a","values":{"customer":null}}`,
		`{"expected_version":3,"expected_content_sha256":"a","values":{"customer":42}}`,
		`{"expected_version":3,"EXPECTED_VERSION":4,"expected_content_sha256":"a"}`,
		`{"expected_version":3,"expected_version":4,"expected_content_sha256":"a"}`,
		`{"expected_version":3,"expected_content_sha256":"a"}{}`,
	} {
		var in htmlTemplatePreviewInput
		if err := decodeSignerJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &in); err == nil {
			t.Fatal("ambiguous preview request was accepted")
		}
	}
}
