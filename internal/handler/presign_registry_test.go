// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestPresignJSONRejectsAmbiguousAuthorityInputs(t *testing.T) {
	id := "11597520-8a53-4c1e-af60-c38b2a739114"
	valid := `{"request_id":"` + id + `","expected_org_id":"` + id + `","expected_user_id":"` + id + `","reference":{"id":"` + id + `","revision":1,"sha256":"` + strings.Repeat("a", 64) + `"},"confirmed":true}`
	for name, body := range map[string]string{
		"canonical":    valid,
		"upper UUID":   strings.Replace(valid, id, strings.ToUpper(id), 1),
		"compact UUID": strings.Replace(valid, id, strings.ReplaceAll(id, "-", ""), 1),
		"URN UUID":     strings.Replace(valid, id, "urn:uuid:"+id, 1),
		"deep null":    strings.Replace(valid, `"revision":1`, `"revision":null`, 1),
		"unknown":      strings.Replace(valid, `"confirmed":true`, `"confirmed":true,"server_override":true`, 1),
		"case alias":   strings.Replace(valid, `"confirmed"`, `"CONFIRMED"`, 1),
		"duplicate":    strings.Replace(valid, `"confirmed":true`, `"confirmed":false,"confirmed":true`, 1),
		"trailing":     valid + `{}`,
		"bad Unicode":  strings.Replace(valid, strings.Repeat("a", 64), `\uD800`, 1),
		"oversize":     valid + strings.Repeat(" ", maxSignerJSONBody),
	} {
		t.Run(name, func(t *testing.T) {
			var in presignregistry.ResourceMutationInput
			err := decodePresignJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &in)
			if name == "canonical" {
				if err != nil || !in.Confirmed {
					t.Fatalf("valid input rejected: %v", err)
				}
			} else if !errors.Is(err, presignregistry.ErrInvalid) {
				t.Fatalf("ambiguous input accepted: %v", err)
			}
		})
	}
}

func TestPresignJSONRequiresCanonicalQuotedCRMGeneration(t *testing.T) {
	for _, value := range []string{`"1"`, `"9007199254740993"`, `1`, `"01"`, `"+1"`, `"1e2"`, `null`, `"9223372036854775808"`} {
		t.Run(value, func(t *testing.T) {
			var out struct {
				CRM presignregistry.CRMScope `json:"crm"`
			}
			err := decodePresignJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"crm":{"generation":`+value+`}}`)), &out)
			want := value == `"1"` || value == `"9007199254740993"`
			if (err == nil) != want {
				t.Fatalf("quoted generation admission mismatch: %v", err)
			}
		})
	}
}

func TestPresignPathsRejectAliasedAndAmbiguousRevisions(t *testing.T) {
	for _, suffix := range []string{"", "?revision=1", "?revision=1000000", "?revision=01", "?revision=0", "?revision=+1", "?revision=1&revision=2", "?revision=1&ignored=1", "?revision=%zz", "?ignored=1", "?revision=1;ignored=2"} {
		t.Run(suffix, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/presign/workflows/test"+suffix, nil)
			_, err := presignRevision(r)
			want := suffix == "" || suffix == "?revision=1" || suffix == "?revision=1000000"
			if (err == nil) != want {
				t.Fatalf("query admission mismatch: %v", err)
			}
		})
	}
	id := uuid.New()
	for _, raw := range []string{id.String(), strings.ToUpper(id.String()), strings.ReplaceAll(id.String(), "-", ""), uuid.Nil.String()} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("id", raw)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
		_, err := presignUUIDParam(r, "id")
		if (err == nil) != (raw == id.String()) {
			t.Fatal("noncanonical path admitted")
		}
	}
}

func TestPresignActorRequiresCapturedSignedSession(t *testing.T) {
	cookies, err := auth.NewSignedCookie(strings.Repeat("42", 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Cookies: cookies}
	org, user := uuid.New(), uuid.New()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/presign/self-grants/create", nil)
	ctx := context.WithValue(r.Context(), auth.UserIDKey, user)
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.TokenScopesKey, []string{"admin"})
	r = r.WithContext(ctx)
	if _, err = s.presignActor(r); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatal("API identity substituted for a signed session")
	}
	payload, _ := json.Marshal(auth.SessionPayload{UserID: uuid.New(), Generation: 0})
	r.AddCookie(cookies.Cookie(SessionCookieName, cookies.Mint(payload, time.Hour), time.Hour))
	if _, err = s.presignActor(r); !errors.Is(err, auth.ErrMutationPermissionRevoked) {
		t.Fatal("different named signer admitted")
	}
	r.Header.Del("Cookie")
	payload, _ = json.Marshal(auth.SessionPayload{UserID: user, Generation: 0})
	r.AddCookie(cookies.Cookie(SessionCookieName, cookies.Mint(payload, time.Hour), time.Hour))
	actor, err := s.presignActor(r)
	if err != nil || actor.UserID() != user || actor.OrgID() != org {
		t.Fatalf("actual original session rejected: %v", err)
	}
}

func TestPresignRecoveryErrorsDoNotClaimAnUnconfirmedOutcome(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
	}{{presignregistry.ErrNotFound, 404}, {presignregistry.ErrConflict, 409}, {presignregistry.ErrUnavailable, 503}, {presignregistry.ErrAudit, 500}, {errors.Join(presignregistry.ErrAudit, pgx.ErrNoRows), 500}, {errors.Join(presignregistry.ErrAudit, auth.ErrMutationCredentialExpired), 500}, {auth.ErrMutationCredentialExpired, 401}, {auth.ErrMutationPermissionRevoked, 403}} {
		w := httptest.NewRecorder()
		writePresignError(w, test.err)
		if w.Code != test.status {
			t.Fatalf("status=%d", w.Code)
		}
		var result map[string]any
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || result["error"] == nil || result["state"] != nil {
			t.Fatal("refusal fabricated a committed/closed outcome")
		}
	}
}
