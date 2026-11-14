//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/jackc/pgx/v5/pgconn"
)

func email128Preferences(t *testing.T, f folderFixture695) emailtemplates.PreferencesV1 {
	t.Helper()
	response := f.request(http.MethodGet, "/api/v1/email-preferences", "")
	if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("preference read refused", response.Code)
	}
	var out emailtemplates.PreferencesV1
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil || out.SchemaVersion != 1 || out.OrgID != f.org {
		t.Fatal("preference identity malformed", err)
	}
	return out
}

func TestWorkspaceEmail128OwnerCASAndTenantE2E(t *testing.T) {
	f := email720Fixture(t)
	other := email720Fixture(t)
	before := email128Preferences(t, f)
	if before.Locale != "en" || before.Revision != 0 || before.UpdatedAt != nil {
		t.Fatal("absent settings did not preserve legacy English")
	}
	var stored, mailBefore int64
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM org_email_preferences_v1 WHERE org_id=$1),(SELECT count(*) FROM email_deliveries)`, f.org).Scan(&stored, &mailBefore); err != nil || stored != 0 {
		t.Fatal("GET created settings", err)
	}
	save := f.request(http.MethodPut, "/api/v1/email-preferences", `{"expected_revision":0,"locale":"sv"}`)
	if save.Code != 200 {
		t.Fatal("valid owner save refused", save.Code)
	}
	one := email128Preferences(t, f)
	if one.Locale != "sv" || one.Revision != 1 || one.UpdatedAt == nil {
		t.Fatal("saved preference lost identity/revision")
	}
	if response := f.request(http.MethodPut, "/api/v1/email-preferences", `{"expected_revision":0,"locale":"en"}`); response.Code != 409 {
		t.Fatal("stale owner save overwrote preferences", response.Code)
	}
	if response := f.request(http.MethodPut, "/api/v1/email-preferences", `{"expected_revision":1,"locale":"sv"}`); response.Code != 200 {
		t.Fatal("explicit same-value CAS refused", response.Code)
	}
	if two := email128Preferences(t, f); two.Revision != 2 || two.Locale != "sv" {
		t.Fatal("same-value save did not advance exactly once")
	}
	if foreign := email128Preferences(t, other); foreign.Revision != 0 || foreign.Locale != "en" {
		t.Fatal("another tenant inherited preferences")
	}
	for _, body := range []string{
		`{"expected_revision":2,"locale":"sv-SE"}`, `{"expected_revision":2,"locale":"SV"}`,
		`{"expected_revision":2,"locale":null}`, `{"expected_revision":null,"locale":"sv"}`,
		`{"expected_revision":2,"locale":"en","locale":"sv"}`,
		`{"expected_revision":2,"locale":"en","org_id":"other"}`,
	} {
		if response := f.request(http.MethodPut, "/api/v1/email-preferences", body); response.Code != 400 {
			t.Fatal("ambiguous preference accepted", response.Code)
		}
	}
	var mailAfter, events int64
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='email_preferences.updated')`, f.org).Scan(&mailAfter, &events); err != nil || mailAfter != mailBefore || events != 2 {
		t.Fatal("preference control sent mail or lost atomic audit", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET role='sender' WHERE id=$1`, f.user.ID); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		if response := f.request(method, "/api/v1/email-preferences", `{"expected_revision":2,"locale":"en"}`); response.Code != 403 {
			t.Fatal("revoked owner retained preference access", method, response.Code)
		}
	}
}

func TestWorkspaceEmail128ExactRevisionBoundaryE2E(t *testing.T) {
	f := email720Fixture(t)
	if response := f.request(http.MethodPut, "/api/v1/email-preferences", `{"expected_revision":0,"locale":"en"}`); response.Code != 200 {
		t.Fatal(response.Code)
	}
	const lastInput int64 = emailtemplates.PreferencesMaxRevisionV1 - 1
	if _, err := f.pool.Exec(f.ctx, `UPDATE org_email_preferences_v1 SET revision=$2 WHERE org_id=$1`, f.org, lastInput); err != nil {
		t.Fatal(err)
	}
	body := `{"expected_revision":9007199254740990,"locale":"sv"}`
	if response := f.request(http.MethodPut, "/api/v1/email-preferences", body); response.Code != 200 {
		t.Fatal("last exact JSON CAS refused", response.Code)
	}
	if result := email128Preferences(t, f); result.Revision != emailtemplates.PreferencesMaxRevisionV1 || result.Locale != "sv" {
		t.Fatal("last JSON-safe revision rounded")
	}
	if response := f.request(http.MethodPut, "/api/v1/email-preferences", `{"expected_revision":9007199254740991,"locale":"en"}`); response.Code != 400 {
		t.Fatal("unrepresentable successor permitted", response.Code)
	}
	_, err := f.pool.Exec(f.ctx, `UPDATE org_email_preferences_v1 SET revision=9007199254740992 WHERE org_id=$1`, f.org)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("database admitted an unrepresentable revision", err)
	}
}

func TestWorkspaceEmail128EditionsConstraintAndPreviewLanguageE2E(t *testing.T) {
	f := email720Fixture(t)
	if response := f.request(http.MethodPut, "/api/v1/email-preferences", `{"expected_revision":0,"locale":"sv"}`); response.Code != 200 {
		t.Fatal(response.Code)
	}
	for _, kind := range []string{dispatch.KindDeclined, dispatch.KindQuotaWarning80} {
		path := "/api/v1/email-templates/" + kind
		body := email720Body(0, "For {{org_name}}", "<p>Saved introduction</p>", "Saved introduction")
		if response := f.request(http.MethodPut, path, body); response.Code != 200 {
			t.Fatal("new native edition save refused", kind, response.Code)
		}
		response := f.request(http.MethodPost, path+"/preview", email720Body(1, "", "", ""))
		var preview emailtemplates.Preview
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &preview) != nil || !preview.Synthetic || !preview.MandatoryContentPreserved {
			t.Fatal("native preview refused", kind, response.Code)
		}
		wantLocale := "en"
		if kind == dispatch.KindQuotaWarning80 {
			wantLocale = "sv"
			if !strings.Contains(preview.HTML, "har nått") || !strings.Contains(preview.Text, "Perioden") {
				t.Fatal("saved quota preference not used")
			}
		}
		if preview.Locale != wantLocale {
			t.Fatal("workspace preference changed document preview language", kind, preview.Locale)
		}
	}
	_, err := f.pool.Exec(f.ctx, `INSERT INTO org_email_template_revisions_v1(org_id,kind,revision,subject_template,html_template,text_template) VALUES($1,'email.voided',1,'','','')`, f.org)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("catalog-only voided edition admitted", err)
	}
	_, err = f.pool.Exec(f.ctx, `UPDATE org_email_template_revisions_v1 SET subject_template='changed' WHERE org_id=$1 AND kind='email.declined'`, f.org)
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("new immutable edition could be changed", err)
	}
	raw, err := os.ReadFile("../db/migrations/00128_workspace_email_and_signing_languages.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("Down unavailable")
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err = tx.Exec(f.ctx, down); !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("rollback discarded retained preferences/editions", err)
	}
}

func TestSyntheticEmailPreviewLocaleRequestDoesNotSavePolicyV1E2E(t *testing.T) {
	f := email720Fixture(t)
	before := email128Preferences(t, f)
	var mailBefore, editionsBefore int64
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM org_email_template_revisions_v1 WHERE org_id=$1)`, f.org).Scan(&mailBefore, &editionsBefore); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{dispatch.KindInvite, dispatch.KindDeclined, dispatch.KindQuotaWarning80} {
		for _, locale := range []string{"en", "sv"} {
			body := `{"expected_revision":0,"subject_template":"Keep this literal subject","html_template":"<p>Keep this literal introduction</p>","text_template":"Keep this literal introduction","preview_locale":"` + locale + `"}`
			path := "/api/v1/email-templates/" + kind
			r := f.request(http.MethodPost, path+"/preview", body)
			var out emailtemplates.Preview
			if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &out) != nil || out.Locale != locale || out.Subject != "Keep this literal subject" || !strings.Contains(out.HTML, "Keep this literal introduction") {
				t.Fatal("exact synthetic locale/literal source lost", kind, locale, r.Code)
			}
			if r := f.request(http.MethodPut, path, body); r.Code != 400 {
				t.Fatal("synthetic locale persisted on Save", r.Code)
			}
		}
	}
	for _, value := range []string{`null`, `""`, `"sv-SE"`, `true`} {
		body := `{"expected_revision":0,"subject_template":"","html_template":"","text_template":"","preview_locale":` + value + `}`
		if r := f.request(http.MethodPost, "/api/v1/email-templates/email.invite/preview", body); r.Code != 400 {
			t.Fatal("invalid locale accepted by HTTP", value, r.Code)
		}
	}
	if after := email128Preferences(t, f); after.Locale != before.Locale || after.Revision != before.Revision {
		t.Fatal("synthetic override saved workspace policy")
	}
	var mailAfter, editions int64
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM org_email_template_revisions_v1 WHERE org_id=$1)`, f.org).Scan(&mailAfter, &editions); err != nil || mailAfter != mailBefore || editions != editionsBefore {
		t.Fatal("preview created mail or editions", err)
	}
}
