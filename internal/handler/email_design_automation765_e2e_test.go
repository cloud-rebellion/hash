//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"strings"
	"testing"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/workspacesmtp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
)

func emailDesign765Input(t *testing.T, footer string) (string, string) {
	t.Helper()
	imageData := image.NewNRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			imageData.SetNRGBA(x, y, color.NRGBA{R: 240, G: 80, B: 30, A: 255})
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, imageData); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded.Bytes())
	design := dispatch.DefaultServiceEmailDesignV1()
	design.Logo = &htmlmaster.Asset{Name: "logo", MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(encoded.Bytes()), SHA256: hex.EncodeToString(digest[:])}
	design.LogoAlt = "Synthetic test logo"
	design.LayoutHTML = `<div style="padding:24px;">{{logo}}<div>{{native_content}}</div><p>` + footer + `</p></div>`
	raw, err := json.Marshal(design)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := dispatch.CanonicalServiceEmailDesignV1(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return canonical, design.Logo.DataBase64
}

// Real owner HTTP, native source admission and real immutable SQL rows. No
// caller-supplied measurements/grants, external mail/AI or transport are used.
func TestEmailDesign122NativeOwnerAPISampleFreezeAndOccupiedDown765E2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	box, err := dispatch.NewStaffAuthMailBox(strings.Repeat("76", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	f.s.StaffAuthMailBox = box
	call := func(method, path string, input any) int {
		return ownedBlocksTemplateCallV1(t, f, q.cookie, method, path, input).Code
	}
	smtp := map[string]any{"expected_revision": 0, "host": "smtp.example.invalid", "port": 587, "tls_mode": "starttls", "sender_name": "Synthetic workspace", "sender_email": "sender@example.invalid", "credentials_action": "replace", "username": "synthetic", "password": "synthetic"}
	if code := call(http.MethodPut, "/api/v1/workspace-smtp", smtp); code != 200 {
		t.Fatal("native owner SMTP configuration", code)
	}
	kind := dispatch.KindInvite
	path := "/api/v1/email-templates/" + kind
	first, logo := emailDesign765Input(t, "Synthetic design one")
	input := func(revision int64, design, label string) map[string]any {
		return map[string]any{"expected_revision": revision, "subject_template": "Design sample " + label, "html_template": "<p>Edition " + label + " for {{recipient_name}}</p>", "text_template": "Edition " + label + " for {{recipient_name}}", "design_json": design}
	}
	if code := call(http.MethodPut, path, input(0, first, "one")); code != 200 {
		t.Fatal("native owner design save", code)
	}
	var stored string
	var commitment []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT design_json,design_sha256 FROM org_email_template_revisions_v1 WHERE org_id=$1 AND kind=$2 AND revision=1`, f.org, kind).Scan(&stored, &commitment); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(first))
	if stored != first || !bytes.Equal(commitment, sum[:]) {
		t.Fatal("native saved design/logo digest differs")
	}
	if code := call(http.MethodPut, path, input(0, first, "stale")); code != 409 {
		t.Fatal("stale native design overwrite", code)
	}
	bad := strings.Replace(first, `"sha256":"`, `"sha256":"0`, 1)
	if code := call(http.MethodPut, path, input(1, bad, "invalid")); code != 400 {
		t.Fatal("bad committed logo accepted", code)
	}
	if r := ownedBlocksTemplateCallV1(t, f, "invalid-cookie", http.MethodPost, path+"/test", map[string]any{"expected_smtp_revision": 1, "expected_template_revision": 1}); r.Code != 401 {
		t.Fatal("unverified session could queue sample", r.Code)
	}
	response := ownedBlocksTemplateCallV1(t, f, q.cookie, http.MethodPost, path+"/test", map[string]any{"expected_smtp_revision": 1, "expected_template_revision": 1})
	var receipt workspacesmtp.TestStatus
	if response.Code != 202 || json.Unmarshal(response.Body.Bytes(), &receipt) != nil || receipt.DeliveryID == uuid.Nil || receipt.Status != "pending" || receipt.SMTPAccepted || receipt.InboxDeliveryConfirmed {
		t.Fatal("saved design sample did not return honest pending", response.Code)
	}
	var to, purpose, subject, body, text, receiptKind string
	var smtpOrg uuid.UUID
	var revision int64
	var subjectHash, htmlHash, textHash []byte
	err = f.pool.QueryRow(f.ctx, `SELECT d.to_email,d.smtp_org_id,d.smtp_purpose,d.subject,d.html_body,d.text_body,t.template_kind,t.template_revision,t.subject_sha256,t.html_sha256,t.text_sha256 FROM email_deliveries d JOIN org_smtp_test_requests_v1 t ON t.email_delivery_id=d.id WHERE d.id=$1`, receipt.DeliveryID).Scan(&to, &smtpOrg, &purpose, &subject, &body, &text, &receiptKind, &revision, &subjectHash, &htmlHash, &textHash)
	if err != nil {
		t.Fatal(err)
	}
	sh, hh, th := sha256.Sum256([]byte(subject)), sha256.Sum256([]byte(body)), sha256.Sum256([]byte(text))
	if to != f.user.Email || smtpOrg != f.org || purpose != "workspace_test" || receiptKind != kind || revision != 1 || !bytes.Equal(subjectHash, sh[:]) || !bytes.Equal(htmlHash, hh[:]) || !bytes.Equal(textHash, th[:]) || !strings.Contains(body, "Synthetic design one") || !strings.Contains(body, "data:image/png;base64,"+logo) || !strings.Contains(body, "https://example.invalid/sign/preview") {
		t.Fatal("sample destination/design/logo/action/receipt not frozen exactly")
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if e := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object('delivery',to_jsonb(d),'receipt',to_jsonb(t))::text FROM email_deliveries d JOIN org_smtp_test_requests_v1 t ON t.email_delivery_id=d.id WHERE d.id=$1`, receipt.DeliveryID).Scan(&value); e != nil {
			t.Fatal(e)
		}
		return value
	}
	before := snapshot()
	second, _ := emailDesign765Input(t, "Synthetic design two")
	if code := call(http.MethodPut, path, input(1, second, "two")); code != 200 {
		t.Fatal("second native edition save", code)
	}
	if snapshot() != before {
		t.Fatal("current design head rewrote frozen sample bytes/receipt")
	}
	if code := call(http.MethodPost, path+"/test", map[string]any{"expected_smtp_revision": 1, "expected_template_revision": 1}); code != 409 {
		t.Fatal("stale selected design could queue", code)
	}
	migration := stdlib.OpenDB(*f.pool.Config().ConnConfig.Copy())
	migration.SetMaxOpenConns(1)
	defer migration.Close()
	if err = mdb.RunMigrationsDownToContext(f.ctx, migration, 121); err == nil {
		t.Fatal("occupied design/sample122 Down accepted")
	}
	version, err := mdb.GetMigrationVersionContext(f.ctx, migration)
	if err != nil || version != 122 || snapshot() != before {
		t.Fatal("refused122Down changed native version or frozen sample", version, err)
	}
	var again string
	var againHash []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT design_json,design_sha256 FROM org_email_template_revisions_v1 WHERE org_id=$1 AND kind=$2 AND revision=1`, f.org, kind).Scan(&again, &againHash); err != nil || again != stored || !bytes.Equal(againHash, commitment) {
		t.Fatal("refused Down changed retained design", err)
	}
	if err = migration.Close(); err != nil {
		t.Fatal("close owned migration bridge", err)
	}
	ownedPlainAssertDrainedV1(t, q)
}

// Genuine settings API occupancy, actual Goose Down refusal and re-Up. A
// multi-version Down commits each empty migration separately:122 may retire
// before121 refuses. Retained121 source must survive that truthful boundary.
func TestAutomation121NativePreferenceOccupiedDownAndReUp765E2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	f := q.f
	response := ownedBlocksTemplateCallV1(t, f, q.cookie, http.MethodPut, "/api/v1/automation-preferences", map[string]any{"expected_revision": 0, "notify_viewed": true, "notify_signed": true})
	if response.Code != 200 {
		t.Fatal("native sender preference save", response.Code)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := f.pool.QueryRow(f.ctx, `SELECT to_jsonb(p)::text FROM sender_automation_preferences_v1 p WHERE org_id=$1 AND sender_user_id=$2`, f.org, f.user.ID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	migration := stdlib.OpenDB(*f.pool.Config().ConnConfig.Copy())
	migration.SetMaxOpenConns(1)
	defer migration.Close()
	if err := mdb.RunMigrationsDownToContext(f.ctx, migration, 120); err == nil {
		t.Fatal("occupied121 preferences erased by Down")
	}
	version, err := mdb.GetMigrationVersionContext(f.ctx, migration)
	if err != nil || version != 121 || snapshot() != before {
		t.Fatal("occupied121 boundary/source changed", version, err)
	}
	if err = mdb.RunMigrationsContext(f.ctx, migration); err != nil {
		t.Fatal("genuine122 re-Up", err)
	}
	version, err = mdb.GetMigrationVersionContext(f.ctx, migration)
	if err != nil || version != 122 || snapshot() != before {
		t.Fatal("re-Up changed retained sender preference", version, err)
	}
	if err = migration.Close(); err != nil {
		t.Fatal("close owned migration bridge", err)
	}
	ownedCreationAssertDrainedV1(t, q, 1)
}
