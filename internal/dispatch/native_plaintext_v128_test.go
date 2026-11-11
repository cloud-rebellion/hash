// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package dispatch

import (
	"html"
	"strings"
	"testing"
)

func TestServiceEmailNativePlainTextKeepsLiteralDataAndHTMLSafeV128(t *testing.T) {
	const value = `Reason <unsafe> & intact "Åsa"`
	const link = "https://example.invalid/document?a=1&b=two"
	for _, locale := range []string{"en", "sv", "unknown"} {
		for _, kind := range []string{KindDeclined, KindNewComment, KindChangesRequested, KindCompletedSender, KindVoided, KindQuotaWarning80} {
			t.Run(locale+"/"+kind, func(t *testing.T) {
				ctx := TemplateContext{
					Locale: locale, DocumentName: value, RecipientName: value, SenderName: value,
					OrgName: value, DeclineReason: value, ChangeContext: value, ChangeQuote: value,
					ChangeProposed: value, PlanName: value, QuotaKind: "documents", QuotaPct: 80,
					QuotaUsed: 8, QuotaLimit: 10, PeriodResetAt: "2030-01-01",
					DownloadURL: link, AuditCertURL: link, OpenURL: link, ApproveURL: link,
					DenyURL: link, UpgradeURL: link,
				}
				_, body, plain, err := Render(kind, ctx)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(plain, value) || strings.Contains(plain, html.EscapeString(value)) {
					t.Fatalf("plain-text email changed literal data: %q", plain)
				}
				if !strings.Contains(body, html.EscapeString(value)) || strings.Contains(body, value) {
					t.Fatalf("HTML email did not retain escaping: %q", body)
				}
				if kind != KindDeclined && kind != KindVoided && (!strings.Contains(plain, link) || !strings.Contains(body, html.EscapeString(link))) {
					t.Fatal("native action link changed or disappeared")
				}
			})
		}
	}
}
