// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"strings"
	"testing"
)

func TestOperatorQuotaEmailPreservesSaaSCopy(t *testing.T) {
	c := TemplateContext{OrgName: "Internal Team", PlanName: "Sales", QuotaKind: "documents", QuotaUsed: 80, QuotaLimit: 100, QuotaPct: 80, PeriodResetAt: "November 1, 2026", UpgradeURL: "https://hash.example.test/settings/billing", InternalOperator: true}
	_, html, text, err := Render(KindQuotaWarning80, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{html, text} {
		lower := strings.ToLower(body)
		if !strings.Contains(lower, "contact your operator") || strings.Contains(lower, "upgrade") || strings.Contains(lower, "billing period") {
			t.Fatalf("misleading operator mail: %s", body)
		}
	}
	c.InternalOperator = false
	_, html, text, err = Render(KindQuotaWarning80, c)
	if err != nil || !strings.Contains(html, "Upgrade now") || !strings.Contains(text, "Review or upgrade") {
		t.Fatalf("SaaS copy changed: %v", err)
	}
}
