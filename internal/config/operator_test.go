// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package config

import (
	"strings"
	"testing"
)

const validOperatorGrants = `[{"org_id":"8cc7bbbc-a0fa-4fd9-b4de-82d438cb44ba","plan_slug":"internal-sales","review_ref":"stage-review-123"}]`

func TestProductionOperatorRetainsSecurityRequirements(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_BILLING_PROVIDER", "operator")
	t.Setenv("HASH_OPERATOR_ENTITLEMENTS", validOperatorGrants)
	t.Setenv("HASH_MOLLIE_API_KEY", "")
	t.Setenv("HASH_MOLLIE_WEBHOOK_PATH_SECRET", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.OperatorEntitlements) != 1 {
		t.Fatal("missing grants")
	}
	t.Setenv("HASH_AUDIT_PRIVATE_KEY", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_AUDIT_PRIVATE_KEY") {
		t.Fatalf("production security bypass: %v", err)
	}
}
func TestOperatorGrantsFailClosed(t *testing.T) {
	for _, raw := range []string{"", `null`, `[]`, validOperatorGrants + ` {}`, strings.Replace(validOperatorGrants, `"plan_slug":"internal-sales"`, `"plan_slug":"internal-sales","plan_slug":"pro"`, 1), strings.Replace(validOperatorGrants, `"review_ref"`, `"unknown"`, 1), strings.Replace(validOperatorGrants, `stage-review-123`, ``, 1), strings.Replace(validOperatorGrants, `8cc7bbbc-a0fa-4fd9-b4de-82d438cb44ba`, `00000000-0000-0000-0000-000000000000`, 1), "[" + validOperatorGrants[1:len(validOperatorGrants)-1] + "," + validOperatorGrants[1:len(validOperatorGrants)-1] + "]"} {
		if _, err := ParseOperatorEntitlements(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	setAllRequired(t)
	t.Setenv("HASH_OPERATOR_ENTITLEMENTS", validOperatorGrants)
	if _, err := Load(); err == nil {
		t.Fatal("operator grants accepted in SaaS mode")
	}
}
