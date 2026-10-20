// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"errors"
	"github.com/bright-interaction/hash/internal/recipients"
	"strings"
	"testing"
)

type automationDecimalRecorderV1 struct {
	calls int
	deny  error
}

func (r *automationDecimalRecorderV1) BeforeDecimalV1(string) error { r.calls++; return r.deny }
func TestAdmittedAutomationPreflightPreservesOriginalPolicyV1(t *testing.T) {
	const source = "{\"version\":1,\"blocks\":[{\"id\":\"amount\",\"type\":\"paragraph\",\"text\":\"Amount {{amount}}\"},{\"id\":\"branch\",\"type\":\"conditional\",\"attrs\":{\"expression\":\"var(amount) > 0\"},\"content\":[{\"id\":\"signature\",\"type\":\"signature_field\",\"attrs\":{\"recipient_role\":\"signer\"}}]}]}"
	valid := []recipients.Values{{Role: "signer", Email: "signer@example.test", Name: "Synthetic signer", Locale: "en"}}
	for _, name := range []string{"valid", "unresolved", "withdrawn", "missing_id", "invalid_recipient", "unsupported_role", "missing_signer", "ambiguous_signer"} {
		t.Run(name, func(t *testing.T) {
			raw, variables := source, "{\"amount\":\"1.5\"}"
			parties := append([]recipients.Values(nil), valid...)
			switch name {
			case "unresolved":
				variables = "{}"
			case "withdrawn":
				raw = strings.Replace(raw, "Amount {{amount}}", "DRAFT KIT v1 (auto-seeded by Hash", 1)
			case "missing_id":
				raw = strings.Replace(raw, "\"id\":\"amount\",", "", 1)
			case "invalid_recipient":
				parties[0].Email = "invalid"
			case "unsupported_role":
				parties[0].Role = "cc"
			case "missing_signer":
				parties = nil
			case "ambiguous_signer":
				parties = append(parties, parties[0])
			}
			old := ValidateAutomationBlockRequest([]byte(raw), []byte(variables), parties)
			recorder := &automationDecimalRecorderV1{}
			got := ValidateAutomationBlockRequestWithAdmissionV1([]byte(raw), []byte(variables), parties, recorder)
			if (old == nil) != (got == nil) || (old != nil && old.Error() != got.Error()) {
				t.Fatalf("original policy changed: old=%v admitted=%v", old, got)
			}
			if name == "valid" && (got != nil || recorder.calls == 0) {
				t.Fatalf("valid fixture did not reach actual decimal site: calls=%d err=%v", recorder.calls, got)
			}
		})
	}
	denied := errors.New("synthetic actual shared decimal capacity refusal")
	recorder := &automationDecimalRecorderV1{deny: denied}
	if err := ValidateAutomationBlockRequestWithAdmissionV1([]byte(source), []byte("{\"amount\":\"1.5\"}"), valid, recorder); !errors.Is(err, denied) || recorder.calls != 1 {
		t.Fatalf("actual first decimal refusal not preserved: calls=%d err=%v", recorder.calls, err)
	}
	if err := ValidateAutomationBlockRequestWithAdmissionV1([]byte(source), []byte("{}"), valid, nil); !errors.Is(err, ErrAutomationBlockAdmissionV1) {
		t.Fatal("nil numeric admission accepted", err)
	}
}
