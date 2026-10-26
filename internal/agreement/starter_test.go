// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package agreement

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/blocks"
)

func TestServicesAgreementRequiresCurrentPartyAndDateValues(t *testing.T) {
	requiredAtInstantiation := []string{
		"provider", "provider_signatory", "provider_title", "provider_orgnr",
		"client", "client_orgnr", "client_signatory",
		"client_title", "effective_date", "offer_valid_until",
		"legal_approval_reference", "dpa_reference",
	}
	referenced := blocks.ExtractVariableNames(&ServicesAgreement.Tree)
	for _, key := range requiredAtInstantiation {
		if !slices.Contains(referenced, key) {
			t.Fatalf("starter no longer references required variable %q", key)
		}
		if value, prefilled := ServicesAgreement.Variables[key]; prefilled {
			t.Fatalf("required variable %q has unsafe built-in value %q", key, value)
		}
	}
}

func TestServicesAgreementRequiresExplicitProviderIdentity(t *testing.T) {
	starter, found := Get("services-agreement-sv")
	if !found {
		t.Fatal("shared starter catalog entry is missing")
	}
	values, err := blocks.ParseVariableValues(starter.VariablesJSON())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range blocks.ExtractVariableNames(&starter.Tree) {
		if _, supplied := values[name]; !supplied {
			values[name] = "Explicit fixture value"
		}
	}
	values["provider"] = "Example Provider AB"
	values["provider_signatory"] = "Sam Sample"
	values["provider_title"] = "Authorized representative"
	complete, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := blocks.ValidateResolvedVariableValues(&starter.Tree, complete)
	if err != nil || resolved["provider"] != values["provider"] || resolved["provider_signatory"] != values["provider_signatory"] || resolved["provider_title"] != values["provider_title"] {
		t.Fatal("explicit contract parties were replaced or refused", resolved, err)
	}
	for _, name := range []string{"provider", "provider_signatory", "provider_title"} {
		for _, missing := range []bool{true, false} {
			label := "blank"
			if missing {
				label = "missing"
			}
			t.Run(name+"/"+label, func(t *testing.T) {
				candidate := make(map[string]string, len(values))
				for key, value := range values {
					candidate[key] = value
				}
				if missing {
					delete(candidate, name)
				} else {
					candidate[name] = " \t"
				}
				raw, err := json.Marshal(candidate)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := blocks.ValidateResolvedVariableValues(&starter.Tree, raw); err == nil || !strings.Contains(err.Error(), name) {
					t.Fatal("contract admitted an unspecified provider identity", err)
				}
			})
		}
	}
}

func TestServicesAgreementDoesNotInventLicensingOrAttachments(t *testing.T) {
	text := string(ServicesAgreement.BlocksJSON())
	for _, forbidden := range []string{"Apache 2.0", "Bilaga A", "öppen källkod"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("starter still contains unsupported claim %q", forbidden)
		}
	}
}
