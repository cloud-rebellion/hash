// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package eidas

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"math"
	"strconv"
	"strings"
	"unicode"
)

// These are pure policy decisions, not model/resource/current-row authority.
// The native Send owner retains actual immutable input and ALL admitted rules.
func EvaluateRulesV1(rules []*generated.EidasRoutingRule, in EvaluateInput) (Decision, error) {
	return evaluateActiveRules(rules, in)
}
func InputForDocumentV1(doc *generated.Document) (EvaluateInput, error) {
	in := EvaluateInput{Variables: map[string]string{}}
	if len(doc.VariablesJson) == 0 {
		return in, nil
	}
	var raw map[string]any
	if err := json.Unmarshal(doc.VariablesJson, &raw); err != nil {
		return in, fmt.Errorf("decode document variables: %w", err)
	}
	for k, v := range raw {
		if s, ok := stringifyVarForEIDAS(v); ok {
			in.Variables[k] = s
		}
	}
	for _, key := range []string{"amount", "deal_amount", "total", "value"} {
		if v, ok := in.Variables[key]; ok {
			n, err := parseContractAmount(v)
			if err != nil {
				// A present but unreadable amount is not the same thing as an
				// absent amount. Silently treating it as zero weakens the eIDAS
				// tier exactly when the guard cannot understand its input.
				return in, fmt.Errorf("invalid %s: %w", key, err)
			}
			in.Amount = n
			// Keep custom predicates on variables.<amount-key> consistent with
			// the built-in amount field; both must see the normalized number.
			in.Variables[key] = strconv.FormatFloat(n, 'f', -1, 64)
			break
		}
	}
	for _, key := range []string{"country", "jurisdiction", "country_code"} {
		if v, ok := in.Variables[key]; ok {
			in.Country = v
			break
		}
	}
	for _, key := range []string{"document_type", "doc_type", "type"} {
		if v, ok := in.Variables[key]; ok {
			in.DocumentType = v
			break
		}
	}
	return in, nil
}

// parseContractAmount accepts the human format used in our Swedish ceremony
// (Unicode thousands spaces and a decimal comma) while rejecting ambiguous or
// non-finite values. Invalid present amounts fail the send instead of silently
// downgrading the required signature tier to the zero-value SES floor.
func parseContractAmount(raw string) (float64, error) {
	value := strings.TrimSpace(raw)
	value = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
	if value == "" {
		return 0, errors.New("amount is empty")
	}
	if strings.Count(value, ",") > 1 || (strings.Contains(value, ",") && strings.Contains(value, ".")) {
		return 0, errors.New("amount uses an ambiguous separator format")
	}
	if strings.Contains(value, ",") {
		value = strings.Replace(value, ",", ".", 1)
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, errors.New("amount must be a finite number")
	}
	return n, nil
}
func stringifyVarForEIDAS(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case nil:
		return "", false
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return "", false
		}
		return string(raw), true
	}
}
