// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package pdflayout defines reusable, identity-free PDF signing layouts.
package pdflayout

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/recipients"
)

var (
	ErrInvalid      = errors.New("invalid PDF signing layout")
	ErrPrecondition = errors.New("PDF template changed; review the current template")
)

const MaxFields = 1000
const MaxParties = 100

type Party struct {
	Role  string `json:"role"`
	Label string `json:"label"`
}

type Field struct {
	PartyRole string  `json:"party_role"`
	Type      string  `json:"type"`
	Page      int32   `json:"page"`
	XPct      float64 `json:"x_pct"`
	YPct      float64 `json:"y_pct"`
	WPct      float64 `json:"w_pct"`
	HPct      float64 `json:"h_pct"`
	Required  bool    `json:"required"`
	Label     string  `json:"label,omitempty"`
}

type Layout struct {
	Version int     `json:"version"`
	Parties []Party `json:"parties"`
	Fields  []Field `json:"fields"`
}

type Binding struct {
	Role   string `json:"role"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Locale string `json:"locale,omitempty"`
}

// Parse recognizes only versioned layouts. Historical arrays never become
// signing fields: their old recipient identifiers must not be cloned.
func Parse(raw []byte, pageCount int32) (*Layout, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || (json.Valid(raw) && raw[0] == '[') {
		return nil, nil
	}
	if len(raw) > 512*1024 || !utf8.Valid(raw) {
		return nil, invalid("layout exceeds the size limit or is not UTF-8")
	}
	if err := validateJSON(raw); err != nil {
		return nil, err
	}
	var layout Layout
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&layout); err != nil {
		return nil, invalid("expected a versioned layout: %v", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, invalid("layout must contain one JSON value")
	}
	if err := layout.Validate(pageCount); err != nil {
		return nil, err
	}
	return &layout, nil
}

// CanonicalForUpdate accepts the empty legacy layout, but new layouts must use
// role slots. It refuses legacy nonempty arrays rather than storing UUIDs.
func CanonicalForUpdate(raw []byte, pageCount int32) ([]byte, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("[]")) {
		return []byte("[]"), nil
	}
	layout, err := Parse(raw, pageCount)
	if err != nil {
		return nil, err
	}
	if layout == nil {
		return nil, invalid("nonempty legacy field arrays must be saved as a named-party layout")
	}
	return json.Marshal(layout)
}

func (l *Layout) Validate(pageCount int32) error {
	if l == nil || l.Version != 1 {
		return invalid("version must be 1")
	}
	if pageCount < 1 || pageCount > 1000 {
		return invalid("verified source page count is required")
	}
	if len(l.Parties) == 0 || len(l.Parties) > MaxParties {
		return invalid("layout needs 1 to %d parties", MaxParties)
	}
	if len(l.Fields) == 0 || len(l.Fields) > MaxFields {
		return invalid("layout needs 1 to %d signature fields", MaxFields)
	}
	roles := make(map[string]int, len(l.Parties))
	for _, party := range l.Parties {
		if party.Role != strings.ToLower(strings.TrimSpace(party.Role)) || recipients.ValidateResponseRole(party.Role) != nil {
			return invalid("party role must be a canonical signing role")
		}
		if _, exists := roles[party.Role]; exists {
			return invalid("party roles must be unique")
		}
		if !validLabel(party.Label) || strings.TrimSpace(party.Label) == "" {
			return invalid("party label must be nonempty and at most 200 characters")
		}
		roles[party.Role] = 0
	}
	for i := range l.Fields {
		field := &l.Fields[i]
		if _, exists := roles[field.PartyRole]; !exists {
			return invalid("field references an undeclared party")
		}
		if field.Type != "signature" || !field.Required {
			return invalid("this layout supports required signature fields only")
		}
		if field.Page < 1 || field.Page > pageCount {
			return invalid("field page is outside the source PDF")
		}
		for _, n := range []*float64{&field.XPct, &field.YPct, &field.WPct, &field.HPct} {
			if math.IsNaN(*n) || math.IsInf(*n, 0) || *n < 0 || *n > 100 {
				return invalid("field geometry must be finite percentages")
			}
			*n = math.Round(*n*10000) / 10000
		}
		if field.WPct <= 0 || field.HPct <= 0 || field.XPct+field.WPct > 100 || field.YPct+field.HPct > 100 {
			return invalid("field rectangle must fit within its page")
		}
		if !validLabel(field.Label) {
			return invalid("field label is invalid")
		}
		roles[field.PartyRole]++
	}
	for _, count := range roles {
		if count == 0 {
			return invalid("every party needs a required signature field")
		}
	}
	return nil
}

func (l *Layout) Bind(input []Binding, locale string) ([]recipients.Values, error) {
	if l == nil {
		if len(input) != 0 {
			return nil, invalid("party bindings require a named-party PDF layout")
		}
		return nil, nil
	}
	if len(input) != len(l.Parties) {
		return nil, invalid("provide exactly one identity for every party slot")
	}
	byRole := make(map[string]recipients.Values, len(input))
	for _, binding := range input {
		if binding.Locale == "" {
			binding.Locale = locale
		}
		if binding.Locale == "" {
			binding.Locale = "en"
		}
		values, err := recipients.Normalize(recipients.Values{Role: binding.Role, Name: binding.Name, Email: binding.Email, Locale: binding.Locale})
		if err != nil {
			return nil, invalid("party identity: %v", err)
		}
		if recipients.ValidateResponseRole(values.Role) != nil {
			return nil, invalid("party role is unsupported")
		}
		if _, exists := byRole[values.Role]; exists {
			return nil, invalid("party identities must use unique roles")
		}
		byRole[values.Role] = values
	}
	values := make([]recipients.Values, len(l.Parties))
	for i, party := range l.Parties {
		value, exists := byRole[party.Role]
		if !exists {
			return nil, invalid("missing identity for party %s", party.Role)
		}
		value.OrderIndex = int32(i)
		values[i] = value
	}
	return values, nil
}

func validLabel(label string) bool {
	if !utf8.ValidString(label) || len(label) > 800 || utf8.RuneCountInString(label) > 200 {
		return false
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
