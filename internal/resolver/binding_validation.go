// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// BindingValidationError describes a safe field constraint without echoing the
// caller's source references, fallback text, or contractual values.
type BindingValidationError struct{ Field, Reason string }

func (e *BindingValidationError) Error() string {
	return "invalid binding " + e.Field + ": " + e.Reason
}

// Match the block renderer and conditional-variable grammar. Dots are literal
// parts of variable names; source paths retain the resolver's separate rules.
var bindingNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_\.]*$`)

func ValidateBindingName(name string) error {
	if err := validateBindingString("variable", name, 128); err != nil {
		return err
	}
	if !bindingNamePattern.MatchString(name) {
		return &BindingValidationError{Field: "variable", Reason: "must start with a letter or underscore and contain only letters, digits, underscores, or dots"}
	}
	return nil
}

// ValidateBinding validates storage and resolver input without fetching a
// source. Empty REST paths still select the complete entity; static and agent
// sources can have empty references, and org.setting ignores source_ref.
func ValidateBinding(name string, kind SourceKind, ref, path, fallback string) error {
	if err := ValidateBindingName(name); err != nil {
		return err
	}
	if !kind.Valid() {
		return &BindingValidationError{Field: "source_kind", Reason: "must be a supported source kind"}
	}
	if err := validateBindingString("source_path", path, 1024); err != nil {
		return err
	}
	if err := validateBindingString("fallback", fallback, 16*1024); err != nil {
		return err
	}
	switch kind {
	case SourceCRMDeal, SourceCRMContact, SourceScannerFind:
		if err := validateBindingString("source_ref", ref, 256); err != nil {
			return err
		}
		if err := validateHTTPSourceRef(ref); err != nil {
			return &BindingValidationError{Field: "source_ref", Reason: err.Error()}
		}
	default:
		if err := validateBindingString("source_ref", ref, 1024); err != nil {
			return err
		}
	}
	return nil
}

func validateBindingString(field, value string, maxBytes int) error {
	if !utf8.ValidString(value) {
		return &BindingValidationError{Field: field, Reason: "must be valid UTF-8"}
	}
	if strings.ContainsRune(value, 0) {
		return &BindingValidationError{Field: field, Reason: "must not contain NUL"}
	}
	if len(value) > maxBytes {
		return &BindingValidationError{Field: field, Reason: "exceeds the supported byte limit"}
	}
	return nil
}
