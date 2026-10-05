// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// Validate storage constraints before taking document or audit locks. The
// document schema still owns block types and variable value semantics.
func validateDocumentUpdateStorage(in updateDocumentInput) error {
	if !utf8.ValidString(in.Name) || strings.ContainsRune(in.Name, 0) {
		return errors.New("document name must be valid UTF-8 without NUL")
	}
	for _, raw := range []json.RawMessage{in.BlocksJSON, in.VariablesJSON} {
		if len(raw) == 0 {
			continue
		}
		if err := validateUniqueJSONObject(raw); err != nil {
			return errors.New("document content must be unambiguous UTF-8 JSON")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		for {
			token, err := decoder.Token()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return errors.New("document content must be valid JSON")
			}
			if value, ok := token.(string); ok && strings.ContainsRune(value, 0) {
				return errors.New("document content strings and keys must not contain NUL")
			}
		}
	}
	return nil
}
