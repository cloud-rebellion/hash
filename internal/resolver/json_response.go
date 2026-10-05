// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var errAmbiguousResponse = errors.New("upstream response must be an unambiguous UTF-8 JSON object")

// Reject duplicate decoded keys, including escaped aliases, before map
// decoding can silently choose a last value for contractual text.
func validateSourceJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if !utf8.Valid(raw) || len(trimmed) == 0 || trimmed[0] != '{' {
		return errAmbiguousResponse
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errAmbiguousResponse
		}
		token, err := d.Token()
		if err != nil {
			return errAmbiguousResponse
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return errAmbiguousResponse
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errAmbiguousResponse
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errAmbiguousResponse
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errAmbiguousResponse
			}
		default:
			return errAmbiguousResponse
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errAmbiguousResponse
	}
	return nil
}
