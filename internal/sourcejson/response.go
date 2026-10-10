// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package sourcejson validates bounded integration response syntax before
// contractual data is decoded into maps or typed records.
package sourcejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var ErrAmbiguousResponse = errors.New("upstream response must be an unambiguous UTF-8 JSON object")

// Validate rejects duplicate decoded keys, including escaped aliases, before
// decoding can silently choose a last value for contractual text. Callers must
// enforce a response byte limit before invoking Validate.
func Validate(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if !utf8.Valid(raw) || len(trimmed) == 0 || trimmed[0] != '{' {
		return ErrAmbiguousResponse
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return ErrAmbiguousResponse
		}
		token, err := d.Token()
		if err != nil {
			return ErrAmbiguousResponse
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
					return ErrAmbiguousResponse
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return ErrAmbiguousResponse
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return ErrAmbiguousResponse
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return ErrAmbiguousResponse
			}
		default:
			return ErrAmbiguousResponse
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrAmbiguousResponse
	}
	return nil
}
