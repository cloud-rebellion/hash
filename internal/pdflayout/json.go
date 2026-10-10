// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdflayout

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// Legal placement and role data have one interpretation even when a stored
// template or a PATCH bypasses the transport's stricter JSON decoder.
func validateJSON(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			break
		}
		if raw[i+1] != 'u' {
			i++
			continue
		}
		if i+6 > len(raw) {
			return invalid("invalid Unicode escape")
		}
		code, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
		if err != nil {
			return invalid("invalid Unicode escape")
		}
		i += 5
		if code >= 0xdc00 && code <= 0xdfff {
			return invalid("unpaired Unicode escape")
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+7 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return invalid("unpaired Unicode escape")
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return invalid("unpaired Unicode escape")
			}
			i += 6
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return walkJSON(decoder, 0)
}

func walkJSON(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return invalid("layout nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return invalid("invalid JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return invalid("invalid JSON key")
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return invalid("duplicate JSON key")
			}
			seen[key] = true
			switch key {
			case "version", "parties", "fields", "role", "label", "party_role", "type", "page", "x_pct", "y_pct", "w_pct", "h_pct", "required":
			default:
				return invalid("unknown or incorrectly cased layout field")
			}
			if err := walkJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walkJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return invalid("invalid JSON delimiter")
	}
	if _, err := decoder.Token(); err != nil {
		return invalid("invalid JSON closing delimiter")
	}
	return nil
}
