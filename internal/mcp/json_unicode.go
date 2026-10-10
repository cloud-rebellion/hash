// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"errors"
	"unicode/utf8"
)

// validateJSONUnicode scans the original wire bytes, before encoding/json can
// normalize invalid UTF-8 or lone UTF-16 escapes into U+FFFD. Contract values,
// identifiers and audit inputs must never acquire different text implicitly.
// NUL is also rejected because PostgreSQL text/jsonb cannot preserve it.
// The ordinary decoder still validates JSON syntax after this linear scan.
func validateJSONUnicode(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON must contain valid UTF-8")
	}
	inString := false
	for index := 0; index < len(raw); index++ {
		switch {
		case !inString && raw[index] == '"':
			inString = true
		case !inString:
			continue
		case raw[index] == '"':
			inString = false
		case raw[index] == '\\':
			if index+1 >= len(raw) {
				continue // The JSON decoder reports incomplete syntax.
			}
			if raw[index+1] != 'u' {
				index++ // An escaped backslash is not a Unicode escape.
				continue
			}
			code, ok := jsonHexQuad(raw, index+2)
			if !ok {
				return errors.New("invalid JSON Unicode escape")
			}
			index += 5
			switch {
			case code == 0:
				return errors.New("JSON keys and strings must not contain NUL")
			case code >= 0xd800 && code <= 0xdbff:
				pair := index + 1
				if pair+5 >= len(raw) || raw[pair] != '\\' || raw[pair+1] != 'u' {
					return errors.New("JSON Unicode surrogate escapes must be paired")
				}
				low, valid := jsonHexQuad(raw, pair+2)
				if !valid || low < 0xdc00 || low > 0xdfff {
					return errors.New("JSON Unicode surrogate escapes must be paired")
				}
				index = pair + 5
			case code >= 0xdc00 && code <= 0xdfff:
				return errors.New("JSON Unicode surrogate escapes must be paired")
			}
		}
	}
	return nil
}

func jsonHexQuad(raw []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, digit := range raw[start : start+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
