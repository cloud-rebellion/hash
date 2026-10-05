// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fields

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxFieldOptionsBytes      = 16 * 1024
	maxFieldOptionsNesting    = 32
	pgNumericIntegerDigits    = 131072
	pgNumericFractionalDigits = 16383
)

// PostgreSQL jsonb rejects NUL, malformed surrogate pairs and out-of-range
// numeric values that encoding/json can accept. It also expands exponent
// notation on readback. Validate without changing the accepted raw options,
// and bound the projected JSON output as well as the original input.
// https://www.postgresql.org/docs/16/datatype-json.html
// https://www.postgresql.org/docs/16/datatype-numeric.html
func validateOptionsJSON(raw []byte) error {
	if len(raw) > maxFieldOptionsBytes || !utf8.Valid(raw) {
		return invalidOptions("must be valid UTF-8 JSON and at most 16 KiB")
	}
	if err := validateOptionsUnicodeEscapes(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return invalidOptions("must be a JSON object")
	}
	validator := optionsJSONValidator{decoder: decoder}
	if err := validator.value(first, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalidOptions("must contain exactly one JSON object")
	}
	return nil
}

func invalidOptions(reason string) error { return &ValidationError{Field: "options", Reason: reason} }

type optionsJSONValidator struct {
	decoder  *json.Decoder
	expanded int
}

func (v *optionsJSONValidator) add(size int64) error {
	if size > int64(maxFieldOptionsBytes-v.expanded) {
		return invalidOptions("expanded JSON must be at most 16 KiB")
	}
	v.expanded += int(size)
	return nil
}

func (v *optionsJSONValidator) value(token json.Token, depth int) error {
	switch value := token.(type) {
	case json.Delim:
		if depth > maxFieldOptionsNesting {
			return invalidOptions("JSON nesting must be at most 32 containers")
		}
		if err := v.add(2); err != nil { // Braces or brackets.
			return err
		}
		items := 0
		for v.decoder.More() {
			if items > 0 {
				if err := v.add(2); err != nil { // jsonb emits comma and space.
					return err
				}
			}
			if value == '{' {
				key, err := v.decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return invalidOptions("must contain valid JSON object keys")
				}
				if err := v.add(optionsStringSize(name) + 2); err != nil { // Key, colon, space.
					return err
				}
			}
			child, err := v.decoder.Token()
			if err != nil {
				return invalidOptions("must contain valid JSON values")
			}
			if err := v.value(child, depth+1); err != nil {
				return err
			}
			items++
		}
		closing, err := v.decoder.Token()
		if err != nil || (value == '{' && closing != json.Delim('}')) || (value == '[' && closing != json.Delim(']')) {
			return invalidOptions("must contain valid JSON containers")
		}
		return nil
	case string:
		return v.add(optionsStringSize(value))
	case json.Number:
		size, err := optionsNumberSize(string(value))
		if err != nil {
			return err
		}
		return v.add(size)
	case bool:
		if value {
			return v.add(4)
		}
		return v.add(5)
	case nil:
		return v.add(4)
	default:
		return invalidOptions("must contain supported JSON values")
	}
}

// Count UTF-8 bytes and JSON escaping without allocating an expanded string.
func optionsStringSize(value string) int64 {
	size := int64(2) // Quotes.
	for _, b := range []byte(value) {
		switch {
		case b == '"' || b == '\\':
			size += 2
		case b == '\b' || b == '\f' || b == '\n' || b == '\r' || b == '\t':
			size += 2
		case b < 0x20:
			size += 6
		default:
			size++
		}
	}
	return size
}

// The JSON decoder already checked the grammar. Integer arithmetic avoids
// float rounding/overflow and never allocates exponent-sized decimal buffers.
func optionsNumberSize(number string) (int64, error) {
	sign := int64(0)
	if strings.HasPrefix(number, "-") {
		sign, number = 1, number[1:]
	}
	exponent := int64(0)
	if index := strings.IndexAny(number, "eE"); index >= 0 {
		var err error
		exponent, err = strconv.ParseInt(number[index+1:], 10, 32)
		if err != nil {
			return 0, invalidOptions("number is outside the supported database range")
		}
		number = number[:index]
	}
	integerDigits, fractionDigits := len(number), 0
	if index := strings.IndexByte(number, '.'); index >= 0 {
		integerDigits, fractionDigits = index, len(number)-index-1
	}
	firstNonzero, digitIndex, found := 0, 0, false
	for _, digit := range number {
		if digit == '.' {
			continue
		}
		if !found && digit != '0' {
			firstNonzero, found = digitIndex, true
		}
		digitIndex++
	}
	// All-zero positive exponents are conservatively counted like a nonzero
	// coefficient. This also excludes extreme zero exponents before jsonb.
	before := int64(integerDigits) + exponent - int64(firstNonzero)
	if before < 0 {
		before = 0
	}
	after := int64(fractionDigits) - exponent
	if after < 0 {
		after = 0
	}
	if before > pgNumericIntegerDigits || after > pgNumericFractionalDigits {
		return 0, invalidOptions("number is outside the supported database range")
	}
	if before == 0 {
		before = 1 // Leading zero for fractions.
	}
	size := sign + before + after
	if after > 0 {
		size++ // Decimal point; fractional trailing zeroes are retained by jsonb.
	}
	return size, nil
}

// Match the pure scanner used at the signer JSON boundary: encoding/json
// otherwise silently replaces unpaired UTF-16 escapes. Scan all strings,
// including nested keys, and distinguish an escaped backslash from \u0000.
func validateOptionsUnicodeEscapes(raw []byte) error {
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
				continue // The decoder reports incomplete JSON.
			}
			if raw[index+1] != 'u' {
				index++
				continue
			}
			code, ok := optionsHexQuad(raw, index+2)
			if !ok {
				return invalidOptions("must contain valid JSON Unicode escapes")
			}
			index += 5
			switch {
			case code == 0:
				return invalidOptions("JSON keys and strings must not contain NUL")
			case code >= 0xd800 && code <= 0xdbff:
				pair := index + 1
				if pair+5 >= len(raw) || raw[pair] != '\\' || raw[pair+1] != 'u' {
					return invalidOptions("JSON Unicode surrogate escapes must be paired")
				}
				low, valid := optionsHexQuad(raw, pair+2)
				if !valid || low < 0xdc00 || low > 0xdfff {
					return invalidOptions("JSON Unicode surrogate escapes must be paired")
				}
				index = pair + 5
			case code >= 0xdc00 && code <= 0xdfff:
				return invalidOptions("JSON Unicode surrogate escapes must be paired")
			}
		}
	}
	return nil
}

func optionsHexQuad(raw []byte, start int) (uint16, bool) {
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
