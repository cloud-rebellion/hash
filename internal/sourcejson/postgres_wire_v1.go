// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sourcejson

import (
	"context"
	"errors"
	"math"
	"unicode/utf8"
)

// ErrPostgreSQLWireV1 deliberately contains no caller-controlled JSON.
var ErrPostgreSQLWireV1 = errors.New("sourcejson: PostgreSQL JSONB wire bound unavailable")

// PostgreSQLJSONBWireUpperBoundV1 reads the ACTUAL SQL input without copying,
// decoding to maps, expanding numbers or changing its spelling. The result is
// data, never admission, an original-row proof, authority or readiness.
//
// For UTF8 PostgreSQL jsonb_out, object/array punctuation has at most the
// counted separators; output key ordering does not change its byte total.
// An input JSON string token upper-bounds its escaped output token: Unicode
// escapes/surrogate pairs can shrink to UTF8; controls, quote and backslash
// already have an equally long or longer required input escape. Numeric output
// is different: decimal exponents can expand a short token into many zeroes.
// The number parser explicitly charges that expansion including preserved
// decimal scale, rather than multiplying unrestricted RawMessage lengths.
//
// Call this before dispatch, keep the actual input under its owner's loan,
// and qualify the pinned server's byte wire oracle. Stored JSONB, compressed
// pg_column_size, caller lengths and later equality checks are not inputs to
// this function. Unsupported overflow, Unicode/NUL or excessive depth refuse;
// no truncated body or guessed fallback is returned.
func PostgreSQLJSONBWireUpperBoundV1(ctx context.Context, raw []byte) (int64, error) {
	if ctx == nil || ctx.Err() != nil || len(raw) == 0 {
		return 0, wireErrorV1(ctx)
	}
	if _, ok := ctx.Deadline(); !ok {
		return 0, ErrPostgreSQLWireV1
	}
	p := postgresWireParserV1{ctx: ctx, raw: raw}
	n, err := p.value(0)
	if err != nil {
		return 0, wireErrorV1(ctx)
	}
	p.space()
	if p.pos != len(raw) || ctx.Err() != nil {
		return 0, wireErrorV1(ctx)
	}
	return n, nil
}
func wireErrorV1(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ErrPostgreSQLWireV1, ctx.Err())
	}
	return ErrPostgreSQLWireV1
}

type postgresWireParserV1 struct {
	ctx   context.Context
	raw   []byte
	pos   int
	steps int
}

func (p *postgresWireParserV1) check() error {
	p.steps++
	if p.steps&4095 == 0 {
		return p.ctx.Err()
	}
	return nil
}
func wireAddV1(a, b int64) (int64, error) {
	if a < 0 || b < 0 || b > math.MaxInt64-a {
		return 0, ErrPostgreSQLWireV1
	}
	return a + b, nil
}
func (p *postgresWireParserV1) space() {
	for p.pos < len(p.raw) {
		switch p.raw[p.pos] {
		case ' ', '\t', '\r', '\n':
			if p.check() != nil {
				p.pos = len(p.raw) + 1
				return
			}
			p.pos++
		default:
			return
		}
	}
}
func (p *postgresWireParserV1) value(depth int) (int64, error) {
	if depth > 64 || p.check() != nil {
		return 0, ErrPostgreSQLWireV1
	}
	p.space()
	if p.pos >= len(p.raw) {
		return 0, ErrPostgreSQLWireV1
	}
	switch p.raw[p.pos] {
	case '"':
		return p.string()
	case '{':
		p.pos++
		p.space()
		if p.pos < len(p.raw) && p.raw[p.pos] == '}' {
			p.pos++
			return 2, nil
		}
		total := int64(2)
		for {
			p.space()
			key, err := p.string()
			if err != nil {
				return 0, err
			}
			p.space()
			if p.pos >= len(p.raw) || p.raw[p.pos] != ':' {
				return 0, ErrPostgreSQLWireV1
			}
			p.pos++
			body, err := p.value(depth + 1)
			if err != nil {
				return 0, err
			}
			for _, n := range []int64{key, 2, body} {
				total, err = wireAddV1(total, n)
				if err != nil {
					return 0, err
				}
			}
			p.space()
			if p.pos >= len(p.raw) {
				return 0, ErrPostgreSQLWireV1
			}
			if p.raw[p.pos] == '}' {
				p.pos++
				return total, nil
			}
			if p.raw[p.pos] != ',' {
				return 0, ErrPostgreSQLWireV1
			}
			p.pos++
			total, err = wireAddV1(total, 2)
			if err != nil {
				return 0, err
			}
		}
	case '[':
		p.pos++
		p.space()
		if p.pos < len(p.raw) && p.raw[p.pos] == ']' {
			p.pos++
			return 2, nil
		}
		total := int64(2)
		for {
			body, err := p.value(depth + 1)
			if err != nil {
				return 0, err
			}
			total, err = wireAddV1(total, body)
			if err != nil {
				return 0, err
			}
			p.space()
			if p.pos >= len(p.raw) {
				return 0, ErrPostgreSQLWireV1
			}
			if p.raw[p.pos] == ']' {
				p.pos++
				return total, nil
			}
			if p.raw[p.pos] != ',' {
				return 0, ErrPostgreSQLWireV1
			}
			p.pos++
			total, err = wireAddV1(total, 2)
			if err != nil {
				return 0, err
			}
		}
	case 't':
		return p.literal("true")
	case 'f':
		return p.literal("false")
	case 'n':
		return p.literal("null")
	default:
		return p.number()
	}
}
func (p *postgresWireParserV1) literal(word string) (int64, error) {
	if len(p.raw)-p.pos < len(word) {
		return 0, ErrPostgreSQLWireV1
	}
	for i := range word {
		if p.raw[p.pos+i] != word[i] {
			return 0, ErrPostgreSQLWireV1
		}
	}
	p.pos += len(word)
	return int64(len(word)), nil
}
func wireHexV1(c byte) (uint16, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint16(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint16(c - 'a' + 10), true
	case c >= 'A' && c <= 'F':
		return uint16(c - 'A' + 10), true
	default:
		return 0, false
	}
}
func (p *postgresWireParserV1) hex4() (uint16, error) {
	if len(p.raw)-p.pos < 4 {
		return 0, ErrPostgreSQLWireV1
	}
	var value uint16
	for i := 0; i < 4; i++ {
		h, ok := wireHexV1(p.raw[p.pos+i])
		if !ok {
			return 0, ErrPostgreSQLWireV1
		}
		value = value*16 + h
	}
	p.pos += 4
	return value, nil
}
func (p *postgresWireParserV1) string() (int64, error) {
	start := p.pos
	if p.pos >= len(p.raw) || p.raw[p.pos] != '"' {
		return 0, ErrPostgreSQLWireV1
	}
	p.pos++
	for p.pos < len(p.raw) {
		if p.check() != nil {
			return 0, ErrPostgreSQLWireV1
		}
		b := p.raw[p.pos]
		p.pos++
		switch {
		case b == '"':
			return int64(p.pos - start), nil
		case b < 0x20:
			return 0, ErrPostgreSQLWireV1
		case b == '\\':
			if p.pos >= len(p.raw) {
				return 0, ErrPostgreSQLWireV1
			}
			escape := p.raw[p.pos]
			p.pos++
			switch escape {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				value, err := p.hex4()
				if err != nil || value == 0 || value >= 0xdc00 && value <= 0xdfff {
					return 0, ErrPostgreSQLWireV1
				}
				if value >= 0xd800 && value <= 0xdbff {
					if len(p.raw)-p.pos < 6 || p.raw[p.pos] != '\\' || p.raw[p.pos+1] != 'u' {
						return 0, ErrPostgreSQLWireV1
					}
					p.pos += 2
					low, err := p.hex4()
					if err != nil || low < 0xdc00 || low > 0xdfff {
						return 0, ErrPostgreSQLWireV1
					}
				}
			default:
				return 0, ErrPostgreSQLWireV1
			}
		case b >= utf8.RuneSelf:
			p.pos--
			_, size := utf8.DecodeRune(p.raw[p.pos:])
			if size == 1 {
				return 0, ErrPostgreSQLWireV1
			}
			p.pos += size
		}
	}
	return 0, ErrPostgreSQLWireV1
}
func (p *postgresWireParserV1) digit() bool {
	return p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9'
}
func (p *postgresWireParserV1) number() (int64, error) {
	negative := int64(0)
	if p.pos < len(p.raw) && p.raw[p.pos] == '-' {
		negative = 1
		p.pos++
	}
	integerStart := p.pos
	if !p.digit() {
		return 0, ErrPostgreSQLWireV1
	}
	if p.raw[p.pos] == '0' {
		p.pos++
		if p.digit() {
			return 0, ErrPostgreSQLWireV1
		}
	} else {
		for p.digit() {
			if p.check() != nil {
				return 0, ErrPostgreSQLWireV1
			}
			p.pos++
		}
	}
	integerDigits := int64(p.pos - integerStart)
	fractionDigits := int64(0)
	if p.pos < len(p.raw) && p.raw[p.pos] == '.' {
		p.pos++
		start := p.pos
		for p.digit() {
			if p.check() != nil {
				return 0, ErrPostgreSQLWireV1
			}
			p.pos++
		}
		if p.pos == start {
			return 0, ErrPostgreSQLWireV1
		}
		fractionDigits = int64(p.pos - start)
	}
	exponent := int64(0)
	if p.pos < len(p.raw) && (p.raw[p.pos] == 'e' || p.raw[p.pos] == 'E') {
		p.pos++
		sign := int64(1)
		if p.pos < len(p.raw) && (p.raw[p.pos] == '+' || p.raw[p.pos] == '-') {
			if p.raw[p.pos] == '-' {
				sign = -1
			}
			p.pos++
		}
		if !p.digit() {
			return 0, ErrPostgreSQLWireV1
		}
		for p.digit() {
			if p.check() != nil {
				return 0, ErrPostgreSQLWireV1
			}
			digit := int64(p.raw[p.pos] - '0')
			if exponent > (math.MaxInt64-digit)/10 {
				return 0, ErrPostgreSQLWireV1
			}
			exponent = exponent*10 + digit
			p.pos++
		}
		exponent *= sign
	}
	// A coefficient has integerDigits+fractionDigits digits. Exponent moves
	// the decimal point; output scale remains max(fractionDigits-exponent,0).
	digits, err := wireAddV1(integerDigits, fractionDigits)
	if err != nil {
		return 0, err
	}
	if exponent > math.MaxInt64-integerDigits {
		return 0, ErrPostgreSQLWireV1
	}
	point := integerDigits + exponent
	var output int64
	switch {
	case point >= digits:
		output = point
	case point > 0:
		output, err = wireAddV1(digits, 1)
	default:
		// point cannot equal MinInt64: exponent was parsed symmetrically
		// within MaxInt64 and integerDigits is at least one.
		output, err = wireAddV1(digits, -point)
		if err == nil {
			output, err = wireAddV1(output, 2)
		}
	}
	if err != nil {
		return 0, err
	}
	return wireAddV1(output, negative)
}
