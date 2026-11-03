// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sourcejson

import (
	"context"
)

// LookupASCIIObjectFieldV1 borrows one top-level JSON value without decoding or
// allocating unrelated metadata. It reuses the native bounded-depth/UTF-8 JSONB
// lexical parser and honors cancellation. The caller already owns the input
// body; output aliases it and grants no input/SQL/application authority.
// Only the selected key must be unique; database JSONB has already canonicalized
// other keys. Contractual writers must still use Validate before map decoding.
func LookupASCIIObjectFieldV1(ctx context.Context, raw []byte, key string) ([]byte, bool, error) {
	if ctx == nil || ctx.Err() != nil || len(key) == 0 || len(key) > 128 {
		return nil, false, ErrPostgreSQLWireV1
	}
	for _, b := range []byte(key) {
		if b < 32 || b > 126 {
			return nil, false, ErrPostgreSQLWireV1
		}
	}
	p := postgresWireParserV1{ctx: ctx, raw: raw}
	p.space()
	if p.pos >= len(raw) || raw[p.pos] != '{' {
		return nil, false, ErrPostgreSQLWireV1
	}
	p.pos++
	p.space()
	var result []byte
	found := false
	if p.pos < len(raw) && raw[p.pos] == '}' {
		p.pos++
	} else {
		for {
			p.space()
			start := p.pos
			if _, err := p.string(); err != nil {
				return nil, false, wireErrorV1(ctx)
			}
			encoded := raw[start:p.pos]
			p.space()
			if p.pos >= len(raw) || raw[p.pos] != ':' {
				return nil, false, ErrPostgreSQLWireV1
			}
			p.pos++
			p.space()
			start = p.pos
			if _, err := p.value(1); err != nil {
				return nil, false, wireErrorV1(ctx)
			}
			if asciiJSONKeyEqualsV1(encoded, key) {
				if found {
					return nil, false, ErrAmbiguousResponse
				}
				found = true
				result = raw[start:p.pos]
			}
			p.space()
			if p.pos >= len(raw) {
				return nil, false, ErrPostgreSQLWireV1
			}
			if raw[p.pos] == '}' {
				p.pos++
				break
			}
			if raw[p.pos] != ',' {
				return nil, false, ErrPostgreSQLWireV1
			}
			p.pos++
		}
	}
	p.space()
	if p.pos != len(raw) || ctx.Err() != nil {
		return nil, false, wireErrorV1(ctx)
	}
	return result, found, nil
}
func asciiJSONKeyEqualsV1(raw []byte, key string) bool {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return false
	}
	j := 0
	for i := 1; i < len(raw)-1; {
		b := raw[i]
		i++
		if b == '\\' {
			if i >= len(raw)-1 {
				return false
			}
			b = raw[i]
			i++
			switch b {
			case 'u':
				if i+4 > len(raw)-1 {
					return false
				}
				var n uint16
				for k := 0; k < 4; k++ {
					v, ok := wireHexV1(raw[i+k])
					if !ok {
						return false
					}
					n = n*16 + v
				}
				i += 4
				if n > 127 {
					return false
				}
				b = byte(n)
			case '"', '\\', '/':
			case 'b':
				b = '\b'
			case 'f':
				b = '\f'
			case 'n':
				b = '\n'
			case 'r':
				b = '\r'
			case 't':
				b = '\t'
			default:
				return false
			}
		}
		if j >= len(key) || b != key[j] {
			return false
		}
		j++
	}
	return j == len(key)
}
