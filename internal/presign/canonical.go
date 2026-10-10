// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

func canonical(value any, domain string) ([]byte, string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, "", invalid("canonical encoding")
	}
	raw := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	if len(raw) == 0 || len(raw) > MaxSnapshotBytes {
		return nil, "", invalid("canonical size")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(raw)
	return append([]byte(nil), raw...), hex.EncodeToString(hash.Sum(nil)), nil
}

func NewPolicy(snapshot PolicySnapshot) (Policy, error) {
	if err := validatePolicy(snapshot); err != nil {
		return Policy{}, err
	}
	normalizeTimes(reflect.ValueOf(&snapshot).Elem())
	raw, commitment, err := canonical(snapshot, PolicyDomain)
	if err != nil {
		return Policy{}, err
	}
	return Policy{snapshot: snapshot, canonical: raw, commitment: commitment}, nil
}

func NewGrant(snapshot GrantSnapshot) (Grant, error) {
	if err := validateGrant(snapshot); err != nil {
		return Grant{}, err
	}
	normalizeTimes(reflect.ValueOf(&snapshot).Elem())
	raw, commitment, err := canonical(snapshot, GrantDomain)
	if err != nil {
		return Grant{}, err
	}
	return Grant{snapshot: snapshot, canonical: raw, commitment: commitment}, nil
}

func NewExecution(snapshot ExecutionSnapshot) (Execution, error) {
	if err := validateExecution(snapshot); err != nil {
		return Execution{}, err
	}
	normalizeTimes(reflect.ValueOf(&snapshot).Elem())
	raw, commitment, err := canonical(snapshot, ExecutionDomain)
	if err != nil {
		return Execution{}, err
	}
	return Execution{snapshot: snapshot, canonical: raw, commitment: commitment}, nil
}

func (p Policy) MarshalJSON() ([]byte, error) {
	if !validSHA(p.commitment) {
		return nil, invalid("uninitialized policy")
	}
	return p.CanonicalJSON(), nil
}
func (g Grant) MarshalJSON() ([]byte, error) {
	if !validSHA(g.commitment) {
		return nil, invalid("uninitialized grant")
	}
	return g.CanonicalJSON(), nil
}
func (e Execution) MarshalJSON() ([]byte, error) {
	if !validSHA(e.commitment) {
		return nil, invalid("uninitialized execution")
	}
	return e.CanonicalJSON(), nil
}

func DecodePolicy(raw []byte) (Policy, error) {
	var snapshot PolicySnapshot
	if err := decodeSnapshot(raw, &snapshot); err != nil {
		return Policy{}, err
	}
	return NewPolicy(snapshot)
}
func DecodeGrant(raw []byte) (Grant, error) {
	var snapshot GrantSnapshot
	if err := decodeSnapshot(raw, &snapshot); err != nil {
		return Grant{}, err
	}
	return NewGrant(snapshot)
}
func DecodeExecution(raw []byte) (Execution, error) {
	var snapshot ExecutionSnapshot
	if err := decodeSnapshot(raw, &snapshot); err != nil {
		return Execution{}, err
	}
	return NewExecution(snapshot)
}

func (p *Policy) UnmarshalJSON(raw []byte) error {
	if p == nil {
		return invalid("nil policy target")
	}
	decoded, err := DecodePolicy(raw)
	if err != nil {
		return err
	}
	*p = decoded
	return nil
}
func (g *Grant) UnmarshalJSON(raw []byte) error {
	if g == nil {
		return invalid("nil grant target")
	}
	decoded, err := DecodeGrant(raw)
	if err != nil {
		return err
	}
	*g = decoded
	return nil
}
func (e *Execution) UnmarshalJSON(raw []byte) error {
	if e == nil {
		return invalid("nil execution target")
	}
	decoded, err := DecodeExecution(raw)
	if err != nil {
		return err
	}
	*e = decoded
	return nil
}

var timeType = reflect.TypeFor[time.Time]()
var uuidType = reflect.TypeFor[uuid.UUID]()

// Drop monotonic/location details before equality and encoding. The validators
// require UTC-offset microsecond timestamps; no deadline rounding is performed.
func normalizeTimes(value reflect.Value) {
	if value.Type() == timeType {
		value.Set(reflect.ValueOf(value.Interface().(time.Time).Round(0).UTC()))
		return
	}
	if value.Type() == uuidType {
		return
	}
	switch value.Kind() {
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			normalizeTimes(value.Field(i))
		}
	case reflect.Array:
		for i := 0; i < value.Len(); i++ {
			normalizeTimes(value.Index(i))
		}
	}
}

func decodeSnapshot(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > MaxSnapshotBytes || !utf8.Valid(raw) {
		return invalid("snapshot JSON size or UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	tokens := 0
	if err := walkJSON(decoder, 0, &tokens); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid("one JSON snapshot required")
	}
	if err := exactShape(raw, reflect.TypeOf(target).Elem()); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return invalid("snapshot JSON types")
	}
	return nil
}

// Validate tokens before map decoding so duplicate decoded keys, including
// escaped aliases, never become last-key-wins evidence. Shape validation below
// rejects case aliases, omissions, nulls and every unknown nested property.
func walkJSON(decoder *json.Decoder, depth int, tokens *int) error {
	if depth > 16 || *tokens > 8192 {
		return invalid("snapshot JSON complexity")
	}
	*tokens = *tokens + 1
	token, err := decoder.Token()
	if err != nil {
		return invalid("snapshot JSON syntax")
	}
	if value, ok := token.(string); ok && !validJSONString(value) {
		return invalid("snapshot JSON string")
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || !validJSONString(key) || seen[key] {
				return invalid("snapshot JSON duplicate or invalid key")
			}
			seen[key] = true
			if err := walkJSON(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return invalid("snapshot JSON object")
		}
	case '[':
		for decoder.More() {
			if err := walkJSON(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return invalid("snapshot JSON array")
		}
	default:
		return invalid("snapshot JSON delimiter")
	}
	return nil
}

func validJSONString(value string) bool {
	if len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

func exactShape(raw []byte, expected reflect.Type) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return invalid("snapshot JSON null or omission")
	}
	if expected == uuidType {
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return invalid("snapshot UUID type")
		}
		id, err := uuid.Parse(value)
		if err != nil || id.String() != value {
			return invalid("canonical snapshot UUID")
		}
		return nil
	}
	if expected == timeType {
		var value time.Time
		if json.Unmarshal(raw, &value) != nil || !validTime(value) {
			return invalid("snapshot timestamp")
		}
		encoded, err := json.Marshal(value.UTC())
		if err != nil || !bytes.Equal(encoded, raw) {
			return invalid("canonical snapshot timestamp")
		}
		return nil
	}
	switch expected.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if raw[0] != '{' || json.Unmarshal(raw, &fields) != nil || len(fields) != expected.NumField() {
			return invalid("exact snapshot JSON object keys")
		}
		for i := 0; i < expected.NumField(); i++ {
			field := expected.Field(i)
			name := field.Tag.Get("json")
			value, ok := fields[name]
			if name == "" || !ok {
				return invalid("exact snapshot JSON object keys")
			}
			if err := exactShape(value, field.Type); err != nil {
				return err
			}
		}
	case reflect.Array:
		var values []json.RawMessage
		if raw[0] != '[' || json.Unmarshal(raw, &values) != nil || len(values) != expected.Len() {
			return invalid("exact snapshot JSON array length")
		}
		for _, value := range values {
			if err := exactShape(value, expected.Elem()); err != nil {
				return err
			}
		}
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int64:
		if err := json.Unmarshal(raw, reflect.New(expected).Interface()); err != nil {
			return invalid("snapshot JSON scalar type")
		}
	default:
		return invalid("unsupported snapshot JSON type")
	}
	return nil
}
