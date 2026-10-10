// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package htmlmaster validates reusable, inert HTML designs and materializes
// declared values and editable text without evaluating templates or fetching
// resources. Approval, tenant authority and exact-PDF review belong to callers.
package htmlmaster

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	SchemaVersion        = 1
	MaxMasterJSONBytes   = 12 << 20
	MaxHTMLBytes         = 256 << 10
	MaxCSSBytes          = 128 << 10
	MaxAssets            = 16
	MaxAssetBytes        = 2 << 20
	MaxTotalAssetBytes   = 8 << 20
	MaxValueChars        = 8192
	MaxSectionChars      = 32768
	MaxDefinitions       = 64
	MaxMaterializedBytes = 16 << 20
)

var (
	ErrInvalid       = errors.New("invalid HTML master")
	ErrLimit         = errors.New("HTML master exceeds limits")
	ErrMissingValues = errors.New("required HTML master values are missing")
	namePattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type Master struct {
	SchemaVersion int       `json:"schema_version"`
	HTML          string    `json:"html"`
	CSS           string    `json:"css"`
	Values        []Value   `json:"values,omitempty"`
	Sections      []Section `json:"sections,omitempty"`
	Assets        []Asset   `json:"assets,omitempty"`
}

type Value struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	MaxChars int    `json:"max_chars"`
}

type Section struct {
	Name        string `json:"name"`
	DefaultText string `json:"default_text"`
	MaxChars    int    `json:"max_chars"`
}

type Asset struct {
	Name       string `json:"name"`
	MediaType  string `json:"media_type"`
	DataBase64 string `json:"data_base64"`
	SHA256     string `json:"sha256"`
}

type Input struct {
	Values   map[string]string `json:"values"`
	Sections map[string]string `json:"sections"`
}

type Result struct {
	HTML            string   `json:"html"`
	MasterDigest    string   `json:"master_digest"`
	ContentDigest   string   `json:"content_digest"`
	ChangedSections []string `json:"changed_sections"`
}

// TemplateCommitment binds approved default values as well as every master
// byte, definition, default section and asset. Required defaults may be blank;
// Materialize checks completeness when a document is instantiated.
type TemplateCommitment struct {
	MasterJSON   json.RawMessage
	DefaultsJSON json.RawMessage
	SHA256       string
}

// Decode refuses unknown fields, duplicate object keys, malformed Unicode and
// trailing JSON. Compile performs the structural and asset-policy validation.
func Decode(raw []byte) (Master, error) {
	var master Master
	if err := strictJSON(raw, &master, MaxMasterJSONBytes); err != nil {
		return master, err
	}
	return master, nil
}

func CanonicalTemplate(masterJSON, defaultVariablesJSON []byte) (TemplateCommitment, error) {
	var result TemplateCommitment
	master, err := Decode(masterJSON)
	if err != nil {
		return result, err
	}
	compiled, err := Compile(master)
	if err != nil {
		return result, err
	}
	defaults := map[string]string{}
	if err := strictJSON(defaultVariablesJSON, &defaults, MaxDefinitions*MaxValueChars*4+4096); err != nil {
		return result, err
	}
	if defaults == nil {
		return result, invalid("default values must be an object")
	}
	if err := compiled.validateValues(defaults, false); err != nil {
		return result, err
	}
	canonicalDefaults, err := json.Marshal(defaults)
	if err != nil {
		return result, invalid("cannot encode default values")
	}
	result.MasterJSON = compiled.CanonicalJSON()
	result.DefaultsJSON = canonicalDefaults
	envelope := struct {
		Master   json.RawMessage `json:"master"`
		Defaults json.RawMessage `json:"defaults"`
	}{result.MasterJSON, result.DefaultsJSON}
	canonical, _ := json.Marshal(envelope)
	result.SHA256 = digest("hash.html-template.v1", canonical)
	return result, nil
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalid, reason) }
func limited(reason string) error { return fmt.Errorf("%w: %s", ErrLimit, reason) }

func digest(domain string, content []byte) string {
	h := sha256.New()
	_, _ = io.WriteString(h, domain+"\x00")
	_, _ = h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

func validText(text string, maxChars int) bool {
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) > maxChars {
		return false
	}
	for _, r := range text {
		if (r < 0x20 && r != '\n' && r != '\r' && r != '\t') || r == 0x7f {
			return false
		}
	}
	return true
}

func strictJSON(raw []byte, destination any, maxBytes int) error {
	if len(raw) == 0 {
		return invalid("empty JSON")
	}
	if len(raw) > maxBytes {
		return limited("JSON bytes")
	}
	if !utf8.Valid(raw) || !validJSONEscapes(raw) {
		return invalid("malformed JSON Unicode")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := checkJSONValue(decoder, 0, reflect.TypeOf(destination).Elem()); err != nil {
		return invalid("malformed, unknown or duplicate JSON fields")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid("trailing JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return invalid("JSON shape or unknown fields")
	}
	return nil
}

func checkJSONValue(decoder *json.Decoder, depth int, shape reflect.Type) error {
	if depth > 16 {
		return ErrLimit
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		if token == nil {
			return ErrInvalid
		}
		if shape.Kind() == reflect.String {
			if _, ok := token.(string); !ok {
				return ErrInvalid
			}
		}
		if shape.Kind() == reflect.Struct || shape.Kind() == reflect.Map || shape.Kind() == reflect.Slice {
			return ErrInvalid
		}
		return nil
	}
	if delim == '{' {
		if shape.Kind() != reflect.Struct && shape.Kind() != reflect.Map {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			var child reflect.Type
			if shape.Kind() == reflect.Map {
				child = shape.Elem()
			} else {
				for i := 0; i < shape.NumField(); i++ {
					field := shape.Field(i)
					if strings.Split(field.Tag.Get("json"), ",")[0] == name {
						child = field.Type
						break
					}
				}
				if child == nil {
					return ErrInvalid
				}
			}
			if err := checkJSONValue(decoder, depth+1, child); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		if shape.Kind() != reflect.Slice {
			return ErrInvalid
		}
		for decoder.More() {
			if err := checkJSONValue(decoder, depth+1, shape.Elem()); err != nil {
				return err
			}
		}
	} else {
		return ErrInvalid
	}
	_, err = decoder.Token()
	return err
}

// encoding/json replaces lone UTF-16 surrogates with U+FFFD. Refuse those
// spellings before decoding so commitments never silently rewrite input.
func validJSONEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		hexBytes, err := hex.DecodeString(string(raw[i+1 : i+5]))
		if err != nil {
			return false
		}
		value := uint16(hexBytes[0])<<8 | uint16(hexBytes[1])
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		hexBytes, err = hex.DecodeString(string(raw[i+3 : i+7]))
		if err != nil {
			return false
		}
		low := uint16(hexBytes[0])<<8 | uint16(hexBytes[1])
		if low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return !inString
}

func isBlank(text string) bool { return strings.TrimSpace(text) == "" }
