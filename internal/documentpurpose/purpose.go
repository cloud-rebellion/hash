// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package documentpurpose separates authoring intent from source representation
// and the existing signature-versus-acknowledgement ceremony choice.
package documentpurpose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"reflect"
)

type Purpose string

const (
	Document     Purpose = "document"
	Presentation Purpose = "presentation"
	Signing      Purpose = "signing"
	MetadataKey          = "hash:document-purpose:v1"
)

var ErrInvalid = errors.New("document purpose is invalid")
var ErrSigningRequired = errors.New("switch this draft to signing mode before configuring or sending a signing workflow")
var ErrTransition = errors.New("remove recipients, signing fields and package or envelope setup before changing this draft's purpose")

func Validate(p Purpose) error {
	switch p {
	case Document, Presentation, Signing:
		return nil
	}
	return ErrInvalid
}
func IsReservedKey(key string) bool { return key == MetadataKey }

// Parse consumes already-admitted document metadata. Absent purpose keeps the
// historical signing behaviour; malformed reserved data never means signing.
func Parse(metadata []byte) (Purpose, error) {
	if len(metadata) == 0 || bytes.Equal(bytes.TrimSpace(metadata), []byte("{}")) {
		return Signing, nil
	}
	raw, exists, err := sourcejson.LookupASCIIObjectFieldV1(context.Background(), metadata, MetadataKey)
	if err != nil {
		return "", ErrInvalid
	}
	if !exists {
		return Signing, nil
	}
	if len(raw) > 256 || sourcejson.Validate(raw) != nil {
		return "", ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || fields["schema_version"] == nil || fields["purpose"] == nil {
		return "", ErrInvalid
	}
	var stored struct {
		SchemaVersion int     `json:"schema_version"`
		Purpose       Purpose `json:"purpose"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&stored) != nil || stored.SchemaVersion != 1 || Validate(stored.Purpose) != nil {
		return "", ErrInvalid
	}
	return stored.Purpose, nil
}
func RequireSigning(metadata []byte) error {
	p, err := Parse(metadata)
	if err != nil {
		return err
	}
	if p != Signing {
		return ErrSigningRequired
	}
	return nil
}

// With changes only the reserved authoring field. Caller owns the native parent,
// CAS, live credential, body admission, draft/evidence/privacy and audit fences.
func With(metadata []byte, p Purpose) ([]byte, error) {
	if len(metadata) == 0 {
		metadata = []byte("{}")
	}
	if Validate(p) != nil {
		return nil, ErrInvalid
	}
	if _, err := Parse(metadata); err != nil {
		return nil, err
	}
	if sourcejson.Validate(metadata) != nil {
		return nil, ErrInvalid
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(metadata, &obj) != nil || obj == nil {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(struct {
		SchemaVersion int     `json:"schema_version"`
		Purpose       Purpose `json:"purpose"`
	}{1, p})
	if err != nil {
		return nil, ErrInvalid
	}
	obj[MetadataKey] = raw
	return json.Marshal(obj)
}

func EqualMetadata(a, b []byte) (bool, error) {
	decode := func(raw []byte) (any, error) {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var v any
		err := d.Decode(&v)
		return v, err
	}
	x, err := decode(a)
	if err != nil {
		return false, ErrInvalid
	}
	y, err := decode(b)
	if err != nil {
		return false, ErrInvalid
	}
	return reflect.DeepEqual(x, y), nil
}

// Response never silently turns malformed reserved state into a signing badge.
func Response(metadata []byte) Purpose {
	p, err := Parse(metadata)
	if err != nil {
		return ""
	}
	return p
}

type DocumentView struct {
	*generated.Document
	Purpose Purpose `json:"purpose"`
}

func View(d *generated.Document) *DocumentView {
	if d == nil {
		return nil
	}
	return &DocumentView{d, Response(d.Metadata)}
}
func Views(rows []*generated.Document) []*DocumentView {
	out := make([]*DocumentView, len(rows))
	for i, d := range rows {
		out[i] = View(d)
	}
	return out
}

// Explicit null, empty and unknown values are not omission. Old clients that
// omit the field retain the zero creation value and legacy signing semantics.
func (p *Purpose) UnmarshalJSON(raw []byte) error {
	if p == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrInvalid
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return ErrInvalid
	}
	value := Purpose(text)
	if Validate(value) != nil {
		return ErrInvalid
	}
	*p = value
	return nil
}
