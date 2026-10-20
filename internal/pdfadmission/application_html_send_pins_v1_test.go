// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"reflect"
	"testing"
)

func mutateHTMLSendPinFieldV1(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(!v.Bool())
		return true
	case reflect.String:
		v.SetString(v.String() + "changed")
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(v.Int() + 1)
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
		return true
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			v.SetBytes([]byte{1})
			return true
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if v.Index(i).CanSet() && mutateHTMLSendPinFieldV1(v.Index(i)) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() && mutateHTMLSendPinFieldV1(v.Field(i)) {
				return true
			}
		}
	}
	return false
}

// All82 actual generated fields are independently perturbed. The only pin
// mutation exceptions are those four columns actually written by the SQL.
// This is a source inventory oracle, never native scope/transaction authority.
func TestHTMLSendEvidencePinBindsEveryOriginalFieldV1(t *testing.T) {
	typ := reflect.TypeOf(generated.Document{})
	if typ.NumField() != 82 {
		t.Fatalf("Document field inventory changed: %d", typ.NumField())
	}
	allowed := map[string]bool{"PdfStorageVersionID": true, "RenderedPdfVersionID": true, "EvidenceVersionPinsRequired": true, "UpdatedAt": true}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		t.Run(name, func(t *testing.T) {
			before := &generated.Document{}
			after := &generated.Document{}
			if !mutateHTMLSendPinFieldV1(reflect.ValueOf(after).Elem().Field(i)) {
				t.Fatal("uncovered field kind")
			}
			if got := htmlSendEvidencePinnedTupleEqualV1(before, after); got != allowed[name] {
				t.Fatalf("pin equality=%v, allowed=%v", got, allowed[name])
			}
			if htmlSendDocumentExactTupleEqualV1(before, after) {
				t.Fatal("exact tuple omitted field")
			}
		})
	}
}
func TestHTMLSendEvidencePinPreservesNilBytePinsV1(t *testing.T) {
	before := &generated.Document{}
	after := &generated.Document{HtmlSourceJson: []byte{}}
	if htmlSendEvidencePinnedTupleEqualV1(before, after) {
		t.Fatal("nil and empty source pins became interchangeable")
	}
	if !htmlSendEvidencePinnedTupleEqualV1(before, before) || htmlSendEvidencePinnedTupleEqualV1(before, nil) {
		t.Fatal("identity or absence changed")
	}
}
