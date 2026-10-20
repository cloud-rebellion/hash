// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

// An independently owned continuation cannot retain a dynamic field from the
// old SQL/SDK document owner. Walk the actual generated model so new mutable
// columns require explicit native clone AND source-derived price coverage.
func TestHistoricalResumePrivateClonesCoverEveryDynamicGeneratedFieldV1(t *testing.T) {
	doc := &generated.Document{}
	v := reflect.ValueOf(doc).Elem()
	textType := reflect.TypeOf(pgtype.Text{})
	expected := int64(0)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch {
		case f.Kind() == reflect.String:
			value := fmt.Sprintf("source-%d-", i) + strings.Repeat("x", 4096)
			f.SetString(value)
			expected += int64(len(value))
		case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.Uint8:
			raw := []byte(strings.Repeat("b", 4096))
			f.Set(reflect.ValueOf(raw).Convert(f.Type()))
			expected += int64(len(raw))
		case f.Type() == textType:
			value := fmt.Sprintf("opaque-version-%d-", i) + strings.Repeat("y", 4096)
			f.Set(reflect.ValueOf(pgtype.Text{String: value, Valid: true}))
			expected += int64(len(value))
		}
	}
	raw, err := historicalResumeDocumentRawBytesV1(doc)
	if err != nil || raw != expected {
		t.Fatalf("private clone price misses a generated dynamic field: got%d expected%d err%v", raw, expected, err)
	}
	private, view := htmlSendCloneDocumentV1(doc), htmlSendCloneDocumentV1(doc)
	if !reflect.DeepEqual(private, doc) || !reflect.DeepEqual(view, doc) {
		t.Fatal("native clone changed source tuple")
	}
	p, u := reflect.ValueOf(private).Elem(), reflect.ValueOf(view).Elem()
	for i := 0; i < v.NumField(); i++ {
		source, a, b := v.Field(i), p.Field(i), u.Field(i)
		name := v.Type().Field(i).Name
		switch {
		case source.Kind() == reflect.String:
			if unsafe.StringData(source.String()) == unsafe.StringData(a.String()) || unsafe.StringData(a.String()) == unsafe.StringData(b.String()) {
				t.Fatalf("private/public clone borrows source string %s", name)
			}
		case source.Kind() == reflect.Slice && source.Type().Elem().Kind() == reflect.Uint8:
			if source.Pointer() == a.Pointer() || a.Pointer() == b.Pointer() {
				t.Fatalf("private/public clone borrows source bytes %s", name)
			}
			source.Index(0).SetUint('z')
			b.Index(0).SetUint('q')
			if a.Index(0).Uint() != 'b' {
				t.Fatalf("source/public mutation changed private %s", name)
			}
		case source.Type() == textType:
			before, own, public := source.Interface().(pgtype.Text), a.Interface().(pgtype.Text), b.Interface().(pgtype.Text)
			if unsafe.StringData(before.String) == unsafe.StringData(own.String) || unsafe.StringData(own.String) == unsafe.StringData(public.String) {
				t.Fatalf("private/public clone borrows opaque identity %s", name)
			}
		}
	}
}
func TestHistoricalResumeRetirementCannotMintSourceOrCommitAuthorityV1(t *testing.T) {
	if _, _, err := (*ApplicationHistoricalFinalizationSourceEvidenceV1)(nil).newHistoricalPrivateIntentContinuationV1(nil, nil); err == nil {
		t.Fatal("invented continuation accepted")
	}
	original, next := &ApplicationHistoricalFinalizationSourceEvidenceV1{}, &ApplicationHistoricalFinalizationSourceEvidenceV1{}
	original.self = original
	next.self = next
	if err := original.RetireHistoricalVersionConsumersV1(next); err == nil {
		t.Fatal("invented private clone/commit retired source")
	}
	if _, err := historicalResumeDocumentCloneRawV1(nil); err == nil {
		t.Fatal("missing original source priced")
	}
}
