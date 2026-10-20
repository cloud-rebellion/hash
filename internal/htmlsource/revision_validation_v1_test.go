// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlsource

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/jackc/pgx/v5/pgtype"
)

func revisionOracleErrorV1(t *testing.T, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) || (got != nil && got.Error() != want.Error()) {
		t.Fatalf("got error %v; original oracle %v", got, want)
	}
}
func TestRevisionValidationStagesReuseOnlyExactOwnedDesignV1(t *testing.T) {
	_, doc := currentFixture(t)
	b, err := NewRevisionValidationBuilderV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.FinishV1(); err == nil {
		t.Fatal("unfinished operation escaped")
	}
	stages := map[RevisionValidationStageV1]int{}
	for {
		stage, err := b.StageV1()
		if err != nil {
			t.Fatal(err)
		}
		if stage == RevisionValidationDoneV1 {
			break
		}
		stages[stage]++
		switch stage {
		case RevisionValidationRawCompileV1:
			m, err := b.MasterV1()
			if err != nil {
				t.Fatal(err)
			}
			m.HTML = "<script>caller copy</script>"
			if len(m.Sections) > 0 {
				m.Sections[0].Name = "wrong"
			}
			in, err := b.InputV1()
			if err != nil {
				t.Fatal(err)
			}
			in.MasterJSON[0] = 'x'
			in.DefaultVarsJSON[0] = 'x'
			in.Values["customer_name"] = "caller copy"
			if err = b.PrepareRawV1(); err != nil {
				t.Fatal(err)
			}
			if err = b.PrepareRawV1(); err == nil {
				t.Fatal("raw stage replayed")
			}
		case RevisionValidationCanonicalCompileV1:
			m, err := b.MasterV1()
			if err != nil {
				t.Fatal(err)
			}
			m.HTML = "<script>caller copy</script>"
			c, err := b.CanonicalV1()
			if err != nil {
				t.Fatal(err)
			}
			c.MasterJSON[0] = 'x'
			c.DefaultsJSON[0] = 'x'
			if err = b.PrepareCanonicalV1(); err != nil {
				t.Fatal(err)
			}
		case RevisionValidationRecordV1:
			raw, _, err := b.RecordVariablesV1()
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) > 0 {
				raw[0] = 'x'
			}
			if err = b.ValidateRecordV1(); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("unknown stage")
		}
	}
	if stages[RevisionValidationRawCompileV1] != 1 || stages[RevisionValidationCanonicalCompileV1] != 1 || stages[RevisionValidationRecordV1] != 2 {
		t.Fatalf("same exact design was not reused: %v", stages)
	}
	v, err := b.FinishV1()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.FinishV1(); err == nil {
		t.Fatal("finished builder reused")
	}
	if !v.MatchesDocumentV1(doc) {
		t.Fatal("actual immutable pins lost")
	}
	current, err := v.CommitmentV1()
	if err != nil {
		t.Fatal(err)
	}
	wantCurrent, err := Commitment(doc)
	if err != nil || current != wantCurrent {
		t.Fatal("current oracle differs", err)
	}
	origin, err := v.OriginCommitmentV1()
	if err != nil {
		t.Fatal(err)
	}
	wantOrigin, err := OriginCommitment(doc)
	if err != nil || origin != wantOrigin || origin == current {
		t.Fatal("origin and current scopes conflated", err)
	}
	copied := *v
	if _, err = copied.CommitmentV1(); err == nil {
		t.Fatal("copied shell accepted")
	}
}

func TestRevisionValidationOriginalSourceOracleV1(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"good", func(*generated.Document) {}},
		{"source-kind", func(d *generated.Document) { d.SourceKind = "blocks" }},
		{"variables", func(d *generated.Document) { d.VariablesJson = []byte("{\"customer_name\":\"stale\"}") }},
		{"unknown", func(d *generated.Document) {
			d.HtmlSourceJson = append([]byte("{\"unknown\":1,"), d.HtmlSourceJson[1:]...)
		}},
		{"duplicate", func(d *generated.Document) {
			d.HtmlSourceJson = append([]byte("{\"schema_version\":1,"), d.HtmlSourceJson[1:]...)
		}},
		{"alias", func(d *generated.Document) {
			d.HtmlSourceJson = bytes.Replace(d.HtmlSourceJson, []byte("\"schema_version\""), []byte("\"SCHEMA_VERSION\""), 1)
		}},
		{"source-commitment", func(d *generated.Document) { replaceSourceField(t, d, "commitment", []byte("\"forged\"")) }},
		{"defaults", func(d *generated.Document) {
			replaceSourceField(t, d, "default_values", []byte("{\"customer_name\":\"other\"}"))
		}},
		{"master", func(d *generated.Document) {
			replaceSourceField(t, d, "master", []byte("{\"schema_version\":1,\"html\":\"<script>bad</script>\"}"))
		}},
		{"pdf-version", func(d *generated.Document) { d.PdfStorageVersionID.String = "wrong" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input, doc := sourceFixture(t)
			attachSource(t, input, doc)
			tc.mutate(doc)
			want := Validate(doc, false)
			v, got := NewRevisionValidationV1(doc)
			revisionOracleErrorV1(t, got, want)
			if want == nil {
				revisionOracleErrorV1(t, v.ValidateV1(true), Validate(doc, true))
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"good", func(*generated.Document) {}}, {"sequence-one", func(d *generated.Document) { d.HtmlCurrentMaterializationSequence.Int32 = 1 }}, {"missing-current", func(d *generated.Document) { d.HtmlCurrentSourceJson = nil }}, {"origin-bad", func(d *generated.Document) { d.HtmlSourceJson = []byte("{}") }},
	} {
		t.Run("normalized/"+tc.name, func(t *testing.T) {
			_, doc := currentFixture(t)
			tc.mutate(doc)
			_, got := NewRevisionValidationV1(doc)
			revisionOracleErrorV1(t, got, Validate(doc, false))
		})
	}
}

func TestRevisionValidationAbsentAndReviewOracleV1(t *testing.T) {
	empty := &generated.Document{}
	v, err := NewRevisionValidationV1(empty)
	if err != nil {
		t.Fatal(err)
	}
	revisionOracleErrorV1(t, v.ValidateV1(true), Validate(empty, true))
	_, got := v.CommitmentV1()
	_, want := Commitment(empty)
	revisionOracleErrorV1(t, got, want)
	_, got = v.OriginCommitmentV1()
	_, want = OriginCommitment(empty)
	revisionOracleErrorV1(t, got, want)
	_, got = v.InputForCurrentV1()
	_, want = InputForCurrent(empty)
	revisionOracleErrorV1(t, got, want)
	_, got = v.MaterializationDigestV1()
	_, want = MaterializationDigest(empty)
	revisionOracleErrorV1(t, got, want)
	_, got = v.ChangedSectionsV1()
	_, want = ChangedSections(empty)
	revisionOracleErrorV1(t, got, want)
	policy, artifact, err := v.SigningPageV1()
	if policy != nil || artifact != nil || err != nil {
		t.Fatal("absence gained signing policy")
	}
	input, doc := currentFixture(t)
	approveFixture(doc, input)
	for _, tc := range []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"old-materialization", func(*generated.Document) {}},
		{"correct", func(d *generated.Document) { d.HtmlReviewedMaterializationID = d.HtmlCurrentMaterializationID }},
		{"digest", func(d *generated.Document) {
			d.HtmlReviewedMaterializationID = d.HtmlCurrentMaterializationID
			d.HtmlReviewedPdfSha256 = bytes.Repeat([]byte{5}, 32)
		}},
		{"before-approval", func(d *generated.Document) {
			d.HtmlReviewedMaterializationID = d.HtmlCurrentMaterializationID
			d.HtmlReviewedAt.Time = input.TemplateApprovedAt.Add(-time.Hour)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := cloneRevisionDocumentV1(doc)
			tc.mutate(d)
			v, err := NewRevisionValidationV1(d)
			if err != nil {
				t.Fatal(err)
			}
			revisionOracleErrorV1(t, v.ValidateV1(true), Validate(d, true))
		})
	}
}

func TestRevisionValidationDocumentPinInventoryV1(t *testing.T) {
	d := &generated.Document{}
	rv := reflect.ValueOf(d).Elem()
	typ := rv.Type()
	variable := 0
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		switch field.Kind() {
		case reflect.String:
			field.SetString("owned-" + typ.Field(i).Name)
			variable++
		case reflect.Slice:
			field.SetBytes([]byte("owned-" + typ.Field(i).Name))
			variable++
		case reflect.Struct:
			if field.Type() == reflect.TypeOf(pgtype.Text{}) {
				field.Set(reflect.ValueOf(pgtype.Text{String: "owned-" + typ.Field(i).Name, Valid: true}))
				variable++
			}
		}
	}
	if variable != 40 || rv.NumField() != 82 {
		t.Fatalf("Document inventory changed: variable%d fields%d", variable, rv.NumField())
	}
	clone := cloneRevisionDocumentV1(d)
	if !revisionDocumentEqualV1(d, clone) {
		t.Fatal("clone pins differ")
	}
	cv := reflect.ValueOf(clone).Elem()
	for i := 0; i < rv.NumField(); i++ {
		a, b := rv.Field(i), cv.Field(i)
		switch a.Kind() {
		case reflect.String:
			if a.Len() > 0 && unsafe.StringData(a.String()) == unsafe.StringData(b.String()) {
				t.Fatalf("string backing alias %s", typ.Field(i).Name)
			}
		case reflect.Slice:
			if a.Len() > 0 {
				old := append([]byte(nil), b.Bytes()...)
				a.Index(0).SetUint(uint64('x'))
				if !bytes.Equal(old, b.Bytes()) {
					t.Fatalf("byte backing alias %s", typ.Field(i).Name)
				}
				a.Index(0).SetUint(uint64(old[0]))
			}
		case reflect.Struct:
			if a.Type() == reflect.TypeOf(pgtype.Text{}) {
				x, y := a.Interface().(pgtype.Text), b.Interface().(pgtype.Text)
				if unsafe.StringData(x.String) == unsafe.StringData(y.String) {
					t.Fatalf("Text backing alias %s", typ.Field(i).Name)
				}
			}
		}
	}
	for i := 0; i < rv.NumField(); i++ {
		changed := cloneRevisionDocumentV1(d)
		field := reflect.ValueOf(changed).Elem().Field(i)
		switch field.Kind() {
		case reflect.Bool:
			field.SetBool(!field.Bool())
		case reflect.Int32, reflect.Int64:
			field.SetInt(field.Int() + 1)
		case reflect.String:
			field.SetString(field.String() + "-changed")
		case reflect.Slice:
			field.SetBytes([]byte("changed"))
		case reflect.Array:
			field.Index(0).SetUint(field.Index(0).Uint() ^ 1)
		case reflect.Struct:
			switch x := field.Interface().(type) {
			case pgtype.Text:
				x.Valid = !x.Valid
				field.Set(reflect.ValueOf(x))
			case pgtype.UUID:
				x.Valid = !x.Valid
				field.Set(reflect.ValueOf(x))
			case pgtype.Int4:
				x.Valid = !x.Valid
				field.Set(reflect.ValueOf(x))
			case pgtype.Int8:
				x.Valid = !x.Valid
				field.Set(reflect.ValueOf(x))
			case pgtype.Timestamptz:
				x.Valid = !x.Valid
				field.Set(reflect.ValueOf(x))
			default:
				t.Fatalf("unhandled pin type %s", field.Type())
			}
		default:
			t.Fatalf("unhandled pin kind %s", field.Kind())
		}
		if revisionDocumentEqualV1(d, changed) {
			t.Fatalf("pin omitted: %s", typ.Field(i).Name)
		}
	}
}

func TestRevisionValidationCallerMutationAndPreparedInputOracleV1(t *testing.T) {
	input, doc := sourceFixture(t)
	attachSource(t, input, doc)
	v, err := NewRevisionValidationV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	original := cloneRevisionDocumentV1(doc)
	doc.HtmlSourceJson[0] = 'x'
	doc.VariablesJson[0] = 'x'
	if v.MatchesDocumentV1(doc) || !v.MatchesDocumentV1(original) {
		t.Fatal("mutable caller document replaced private pins")
	}
	gotInput, gotResult, changed, err := v.MaterializeRevisionV1(map[string]string{"customer_name": "Revised AB"}, map[string]string{"scope": "Fresh negotiated text"})
	if err != nil || !changed {
		t.Fatal("valid declared revision refused", err)
	}
	wantInput, err := InputForCurrent(original)
	if err != nil {
		t.Fatal(err)
	}
	wantInput.Values["customer_name"] = "Revised AB"
	wantInput.Sections["scope"] = "Fresh negotiated text"
	master, err := htmlmaster.Decode(wantInput.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	wantResult, err := compiled.Materialize(htmlmaster.Input{Values: wantInput.Values, Sections: wantInput.Sections})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotInput, wantInput) || !reflect.DeepEqual(gotResult, wantResult) {
		t.Fatal("prepared revision differs from original helper outputs")
	}
	gotInput.MasterJSON[0] = 'x'
	gotInput.DefaultVarsJSON[0] = 'x'
	gotInput.Values["customer_name"] = "mutated"
	gotInput.Sections["scope"] = "mutated"
	gotResult.ChangedSections[0] = "mutated"
	after, err := v.InputForCurrentV1()
	if err != nil || after.Values["customer_name"] != input.Values["customer_name"] || after.MasterJSON[0] == 'x' {
		t.Fatal("defensive output alias", err)
	}
	raw, err := v.EffectiveJSONV1()
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'x'
	again, err := v.EffectiveJSONV1()
	if err != nil || again[0] == 'x' {
		t.Fatal("effective JSON alias", err)
	}
	canonical, err := v.CanonicalV1()
	if err != nil {
		t.Fatal(err)
	}
	canonical.MasterJSON[0] = 'x'
	canonical2, err := v.CanonicalV1()
	if err != nil || canonical2.MasterJSON[0] == 'x' {
		t.Fatal("canonical JSON alias", err)
	}
	_, _, changed, err = v.MaterializeRevisionV1(nil, nil)
	if err != nil || changed {
		t.Fatal("unchanged revision gained acceptance", err)
	}
}

func TestRevisionValidationTransportDifferentMasterIsRevalidatedV1(t *testing.T) {
	_, doc := currentFixture(t)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, doc.HtmlCurrentSourceJson, "", "  "); err != nil {
		t.Fatal(err)
	}
	doc.HtmlCurrentSourceJson = pretty.Bytes()
	b, err := NewRevisionValidationBuilderV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[RevisionValidationStageV1]int{}
	for {
		stage, err := b.StageV1()
		if err != nil {
			t.Fatal(err)
		}
		if stage == RevisionValidationDoneV1 {
			break
		}
		counts[stage]++
		switch stage {
		case RevisionValidationRawCompileV1:
			err = b.PrepareRawV1()
		case RevisionValidationCanonicalCompileV1:
			err = b.PrepareCanonicalV1()
		case RevisionValidationRecordV1:
			err = b.ValidateRecordV1()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if counts[RevisionValidationRawCompileV1] != 2 || counts[RevisionValidationCanonicalCompileV1] != 2 || counts[RevisionValidationRecordV1] != 2 {
		t.Fatalf("different raw design spelling bypassed revalidation: %v", counts)
	}
	v, err := b.FinishV1()
	if err != nil {
		t.Fatal(err)
	}
	got, ge := v.CommitmentV1()
	want, we := Commitment(doc)
	revisionOracleErrorV1(t, ge, we)
	if got != want {
		t.Fatal("transport changed typed commitment")
	}
	input, err := v.InputForCurrentV1()
	if err != nil {
		t.Fatal(err)
	}
	original, err := InputForCurrent(doc)
	if err != nil || !reflect.DeepEqual(input, original) {
		t.Fatal("original source spelling was normalized away", err)
	}
}
