// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestHTMLRevisionPreparedPinnedTypedLayoutsV1(t *testing.T) {
	for _, entry := range []struct {
		name         string
		actual, want uintptr
	}{
		{"Master", unsafe.Sizeof(htmlmaster.Master{}), 128}, {"Compiled", unsafe.Sizeof(htmlmaster.Compiled{}), 208},
		{"Value", unsafe.Sizeof(htmlmaster.Value{}), 32}, {"Section", unsafe.Sizeof(htmlmaster.Section{}), 40}, {"Asset", unsafe.Sizeof(htmlmaster.Asset{}), 64},
		{"ContractProfile", unsafe.Sizeof(htmlmaster.ContractProfile{}), 88}, {"ContractParty", unsafe.Sizeof(htmlmaster.ContractParty{}), 96}, {"ContractTerm", unsafe.Sizeof(htmlmaster.ContractTerm{}), 48},
		{"SigningPagePolicy", unsafe.Sizeof(htmlmaster.SigningPagePolicy{}), 248}, {"TemplateCommitment", unsafe.Sizeof(htmlmaster.TemplateCommitment{}), 64},
		{"Input", unsafe.Sizeof(htmlsource.Input{}), 176}, {"PartyBinding", unsafe.Sizeof(htmlsource.PartyBinding{}), 32}, {"SigningArtifact", unsafe.Sizeof(htmlsource.SigningArtifact{}), 384}, {"SigningRectangle", unsafe.Sizeof(htmlsource.SigningRectangle{}), 56}, {"RecordPins", unsafe.Sizeof(htmlsource.RevisionValidationRecordPinsV1{}), 120},
	} {
		if entry.actual != entry.want {
			t.Errorf("%s layout changed: got%d want%d", entry.name, entry.actual, entry.want)
		}
	}
}

func TestHTMLRevisionPreparedTinyAndOverflowV1(t *testing.T) {
	n := int64(0)
	if !htmlRevisionRetentionAllocV1(&n, 1) || n < 16 {
		t.Fatalf("tiny allocator class not priced: %d", n)
	}
	n = math.MaxInt64
	if htmlRevisionRetentionAllocV1(&n, 1) {
		t.Fatal("overflow accepted")
	}
	n = 0
	if htmlRevisionRetentionAllocV1(&n, -1) {
		t.Fatal("negative allocation accepted")
	}
	for _, n := range []int64{-1, math.MaxInt64, math.MaxInt64 - 1} {
		if _, err := htmlRevisionRetentionFinishV1(n); err == nil {
			t.Fatalf("invalid final size accepted: %d", n)
		}
	}
	for _, n := range []int64{0, 1, 8191, 8192, 8193} {
		size, err := htmlRevisionRetentionFinishV1(n)
		if err != nil || size < n || size%8192 != 0 {
			t.Fatalf("unrounded size %d ->%d,%v", n, size, err)
		}
	}
	if _, err := htmlRevisionPreparedTemplateRetentionV1(htmlRevisionCanonicalOutputComponentsV1{masterJSONBytes: math.MaxInt64}); err == nil {
		t.Fatal("template output overflow accepted")
	}
}

func TestHTMLRevisionPreparedDocumentAll40VariableFieldsV1(t *testing.T) {
	typ := reflect.TypeOf(generated.Document{})
	if typ.NumField() != 82 {
		t.Fatalf("Document pins changed: %d", typ.NumField())
	}
	baseline, err := htmlRevisionPreparedDocumentCloneV1(&generated.Document{})
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("v", 32768)
	count := 0
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		kind := field.Type.Kind()
		variable := kind == reflect.String || kind == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8 || field.Type == reflect.TypeOf(pgtype.Text{})
		if !variable {
			continue
		}
		count++
		t.Run(field.Name, func(t *testing.T) {
			doc := &generated.Document{}
			value := reflect.ValueOf(doc).Elem().Field(i)
			switch {
			case field.Type == reflect.TypeOf(pgtype.Text{}):
				value.Set(reflect.ValueOf(pgtype.Text{String: payload, Valid: false})) // Even invalid Text backing is cloned.
			case kind == reflect.String:
				value.SetString(payload)
			default:
				value.SetBytes([]byte(payload))
			}
			size, err := htmlRevisionPreparedDocumentCloneV1(doc)
			if err != nil {
				t.Fatal(err)
			}
			if size < baseline+int64(len(payload)) {
				t.Fatalf("actual %s clone mass omitted: %d baseline%d", field.Name, size, baseline)
			}
		})
	}
	if count != 40 {
		t.Fatalf("variable clone inventory changed: %d", count)
	}
	if _, err := htmlRevisionPreparedDocumentCloneV1(nil); err == nil {
		t.Fatal("nil Document accepted")
	}
}

func TestHTMLRevisionPreparedMasterProjectionSeparatesBackingV1(t *testing.T) {
	empty := htmlmaster.Master{HTML: "<p>Ready</p>"}
	copySize, err := htmlRevisionPreparedMasterProjectionV1(empty)
	if err != nil {
		t.Fatal(err)
	}
	large := empty
	large.HTML = strings.Repeat("x", 100000)
	large.CSS = strings.Repeat("y", 50000)
	projected, err := htmlRevisionPreparedMasterProjectionV1(large)
	if err != nil || projected != copySize {
		t.Fatalf("immutable shared strings repriced as projection: %d,%v", projected, err)
	}
	retained, err := htmlRevisionPreparedMasterRetentionV1(large)
	if err != nil || retained < projected+int64(len(large.HTML)+len(large.CSS)) {
		t.Fatalf("actual parser-owned string backing omitted: %d,%v", retained, err)
	}
	maximum := large
	maximum.Values = make([]htmlmaster.Value, 64)
	maximum.Sections = make([]htmlmaster.Section, 64)
	maximum.Assets = make([]htmlmaster.Asset, 16)
	maximum.ContractProfile = &htmlmaster.ContractProfile{Parties: make([]htmlmaster.ContractParty, 2), Terms: make([]htmlmaster.ContractTerm, 16)}
	maximum.SigningPage = &htmlmaster.SigningPagePolicy{}
	actual, err := htmlRevisionPreparedMasterProjectionV1(maximum)
	if err != nil {
		t.Fatal(err)
	}
	beforeGetter, err := htmlRevisionPreparedMasterProjectionCeilingV1()
	if err != nil || beforeGetter < actual {
		t.Fatalf("pre-getter typed topology underpriced: %d<%d,%v", beforeGetter, actual, err)
	}
	maximum.Values = append(maximum.Values, htmlmaster.Value{})
	if _, err = htmlRevisionPreparedMasterProjectionV1(maximum); err == nil {
		t.Fatal("beyond existing definition maximum accepted")
	}
}

func TestHTMLRevisionPreparedActualCompileOutputOracleV1(t *testing.T) {
	ctx := context.Background()
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pngBytes.Bytes())
	encoded := base64.StdEncoding.EncodeToString(pngBytes.Bytes())
	wrapped := encoded[:40] + "\r\n" + encoded[40:]
	master := htmlmaster.Master{SchemaVersion: 1, HTML: "<main><img src=\"hash-asset:logo\"/><p>Ready</p></main>", CSS: "main { color: #112233; }", Assets: []htmlmaster.Asset{{Name: "logo", MediaType: "image/png", SHA256: hex.EncodeToString(sum[:]), DataBase64: wrapped}}}
	stats, err := htmlInputCanonicalInspectV1(ctx, master)
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := htmlRevisionCanonicalOutputComponentsForV1(master, stats, defaults)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	var normalized htmlmaster.Master
	if err = json.Unmarshal(compiled.CanonicalJSON(), &normalized); err != nil {
		t.Fatal(err)
	}
	if normalized.Assets[0].DataBase64 != encoded || len(normalized.Assets[0].DataBase64) >= len(wrapped) {
		t.Fatal("fixture did not exercise accepted non-growing CR/LF base64 canonicalization")
	}
	retained, err := htmlRevisionPreparedCompiledRetentionV1(master, stats, out)
	if err != nil {
		t.Fatal(err)
	}
	// Independent actual outputs and fixed object storage form a necessary lower
	// bound; full scratch remains separately priced by the existing canonical unit.
	actualLower := int64(len(compiled.CanonicalJSON())+len(compiled.Digest())+len(normalized.HTML)+len(normalized.CSS)+len(encoded)+len("data:image/png;base64,")+len(encoded)) + int64(unsafe.Sizeof(*compiled))
	if retained < actualLower {
		t.Fatalf("retained actual output underpriced: %d<%d", retained, actualLower)
	}
	templateBytes, err := htmlRevisionPreparedTemplateRetentionV1(out)
	if err != nil || templateBytes < int64(len(canonical.MasterJSON)+len(canonical.DefaultsJSON)+len(canonical.SHA256)) {
		t.Fatalf("actual TemplateCommitment omitted: %d,%v", templateBytes, err)
	}
	altered := stats
	altered.pixels = math.MaxInt64
	noPixels, err := htmlRevisionPreparedCompiledRetentionV1(master, altered, out)
	if err != nil || noPixels != retained {
		t.Fatalf("retained component includes ephemeral image decoder arena: %d/%d,%v", noPixels, retained, err)
	}
}

func TestHTMLRevisionPreparedProjectionBeforeActualGetterV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw := []byte("{\"master\":{\"schema_version\":1,\"html\":\"<p>Ready</p>\"},\"default_values\":{},\"values\":{\"name\":\"Ada\"},\"sections\":{}}")
	parts, err := htmlRevisionSourceDecodeComponentsForV1(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	beforeGetter, err := htmlRevisionPreparedInputProjectionFromSourceV1(raw, parts)
	if err != nil {
		t.Fatal(err)
	}
	actual := htmlsource.Input{MasterJSON: bytes.Clone(raw[parts.masterStart:parts.masterEnd]), DefaultVarsJSON: bytes.Clone(raw[parts.defaultsStart:parts.defaultsEnd]), Values: map[string]string{"name": "Ada"}, Sections: map[string]string{}, PartyBindings: make([]htmlsource.PartyBinding, 2), SigningArtifact: &htmlsource.SigningArtifact{Fields: make([]htmlsource.SigningRectangle, 2)}}
	afterGetter, err := htmlRevisionPreparedInputProjectionV1(actual)
	if err != nil || beforeGetter < afterGetter {
		t.Fatalf("real projection exceeds pre-getter bound: %d<%d,%v", beforeGetter, afterGetter, err)
	}
	invalid := parts
	invalid.masterEnd = len(raw) + 1
	if _, err = htmlRevisionPreparedInputProjectionFromSourceV1(raw, invalid); err == nil {
		t.Fatal("foreign/out-of-range source span accepted")
	}
	actual.Values = make(map[string]string)
	for i := 0; i < 65; i++ {
		actual.Values[string(rune('a'+i))] = "v"
	}
	if _, err = htmlRevisionPreparedInputProjectionV1(actual); err == nil {
		t.Fatal("beyond existing input cardinality accepted")
	}
	p := htmlsource.RevisionValidationRecordPinsV1{PDFSHA256: make([]byte, 32), VariablesJSON: bytes.Repeat([]byte("v"), 32768)}
	pins, err := htmlRevisionPreparedRecordPinsProjectionV1(p)
	if err != nil || pins < int64(len(p.PDFSHA256)+len(p.VariablesJSON))+int64(unsafe.Sizeof(p)) {
		t.Fatalf("actual record pin clone omitted: %d,%v", pins, err)
	}
}
