// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func htmlRevisionRecordFixtureTestV1(t *testing.T, schema int) (htmlsource.Input, *generated.Document) {
	t.Helper()
	if schema == 2 {
		input, doc, _ := testfixture.HTMLContract(t)
		return input, doc
	}
	if schema == 3 {
		input, doc, _ := testfixture.BrandedHTMLContract(t)
		return input, doc
	}
	master := htmlmaster.Master{SchemaVersion: 1, HTML: "<p>Approved immutable text</p>"}
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	input := htmlsource.Input{TemplateID: uuid.New(), TemplateVersion: 1, TemplateContentSHA256: canonical.SHA256, MasterJSON: canonical.MasterJSON, DefaultVarsJSON: canonical.DefaultsJSON, Values: map[string]string{}, Sections: map[string]string{}, TemplateApprovedBy: uuid.New(), TemplateApprovedAt: time.Date(2026, 10, 15, 0, 0, 0, 1, time.UTC)}
	sum := sha256.Sum256([]byte("synthetic PDF tuple only"))
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), TemplateID: pgtype.UUID{Bytes: input.TemplateID, Valid: true}, SourceKind: "pdf", PdfStorageKey: pgtype.Text{String: "org/synthetic/documents/source.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "synthetic-version", Valid: true}, PdfSha256: sum[:], VariablesJson: []byte("{}")}
	return input, doc
}
func TestHTMLRevisionRecordEnvelopeBoundsActualOriginalNewV1(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		t.Run(string(rune('0'+schema)), func(t *testing.T) {
			input, doc := htmlRevisionRecordFixtureTestV1(t, schema)
			ctx := applicationTestContextV1(t)
			canonical, err := htmlmaster.CanonicalTemplate(input.MasterJSON, input.DefaultVarsJSON)
			if err != nil {
				t.Fatal(err)
			}
			pins := htmlsource.RevisionValidationRecordPinsV1{DocumentID: doc.ID, OrgID: doc.OrgID, PDFKey: doc.PdfStorageKey.String, PDFVersionID: doc.PdfStorageVersionID.String, PDFSHA256: doc.PdfSha256, VariablesJSON: doc.VariablesJson}
			parts, err := htmlRevisionRecordComponentsForV1(ctx, input, canonical, pins)
			if err != nil {
				t.Fatal(err)
			}
			// This is the actual unchanged source.New encoder, not a mirrored source
			// struct or helper formula. Synthetic fixtures assert no PDF/SQL authority.
			actual, err := htmlsource.New(input, doc)
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(actual)) > parts.sourceJSONBytes {
				t.Fatal("actual original New output exceeds typed envelope", len(actual), parts.sourceJSONBytes)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(actual, &fields); err != nil {
				t.Fatal(err)
			}
			want := 18
			if schema >= 2 {
				want++
			}
			if schema == 3 {
				want++
			}
			if len(fields) != want {
				t.Fatal("actual source schema field inventory changed", len(fields), want)
			}
			for name, bound := range map[string]int64{"values": parts.valuesJSONBytes, "sections": parts.sectionsJSONBytes, "party_bindings": parts.bindingsJSONBytes, "signing_artifact": parts.artifactJSONBytes} {
				if raw := fields[name]; raw != nil {
					wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, raw)
					if err != nil || int64(len(raw)) > bound || wire > bound {
						t.Fatal("actual typed suboutput exceeds logical envelope", name, err, int64(len(raw)), wire, bound)
					}
				}
			}
			// sourceCommitment marshals the same typed record with commitment empty.
			// Re-encoding the actual root values has the same JSON value lengths while
			// deliberately using the independent generic map encoder/order as oracle.
			fields["commitment"] = json.RawMessage("\"\"")
			hashInput, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if int64(len(hashInput)) > parts.sourceJSONBytes || parts.sourceNewEncoderBytes <= parts.sourceCommitmentEncoderBytes {
				t.Fatal("hash/final encoders lost separately retained masses")
			}
			origin := pins
			origin.Origin = true
			origin.VariablesJSON = nil
			originParts, err := htmlRevisionRecordComponentsForV1(ctx, input, canonical, origin)
			if err != nil || originParts.variablesParserBytes != 0 || originParts.originVariablesParserBytes == 0 || originParts.originValuesEncoderBytes == 0 {
				t.Fatal("origin Values Marshal/strict parser was replaced by current Variables bytes", err)
			}
		})
	}
}
func TestHTMLRevisionRawMessageEnvelopeUsesActualEncoderEscapesV1(t *testing.T) {
	for _, raw := range [][]byte{[]byte("{ \"text\": \"<&>é\", \"number\":1e999999 }"), []byte("{\"text\":\"\u2028\u2029\"}"), []byte("{\"nested\":{\"s\":\"\\\\u003c\"},\"array\":[1,-2,3]}")} {
		bound, err := htmlRevisionRawMessageOutputV1(raw)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := json.Marshal(struct {
			Value json.RawMessage `json:"value"`
		}{Value: raw})
		if err != nil {
			t.Fatal(err)
		}
		var root map[string]json.RawMessage
		if err = json.Unmarshal(actual, &root); err != nil {
			t.Fatal(err)
		}
		if int64(len(root["value"])) > bound {
			t.Fatal("actual RawMessage compact/HTML/Unicode expansion exceeded bound")
		}
	}
}
func TestHTMLRevisionTypedMapsAndArtifactCoverExpansionBeforeRefusalV1(t *testing.T) {
	values := map[string]string{"<&>\x01\u2028": "é<&>\x02\u2029", "escaped\\key": "\"line\nwith\ttext"}
	shape, err := htmlRevisionStringMapOutputV1(values)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	ctx := applicationTestContextV1(t)
	wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, raw)
	if err != nil || int64(len(raw)) > shape.raw || wire > shape.raw {
		t.Fatal("actual escaping/map output exceeded future parser input", err)
	}
	actualShape, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, raw)
	if err != nil {
		t.Fatal(err)
	}
	future, err := htmlAuthoringInputParserArenaV1(shape, 2)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := htmlAuthoringInputParserArenaV1(actualShape, 2)
	if err != nil || future < actual {
		t.Fatal("future two-pass actual typed-map parser underpriced", err, future, actual)
	}
	_, doc, _ := testfixture.BrandedHTMLContract(t)
	_, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || artifact == nil {
		t.Fatal(err)
	}
	// Before original policy rejection, a typed record may carry extreme integer
	// spellings. The fixed output envelope still covers these actual widths.
	artifact.Version = math.MaxInt
	artifact.Policy = "<&>\x01"
	artifact.PlanSHA256 = "\u2028"
	artifact.Composition.MergedBytes = math.MinInt64
	artifact.Composition.SigningPage.UserUnitMilli = math.MaxInt64
	artifact.Composition.SigningPage.Rotation = math.MinInt
	for i := range artifact.Composition.SigningPage.BoxesMilliPoints {
		for j := range artifact.Composition.SigningPage.BoxesMilliPoints[i] {
			artifact.Composition.SigningPage.BoxesMilliPoints[i][j] = math.MinInt64
		}
	}
	for i := range artifact.Fields {
		artifact.Fields[i].Page = math.MinInt32
		artifact.Fields[i].X = math.MinInt64
		artifact.Fields[i].Y = math.MaxInt64
		artifact.Fields[i].Slot = "<&>\x01"
	}
	bound, err := htmlRevisionArtifactTypedOutputV1(artifact)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(artifact)
	if err != nil || int64(len(encoded)) > bound {
		t.Fatal("actual extreme typed artifact exceeded envelope", err, len(encoded), bound)
	}
	// Explicit object/key/integer inventory guards the selected actual schema.
	var root map[string]json.RawMessage
	if err = json.Unmarshal(encoded, &root); err != nil || len(root) != 5 {
		t.Fatal("artifact root schema drift", err)
	}
	var composition map[string]json.RawMessage
	if err = json.Unmarshal(root["composition"], &composition); err != nil || len(composition) != 12 {
		t.Fatal("artifact composition schema drift", err)
	}
	var geometry map[string]json.RawMessage
	if err = json.Unmarshal(composition["signing_page"], &geometry); err != nil || len(geometry) != 3 {
		t.Fatal("artifact geometry schema drift", err)
	}
	var boxes [][]int64
	if err = json.Unmarshal(geometry["boxes_milli_points"], &boxes); err != nil || len(boxes) != 5 {
		t.Fatal("artifact box schema drift", err)
	}
	for _, box := range boxes {
		if len(box) != 4 {
			t.Fatal("artifact coordinate schema drift")
		}
	}
	var rectangles []map[string]json.RawMessage
	if err = json.Unmarshal(root["fields"], &rectangles); err != nil || len(rectangles) != 2 {
		t.Fatal("artifact rectangle count drift", err)
	}
	for _, rectangle := range rectangles {
		if len(rectangle) != 6 {
			t.Fatal("artifact rectangle field schema drift")
		}
	}
}
func TestHTMLRevisionRecordComponentsRejectUnavailableAndOverflowV1(t *testing.T) {
	if _, err := htmlRevisionTypedEncoderV1(math.MaxInt64); err == nil {
		t.Fatal("encoder arithmetic wrapped capacity")
	}
	total := int64(math.MaxInt64)
	if htmlRevisionRecordAddV1(&total, 1, 1) {
		t.Fatal("record arithmetic wrapped capacity")
	}
	input, doc := htmlRevisionRecordFixtureTestV1(t, 1)
	canonical, err := htmlmaster.CanonicalTemplate(input.MasterJSON, input.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	pins := htmlsource.RevisionValidationRecordPinsV1{PDFKey: doc.PdfStorageKey.String, PDFVersionID: doc.PdfStorageVersionID.String, VariablesJSON: doc.VariablesJson}
	if _, err := htmlRevisionRecordComponentsForV1(context.Background(), input, canonical, pins); err == nil {
		t.Fatal("unbounded context reached typed expansion")
	}
	ctx, cancel := context.WithCancel(applicationTestContextV1(t))
	cancel()
	if _, err := htmlRevisionRecordComponentsForV1(ctx, input, canonical, pins); err == nil {
		t.Fatal("canceled context reached typed expansion")
	}
	ctx = applicationTestContextV1(t)
	pins.VariablesJSON = bytes.Repeat([]byte("x"), 1024)
	if _, err := htmlRevisionRecordComponentsForV1(ctx, input, canonical, pins); err == nil {
		t.Fatal("malformed actual VariablesJSON gained parser component")
	}
	input.Values = map[string]string{}
	for i := 0; i <= htmlmaster.MaxDefinitions; i++ {
		input.Values[string(rune(i+1))] = ""
	}
	if _, err := htmlRevisionRecordComponentsForV1(ctx, input, canonical, pins); err == nil {
		t.Fatal("already-invalid source maps exceed actual fixed definition schema")
	}
}
