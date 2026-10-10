// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"time"

	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const pdfIntakePolicy = "hash-pdf-intake-v1"

// PDFProperties records observed facilities, not guessed removal capabilities.
// False booleans are deliberately serialized in the isolated worker protocol.
type PDFProperties struct {
	InfoDictionary bool `json:"info_dictionary"`
	XMPMetadata    bool `json:"xmp_metadata"`
	ObjectStreams  bool `json:"object_streams"`
	Linearization  bool `json:"linearization"`
	EmbeddedFiles  bool `json:"embedded_files"`
	AcroForm       bool `json:"acroform"`
	Annotations    bool `json:"annotations"`
}

// PDFProof describes this intake rewrite only. It makes no claim about later
// stamping, certificates, malware detection, or source information in visible
// page content. It contains no source metadata values.
type PDFProof struct {
	SchemaVersion        int           `json:"schema_version"`
	Policy               string        `json:"policy"`
	SourceSHA256         string        `json:"source_sha256"`
	OutputSHA256         string        `json:"output_sha256"`
	PagesBefore          int           `json:"pages_before"`
	PagesAfter           int           `json:"pages_after"`
	GeometrySHA256Before string        `json:"geometry_sha256_before"`
	GeometrySHA256After  string        `json:"geometry_sha256_after"`
	Before               PDFProperties `json:"before"`
	After                PDFProperties `json:"after"`
	Removed              []string      `json:"removed"`
	Absent               []string      `json:"absent"`
	Generated            []string      `json:"generated"`
}

var errPDFProof = errors.New("sanitize: invalid PDF intake proof")

func pdfSHA(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func validPDFSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func pdfCategories(p PDFProperties) []struct {
	name    string
	present bool
} {
	return []struct {
		name    string
		present bool
	}{
		{"source_info_dictionary", p.InfoDictionary}, {"xmp_metadata", p.XMPMetadata},
		{"object_streams", p.ObjectStreams}, {"linearization", p.Linearization},
		{"embedded_files", p.EmbeddedFiles}, {"acroform", p.AcroForm}, {"annotations", p.Annotations},
	}
}

func newPDFProof(source, output []byte, pages int, before, after PDFProperties, beforeGeometry, afterGeometry string) *PDFProof {
	p := &PDFProof{SchemaVersion: 1, Policy: pdfIntakePolicy, SourceSHA256: pdfSHA(source), OutputSHA256: pdfSHA(output), PagesBefore: pages, PagesAfter: pages, GeometrySHA256Before: beforeGeometry, GeometrySHA256After: afterGeometry, Before: before, After: after, Removed: []string{}, Absent: []string{}, Generated: []string{}}
	for _, category := range pdfCategories(before) {
		if category.present {
			p.Removed = append(p.Removed, category.name)
		} else {
			p.Absent = append(p.Absent, category.name)
		}
	}
	if after.InfoDictionary {
		p.Generated = append(p.Generated, "info_dictionary")
	}
	return p
}

// ValidatePDFReport checks the bounded, exact policy shape without parsing a
// PDF in the parent application. Legacy reports cannot satisfy this contract.
func ValidatePDFReport(report Report) error {
	p := report.PDF
	if p == nil || report.Provenance != "observed" || report.ContentType != "application/pdf" || report.Method != "pdfcpu" || report.UnsupportedT || len(report.Asset) > 128 || report.BytesBefore < 1 || report.BytesBefore > MaxPDFBytes || report.BytesAfter < 1 || report.BytesAfter > MaxPDFBytes {
		return errPDFProof
	}
	if p.SchemaVersion != 1 || p.Policy != pdfIntakePolicy || !validPDFSHA(p.SourceSHA256) || !validPDFSHA(p.OutputSHA256) || !validPDFSHA(p.GeometrySHA256Before) || p.GeometrySHA256Before != p.GeometrySHA256After || p.PagesBefore < 1 || p.PagesBefore > MaxPDFPages || p.PagesBefore != p.PagesAfter {
		return errPDFProof
	}
	if p.After.XMPMetadata || p.After.ObjectStreams || p.After.Linearization || p.After.EmbeddedFiles || p.After.AcroForm || p.After.Annotations {
		return errPDFProof
	}
	want := newPDFProof(nil, nil, p.PagesBefore, p.Before, p.After, p.GeometrySHA256Before, p.GeometrySHA256After)
	if !reflect.DeepEqual(p.Removed, want.Removed) || !reflect.DeepEqual(p.Absent, want.Absent) || !reflect.DeepEqual(p.Generated, want.Generated) || !reflect.DeepEqual(report.Stripped, want.Removed) {
		return errPDFProof
	}
	return nil
}

// ValidatePDFResult binds the worker's report to the exact submitted and
// returned bytes. Callers supply digests; this function never parses a PDF.
func ValidatePDFResult(report Report, sourceSHA256, outputSHA256 string, bytesBefore, bytesAfter int64) error {
	if err := ValidatePDFReport(report); err != nil {
		return err
	}
	if report.PDF.SourceSHA256 != sourceSHA256 || report.PDF.OutputSHA256 != outputSHA256 || report.BytesBefore != bytesBefore || report.BytesAfter != bytesAfter {
		return errPDFProof
	}
	return nil
}

// DecodePDFReport validates an observed report at a JSON trust boundary,
// including explicit false observations. Missing, null, duplicate, unknown or
// future-policy fields cannot silently become a successful typed proof.
func DecodePDFReport(raw []byte) (Report, error) {
	var report Report
	if len(raw) == 0 || len(raw) > pdfWorkerHeaderLimit || strictPDFWorkerJSON(raw) != nil {
		return report, errPDFProof
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF {
		return Report{}, errPDFProof
	}
	var fields, proof map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return Report{}, errPDFProof
	}
	for key, value := range fields {
		switch key {
		case "asset", "content_type", "method", "stripped", "bytes_before", "bytes_after", "provenance", "pdf", "unsupported_type":
		default:
			return Report{}, errPDFProof
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Report{}, errPDFProof
		}
	}
	for _, key := range []string{"asset", "content_type", "method", "stripped", "bytes_before", "bytes_after", "provenance", "pdf"} {
		if value, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Report{}, errPDFProof
		}
	}
	if json.Unmarshal(fields["pdf"], &proof) != nil {
		return Report{}, errPDFProof
	}
	if len(proof) != 13 {
		return Report{}, errPDFProof
	}
	for _, key := range []string{"schema_version", "policy", "source_sha256", "output_sha256", "pages_before", "pages_after", "geometry_sha256_before", "geometry_sha256_after", "before", "after", "removed", "absent", "generated"} {
		if value, ok := proof[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Report{}, errPDFProof
		}
	}
	for _, key := range []string{"before", "after"} {
		var properties map[string]json.RawMessage
		if json.Unmarshal(proof[key], &properties) != nil || len(properties) != 7 {
			return Report{}, errPDFProof
		}
		for _, category := range []string{"info_dictionary", "xmp_metadata", "object_streams", "linearization", "embedded_files", "acroform", "annotations"} {
			value := bytes.TrimSpace(properties[category])
			if !bytes.Equal(value, []byte("true")) && !bytes.Equal(value, []byte("false")) {
				return Report{}, errPDFProof
			}
		}
	}
	if err := ValidatePDFReport(report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func pdfConfiguration() *model.Configuration {
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	conf.WriteObjectStream, conf.WriteXRefStream = false, false
	conf.Eol = types.EolLF
	return conf
}

// walkPDF visits direct objects only; indirect objects are each inspected once
// through the xref table. Depth and work limits also bound malformed nesting.
func walkPDF(object types.Object, key string, depth int, budget *int, visit func(types.Object, string) error) error {
	*budget--
	if depth > 128 || *budget < 0 {
		return errors.New("sanitize: PDF object graph exceeds inspection bounds")
	}
	if err := visit(object, key); err != nil {
		return err
	}
	if d := pdfObjectDict(object); d != nil {
		for k, value := range d {
			if err := walkPDF(value, k, depth+1, budget, visit); err != nil {
				return err
			}
		}
	} else if a, ok := object.(types.Array); ok {
		for _, value := range a {
			if err := walkPDF(value, key, depth+1, budget, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func pdfObjectDict(object types.Object) types.Dict {
	switch value := object.(type) {
	case types.Dict:
		return value
	case types.StreamDict:
		return value.Dict
	case *types.StreamDict:
		if value != nil {
			return value.Dict
		}
	case types.ObjectStreamDict:
		return value.Dict
	case *types.ObjectStreamDict:
		if value != nil {
			return value.Dict
		}
	case types.XRefStreamDict:
		return value.Dict
	case *types.XRefStreamDict:
		if value != nil {
			return value.Dict
		}
	}
	return nil
}

func eachPDFObject(ctx *model.Context, visit func(types.Object, string) error) error {
	if len(ctx.Table) > 250000 {
		return errors.New("sanitize: PDF object graph exceeds inspection bounds")
	}
	budget := 1000000
	for _, entry := range ctx.Table {
		if entry == nil || entry.Free || entry.Object == nil {
			continue
		}
		if err := walkPDF(entry.Object, "", 0, &budget, visit); err != nil {
			return err
		}
	}
	return nil
}

func observedPDFProperties(ctx *model.Context) (PDFProperties, error) {
	p := PDFProperties{InfoDictionary: ctx.Info != nil}
	err := eachPDFObject(ctx, func(object types.Object, key string) error {
		d := pdfObjectDict(object)
		if d == nil {
			return nil
		}
		if _, ok := d["Metadata"]; ok {
			p.XMPMetadata = true
		}
		if _, ok := d["Linearized"]; ok {
			p.Linearization = true
		}
		if _, ok := d["EmbeddedFiles"]; ok {
			p.EmbeddedFiles = true
		}
		if _, ok := d["AcroForm"]; ok {
			p.AcroForm = true
		}
		if _, ok := d["Annots"]; ok {
			p.Annotations = true
		}
		if typ := d.NameEntry("Type"); typ != nil {
			switch *typ {
			case "Metadata":
				p.XMPMetadata = true
			case "ObjStm":
				p.ObjectStreams = true
			case "EmbeddedFile":
				p.EmbeddedFiles = true
			case "Annot":
				p.Annotations = true
			}
		}
		return nil
	})
	return p, err
}

func observePDF(raw []byte) (*model.Context, PDFProperties, string, error) {
	ctx, err := pdfapi.ReadContext(bytes.NewReader(raw), pdfConfiguration())
	if err != nil {
		return nil, PDFProperties{}, "", errors.New("sanitize: invalid PDF")
	}
	properties, err := observedPDFProperties(ctx)
	if err != nil {
		return nil, PDFProperties{}, "", err
	}
	if _, err := metadataTargets(ctx); err != nil {
		return nil, PDFProperties{}, "", err
	}
	if err := pdfapi.ValidateContext(ctx); err != nil {
		return nil, PDFProperties{}, "", errors.New("sanitize: invalid PDF")
	}
	if ctx.PageCount < 1 || ctx.PageCount > MaxPDFPages {
		return nil, PDFProperties{}, "", ErrTooManyPages
	}
	geometry, err := pdfGeometry(ctx)
	if err != nil {
		return nil, PDFProperties{}, "", err
	}
	return ctx, properties, geometry, nil
}

func pdfGeometry(ctx *model.Context) (string, error) {
	boundaries, err := ctx.PageBoundaries(nil)
	if err != nil || len(boundaries) != ctx.PageCount {
		return "", errors.New("sanitize: invalid PDF page geometry")
	}
	type page struct {
		Boxes    [5][4]float64 `json:"boxes"`
		Rotation int           `json:"rotation"`
		UserUnit float64       `json:"user_unit"`
	}
	pages := make([]page, len(boundaries))
	for i, b := range boundaries {
		for j, rect := range []*types.Rectangle{b.MediaBox(), b.CropBox(), b.TrimBox(), b.BleedBox(), b.ArtBox()} {
			if rect == nil {
				return "", errors.New("sanitize: invalid PDF page geometry")
			}
			values := [4]float64{rect.LL.X, rect.LL.Y, rect.UR.X, rect.UR.Y}
			for _, value := range values {
				if math.IsNaN(value) || math.IsInf(value, 0) {
					return "", errors.New("sanitize: invalid PDF page geometry")
				}
			}
			pages[i].Boxes[j] = values
		}
		pages[i].Rotation, pages[i].UserUnit = b.Rot, 1
		dict, _, _, err := ctx.PageDict(i+1, false)
		if err != nil {
			return "", errors.New("sanitize: invalid PDF page geometry")
		}
		if value, ok := dict["UserUnit"]; ok {
			value, err = ctx.Dereference(value)
			if err != nil {
				return "", errors.New("sanitize: invalid PDF page geometry")
			}
			switch n := value.(type) {
			case types.Float:
				pages[i].UserUnit = float64(n)
			case types.Integer:
				pages[i].UserUnit = float64(n)
			default:
				return "", errors.New("sanitize: invalid PDF page geometry")
			}
			if pages[i].UserUnit <= 0 || math.IsNaN(pages[i].UserUnit) || math.IsInf(pages[i].UserUnit, 0) {
				return "", errors.New("sanitize: invalid PDF page geometry")
			}
		}
	}
	encoded, err := json.Marshal(pages)
	if err != nil {
		return "", errors.New("sanitize: invalid PDF page geometry")
	}
	return pdfSHA(encoded), nil
}

// removePDFMetadata severs metadata edges without deleting arbitrary graphs.
// A metadata object shared with visual or other non-metadata content is refused
// rather than changing that shared object behind the caller's back.
func metadataTargets(ctx *model.Context) (map[int]bool, error) {
	metadata := map[int]bool{}
	if ctx.Info != nil && ctx.Root != nil && ctx.Info.ObjectNumber == ctx.Root.ObjectNumber {
		return nil, errors.New("sanitize: shared source Info object")
	}
	if err := eachPDFObject(ctx, func(object types.Object, key string) error {
		if d := pdfObjectDict(object); d != nil {
			if value, ok := d["Metadata"]; ok && value != nil {
				ref, ok := value.(types.IndirectRef)
				if !ok {
					return errors.New("sanitize: invalid metadata reference")
				}
				entry := ctx.Table[int(ref.ObjectNumber)]
				if entry == nil || entry.Free {
					return errors.New("sanitize: invalid metadata reference")
				}
				switch entry.Object.(type) {
				case types.StreamDict, *types.StreamDict:
				default:
					return errors.New("sanitize: invalid metadata reference")
				}
				metadata[int(ref.ObjectNumber)] = true
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	for number, entry := range ctx.Table {
		if entry == nil || entry.Free {
			continue
		}
		if d := pdfObjectDict(entry.Object); d != nil {
			if typ := d.NameEntry("Type"); typ != nil && *typ == "Metadata" {
				switch entry.Object.(type) {
				case types.StreamDict, *types.StreamDict:
				default:
					return nil, errors.New("sanitize: invalid metadata stream")
				}
				metadata[number] = true
			}
		}
	}
	budget := 1000000
	for _, entry := range ctx.Table {
		if entry == nil || entry.Free || entry.Object == nil {
			continue
		}
		object := entry.Object
		// Parsed xref streams carry the trailer's legitimate direct Info edge.
		// Exclude that one edge only; nested/custom edges still undergo the alias
		// check, and an ordinary dictionary merely named Info is never exempt.
		var trailer types.Dict
		switch stream := object.(type) {
		case types.XRefStreamDict:
			trailer = stream.Dict
		case *types.XRefStreamDict:
			if stream != nil {
				trailer = stream.Dict
			}
		}
		if trailer != nil && ctx.Info != nil {
			if ref, ok := trailer["Info"].(types.IndirectRef); ok && ref == *ctx.Info {
				copy := types.Dict{}
				for key, value := range trailer {
					if key != "Info" {
						copy[key] = value
					}
				}
				object = copy
			}
		}
		if err := walkPDF(object, "", 0, &budget, func(object types.Object, key string) error {
			if ref, ok := object.(types.IndirectRef); ok {
				number := int(ref.ObjectNumber)
				if ctx.Info != nil && number == int(ctx.Info.ObjectNumber) {
					return errors.New("sanitize: shared source Info object")
				}
				if metadata[number] && key != "Metadata" {
					return errors.New("sanitize: shared metadata object")
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if ctx.AdditionalStreams != nil && ctx.Info != nil {
		for _, object := range *ctx.AdditionalStreams {
			if ref, ok := object.(types.IndirectRef); ok && ref.ObjectNumber == ctx.Info.ObjectNumber {
				return nil, errors.New("sanitize: shared source Info object")
			}
		}
	}
	return metadata, nil
}

func removePDFMetadata(ctx *model.Context) error {
	metadata, err := metadataTargets(ctx)
	if err != nil {
		return err
	}
	if ctx.Info != nil {
		dict, err := ctx.DereferenceDict(*ctx.Info)
		if err != nil || dict == nil {
			return errors.New("sanitize: invalid source Info dictionary")
		}
		for key := range dict {
			delete(dict, key)
		}
		ctx.Info = nil
	}
	xref := ctx.XRefTable
	xref.Title, xref.Subject, xref.Author, xref.Creator, xref.Producer, xref.CreationDate, xref.ModDate, xref.Keywords = "", "", "", "", "", "", "", ""
	ctx.KeywordList, ctx.Properties, ctx.CatalogXMPMeta = nil, nil, nil
	for number := range metadata {
		entry := ctx.Table[number]
		clearStream := func(stream *types.StreamDict) {
			stream.Raw, stream.Content, stream.FilterPipeline = nil, nil, nil
			delete(stream.Dict, "Filter")
			delete(stream.Dict, "DecodeParms")
			stream.Dict["Length"] = types.Integer(0)
			zero := int64(0)
			stream.StreamLength = &zero
			stream.StreamLengthObjNr = nil
		}
		switch stream := entry.Object.(type) {
		case types.StreamDict:
			clearStream(&stream)
			entry.Object = stream
		case *types.StreamDict:
			if stream != nil {
				clearStream(stream)
			}
		}
	}
	if ctx.AdditionalStreams != nil {
		retained := types.Array{}
		for _, object := range *ctx.AdditionalStreams {
			if ref, ok := object.(types.IndirectRef); ok && metadata[int(ref.ObjectNumber)] {
				continue
			}
			retained = append(retained, object)
		}
		ctx.AdditionalStreams = &retained
	}
	return eachPDFObject(ctx, func(object types.Object, key string) error {
		if d := pdfObjectDict(object); d != nil {
			delete(d, "Metadata")
			// These facilities must not survive an unsuccessful removal command.
			delete(d, "AcroForm")
			delete(d, "EmbeddedFiles")
			delete(d, "Annots")
		}
		return nil
	})
}

func verifyGeneratedInfo(ctx *model.Context) error {
	if ctx.Info == nil {
		if ctx.XRefTable.Version() < model.V20 {
			return errors.New("sanitize: missing generated PDF Info")
		}
		return nil
	}
	dict, err := ctx.DereferenceDict(*ctx.Info)
	if err != nil || len(dict) != 3 {
		return errors.New("sanitize: source Info survived rewrite")
	}
	values := map[string]string{}
	for _, key := range []string{"Producer", "CreationDate", "ModDate"} {
		value, ok := dict[key].(types.StringLiteral)
		if !ok {
			return errors.New("sanitize: unexpected generated PDF Info")
		}
		values[key] = string(value)
	}
	if values["Producer"] != "pdfcpu "+model.VersionStr || values["CreationDate"] != values["ModDate"] {
		return errors.New("sanitize: unexpected generated PDF Info")
	}
	date, valid := types.DateTime(values["CreationDate"], false)
	if !valid || date.Before(time.Now().Add(-time.Minute)) || date.After(time.Now().Add(time.Minute)) {
		return errors.New("sanitize: unexpected generated PDF Info dates")
	}
	return nil
}
