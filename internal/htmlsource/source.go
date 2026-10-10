// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package htmlsource preserves an approved HTML master and the exact inputs
// rendered into a document's immutable PDF. PDF rendering and human authority
// belong to callers; this package refuses drift before the signing lifecycle.
package htmlsource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
)

const SchemaVersion = 1
const ContractSchemaVersion = 2
const maxSourceBytes = 24 << 20

var (
	ErrInvalid        = errors.New("HTML document source is invalid or differs from its rendered PDF")
	ErrReviewRequired = errors.New("HTML document requires human review of its exact rendered PDF before sending")
)

// Input.Values contains the final effective values used for rendering, after
// merging the approved defaults with declared caller overrides. New never
// resolves live data or silently replaces printed values with new defaults.
type Input struct {
	TemplateID            uuid.UUID
	TemplateVersion       int32
	TemplateContentSHA256 string
	MasterJSON            json.RawMessage
	DefaultVarsJSON       json.RawMessage
	Values                map[string]string
	Sections              map[string]string
	TemplateApprovedBy    uuid.UUID
	TemplateApprovedAt    time.Time
	PartyBindings         []PartyBinding
}

type source struct {
	SchemaVersion         int               `json:"schema_version"`
	DocumentID            uuid.UUID         `json:"document_id"`
	OrgID                 uuid.UUID         `json:"org_id"`
	TemplateID            uuid.UUID         `json:"template_id"`
	TemplateVersion       int32             `json:"template_version"`
	TemplateContentSHA256 string            `json:"template_content_sha256"`
	TemplateApprovedBy    uuid.UUID         `json:"template_approved_by"`
	TemplateApprovedAt    time.Time         `json:"template_approved_at"`
	MasterJSON            json.RawMessage   `json:"master"`
	DefaultVarsJSON       json.RawMessage   `json:"default_values"`
	Values                map[string]string `json:"values"`
	Sections              map[string]string `json:"sections"`
	MasterDigest          string            `json:"master_digest"`
	ContentDigest         string            `json:"content_digest"`
	PDFKey                string            `json:"pdf_key"`
	PDFSHA256             string            `json:"pdf_sha256"`
	PDFVersionID          string            `json:"pdf_version_id"`
	Commitment            string            `json:"commitment"`
	PartyBindings         []PartyBinding    `json:"party_bindings,omitempty"`
}

// New constructs provenance after the caller renders and stores the exact PDF.
// It does not mutate doc, accept a review, or prove renderer correctness. The
// caller must attach it using the first-set immutable database boundary.
func New(input Input, doc *generated.Document) (json.RawMessage, error) {
	if doc == nil {
		return nil, invalid("missing document")
	}
	if len(input.MasterJSON) > htmlmaster.MaxMasterJSONBytes ||
		len(input.DefaultVarsJSON) > htmlmaster.MaxDefinitions*htmlmaster.MaxValueChars*4+4096 ||
		len(input.Values) > htmlmaster.MaxDefinitions || len(input.Sections) > htmlmaster.MaxDefinitions || len(input.PartyBindings) > 2 {
		return nil, invalid("source inputs exceed limits")
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		return nil, invalid("master")
	}
	version := SchemaVersion
	if master.SchemaVersion == ContractSchemaVersion {
		version = ContractSchemaVersion
	}
	bindings := slices.Clone(input.PartyBindings)
	slices.SortFunc(bindings, func(a, b PartyBinding) int { return strings.Compare(a.Slot, b.Slot) })
	s := source{
		SchemaVersion: version, DocumentID: doc.ID, OrgID: doc.OrgID,
		TemplateID: input.TemplateID, TemplateVersion: input.TemplateVersion,
		TemplateContentSHA256: input.TemplateContentSHA256,
		TemplateApprovedBy:    input.TemplateApprovedBy, TemplateApprovedAt: input.TemplateApprovedAt.UTC(),
		MasterJSON: bytes.Clone(input.MasterJSON), DefaultVarsJSON: bytes.Clone(input.DefaultVarsJSON),
		Values: maps.Clone(input.Values), Sections: maps.Clone(input.Sections),
		PDFKey: doc.PdfStorageKey.String, PDFSHA256: hex.EncodeToString(doc.PdfSha256), PDFVersionID: doc.PdfStorageVersionID.String,
		PartyBindings: bindings,
	}
	if s.Values == nil {
		s.Values = map[string]string{}
	}
	if s.Sections == nil {
		s.Sections = map[string]string{}
	}
	if err := validateIdentity(s, doc); err != nil {
		return nil, err
	}
	canonical, result, err := materialize(s)
	if err != nil {
		return nil, err
	}
	s.MasterJSON, s.DefaultVarsJSON = canonical.MasterJSON, canonical.DefaultsJSON
	s.MasterDigest, s.ContentDigest = result.MasterDigest, result.ContentDigest
	if err := validateVariables(s.Values, doc.VariablesJson); err != nil {
		return nil, err
	}
	s.Commitment, err = sourceCommitment(s, canonical)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > maxSourceBytes {
		return nil, invalid("source encoding or size")
	}
	return raw, nil
}

// Validate recomputes the approved-template and materialized-content
// commitments, checks exact document/PDF identity and printed values, and can
// require a human review bound to the same PDF digest. A missing source leaves
// historical block and static-PDF behavior unchanged; JSON null is invalid.
func Validate(doc *generated.Document, requireReview bool) error {
	_, err := validatedSource(doc, requireReview)
	return err
}

// Commitment returns the stable typed commitment after validating the saved
// source against the document's identity, printed inputs and exact PDF. It
// ignores transport formatting and does not require a completed human review.
// Unlike Validate, absent legacy source is an error: it has no HTML commitment.
func Commitment(doc *generated.Document) (string, error) {
	s, err := validatedSource(doc, false)
	if err != nil {
		return "", err
	}
	if s.Commitment == "" {
		return "", invalid("missing HTML source commitment")
	}
	return s.Commitment, nil
}

func validatedSource(doc *generated.Document, requireReview bool) (source, error) {
	if doc == nil {
		return source{}, invalid("missing document")
	}
	if len(doc.HtmlSourceJson) == 0 {
		if doc.HtmlCurrentMaterializationID.Valid || len(doc.HtmlCurrentSourceJson) != 0 || doc.HtmlCurrentPageCount.Valid || doc.HtmlCurrentMaterializationSequence.Valid || doc.HtmlReviewedMaterializationID.Valid {
			return source{}, invalid("current materialization has no immutable origin")
		}
		return source{}, nil
	}
	raw := doc.HtmlSourceJson
	if !doc.HtmlCurrentMaterializationID.Valid {
		if len(doc.HtmlCurrentSourceJson) != 0 || doc.HtmlCurrentPageCount.Valid || doc.HtmlCurrentMaterializationSequence.Valid || doc.HtmlReviewedMaterializationID.Valid {
			return source{}, invalid("orphan current materialization projection")
		}
	} else {
		if uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) == uuid.Nil || len(doc.HtmlCurrentSourceJson) == 0 ||
			!doc.HtmlCurrentPageCount.Valid || doc.HtmlCurrentPageCount.Int32 < 1 || doc.HtmlCurrentPageCount.Int32 > 500 ||
			!doc.HtmlCurrentMaterializationSequence.Valid || doc.HtmlCurrentMaterializationSequence.Int32 < 1 {
			return source{}, invalid("incomplete current materialization projection")
		}
		origin, err := validatedOrigin(doc)
		if err != nil {
			return source{}, err
		}
		current, err := validatedRecord(doc, doc.HtmlCurrentSourceJson, false)
		if err != nil {
			return source{}, err
		}
		if !sameApprovedOrigin(origin, current) ||
			(doc.HtmlCurrentMaterializationSequence.Int32 == 1 && current.Commitment != origin.Commitment) {
			return source{}, invalid("current materialization changed its immutable approved origin")
		}
		raw = doc.HtmlCurrentSourceJson
		if requireReview && (!doc.HtmlReviewedMaterializationID.Valid || doc.HtmlReviewedMaterializationID.Bytes != doc.HtmlCurrentMaterializationID.Bytes) {
			return source{}, ErrReviewRequired
		}
	}
	return validatedRecord(doc, raw, requireReview)
}

func validatedRecord(doc *generated.Document, raw []byte, requireReview bool) (source, error) {
	var s source
	if err := decodeSource(raw, &s); err != nil {
		return source{}, err
	}
	if err := validateIdentity(s, doc); err != nil {
		return source{}, err
	}
	canonical, result, err := materialize(s)
	if err != nil {
		return source{}, err
	}
	if s.MasterDigest != result.MasterDigest || s.ContentDigest != result.ContentDigest {
		return source{}, invalid("materialization commitment")
	}
	commitment, err := sourceCommitment(s, canonical)
	if err != nil || s.Commitment != commitment {
		return source{}, invalid("source commitment")
	}
	if err := validateVariables(s.Values, doc.VariablesJson); err != nil {
		return source{}, err
	}
	if requireReview && (len(doc.HtmlReviewedPdfSha256) != sha256.Size ||
		!bytes.Equal(doc.HtmlReviewedPdfSha256, doc.PdfSha256) ||
		!doc.HtmlReviewedBy.Valid || uuid.UUID(doc.HtmlReviewedBy.Bytes) == uuid.Nil ||
		!doc.HtmlReviewedAt.Valid || doc.HtmlReviewedAt.InfinityModifier != pgtype.Finite || doc.HtmlReviewedAt.Time.IsZero() ||
		doc.HtmlReviewedAt.Time.Before(s.TemplateApprovedAt)) {
		return source{}, ErrReviewRequired
	}
	return s, nil
}

// EffectiveJSON returns a defensive copy of the validated current source. The
// first-set JSON remains the origin; a broken explicit projection never falls
// back to that old materialization.
func EffectiveJSON(doc *generated.Document) (json.RawMessage, error) {
	if _, err := validatedSource(doc, false); err != nil {
		return nil, err
	}
	if doc.HtmlCurrentMaterializationID.Valid {
		return bytes.Clone(doc.HtmlCurrentSourceJson), nil
	}
	return bytes.Clone(doc.HtmlSourceJson), nil
}

// InputForCurrent recovers only the frozen design/approval and current printed
// inputs. Callers merge declared overrides here, never against a latest template.
func InputForCurrent(doc *generated.Document) (Input, error) {
	s, err := validatedSource(doc, false)
	if err != nil || s.Commitment == "" {
		return Input{}, invalid("missing or invalid current HTML source")
	}
	return Input{TemplateID: s.TemplateID, TemplateVersion: s.TemplateVersion, TemplateContentSHA256: s.TemplateContentSHA256,
		MasterJSON: bytes.Clone(s.MasterJSON), DefaultVarsJSON: bytes.Clone(s.DefaultVarsJSON), Values: maps.Clone(s.Values), Sections: maps.Clone(s.Sections),
		TemplateApprovedBy: s.TemplateApprovedBy, TemplateApprovedAt: s.TemplateApprovedAt, PartyBindings: slices.Clone(s.PartyBindings)}, nil
}

// OriginCommitment validates the immutable first materialization independently
// of the current PDF projection and returns its stable typed chain anchor.
func OriginCommitment(doc *generated.Document) (string, error) {
	s, err := validatedOrigin(doc)
	if err != nil {
		return "", err
	}
	return s.Commitment, nil
}

// ChangedSections reports exact differences from the approved master text.
func ChangedSections(doc *generated.Document) ([]string, error) {
	s, err := validatedSource(doc, false)
	if err != nil || s.Commitment == "" {
		return nil, invalid("missing or invalid current HTML source")
	}
	_, result, err := materialize(s)
	return append([]string{}, result.ChangedSections...), err
}

func MaterializationDigest(doc *generated.Document) (string, error) {
	s, err := validatedSource(doc, false)
	if err != nil || s.Commitment == "" {
		return "", invalid("missing or invalid current HTML source")
	}
	return s.ContentDigest, nil
}

func validatedOrigin(doc *generated.Document) (source, error) {
	if doc == nil || len(doc.HtmlSourceJson) == 0 {
		return source{}, invalid("missing immutable HTML origin")
	}
	var s source
	if err := decodeSource(doc.HtmlSourceJson, &s); err != nil {
		return source{}, err
	}
	digest, err := hex.DecodeString(s.PDFSHA256)
	if err != nil {
		return source{}, invalid("origin PDF digest")
	}
	variables, err := json.Marshal(s.Values)
	if err != nil {
		return source{}, invalid("origin printed inputs")
	}
	// Document has no synchronization fields. The copy is used only to validate
	// the retained original tuple, never to project it onto a live database row.
	origin := *doc
	origin.PdfStorageKey = pgtype.Text{String: s.PDFKey, Valid: true}
	origin.PdfSha256 = digest
	origin.PdfStorageVersionID = pgtype.Text{String: s.PDFVersionID, Valid: true}
	origin.VariablesJson = variables
	return validatedRecord(&origin, doc.HtmlSourceJson, false)
}

func sameApprovedOrigin(a, b source) bool {
	return a.SchemaVersion == b.SchemaVersion && a.DocumentID == b.DocumentID && a.OrgID == b.OrgID &&
		a.TemplateID == b.TemplateID && a.TemplateVersion == b.TemplateVersion && a.TemplateContentSHA256 == b.TemplateContentSHA256 &&
		a.TemplateApprovedBy == b.TemplateApprovedBy && a.TemplateApprovedAt.Equal(b.TemplateApprovedAt) && a.MasterDigest == b.MasterDigest &&
		slices.Equal(a.PartyBindings, b.PartyBindings)
}

func materialize(s source) (htmlmaster.TemplateCommitment, htmlmaster.Result, error) {
	canonical, err := htmlmaster.CanonicalTemplate(s.MasterJSON, s.DefaultVarsJSON)
	if err != nil {
		return canonical, htmlmaster.Result{}, invalid("master or approved defaults")
	}
	if canonical.SHA256 != s.TemplateContentSHA256 {
		return canonical, htmlmaster.Result{}, invalid("approved template commitment")
	}
	master, err := htmlmaster.Decode(canonical.MasterJSON)
	if err != nil {
		return canonical, htmlmaster.Result{}, invalid("canonical master")
	}
	if master.SchemaVersion != s.SchemaVersion {
		return canonical, htmlmaster.Result{}, invalid("master and source schema versions differ")
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return canonical, htmlmaster.Result{}, invalid("compiled master")
	}
	result, err := compiled.Materialize(htmlmaster.Input{Values: s.Values, Sections: s.Sections})
	if err != nil {
		return canonical, result, invalid("materialized values or sections")
	}
	return canonical, result, nil
}

func validateIdentity(s source, doc *generated.Document) error {
	if (s.SchemaVersion != SchemaVersion && s.SchemaVersion != ContractSchemaVersion) || s.DocumentID == uuid.Nil || s.OrgID == uuid.Nil ||
		s.DocumentID != doc.ID || s.OrgID != doc.OrgID || doc.SourceKind != "pdf" || doc.IsEnvelope ||
		s.TemplateID == uuid.Nil || s.TemplateVersion < 1 || !doc.TemplateID.Valid || uuid.UUID(doc.TemplateID.Bytes) != s.TemplateID ||
		s.TemplateApprovedBy == uuid.Nil || s.TemplateApprovedAt.IsZero() || !validSHA256(s.TemplateContentSHA256) {
		return invalid("document or template identity/approval")
	}
	if !doc.PdfStorageKey.Valid || s.PDFKey == "" || strings.TrimSpace(s.PDFKey) != s.PDFKey || s.PDFKey != doc.PdfStorageKey.String ||
		len(doc.PdfSha256) != sha256.Size || !validSHA256(s.PDFSHA256) || s.PDFSHA256 != hex.EncodeToString(doc.PdfSha256) ||
		!doc.PdfStorageVersionID.Valid || s.PDFVersionID == "" || len(s.PDFVersionID) > 1024 ||
		strings.TrimSpace(s.PDFVersionID) != s.PDFVersionID || s.PDFVersionID != doc.PdfStorageVersionID.String {
		return invalid("exact PDF key, digest or VersionId")
	}
	if s.Values == nil || s.Sections == nil {
		return invalid("input maps must be objects")
	}
	if err := validatePartyBindings(s, doc); err != nil {
		return err
	}
	return nil
}

func validateVariables(values map[string]string, raw json.RawMessage) error {
	var variables map[string]string
	if err := strictDecode(raw, &variables, htmlmaster.MaxDefinitions*htmlmaster.MaxValueChars*4+4096); err != nil || variables == nil || !maps.Equal(values, variables) {
		return invalid("document values differ from rendered values; create and review a fresh PDF")
	}
	return nil
}

func sourceCommitment(s source, canonical htmlmaster.TemplateCommitment) (string, error) {
	s.Commitment = ""
	// JSONB may reorder object keys or spacing; bind canonical typed source,
	// not its transport spelling. The template canonicalizer owns master data.
	s.MasterJSON, s.DefaultVarsJSON = canonical.MasterJSON, canonical.DefaultsJSON
	raw, err := json.Marshal(s)
	if err != nil {
		return "", invalid("source encoding")
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "hash.html-source.v%d\x00", s.SchemaVersion)
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalid, reason) }

func decodeSource(raw []byte, s *source) error {
	if err := strictDecode(raw, s, maxSourceBytes); err != nil {
		return err
	}
	// encoding/json matches struct names case-insensitively. Require exact
	// schema keys rather than admitting aliases with ambiguous commitments.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return invalid("source must be an object")
	}
	allowed := map[string]bool{"schema_version": true, "document_id": true, "org_id": true, "template_id": true, "template_version": true, "template_content_sha256": true, "template_approved_by": true, "template_approved_at": true, "master": true, "default_values": true, "values": true, "sections": true, "master_digest": true, "content_digest": true, "pdf_key": true, "pdf_sha256": true, "pdf_version_id": true, "commitment": true}
	if s.SchemaVersion == ContractSchemaVersion {
		allowed["party_bindings"] = true
		var bindings []map[string]json.RawMessage
		if err := json.Unmarshal(fields["party_bindings"], &bindings); err != nil || len(bindings) != 2 {
			return invalid("contract party bindings")
		}
		for _, binding := range bindings {
			if len(binding) != 2 || binding["slot"] == nil || binding["recipient_id"] == nil {
				return invalid("contract party binding schema keys")
			}
		}
	}
	if len(fields) != len(allowed) {
		return invalid("missing source fields")
	}
	for name := range fields {
		if !allowed[name] {
			return invalid("unknown source field")
		}
	}
	return nil
}

func strictDecode(raw []byte, destination any, maxBytes int) error {
	if len(raw) == 0 || len(raw) > maxBytes || !utf8.Valid(raw) || !validJSONEscapes(raw) {
		return invalid("JSON size or Unicode")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := checkJSONValue(decoder, 0); err != nil {
		return invalid("malformed or duplicate JSON fields")
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

func checkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 20 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return ErrInvalid
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
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
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	} else if delim == '[' {
		for decoder.More() {
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	} else {
		return ErrInvalid
	}
	_, err = decoder.Token()
	return err
}

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
		part, err := hex.DecodeString(string(raw[i+1 : i+5]))
		if err != nil {
			return false
		}
		value := uint16(part[0])<<8 | uint16(part[1])
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
		part, err = hex.DecodeString(string(raw[i+3 : i+7]))
		if err != nil {
			return false
		}
		low := uint16(part[0])<<8 | uint16(part[1])
		if low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return !inString
}
