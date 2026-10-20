// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlsource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// RevisionValidationV1 is a pure immutable operation value, not native session,
// current-row, actor, resource, approval or mutation authority. Its fixed native
// owner must retain the actual source/body borrower and every resource consumer.
// Origin-only validation remains OriginCommitment: this operation first proves
// the complete current document, and cannot replace that narrower legacy API.
// No mutable model or Compiled pointer is exposed to a caller.
type RevisionValidationV1 struct {
	self             *RevisionValidationV1
	document         *generated.Document
	effective        source
	originCommitment string
	design           *revisionValidationDesignV1
	changedSections  []string
}

type RevisionValidationStageV1 uint8

const (
	RevisionValidationRawCompileV1 RevisionValidationStageV1 = iota + 1
	RevisionValidationCanonicalCompileV1
	RevisionValidationRecordV1
	RevisionValidationDoneV1
)

type revisionValidationDesignV1 struct {
	raw, defaults                  []byte
	rawMaster, canonicalMaster     htmlmaster.Master
	canonical                      htmlmaster.TemplateCommitment
	rawCompiled, canonicalCompiled *htmlmaster.Compiled
}
type revisionValidationRecordV1 struct {
	source   source
	document *generated.Document
	origin   bool
	design   *revisionValidationDesignV1
}

// The concrete builder separates raw Compile, actual canonical Compile and
// record materialization/encoding. Native code can inspect those exact produced
// models and acquire its fixed owned resource grants BEFORE each fixed stage.
// There is no arbitrary work, size, call-count or admission callback.
type RevisionValidationBuilderV1 struct {
	self              *RevisionValidationBuilderV1
	document          *generated.Document
	normalized        bool
	stage             RevisionValidationStageV1
	record            *revisionValidationRecordV1
	designs           []*revisionValidationDesignV1
	origin, effective source
	changedSections   []string
	failure           error
	finished          bool
}

// NewRevisionValidationBuilderV1 performs only exact document cloning, original
// projection checks, source decoding/identity and raw-master Decode. Those
// initial parser/clone resources must already be owned. In particular it does
// NOT Compile, materialize or encode origin Variables before returning a stage.
func NewRevisionValidationBuilderV1(doc *generated.Document) (*RevisionValidationBuilderV1, error) {
	if doc == nil {
		return nil, invalid("missing document")
	}
	b := &RevisionValidationBuilderV1{document: cloneRevisionDocumentV1(doc)}
	b.self = b
	d := b.document
	if len(d.HtmlSourceJson) == 0 {
		if d.HtmlCurrentMaterializationID.Valid || len(d.HtmlCurrentSourceJson) != 0 || d.HtmlCurrentPageCount.Valid || d.HtmlCurrentMaterializationSequence.Valid || d.HtmlReviewedMaterializationID.Valid {
			return nil, invalid("current materialization has no immutable origin")
		}
		b.stage = RevisionValidationDoneV1
		return b, nil
	}
	if !d.HtmlCurrentMaterializationID.Valid {
		if len(d.HtmlCurrentSourceJson) != 0 || d.HtmlCurrentPageCount.Valid || d.HtmlCurrentMaterializationSequence.Valid || d.HtmlReviewedMaterializationID.Valid {
			return nil, invalid("orphan current materialization projection")
		}
		if err := b.beginRecordV1(d.HtmlSourceJson, d, false); err != nil {
			return nil, err
		}
		return b, nil
	}
	if uuid.UUID(d.HtmlCurrentMaterializationID.Bytes) == uuid.Nil || len(d.HtmlCurrentSourceJson) == 0 || !d.HtmlCurrentPageCount.Valid || d.HtmlCurrentPageCount.Int32 < 1 || d.HtmlCurrentPageCount.Int32 > 500 || !d.HtmlCurrentMaterializationSequence.Valid || d.HtmlCurrentMaterializationSequence.Int32 < 1 {
		return nil, invalid("incomplete current materialization projection")
	}
	b.normalized = true
	var origin source
	if err := decodeSource(d.HtmlSourceJson, &origin); err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(origin.PDFSHA256)
	if err != nil {
		return nil, invalid("origin PDF digest")
	}
	historical := *d
	historical.PdfStorageKey = pgtype.Text{String: origin.PDFKey, Valid: true}
	historical.PdfSha256 = digest
	historical.PdfStorageVersionID = pgtype.Text{String: origin.PDFVersionID, Valid: true}
	// Concrete Values encoding is deferred to the fixed Record stage. It cannot
	// affect validateIdentity, and the original map[string]string Marshal cannot
	// fail for an encodable typed source. It is priced before that stage executes.
	historical.VariablesJson = nil
	if err = b.beginDecodedRecordV1(origin, &historical, true); err != nil {
		return nil, err
	}
	return b, nil
}
func (b *RevisionValidationBuilderV1) validV1() bool {
	return b != nil && b.self == b && !b.finished && b.document != nil
}
func (b *RevisionValidationBuilderV1) failV1(err error) error {
	if err != nil {
		b.failure = err
	}
	return err
}
func (b *RevisionValidationBuilderV1) StageV1() (RevisionValidationStageV1, error) {
	if !b.validV1() {
		return 0, invalid("revision validation scope")
	}
	if b.failure != nil {
		return 0, b.failure
	}
	return b.stage, nil
}
func (b *RevisionValidationBuilderV1) beginRecordV1(raw []byte, doc *generated.Document, origin bool) error {
	var s source
	if err := decodeSource(raw, &s); err != nil {
		return err
	}
	return b.beginDecodedRecordV1(s, doc, origin)
}
func (b *RevisionValidationBuilderV1) beginDecodedRecordV1(s source, doc *generated.Document, origin bool) error {
	if err := validateIdentity(s, doc); err != nil {
		return err
	}
	r := &revisionValidationRecordV1{source: s, document: doc, origin: origin}
	b.record = r
	for _, design := range b.designs {
		// Exact immutable raw bytes/defaults, never an unvalidated claimed SHA.
		if bytes.Equal(design.raw, s.MasterJSON) && bytes.Equal(design.defaults, s.DefaultVarsJSON) {
			if design.canonical.SHA256 != s.TemplateContentSHA256 {
				return invalid("approved template commitment")
			}
			if design.canonicalMaster.SchemaVersion != s.SchemaVersion {
				return invalid("master and source schema versions differ")
			}
			r.design = design
			b.stage = RevisionValidationRecordV1
			return nil
		}
	}
	master, err := htmlmaster.Decode(s.MasterJSON)
	if err != nil {
		return invalid("master or approved defaults")
	}
	design := &revisionValidationDesignV1{raw: bytes.Clone(s.MasterJSON), defaults: bytes.Clone(s.DefaultVarsJSON), rawMaster: master}
	r.design = design
	b.stage = RevisionValidationRawCompileV1
	return nil
}

// MasterV1 returns a defensive copy of the ACTUAL next raw/canonical model.
// Mutating it cannot change the private model that the subsequent fixed stage
// uses. The native owner must retain/price this inspection copy independently.
func (b *RevisionValidationBuilderV1) MasterV1() (htmlmaster.Master, error) {
	if !b.validV1() || b.failure != nil || b.record == nil || b.record.design == nil {
		return htmlmaster.Master{}, invalid("revision validation scope")
	}
	if b.stage == RevisionValidationRawCompileV1 {
		return cloneRevisionMasterV1(b.record.design.rawMaster), nil
	}
	if b.stage == RevisionValidationCanonicalCompileV1 || b.stage == RevisionValidationRecordV1 {
		return cloneRevisionMasterV1(b.record.design.canonicalMaster), nil
	}
	return htmlmaster.Master{}, invalid("revision validation stage")
}
func (b *RevisionValidationBuilderV1) InputV1() (Input, error) {
	if !b.validV1() || b.failure != nil || b.record == nil {
		return Input{}, invalid("revision validation scope")
	}
	return revisionInputV1(b.record.source), nil
}
func (b *RevisionValidationBuilderV1) CanonicalV1() (htmlmaster.TemplateCommitment, error) {
	if !b.validV1() || b.failure != nil || b.record == nil || b.stage == RevisionValidationRawCompileV1 {
		return htmlmaster.TemplateCommitment{}, invalid("revision validation stage")
	}
	return cloneRevisionCanonicalV1(b.record.design.canonical), nil
}

func (b *RevisionValidationBuilderV1) PrepareRawV1() error {
	if !b.validV1() || b.failure != nil || b.stage != RevisionValidationRawCompileV1 || b.record == nil {
		return invalid("revision validation stage")
	}
	r := b.record
	d := r.design
	canonical, err := htmlmaster.CanonicalTemplate(d.raw, d.defaults)
	if err != nil {
		return b.failV1(invalid("master or approved defaults"))
	}
	if canonical.SHA256 != r.source.TemplateContentSHA256 {
		return b.failV1(invalid("approved template commitment"))
	}
	canonicalMaster, err := htmlmaster.Decode(canonical.MasterJSON)
	if err != nil {
		return b.failV1(invalid("canonical master"))
	}
	if canonicalMaster.SchemaVersion != r.source.SchemaVersion {
		return b.failV1(invalid("master and source schema versions differ"))
	}
	// Keep raw and canonical compiled behavior distinct. The original artifact,
	// parties and fresh-input helpers Compile the raw saved Master; materialize
	// Compiles the produced canonical Master. No equivalence is assumed here.
	rawCompiled, err := htmlmaster.Compile(d.rawMaster)
	if err != nil {
		return b.failV1(invalid("compiled master"))
	}
	d.canonical, d.canonicalMaster, d.rawCompiled = canonical, canonicalMaster, rawCompiled
	b.stage = RevisionValidationCanonicalCompileV1
	return nil
}
func (b *RevisionValidationBuilderV1) PrepareCanonicalV1() error {
	if !b.validV1() || b.failure != nil || b.stage != RevisionValidationCanonicalCompileV1 || b.record == nil {
		return invalid("revision validation stage")
	}
	d := b.record.design
	compiled, err := htmlmaster.Compile(d.canonicalMaster)
	if err != nil {
		return b.failV1(invalid("compiled master"))
	}
	d.canonicalCompiled = compiled
	b.designs = append(b.designs, d)
	b.stage = RevisionValidationRecordV1
	return nil
}
func (b *RevisionValidationBuilderV1) ValidateRecordV1() error {
	if !b.validV1() || b.failure != nil || b.stage != RevisionValidationRecordV1 || b.record == nil {
		return invalid("revision validation stage")
	}
	r := b.record
	s := r.source
	d := r.design
	if r.origin {
		variables, err := json.Marshal(s.Values)
		if err != nil {
			return b.failV1(invalid("origin printed inputs"))
		}
		r.document.VariablesJson = variables
	}
	result, err := d.canonicalCompiled.Materialize(htmlmaster.Input{Values: s.Values, Sections: s.Sections})
	if err != nil {
		return b.failV1(invalid("materialized values or sections"))
	}
	if s.MasterDigest != result.MasterDigest || s.ContentDigest != result.ContentDigest {
		return b.failV1(invalid("materialization commitment"))
	}
	if err = validateRevisionArtifactV1(s, d.rawCompiled); err != nil {
		return b.failV1(err)
	}
	commitment, err := sourceCommitment(s, d.canonical)
	if err != nil || s.Commitment != commitment {
		return b.failV1(invalid("source commitment"))
	}
	if err = validateVariables(s.Values, r.document.VariablesJson); err != nil {
		return b.failV1(err)
	}
	if r.origin {
		b.origin = s
		if err = b.beginRecordV1(b.document.HtmlCurrentSourceJson, b.document, false); err != nil {
			return b.failV1(err)
		}
		return nil
	}
	if b.normalized && (!sameApprovedOrigin(b.origin, s) || (b.document.HtmlCurrentMaterializationSequence.Int32 == 1 && s.Commitment != b.origin.Commitment)) {
		return b.failV1(invalid("current materialization changed its immutable approved origin"))
	}
	b.effective = s
	b.changedSections = slices.Clone(result.ChangedSections)
	b.stage = RevisionValidationDoneV1
	return nil
}
func (b *RevisionValidationBuilderV1) FinishV1() (*RevisionValidationV1, error) {
	if !b.validV1() || b.failure != nil || b.stage != RevisionValidationDoneV1 {
		if b != nil && b.failure != nil {
			return nil, b.failure
		}
		return nil, invalid("revision validation stage")
	}
	v := &RevisionValidationV1{document: b.document, effective: b.effective, changedSections: b.changedSections}
	if b.record != nil {
		v.design = b.record.design
	}
	if b.normalized {
		v.originCommitment = b.origin.Commitment
	} else {
		v.originCommitment = b.effective.Commitment
	}
	v.self = v
	b.finished = true
	b.document = nil
	b.record = nil
	b.designs = nil
	b.origin = source{}
	b.effective = source{}
	b.changedSections = nil
	return v, nil
}

// NewRevisionValidationV1 is a pure convenience/oracle runner. Production native
// code must drive the explicit builder stages with real source/model grants;
// this constructor itself supplies no admission, deadline, DB or CPU authority.
func NewRevisionValidationV1(doc *generated.Document) (*RevisionValidationV1, error) {
	b, err := NewRevisionValidationBuilderV1(doc)
	if err != nil {
		return nil, err
	}
	for {
		stage, err := b.StageV1()
		if err != nil {
			return nil, err
		}
		switch stage {
		case RevisionValidationRawCompileV1:
			err = b.PrepareRawV1()
		case RevisionValidationCanonicalCompileV1:
			err = b.PrepareCanonicalV1()
		case RevisionValidationRecordV1:
			err = b.ValidateRecordV1()
		case RevisionValidationDoneV1:
			return b.FinishV1()
		default:
			return nil, invalid("revision validation stage")
		}
		if err != nil {
			return nil, err
		}
	}
}
func (v *RevisionValidationV1) validV1() bool { return v != nil && v.self == v && v.document != nil }
func (v *RevisionValidationV1) MatchesDocumentV1(doc *generated.Document) bool {
	return v.validV1() && revisionDocumentEqualV1(v.document, doc)
}
func (v *RevisionValidationV1) ValidateV1(requireReview bool) error {
	if !v.validV1() {
		return invalid("revision validation scope")
	}
	if !requireReview || len(v.document.HtmlSourceJson) == 0 {
		return nil
	}
	d := v.document
	s := v.effective
	if d.HtmlCurrentMaterializationID.Valid && (!d.HtmlReviewedMaterializationID.Valid || d.HtmlReviewedMaterializationID.Bytes != d.HtmlCurrentMaterializationID.Bytes) {
		return ErrReviewRequired
	}
	if len(d.HtmlReviewedPdfSha256) != sha256.Size || !bytes.Equal(d.HtmlReviewedPdfSha256, d.PdfSha256) || !d.HtmlReviewedBy.Valid || uuid.UUID(d.HtmlReviewedBy.Bytes) == uuid.Nil || !d.HtmlReviewedAt.Valid || d.HtmlReviewedAt.InfinityModifier != pgtype.Finite || d.HtmlReviewedAt.Time.IsZero() || d.HtmlReviewedAt.Time.Before(s.TemplateApprovedAt) {
		return ErrReviewRequired
	}
	return nil
}
func (v *RevisionValidationV1) CommitmentV1() (string, error) {
	if !v.validV1() {
		return "", invalid("revision validation scope")
	}
	if v.effective.Commitment == "" {
		return "", invalid("missing HTML source commitment")
	}
	return v.effective.Commitment, nil
}
func (v *RevisionValidationV1) OriginCommitmentV1() (string, error) {
	if !v.validV1() {
		return "", invalid("revision validation scope")
	}
	if len(v.document.HtmlSourceJson) == 0 {
		return "", invalid("missing immutable HTML origin")
	}
	return v.originCommitment, nil
}
func (v *RevisionValidationV1) EffectiveJSONV1() (json.RawMessage, error) {
	if !v.validV1() {
		return nil, invalid("revision validation scope")
	}
	if v.document.HtmlCurrentMaterializationID.Valid {
		return bytes.Clone(v.document.HtmlCurrentSourceJson), nil
	}
	return bytes.Clone(v.document.HtmlSourceJson), nil
}
func (v *RevisionValidationV1) InputForCurrentV1() (Input, error) {
	if !v.validV1() || v.effective.Commitment == "" {
		return Input{}, invalid("missing or invalid current HTML source")
	}
	return revisionInputV1(v.effective), nil
}
func (v *RevisionValidationV1) MaterializationDigestV1() (string, error) {
	if !v.validV1() || v.effective.Commitment == "" {
		return "", invalid("missing or invalid current HTML source")
	}
	return v.effective.ContentDigest, nil
}
func (v *RevisionValidationV1) ChangedSectionsV1() ([]string, error) {
	if !v.validV1() || v.effective.Commitment == "" {
		return nil, invalid("missing or invalid current HTML source")
	}
	return append([]string{}, v.changedSections...), nil
}
func (v *RevisionValidationV1) CanonicalV1() (htmlmaster.TemplateCommitment, error) {
	if !v.validV1() || v.design == nil {
		return htmlmaster.TemplateCommitment{}, invalid("missing or invalid current HTML source")
	}
	return cloneRevisionCanonicalV1(v.design.canonical), nil
}

// MaterializeRevisionV1 permits only declared value/section overrides. The
// design, approval and bindings are constructed internally from this immutable
// operation, not accepted from a candidate claiming the same template SHA.
// Changed is the original content-digest or optional-empty-addition decision;
// a handler still maps false to its existing conflict and performs fresh render.
func (v *RevisionValidationV1) MaterializeRevisionV1(values, sections map[string]string) (input Input, result htmlmaster.Result, changed bool, err error) {
	input, err = v.InputForCurrentV1()
	if err != nil {
		return input, result, false, err
	}
	for key, value := range values {
		input.Values[strings.Clone(key)] = strings.Clone(value)
	}
	for key, value := range sections {
		input.Sections[strings.Clone(key)] = strings.Clone(value)
	}
	result, err = v.design.rawCompiled.Materialize(htmlmaster.Input{Values: input.Values, Sections: input.Sections})
	if err != nil {
		return Input{}, htmlmaster.Result{}, false, err
	}
	changed = result.ContentDigest != v.effective.ContentDigest
	if !changed {
		// Master/default/approval/bindings are the exact already-validated values
		// constructed above. Only these private declared maps can differ here.
		changed = maps.Equal(v.effective.Sections, input.Sections) && len(input.Values) > len(v.effective.Values)
		if changed {
			for key, value := range v.effective.Values {
				if next, ok := input.Values[key]; !ok || next != value {
					changed = false
					break
				}
			}
		}
		if changed {
			for key, value := range input.Values {
				if _, present := v.effective.Values[key]; present {
					continue
				}
				optional := false
				for _, definition := range v.design.canonicalMaster.Values {
					if definition.Name == key && !definition.Required {
						optional = true
						break
					}
				}
				if value != "" || !optional {
					changed = false
					break
				}
			}
		}
	}
	result.ChangedSections = slices.Clone(result.ChangedSections)
	return input, result, changed, nil
}
func (v *RevisionValidationV1) SigningPageHTMLV1(values, sections map[string]string) (string, error) {
	if !v.validV1() || v.design == nil {
		return "", invalid("approved signing page is absent")
	}
	return v.design.rawCompiled.SigningPageHTML(htmlmaster.Input{Values: values, Sections: sections})
}
func (v *RevisionValidationV1) NewSigningArtifactV1(values, sections map[string]string, composition sanitize.PDFCompositionManifest) (*SigningArtifact, error) {
	if !v.validV1() || v.design == nil {
		return nil, invalid("signing page policy")
	}
	return NewSigningArtifact(v.design.rawCompiled, htmlmaster.Input{Values: values, Sections: sections}, slices.Clone(v.effective.PartyBindings), composition)
}

func revisionInputV1(s source) Input {
	return Input{TemplateID: s.TemplateID, TemplateVersion: s.TemplateVersion, TemplateContentSHA256: s.TemplateContentSHA256, MasterJSON: bytes.Clone(s.MasterJSON), DefaultVarsJSON: bytes.Clone(s.DefaultVarsJSON), Values: maps.Clone(s.Values), Sections: maps.Clone(s.Sections), TemplateApprovedBy: s.TemplateApprovedBy, TemplateApprovedAt: s.TemplateApprovedAt, PartyBindings: slices.Clone(s.PartyBindings), SigningArtifact: cloneSigningArtifact(s.SigningArtifact)}
}
func cloneRevisionCanonicalV1(c htmlmaster.TemplateCommitment) htmlmaster.TemplateCommitment {
	c.MasterJSON = bytes.Clone(c.MasterJSON)
	c.DefaultsJSON = bytes.Clone(c.DefaultsJSON)
	return c
}
func cloneRevisionMasterV1(m htmlmaster.Master) htmlmaster.Master {
	m.Values = slices.Clone(m.Values)
	m.Sections = slices.Clone(m.Sections)
	m.Assets = slices.Clone(m.Assets)
	m.ContractProfile = mCloneContractV1(m.ContractProfile)
	m.SigningPage = cloneRevisionPolicyV1(m.SigningPage)
	return m
}
func mCloneContractV1(p *htmlmaster.ContractProfile) *htmlmaster.ContractProfile {
	if p == nil {
		return nil
	}
	c := *p
	c.Parties = slices.Clone(p.Parties)
	c.Terms = slices.Clone(p.Terms)
	return &c
}
func cloneRevisionPolicyV1(p *htmlmaster.SigningPagePolicy) *htmlmaster.SigningPagePolicy {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}
func validateRevisionArtifactV1(s source, compiled *htmlmaster.Compiled) error {
	if s.SchemaVersion != SigningPageSchemaVersion {
		if s.SigningArtifact != nil {
			return invalid("legacy source cannot carry signing artifact")
		}
		return nil
	}
	a := s.SigningArtifact
	if a == nil || a.Version != 1 || a.Policy != "hash-branded-signing-page-a4-v1" || !validSHA256(a.PlanSHA256) {
		return invalid("signing artifact policy")
	}
	if err := sanitize.ValidatePDFCompositionManifest(a.Composition, s.PDFSHA256, a.Composition.FinalPages); err != nil {
		return invalid("signing artifact geometry or PDF binding")
	}
	if !slices.Equal(a.Fields, signingRectangles(int32(a.Composition.FinalPages))) {
		return invalid("signing artifact rectangles")
	}
	if compiled == nil {
		return invalid("signing artifact master")
	}
	plan, err := signingPlanDigest(compiled, htmlmaster.Input{Values: s.Values, Sections: s.Sections}, s.PartyBindings)
	if err != nil || plan != a.PlanSHA256 {
		return invalid("signing artifact plan commitment")
	}
	return nil
}

// RecordVariablesV1 exposes only a defensive actual record parser input. For
// origin, the original fixed typed Values Marshal creates that input inside
// RecordV1; the native owner prices it from InputV1.Values before dispatch.
func (b *RevisionValidationBuilderV1) RecordVariablesV1() ([]byte, bool, error) {
	if !b.validV1() || b.failure != nil || b.stage != RevisionValidationRecordV1 || b.record == nil {
		return nil, false, invalid("revision validation stage")
	}
	return bytes.Clone(b.record.document.VariablesJson), b.record.origin, nil
}

// RevisionValidationRecordPinsV1 contains actual encoding/parser inputs from
// the private current record. They are data, never capacity or SQL authority.
// Strings are immutable; every mutable byte field is detached.
type RevisionValidationRecordPinsV1 struct {
	DocumentID, OrgID        uuid.UUID
	PDFKey, PDFVersionID     string
	PDFSHA256, VariablesJSON []byte
	Origin                   bool
}

func (b *RevisionValidationBuilderV1) RecordPinsV1() (RevisionValidationRecordPinsV1, error) {
	if !b.validV1() || b.failure != nil || b.stage != RevisionValidationRecordV1 || b.record == nil {
		return RevisionValidationRecordPinsV1{}, invalid("revision validation stage")
	}
	r := b.record
	d := r.document
	return RevisionValidationRecordPinsV1{DocumentID: d.ID, OrgID: d.OrgID, PDFKey: d.PdfStorageKey.String, PDFVersionID: d.PdfStorageVersionID.String, PDFSHA256: bytes.Clone(d.PdfSha256), VariablesJSON: bytes.Clone(d.VariablesJson), Origin: r.origin}, nil
}
