// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

const DataAdmissionDomain = "hash:presign-data-admission:v1\x00"

// DataAdmissionSnapshot records checked data, separately from human review and
// delegated signature evidence. It contains commitments, never CRM credentials.
// Its canonical bytes are private evidence, not a public API response.
type DataAdmissionSnapshot struct {
	Version              int                 `json:"version"`
	OrgID                uuid.UUID           `json:"org_id"`
	DocumentID           uuid.UUID           `json:"document_id"`
	SenderID             uuid.UUID           `json:"sender_id"`
	PolicyID             uuid.UUID           `json:"policy_id"`
	WorkflowID           uuid.UUID           `json:"workflow_id"`
	WorkflowRevision     int64               `json:"workflow_revision"`
	DefinitionSHA256     string              `json:"definition_sha256"`
	Template             presign.TemplatePin `json:"template"`
	InputMode            string              `json:"input_mode"`
	SourceCommitment     string              `json:"source_commitment"`
	ContentSHA256        string              `json:"content_sha256"`
	ValuesSHA256         string              `json:"values_sha256"`
	SectionsSHA256       string              `json:"sections_sha256"`
	ReviewEvidenceSHA256 string              `json:"review_evidence_sha256"`
	ReviewKind           string              `json:"review_kind"`
	GrantorSHA256        string              `json:"grantor_sha256"`
	CRMRecords           []RecordRule        `json:"crm_records"`
	CRMValues            []AdmittedCRMValue  `json:"crm_values"`
	ValidUntil           time.Time           `json:"valid_until"`
}

type AdmittedCRMValue struct {
	Variable    string                       `json:"variable"`
	SourceKind  string                       `json:"source_kind"`
	SourceRef   string                       `json:"source_ref"`
	SourcePath  string                       `json:"source_path"`
	Observation resolver.CRMValueObservation `json:"observation"`
}

// DataAdmission can only be constructed from evaluated inputs or decoded
// committed evidence. Neither constructor locks rows or establishes authority.
type DataAdmission struct {
	snapshot   DataAdmissionSnapshot
	canonical  []byte
	commitment string
}

func (a DataAdmission) Commitment() string    { return a.commitment }
func (a DataAdmission) CanonicalJSON() []byte { return bytes.Clone(a.canonical) }
func (a DataAdmission) Snapshot() DataAdmissionSnapshot {
	s := a.snapshot
	s.CRMRecords = append([]RecordRule{}, s.CRMRecords...)
	s.CRMValues = append([]AdmittedCRMValue{}, s.CRMValues...)
	return s
}

// EvaluateExecutionData enforces every stored rule against the actual validated
// current source. CRM reports require the resolver's private original binding
// and account fence; exported JSON alone cannot supply those witnesses. Callers
// must additionally lock/recheck all bindings, mapping review and the active CRM
// generation, then repeat this evaluation and natural deadlines after waits.
// This function does not authorize dispatch, render, review or mutate a document.
func EvaluateExecutionData(d WorkflowDefinition, grantor presign.NamedRepresentative, doc *generated.Document, reports []resolver.ResolveReport, at time.Time) (DataAdmission, error) {
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID != d.OrgID || doc.SenderID != grantor.UserID || doc.Status != "draft" || doc.DeletedAt.Valid || doc.ParentEnvelopeID.Valid || at.IsZero() {
		return DataAdmission{}, invalid("data admission document or grantor")
	}
	reviewed := d.Kind == KindReviewedDocument
	if htmlsource.Validate(doc, reviewed) != nil {
		return DataAdmission{}, invalid("data admission source or actual review")
	}
	in, err := htmlsource.InputForCurrent(doc)
	if err != nil || ValidateDefinitionAgainstTemplate(d, in.MasterJSON, in.DefaultVarsJSON) != nil ||
		in.TemplateID != d.Template.ID || int64(in.TemplateVersion) != d.Template.Version || in.TemplateContentSHA256 != d.Template.ContentSHA256 ||
		in.TemplateApprovedBy != d.Template.ApprovedBy || !in.TemplateApprovedAt.Equal(d.Template.ApprovedAt) {
		return DataAdmission{}, invalid("data admission selected template")
	}
	m, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		return DataAdmission{}, invalid("data admission master")
	}
	var defaults map[string]string
	if json.Unmarshal(in.DefaultVarsJSON, &defaults) != nil {
		return DataAdmission{}, invalid("data admission defaults")
	}
	crmReports := map[string]resolver.ResolveReport{}
	for _, r := range reports {
		isCRM := r.SourceKind == "crm.deal" || r.SourceKind == "crm.contact" || r.SourceKind == "crm.company"
		if !isCRM {
			if r.CRMObservation != nil {
				return DataAdmission{}, invalid("unexpected CRM witness")
			}
			continue
		}
		if _, exists := crmReports[r.Variable]; exists || resolver.ValidateFreshCRMReport(r, doc.OrgID, doc.ID, at) != nil {
			return DataAdmission{}, invalid("original fresh CRM report")
		}
		crmReports[r.Variable] = r
	}
	grantorFields := map[string]string{"name": grantor.Name, "email": grantor.Email, "company_name": grantor.CompanyName, "company_id": grantor.CompanyID, "authority_basis": grantor.AuthorityBasis}
	s := DataAdmissionSnapshot{Version: 1, OrgID: doc.OrgID, DocumentID: doc.ID, SenderID: doc.SenderID,
		PolicyID: d.PolicyID, WorkflowID: d.ID, WorkflowRevision: d.Revision, Template: d.Template,
		InputMode: presign.InputApprovedData, ReviewKind: "none", ReviewEvidenceSHA256: NoHumanReviewSHA256(), CRMRecords: []RecordRule{}, CRMValues: []AdmittedCRMValue{}}
	if reviewed {
		s.InputMode, s.ReviewKind = presign.InputReviewedDocument, "human"
	}
	_, s.DefinitionSHA256, _, err = CanonicalDefinition(d)
	if err != nil {
		return DataAdmission{}, err
	}
	selected := map[string]string{}
	used := map[string]bool{}
	for _, r := range d.DataRules.Values {
		value, present := in.Values[r.Variable]
		switch r.Mode {
		case ModeReviewedValue:
			// Actual source review has already been checked. Optional absence is
			// retained; it never silently becomes an explicit empty value.
		case ModeAbsent:
			if present {
				return DataAdmission{}, invalid("absent rule presence")
			}
		case ModeDefault:
			want, ok := defaults[r.Variable]
			if !ok || !present || value != want {
				return DataAdmission{}, invalid("exact approved default")
			}
		case ModeLiteral:
			if !present || value != *r.Literal {
				return DataAdmission{}, invalid("exact approved literal")
			}
		case ModeGrantor:
			if !present || value != grantorFields[r.GrantorField] {
				return DataAdmission{}, invalid("exact named grantor value")
			}
		case ModeCRM:
			entry, exists := crmReports[r.Variable]
			if !exists || !present || entry.Value != value || entry.SourceKind != r.SourceKind || entry.SourcePath != r.SourcePath || entry.CRMObservation == nil || d.DataRules.CRM == nil {
				return DataAdmission{}, invalid("exact CRM scalar rule")
			}
			c, o := d.DataRules.CRM, *entry.CRMObservation
			if o.ConnectionID != c.ConnectionID || o.Generation != strconv.FormatInt(c.Generation, 10) || o.Origin != c.Origin || o.CRMTeamID != c.TeamID || o.CRMUserID != c.UserID || o.Transformation != "" || !validSHA(o.BodySHA256) ||
				o.ObservedAt.IsZero() || o.ObservedAt.After(at) || at.Sub(o.ObservedAt) > resolver.CRMObservationMaxAge {
				return DataAdmission{}, invalid("exact CRM account and observation")
			}
			if previous, ok := selected[r.SourceKind]; ok && previous != entry.SourceRef {
				return DataAdmission{}, invalid("one selected native record per kind")
			}
			selected[r.SourceKind] = entry.SourceRef
			used[r.Variable] = true
			s.CRMValues = append(s.CRMValues, AdmittedCRMValue{r.Variable, r.SourceKind, entry.SourceRef, r.SourcePath, o})
			until := o.ObservedAt.Add(resolver.CRMObservationMaxAge)
			if s.ValidUntil.IsZero() || until.Before(s.ValidUntil) {
				s.ValidUntil = until
			}
		}
	}
	if len(used) != len(crmReports) {
		return DataAdmission{}, invalid("unapproved CRM mapping")
	}
	if c := d.DataRules.CRM; c != nil {
		if len(selected) != len(c.Records) {
			return DataAdmission{}, invalid("complete selected CRM record set")
		}
		for _, r := range c.Records {
			id, ok := selected[r.Kind]
			if !ok || c.Selection == "fixed_record_set" && id != r.ID {
				return DataAdmission{}, invalid("approved CRM record identity")
			}
			s.CRMRecords = append(s.CRMRecords, RecordRule{Kind: r.Kind, ID: id})
		}
	}
	sections := map[string]string{}
	bySection := map[string]htmlmaster.Section{}
	for _, v := range m.Sections {
		bySection[v.Name] = v
	}
	for _, r := range d.DataRules.Sections {
		text, exists := in.Sections[r.Section]
		if !exists {
			text = bySection[r.Section].DefaultText
		}
		if r.Mode == ModeDefault && text != bySection[r.Section].DefaultText || r.Mode == ModeLiteral && text != *r.Literal {
			return DataAdmission{}, invalid("exact approved section text")
		}
		sections[r.Section] = text
	}
	s.SourceCommitment, err = htmlsource.Commitment(doc)
	if err != nil {
		return DataAdmission{}, err
	}
	s.ContentSHA256, err = htmlsource.MaterializationDigest(doc)
	if err != nil {
		return DataAdmission{}, err
	}
	raw, _ := canonical(in.Values)
	s.ValuesSHA256 = domainSHA("hash:presign-execution-values:v1", raw)
	raw, _ = canonical(sections)
	s.SectionsSHA256 = domainSHA("hash:presign-execution-sections:v1", raw)
	raw, _ = canonical(grantor)
	s.GrantorSHA256 = domainSHA("hash:presign-execution-grantor:v1", raw)
	if reviewed {
		s.ReviewEvidenceSHA256 = actualReviewSHA256(doc)
	}
	sort.Slice(s.CRMRecords, func(i, j int) bool { return s.CRMRecords[i].Kind < s.CRMRecords[j].Kind })
	sort.Slice(s.CRMValues, func(i, j int) bool { return s.CRMValues[i].Variable < s.CRMValues[j].Variable })
	return newDataAdmission(s)
}

func newDataAdmission(s DataAdmissionSnapshot) (DataAdmission, error) {
	if s.Version != 1 || s.OrgID == uuid.Nil || s.DocumentID == uuid.Nil || s.SenderID == uuid.Nil || s.PolicyID == uuid.Nil || s.WorkflowID == uuid.Nil || s.WorkflowRevision < 1 || s.WorkflowRevision > presign.MaxRevision || s.CRMRecords == nil || s.CRMValues == nil || len(s.CRMRecords) > 3 || len(s.CRMValues) > 64 {
		return DataAdmission{}, invalid("admission snapshot identity or bounds")
	}
	for _, v := range []string{s.DefinitionSHA256, s.SourceCommitment, s.ContentSHA256, s.ValuesSHA256, s.SectionsSHA256, s.GrantorSHA256, s.Template.ContentSHA256} {
		if !validSHA(v) {
			return DataAdmission{}, invalid("admission commitment")
		}
	}
	if s.Template.ID == uuid.Nil || s.Template.Version < 1 || s.Template.Version > presign.MaxRevision || s.Template.ApprovedBy == uuid.Nil || s.Template.ApprovedAt.IsZero() ||
		(s.InputMode != presign.InputReviewedDocument && s.InputMode != presign.InputApprovedData) ||
		(s.InputMode == presign.InputReviewedDocument && (s.ReviewKind != "human" || !validSHA(s.ReviewEvidenceSHA256) || s.ReviewEvidenceSHA256 == NoHumanReviewSHA256())) || (s.InputMode == presign.InputApprovedData && (s.ReviewKind != "none" || s.ReviewEvidenceSHA256 != NoHumanReviewSHA256())) ||
		(len(s.CRMValues) == 0) != (len(s.CRMRecords) == 0) || (len(s.CRMValues) == 0) != s.ValidUntil.IsZero() {
		return DataAdmission{}, invalid("admission mode, review or deadline")
	}
	selected := map[string]string{}
	previous := ""
	for _, r := range s.CRMRecords {
		if r.Kind <= previous || crmconnection.ValidateRecordRef(crmconnection.RecordRef{Kind: crmconnection.RecordKind(r.Kind), ID: r.ID}) != nil {
			return DataAdmission{}, invalid("canonical selected CRM records")
		}
		selected[r.Kind], previous = r.ID, r.Kind
	}
	previous = ""
	var earliest time.Time
	var account crmconnection.Identity
	usedRecords := map[string]bool{}
	for _, v := range s.CRMValues {
		o := v.Observation
		generation, err := strconv.ParseInt(o.Generation, 10, 64)
		id := crmconnection.Identity{ID: o.ConnectionID, OrgID: s.OrgID, Generation: generation, Origin: o.Origin, CRMTeamID: o.CRMTeamID, CRMUserID: o.CRMUserID}
		catalogPath := false
		for _, f := range crmconnection.Catalog(crmconnection.RecordKind(v.SourceKind)) {
			if f.Path == v.SourcePath {
				catalogPath = true
			}
		}
		if !declaredName.MatchString(v.Variable) || v.Variable <= previous || selected[v.SourceKind] != v.SourceRef || !catalogPath || err != nil || o.Generation != strconv.FormatInt(generation, 10) || crmconnection.ValidateIdentity(id) != nil || !validSHA(o.BodySHA256) || !validSHA(o.ValueSHA256) || o.Transformation != "" || o.ObservedAt.IsZero() || o.RecordUpdatedAt.IsZero() {
			return DataAdmission{}, invalid("canonical CRM scalar witness")
		}
		if account.ID != uuid.Nil && account != id {
			return DataAdmission{}, invalid("one original CRM account")
		}
		account = id
		until := o.ObservedAt.Add(resolver.CRMObservationMaxAge)
		if earliest.IsZero() || until.Before(earliest) {
			earliest = until
		}
		usedRecords[v.SourceKind], previous = true, v.Variable
	}
	if len(usedRecords) != len(selected) || !earliest.Equal(s.ValidUntil) {
		return DataAdmission{}, invalid("exact CRM deadline and coverage")
	}
	raw, err := canonical(s)
	if err != nil || len(raw) > presign.MaxSnapshotBytes {
		return DataAdmission{}, invalid("admission byte bound")
	}
	return DataAdmission{snapshot: s, canonical: raw, commitment: sha(append([]byte(DataAdmissionDomain), raw...))}, nil
}

// NoHumanReviewSHA256 records that this data admission does not rely on human
// review. A document may have an unrelated prior review; it is never invented,
// removed or asserted by this commitment. This is not privacy acknowledgment.
func NoHumanReviewSHA256() string {
	return domainSHA("hash:presign-execution-review-absence:v1", []byte(`{"version":1,"kind":"none","human_review_relied_on":false}`))
}

func actualReviewSHA256(doc *generated.Document) string {
	review := struct {
		By              uuid.UUID `json:"by"`
		At              time.Time `json:"at"`
		PDFSHA256       string    `json:"pdf_sha256"`
		Materialization uuid.UUID `json:"materialization"`
	}{uuid.UUID(doc.HtmlReviewedBy.Bytes), doc.HtmlReviewedAt.Time.UTC(), hex.EncodeToString(doc.HtmlReviewedPdfSha256), uuid.UUID(doc.HtmlReviewedMaterializationID.Bytes)}
	raw, _ := canonical(review)
	return domainSHA("hash:presign-execution-review:v1", raw)
}

// ValidateDataAdmissionDocument checks immutable admission against the actual
// source and actual human review record, including during committed recovery.
// It intentionally does not require a fresh CRM read, grant or draft status.
// The caller must load the authoritative exact document/source rows and storage
// artifacts; a successful descriptor check does not itself prove that loading.
func ValidateDataAdmissionDocument(a DataAdmission, doc *generated.Document) error {
	decoded, err := DecodeDataAdmission(a.CanonicalJSON())
	if err != nil || decoded.Commitment() != a.Commitment() || doc == nil {
		return invalid("admission document integrity")
	}
	s := a.Snapshot()
	if doc.ID != s.DocumentID || doc.OrgID != s.OrgID || doc.SenderID != s.SenderID || htmlsource.Validate(doc, s.InputMode == presign.InputReviewedDocument) != nil {
		return invalid("admission actual source or review")
	}
	in, err := htmlsource.InputForCurrent(doc)
	if err != nil || in.TemplateID != s.Template.ID || int64(in.TemplateVersion) != s.Template.Version || in.TemplateContentSHA256 != s.Template.ContentSHA256 || in.TemplateApprovedBy != s.Template.ApprovedBy || !in.TemplateApprovedAt.Equal(s.Template.ApprovedAt) {
		return invalid("admission actual template")
	}
	source, err := htmlsource.Commitment(doc)
	if err != nil || source != s.SourceCommitment {
		return invalid("admission actual source commitment")
	}
	content, err := htmlsource.MaterializationDigest(doc)
	if err != nil || content != s.ContentSHA256 {
		return invalid("admission actual printed content")
	}
	raw, _ := canonical(in.Values)
	if domainSHA("hash:presign-execution-values:v1", raw) != s.ValuesSHA256 {
		return invalid("admission actual values")
	}
	m, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		return invalid("admission actual master")
	}
	sections := map[string]string{}
	for _, v := range m.Sections {
		text, exists := in.Sections[v.Name]
		if !exists {
			text = v.DefaultText
		}
		sections[v.Name] = text
	}
	raw, _ = canonical(sections)
	if domainSHA("hash:presign-execution-sections:v1", raw) != s.SectionsSHA256 {
		return invalid("admission actual sections")
	}
	if s.InputMode == presign.InputReviewedDocument && actualReviewSHA256(doc) != s.ReviewEvidenceSHA256 {
		return invalid("admission exact actual review record")
	}
	return nil
}

// DecodeDataAdmission is for committed evidence readback. A decoded descriptor
// is not a fresh resolver observation or authorization to consume a grant.
func DecodeDataAdmission(raw []byte) (DataAdmission, error) {
	var s DataAdmissionSnapshot
	if err := strictDecode(raw, &s, presign.MaxSnapshotBytes); err != nil {
		return DataAdmission{}, err
	}
	a, err := newDataAdmission(s)
	if err != nil || !bytes.Equal(raw, a.canonical) {
		return DataAdmission{}, invalid("canonical admission evidence")
	}
	return a, nil
}

// ValidateDataAdmissionForExecution binds immutable evidence. Live locks,
// source re-evaluation and original-credential/deadline checks are still required
// for a fresh use; committed recovery must not perform a new grant admission.
func ValidateDataAdmissionForExecution(a DataAdmission, p presign.Policy, g presign.Grant, doc presign.DocumentSnapshot) error {
	decoded, err := DecodeDataAdmission(a.CanonicalJSON())
	if err != nil || decoded.Commitment() != a.Commitment() {
		return invalid("data admission integrity")
	}
	s, ps, gs := a.Snapshot(), p.Snapshot(), g.Snapshot()
	raw, _ := canonical(gs.Grantor)
	if ps.OrgID != doc.OrgID || gs.OrgID != doc.OrgID || gs.Policy != p.Reference() || doc.SenderID != gs.Grantor.UserID ||
		ps.Template.ID != doc.Template.ID || ps.Template.Version != doc.Template.Version || ps.Template.ContentSHA256 != doc.Template.ContentSHA256 || ps.Template.ApprovedBy != doc.Template.ApprovedBy || !ps.Template.ApprovedAt.Equal(doc.Template.ApprovedAt) ||
		s.OrgID != doc.OrgID || s.DocumentID != doc.ID || s.SenderID != doc.SenderID || s.PolicyID != ps.ID || s.WorkflowID != ps.Workflow.ID || s.WorkflowRevision != ps.Workflow.Revision || s.DefinitionSHA256 != ps.Workflow.ContentSHA256 || s.InputMode != ps.Rules.InputMode ||
		s.Template.ID != doc.Template.ID || s.Template.Version != doc.Template.Version || s.Template.ContentSHA256 != doc.Template.ContentSHA256 || s.Template.ApprovedBy != doc.Template.ApprovedBy || !s.Template.ApprovedAt.Equal(doc.Template.ApprovedAt) ||
		s.SourceCommitment != doc.Materialization.SourceCommitment || s.ValuesSHA256 != doc.ValuesSHA256 || s.SectionsSHA256 != doc.SectionsSHA256 || s.ReviewEvidenceSHA256 != doc.ReviewEvidenceSHA256 || a.Commitment() != doc.DataEvidenceSHA256 || s.GrantorSHA256 != domainSHA("hash:presign-execution-grantor:v1", raw) {
		return invalid("execution data admission binding")
	}
	return nil
}
