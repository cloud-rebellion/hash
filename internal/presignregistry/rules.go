// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
)

var declaredName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func invalid(path string) error                  { return fmt.Errorf("%w: %s", ErrInvalid, path) }
func sha(raw []byte) string                      { v := sha256.Sum256(raw); return hex.EncodeToString(v[:]) }
func domainSHA(domain string, raw []byte) string { return sha(append([]byte(domain+"\x00"), raw...)) }
func validSHA(v string) bool {
	raw, err := hex.DecodeString(v)
	return err == nil && len(raw) == 32 && v == strings.ToLower(v)
}
func visible(v string, maxRunes int) bool {
	if v == "" || strings.TrimSpace(v) != v || !utf8.ValidString(v) || utf8.RuneCountInString(v) > maxRunes || len(v) > maxRunes*4 {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// DecodeDefinition rejects ambiguous JSON and exact-case aliases before normal
// Go decoding, whose field matching alone is case-insensitive.
func DecodeDefinition(raw []byte) (WorkflowDefinition, error) {
	var d WorkflowDefinition
	if err := strictDecode(raw, &d, MaxDefinitionBytes); err != nil {
		return d, err
	}
	if err := ValidateDefinition(d); err != nil {
		return WorkflowDefinition{}, err
	}
	return d, nil
}

func strictDecode(raw []byte, out any, max int) error {
	if len(raw) == 0 || len(raw) > max || sourcejson.Validate(raw) != nil {
		return invalid("JSON shape or bounds")
	}
	var value any
	if json.Unmarshal(raw, &value) != nil || checkShape(value, reflect.TypeOf(out).Elem()) != nil {
		return invalid("exact JSON keys, presence or null")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return invalid("JSON types")
	}
	return nil
}

func checkShape(v any, t reflect.Type) error {
	if v == nil {
		return ErrInvalid
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Time{}) {
		if _, ok := v.(string); !ok {
			return ErrInvalid
		}
		return nil
	}
	if t == reflect.TypeOf(uuid.UUID{}) {
		s, ok := v.(string)
		id, err := uuid.Parse(s)
		if !ok || err != nil || id.String() != s {
			return ErrInvalid
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			parts := strings.Split(f.Tag.Get("json"), ",")
			if parts[0] != "" && parts[0] != "-" {
				fields[parts[0]] = f
				if len(parts) == 1 {
					if _, ok := m[parts[0]]; !ok {
						return ErrInvalid
					}
				}
			}
		}
		for key, value := range m {
			f, ok := fields[key]
			if !ok || checkShape(value, f.Type) != nil {
				return ErrInvalid
			}
			if strings.Contains(f.Tag.Get("json"), ",string") {
				s, ok := value.(string)
				n, err := strconv.ParseInt(s, 10, 64)
				if !ok || err != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
					return ErrInvalid
				}
			}
		}
	case reflect.Slice, reflect.Array:
		a, ok := v.([]any)
		if !ok {
			return ErrInvalid
		}
		for _, x := range a {
			if checkShape(x, t.Elem()) != nil {
				return ErrInvalid
			}
		}
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		for _, x := range m {
			if checkShape(x, t.Elem()) != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}

func ValidateDefinition(d WorkflowDefinition) error {
	if d.Version != DefinitionVersion || d.ID == uuid.Nil || d.PolicyID == uuid.Nil || d.OrgID == uuid.Nil || d.Revision < 1 || d.Revision > presign.MaxRevision || !visible(d.Name, 200) || d.Operation != presign.OperationPreSignAndSend {
		return invalid("workflow identity or operation")
	}
	if d.Kind != KindReviewedDocument && d.Kind != KindApprovedData {
		return invalid("recognized workflow kind")
	}
	if d.Template.ID == uuid.Nil || d.Template.Version < 1 || d.Template.Version > presign.MaxRevision || !validSHA(d.Template.ContentSHA256) || d.Template.ApprovedBy == uuid.Nil || d.Template.ApprovedAt.IsZero() {
		return invalid("selected approved template")
	}
	if d.Executor.UserID == uuid.Nil || (d.Executor.Kind != presign.ExecutorMember && d.Executor.Kind != presign.ExecutorAPIKey) || (d.Executor.Kind == presign.ExecutorMember && d.Executor.CredentialID != uuid.Nil) || (d.Executor.Kind == presign.ExecutorAPIKey && d.Executor.CredentialID == uuid.Nil) {
		return invalid("actual executor identity")
	}
	if d.MaxGrantDurationSeconds < 1 || d.MaxGrantDurationSeconds > int64(presign.MaxGrantDuration/time.Second) || d.MaxUses < 1 || d.MaxUses > presign.MaxRecordedUses {
		return invalid("finite policy caps")
	}
	i := d.InputRules
	if i.Version != 1 || i.SourceSchemaVersion != 3 || !i.Standalone || !i.SignatureFieldsOnly || !i.AuthorMustBeGrantor {
		return invalid("initial source3 execution eligibility")
	}
	r := d.RecipientRules
	if r.Version != 1 || r.Provider != "named_grantor_exact" || r.Customer != "printed_profile_exact" || r.Mode != "parallel" || !visible(r.ProviderCompanyName, 200) || !visible(r.ProviderCompanyID, 100) || !visible(r.ProviderAuthorityBasis, 500) {
		return invalid("recipient and provider company rules")
	}
	if d.DataRules.Version != 1 || d.DataRules.Values == nil || d.DataRules.Sections == nil || len(d.DataRules.Values) > 64 || len(d.DataRules.Sections) > 64 {
		return invalid("bounded complete data rules")
	}
	seen := map[string]bool{}
	usesCRM := false
	for _, v := range d.DataRules.Values {
		if !declaredName.MatchString(v.Variable) || seen[v.Variable] {
			return invalid("unique declared value rules")
		}
		seen[v.Variable] = true
		if v.Mode != ModeLiteral && v.Literal != nil || v.Mode != ModeGrantor && v.GrantorField != "" || v.Mode != ModeCRM && (v.SourceKind != "" || v.SourcePath != "") {
			return invalid("mode-specific value rule")
		}
		switch v.Mode {
		case ModeReviewedValue:
			if d.Kind != KindReviewedDocument {
				return invalid("manual values require human-reviewed workflow")
			}
		case ModeDefault, ModeAbsent:
		case ModeLiteral:
			if v.Literal == nil || !utf8.ValidString(*v.Literal) || strings.ContainsRune(*v.Literal, 0) || utf8.RuneCountInString(*v.Literal) > htmlmaster.MaxValueChars {
				return invalid("bounded explicit literal")
			}
		case ModeGrantor:
			if v.GrantorField != "name" && v.GrantorField != "email" && v.GrantorField != "company_name" && v.GrantorField != "company_id" && v.GrantorField != "authority_basis" {
				return invalid("named grantor field")
			}
		case ModeCRM:
			usesCRM = true
			found := false
			for _, f := range crmconnection.Catalog(crmconnection.RecordKind(v.SourceKind)) {
				if f.Path == v.SourcePath {
					found = true
				}
			}
			if !found {
				return invalid("source-native CRM scalar catalog")
			}
		default:
			return invalid("recognized value rule")
		}
	}
	seen = map[string]bool{}
	for _, s := range d.DataRules.Sections {
		if !declaredName.MatchString(s.Section) || seen[s.Section] {
			return invalid("unique declared section rules")
		}
		seen[s.Section] = true
		if s.Mode != ModeLiteral && s.Literal != nil {
			return invalid("section literal mode")
		}
		switch s.Mode {
		case ModeReviewedValue:
			if d.Kind != KindReviewedDocument {
				return invalid("new prose requires human review")
			}
		case ModeDefault:
		case ModeLiteral:
			if s.Literal == nil || !utf8.ValidString(*s.Literal) || strings.ContainsRune(*s.Literal, 0) || utf8.RuneCountInString(*s.Literal) > htmlmaster.MaxSectionChars {
				return invalid("bounded approved section literal")
			}
		default:
			return invalid("recognized approved section rule")
		}
	}
	if usesCRM != (d.DataRules.CRM != nil) {
		return invalid("explicit CRM scope")
	}
	if c := d.DataRules.CRM; c != nil {
		identity := crmconnection.Identity{ID: c.ConnectionID, OrgID: d.OrgID, Generation: c.Generation, Origin: c.Origin, CRMTeamID: c.TeamID, CRMUserID: c.UserID}
		if crmconnection.ValidateIdentity(identity) != nil || (c.Selection != "fixed_record_set" && c.Selection != "execution_record_set") || len(c.Records) < 1 || len(c.Records) > 3 {
			return invalid("bounded actual CRM account and record selection")
		}
		kinds := map[string]bool{}
		for _, r := range c.Records {
			id := r.ID
			if c.Selection == "execution_record_set" {
				if id != "" {
					return invalid("execution selection cannot pretend fixed record")
				}
				id = "checked_at_execution"
			}
			if kinds[r.Kind] || crmconnection.ValidateRecordRef(crmconnection.RecordRef{Kind: crmconnection.RecordKind(r.Kind), ID: id}) != nil {
				return invalid("unique native CRM record kinds")
			}
			kinds[r.Kind] = true
		}
		for _, v := range d.DataRules.Values {
			if v.Mode == ModeCRM && !kinds[v.SourceKind] {
				return invalid("CRM mapping without selected kind")
			}
		}
	}
	raw, err := canonical(d)
	if err != nil || len(raw) > MaxDefinitionBytes {
		return invalid("workflow definition bound")
	}
	return nil
}

// CanonicalDefinition returns independent canonical bytes and purpose-separated
// rule commitments. It does not approve the definition or prove live authority.
func CanonicalDefinition(d WorkflowDefinition) ([]byte, string, presign.RulesSnapshot, error) {
	if err := ValidateDefinition(d); err != nil {
		return nil, "", presign.RulesSnapshot{}, err
	}
	d.DataRules.Values = append([]ValueRule{}, d.DataRules.Values...)
	d.DataRules.Sections = append([]SectionRule{}, d.DataRules.Sections...)
	sort.Slice(d.DataRules.Values, func(i, j int) bool { return d.DataRules.Values[i].Variable < d.DataRules.Values[j].Variable })
	sort.Slice(d.DataRules.Sections, func(i, j int) bool { return d.DataRules.Sections[i].Section < d.DataRules.Sections[j].Section })
	if d.DataRules.CRM != nil {
		c := *d.DataRules.CRM
		c.Records = append([]RecordRule(nil), c.Records...)
		sort.Slice(c.Records, func(i, j int) bool { return c.Records[i].Kind < c.Records[j].Kind })
		d.DataRules.CRM = &c
	}
	raw, _ := canonical(d)
	a, _ := canonical(d.InputRules)
	b, _ := canonical(d.DataRules)
	c, _ := canonical(d.RecipientRules)
	mode := presign.InputReviewedDocument
	if d.Kind == KindApprovedData {
		mode = presign.InputApprovedData
	}
	rules := presign.RulesSnapshot{InputMode: mode, InputRulesSHA256: domainSHA("hash:presign-input-rules:v1", a), DataRulesSHA256: domainSHA("hash:presign-data-rules:v1", b), RecipientRulesSHA256: domainSHA("hash:presign-recipient-rules:v1", c)}
	return raw, domainSHA("hash:presign-workflow:v1", raw), rules, nil
}

// ValidateDefinitionAgainstTemplate requires one explicit rule per declaration.
// It does not materialize unknown future CRM values or claim a PDF was reviewed.
func ValidateDefinitionAgainstTemplate(d WorkflowDefinition, masterJSON, defaultsJSON []byte) error {
	if err := ValidateDefinition(d); err != nil {
		return err
	}
	pin, err := htmlmaster.CanonicalTemplate(masterJSON, defaultsJSON)
	if err != nil || pin.SHA256 != d.Template.ContentSHA256 {
		return invalid("exact template content")
	}
	m, err := htmlmaster.Decode(pin.MasterJSON)
	if err != nil || m.SchemaVersion != 3 || m.ContractProfile == nil || m.SigningPage == nil {
		return invalid("approved source3 contract master")
	}
	if _, err := htmlmaster.Compile(m); err != nil {
		return invalid("compiled approved master")
	}
	var defaults map[string]string
	if json.Unmarshal(pin.DefaultsJSON, &defaults) != nil {
		return invalid("template defaults")
	}
	vs := map[string]ValueRule{}
	for _, v := range d.DataRules.Values {
		vs[v.Variable] = v
	}
	ss := map[string]SectionRule{}
	for _, s := range d.DataRules.Sections {
		ss[s.Section] = s
	}
	if len(vs) != len(m.Values) || len(ss) != len(m.Sections) {
		return invalid("complete declaration rule coverage")
	}
	for _, v := range m.Values {
		r, ok := vs[v.Name]
		if !ok {
			return invalid("undeclared or missing variable rule")
		}
		if r.Mode == ModeAbsent && v.Required {
			return invalid("required variable cannot be absent")
		}
		if r.Mode == ModeLiteral && (utf8.RuneCountInString(*r.Literal) > v.MaxChars || v.Required && strings.TrimSpace(*r.Literal) == "") {
			return invalid("literal variable bound/completeness")
		}
		if r.Mode == ModeDefault {
			value, present := defaults[v.Name]
			if !present || v.Required && strings.TrimSpace(value) == "" {
				return invalid("approved default presence/completeness")
			}
		}
	}
	for _, s := range m.Sections {
		r, ok := ss[s.Name]
		if !ok {
			return invalid("undeclared or missing section rule")
		}
		if r.Mode == ModeLiteral && utf8.RuneCountInString(*r.Literal) > s.MaxChars {
			return invalid("literal section bound")
		}
	}
	for _, p := range m.ContractProfile.Parties {
		if p.Slot != "provider" {
			continue
		}
		refs := map[string]string{p.RepresentativeName: "name", p.RepresentativeEmail: "email", p.CompanyName: "company_name", p.CompanyID: "company_id", p.RepresentativeAuthority: "authority_basis"}
		for ref, field := range refs {
			r := vs[ref]
			if r.Mode == ModeGrantor && r.GrantorField != field {
				return invalid("provider grantor field binding")
			}
			if r.Mode == ModeGrantor {
				continue
			}
			if d.Kind == KindApprovedData {
				return invalid("approved-data provider must be named grantor")
			}
		}
	}
	return nil
}
