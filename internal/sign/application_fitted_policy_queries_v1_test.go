// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Real normal-sqlc projection methods and the same policy run over synthetic
// rows. Test-created headers are never SQL/cache/resource/readiness authority.
// Old SELECT* or unscoped policy-list reads are unexpected fixture queries.
type fittedProjectionDBTestV1 struct {
	doc        *generated.Document
	current    *generated.Recipient
	parties    []*generated.Recipient
	fields     []*generated.DocumentField
	controller *generated.DocumentLawfulBasisConfirmation
	org        *generated.Org
	branding   *generated.DocumentBrandingOverride
	unfilled   int64
	calls      []string
}

func projectionObjectTestV1[T any](source any) *T {
	out := new(T)
	dst := reflect.ValueOf(out).Elem()
	src := reflect.ValueOf(source)
	if src.Kind() == reflect.Pointer {
		src = src.Elem()
	}
	for i := 0; i < dst.NumField(); i++ {
		field := dst.Type().Field(i)
		v := src.FieldByName(field.Name)
		if v.IsValid() && v.Type().AssignableTo(dst.Field(i).Type()) {
			dst.Field(i).Set(v)
		}
	}
	return out
}
func (d *fittedProjectionDBTestV1) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected projection fixture mutation")
}
func (d *fittedProjectionDBTestV1) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	name := strings.SplitN(sql, "\n", 2)[0]
	d.calls = append(d.calls, name)
	switch {
	case strings.Contains(name, "-- name: ReadSignatureFitPolicyDocumentV1 "):
		return presentedCredentialTestRowV1{object: projectionObjectTestV1[generated.ReadSignatureFitPolicyDocumentV1Row](d.doc)}
	case strings.Contains(name, "-- name: ReadSignatureFitPolicyRecipientV1 "):
		return presentedCredentialTestRowV1{object: projectionObjectTestV1[generated.ReadSignatureFitPolicyRecipientV1Row](d.current)}
	case strings.Contains(name, "-- name: ReadSignatureFitPolicyControllerV1 "):
		return presentedCredentialTestRowV1{object: d.controller}
	case strings.Contains(name, "-- name: ReadSignatureFitPolicyOrgV1 "):
		return presentedCredentialTestRowV1{object: projectionObjectTestV1[generated.ReadSignatureFitPolicyOrgV1Row](d.org)}
	case strings.Contains(name, "-- name: ReadSignatureFitPolicyBrandingV1 "):
		if d.branding == nil {
			return presentedCredentialTestRowV1{err: pgx.ErrNoRows}
		}
		return presentedCredentialTestRowV1{object: projectionObjectTestV1[generated.ReadSignatureFitPolicyBrandingV1Row](d.branding)}
	case strings.Contains(name, "-- name: CountUnfilledRequiredForRecipient "):
		return presentedCredentialTestRowV1{object: &struct{ Count int64 }{d.unfilled}}
	default:
		return presentedCredentialTestRowV1{err: errors.New("unexpected projection fixture read")}
	}
}
func (d *fittedProjectionDBTestV1) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	name := strings.SplitN(sql, "\n", 2)[0]
	d.calls = append(d.calls, name)
	var objects []any
	switch {
	case strings.Contains(name, "-- name: ListSignatureFitPolicyPartiesV1 "):
		for _, r := range d.parties {
			objects = append(objects, projectionObjectTestV1[generated.ListSignatureFitPolicyPartiesV1Row](r))
		}
	case strings.Contains(name, "-- name: ListSignatureFitPolicyFieldsV1 "):
		for _, r := range d.fields {
			row := projectionObjectTestV1[generated.ListSignatureFitPolicyFieldsV1Row](r)
			row.OptionsWireBytes = int64(len(r.OptionsJson))
			objects = append(objects, row)
		}
	default:
		return nil, errors.New("unexpected projection fixture collection")
	}
	return &presentedCredentialTestRowsV1{objects: objects, index: -1}, nil
}

type fittedProjectionFixtureTestV1 struct {
	base    *presentedCredentialTestFixtureV1
	context *RecipientContext
	input   SignInput
	db      *fittedProjectionDBTestV1
	policy  *applicationFittedPolicyQueriesV1
}

func newFittedProjectionFixtureTestV1(t *testing.T) *fittedProjectionFixtureTestV1 {
	t.Helper()
	f := newPresentedCredentialTestFixtureV1(t)
	_, doc, parties := testfixture.BrandedHTMLContract(t)
	doc.Status = "sent"
	doc.LawfulBasis = "contract"
	doc.SigningAdmissionPolicy = "pdf-static-v1"
	doc.SentAt = f.db.document.SentAt
	doc.ExpiresAt = f.db.document.ExpiresAt
	doc.Article13NoticeEpochAt = doc.SentAt
	doc.Article13NoticeSchema = f.db.document.Article13NoticeSchema
	doc.Article13NoticeEpochV61Committed = true
	admissionID := uuid.New()
	doc.SigningAdmissionActiveID = pgtype.UUID{Bytes: admissionID, Valid: true}
	chosen := parties[1]
	old := f.db.recipient
	f.db.recipient = &generated.GetRecipientByTokenHashRow{ID: chosen.ID, DocumentID: doc.ID, DocOrgID: doc.OrgID, DocStatus: doc.Status, Role: chosen.Role, Status: chosen.Status, Name: chosen.Name, Email: chosen.Email, MagicTokenHash: bytes.Clone(f.digest), MagicTokenExpiresAt: old.MagicTokenExpiresAt, SentAt: doc.SentAt}
	f.db.document = doc
	f.db.org.ID = doc.OrgID
	f.db.confirmation.DocumentID = doc.ID
	f.db.confirmation.OrgID = doc.OrgID
	rc := f.lookup(t)
	in := presentedCredentialTestInputV1(t, rc)
	currentDoc := *doc
	current := presentedFreshRecipientTestV1(rc)
	current.Name = chosen.Name
	current.Email = chosen.Email
	fields := testfixture.BrandedSignatureFields(t, doc)
	brand := testfixture.BrandedSigningPolicy().Branding
	txt := func(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }
	branding := &generated.DocumentBrandingOverride{DocumentID: doc.ID, PrimaryHex: txt(brand.PrimaryHex), AccentHex: txt(brand.AccentHex), SurfaceHex: txt(brand.SurfaceHex), TextHex: txt(brand.TextHex), MutedHex: txt(brand.MutedHex), LogoUrl: txt(brand.LogoURL), LogoAlt: txt(brand.LogoAlt), FontHeading: txt(brand.FontHeading), FontBody: txt(brand.FontBody), SignatureColor: txt(brand.SignatureColor)}
	db := &fittedProjectionDBTestV1{doc: &currentDoc, current: current, parties: parties, fields: fields, controller: f.db.confirmation, org: f.db.org, branding: branding}
	q := &applicationFittedPolicyQueriesV1{queries: generated.New(db), key: applicationRequestKeyV1{doc.OrgID, doc.ID, current.ID}, admissionID: admissionID}
	q.contextHeader = generated.GetSignatureFitRequestScopeHeaderV1Row{DocumentNameBytes: int64(len(doc.Name)), LawfulBasisBytes: int64(len(doc.LawfulBasis)), ControllerNameBytes: int64(len(db.controller.ControllerName)), ControllerContactBytes: int64(len(db.controller.ControllerContact)), ConfirmationBasisBytes: int64(len(db.controller.LawfulBasis)), ConfirmationViaBytes: int64(len(db.controller.Via)), ControllerOrgNameBytes: int64(len(db.org.Name))}
	out := &fittedProjectionFixtureTestV1{base: f, context: rc, input: in, db: db, policy: q}
	out.refreshHeaderV1()
	return out
}
func (f *fittedProjectionFixtureTestV1) refreshHeaderV1() {
	d := f.db.doc
	f.policy.header = generated.GetSignatureFitHTMLPolicySizeHeaderV1Row{DocumentID: d.ID, OrgID: d.OrgID, AdmissionID: pgtype.UUID{Bytes: f.policy.admissionID, Valid: true}, HasHtmlSource: len(d.HtmlSourceJson) > 0, HasCurrentHtmlSource: len(d.HtmlCurrentSourceJson) > 0, HtmlOriginWireBytes: int64(len(d.HtmlSourceJson)), HtmlCurrentWireBytes: int64(len(d.HtmlCurrentSourceJson)), VariablesWireBytes: int64(len(d.VariablesJson)), PartyCount: int64(len(f.db.parties)), FieldCount: int64(len(f.db.fields))}
	if f.db.branding != nil {
		f.policy.header.BrandingCount = 1
	}
	for _, r := range f.db.fields {
		f.policy.header.FieldOptionsWireBytes += int64(len(r.OptionsJson))
	}
}
func (f *fittedProjectionFixtureTestV1) validateV1(ctx context.Context) error {
	d, err := f.policy.documentV1(ctx)
	if err != nil {
		return err
	}
	r, err := f.policy.recipientV1(ctx)
	if err != nil {
		return err
	}
	return f.base.engine.validateFittedSigningPolicyQueriesV1(ctx, f.context, f.input, d, r, f.policy)
}
func TestFittedPolicyProjectionV1PreservesCompleteBrandedContract(t *testing.T) {
	f := newFittedProjectionFixtureTestV1(t)
	if err := f.validateV1(context.Background()); err != nil {
		t.Fatal("complete projected contract refused", err)
	}
	names := strings.Join(f.db.calls, "\n")
	for _, want := range []string{"ReadSignatureFitPolicyDocumentV1", "ReadSignatureFitPolicyRecipientV1", "ReadSignatureFitPolicyControllerV1", "ReadSignatureFitPolicyOrgV1", "ListSignatureFitPolicyPartiesV1", "ListSignatureFitPolicyFieldsV1", "ReadSignatureFitPolicyBrandingV1", "CountUnfilledRequiredForRecipient"} {
		if !strings.Contains(names, want) {
			t.Fatal("complete policy omitted required projection", want)
		}
	}
	for _, forbidden := range []string{"-- name: GetDocument ", "-- name: ListRecipientsByDocument ", "-- name: ListFieldsByDocument ", "-- name: GetOrg "} {
		if strings.Contains(names, forbidden) {
			t.Fatal("minimal projected policy used broad query", forbidden)
		}
	}
}
func TestFittedPolicyProjectionV1RejectsHTMLAndPartyDrift(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fittedProjectionFixtureTestV1)
	}{
		{"unreviewed variables", func(f *fittedProjectionFixtureTestV1) { f.db.doc.VariablesJson = json.RawMessage(`{"price":"1"}`) }},
		{"malformed master", func(f *fittedProjectionFixtureTestV1) {
			var s map[string]json.RawMessage
			_ = json.Unmarshal(f.db.doc.HtmlSourceJson, &s)
			s["master"] = json.RawMessage(`{}`)
			f.db.doc.HtmlSourceJson, _ = json.Marshal(s)
		}},
		{"orphan current materialization", func(f *fittedProjectionFixtureTestV1) {
			f.db.doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		}},
		{"corrupt explicit current source", func(f *fittedProjectionFixtureTestV1) {
			f.db.doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
			f.db.doc.HtmlCurrentSourceJson = json.RawMessage(`{}`)
			f.db.doc.HtmlCurrentPageCount = pgtype.Int4{Int32: 2, Valid: true}
			f.db.doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 2, Valid: true}
		}},
		{"wrong exact PDF version", func(f *fittedProjectionFixtureTestV1) { f.db.doc.PdfStorageVersionID.String += "-different" }},
		{"removed provider and field", func(f *fittedProjectionFixtureTestV1) {
			f.db.parties = f.db.parties[1:]
			kept := f.db.fields[:0]
			for _, r := range f.db.fields {
				if uuid.UUID(r.RecipientID.Bytes) == f.db.current.ID {
					kept = append(kept, r)
				}
			}
			f.db.fields = kept
		}},
		{"different intended identity", func(f *fittedProjectionFixtureTestV1) { f.db.parties[0].Name = "Changed representative" }},
		{"different intended email", func(f *fittedProjectionFixtureTestV1) { f.db.parties[0].Email = "changed@example.test" }},
		{"different intended UUID", func(f *fittedProjectionFixtureTestV1) { f.db.parties[0].ID = uuid.New() }},
		{"different role", func(f *fittedProjectionFixtureTestV1) { f.db.parties[0].Role = "signer" }},
		{"optional signature", func(f *fittedProjectionFixtureTestV1) { f.db.fields[0].Required = false }},
		{"changed signing rectangle", func(f *fittedProjectionFixtureTestV1) { f.db.fields[0].Page = 1 }},
		{"changed signing options", func(f *fittedProjectionFixtureTestV1) { f.db.fields[0].OptionsJson = json.RawMessage(`{}`) }},
		{"changed branding", func(f *fittedProjectionFixtureTestV1) { f.db.branding.FontBody.String = "Changed font" }},
		{"missing branding", func(f *fittedProjectionFixtureTestV1) { f.db.branding = nil }},
		{"unfilled required field", func(f *fittedProjectionFixtureTestV1) { f.db.unfilled = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFittedProjectionFixtureTestV1(t)
			if err := f.validateV1(context.Background()); err != nil {
				t.Fatal("invalid baseline", err)
			}
			tc.mutate(f)
			f.refreshHeaderV1()
			if err := f.validateV1(context.Background()); err == nil {
				t.Fatal("projected policy accepted changed contract")
			}
		})
	}
}
func TestFittedPolicyProjectionV1RejectsForeignScopeBeforeQuery(t *testing.T) {
	f := newFittedProjectionFixtureTestV1(t)
	_, err := f.policy.ListRecipientsByDocument(context.Background(), uuid.New())
	if err == nil || len(f.db.calls) != 0 {
		t.Fatal("foreign document reached projected SQL")
	}
	_, err = f.policy.GetOrg(context.Background(), uuid.New())
	if err == nil || len(f.db.calls) != 0 {
		t.Fatal("foreign org reached projected SQL")
	}
	_, err = f.policy.GetDocumentLawfulBasisConfirmation(context.Background(), generated.GetDocumentLawfulBasisConfirmationParams{DocumentID: f.db.doc.ID, OrgID: uuid.New()})
	if err == nil || len(f.db.calls) != 0 {
		t.Fatal("foreign controller reached projected SQL")
	}
	_, err = f.policy.CountUnfilledRequiredForRecipient(context.Background(), generated.CountUnfilledRequiredForRecipientParams{DocumentID: f.db.doc.ID, RecipientID: pgtype.UUID{Bytes: uuid.New(), Valid: true}})
	if err == nil || len(f.db.calls) != 0 {
		t.Fatal("foreign recipient reached projected SQL")
	}
	var nilQueries *generated.Queries
	if !signerRoleQueriesNilV1(nilQueries) {
		t.Fatal("shared policy lost typed-nil generated-query refusal")
	}
}

func TestApplicationRequestPolicyHeaderV1RejectsUnboundSizeAndScope(t *testing.T) {
	key := applicationRequestKeyV1{uuid.New(), uuid.New(), uuid.New()}
	admissionID := uuid.New()
	base := generated.GetSignatureFitHTMLPolicySizeHeaderV1Row{DocumentID: key.document, OrgID: key.org, AdmissionID: pgtype.UUID{Bytes: admissionID, Valid: true}, HasHtmlSource: true, HtmlOriginWireBytes: 100, VariablesWireBytes: 20, PartyCount: 2, FieldCount: 2, BrandingCount: 1, ProjectedTextBytes: 300, FieldOptionsWireBytes: 400, PolicyBytes: 100 + 20 + 300 + 400 + 4096*6}
	if got, err := applicationRequestPolicyHeaderV1(&base, key, admissionID); err != nil || got != base.PolicyBytes {
		t.Fatal("exact header refused", got, err)
	}
	cases := []struct {
		name   string
		mutate func(*generated.GetSignatureFitHTMLPolicySizeHeaderV1Row)
	}{
		{"foreign org", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.OrgID = uuid.New() }},
		{"foreign document", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.DocumentID = uuid.New() }},
		{"missing admission", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.AdmissionID.Valid = false }},
		{"foreign admission", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.AdmissionID.Bytes = uuid.New() }},
		{"missing origin declaration", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.HasHtmlSource = false }},
		{"negative variable length", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.VariablesWireBytes = -1 }},
		{"absent parties", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.PartyCount = 0 }},
		{"too many parties", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.PartyCount = 101 }},
		{"absent fields", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.FieldCount = 0 }},
		{"too many fields", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.FieldCount = 1001 }},
		{"too many brands", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.BrandingCount = 2 }},
		{"unbound logical sum", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.PolicyBytes-- }},
		{"overflow", func(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row) { h.ProjectedTextBytes = int64(1<<63 - 1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := base
			tc.mutate(&b)
			if _, err := applicationRequestPolicyHeaderV1(&b, key, admissionID); err == nil {
				t.Fatal("unbound header admitted")
			}
		})
	}
}
