// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/fitselect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are synthetic SQL rows exercising the real generated lookup boundary.
// They prove private credential-policy behavior, not public runtime/global
// admission, real PostgreSQL or renderer readiness.
type presentedCredentialTestDBV1 struct {
	recipient         *generated.GetRecipientByTokenHashRow
	document          *generated.Document
	org               *generated.Org
	confirmation      *generated.DocumentLawfulBasisConfirmation
	calls             int
	beforeQuery       func(string)
	policyCollections bool
}

func (d *presentedCredentialTestDBV1) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	d.calls++
	return pgconn.CommandTag{}, errors.New("unexpected fixture mutation")
}
func (d *presentedCredentialTestDBV1) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	d.calls++
	if !d.policyCollections {
		return nil, errors.New("unexpected fixture collection query")
	}
	name := strings.SplitN(query, "\n", 2)[0]
	switch {
	case strings.Contains(name, "-- name: ListRecipientsByDocument "):
		return &presentedCredentialTestRowsV1{objects: []any{d.freshRecipientV1()}, index: -1}, nil
	case strings.Contains(name, "-- name: ListFieldsByDocument "):
		n := func(value int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(value), Valid: true} }
		field := &generated.DocumentField{ID: uuid.New(), DocumentID: d.document.ID, RecipientID: pgtype.UUID{Bytes: d.recipient.ID, Valid: true}, Type: "signature", Page: 1, XPct: n(10), YPct: n(10), WPct: n(50), HPct: n(10), Required: true}
		return &presentedCredentialTestRowsV1{objects: []any{field}, index: -1}, nil
	default:
		return nil, errors.New("unexpected fixture collection query")
	}
}
func (d *presentedCredentialTestDBV1) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	d.calls++
	name := strings.SplitN(query, "\n", 2)[0]
	if d.beforeQuery != nil {
		d.beforeQuery(name)
	}
	switch {
	case strings.Contains(name, "-- name: GetRecipientByTokenHash "):
		return presentedCredentialTestRowV1{object: d.recipient}
	case strings.Contains(name, "-- name: GetRecipient "):
		return presentedCredentialTestRowV1{object: d.freshRecipientV1()}
	case strings.Contains(name, "-- name: GetDocument "):
		return presentedCredentialTestRowV1{object: d.document}
	case strings.Contains(name, "-- name: GetDocumentLawfulBasisConfirmation "):
		return presentedCredentialTestRowV1{object: d.confirmation}
	case strings.Contains(name, "-- name: GetOrg "):
		return presentedCredentialTestRowV1{object: d.org}
	case d.policyCollections && strings.Contains(name, "-- name: CountUnfilledRequiredForRecipient "):
		return presentedCredentialTestRowV1{object: &struct{ Count int64 }{}}
	default:
		return presentedCredentialTestRowV1{err: errors.New("unexpected fixture lookup")}
	}
}
func (d *presentedCredentialTestDBV1) freshRecipientV1() *generated.Recipient {
	r := d.recipient
	return &generated.Recipient{ID: r.ID, DocumentID: r.DocumentID, Role: r.Role, Email: r.Email, Name: r.Name, OrderIndex: r.OrderIndex, Status: r.Status, MagicTokenHash: r.MagicTokenHash, SentAt: r.SentAt, FirstViewedAt: r.FirstViewedAt, SignedAt: r.SignedAt, DeclinedReason: r.DeclinedReason, CreatedAt: r.CreatedAt, MagicTokenExpiresAt: r.MagicTokenExpiresAt, Locale: r.Locale}
}

type presentedCredentialTestRowsV1 struct {
	objects []any
	index   int
	closed  bool
}

func (r *presentedCredentialTestRowsV1) Close()                                       { r.closed = true }
func (r *presentedCredentialTestRowsV1) Err() error                                   { return nil }
func (r *presentedCredentialTestRowsV1) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *presentedCredentialTestRowsV1) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *presentedCredentialTestRowsV1) Next() bool {
	if r.closed {
		return false
	}
	r.index++
	return r.index < len(r.objects)
}
func (r *presentedCredentialTestRowsV1) Scan(dest ...any) error {
	if r.index < 0 || r.index >= len(r.objects) {
		return errors.New("fixture row unavailable")
	}
	return (presentedCredentialTestRowV1{object: r.objects[r.index]}).Scan(dest...)
}
func (r *presentedCredentialTestRowsV1) Values() ([]any, error) {
	return nil, errors.New("unexpected fixture Values")
}
func (r *presentedCredentialTestRowsV1) RawValues() [][]byte { return nil }
func (r *presentedCredentialTestRowsV1) Conn() *pgx.Conn     { return nil }

type presentedCredentialTestRowV1 struct {
	object any
	err    error
}

func (r presentedCredentialTestRowV1) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	value := reflect.ValueOf(r.object)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return pgx.ErrNoRows
	}
	value = value.Elem()
	if value.Kind() != reflect.Struct || value.NumField() != len(dest) {
		return errors.New("fixture scan column count mismatch")
	}
	for i, target := range dest {
		out := reflect.ValueOf(target)
		if out.Kind() != reflect.Pointer || out.IsNil() || !value.Field(i).Type().AssignableTo(out.Elem().Type()) {
			return errors.New("fixture scan type mismatch")
		}
		out.Elem().Set(value.Field(i))
	}
	return nil
}

type presentedCredentialTestFixtureV1 struct {
	engine *Engine
	db     *presentedCredentialTestDBV1
	now    time.Time
	digest []byte
}

func newPresentedCredentialTestFixtureV1(t *testing.T) *presentedCredentialTestFixtureV1 {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	epoch := pgtype.Timestamptz{Time: now.Add(-time.Hour), Valid: true}
	expires := pgtype.Timestamptz{Time: now.Add(time.Minute), Valid: true}
	orgID, documentID, recipientID := uuid.New(), uuid.New(), uuid.New()
	hash := sha256.Sum256([]byte("synthetic presented credential"))
	d := &presentedCredentialTestDBV1{
		recipient: &generated.GetRecipientByTokenHashRow{ID: recipientID, DocumentID: documentID, DocOrgID: orgID, DocStatus: "sent", Role: "signer", Status: "sent", Name: "Signer", Email: "signer@example.test", Locale: "en", MagicTokenHash: bytes.Clone(hash[:]), MagicTokenExpiresAt: expires, SentAt: epoch},
		document: &generated.Document{ID: documentID, OrgID: orgID, Name: "Frozen agreement", Status: "sent", SourceKind: "pdf", RequiresSignature: true, RoutingTier: "SES", LawfulBasis: "contract", SentAt: epoch, ExpiresAt: expires,
			Article13NoticeEpochAt: epoch, Article13NoticeSchema: article13.Schema, Article13NoticeEpochV61Committed: true, SigningAdmissionPolicy: "pdf-static-v1"},
		org:          &generated.Org{ID: orgID, Name: "Example controller", Plan: "pro"},
		confirmation: &generated.DocumentLawfulBasisConfirmation{OrgID: orgID, DocumentID: documentID, LawfulBasis: "contract", ConfirmedAt: epoch, ControllerName: "Example controller", ControllerContact: "controller@example.test", Via: "rest"},
	}
	f := &presentedCredentialTestFixtureV1{db: d, now: now, digest: bytes.Clone(hash[:])}
	f.engine = &Engine{Queries: generated.New(d), Now: func() time.Time { return f.now }}
	return f
}
func (f *presentedCredentialTestFixtureV1) lookup(t *testing.T) *RecipientContext {
	t.Helper()
	rc, err := f.engine.lookupByTokenQueriesV1(context.Background(), f.digest, f.engine.Queries)
	if err != nil {
		t.Fatal(err)
	}
	return rc
}
func presentedCredentialTestInputV1(t *testing.T, rc *RecipientContext) SignInput {
	t.Helper()
	legal, err := article13.LegalBasisDisclosureV1(rc.Document.LawfulBasis)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := article13.NewSnapshotForSchema(rc.Document.Article13NoticeSchema, article13.Input{
		OrgID: rc.Document.OrgID, DocumentID: rc.Document.ID, RecipientID: rc.Recipient.ID, SentAt: rc.Document.SentAt.Time,
		Controller: strings.TrimSpace(rc.LawfulBasisConfirmation.ControllerName), ControllerContact: strings.TrimSpace(rc.LawfulBasisConfirmation.ControllerContact),
		Processor: "Synthetic Hash operator", ProcessorContact: "privacy@operator.example", PurposeSummary: article13.PurposeSummaryV1(rc.Document.Name),
		LegalBasisDisclosure: legal, RetentionYears: article13.RetentionYearsV1, SupervisoryAuthority: "Synthetic authority", PolicyURL: "https://operator.example/privacy",
		DSRCapability: article13.DSRCapabilitySignerRequest, Copy: article13.RenderedCopyV1(rc.Document.Name),
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := article13.NewEvidence(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return SignInput{TypedName: "Submitted signer", Font: "Caveat", Notice: evidence}
}
func presentedFreshRecipientTestV1(rc *RecipientContext) *generated.Recipient {
	return &generated.Recipient{ID: rc.Recipient.ID, DocumentID: rc.Recipient.DocumentID, Role: rc.Recipient.Role, Status: rc.Recipient.Status,
		MagicTokenHash: bytes.Clone(rc.Recipient.MagicTokenHash), MagicTokenExpiresAt: rc.Recipient.MagicTokenExpiresAt}
}

func TestPresentedLookupV1RejectsWrongDigestAndParentLink(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*presentedCredentialTestFixtureV1)
	}{
		{"short presented digest", func(f *presentedCredentialTestFixtureV1) { f.digest = []byte("short") }},
		{"returned different digest", func(f *presentedCredentialTestFixtureV1) { f.db.recipient.MagicTokenHash[0] ^= 1 }},
		{"missing returned digest", func(f *presentedCredentialTestFixtureV1) { f.db.recipient.MagicTokenHash = nil }},
		{"wrong document", func(f *presentedCredentialTestFixtureV1) { f.db.document.ID = uuid.New() }},
		{"wrong tenant", func(f *presentedCredentialTestFixtureV1) { f.db.document.OrgID = uuid.New() }},
		{"missing recipient identity", func(f *presentedCredentialTestFixtureV1) { f.db.recipient.ID = uuid.Nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			tc.mutate(f)
			if rc, err := f.engine.lookupByTokenQueriesV1(context.Background(), f.digest, f.engine.Queries); err == nil || rc != nil {
				t.Fatal("invalid presented lookup succeeded")
			}
		})
	}
}

func TestPresentedLookupV1OwnsDigestAcrossDatabaseWait(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	f.db.beforeQuery = func(name string) {
		if strings.Contains(name, "GetRecipientByTokenHash") {
			f.digest[0] ^= 1
		}
	}
	rc := f.lookup(t)
	doc := *rc.Document
	if err := ValidateLockedRecipientCredential(rc, presentedFreshRecipientTestV1(rc), &doc, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, presentedCredentialTestInputV1(t, rc)); err != nil {
		t.Fatal(err)
	}
}

func TestPresentedSnapshotV1RejectsMutableContextRewrites(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RecipientContext)
	}{
		{"recipient digest", func(rc *RecipientContext) { rc.Recipient.MagicTokenHash[0] ^= 1 }},
		{"recipient deadline", func(rc *RecipientContext) {
			rc.Recipient.MagicTokenExpiresAt.Time = rc.Recipient.MagicTokenExpiresAt.Time.Add(time.Hour)
		}},
		{"document deadline", func(rc *RecipientContext) { rc.Document.ExpiresAt.Time = rc.Document.ExpiresAt.Time.Add(time.Hour) }},
		{"recipient parent", func(rc *RecipientContext) { id := uuid.New(); rc.Document.ID = id; rc.Recipient.DocumentID = id }},
		{"tenant", func(rc *RecipientContext) { rc.Document.OrgID = uuid.New(); rc.Recipient.DocOrgID = rc.Document.OrgID }},
		{"notice epoch", func(rc *RecipientContext) {
			rc.Document.SentAt.Time = rc.Document.SentAt.Time.Add(time.Second)
			rc.Document.Article13NoticeEpochAt = rc.Document.SentAt
		}},
		{"notice schema", func(rc *RecipientContext) { rc.Document.Article13NoticeSchema = "different" }},
		{"notice commitment", func(rc *RecipientContext) { rc.Document.Article13NoticeEpochV61Committed = false }},
		{"document notice purpose", func(rc *RecipientContext) { rc.Document.Name = "Changed purpose" }},
		{"controller", func(rc *RecipientContext) { rc.LawfulBasisConfirmation.ControllerName = "Different controller" }},
		{"controller contact", func(rc *RecipientContext) { rc.LawfulBasisConfirmation.ControllerContact = "other@example.test" }},
		{"lawful basis", func(rc *RecipientContext) {
			rc.Document.LawfulBasis = "changed"
			rc.LawfulBasisConfirmation.LawfulBasis = "changed"
		}},
		{"controller tenant", func(rc *RecipientContext) { rc.ControllerOrg.ID = uuid.New() }},
		{"controller confirmation", func(rc *RecipientContext) {
			rc.LawfulBasisConfirmation.ConfirmedAt.Time = rc.LawfulBasisConfirmation.ConfirmedAt.Time.Add(time.Second)
		}},
		{"role", func(rc *RecipientContext) { rc.Recipient.Role = "approver" }},
		{"original recipient eligibility", func(rc *RecipientContext) { rc.Recipient.Status = "pending" }},
		{"policy", func(rc *RecipientContext) { rc.Document.SigningAdmissionPolicy = "historical" }},
		{"source kind", func(rc *RecipientContext) { rc.Document.SourceKind = "blocks" }},
		{"tier", func(rc *RecipientContext) { rc.Document.RoutingTier = "AES" }},
		{"signature requirement", func(rc *RecipientContext) { rc.Document.RequiresSignature = false }},
		{"envelope", func(rc *RecipientContext) { rc.Document.IsEnvelope = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc := f.lookup(t)
			in := presentedCredentialTestInputV1(t, rc)
			// Rewrite exported state and the supposed fresh state together. The previous
			// comparison of those two mutable rows would no longer preserve admission.
			tc.mutate(rc)
			doc := *rc.Document
			fresh := presentedFreshRecipientTestV1(rc)
			if err := ValidateLockedRecipientCredential(rc, fresh, &doc, f.now); err == nil {
				t.Fatal("rewritten admission was accepted")
			}
			if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, in); err == nil {
				t.Fatal("rewritten context issued intent")
			}
		})
	}
}

func TestPresentedCredentialV1KeepsOriginalDeadlinesAndRotation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.Recipient, *generated.Document, *presentedCredentialTestFixtureV1)
	}{
		{"fresh token rotation", func(r *generated.Recipient, _ *generated.Document, _ *presentedCredentialTestFixtureV1) {
			r.MagicTokenHash[0] ^= 1
		}},
		{"fresh recipient expired", func(r *generated.Recipient, _ *generated.Document, f *presentedCredentialTestFixtureV1) {
			r.MagicTokenExpiresAt.Time = f.now.Add(-time.Second)
		}},
		{"fresh document expired", func(_ *generated.Recipient, d *generated.Document, f *presentedCredentialTestFixtureV1) {
			d.ExpiresAt.Time = f.now.Add(-time.Second)
		}},
		{"later extension cannot revive original", func(r *generated.Recipient, d *generated.Document, f *presentedCredentialTestFixtureV1) {
			f.now = f.now.Add(2 * time.Minute)
			r.MagicTokenExpiresAt.Time = f.now.Add(time.Hour)
			d.ExpiresAt.Time = f.now.Add(time.Hour)
		}},
		{"fresh notice epoch", func(_ *generated.Recipient, d *generated.Document, _ *presentedCredentialTestFixtureV1) {
			d.SentAt.Time = d.SentAt.Time.Add(time.Second)
			d.Article13NoticeEpochAt = d.SentAt
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc := f.lookup(t)
			fresh := presentedFreshRecipientTestV1(rc)
			doc := *rc.Document
			if err := ValidateLockedRecipientCredential(rc, fresh, &doc, f.now); err != nil {
				t.Fatal(err)
			}
			tc.mutate(fresh, &doc, f)
			if err := ValidateLockedRecipientCredential(rc, fresh, &doc, f.now); err == nil {
				t.Fatal("stale admitted credential was accepted")
			}
		})
	}
}

func TestFittedIntentV1RequiresPresentedIssuerAndFrozenNotice(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *presentedCredentialTestFixtureV1, **RecipientContext, *SignInput)
	}{
		{"forged exported context", func(_ *testing.T, _ *presentedCredentialTestFixtureV1, rc **RecipientContext, _ *SignInput) {
			old := *rc
			*rc = &RecipientContext{Recipient: old.Recipient, Document: old.Document, ControllerOrg: old.ControllerOrg, LawfulBasisConfirmation: old.LawfulBasisConfirmation}
		}},
		{"different engine", func(t *testing.T, f *presentedCredentialTestFixtureV1, _ **RecipientContext, _ *SignInput) {
			// A distinct issuer keeps the same fixture dependencies without
			// copying the Engine's synchronization or retained journal lifetime.
			f.engine = &Engine{Queries: f.engine.Queries, Now: f.engine.Now}
		}},
		{"unsupported font", func(_ *testing.T, _ *presentedCredentialTestFixtureV1, _ **RecipientContext, in *SignInput) {
			in.Font = "external font"
		}},
		{"invalid typed name", func(_ *testing.T, _ *presentedCredentialTestFixtureV1, _ **RecipientContext, in *SignInput) {
			in.TypedName = ""
		}},
		{"different notice controller", func(_ *testing.T, _ *presentedCredentialTestFixtureV1, _ **RecipientContext, in *SignInput) {
			in.Notice.Snapshot.Controller = "Another controller"
			in.Notice, _ = article13.NewEvidence(in.Notice.Snapshot)
		}},
		{"different notice purpose", func(_ *testing.T, _ *presentedCredentialTestFixtureV1, _ **RecipientContext, in *SignInput) {
			in.Notice.Snapshot.PurposeSummary = "Changed purpose"
			in.Notice, _ = article13.NewEvidence(in.Notice.Snapshot)
		}},
		{"missing committed epoch", func(t *testing.T, f *presentedCredentialTestFixtureV1, rc **RecipientContext, _ *SignInput) {
			f.db.document.Article13NoticeEpochV61Committed = false
			next := f.lookup(t)
			*rc = next
		}},
		{"infinite sent epoch", func(t *testing.T, f *presentedCredentialTestFixtureV1, rc **RecipientContext, _ *SignInput) {
			f.db.document.SentAt.InfinityModifier = pgtype.Infinity
			f.db.document.Article13NoticeEpochAt = f.db.document.SentAt
			*rc = f.lookup(t)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc := f.lookup(t)
			in := presentedCredentialTestInputV1(t, rc)
			if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, in); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, f, &rc, &in)
			if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, in); err == nil {
				t.Fatal("invalid provenance or intent was accepted")
			}
		})
	}
}

func TestFittedIntentV1IDLookupDoesNotIssuePresentedProvenance(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	original := f.lookup(t)
	in := presentedCredentialTestInputV1(t, original)
	synthetic, err := f.engine.LookupByRecipientID(context.Background(), original.Recipient.ID, original.Document.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	synthetic.ControllerOrg, synthetic.LawfulBasisConfirmation = original.ControllerOrg, original.LawfulBasisConfirmation
	if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), synthetic, in); !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("ID lookup supplied presented signing authority")
	}
	// Existing QES/historical contexts without private provenance keep their exact
	// previous exported locked-credential contract; the fitted issuer still refuses.
	doc := *synthetic.Document
	if err := ValidateLockedRecipientCredential(synthetic, presentedFreshRecipientTestV1(synthetic), &doc, f.now); err != nil {
		t.Fatal(err)
	}
}

func TestFittedIntentV1IsPrivateAndCancellationDoesNotDiscloseCause(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	in := presentedCredentialTestInputV1(t, rc)
	intent, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, in)
	if err != nil {
		t.Fatal(err)
	}
	in.TypedName, in.Font = "Later mutable input", "other font"
	if captured := intent.inputV1(in); captured.TypedName != "Submitted signer" || captured.Font != "Caveat" {
		t.Fatal("intent did not retain submitted values")
	}
	encoded, err := json.Marshal(intent)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("private intent was serialized")
	}
	cause := errors.New("private backend credential detail")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	_, err = f.engine.issueFittedSigningIntentV1(ctx, rc, intent.inputV1(in))
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("private cancellation cause was lost or disclosed")
	}
}

func TestFittedPolicyV1RejectsSyntheticProvenanceBeforeSQL(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	in := presentedCredentialTestInputV1(t, rc)
	rc.presentedCredential = nil
	f.db.calls = 0
	state := fitselect.LockedStateV1{Document: rc.Document, Recipient: presentedFreshRecipientTestV1(rc), Queries: f.engine.Queries}
	if err := f.engine.validateFittedSigningPolicyV1(context.Background(), rc, in, state); !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("synthetic provenance entered fitted policy")
	}
	if f.db.calls != 0 {
		t.Fatal("fitted policy queried SQL before provenance admission")
	}
}

func TestEngineSignV1ChecksOriginalProvenanceAndKeepsFittedRouteClosed(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	in := presentedCredentialTestInputV1(t, rc)
	calls := f.db.calls
	if result, err := f.engine.Sign(context.Background(), rc, in); result != nil || !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("fitted route readiness was bypassed")
	}
	f.now = f.now.Add(2 * time.Minute)
	if result, err := f.engine.Sign(context.Background(), rc, in); result != nil || !errors.Is(err, ErrMagicLinkExpired) {
		t.Fatal("actual sign boundary ignored original receipt expiry")
	}
	if f.db.calls != calls {
		t.Fatal("closed fitted sign route started preparation or SQL effects")
	}
}

func TestFittedIntentV1RejectsUnknownDeadlineShapes(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*presentedCredentialTestFixtureV1)
	}{
		{"missing recipient expiry", func(f *presentedCredentialTestFixtureV1) { f.db.recipient.MagicTokenExpiresAt = pgtype.Timestamptz{} }},
		{"zero recipient expiry", func(f *presentedCredentialTestFixtureV1) { f.db.recipient.MagicTokenExpiresAt.Time = time.Time{} }},
		{"positive infinite recipient expiry", func(f *presentedCredentialTestFixtureV1) {
			f.db.recipient.MagicTokenExpiresAt.InfinityModifier = pgtype.Infinity
		}},
		{"negative infinite recipient expiry", func(f *presentedCredentialTestFixtureV1) {
			f.db.recipient.MagicTokenExpiresAt.InfinityModifier = pgtype.NegativeInfinity
		}},
		{"zero document expiry", func(f *presentedCredentialTestFixtureV1) { f.db.document.ExpiresAt.Time = time.Time{} }},
		{"positive infinite document expiry", func(f *presentedCredentialTestFixtureV1) { f.db.document.ExpiresAt.InfinityModifier = pgtype.Infinity }},
		{"negative infinite document expiry", func(f *presentedCredentialTestFixtureV1) {
			f.db.document.ExpiresAt.InfinityModifier = pgtype.NegativeInfinity
		}},
		{"zero controller confirmation", func(f *presentedCredentialTestFixtureV1) { f.db.confirmation.ConfirmedAt.Time = time.Time{} }},
		{"infinite controller confirmation", func(f *presentedCredentialTestFixtureV1) {
			f.db.confirmation.ConfirmedAt.InfinityModifier = pgtype.Infinity
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			tc.mutate(f)
			// The historical read-only lookup remains compatible with its prior nullable
			// timestamp rules. Strict fitted issuance independently refuses uncertainty.
			rc := f.lookup(t)
			in := presentedCredentialTestInputV1(t, rc)
			if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, in); !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
				t.Fatal("unknown deadline shape issued fitted intent")
			}
		})
	}
	t.Run("absent document expiry with bounded recipient expiry", func(t *testing.T) {
		f := newPresentedCredentialTestFixtureV1(t)
		f.db.document.ExpiresAt = pgtype.Timestamptz{}
		rc := f.lookup(t)
		if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, presentedCredentialTestInputV1(t, rc)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFittedPolicyV1RefusesCancellationDuringFinalSuccessfulSQL(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	in := presentedCredentialTestInputV1(t, rc)
	state := fitselect.LockedStateV1{Document: rc.Document, Recipient: presentedFreshRecipientTestV1(rc), Queries: f.engine.Queries}
	f.db.policyCollections = true
	// Exercise the genuine generated controller/role/field/count call chain over
	// labeled synthetic rows before injecting cancellation at its final response.
	if err := f.engine.validateFittedSigningPolicyV1(context.Background(), rc, in, state); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("private late SQL cancellation detail")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	countReached := false
	f.db.beforeQuery = func(name string) {
		if strings.Contains(name, "-- name: CountUnfilledRequiredForRecipient ") {
			countReached = true
			cancel(cause)
		}
	}
	err := f.engine.validateFittedSigningPolicyV1(ctx, rc, in, state)
	if !countReached {
		t.Fatal("fixture did not reach the final policy SQL response")
	}
	if !errors.Is(err, ErrSigningAdmissionUnavailableV1) || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("late cancellation was accepted or its private cause was lost/disclosed")
	}
}

func TestFittedPolicyV1RebindsActualTransactionRoutingScope(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"changed policy", func(d *generated.Document) { d.SigningAdmissionPolicy = "historical" }},
		{"changed source", func(d *generated.Document) { d.SourceKind = "blocks" }},
		{"changed tier", func(d *generated.Document) { d.RoutingTier = "AES" }},
		{"removed signature requirement", func(d *generated.Document) { d.RequiresSignature = false }},
		{"envelope", func(d *generated.Document) { d.IsEnvelope = true }},
		{"envelope child", func(d *generated.Document) { d.ParentEnvelopeID = pgtype.UUID{Bytes: uuid.New(), Valid: true} }},
		{"deleted document", func(d *generated.Document) { d.DeletedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc := f.lookup(t)
			in := presentedCredentialTestInputV1(t, rc)
			locked := *rc.Document
			tc.mutate(&locked)
			f.db.calls = 0
			state := fitselect.LockedStateV1{Document: &locked, Recipient: presentedFreshRecipientTestV1(rc), Queries: f.engine.Queries}
			if err := f.engine.validateFittedSigningPolicyV1(context.Background(), rc, in, state); !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
				t.Fatal("changed transaction scope was admitted")
			}
			if f.db.calls != 0 {
				t.Fatal("changed routing scope reached later policy SQL")
			}
		})
	}
}

func TestFittedPolicyV1RefusesUnknownCurrentDeadlineShapesBeforeSQL(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.Recipient, *generated.Document)
	}{
		{"missing recipient expiry", func(r *generated.Recipient, _ *generated.Document) { r.MagicTokenExpiresAt = pgtype.Timestamptz{} }},
		{"zero recipient expiry", func(r *generated.Recipient, _ *generated.Document) { r.MagicTokenExpiresAt.Time = time.Time{} }},
		{"positive infinite recipient expiry", func(r *generated.Recipient, _ *generated.Document) {
			r.MagicTokenExpiresAt.InfinityModifier = pgtype.Infinity
		}},
		{"negative infinite recipient expiry", func(r *generated.Recipient, _ *generated.Document) {
			r.MagicTokenExpiresAt.InfinityModifier = pgtype.NegativeInfinity
		}},
		{"zero document expiry", func(_ *generated.Recipient, d *generated.Document) { d.ExpiresAt.Time = time.Time{} }},
		{"positive infinite document expiry", func(_ *generated.Recipient, d *generated.Document) { d.ExpiresAt.InfinityModifier = pgtype.Infinity }},
		{"negative infinite document expiry", func(_ *generated.Recipient, d *generated.Document) {
			d.ExpiresAt.InfinityModifier = pgtype.NegativeInfinity
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc := f.lookup(t)
			in := presentedCredentialTestInputV1(t, rc)
			locked := *rc.Document
			fresh := presentedFreshRecipientTestV1(rc)
			tc.mutate(fresh, &locked)
			f.db.calls = 0
			state := fitselect.LockedStateV1{Document: &locked, Recipient: fresh, Queries: f.engine.Queries}
			if err := f.engine.validateFittedSigningPolicyV1(context.Background(), rc, in, state); !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
				t.Fatal("unknown current deadline was accepted")
			}
			if f.db.calls != 0 {
				t.Fatal("unknown current deadline reached policy SQL")
			}
		})
	}
	t.Run("optional absent current document expiry", func(t *testing.T) {
		f := newPresentedCredentialTestFixtureV1(t)
		rc := f.lookup(t)
		in := presentedCredentialTestInputV1(t, rc)
		locked := *rc.Document
		locked.ExpiresAt = pgtype.Timestamptz{}
		f.db.policyCollections = true
		state := fitselect.LockedStateV1{Document: &locked, Recipient: presentedFreshRecipientTestV1(rc), Queries: f.engine.Queries}
		if err := f.engine.validateFittedSigningPolicyV1(context.Background(), rc, in, state); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFittedPolicyV1RequiresFiniteCurrentControllerConfirmation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.DocumentLawfulBasisConfirmation)
	}{
		{"missing confirmation", func(c *generated.DocumentLawfulBasisConfirmation) { c.ConfirmedAt = pgtype.Timestamptz{} }},
		{"zero confirmation", func(c *generated.DocumentLawfulBasisConfirmation) { c.ConfirmedAt.Time = time.Time{} }},
		{"positive infinite confirmation", func(c *generated.DocumentLawfulBasisConfirmation) { c.ConfirmedAt.InfinityModifier = pgtype.Infinity }},
		{"negative infinite confirmation", func(c *generated.DocumentLawfulBasisConfirmation) {
			c.ConfirmedAt.InfinityModifier = pgtype.NegativeInfinity
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc := f.lookup(t)
			in := presentedCredentialTestInputV1(t, rc)
			// The issued receipt remains finite; only the actual current SQL result is
			// changed, so the test reaches and checks the real confirmation query.
			tc.mutate(f.db.confirmation)
			f.db.calls = 0
			state := fitselect.LockedStateV1{Document: rc.Document, Recipient: presentedFreshRecipientTestV1(rc), Queries: f.engine.Queries}
			if err := f.engine.validateFittedSigningPolicyV1(context.Background(), rc, in, state); !errors.Is(err, ErrSignerLawfulBasisUnavailable) {
				t.Fatal("uncertain current confirmation was accepted")
			}
			if f.db.calls != 1 {
				t.Fatal("fixture did not stop at the actual confirmation result")
			}
		})
	}
}
