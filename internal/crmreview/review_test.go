// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package crmreview

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func reviewDocument() *generated.Document {
	return &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Status: "draft", SourceKind: "blocks",
		BlocksJson:    json.RawMessage(`{"version":1,"blocks":[{"id":"terms","type":"paragraph","text":"{{amount}} {{title}}"}]}`),
		VariablesJson: json.RawMessage(`{"amount":"9007199254740993.2300","title":"Reviewed title"}`)}
}

func reviewBindings(doc *generated.Document) []*generated.DocumentVariableBinding {
	stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 10, 0, 0, 0, 123456000, time.UTC), Valid: true}
	return []*generated.DocumentVariableBinding{
		{DocumentID: doc.ID, VariableName: "title", SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: "title", CreatedAt: stamp, UpdatedAt: stamp},
		{DocumentID: doc.ID, VariableName: "amount", SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: "value", CreatedAt: stamp, UpdatedAt: stamp},
	}
}

func cloneBindings(rows []*generated.DocumentVariableBinding) []*generated.DocumentVariableBinding {
	cloned := make([]*generated.DocumentVariableBinding, len(rows))
	for i, r := range rows {
		c := *r
		cloned[i] = &c
	}
	return cloned
}

func reviewConnection(doc *generated.Document) *generated.CrmConnection {
	return &generated.CrmConnection{ID: uuid.New(), OrgID: doc.OrgID, Generation: 3, Status: "active", Origin: "https://crm.example.test", CrmTeamID: "team_1", CrmUserID: "user_1"}
}

func savedReview(t testing.TB, doc *generated.Document, bindings []*generated.DocumentVariableBinding, conn *generated.CrmConnection) *generated.DocumentCrmMappingReview {
	t.Helper()
	digest, err := CRMSemanticDigest(bindings)
	if err != nil {
		t.Fatal(err)
	}
	content, err := ContentCommitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	stamp := pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}
	r := &generated.DocumentCrmMappingReview{DocumentID: doc.ID, HasMappings: conn != nil, BindingDigest: digest, ContentCommitment: content, ReviewedBy: uuid.New(), CreatedAt: stamp, UpdatedAt: stamp}
	if conn != nil {
		r.ConnectionID = pgtype.UUID{Bytes: conn.ID, Valid: true}
		r.ConnectionGeneration = pgtype.Int8{Int64: conn.Generation, Valid: true}
		r.Origin = conn.Origin
		r.CrmTeamID = conn.CrmTeamID
		r.CrmUserID = conn.CrmUserID
	}
	return r
}

func TestBindingFingerprintsProtectIndependentLedgerRevision(t *testing.T) {
	doc := reviewDocument()
	rows := reviewBindings(doc)
	full, err := FullBindingFingerprint(rows)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := CRMSemanticDigest(rows)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []*generated.DocumentVariableBinding{rows[1], rows[0]}
	if next, _ := FullBindingFingerprint(reversed); next != full || rows[0].VariableName != "title" {
		t.Fatal("fingerprint changed by input order or mutated ledger")
	}
	for _, kind := range []string{"precise_revision", "cache", "error", "resolved_at"} {
		t.Run(kind, func(t *testing.T) {
			changed := cloneBindings(rows)
			switch kind {
			case "precise_revision":
				changed[0].UpdatedAt.Time = changed[0].UpdatedAt.Time.Add(time.Microsecond)
			case "cache":
				changed[0].LastValue = "later observation"
			case "error":
				changed[0].LastError = "source_unavailable"
			case "resolved_at":
				changed[0].LastResolved = changed[0].UpdatedAt
			}
			if next, _ := FullBindingFingerprint(changed); next == full {
				t.Fatal("independent ledger change was not bound")
			}
			if next, _ := CRMSemanticDigest(changed); next != semantic {
				t.Fatal("observation/revision state changed semantic mapping")
			}
		})
	}
	changed := cloneBindings(rows)
	changed[0].SourceRef = "deal_2"
	if next, _ := CRMSemanticDigest(changed); next == semantic {
		t.Fatal("record replacement did not change semantic digest")
	}
	changed = cloneBindings(rows)
	changed[0].Fallback = "manual"
	if next, _ := CRMSemanticDigest(changed); next == semantic {
		t.Fatal("fallback change did not change semantic digest")
	}
	extra := *rows[0]
	extra.VariableName = "manual"
	extra.SourceKind = "static"
	extra.SourceRef = ""
	extra.SourcePath = ""
	if next, _ := CRMSemanticDigest(append(cloneBindings(rows), &extra)); next != semantic {
		t.Fatal("non-CRM member changed CRM-only digest")
	}
	if next, _ := FullBindingFingerprint(append(cloneBindings(rows), &extra)); next == full {
		t.Fatal("full fingerprint omitted non-CRM member")
	}
	if next, _ := CRMSemanticDigest(rows[:1]); next == semantic {
		t.Fatal("deleted CRM member did not change digest")
	}
}

func TestBindingFingerprintRefusesAmbiguousOrOversizedLedger(t *testing.T) {
	doc := reviewDocument()
	rows := reviewBindings(doc)
	for _, kind := range []string{"nil", "duplicate", "foreign_document", "unsupported_path", "missing_time", "infinite_time", "backwards_time", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			bad := cloneBindings(rows)
			switch kind {
			case "nil":
				bad[0] = nil
			case "duplicate":
				bad[1].VariableName = bad[0].VariableName
			case "foreign_document":
				bad[1].DocumentID = uuid.New()
			case "unsupported_path":
				bad[0].SourcePath = "private.notes"
			case "missing_time":
				bad[0].CreatedAt.Valid = false
			case "infinite_time":
				bad[0].UpdatedAt.InfinityModifier = pgtype.Infinity
			case "backwards_time":
				bad[0].UpdatedAt.Time = bad[0].CreatedAt.Time.Add(-time.Microsecond)
			case "oversized":
				bad = make([]*generated.DocumentVariableBinding, MaxBindings+1)
			}
			if _, err := FullBindingFingerprint(bad); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid ledger accepted: %v", err)
			}
		})
	}
}

func TestContentCommitmentBindsExactCanonicalContract(t *testing.T) {
	doc := reviewDocument()
	before, err := ContentCommitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	copy := *doc
	copy.BlocksJson = json.RawMessage(` { "blocks": [ { "text":"{{amount}} {{title}}", "type":"paragraph", "id":"terms" } ], "version":1 } `)
	copy.VariablesJson = json.RawMessage(`{"title":"Reviewed title","amount":"9007199254740993.2300"}`)
	if next, err := ContentCommitment(&copy); err != nil || next != before {
		t.Fatal("transport spelling changed canonical content")
	}
	copy.VariablesJson = json.RawMessage(`{"amount":"9007199254740993.23","title":"Reviewed title"}`)
	if next, _ := ContentCommitment(&copy); next == before {
		t.Fatal("decimal lexical change was not bound")
	}
	copy = *doc
	copy.ID = uuid.New()
	if next, _ := ContentCommitment(&copy); next == before {
		t.Fatal("content commitment copied across documents")
	}
	for _, raw := range []string{`{"amount":"1","amount":"2"}`, `{"amount":null}`, `{"amount":9007199254740993.23}`, `{"amount":"\ud800"}`} {
		copy = *doc
		copy.VariablesJson = json.RawMessage(raw)
		if _, err := ContentCommitment(&copy); err == nil {
			t.Fatal("ambiguous/non-string value accepted")
		}
	}
	copy = *doc
	copy.BlocksJson = json.RawMessage(`{"version":1,"version":2,"blocks":[]}`)
	if _, err := ContentCommitment(&copy); err == nil {
		t.Fatal("duplicate block schema accepted")
	}
	for _, raw := range []string{`{"version":1,"Version":1,"blocks":[]}`, `{"version":1,"blocks":[{"id":"terms","ID":"different","type":"paragraph","text":"reviewed"}]}`} {
		copy = *doc
		copy.BlocksJson = json.RawMessage(raw)
		if _, err := ContentCommitment(&copy); err == nil {
			t.Fatal("case-aliased canonical block member accepted")
		}
	}
	for _, raw := range []string{`{"amount":"\\ud800"}`, `{"amount":"\ud83d\ude00"}`} {
		copy = *doc
		copy.VariablesJson = json.RawMessage(raw)
		if _, err := ContentCommitment(&copy); err != nil {
			t.Fatal("literal escape or valid surrogate pair refused")
		}
	}
	copy = *doc
	copy.SourceKind = "pdf"
	if _, err := ContentCommitment(&copy); err == nil {
		t.Fatal("uploaded PDF printed text treated as editable")
	}
	_, htmlDoc, _ := testfixture.HTMLContract(t)
	if _, err := ContentCommitment(htmlDoc); err != nil {
		t.Fatal(err)
	}
	htmlDoc.VariablesJson = json.RawMessage(`{"customer_name":"different printed name"}`)
	if _, err := ContentCommitment(htmlDoc); err == nil {
		t.Fatal("HTML printed/source value mismatch accepted")
	}
}

func TestReviewedMappingRequiresCurrentContentAndAccount(t *testing.T) {
	doc := reviewDocument()
	rows := reviewBindings(doc)
	conn := reviewConnection(doc)
	review := savedReview(t, doc, rows, conn)
	if ok, err := ReviewMatches(doc, rows, review, conn); !ok || err != nil {
		t.Fatalf("valid review refused: %v", err)
	}
	for _, kind := range []string{"content", "record", "removed_member", "all_deleted", "no_review", "foreign_review", "foreign_account", "generation", "origin", "team", "principal", "revoked", "missing_account", "invalid_review"} {
		t.Run(kind, func(t *testing.T) {
			d := *doc
			bs := cloneBindings(rows)
			r := *review
			c := *conn
			rp, cp := &r, &c
			switch kind {
			case "content":
				d.VariablesJson = json.RawMessage(`{"amount":"2","title":"Reviewed title"}`)
			case "record":
				bs[0].SourceRef = "deal_2"
			case "removed_member":
				bs = bs[:1]
			case "all_deleted":
				bs = nil
			case "no_review":
				rp = nil
			case "foreign_review":
				r.DocumentID = uuid.New()
			case "foreign_account":
				c.OrgID = uuid.New()
			case "generation":
				c.Generation++
			case "origin":
				c.Origin = "https://other.example.test"
			case "team":
				c.CrmTeamID = "team_2"
			case "principal":
				c.CrmUserID = "user_2"
			case "revoked":
				c.Status = "revoked"
			case "missing_account":
				cp = nil
			case "invalid_review":
				r.ConnectionGeneration.Valid = false
			}
			if ok, _ := ReviewMatches(&d, bs, rp, cp); ok {
				t.Fatal("stale or foreign review accepted")
			}
		})
	}
}

func TestExplicitUnlinkKeepsManualAuthoringIndependent(t *testing.T) {
	doc := reviewDocument()
	unlink := savedReview(t, doc, nil, nil)
	if ok, err := ReviewMatches(doc, nil, nil, nil); !ok || err != nil {
		t.Fatal("ordinary manual document refused")
	}
	doc.VariablesJson = json.RawMessage(`{"amount":"later manual value"}`)
	if ok, err := ReviewMatches(doc, nil, unlink, nil); !ok || err != nil {
		t.Fatal("reviewed unlink required a live account or original manual content")
	}
	if ok, _ := ReviewMatches(doc, reviewBindings(doc), unlink, reviewConnection(doc)); ok {
		t.Fatal("unreviewed re-addition accepted after unlink")
	}
	bad := *unlink
	bad.Origin = "https://crm.example.test"
	if ok, err := ReviewMatches(doc, nil, &bad, nil); ok || err == nil {
		t.Fatal("unlink retained an account claim")
	}
}

type sendStore struct {
	bindings     []*generated.DocumentVariableBinding
	review       *generated.DocumentCrmMappingReview
	conn         *generated.CrmConnection
	readErr      error
	shares       int
	boundedReads int
	existsReads  int
}

func (s *sendStore) ListVariableBindings(context.Context, uuid.UUID) ([]*generated.DocumentVariableBinding, error) {
	return s.bindings, s.readErr
}
func (s *sendStore) ListCRMMappingBindingsForShare(context.Context, generated.ListCRMMappingBindingsForShareParams) ([]*generated.DocumentVariableBinding, error) {
	s.boundedReads++
	return s.bindings, s.readErr
}
func (s *sendStore) DocumentHasCRMBindings(_ context.Context, arg generated.DocumentHasCRMBindingsParams) (bool, error) {
	s.existsReads++
	if s.readErr != nil {
		return false, s.readErr
	}
	for _, row := range s.bindings {
		if row != nil && row.DocumentID == arg.DocumentID && crmKind(row.SourceKind) {
			return true, nil
		}
	}
	return false, nil
}
func (s *sendStore) GetDocumentCRMMappingReviewForShare(context.Context, generated.GetDocumentCRMMappingReviewForShareParams) (*generated.DocumentCrmMappingReview, error) {
	if s.review == nil {
		return nil, pgx.ErrNoRows
	}
	return s.review, s.readErr
}
func (s *sendStore) GetCRMConnectionByOrg(_ context.Context, org uuid.UUID) (*generated.CrmConnection, error) {
	if s.conn == nil || s.conn.OrgID != org {
		return nil, pgx.ErrNoRows
	}
	return s.conn, s.readErr
}
func (s *sendStore) GetCRMConnectionByOrgForShare(ctx context.Context, org uuid.UUID) (*generated.CrmConnection, error) {
	s.shares++
	return s.GetCRMConnectionByOrg(ctx, org)
}

// Synthetic HTTP account/deal responses exercise actual strict typed decoding
// and the resolver's unexported proof. They establish no live CRM acceptance.
func freshReports(t *testing.T, doc *generated.Document, store *sendStore) []resolver.ResolveReport {
	t.Helper()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("ab", 32) {
			t.Error("synthetic observation did not use the original authenticated credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			_, _ = w.Write([]byte(`{"id":"user_1","team_id":"team_1","is_active":true}`))
		case "/api/v1/deals/deal_1":
			_, _ = w.Write([]byte(`{"id":"deal_1","team_id":"team_1","updated_at":"2026-10-01T10:00:00Z","title":"Reviewed title","value":9007199254740993.2300}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(provider.Close)
	client, err := crmconnection.NewClient(provider.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crmconnection.NewKeyring(strings.Repeat("1234", 16), "")
	if err != nil {
		t.Fatal(err)
	}
	store.conn.Origin = provider.URL
	id := crmconnection.Identity{ID: store.conn.ID, OrgID: doc.OrgID, Generation: store.conn.Generation, Origin: provider.URL, CRMTeamID: store.conn.CrmTeamID, CRMUserID: store.conn.CrmUserID}
	cipher, err := keys.Seal(id, strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	store.conn.CredentialCiphertext = cipher
	store.conn.VerifiedAt = pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}
	r := resolver.New(nil)
	r.Q = store
	r.CRM = &resolver.CRMRecords{Store: store, Client: client, Keys: keys, Origin: provider.URL}
	_, report, err := r.Resolve(context.Background(), doc, resolver.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	store.review = savedReview(t, doc, store.bindings, store.conn)
	return report
}

func TestSendRequiresRealFreshReportsForEveryReviewedCRMMapping(t *testing.T) {
	doc := reviewDocument()
	store := &sendStore{bindings: reviewBindings(doc), conn: reviewConnection(doc)}
	reports := freshReports(t, doc, store)
	if err := checkForSend(context.Background(), store, doc, reports, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"no_resolver", "missing_report", "duplicate", "forged_exported_proof", "value_changed", "ref_changed", "wrong_org", "expired", "future", "review_deleted", "binding_removed", "all_bindings_deleted", "generation_changed", "account_revoked", "non_crm_frozen_content_changed"} {
		t.Run(kind, func(t *testing.T) {
			s := *store
			s.bindings = cloneBindings(store.bindings)
			copyConn := *store.conn
			s.conn = &copyConn
			d := *doc
			rs := append([]resolver.ResolveReport(nil), reports...)
			now := time.Now()
			switch kind {
			case "no_resolver":
				rs = nil
			case "missing_report":
				rs = rs[:1]
			case "duplicate":
				rs = append(rs, rs[0])
			case "forged_exported_proof":
				e := rs[0]
				rs[0] = resolver.ResolveReport{Variable: e.Variable, SourceKind: e.SourceKind, SourceRef: e.SourceRef, SourcePath: e.SourcePath, Value: e.Value, ResolvedFrom: e.ResolvedFrom, CRMObservation: e.CRMObservation}
			case "value_changed":
				rs[0].Value = "different agreement"
			case "ref_changed":
				rs[0].SourceRef = "deal_2"
			case "wrong_org":
				d.OrgID = uuid.New()
			case "expired":
				now = now.Add(resolver.CRMObservationMaxAge + time.Second)
			case "future":
				now = now.Add(-time.Minute)
			case "review_deleted":
				s.review = nil
			case "binding_removed":
				s.bindings = s.bindings[:1]
			case "all_bindings_deleted":
				s.bindings = nil
			case "generation_changed":
				s.conn.Generation++
			case "account_revoked":
				s.conn.Status = "revoked"
			case "non_crm_frozen_content_changed":
				d.VariablesJson = json.RawMessage(`{"amount":"9007199254740993.2300","title":"Reviewed title","external_note":"new live value"}`)
				extra := *s.bindings[0]
				extra.VariableName = "external_note"
				extra.SourceKind = "org.setting"
				extra.SourceRef = ""
				extra.SourcePath = "org.name"
				s.bindings = append(s.bindings, &extra)
			}
			if err := checkForSend(context.Background(), &s, &d, rs, now); !errors.Is(err, ErrReviewRequired) {
				t.Fatalf("unsafe send accepted: %v", err)
			}
		})
	}
}

func TestSendManualCompatibilityAndDependencyRefusal(t *testing.T) {
	doc := reviewDocument()
	store := &sendStore{}
	if err := checkForSend(context.Background(), store, doc, nil, time.Now()); err != nil || store.shares != 0 || store.boundedReads != 0 || store.existsReads != 1 {
		t.Fatal("manual send consulted CRM account")
	}
	store.review = savedReview(t, doc, nil, nil)
	doc.VariablesJson = json.RawMessage(`{"amount":"later manual edit"}`)
	if err := checkForSend(context.Background(), store, doc, nil, time.Now()); err != nil || store.shares != 0 {
		t.Fatal("explicit unlink blocked manual send")
	}
	store.bindings = make([]*generated.DocumentVariableBinding, MaxBindings+1)
	for i := range store.bindings {
		row := *reviewBindings(doc)[0]
		row.VariableName = fmt.Sprintf("manual_%d", i)
		row.SourceKind, row.SourceRef, row.SourcePath, row.Fallback = "static", "", "", "manual value"
		store.bindings[i] = &row
	}
	for _, retained := range []*generated.DocumentCrmMappingReview{nil, store.review} {
		store.review = retained
		if err := checkForSend(context.Background(), store, doc, nil, time.Now()); err != nil || store.boundedReads != 0 || store.shares != 0 {
			t.Fatal("large ordinary manual ledger acquired a CRM review restriction")
		}
	}
	invalidUnlink := *store.review
	invalidUnlink.BindingDigest = strings.Repeat("a", 64)
	store.review = &invalidUnlink
	if err := checkForSend(context.Background(), store, doc, nil, time.Now()); !errors.Is(err, ErrReviewRequired) || store.boundedReads != 0 || store.shares != 0 {
		t.Fatal("wrong empty-mapping digest accepted as an explicit unlink")
	}
	store.review = nil
	store.bindings[len(store.bindings)-1] = reviewBindings(doc)[0]
	if err := checkForSend(context.Background(), store, doc, nil, time.Now()); !errors.Is(err, ErrReviewRequired) || store.boundedReads != 1 {
		t.Fatal("CRM beyond the 128th ledger row bypassed bounded review admission")
	}
	store.bindings = nil
	unavailable := errors.New("database dependency unavailable")
	store.readErr = unavailable
	if err := checkForSend(context.Background(), store, doc, nil, time.Now()); !errors.Is(err, unavailable) {
		t.Fatal("dependency outage bypassed admission")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkForSend(ctx, store, doc, nil, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled admission continued")
	}
	if err := CheckForSend(context.Background(), nil, doc, nil); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("missing query wiring accepted")
	}
}
