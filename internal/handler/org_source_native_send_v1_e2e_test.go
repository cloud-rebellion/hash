//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestNativeManualPDFOrgSettingSendV1E2E(t *testing.T) {
	trace := new(nativeOrgSourceGrantTrace257d)
	q := newOwnedOrgSourceSingleOrganisationFixture257d(t, trace)
	ownedCreationPrepareProPlanV1(t, q)
	if err := malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	root := packageImported220(t, q, "Actual manual PDF org source")
	if root.SourceKind != "pdf" || len(root.HtmlSourceJson) != 0 || root.IsEnvelope || root.ParentEnvelopeID.Valid {
		t.Fatal("manual source must be genuine standalone non-HTML PDF")
	}
	org, err := q.f.q.GetOrg(q.f.ctx, q.f.org)
	if err != nil || org == nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"role": "signer", "email": "manual-source@org-setting.test", "name": "Actual source signer", "locale": "en"})
	reply := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/recipients", string(raw), q.cookie)
	var party recipientResponse
	if reply.Code != http.StatusCreated || json.Unmarshal(reply.Body.Bytes(), &party) != nil || party.ID == uuid.Nil {
		t.Fatal("actual manual PDF party creation failed", reply.Code)
	}
	field := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(field, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{"document_id": root.ID.String(), "type": "signature", "recipient_id": party.ID.String(), "page": 1, "required": true, "label": "Signature", "x_pct": 20, "y_pct": 65, "w_pct": 45, "h_pct": 10}, nil))
	if field.Code != http.StatusCreated {
		t.Fatal("actual manual signature placement failed", field.Code)
	}
	if _, err := q.f.q.UpsertVariableBinding(q.f.ctx, generated.UpsertVariableBindingParams{DocumentID: root.ID, VariableName: "customer", SourceKind: string(resolver.SourceOrgSetting), SourcePath: "org.name"}); err != nil {
		t.Fatal(err)
	}
	q.f.s.Send.Resolver = resolver.New(q.f.q, &resolver.OrgSettingSource{Q: q.f.q, Plans: q.f.s.Billing})
	trace.beginV1(t, q)
	reply = submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/send", `{"lawful_basis":"contract"}`, q.cookie)
	trace.checkpointV1("http-response")
	if reply.Code != http.StatusOK {
		t.Fatal("manual PDF source Send failed", reply.Code, reply.Body.String())
	}
	completed, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: root.ID, OrgID: q.f.org})
	if err != nil || completed == nil || completed.Status != "sent" {
		t.Fatal("manual source was not genuinely sent", err)
	}
	var frozen map[string]string
	bindings, err := q.f.q.ListVariableBindings(q.f.ctx, root.ID)
	if json.Unmarshal(completed.VariablesJson, &frozen) != nil || frozen["customer"] != org.Name || err != nil || len(bindings) != 1 || bindings[0].LastValue != org.Name || !bindings[0].LastResolved.Valid || bindings[0].SourceKind != string(resolver.SourceOrgSetting) || bindings[0].SourcePath != "org.name" {
		t.Fatal("manual PDF source/observation was not truly frozen", err)
	}
	q.assertObserversOnlyV1(t)
	trace.checkpointV1("joined-observers-only")
}

func nativeOrgSourceBranding257(t *testing.T, f lifecycleAuthorizationFixture) {
	t.Helper()
	// Genuine fixture source data, not a document/evidence measurement or claim.
	if _, err := f.q.UpsertOrgBranding(f.ctx, generated.UpsertOrgBrandingParams{OrgID: f.org, PrimaryHex: "#123456", AccentHex: "#345678", SurfaceHex: "#ffffff", TextHex: "#111111", MutedHex: "#777777", FontHeading: "Inter", FontBody: "Inter", SignatureColor: "#111111"}); err != nil {
		t.Fatal(err)
	}
}

type nativeOrgSourceCase257d struct {
	name, path, want                   string
	family, child, twice, subscription bool
}

func nativeOrgSourcePrepare257d(t *testing.T, q *ownedPublicReadFixtureV1, c nativeOrgSourceCase257d) (lifecycleAuthorizationFixture, string, uuid.UUID, []string) {
	t.Helper()
	f := setupNativeLifecycleAuthorizationWithFixture257d(t, "owner", false, c.family, q)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	target := f.doc.ID
	if c.child {
		children, err := f.s.Envelopes.Children(f.ctx, f.doc.ID, f.org)
		if err != nil || len(children) != 2 {
			t.Fatal("actual attached child family unavailable", err)
		}
		target = children[0].ID
		// Preserve real public authoring/M94 production. Do not directly
		// replace a JSON body or manufacture its measurement in SQL.
		body, _ := json.Marshal(map[string]any{"expected_updated_at": children[0].UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "variables_json": map[string]string{}})
		changed := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/documents/"+target.String(), string(body), cookie)
		if changed.Code != http.StatusOK {
			t.Fatal("actual child variable authoring failed", changed.Code, changed.Body.String())
		}
	}
	if c.path == "branding.primary_hex" {
		nativeOrgSourceBranding257(t, f)
	}
	plans := f.s.Billing
	if c.subscription {
		var plan uuid.UUID
		if err := f.pool.QueryRow(f.ctx, "SELECT id FROM billing_plans WHERE slug='pro'").Scan(&plan); err != nil || plan == uuid.Nil {
			t.Fatal("real measured pro identity missing", err)
		}
		now := time.Now().UTC()
		if _, err := f.q.UpsertOrgSubscription(f.ctx, generated.UpsertOrgSubscriptionParams{OrgID: f.org, PlanID: plan, Provider: "mock", Status: "active", CurrentPeriodStart: pgtype.Timestamptz{Time: now.Add(-time.Hour), Valid: true}, CurrentPeriodEnd: pgtype.Timestamptz{Time: now.Add(24 * time.Hour), Valid: true}}); err != nil {
			t.Fatal("actual subscription source fixture unavailable", err)
		}
		plans = billing.New(f.q, nil, f.s.PublicURL, "")
	}
	f.s.Send.Resolver = resolver.New(f.q, &resolver.OrgSettingSource{Q: f.q, Plans: plans})
	variables := []string{"customer"}
	if c.twice {
		variables = append(variables, "customer_plan_copy")
	}
	for _, name := range variables {
		binding, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{DocumentID: target, VariableName: name, SourceKind: string(resolver.SourceOrgSetting), SourceRef: "actual native org source fixture", SourcePath: c.path})
		if err != nil || binding == nil || binding.LastResolved.Valid || binding.LastValue != "" || binding.LastError != "" || binding.Fallback != "" {
			t.Fatal("native source binding must start actually unresolved", err)
		}
	}
	return f, cookie, target, variables
}

func TestNativeLegacyOrgSettingSendSourcesV1E2E(t *testing.T) {
	for _, c := range []nativeOrgSourceCase257d{
		{name: "ordinary organization name", path: "org.name", want: "Resolved fixture customer"},
		{name: "ordinary draft branding", path: "branding.primary_hex", want: "#123456"},
		{name: "ordinary two operator plan bindings", path: "org.plan", want: "pro", twice: true},
		{name: "ordinary two subscription plan bindings", path: "org.plan", want: "pro", twice: true, subscription: true},
		{name: "envelope root organization name", path: "org.name", want: "Resolved fixture customer", family: true},
		{name: "actual registered child organization name", path: "org.name", want: "Resolved fixture customer", family: true, child: true},
		{name: "actual registered child branding", path: "branding.primary_hex", want: "#123456", family: true, child: true},
		{name: "actual registered child two operator plans", path: "org.plan", want: "pro", family: true, child: true, twice: true},
		{name: "actual registered child subscription plans", path: "org.plan", want: "pro", family: true, child: true, twice: true, subscription: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			trace := new(nativeOrgSourceGrantTrace257d)
			q := newOwnedOrgSourceSingleOrganisationFixture257d(t, trace)
			f, cookie, target, variables := nativeOrgSourcePrepare257d(t, q, c)
			trace.beginV1(t, q)
			response := f.submit("send", cookie)
			trace.checkpointV1("http-response")
			if response.Code != http.StatusOK {
				t.Fatal("genuine native source Send failed", response.Code, response.Body.String())
			}
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: target, OrgID: f.org})
			if err != nil || doc.Status != "sent" {
				t.Fatal("original target did not genuinely send", err)
			}
			var values map[string]string
			if json.Unmarshal(doc.VariablesJson, &values) != nil {
				t.Fatal("frozen actual variables unavailable")
			}
			bindings, err := f.q.ListVariableBindings(f.ctx, target)
			if err != nil || len(bindings) != len(variables) {
				t.Fatal("actual source binding observation count changed", err)
			}
			for _, name := range variables {
				if values[name] != c.want {
					t.Fatal("original frozen source value missing", name)
				}
			}
			for _, binding := range bindings {
				if binding.SourceKind != string(resolver.SourceOrgSetting) || binding.SourcePath != c.path || binding.LastValue != c.want || !binding.LastResolved.Valid || binding.LastError != "" || binding.Fallback != "" {
					t.Fatal("original native source observation was not committed")
				}
			}
			// Every current native producer must have retained its own original
			// measurement; this witness writes none and repairs no older history.
			var total, measured int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,count(*) FILTER(WHERE m.event_id IS NOT NULL AND m.org_id=e.org_id AND m.document_id=e.document_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer)::integer FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.org_id=$1 AND e.document_id IS NOT NULL`, f.org).Scan(&total, &measured); err != nil || total == 0 || total != measured {
				t.Fatal("native org source journey omitted original producer measurement", total, measured, err)
			}
			q.assertObserversOnlyV1(t)
			trace.checkpointV1("joined-observers-only")
		})
	}
}

// Independent real PostgreSQL query-predicate controls, paired with the normal
// Send integrations above. Raw query access here is not native session/source
// authority and proves no body admission by itself.
func TestNativeLegacyOrgSourceSQLScopeRefusalsV1E2E(t *testing.T) {
	f := setupNativeLifecycleAuthorization256(t, "owner", false, true)
	nativeOrgSourceBranding257(t, f)
	root, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	children, err := f.s.Envelopes.Children(f.ctx, root.ID, f.org)
	if err != nil || len(children) != 2 {
		t.Fatal(err)
	}
	child := children[0]
	p := generated.GetLegacySendOrgSourceReadHeaderV1Params{RootDocumentID: root.ID, DocumentID: child.ID, OrgID: f.org, ExpectedRootUpdatedAt: root.UpdatedAt, ExpectedDocumentUpdatedAt: child.UpdatedAt, ExpectedIsPdfSource: false, ExpectedIsEnvelope: false, ExpectedRootIsPdfSource: false, ExpectedRootIsEnvelope: true}
	for _, c := range []struct {
		name   string
		change func(*generated.GetLegacySendOrgSourceReadHeaderV1Params)
	}{
		{"foreign organization", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) { v.OrgID = uuid.New() }},
		{"unknown physical root", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) { v.RootDocumentID = uuid.New() }},
		{"unknown logical member", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) { v.DocumentID = uuid.New() }},
		{"member cannot become root", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) {
			v.RootDocumentID = child.ID
			v.ExpectedRootUpdatedAt = child.UpdatedAt
			v.ExpectedRootIsEnvelope = false
		}},
		{"wrong root clock", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) {
			v.ExpectedRootUpdatedAt.Time = v.ExpectedRootUpdatedAt.Time.Add(-time.Microsecond)
		}},
		{"wrong logical clock", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) {
			v.ExpectedDocumentUpdatedAt.Time = v.ExpectedDocumentUpdatedAt.Time.Add(-time.Microsecond)
		}},
		{"wrong source format", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) { v.ExpectedIsPdfSource = true }},
		{"wrong root source format", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) { v.ExpectedRootIsPdfSource = true }},
		{"nested envelope is not member", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) { v.ExpectedIsEnvelope = true }},
		{"ordinary document is not root envelope", func(v *generated.GetLegacySendOrgSourceReadHeaderV1Params) { v.ExpectedRootIsEnvelope = false }},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := p
			c.change(&bad)
			if _, err := f.q.GetLegacySendOrgSourceReadHeaderV1(f.ctx, bad); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("wrong legacy source scope returned organization header", err)
			}
			if _, err := f.q.GetLegacySendOrgBrandingSourceReadHeaderV1(f.ctx, generated.GetLegacySendOrgBrandingSourceReadHeaderV1Params(bad)); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("wrong legacy source scope returned branding header", err)
			}
		})
	}
	// The original reviewed-HTML queries must still refuse every legacy shape.
	if _, err := f.q.GetHTMLSendOrgSourceReadHeaderV1(f.ctx, generated.GetHTMLSendOrgSourceReadHeaderV1Params{DocumentID: root.ID, OrgID: f.org}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("original HTML source gate broadened", err)
	}
	if _, err := f.q.GetHTMLSendOrgBrandingSourceReadHeaderV1(f.ctx, generated.GetHTMLSendOrgBrandingSourceReadHeaderV1Params{DocumentID: child.ID, OrgID: f.org}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("original HTML member source gate broadened", err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	q := f.q.WithTx(tx)
	h, err := q.GetLegacySendOrgSourceReadHeaderV1(f.ctx, p)
	if err != nil || h == nil {
		t.Fatal("actual legacy query header unavailable", err)
	}
	read := generated.ReadLegacySendOrgSourceV1Params{RootDocumentID: p.RootDocumentID, DocumentID: p.DocumentID, OrgID: p.OrgID, ExpectedRootUpdatedAt: p.ExpectedRootUpdatedAt, ExpectedDocumentUpdatedAt: p.ExpectedDocumentUpdatedAt, ExpectedIsPdfSource: p.ExpectedIsPdfSource, ExpectedIsEnvelope: p.ExpectedIsEnvelope, ExpectedRootIsPdfSource: p.ExpectedRootIsPdfSource, ExpectedRootIsEnvelope: p.ExpectedRootIsEnvelope, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes}
	org, err := q.ReadLegacySendOrgSourceV1(f.ctx, read)
	if err != nil || org == nil || org.ID != f.org || org.Name != "Resolved fixture customer" {
		t.Fatal("actual legacy query changed source", err)
	}
	read.ExpectedRawTextBytes++
	if _, err := q.ReadLegacySendOrgSourceV1(f.ctx, read); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("stale organization tuple/size was expanded", err)
	}
	brand, err := q.GetLegacySendOrgBrandingSourceReadHeaderV1(f.ctx, generated.GetLegacySendOrgBrandingSourceReadHeaderV1Params(p))
	if err != nil || brand == nil {
		t.Fatal(err)
	}
	b := generated.ReadLegacySendOrgBrandingSourceV1Params{RootDocumentID: p.RootDocumentID, DocumentID: p.DocumentID, OrgID: p.OrgID, ExpectedRootUpdatedAt: p.ExpectedRootUpdatedAt, ExpectedDocumentUpdatedAt: p.ExpectedDocumentUpdatedAt, ExpectedIsPdfSource: p.ExpectedIsPdfSource, ExpectedIsEnvelope: p.ExpectedIsEnvelope, ExpectedRootIsPdfSource: p.ExpectedRootIsPdfSource, ExpectedRootIsEnvelope: p.ExpectedRootIsEnvelope, ExpectedCreatedAt: brand.CreatedAt, ExpectedUpdatedAt: brand.UpdatedAt, ExpectedSchemaVersion: brand.SchemaVersion, ExpectedRawTextBytes: brand.RawTextBytes}
	branding, err := q.ReadLegacySendOrgBrandingSourceV1(f.ctx, b)
	if err != nil || branding == nil || branding.PrimaryHex != "#123456" {
		t.Fatal("actual legacy branding source changed", err)
	}
	b.ExpectedSchemaVersion++
	if _, err := q.ReadLegacySendOrgBrandingSourceV1(f.ctx, b); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("stale branding schema was expanded", err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	response := f.submit("send", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
	if response.Code != http.StatusOK {
		t.Fatal("genuine root Send failed before terminal-state scope refusal", response.Code, response.Body.String())
	}
	if _, err := f.q.GetLegacySendOrgSourceReadHeaderV1(f.ctx, p); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("sent source was treated as draft preparation", err)
	}
}
