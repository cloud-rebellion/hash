//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/mcp"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// This journey uses public actual creators/topology/recipients and real native
// Send/Sign owners. The existing local renderer/storage protocol peers are
// synthetic; no Object Lock, layout fidelity or deployed capacity is claimed.
// It never inserts/repairs a read-size cache or fabricates a source/Tx receipt.
func TestOwnedBlockEnvelopeSendAndTwoPartyEvidenceE2E(t *testing.T) {
	testOwnedBlockEnvelopeSendAndTwoPartyEvidence165V1(t, false)
}

// These real MCP journeys keep the original direct/component controls above
// and below, while exercising production Billing/EIDAS and nested child roles.
func TestOwnedBlockEnvelopeMCPMockSubscriptionE2E(t *testing.T) {
	testOwnedBlockEnvelopeSendAndTwoPartyEvidence165V1(t, false, ownedEnvelopeMCPMock165V1)
}

func TestOwnedBlockEnvelopeMCPOperatorProE2E(t *testing.T) {
	testOwnedBlockEnvelopeSendAndTwoPartyEvidence165V1(t, false, ownedEnvelopeMCPOperator165V1)
}

type ownedEnvelopeMCPProfile165V1 uint8

const (
	ownedEnvelopeMCPMock165V1 ownedEnvelopeMCPProfile165V1 = iota + 1
	ownedEnvelopeMCPOperator165V1
)

func TestOwnedBlockEnvelopeCommentFinalizationAndFrozenEvidenceE2E(t *testing.T) {
	testOwnedBlockEnvelopeSendAndTwoPartyEvidence165V1(t, true)
}

func testOwnedBlockEnvelopeSendAndTwoPartyEvidence165V1(t *testing.T, commentBoundary bool, profile ...ownedEnvelopeMCPProfile165V1) {
	t.Helper()
	if len(profile) > 1 || len(profile) == 1 && profile[0] != ownedEnvelopeMCPMock165V1 && profile[0] != ownedEnvelopeMCPOperator165V1 {
		t.Fatal("unsupported explicit envelope MCP profile")
	}
	fullMCP := len(profile) == 1
	var q *ownedPublicReadFixtureV1
	if fullMCP {
		// Chosen before fixture DB/pool/runtime birth. Global128 and every
		// byte, DB, SQL, provider and physical worker limit stay unchanged.
		limits := workguard.LimitsV1{
			Global:       workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1},
			Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1},
			MaxGrants:    128, MaxOrganisationGrants: 96,
		}
		q = newOwnedPublicReadFixtureAllocated257dV1(t, true, limits)
	} else {
		q = newOwnedPublicReadFixtureV1(t)
	}
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Envelopes = envelopes.New(f.q)
	f.s.Send.Envelopes = f.s.Envelopes
	f.s.Sign.Storage = f.s.Storage
	f.s.Sign.EnvelopeChildren = func(ctx context.Context, doc *generated.Document) ([]*generated.Document, error) {
		if doc == nil || !doc.IsEnvelope {
			return nil, nil
		}
		return f.s.Envelopes.Children(ctx, doc.ID, doc.OrgID)
	}
	var callMCP func(string, map[string]any) json.RawMessage
	if fullMCP {
		// Operator mode keeps the fixture's genuinely measured Pro entitlement.
		// Mock mode matches the actual supported browser subscription seed.
		if profile[0] == ownedEnvelopeMCPMock165V1 {
			// Match browser CI's actual supported development subscription. The
			// unlimited enterprise plan is deliberately invalid in operator mode.
			f.s.Billing = billing.New(f.q, billing.MockProvider{}, f.s.PublicURL, f.s.PublicURL+"/webhooks/billing/mock")
			var enterprise uuid.UUID
			if err := f.pool.QueryRow(f.ctx, "SELECT id FROM billing_plans WHERE slug='enterprise'").Scan(&enterprise); err != nil || enterprise == uuid.Nil {
				t.Fatal("actual enterprise catalog identity unavailable", err)
			} //nolint:rawsql -- fixed scalar identity, never a catalog body/cache write
			measured, err := q.runtime.SessionsV1().ControlledMeasurePlanSourceV1(f.ctx, enterprise)
			if measured != nil {
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := measured.CloseV1(cleanup); err != nil {
						t.Error("enterprise source cleanup", err)
					}
				})
			}
			if err != nil || measured == nil {
				t.Fatal("genuine enterprise catalog measurement failed", err)
			}
			receipt, err := measured.ReceiptV1()
			if err != nil || receipt.Kind != "plan" || receipt.SourceID != enterprise || receipt.OrgID != uuid.Nil || receipt.WireBytes <= 0 || receipt.ServerVersionNum != 160015 || !receipt.CreatedAt.Valid || !receipt.MeasuredAt.Valid {
				t.Fatal("enterprise catalog receipt differs", err)
			}
			measured.CloseConsumerV1()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = measured.CloseV1(cleanup)
			cancel()
			if err != nil {
				t.Fatal("enterprise source owner did not retire", err)
			}
			// Same real row/period/provider as the checked-in browser CI seed;
			// this grants no operator exemption and fabricates no measured source.
			now := time.Now().UTC().Truncate(time.Microsecond)
			end := pgtype.Timestamptz{Time: now.Add(24 * time.Hour), Valid: true}
			subscription, err := f.q.UpsertOrgSubscription(f.ctx, generated.UpsertOrgSubscriptionParams{OrgID: f.org, PlanID: enterprise, Provider: "mock", Status: "trialing", CurrentPeriodStart: pgtype.Timestamptz{Time: now, Valid: true}, CurrentPeriodEnd: end, TrialEndsAt: end})
			if err != nil || subscription == nil || subscription.ID == uuid.Nil || subscription.OrgID != f.org || subscription.PlanID != enterprise || subscription.Provider != "mock" || subscription.Status != "trialing" || !subscription.CurrentPeriodEnd.Valid || !subscription.CurrentPeriodEnd.Time.Equal(end.Time) {
				t.Fatal("actual browser enterprise subscription differs", err)
			}
		}
		f.s.Send.Billing = f.s.Billing
		f.s.Send.EIDAS = eidas.New(f.q)
		f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
		f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Send: f.s.Send, Versions: f.s.Versions, Envelopes: f.s.Envelopes, Billing: f.s.Billing, Storage: f.s.Storage, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: f.s.PublicURL})
		mint, err := auth.MintAPIKey()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, Name: "Synthetic exact browser envelope", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"read", "write:authoring", "write:workflow"}}); err != nil {
			t.Fatal(err)
		}
		callMCP = func(tool string, args map[string]any) json.RawMessage {
			response := submitAuthoringMCPE2E(f, f.ctx, tool, mint.Plaintext, args)
			return json.RawMessage(fieldMCPTextE2E(t, response, false))
		}
	}
	create := func(name, role string) uuid.UUID {
		tree := map[string]any{"version": 1, "blocks": []any{}}
		if role != "" {
			tree["blocks"] = []any{map[string]any{"id": "terms-" + role, "type": "paragraph", "text": "Approved " + role + " terms for {{company}}."}, map[string]any{"id": "signature-" + role, "type": "signature_field", "attrs": map[string]any{"recipient_role": role}}}
		}
		payload, err := json.Marshal(map[string]any{"name": name, "source_kind": "blocks", "blocks_json": tree, "variables_json": map[string]string{"company": "Synthetic family company"}})
		if err != nil {
			t.Fatal(err)
		}
		w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents", string(payload), q.cookie)
		if w.Code != http.StatusCreated {
			t.Fatalf("actual block creator=%d %s", w.Code, w.Body.String())
		}
		var result struct{ ID uuid.UUID }
		if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.ID == uuid.Nil {
			t.Fatal("actual creator omitted document", err)
		}
		return result.ID
	}
	var root uuid.UUID
	var children []uuid.UUID
	if fullMCP {
		unique := "envelope-sign-" + uuid.NewString()
		createChild := func(name string, tree map[string]any) uuid.UUID {
			raw := callMCP("create_document", map[string]any{"name": name, "source_kind": "blocks", "blocks_json": tree})
			var row struct{ ID uuid.UUID }
			if err := json.Unmarshal(raw, &row); err != nil || row.ID == uuid.Nil {
				t.Fatal("actual browser child creator omitted identity", err)
			}
			return row.ID
		}
		childA := createChild("Envelope MSA "+unique, map[string]any{"version": 1, "blocks": []any{
			map[string]any{"id": "msa-proof", "type": "paragraph", "text": "ENVELOPE MSA CONTENT " + unique},
			map[string]any{"id": "msa-signer", "type": "signature_field", "attrs": map[string]any{"recipient_role": "signer"}},
		}})
		childB := createChild("Envelope DPA "+unique, map[string]any{"version": 1, "blocks": []any{
			map[string]any{"id": "dpa-proof", "type": "paragraph", "text": "ENVELOPE DPA CONTENT " + unique},
			map[string]any{"id": "dpa-approval-callout", "type": "callout", "attrs": map[string]any{"tone": "info"}, "content": []any{
				map[string]any{"id": "dpa-approver", "type": "signature_field", "attrs": map[string]any{"recipient_role": "approver"}},
			}},
		}})
		children = []uuid.UUID{childA, childB}
		var envelope struct{ ID uuid.UUID }
		if err := json.Unmarshal(callMCP("create_envelope", map[string]any{"name": "Envelope signing proof " + unique, "child_ids": children}), &envelope); err != nil || envelope.ID == uuid.Nil {
			t.Fatal("actual browser MCP envelope creator omitted identity", err)
		}
		root = envelope.ID
		for _, role := range []string{"signer", "approver"} {
			name := "Envelope Signer"
			if role == "approver" {
				name = "Envelope Approver"
			}
			callMCP("add_recipient", map[string]any{"document_id": root, "role": role, "email": role + "-" + unique + "@example.com", "name": name})
		}
		rootDoc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
		var shell struct {
			Blocks []json.RawMessage `json:"blocks"`
		}
		if err != nil || rootDoc == nil || !rootDoc.IsEnvelope || rootDoc.ParentEnvelopeID.Valid || json.Unmarshal(rootDoc.BlocksJson, &shell) != nil || len(shell.Blocks) != 0 {
			t.Fatal("actual MCP envelope is not a genuine empty root", err)
		}
	} else {
		root = create("Owned envelope", "")
		children = []uuid.UUID{create("Buyer terms", "buyer"), create("Seller terms", "seller")}
		base := "/api/v1/documents/" + root.String()
		if w := submitSessionOperationE2E(f.s, http.MethodPost, base+"/promote-to-envelope", "{}", q.cookie); w.Code != http.StatusOK {
			t.Fatalf("actual promote=%d %s", w.Code, w.Body.String())
		}
		for i, child := range children {
			raw := fmt.Sprintf("{\"child_id\":\"%s\",\"position\":%d}", child, i+1)
			if w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/envelopes/"+root.String()+"/attach", raw, q.cookie); w.Code != http.StatusOK {
				t.Fatalf("actual attach=%d %s", w.Code, w.Body.String())
			}
		}
		for i, role := range []string{"buyer", "seller"} {
			raw, _ := json.Marshal(map[string]any{"email": role + "@family.example.test", "name": "Synthetic " + role, "role": role, "order_index": i, "locale": "en"})
			if w := submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", string(raw), q.cookie); w.Code != http.StatusCreated {
				t.Fatalf("actual family recipient=%d %s", w.Code, w.Body.String())
			}
		}
	}
	original := make([]*generated.Document, 0, len(children))
	for _, id := range children {
		d, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		original = append(original, d)
		if d.SourceKind != "blocks" || len(d.HtmlSourceJson) != 0 || d.PdfStorageKey.Valid {
			t.Fatal("fixture introduced pre-send HTML/PDF")
		}
	}
	actor := sendengine.Actor{OrgID: f.org, UserID: &f.user.ID, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	var err error
	var sent sendengine.SendResult
	if fullMCP {
		// Only a public response view is decoded here. The real MCP dispatcher
		// retains/closes the actual Send result owner through response writing.
		raw := callMCP("send_document", map[string]any{"document_id": root, "lawful_basis": "contract"})
		var outcome struct {
			DocumentID uuid.UUID `json:"document_id"`
			sendengine.SendResult
		}
		if err = json.Unmarshal(raw, &outcome); err != nil || outcome.DocumentID != root {
			t.Fatal("actual MCP Send outcome is not this envelope", err)
		}
		sent = outcome.SendResult
	} else {
		sent, err = f.s.Send.Send(f.ctx, actor, root)
	}
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatalf("actual owned family Send=%+v err=%v", sent, err)
	}
	links := sent.Links
	if fullMCP {
		// Match the browser's explicit signer-then-approver interaction order;
		// these are the unchanged actual public links, never minted test data.
		links = make([]sendengine.SignLink, 0, 2)
		for _, role := range []string{"signer", "approver"} {
			for _, link := range sent.Links {
				if link.Role == role {
					links = append(links, link)
				}
			}
		}
		if len(links) != 2 || links[0].Role != "signer" || links[1].Role != "approver" {
			t.Fatal("actual browser role links differ")
		}
	}
	parties := make([]signerBrowserPartyE2E, 0, len(links))
	for _, link := range links {
		u, err := url.Parse(link.URL)
		if err != nil {
			t.Fatal(err)
		}
		parties = append(parties, signerBrowserPartyE2E{Token: strings.TrimPrefix(u.Path, "/sign/"), RecipientID: link.RecipientID, Name: link.Name, Role: link.Role})
	}
	sent.CloseConsumerV1()
	q.assertObserversOnlyV1(t)
	rootDoc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
	if err != nil || rootDoc.Status != "sent" {
		t.Fatal("actual root send not committed", err)
	}
	for i, id := range children {
		d, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
		if err != nil || d.Status != "sent" || !d.EvidenceVersionPinsRequired || d.SentAt != rootDoc.SentAt || d.Article13NoticeEpochAt != rootDoc.Article13NoticeEpochAt || d.Article13NoticeSchema != rootDoc.Article13NoticeSchema || !d.Article13NoticeEpochV61Committed {
			t.Fatal("child did not share exact durable root ceremony", err)
		}
		if !bytes.Equal(d.BlocksJson, original[i].BlocksJson) || !bytes.Equal(d.VariablesJson, original[i].VariablesJson) {
			t.Fatal("family send changed original approved block content/values")
		}
	}
	for _, id := range append([]uuid.UUID{root}, children...) {
		b, err := f.q.GetDocumentBrandingOverride(f.ctx, id)
		if err != nil || branding.ValidateFrozenSnapshot(id, b) != nil {
			t.Fatal("family member missing genuine complete branding snapshot", err)
		}
		var count int
		if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM events WHERE org_id=$1 AND document_id=$2 AND kind='document.sent'", f.org, id).Scan(&count); err != nil || count != 1 {
			t.Fatal("member sent audit missing/duplicated", count, err)
		}
	} //nolint:rawsql -- read-only witness in owned disposable database
	if commentBoundary {
		ownedEnvelopeChildCommentBeforeFreeze165V1(t, q, children[0])
	}
	// A real terminal event hook and the real sign result independently borrow
	// publication output. The hook has no authority to release the result owner.
	completionGate := newOwnedPlainAuditGateV1(audit.KindDocumentCompleted)
	defer func() {
		completionGate.unblock()
		select {
		case <-completionGate.started:
			ownedPlainAwaitV1(t, completionGate.returned, "terminal completion hook cleanup")
		default:
		}
	}()
	subscribeCompletion := func() {
		f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, entry audit.Entry) {
			if entry.Kind != audit.KindDocumentCompleted || entry.DocumentID == nil || *entry.DocumentID != root {
				return
			}
			completionGate.eventID = id
			completionGate.entry = entry
			close(completionGate.started)
			<-completionGate.release
			close(completionGate.returned)
		})
	}
	if !commentBoundary {
		subscribeCompletion()
	}
	publicationSnapshot := func() string {
		t.Helper()
		var state string
		err := f.pool.QueryRow(f.ctx, `SELECT jsonb_agg(jsonb_build_object('id',d.id,'blocks',d.blocks_json,'variables',d.variables_json,'origin',d.html_source_json,'current',d.html_current_source_json,'metadata',d.metadata,'report_source',d.metadata_redaction_report,'policy',to_jsonb(p),'response',to_jsonb(r),'report',to_jsonb(s)) ORDER BY d.id)::text FROM documents d JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id JOIN html_creation_response_sizes_v1 r ON r.document_id=d.id JOIN document_read_report_sizes_v1 s ON s.document_id=d.id WHERE d.id=ANY($1::uuid[]) AND d.org_id=$2`, append([]uuid.UUID{root}, children...), f.org).Scan(&state)
		if err != nil || state == "" {
			t.Fatal("actual pre-publication source/cache witness unavailable", err)
		}
		return state
	} //nolint:rawsql -- immutable actual source and genuine existing cache oracle only
	var publicationBefore string
	var beforeResultParent, beforeResultDB int64
	var finalToken string
	for i, party := range parties {
		rc := q.lookupV1(t, party.Token)
		t.Cleanup(func() { _ = rc.CloseReadV1() }) // failed assertions still join the real borrower
		if i == len(parties)-1 {
			publicationBefore = publicationSnapshot()
			snapshot, err := q.runtime.SnapshotV1(f.org)
			if err != nil {
				t.Fatal(err)
			}
			beforeResultParent = snapshot.Global.ParentBytes
			beforeResultDB = snapshot.Global.DBStagingBytes
		}
		notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := signerArticle13NoticeEvidence(rc, notice)
		if err != nil {
			t.Fatal(err)
		}
		// Mutated public views cannot replace the actual original source/recipient.
		// Observe the real same-factory vector and committed row set around refusal.
		for _, which := range []string{"document", "recipient"} {
			copyContext := *rc
			if which == "document" {
				copyDocument := *rc.Document
				copyDocument.VariablesJson = append(bytes.Clone(rc.Document.VariablesJson), byte(32))
				copyContext.Document = &copyDocument
			} else {
				copyRecipient := *rc.Recipient
				copyRecipient.ID = uuid.New()
				copyContext.Recipient = &copyRecipient
			}
			before, err := q.runtime.SnapshotV1(f.org)
			if err != nil {
				t.Fatal(err)
			}
			pendingBefore := q.runtime.SessionsV1().PendingV1()
			var signaturesBefore int
			if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM signatures WHERE document_id=$1", root).Scan(&signaturesBefore); err != nil {
				t.Fatal(err)
			}
			expected := sign.ErrMagicLinkExpired
			if which == "recipient" {
				expected = sign.ErrInvalidNoticeEvidence
			}
			rejected, err := f.s.Sign.Sign(f.ctx, &copyContext, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic mutated signature view"})
			if rejected != nil || !errors.Is(err, expected) {
				t.Fatalf("mutated %s view authorized native signing: result=%+v err=%v", which, rejected, err)
			}
			after, err := q.runtime.SnapshotV1(f.org)
			if err != nil {
				t.Fatal(err)
			}
			pendingAfter := q.runtime.SessionsV1().PendingV1()
			var signaturesAfter int
			if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM signatures WHERE document_id=$1", root).Scan(&signaturesAfter); err != nil {
				t.Fatal(err)
			}
			if before.Global != after.Global || before.Organisation != after.Organisation || before.GlobalGrants != after.GlobalGrants || before.OrganisationGrants != after.OrganisationGrants || pendingBefore != pendingAfter || signaturesBefore != signaturesAfter {
				t.Fatal("mutated view changed actual source/SQL ownership or signature rows")
			}
		}
		input := sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic owned envelope qualifier"}
		var result *sign.Result
		if commentBoundary && i == len(parties)-1 {
			result, err = ownedEnvelopeCommentFinalizing165V1(t, q, root, children, rc, input, completionGate, subscribeCompletion)
		} else {
			result, err = f.s.Sign.Sign(f.ctx, rc, input)
		}
		if err != nil {
			t.Fatal("actual owned family signer", err)
		}
		if result.Completed != (i == len(parties)-1) {
			t.Fatal("family completed before every required party")
		}
		if result.Completed {
			ownedPlainAwaitV1(t, completionGate.started, "actual terminal root audit hook")
			if completionGate.entry.OrgID != f.org || completionGate.entry.ActorUserID != nil || completionGate.entry.RecipientID != nil || completionGate.eventID == uuid.Nil {
				t.Fatal("terminal hook lost original root/actor scope")
			}
			retained, err := q.runtime.SnapshotV1(f.org)
			if err != nil || retained.Global.ParentBytes <= beforeResultParent || retained.Global.DBStagingBytes <= beforeResultDB {
				t.Fatal("native publication source/output retired before result and hook last use", err)
			}
			completionGate.unblock()
			ownedPlainAwaitV1(t, completionGate.returned, "actual terminal hook return")
			q.reconcileV1(t)
			retained, err = q.runtime.SnapshotV1(f.org)
			if err != nil || retained.Global.ParentBytes <= beforeResultParent || retained.Global.DBStagingBytes <= beforeResultDB {
				t.Fatal("hook return released the independently retained publication result", err)
			}
			if publicationSnapshot() != publicationBefore {
				t.Fatal("terminal scalar publication changed original JSON/source or M91/M92/M93")
			}
			u, err := url.Parse(result.FinalPDFURL)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) != 3 || parts[0] != "sign" || parts[2] != "final-pdf" {
				t.Fatal("unexpected actual family final capability")
			}
			finalToken = parts[1]
		}
		if err = rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		// The user hook signal precedes audit.Logger's actual lastUse defer.
		// Observe the real native/coordinator drain before the unchanged exact
		// observer and all-pending oracle; elapsed time alone grants no credit.
		ownedPlainAssertDrainedV1(t, q)
	}
	var completionEvents int
	var measured bool
	err = f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,COALESCE(bool_and(m.event_id IS NOT NULL AND m.org_id=e.org_id AND m.document_id=e.document_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer AND e.actor_user_id IS NULL AND e.recipient_id IS NULL AND p->>'final_pdf_key'=d.final_pdf_key AND p->>'final_pdf_sha256'=encode(d.final_pdf_sha,'hex') AND p->>'final_pdf_version_id'=d.final_pdf_version_id AND p->>'audit_cert_key'=d.audit_cert_key AND p->>'audit_cert_sha256'=encode(d.audit_cert_sha256,'hex') AND p->>'audit_cert_version_id'=d.audit_cert_version_id AND p->>'audit_payload_key'=d.audit_payload_key AND p->>'audit_payload_sha256'=encode(d.audit_payload_sha256,'hex') AND p->>'audit_payload_version_id'=d.audit_payload_version_id AND p->>'audit_signature_key'=d.audit_signature_key AND p->>'audit_signature_sha256'=encode(d.audit_signature_sha256,'hex') AND p->>'audit_signature_version_id'=d.audit_signature_version_id),false) FROM events e JOIN documents d ON d.id=e.document_id AND d.org_id=e.org_id CROSS JOIN LATERAL (SELECT convert_from(e.payload_hashed,'UTF8')::jsonb AS p) payload LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.org_id=$1 AND e.document_id=ANY($2::uuid[]) AND e.kind='document.completed'`, f.org, append([]uuid.UUID{root}, children...)).Scan(&completionEvents, &measured)
	if err != nil || completionEvents != 3 || !measured {
		t.Fatal("terminal root/children lack intrinsic M94 and exact four-artifact payload tuple", completionEvents, err)
	} //nolint:rawsql -- committed real terminal events and actual measured/legal tuple only
	completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
	if err != nil || completed.Status != "completed" {
		t.Fatal("family root not completed", err)
	}
	type artifact struct {
		key, version pgtype.Text
		digest       []byte
	}
	var verified [][]byte
	for _, a := range []artifact{{completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha}, {completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256}, {completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256}, {completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256}} {
		if !a.key.Valid || !a.version.Valid || a.version.String == "" || len(a.digest) != sha256.Size {
			t.Fatal("family completion missing artifact pins")
		}
		body, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, a.key.String, a.digest, a.version)
		if err != nil {
			t.Fatal(err)
		}
		verified = append(verified, body)
	}
	if !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(verified[2]), string(verified[3])) {
		t.Fatal("family detached evidence signature invalid")
	}
	for _, id := range children {
		child, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
		if err != nil || child.Status != "completed" || child.FinalPdfKey != completed.FinalPdfKey || child.FinalPdfVersionID != completed.FinalPdfVersionID || !bytes.Equal(child.FinalPdfSha, completed.FinalPdfSha) || child.AuditCertKey != completed.AuditCertKey || child.AuditCertVersionID != completed.AuditCertVersionID || !bytes.Equal(child.AuditCertSha256, completed.AuditCertSha256) || child.AuditPayloadKey != completed.AuditPayloadKey || child.AuditPayloadVersionID != completed.AuditPayloadVersionID || !bytes.Equal(child.AuditPayloadSha256, completed.AuditPayloadSha256) || child.AuditSignatureKey != completed.AuditSignatureKey || child.AuditSignatureVersionID != completed.AuditSignatureVersionID || !bytes.Equal(child.AuditSignatureSha256, completed.AuditSignatureSha256) {
			t.Fatal("completed child did not inherit exact family artifacts", err)
		}
	}
	if finalToken == "" {
		t.Fatal("family final capability absent")
	}
	if w := q.requestV1(finalToken, "/final-pdf"); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), verified[0]) {
		t.Fatalf("actual family final download=%d", w.Code)
	}
	q.assertObserversOnlyV1(t)
	if commentBoundary {
		ownedEnvelopeChildFrozenRefusal165V1(t, q, root, children)
	}
}
