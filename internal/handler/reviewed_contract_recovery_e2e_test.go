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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These cases moved from internal/sign so their baseline uses the actual
// template preview/approval, native HTML creation, PDF review and two-party
// Send/Sign producers. The same corruption matrix and before/after invariants
// remain. Renderer/storage are synthetic; this is not browser/provider proof.
var reviewedContractRecoveryCorruptions = []string{
	"mode_downgrade", "missing_party", "different_name", "different_email", "different_role",
	"replacement_party", "extra_recipient", "missing_signature", "misbound_signature", "missing_field",
}

func TestReviewedContractFinalizingRebuildRejectsDriftBeforeEvidenceE2E(t *testing.T) {
	for _, corruption := range reviewedContractRecoveryCorruptions {
		t.Run(corruption, func(t *testing.T) {
			f := newReviewedContractRecoveryE2E(t, false)
			corruptReviewedContractRecoveryE2E(t, f, corruption)
			assertReviewedContractRecoveryRefusedE2E(t, f, false)
		})
	}
}

func TestReviewedContractFinalizingResumeRejectsDriftBeforeEvidenceE2E(t *testing.T) {
	for _, corruption := range reviewedContractRecoveryCorruptions {
		t.Run(corruption, func(t *testing.T) {
			f := newReviewedContractRecoveryE2E(t, true)
			corruptReviewedContractRecoveryE2E(t, f, corruption)
			assertReviewedContractRecoveryRefusedE2E(t, f, true)
		})
	}
}

func TestReviewedContractFinalizationRecoveryCompletesBoundPartiesE2E(t *testing.T) {
	for _, withIntent := range []bool{false, true} {
		label := "rebuild"
		if withIntent {
			label = "resume"
		}
		t.Run(label, func(t *testing.T) {
			f := newReviewedContractRecoveryE2E(t, withIntent)
			before := reviewedContractHistoryE2E(t, f)
			rows, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); err != nil {
				t.Fatal(err)
			}
			f.assertCompleted(t, "reviewed_contract_"+label)
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
			if err != nil {
				t.Fatal(err)
			}
			current, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
			if err != nil || htmlsource.ValidateContractParties(doc, current) != nil {
				t.Fatalf("completed source lost its named recipients: %v", err)
			}
			if len(rows) != len(current) || rows[0].ID != current[0].ID || rows[1].ID != current[1].ID || before != reviewedContractHistoryE2E(t, f) {
				t.Fatal("recovery changed recipient bindings or immutable HTML history")
			}
			calls := f.storageRequests.Load()
			snapshot := reviewedContractRecoverySnapshotE2E(t, f)
			if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); err != nil {
				t.Fatal(err)
			}
			if f.storageRequests.Load() != calls || snapshot != reviewedContractRecoverySnapshotE2E(t, f) {
				t.Fatal("completed reviewed-contract retry changed evidence or publication state")
			}
		})
	}
}

type reviewedContractRecoveryFixtureE2E struct {
	native                            *ownedPublicReadFixtureV1
	ctx                               context.Context
	pool                              *pgxpool.Pool
	q                                 *generated.Queries
	engine                            *sign.Engine
	store                             *storage.Client
	orgID, docID                      uuid.UUID
	original                          *generated.Document
	names, tokens                     []string
	finalizationRenderStart           int
	storageRequests, rendererRequests atomic.Int64
	rendererFail, retentionFail       atomic.Bool
}

func newReviewedContractRecoveryE2E(t *testing.T, withIntent bool) *reviewedContractRecoveryFixtureE2E {
	t.Helper()
	native := newOwnedPublicReadFixtureV1(t)
	f := &reviewedContractRecoveryFixtureE2E{native: native, ctx: native.f.ctx, pool: native.f.pool, q: native.f.q, engine: native.f.s.Sign, orgID: native.f.org}
	objects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.storageRequests.Add(1)
		if f.retentionFail.Load() && (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.URL.Path, "/final-") {
			// The interruption is admitted only after the original native Stage has
			// durably committed the actual artifact intent. Initial PUTs still work.
			var staged bool
			if err := f.pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM document_finalization_intents WHERE org_id=$1 AND document_id=$2)", f.orgID, f.docID).Scan(&staged); err != nil {
				http.Error(w, "synthetic intent observation failed", http.StatusInternalServerError)
				return
			}
			if staged {
				http.Error(w, "synthetic post-intent evidence outage", http.StatusForbidden)
				return
			}
		}
		native.storagePeer.ServeHTTP(w, r)
	}))
	t.Cleanup(objects.Close)
	client, err := storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-reviewed-recovery", SecretKey: "synthetic-reviewed-recovery-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	f.store = client
	native.f.s.Storage, native.f.s.Send.Storage, native.f.s.Sign.Storage = client, client, client
	native.evidence.client = client
	renderer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.rendererRequests.Add(1)
		if f.rendererFail.Load() {
			http.Error(w, "synthetic renderer outage", http.StatusServiceUnavailable)
			return
		}
		native.renderer.ServeHTTP(w, r)
	}))
	t.Cleanup(renderer.Close)
	native.f.s.Sign.PDF = render.NewGotenberg(renderer.URL)
	// Preserve the original schema-2 reviewed contract profile. Schema-3 has
	// additional database immutability rules; its frozen layout is a separate
	// cohort and must not turn these deliberate recovery corruptions into
	// failures while constructing the requested damaged state.
	native.template = createHTMLContractDesignE2E(t, native.f, native.cookie)
	approveHTMLCreationTemplateE2E(t, native.f, native.template)
	doc, parties := native.createSentV1(t)
	f.docID, f.original = doc.ID, doc
	for _, party := range parties {
		f.names = append(f.names, party.Name)
		f.tokens = append(f.tokens, party.Token)
	}
	// Preview and document creation already render the printed party names.
	// Only later sources can establish the finalization renderer assertion.
	f.finalizationRenderStart = len(native.renderer.protocol.sources())
	if result, err := ordinaryPreparationSign249(t, native, parties[0].Token, parties[0].Name); err != nil || result == nil || result.Completed {
		t.Fatalf("first reviewed party result=%+v error=%v", result, err)
	}
	if withIntent {
		f.retentionFail.Store(true)
	} else {
		f.rendererFail.Store(true)
	}
	if result, err := ordinaryPreparationSign249(t, native, parties[1].Token, parties[1].Name); err != nil || result == nil || result.Completed {
		t.Fatalf("staged reviewed contract result=%+v error=%v", result, err)
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
	if err != nil || current == nil || current.Status != "finalizing" {
		t.Fatalf("reviewed fixture did not reach genuine finalizing: doc=%v error=%v", current, err)
	}
	_, err = f.q.GetDocumentFinalizationIntent(f.ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: f.docID, OrgID: f.orgID})
	if (withIntent && err != nil) || (!withIntent && !errors.Is(err, pgx.ErrNoRows)) {
		t.Fatalf("fixture intent boundary mismatch: withIntent=%v error=%v", withIntent, err)
	}
	f.retentionFail.Store(false)
	f.rendererFail.Store(false)
	return f
}

func assertReviewedContractRecoveryRefusedE2E(t *testing.T, f *reviewedContractRecoveryFixtureE2E, withIntent bool) {
	t.Helper()
	if withIntent {
		if _, err := f.q.GetDocumentFinalizationIntent(f.ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: f.docID, OrgID: f.orgID}); err != nil {
			t.Fatal("actual existing-intent resume stimulus missing", err)
		}
	}
	before := reviewedContractRecoverySnapshotE2E(t, f)
	renders, calls := f.rendererRequests.Load(), f.storageRequests.Load()
	// FinalizeStranded's finalizing branch enters the same genuine resume
	// workflow when an intent exists. This supported entry replaces the former
	// additional direct call to sign's unexported resume helper.
	if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); err == nil {
		t.Fatal("damaged reviewed contract finalized")
	}
	if f.storageRequests.Load() != calls || f.rendererRequests.Load() != renders || before != reviewedContractRecoverySnapshotE2E(t, f) {
		t.Fatalf("rejected recovery touched evidence, renderer or database: storageCalls=%d rendererCalls=%d", f.storageRequests.Load()-calls, f.rendererRequests.Load()-renders)
	}
}

func (f *reviewedContractRecoveryFixtureE2E) snapshot(t *testing.T) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
 'document',(SELECT to_jsonb(d) FROM documents d WHERE id=$1),
 'recipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM recipients r WHERE document_id=$1),
 'fields',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM document_fields f WHERE document_id=$1),
 'signatures',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signatures s WHERE document_id=$1),
 'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM events e WHERE document_id=$1),
 'outbox',(SELECT jsonb_agg(to_jsonb(ed) ORDER BY id) FROM email_deliveries ed WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1)),
 'ordinary_preparation',(SELECT to_jsonb(p) FROM document_ordinary_finalization_preparations_v1 p WHERE document_id=$1),
 'ordinary_outputs',(SELECT jsonb_agg(to_jsonb(o) ORDER BY kind) FROM document_ordinary_finalization_outputs_v1 o WHERE document_id=$1))::text`, f.docID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func (f *reviewedContractRecoveryFixtureE2E) assertCompleted(t *testing.T, label string) {
	t.Helper()
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
	if err != nil || doc == nil || doc.Status != "completed" {
		t.Fatal("reviewed recovery did not complete", err)
	}
	if doc.PdfStorageKey != f.original.PdfStorageKey || doc.PdfStorageVersionID != f.original.PdfStorageVersionID || !bytes.Equal(doc.PdfSha256, f.original.PdfSha256) {
		t.Fatal("recovery changed retained original PDF commitment")
	}
	type artifact struct {
		key, version string
		digest       []byte
	}
	artifacts := []artifact{{doc.FinalPdfKey.String, doc.FinalPdfVersionID.String, doc.FinalPdfSha}, {doc.AuditCertKey.String, doc.AuditCertVersionID.String, doc.AuditCertSha256}, {doc.AuditPayloadKey.String, doc.AuditPayloadVersionID.String, doc.AuditPayloadSha256}, {doc.AuditSignatureKey.String, doc.AuditSignatureVersionID.String, doc.AuditSignatureSha256}}
	bodies := make([][]byte, 0, 4)
	for _, a := range artifacts {
		if a.key == "" || a.version == "" || len(a.digest) != sha256.Size {
			t.Fatal("recovery omitted exact artifact pins")
		}
		body, err := f.store.GetVerifiedVersion(f.ctx, a.key, a.version, a.digest)
		if err != nil {
			t.Fatal("read exact completed artifact", err)
		}
		bodies = append(bodies, body)
	}
	finalPages, finalErr := sanitize.PageCountWithContext(f.ctx, bodies[0])
	source, sourceErr := f.store.GetVerifiedVersion(f.ctx, f.original.PdfStorageKey.String, f.original.PdfStorageVersionID.String, f.original.PdfSha256)
	sourcePages, pageErr := sanitize.PageCountWithContext(f.ctx, source)
	certPages, certErr := sanitize.PageCountWithContext(f.ctx, bodies[1])
	if finalErr != nil || sourceErr != nil || pageErr != nil || finalPages != sourcePages || finalPages < 1 || certErr != nil || certPages < 1 {
		t.Fatal("completed final/source/certificate PDF geometry or readability differs", finalErr, sourceErr, pageErr, certErr)
	}
	if !sign.Verify(f.engine.Signer.PublicKeyBase64(), string(bodies[2]), string(bodies[3])) {
		t.Fatal("detached certificate verification failed")
	}
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.orgID, PageLimit: 1000})
	if err != nil || len(events) < 2 || len(events) >= 1000 || events[len(events)-1].Kind != audit.KindDocumentCompleted {
		t.Fatal("completion ledger missing", err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	if result := verifier.Result(); !result.OK || !result.Complete {
		t.Fatalf("completion chain invalid: %+v", result)
	}
	head := events[len(events)-2]
	claims, err := render.NewCertificateEvidenceClaimsV1(doc, doc.FinalPdfSha, &generated.LatestEventChainHeadForOrgRow{RowHash: head.RowHash, CreatedAt: head.CreatedAt}, events[:len(events)-1])
	if err != nil || !strings.Contains(string(bodies[2]), claims.HTML()) {
		t.Fatal("signed certificate does not bind exact artifact and pre-completion ledger", err)
	}
	sources := f.native.renderer.protocol.sources()
	if len(sources) <= f.finalizationRenderStart {
		t.Fatal("completed recovery omitted a finalization render source")
	}
	rendered := strings.Join(sources[f.finalizationRenderStart:], "\n")
	for _, name := range f.names {
		if !strings.Contains(rendered, name) {
			t.Fatalf("final rendering omitted party %q", name)
		}
	}
	var signed, completed, mail int
	if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.signed'),
 (SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.completed'),
 (SELECT count(*) FROM email_deliveries WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1) OR to_email=(SELECT email FROM users WHERE id=(SELECT sender_id FROM documents WHERE id=$1)))`, f.docID).Scan(&signed, &completed, &mail); err != nil {
		t.Fatal(err)
	}
	if signed != len(f.names) || completed != 1 || mail != len(f.names)*2+1 {
		t.Fatalf("signed/completed/mail=%d/%d/%d", signed, completed, mail)
	}
	for _, token := range f.tokens {
		if unexpected, err := f.engine.LookupByToken(f.ctx, auth.HashMagicToken(token)); err == nil {
			_ = unexpected.CloseReadV1()
			t.Fatal("completed reviewed contract retained an active invitation")
		}
	}
	if directory := os.Getenv("HASH_E2E_ARTIFACT_DIR"); directory != "" {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		fields, err := f.q.ListFieldsByDocument(f.ctx, f.docID)
		if err != nil {
			t.Fatal(err)
		}
		recipients, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
		if err != nil {
			t.Fatal(err)
		}
		roles := make(map[uuid.UUID]*generated.Recipient)
		for _, recipient := range recipients {
			roles[recipient.ID] = recipient
		}
		var placements []map[string]any
		for _, field := range fields {
			owner := roles[uuid.UUID(field.RecipientID.Bytes)]
			if owner == nil {
				t.Fatal("completed field lost its named party")
			}
			placements = append(placements, map[string]any{"id": field.ID, "recipient_id": owner.ID, "role": owner.Role, "name": owner.Name, "type": field.Type,
				"page": field.Page, "x_pct": numericToFloat(field.XPct), "y_pct": numericToFloat(field.YPct), "w_pct": numericToFloat(field.WPct), "h_pct": numericToFloat(field.HPct)})
		}
		receipt, err := json.MarshalIndent(map[string]any{"document_id": f.docID, "organization_id": f.orgID,
			"source":       map[string]any{"key": f.original.PdfStorageKey.String, "version_id": f.original.PdfStorageVersionID.String, "sha256": fmt.Sprintf("%x", f.original.PdfSha256)},
			"final_sha256": fmt.Sprintf("%x", doc.FinalPdfSha), "certificate_sha256": fmt.Sprintf("%x", doc.AuditCertSha256), "public_key": f.engine.Signer.PublicKeyBase64(), "placements": placements}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, label+"-receipt.json"), receipt, 0600); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string][]byte{label + "-final.pdf": bodies[0], label + "-audit.pdf": bodies[1], label + "-payload.txt": bodies[2], label + "-signature.txt": bodies[3]} {
			if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func corruptReviewedContractRecoveryE2E(t *testing.T, f *reviewedContractRecoveryFixtureE2E, corruption string) {
	t.Helper()
	rows, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("corruption fixture recipients=%d error=%v", len(rows), err)
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, f.docID)
	if err != nil || len(fields) != 2 {
		t.Fatalf("corruption fixture fields=%d error=%v", len(fields), err)
	}
	// These deliberate database corruptions represent damaged recovery state;
	// ordinary API mutations already reject them under the shared parent lock.
	switch corruption {
	case "mode_downgrade":
		_, err = f.pool.Exec(f.ctx, `UPDATE documents SET requires_signature=false WHERE id=$1`, f.docID) //nolint:rawsql
	case "missing_party", "replacement_party":
		_, err = f.pool.Exec(f.ctx, `DELETE FROM recipients WHERE id=$1`, rows[1].ID) //nolint:rawsql
		if err == nil && corruption == "replacement_party" {
			_, hash, mintErr := auth.MintMagicToken()
			if mintErr != nil {
				t.Fatal(mintErr)
			}
			// The production query correctly refuses creation after draft. Seed
			// a fresh UUID directly to simulate only this damaged recovery row.
			tag, insertErr := f.pool.Exec(f.ctx, `INSERT INTO recipients
				(document_id,role,email,name,order_index,magic_token_hash,magic_token_expires_at,locale)
				SELECT id,$3,$4,$5,$6,$7,$8,$9 FROM documents WHERE id=$1 AND org_id=$2 AND status='finalizing'`,
				f.docID, f.orgID, rows[1].Role, rows[1].Email, rows[1].Name, rows[1].OrderIndex, hash,
				time.Now().Add(time.Hour), rows[1].Locale) //nolint:rawsql -- deliberate isolated recovery corruption
			err = insertErr
			if err == nil && tag.RowsAffected() != 1 {
				err = errors.New("replacement recovery recipient was not inserted")
			}
		}
	case "different_name":
		_, err = f.pool.Exec(f.ctx, `UPDATE recipients SET name='Different recovery representative' WHERE id=$1`, rows[1].ID) //nolint:rawsql
	case "different_email":
		_, err = f.pool.Exec(f.ctx, `UPDATE recipients SET email='different-recovery@example.test' WHERE id=$1`, rows[1].ID) //nolint:rawsql
	case "different_role":
		_, err = f.pool.Exec(f.ctx, `UPDATE recipients SET role='signer' WHERE id=$1`, rows[1].ID) //nolint:rawsql
	case "extra_recipient":
		_, hash, mintErr := auth.MintMagicToken()
		if mintErr != nil {
			t.Fatal(mintErr)
		}
		// Bypass only fixture seeding; production recipient creation remains
		// draft-only and must never admit this extra finalizing participant.
		tag, insertErr := f.pool.Exec(f.ctx, `INSERT INTO recipients
			(document_id,role,email,name,order_index,magic_token_hash,magic_token_expires_at,locale)
			SELECT id,$3,$4,$5,$6,$7,$8,$9 FROM documents WHERE id=$1 AND org_id=$2 AND status='finalizing'`,
			f.docID, f.orgID, "approver", "extra-recovery@example.test", "Unexpected recovery person", int32(2), hash,
			time.Now().Add(time.Hour), "en") //nolint:rawsql -- deliberate isolated recovery corruption
		err = insertErr
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("extra recovery recipient was not inserted")
		}
	case "missing_signature":
		_, err = f.pool.Exec(f.ctx, `DELETE FROM signatures WHERE document_id=$1 AND recipient_id=$2`, f.docID, rows[1].ID) //nolint:rawsql
	case "misbound_signature":
		var other uuid.UUID
		for _, field := range fields {
			if uuid.UUID(field.RecipientID.Bytes) != rows[1].ID {
				other = field.ID
			}
		}
		_, err = f.pool.Exec(f.ctx, `UPDATE signatures SET field_id=$3 WHERE document_id=$1 AND recipient_id=$2`, f.docID, rows[1].ID, other) //nolint:rawsql
	case "missing_field":
		_, err = f.pool.Exec(f.ctx, `DELETE FROM document_fields WHERE document_id=$1 AND recipient_id=$2`, f.docID, rows[1].ID) //nolint:rawsql
	default:
		t.Fatalf("unknown fixture corruption %q", corruption)
	}
	if err != nil {
		t.Fatalf("seed corruption %s: %v", corruption, err)
	}
}

func reviewedContractHistoryE2E(t *testing.T, f *reviewedContractRecoveryFixtureE2E) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'materializations',(SELECT jsonb_agg(to_jsonb(m) ORDER BY sequence) FROM html_document_materializations m WHERE document_id=$1),
		'snapshots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM html_document_materialization_snapshots s WHERE document_id=$1))::text`, f.docID).Scan(&state); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	return state
}

func reviewedContractRecoverySnapshotE2E(t *testing.T, f *reviewedContractRecoveryFixtureE2E) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'intent',(SELECT to_jsonb(i) FROM document_finalization_intents i WHERE document_id=$1),
		'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM document_versions v WHERE document_id=$1),
		'reminders',(SELECT to_jsonb(r) FROM reminders r WHERE document_id=$1),
		'outbox',(SELECT jsonb_agg(to_jsonb(ed) ORDER BY id) FROM email_deliveries ed
			WHERE position($1::text in html_body)>0 OR to_email=(SELECT email FROM users WHERE id=(SELECT sender_id FROM documents WHERE id=$1))))::text`, f.docID).Scan(&state); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	return strings.Join([]string{f.snapshot(t), reviewedContractHistoryE2E(t, f), state}, "\n")
}
