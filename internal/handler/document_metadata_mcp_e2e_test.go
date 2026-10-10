//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This is real PostgreSQL and /mcp middleware/dispatch coverage with synthetic
// credentials. The shared sizable-design fixture uses the source-built PDF
// worker and synthetic renderer/storage peers; this is not capacity or live
// provider acceptance. Credential-use counters are outside the read snapshot.
func metadataMCPJSONE2E(t *testing.T, response *httptest.ResponseRecorder, dst any) {
	t.Helper()
	text := fieldMCPTextE2E(t, response, false)
	if len(text) > 64<<10 || strings.Contains(text, "Bounded synthetic approved layout.") {
		t.Fatal("MCP metadata response transferred an inline design")
	}
	if err := json.Unmarshal([]byte(text), dst); err != nil {
		t.Fatal("MCP metadata response was not valid JSON:", err)
	}
}

func mintMetadataDocumentKeyE2E(t *testing.T, f lifecycleAuthorizationFixture, documentID uuid.UUID) *auth.MintedKey {
	t.Helper()
	mint, err := auth.MintDocumentAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{
		DocumentID: documentID, OrgID: f.org, Name: "Synthetic metadata read boundary", Prefix: mint.Prefix,
		KeyHash: mint.Hash, Scopes: []string{"read"}, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	return mint
}

func seedMetadataRelatedRowsE2E(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document) {
	t.Helper()
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Name: "Metadata reader witness", Email: uuid.NewString() + "@metadata.test",
		MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	}); err != nil {
		t.Fatal(err)
	}
	if doc.SourceKind == "blocks" {
		if _, err := versions.New(f.q).Snapshot(f.ctx, versions.SnapshotInput{
			DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind,
			BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, Via: versions.ViaHuman,
			Summary: "Synthetic metadata identity witness",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDocumentMetadataMCPReadProjectionE2E(t *testing.T) {
	m := setupMetadataProjectionE2E(t)
	f := m.f
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{
		Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: f.s.Versions,
		Envelopes: envelopes.New(f.q), Billing: f.s.Billing, PublicURL: f.s.PublicURL,
	})
	orgKey, _ := mintAuthoringMCPE2E(t, f)
	docKey := mintMetadataDocumentKeyE2E(t, f, m.current.ID)
	seedMetadataRelatedRowsE2E(t, f, m.current)
	deleted := seedDocumentDeleteDraft(t, f.ctx, f.q, f.org, f.user.ID)
	seedMetadataRelatedRowsE2E(t, f, deleted)
	if err := f.q.DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: deleted.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	foreignOrg, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Foreign MCP metadata fixture", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	foreignUser, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Email: uuid.NewString() + "@metadata.test", Name: "Foreign synthetic owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := seedDocumentDeleteDraft(t, f.ctx, f.q, foreignOrg.ID, foreignUser.ID)
	seedMetadataRelatedRowsE2E(t, f, foreign)
	states := map[uuid.UUID][]byte{}
	for _, doc := range []*generated.Document{m.reviewed, m.current, m.legacy, m.static} {
		states[doc.ID] = metadataHistoryStateE2E(t, f, doc.ID)
	}
	events, renders, requests := metadataAuditCountE2E(t, f), len(m.renderer.sources()), m.storage.requests.Load()
	call := func(tool, key string, args map[string]any) *httptest.ResponseRecorder {
		return submitAuthoringMCPE2E(f, f.ctx, tool, key, args)
	}

	t.Run("document scoped named matches and confinement", func(t *testing.T) {
		for _, tc := range []struct {
			name, tool, query string
			count             int
		}{
			{"list bound document", "list_documents", "", 1},
			{"case insensitive name match", "search_documents", strings.ToUpper(m.current.Name), 1},
			{"missing name", "search_documents", "no-such-design-" + uuid.NewString(), 0},
			{"sibling name", "search_documents", m.static.Name, 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var out struct {
					Documents []*generated.Document `json:"documents"`
					Count     int                   `json:"count"`
				}
				metadataMCPJSONE2E(t, call(tc.tool, docKey.Plaintext, map[string]any{"query": tc.query}), &out)
				if out.Count != tc.count || len(out.Documents) != tc.count {
					t.Fatal("document-scoped list/search escaped its named match boundary")
				}
				for _, got := range out.Documents {
					want := *metadataFullDocumentE2E(t, f, m.current.ID)
					want.HtmlSourceJson, want.HtmlCurrentSourceJson = nil, nil
					gotJSON, gotErr := json.Marshal(got)
					wantJSON, wantErr := json.Marshal(&want)
					if gotErr != nil || wantErr != nil || !bytes.Equal(gotJSON, wantJSON) {
						t.Fatal("scoped metadata lost ordinary fields/current pins or exposed source JSON")
					}
				}
			})
		}
	})

	t.Run("related readers retain active tenant and document boundaries", func(t *testing.T) {
		for _, tc := range []struct {
			tool, key string
		}{
			{"list_recipients", "recipients"},
			{"get_document_events", "events"},
			{"list_document_versions", "versions"},
		} {
			t.Run(tc.tool, func(t *testing.T) {
				var out map[string]json.RawMessage
				metadataMCPJSONE2E(t, call(tc.tool, orgKey.Plaintext, map[string]any{"document_id": m.current.ID}), &out)
				var rows []map[string]json.RawMessage
				if err := json.Unmarshal(out[tc.key], &rows); err != nil || len(rows) == 0 {
					t.Fatal("active HTML document related reader lost its positive rows")
				}
				for _, row := range rows {
					var id string
					if err := json.Unmarshal(row["document_id"], &id); err != nil || id != m.current.ID.String() {
						t.Fatal("related metadata reader returned another document's row")
					}
					if tc.key == "versions" {
						if _, exists := row["html_source_json"]; exists {
							t.Fatal("MCP history exposed an inline authoring snapshot")
						}
					}
				}
				for _, target := range []*generated.Document{foreign, deleted} {
					if text := fieldMCPTextE2E(t, call(tc.tool, orgKey.Plaintext, map[string]any{"document_id": target.ID}), true); text != "document not found" {
						t.Fatal("foreign/deleted related metadata reader lost its document-not-found refusal")
					}
				}
				if text := fieldMCPTextE2E(t, call(tc.tool, docKey.Plaintext, map[string]any{"document_id": m.reviewed.ID}), true); !strings.Contains(text, "scoped") {
					t.Fatal("document token enumerated a sibling's related metadata")
				}
			})
		}
	})
	assertMetadataNoEffectsE2E(t, m, events, renders, requests, states)

	t.Run("envelope thin publication retains keys and ordered children", func(t *testing.T) {
		parent := seedDocumentDeleteDraft(t, f.ctx, f.q, f.org, f.user.ID)
		if _, err := f.q.MarkAsEnvelope(f.ctx, generated.MarkAsEnvelopeParams{ID: parent.ID, OrgID: f.org}); err != nil {
			t.Fatal(err)
		}
		for i, doc := range []*generated.Document{m.current, m.reviewed, m.static} {
			if _, err := f.q.AttachToEnvelope(f.ctx, generated.AttachToEnvelopeParams{
				ID: doc.ID, OrgID: f.org, ParentEnvelopeID: pgtype.UUID{Bytes: parent.ID, Valid: true}, EnvelopePosition: pgtype.Int4{Int32: int32(i + 1), Valid: true},
			}); err != nil {
				t.Fatal(err)
			}
		}
		check := func(tool string, args map[string]any, ids []uuid.UUID) {
			t.Helper()
			var out struct {
				Children []map[string]any `json:"children"`
				Count    int              `json:"count"`
			}
			metadataMCPJSONE2E(t, call(tool, orgKey.Plaintext, args), &out)
			if out.Count != len(ids) || len(out.Children) != len(ids) {
				t.Fatal("MCP envelope metadata changed its child count")
			}
			for i, id := range ids {
				doc := metadataFullDocumentE2E(t, f, id)
				want := map[string]any{"id": id.String(), "name": doc.Name, "status": doc.Status, "source_kind": doc.SourceKind,
					"is_envelope": doc.IsEnvelope, "created_at": doc.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
					"parent_envelope_id": parent.ID.String(), "envelope_position": float64(i + 1)}
				if !reflect.DeepEqual(out.Children[i], want) {
					t.Fatal("MCP envelope publication lost its existing keys or child order")
				}
			}
		}
		check("list_envelope_children", map[string]any{"envelope_id": parent.ID}, []uuid.UUID{m.current.ID, m.reviewed.ID, m.static.ID})
		if text := fieldMCPTextE2E(t, call("list_envelope_children", docKey.Plaintext, map[string]any{"envelope_id": parent.ID}), true); !strings.Contains(text, "scoped") {
			t.Fatal("document token read a sibling envelope's children")
		}
		check("reorder_envelope_children", map[string]any{"envelope_id": parent.ID, "child_id_order": []uuid.UUID{m.static.ID, m.reviewed.ID, m.current.ID}}, []uuid.UUID{m.static.ID, m.reviewed.ID, m.current.ID})
		check("list_envelope_children", map[string]any{"envelope_id": parent.ID}, []uuid.UUID{m.static.ID, m.reviewed.ID, m.current.ID})
		assertMetadataNoEffectsE2E(t, m, events+1, renders, requests, states)
		var count int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND actor_user_id=$2 AND payload_json->>'tool'='reorder_envelope_children'`, parent.ID, f.user.ID).Scan(&count); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- fixture-owned exact intended MCP reorder event
		if count != 1 {
			t.Fatal("MCP reorder lost its one original-actor audit event")
		}
	})
	// Explicit source retrieval remains authoritative after the thin reads.
	if !bytes.Equal(m.current.HtmlSourceJson, metadataFullDocumentE2E(t, f, m.current.ID).HtmlSourceJson) {
		t.Fatal("metadata reads/reorder discarded the retained original design")
	}
}
