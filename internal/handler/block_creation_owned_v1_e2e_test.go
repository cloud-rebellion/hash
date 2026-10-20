//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"net/http"
	"testing"
	"time"
)

// Real REST/MCP middleware, first-party native sessions and PostgreSQL caches;
// this fixture's renderer/storage/identity remain explicitly synthetic. No
// historical row repair, cap changes or premeasured fake document is involved.
func TestOwnedBlocksCreationActualRESTAndMCPFreshMeasurementsE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			ownedCreationPrepareProPlanV1(t, q)
			f := q.f
			credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			if transport == "mcp" {
				f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
				f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: versions.New(f.q), Billing: f.s.Billing, Send: f.s.Send, PDFCreationSessions: q.runtime.SessionsV1()})
				key, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
				credential = key.Plaintext
			}
			args := map[string]any{"name": "Fresh block contract", "source_kind": "blocks", "blocks_json": json.RawMessage("{\"version\":0,\"blocks\":[{\"type\":\"paragraph\",\"text\":\"Customer {{customer}}\"},{\"type\":\"signature_field\",\"attrs\":{\"recipient_role\":\"buyer\"}}]}"), "variables_json": map[string]string{"customer": "Original exact customer"}}
			response := submitDocumentCreationE2E(f, f.ctx, transport, credential, args)
			var doc generated.Document
			if transport == "rest" {
				if response.Code != http.StatusCreated {
					t.Fatalf("create=%d %s", response.Code, response.Body.String())
				}
				if err := json.Unmarshal(response.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
			} else {
				var rpc struct {
					Result struct {
						Content []struct{ Text string }
						IsError bool
					}
				}
				if err := json.Unmarshal(response.Body.Bytes(), &rpc); err != nil || rpc.Result.IsError || len(rpc.Result.Content) != 1 {
					t.Fatalf("MCP response %v %s", err, response.Body.String())
				}
				if err := json.Unmarshal([]byte(rpc.Result.Content[0].Text), &doc); err != nil {
					t.Fatal(err)
				}
			}
			if doc.ID == uuid.Nil {
				t.Fatal("actual document ID absent")
			}
			stored, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			tree, err := blocks.ParseCanonicalTree(stored.BlocksJson)
			if err != nil || len(tree.Blocks) != 2 || tree.Blocks[0].ID == "" || tree.Blocks[1].ID == "" || tree.Blocks[0].ID == tree.Blocks[1].ID {
				t.Fatalf("original generated canonical IDs not persisted: %v", err)
			}
			var policies, responses, reports, events, versionsCount int
			err = f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM document_signing_policy_sizes_v1 WHERE document_id=$1),(SELECT count(*) FROM html_creation_response_sizes_v1 WHERE document_id=$1),(SELECT count(*) FROM document_read_report_sizes_v1 WHERE document_id=$1),(SELECT count(*) FROM events e JOIN html_snapshot_event_payload_sizes_v1 s ON s.event_id=e.id WHERE e.document_id=$1),(SELECT count(*) FROM document_versions WHERE document_id=$1)", doc.ID).Scan(&policies, &responses, &reports, &events, &versionsCount)
			if err != nil {
				t.Fatal(err)
			}
			wantVersions := 0
			if transport == "mcp" {
				wantVersions = 1
			}
			if policies != 1 || responses != 1 || reports != 1 || events != 1 || versionsCount != wantVersions {
				t.Fatalf("fresh producer did not join original writes: policy=%d response=%d report=%d event=%d versions=%d", policies, responses, reports, events, versionsCount)
			}
			ownedCreationAssertDrainedV1(t, q, 2)
		})
	}
}
