//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A wrapper's own body is not rendered. Refusing promotion must preserve the
// populated agreement and all source caches/audit state, on every real boundary.
func TestOwnedEnvelopePromotionKeepsAgreementBodyE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp", "query"} {
		t.Run(transport, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			ownedCreationPrepareProPlanV1(t, q)
			f := q.f
			f.s.Envelopes = envelopes.New(f.q)
			credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			createTransport := transport
			if transport == "query" {
				createTransport = "rest"
			}
			if transport == "mcp" {
				f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
				f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: versions.New(f.q), Billing: f.s.Billing, Send: f.s.Send, Envelopes: f.s.Envelopes, PDFCreationSessions: q.runtime.SessionsV1()})
				key, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
				credential = key.Plaintext
			}
			doc := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, createTransport, credential, map[string]any{
				"name": "Main agreement must remain visible", "source_kind": "blocks",
				"blocks_json": map[string]any{"version": 1, "blocks": []any{map[string]any{"id": "terms", "type": "paragraph", "text": "These are the agreed contractual terms."}}},
			}), createTransport)
			before := authoringMCPStateE2E(t, f)
			cache := ownedBlockCacheStateV1(t, f, doc.ID)
			if transport == "query" {
				_, err := f.q.MarkAsEnvelope(f.ctx, generated.MarkAsEnvelopeParams{ID: doc.ID, OrgID: f.org})
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("populated SQL promotion error=%v", err)
				}
			} else {
				response := ownedTopologyCallV1(t, f, transport, credential, "promote", doc.ID, uuid.Nil, nil)
				if transport == "mcp" {
					if got := fieldMCPTextE2E(t, response, true); got != "document not eligible for envelope mutation" {
						t.Fatalf("populated MCP promotion=%q", got)
					}
				} else if response.Code != http.StatusNotFound {
					t.Fatalf("populated promotion=%d %s", response.Code, response.Body.String())
				}
			}
			if authoringMCPStateE2E(t, f) != before || ownedBlockCacheStateV1(t, f, doc.ID) != cache {
				t.Fatal("refusal changed the agreement, topology, source caches or audit")
			}
			empty := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, createTransport, credential, map[string]any{"name": "Empty package wrapper", "source_kind": "blocks"}), createTransport)
			if transport == "query" {
				row, err := f.q.MarkAsEnvelope(f.ctx, generated.MarkAsEnvelopeParams{ID: empty.ID, OrgID: f.org})
				if err != nil || row == nil || !row.IsEnvelope {
					t.Fatalf("empty SQL promotion=%v", err)
				}
			} else {
				ownedTopologySucceededV1(t, ownedTopologyCallV1(t, f, transport, credential, "promote", empty.ID, uuid.Nil, nil), transport)
			}
			ownedCreationAssertDrainedV1(t, q, 2)
		})
	}
}
