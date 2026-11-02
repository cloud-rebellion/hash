//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
)

func setupNativeCanonicalCollabE2E(t *testing.T, name string) (*ownedPublicReadFixtureV1, *generated.Document, string) {
	t.Helper()
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Collab = collab.NewHub(f.q)
	f.s.Collab.FlushEvery = 0
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		f.s.Collab.Shutdown(ctx)
	})
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	doc := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, "rest", cookie, map[string]any{
		"name": name, "source_kind": "blocks", "blocks_json": json.RawMessage(`{"version":1,"blocks":[]}`), "variables_json": map[string]string{},
	}), "rest")
	return q, doc, cookie
}

func assertNativeCanonicalCollabMeasurementsE2E(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) {
	t.Helper()
	var exact bool
	err := f.pool.QueryRow(f.ctx, `SELECT d.source_kind='blocks' AND d.status='draft'
 AND p.org_id=d.org_id AND p.html_origin_wire_bytes=0 AND p.html_current_wire_bytes=0
 AND p.variables_wire_bytes=COALESCE(octet_length(d.variables_json::text),0)
 AND r.org_id=d.org_id AND r.blocks_wire_bytes=COALESCE(octet_length(d.blocks_json::text),0)
 AND r.metadata_wire_bytes=COALESCE(octet_length(d.metadata::text),0)
 AND m.org_id=d.org_id AND m.report_wire_bytes=COALESCE(octet_length(d.metadata_redaction_report::text),0)
 AND p.measurement_server_version_num=current_setting('server_version_num')::integer
 AND r.measurement_server_version_num=p.measurement_server_version_num
 AND m.measurement_server_version_num=p.measurement_server_version_num
 AND isfinite(p.measured_at) AND isfinite(r.measured_at) AND isfinite(m.measured_at)
 FROM documents d JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id
 JOIN html_creation_response_sizes_v1 r ON r.document_id=d.id
 JOIN document_read_report_sizes_v1 m ON m.document_id=d.id
 WHERE d.id=$1 AND d.org_id=$2`, id, f.org).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("canonical save did not retain real current policy/response/report measurements", err)
	} //nolint:rawsql -- actual native output/cache oracle, never a producer
}

func nativeCanonicalCollabStateE2E(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_array(
 (SELECT row_to_json(d) FROM documents d WHERE id=$1),
 (SELECT row_to_json(g) FROM collab_document_generations g WHERE document_id=$1),
 (SELECT row_to_json(s) FROM collab_doc_states s WHERE document_id=$1),
 (SELECT row_to_json(g) FROM collab_state_generations g WHERE document_id=$1),
 (SELECT row_to_json(p) FROM document_signing_policy_sizes_v1 p WHERE document_id=$1),
 (SELECT row_to_json(r) FROM html_creation_response_sizes_v1 r WHERE document_id=$1),
 (SELECT row_to_json(m) FROM document_read_report_sizes_v1 m WHERE document_id=$1),
 (SELECT jsonb_agg(e ORDER BY created_at,id) FROM events e WHERE document_id=$1))::text`, id).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state //nolint:rawsql -- exact synthetic rollback/no-effect snapshot only
}

func TestNativeCanonicalCollabEmptyThenTypedSaveKeepsSendPreflightMeasurementsE2E(t *testing.T) {
	for _, initialEmpty := range []bool{false, true} {
		t.Run(fmt.Sprintf("initial_empty_%t", initialEmpty), func(t *testing.T) {
			q, doc, cookie := setupNativeCanonicalCollabE2E(t, "Native empty and typed canonical save")
			f := q.f
			peer := canonicalSavePeer{id: "native-canonical-peer", user: f.user.ID}
			joined, err := f.s.Collab.Join(f.ctx, doc.ID, f.org, peer)
			if err != nil {
				t.Fatal(err)
			}
			steps := []bool{true}
			if initialEmpty {
				steps = []bool{false, true}
			}
			for _, typed := range steps {
				if typed {
					if err := joined.Room.HandleFrame(f.ctx, peer, []byte{0, 2, 1, 42}); err != nil {
						t.Fatal(err)
					}
				}
				cp, err := joined.Room.CaptureSaveCheckpoint(peer.ID())
				if err != nil {
					t.Fatal(err)
				}
				blocks := doc.BlocksJson
				if typed {
					blocks = json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Actual typed canonical clause"}]}`)
				}
				body := collabSaveInput{PeerID: peer.ID(), Checkpoint: hex.EncodeToString(cp.Token[:]), Generation: fmt.Sprint(cp.Generation), ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), BlocksJSON: blocks}
				w := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/collab/save", body)
				if w.Code != http.StatusOK {
					t.Fatalf("native canonical typed=%t save=%d %s", typed, w.Code, w.Body.String())
				}
				doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
				if err != nil {
					t.Fatal(err)
				}
				if typed && !strings.Contains(string(doc.BlocksJson), "Actual typed canonical clause") {
					t.Fatal("typed canonical source was not persisted")
				}
				state, err := f.q.GetCollabDocStateWithGeneration(f.ctx, doc.ID)
				if err != nil || !state.Generation.Valid || state.Generation.Int64 != cp.Generation+1 || len(state.YdocState) != len(cp.State) {
					t.Fatal("canonical source/replay/generation did not share the native commit", err)
				}
				assertNativeCanonicalCollabMeasurementsE2E(t, f, doc.ID)
			}
			before := nativeCanonicalCollabStateE2E(t, f, doc.ID)
			w := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/send", map[string]any{"lawful_basis": "contract"})
			// This deliberately recipient-free draft must reach its specific business
			// preflight, proving native source/policy admission before renderer or mail.
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), send.ErrNoRecipients.Error()) {
				t.Fatalf("saved native source did not reach exact Send recipient preflight=%d %s", w.Code, w.Body.String())
			}
			if nativeCanonicalCollabStateE2E(t, f, doc.ID) != before {
				t.Fatal("failed Send preflight changed actual source/history/cache/audit")
			}
			ownedPlainAssertDrainedV1(t, q)
		})
	}
}

func TestNativeCanonicalCollabAuditFaultRollsBackRoomSourceHistoryAndMeasurementsE2E(t *testing.T) {
	q, doc, cookie := setupNativeCanonicalCollabE2E(t, "Atomic canonical audit refusal")
	f := q.f
	peer := canonicalSavePeer{id: "native-canonical-rollback", user: f.user.ID}
	joined, err := f.s.Collab.Join(f.ctx, doc.ID, f.org, peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := joined.Room.HandleFrame(f.ctx, peer, []byte{0, 2, 1, 42}); err != nil {
		t.Fatal(err)
	}
	cp, err := joined.Room.CaptureSaveCheckpoint(peer.ID())
	if err != nil {
		t.Fatal(err)
	}
	before := nativeCanonicalCollabStateE2E(t, f, doc.ID)
	_, err = f.pool.Exec(f.ctx, `CREATE FUNCTION canonical_collab_fault691() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.document_id='`+doc.ID.String()+`'::uuid AND NEW.kind='document.updated' THEN RAISE EXCEPTION 'synthetic canonical audit fault' USING ERRCODE='P0001'; END IF; RETURN NEW; END$$; CREATE TRIGGER canonical_collab_fault691 BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION canonical_collab_fault691()`)
	if err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- isolated synthetic audit failure only
	body := collabSaveInput{PeerID: peer.ID(), Checkpoint: hex.EncodeToString(cp.Token[:]), Generation: fmt.Sprint(cp.Generation), ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), BlocksJSON: json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Must roll back with audit"}]}`)}
	w := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/collab/save", body)
	if w.Code != http.StatusInternalServerError || nativeCanonicalCollabStateE2E(t, f, doc.ID) != before {
		t.Fatalf("audit fault failed atomic canonical rollback=%d", w.Code)
	}
	fresh, err := joined.Room.CaptureSaveCheckpoint(peer.ID())
	if err != nil || fresh.Token != cp.Token || fresh.Generation != cp.Generation {
		t.Fatal("failed native transaction advanced actual room checkpoint", err)
	}
	if _, err = f.pool.Exec(f.ctx, "DROP TRIGGER canonical_collab_fault691 ON events; DROP FUNCTION canonical_collab_fault691()"); err != nil {
		t.Fatal(err)
	}
	w = ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/collab/save", body)
	if w.Code != http.StatusOK {
		t.Fatalf("same genuine checkpoint retry after known rollback=%d %s", w.Code, w.Body.String())
	}
	assertNativeCanonicalCollabMeasurementsE2E(t, f, doc.ID)
	// Native template/creation plus explicit M95 preparation own two observers.
	ownedCreationAssertDrainedV1(t, q, 2)
}
