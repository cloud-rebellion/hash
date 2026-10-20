//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Every row and measurement comes from actual public intake/native field/Send
// writers. Send first creates a valid single-signer ordinary-PDF ceremony. Only
// afterward, genuine scalar assignment changes model historical/invalid field
// data for the original GET own+NULL/foreign exclusion rule. These changes give
// no Send/signing authority and never replace source/PDF/status/token/cache pins.
func ownedFieldReadVisibility182V1(t *testing.T, q *ownedPublicReadFixtureV1, option string) (*generated.Document, string, map[uuid.UUID]string) {
	t.Helper()
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Sign.Storage = f.s.Storage
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Measured field visibility")))
	var created struct {
		Document  documentResponse `json:"document"`
		PageCount int              `json:"page_count"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.PageCount != 1 {
		t.Fatal("real visibility PDF import failed", w.Code)
	}
	id := created.Document.ID
	for _, body := range []string{`{"email":"first@field.example.test","name":"First Field Person","role":"signer","locale":"en"}`} {
		w = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+id.String()+"/recipients", body, q.cookie)
		if w.Code != http.StatusCreated {
			t.Fatal("real visibility party failed", w.Code)
		}
	}
	parties, err := f.q.ListRecipientsByDocument(f.ctx, id)
	if err != nil || len(parties) != 1 {
		t.Fatal("actual visibility parties absent", err)
	}
	visible := map[uuid.UUID]string{}
	for _, spec := range []struct {
		recipient, label, kind string
		y                      float64
		options                map[string]any
	}{
		{parties[0].ID.String(), "Text Å<&", "own", 10, map[string]any{"metadata": option}},
		{parties[0].ID.String(), "", "unassigned", 20, map[string]any{}},
		{parties[0].ID.String(), "Other party", "other", 30, map[string]any{}},
	} {
		body, err := json.Marshal(map[string]any{"recipient_id": spec.recipient, "type": "text", "page": 1, "x_pct": 12.5, "y_pct": spec.y, "w_pct": 65, "h_pct": 5, "required": false, "label": spec.label, "options": spec.options})
		if err != nil {
			t.Fatal(err)
		}
		w = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+id.String()+"/fields", string(body), q.cookie)
		var row struct {
			ID uuid.UUID `json:"id"`
		}
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &row) != nil || row.ID == uuid.Nil {
			t.Fatal("genuine visibility field writer failed", w.Code)
		}
		visible[row.ID] = spec.kind
	}
	// Use the same real authenticated REST writer as the text fields; this
	// GET fixture deliberately has no MCP dependency or verifier configured.
	for j, party := range parties {
		w = httptest.NewRecorder()
		f.s.Routes().ServeHTTP(w, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{"document_id": id.String(), "recipient_id": party.ID.String(), "type": "signature", "page": 1, "x_pct": 12, "y_pct": 60 + j*10, "w_pct": 65, "h_pct": 5, "required": true, "label": "Field signature", "options": map[string]any{}}, nil))
		var signature struct {
			ID uuid.UUID `json:"id"`
		}
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &signature) != nil || signature.ID == uuid.Nil {
			t.Fatal("genuine visibility signature writer failed", w.Code)
		}
		ownedPlainAssertDrainedV1(t, q)
	}
	actualFields, err := f.q.ListFieldsByDocument(f.ctx, id)
	if err != nil || len(actualFields) != 4 {
		t.Fatal("genuine visibility field roster absent", err)
	}
	for _, field := range actualFields {
		if field.Type == "signature" {
			if !field.RecipientID.Valid {
				t.Fatal("real signature lost recipient")
			}
			if uuid.UUID(field.RecipientID.Bytes) == parties[0].ID {
				visible[field.ID] = "signature"
			} else {
				visible[field.ID] = "other"
			}
		}
	}
	actor := sendengine.Actor{UserID: &f.user.ID, OrgID: f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	sent, err := f.s.Send.Send(f.ctx, actor, id)
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 1 {
		t.Fatal("genuine visibility Send failed", err)
	}
	token := ""
	for _, link := range sent.Links {
		if link.RecipientID == parties[0].ID {
			u, err := url.Parse(link.URL)
			if err != nil {
				t.Fatal(err)
			}
			token = strings.Clone(strings.TrimPrefix(u.Path, "/sign/"))
		}
	}
	if token == "" {
		t.Fatal("actual first-party invitation absent")
	}
	// The link is copied; the actual Send result has no further use.
	// Keep the defer for earlier failures, then end its genuine consumer before
	// the independent GET and observers-only/resource assertions.
	sent.CloseConsumerV1()
	ownedPlainAssertDrainedV1(t, q)
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	// Positive control before the intentional legacy assignment stimuli.
	healthy := q.requestV1(token, "/fields")
	var baseline struct {
		Count int `json:"count"`
	}
	if healthy.Code != http.StatusOK || json.Unmarshal(healthy.Body.Bytes(), &baseline) != nil || baseline.Count != 4 {
		t.Fatal("genuine sent ordinary-PDF visibility control failed", healthy.Code)
	}
	q.assertObserversOnlyV1(t)
	// A separately imported draft's real recipient is an exclusion-only row,
	// not a replacement party or credential for the sent source.
	foreignImport := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(foreignImport, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Foreign draft exclusion only")))
	var foreignDoc struct {
		Document documentResponse `json:"document"`
	}
	if foreignImport.Code != http.StatusCreated || json.Unmarshal(foreignImport.Body.Bytes(), &foreignDoc) != nil {
		t.Fatal("genuine foreign draft import failed", foreignImport.Code)
	}
	foreignPartyResponse := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+foreignDoc.Document.ID.String()+"/recipients", `{"email":"foreign@field.example.test","name":"Foreign Draft Person","role":"signer","locale":"en"}`, q.cookie)
	if foreignPartyResponse.Code != http.StatusCreated {
		t.Fatal("genuine foreign draft recipient failed", foreignPartyResponse.Code)
	}
	foreignParties, err := f.q.ListRecipientsByDocument(f.ctx, foreignDoc.Document.ID)
	if err != nil || len(foreignParties) != 1 {
		t.Fatal("foreign exclusion recipient absent", err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var locked uuid.UUID
	if err = tx.QueryRow(f.ctx, "SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", id, f.org).Scan(&locked); err != nil || locked != id {
		t.Fatal("actual legacy assignment parent lock failed", err)
	}
	for field, kind := range visible {
		if kind != "unassigned" && kind != "other" {
			continue
		}
		var assignee any
		if kind == "other" {
			assignee = foreignParties[0].ID
		}
		tag, err := tx.Exec(f.ctx, "UPDATE document_fields SET recipient_id=$3 WHERE id=$1 AND document_id=$2", field, id, assignee)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("actual historical/invalid assignment stimulus rejected", kind, err)
		}
	} //nolint:rawsql -- scalar negative/legacy fixture only, no signing/source/cache authority
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
	if err != nil || !sameSignerDocumentSource(doc, current) || current.Status != "sent" {
		t.Fatal("assignment stimulus changed original authenticated source/PDF/status", err)
	}
	return current, token, visible
}

func TestOwnedSignerFieldReadVisibilityAndActualSizeDebtE2E(t *testing.T) {
	var smallParent, smallDB int64
	for _, size := range []string{"small", "large"} {
		t.Run(size, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			option := "Å<&\u2028\x01"
			if size == "large" {
				option = strings.Repeat(option, 150)
			}
			doc, token, kinds := ownedFieldReadVisibility182V1(t, q, option)
			before := nativeCommentWholeState164V1(t, q, doc, q.f.pool)
			w := &ownedCommentPageWriter166V1{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{}), life: q.f.ctx}
			done := make(chan struct{})
			var release sync.Once
			defer func() {
				release.Do(func() { close(w.release) })
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("visibility GET did not join")
				}
			}()
			r := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+"/sign/"+token+"/fields", nil).WithContext(q.f.ctx)
			go func() { defer close(done); q.f.s.Routes().ServeHTTP(w, r) }()
			select {
			case <-w.entered:
			case <-done:
				t.Fatal("visibility read returned before write")
			case <-time.After(5 * time.Second):
				t.Fatal("visibility read did not reach write")
			}
			if w.Code != http.StatusOK {
				t.Fatal("visibility read refused", w.Code)
			}
			s := q.snapshotV1(t)
			if size == "small" {
				smallParent, smallDB = s.Organisation.ParentBytes, s.Organisation.DBStagingBytes
			} else if s.Organisation.ParentBytes <= smallParent || s.Organisation.DBStagingBytes <= smallDB {
				t.Fatal("genuinely larger options did not increase retained native response debt")
			}
			release.Do(func() { close(w.release) })
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("visibility GET did not finish")
			}
			var result struct {
				Fields []map[string]json.RawMessage `json:"fields"`
				Count  int                          `json:"count"`
			}
			if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Count != 3 || len(result.Fields) != 3 {
				t.Fatal("own+unassigned field response lost exact count")
			}
			seen := map[string]bool{}
			for _, field := range result.Fields {
				var id uuid.UUID
				var kind string
				if json.Unmarshal(field["id"], &id) != nil || json.Unmarshal(field["type"], &kind) != nil {
					t.Fatal("field identity/type absent")
				}
				name, exists := kinds[id]
				if !exists {
					t.Fatal("unexpected visible field")
				}
				if name == "other" || seen[name] {
					t.Fatal("other-party or duplicate field disclosed")
				}
				seen[name] = true
				if name == "unassigned" {
					if field["recipient_id"] != nil || field["label"] != nil || field["value"] != nil || field["completed_at"] != nil {
						t.Fatal("unassigned/NULL field semantics changed")
					}
				}
				if name == "own" {
					var options map[string]string
					if json.Unmarshal(field["options"], &options) != nil || options["metadata"] != option {
						t.Fatal("JSON options escaping changed actual stored value")
					}
				}
			}
			if !seen["own"] || !seen["unassigned"] || !seen["signature"] {
				t.Fatal("required visible field category absent")
			}
			q.assertObserversOnlyV1(t)
			if nativeCommentWholeState164V1(t, q, doc, q.f.pool) != before {
				t.Fatal("visibility GET changed business state")
			}
		})
	}
}
