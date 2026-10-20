//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestHistoricalFinalizationNativeClaimRefusesUnsignedV1E2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	payload := "{\"name\":\"Synthetic native finalizing refusal\",\"source_kind\":\"blocks\",\"blocks_json\":{\"version\":1,\"blocks\":[{\"id\":\"terms\",\"type\":\"paragraph\",\"text\":\"Approved synthetic contract\"},{\"id\":\"sign\",\"type\":\"signature_field\",\"attrs\":{\"recipient_role\":\"signer\"}}]},\"variables_json\":{}}"
	created := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents", payload, q.cookie)
	if created.Code != http.StatusCreated {
		t.Fatalf("actual creator=%d %s", created.Code, created.Body.String())
	}
	var document struct{ ID uuid.UUID }
	if err := json.Unmarshal(created.Body.Bytes(), &document); err != nil || document.ID == uuid.Nil {
		t.Fatal(err)
	}
	base := "/api/v1/documents/" + document.ID.String()
	party := submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", "{\"email\":\"signer@native-finalize.example.test\",\"name\":\"Synthetic signer\",\"role\":\"signer\",\"locale\":\"en\"}", q.cookie)
	if party.Code != http.StatusCreated {
		t.Fatalf("actual recipient=%d %s", party.Code, party.Body.String())
	}
	sent := submitSessionOperationE2E(f.s, http.MethodPost, base+"/send", "{\"lawful_basis\":\"contract\"}", q.cookie)
	if sent.Code != http.StatusOK {
		t.Fatalf("actual Send=%d %s", sent.Code, sent.Body.String())
	}
	q.assertObserversOnlyV1(t)
	before, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: document.ID, OrgID: f.org})
	if err != nil || before == nil || before.Status != "sent" {
		t.Fatal("actual postSend baseline unavailable", err)
	}
	var beforeEvents int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM events WHERE org_id=$1 AND document_id=$2", f.org, document.ID).Scan(&beforeEvents); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- read-only independent witness in owned disposable DB
	factory := q.runtime.SessionsV1()
	operation, err := factory.NewHTMLSendOperationV1(f.ctx, f.org, document.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer operation.CloseConsumerV1()
	stage, err := operation.OpenSQLV1(pdfadmission.HTMLHistoricalFinalizationClaimV1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stage.CloseSQLV1() }()
	session := stage.SessionV1()
	if _, err = session.NewAdmissionV1(stage.ContextV1()); err != nil {
		t.Fatal(err)
	}
	err = stage.WithTxV1(func(call context.Context, _ generated.DBTX) error {
		w, err := session.NewHTMLSendWorkV1(call, stage)
		if err != nil {
			return err
		}
		if _, err = w.StateV1(call); err != nil {
			return err
		}
		if _, err = w.ReadModelsV1(call); err != nil {
			return err
		}
		if err = w.ValidateHistoricalFinalizationSigningPageV1(call); err != nil {
			return err
		}
		if _, err = w.ReadRecipientsV1(call); err != nil {
			return err
		}
		if _, err = w.HistoricalFinalizationRolesV1(call); err != nil {
			return err
		}
		if _, _, err = w.BeginHistoricalFinalizingV1(call); err == nil {
			t.Fatal("native root transitioned without private actual readiness")
		}
		if err = w.ValidateHistoricalFinalizationReadinessV1(call, "signature"); !errors.Is(err, pdfadmission.ErrHistoricalFinalizationNotReadyV1) {
			t.Fatalf("actual unsigned role admitted finalizing: %v", err)
		}
		if _, _, err = w.BeginHistoricalFinalizingV1(call); err == nil {
			t.Fatal("refused actual readiness still allowed transition")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = session.CommitV1(stage.ContextV1()); err != nil {
		t.Fatal(err)
	}
	if err = stage.CloseSQLV1(); err != nil {
		t.Fatal(err)
	}
	operation.CloseConsumerV1()
	cleanup, stop := context.WithTimeout(context.WithoutCancel(f.ctx), 5*time.Second)
	defer stop()
	if err = factory.ReconcileCleanupV1(cleanup); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: document.ID, OrgID: f.org})
	if err != nil || !reflect.DeepEqual(before, current) {
		t.Fatalf("unsigned refusal changed exact postSend Document baseline: err=%v before_status=%s after_status=%s before_bound=%t after_bound=%t before_completion=%v after_completion=%v", err, before.Status, current.Status, before.CompletionEffectiveAtBound, current.CompletionEffectiveAtBound, before.CompletionEffectiveAt, current.CompletionEffectiveAt)
	}
	var afterEvents, signatures, intents int
	if err = f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*)::integer FROM events WHERE org_id=$1 AND document_id=$2),(SELECT count(*)::integer FROM signatures WHERE document_id=$2),(SELECT count(*)::integer FROM document_finalization_intents WHERE org_id=$1 AND document_id=$2)", f.org, document.ID).Scan(&afterEvents, &signatures, &intents); err != nil || afterEvents != beforeEvents || signatures != 0 || intents != 0 {
		t.Fatal("native unsigned refusal left evidence/intent/event effects", err)
	} //nolint:rawsql -- read-only independent witness in owned disposable DB
}
