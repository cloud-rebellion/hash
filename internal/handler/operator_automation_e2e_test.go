//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Exercise the actual API admission, template materialization, quota transaction
// and send boundary against PostgreSQL. No dispatcher consumes this test outbox.
func TestOperatorAutomationEntitlementAndQuotasE2E(t *testing.T) {
	t.Run("unassigned organization leaves no durable draft", func(t *testing.T) {
		f := setupAutomationAuthorizationE2E(t, time.Time{})
		approved, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Approved operator fixture", Plan: "pro"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := f.pool.Exec(cleanupCtx, `DELETE FROM orgs WHERE id=$1`, approved.ID); err != nil {
				t.Error(err)
			}
		})
		f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: approved.ID, PlanSlug: "free", ReviewRef: "synthetic reviewed binding"}})
		f.s.Send.Billing = f.s.Billing
		if err := f.s.Billing.ValidateOperatorPlans(f.ctx); err != nil {
			t.Fatal(err)
		}
		before := f.snapshot(t)
		response := f.submit()
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("unassigned request=%d %s", response.Code, response.Body.String())
		}
		if f.snapshot(t) != before {
			t.Fatal("unassigned organization persisted request, draft, recipients, version, audit or outbox")
		}
	})

	for _, test := range []struct {
		name                    string
		documentQuota, recQuota int
		documents, recipients   int
		wantStatus              int
	}{
		{"document limit rolls back materialization", 1, 20, 1, 0, http.StatusPaymentRequired},
		{"recipient limit rolls back materialization", 20, 1, 1, 1, http.StatusPaymentRequired},
		{"approved quota exceeds SaaS free plan", 6, 20, 5, 0, http.StatusCreated},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := setupAutomationAuthorizationE2E(t, time.Time{})
			slug := "operator-test-" + uuid.NewString()
			var planID uuid.UUID
			if err := f.pool.QueryRow(f.ctx, `INSERT INTO billing_plans(slug,name,document_quota_monthly,recipient_quota_monthly,features_json) VALUES($1,'Reviewed operator test',$2,$3,'{"mcp":true,"evidence_bundle":true}') RETURNING id`, slug, test.documentQuota, test.recQuota).Scan(&planID); err != nil {
				t.Fatal(err)
			}
			// Measure this newly created synthetic catalog source through the same
			// admitted maintenance primitive as the original free-plan fixture.
			measurement, err := f.s.HTMLCreationSessions.ControlledMeasurePlanSourceV1(f.ctx, planID)
			if measurement != nil {
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := measurement.CloseV1(cleanup); err != nil {
						t.Error("operator plan source cleanup", err)
					}
				})
			}
			if err != nil || measurement == nil {
				t.Fatal("prepare actual operator plan source", err)
			}
			measurement.CloseConsumerV1()
			cleanup, stopMeasurement := context.WithTimeout(context.Background(), 5*time.Second)
			measureErr := measurement.CloseV1(cleanup)
			stopMeasurement()
			if measureErr != nil {
				t.Fatal("operator plan source did not join", measureErr)
			}
			t.Cleanup(func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := f.pool.Exec(cleanupCtx, `DELETE FROM billing_plans WHERE slug=$1`, slug); err != nil {
					t.Error(err)
				}
			})
			f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: slug, ReviewRef: "synthetic reviewed binding"}})
			f.s.Send.Billing = f.s.Billing
			if err := f.s.Billing.ValidateOperatorPlans(f.ctx); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < test.documents; i++ {
				doc, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user, Name: "Existing quota-consuming draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					for r := 0; r < test.recipients; r++ {
						_, hash, err := auth.MintMagicToken()
						if err != nil {
							t.Fatal(err)
						}
						if _, err := f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@operator-quota.test", Name: "Existing recipient", Locale: "en", MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			before := f.snapshot(t)
			response := f.submit()
			if response.Code != test.wantStatus {
				t.Fatalf("operator request=%d %s; want %d", response.Code, response.Body.String(), test.wantStatus)
			}
			if test.wantStatus == http.StatusPaymentRequired {
				if f.snapshot(t) != before {
					t.Fatal("quota refusal persisted request, draft, recipients, version, audit or outbox")
				}
				return
			}
			var result automationSignatureRequestResponse
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Status != "sent" {
				t.Fatalf("approved operator send=%#v err=%v", result, err)
			}
			replayed := f.submit()
			if replayed.Code != http.StatusOK {
				t.Fatalf("replay at exact quota=%d %s", replayed.Code, replayed.Body.String())
			}
			var docs, requests, versions, subscriptions, invoices int
			if err := f.pool.QueryRow(f.ctx, `SELECT
				(SELECT count(*) FROM documents WHERE org_id=$1),
				(SELECT count(*) FROM automation_signature_requests WHERE org_id=$1),
				(SELECT count(*) FROM document_versions WHERE org_id=$1),
				(SELECT count(*) FROM org_subscriptions WHERE org_id=$1),
				(SELECT count(*) FROM billing_invoices WHERE org_id=$1)`, f.org).Scan(&docs, &requests, &versions, &subscriptions, &invoices); err != nil {
				t.Fatal(err)
			}
			if docs != test.documents+1 || requests != 1 || versions != 1 || subscriptions != 0 || invoices != 0 {
				t.Fatalf("docs=%d requests=%d versions=%d subscriptions=%d invoices=%d", docs, requests, versions, subscriptions, invoices)
			}
		})
	}
}
