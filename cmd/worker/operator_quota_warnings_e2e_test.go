//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
)

func TestOperatorQuotaWarningAtomicConcurrentE2E(t *testing.T) {
	ctx, pool, w, orgID, userID, _ := setupSoftDeletePurgeE2E(t)
	w.audit = audit.New(w.queries, pool)
	w.baseURL = "https://hash.example.test"
	w.billing = billing.NewOperator(w.queries, []config.OperatorEntitlement{{OrgID: orgID, PlanSlug: "free", ReviewRef: "test-reviewed-plan"}})
	if err := w.billing.ValidateOperatorPlans(ctx); err != nil {
		t.Fatal(err)
	}
	// The real seeded free plan has a five-document cap. Four reaches 80%.
	for i := 0; i < 4; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind) VALUES($1,$2,'quota fixture','blocks')`, orgID, userID); err != nil {
			t.Fatal(err)
		}
	}
	// Inject a queue failure: no warning marker or outbox can survive rollback.
	if _, err := pool.Exec(ctx, `CREATE FUNCTION fail_operator_email() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture enqueue failure'; END $$; CREATE TRIGGER operator_email_failure BEFORE INSERT ON email_deliveries FOR EACH ROW EXECUTE FUNCTION fail_operator_email()`); err != nil {
		t.Fatal(err)
	}
	if err := w.queueOperatorQuotaWarning(ctx, orgID); err == nil {
		t.Fatal("queue failure falsely succeeded")
	}
	var partialEmails, partialEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM email_deliveries`).Scan(&partialEmails); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind=$2`, orgID, audit.KindBillingQuotaWarning80).Scan(&partialEvents); err != nil {
		t.Fatal(err)
	}
	if partialEmails != 0 || partialEvents != 0 {
		t.Fatalf("partial warning committed: %d emails %d events", partialEmails, partialEvents)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER operator_email_failure ON email_deliveries; DROP FUNCTION fail_operator_email()`); err != nil {
		t.Fatal(err)
	}
	// Cancellation while waiting on the real org lock must release the warning
	// transaction and permit subsequent attempts without a partial marker.
	lockTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.billing.LockDocumentQuotaMutation(ctx, w.queries.WithTx(lockTx), orgID); err != nil {
		t.Fatal(err)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	cancelled := make(chan error, 1)
	go func() { cancelled <- w.queueOperatorQuotaWarning(cancelCtx, orgID) }()
	waiting := false
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-cancelled:
		if err == nil {
			t.Fatal("cancelled lock wait succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled warning did not release transaction")
	}
	if !waiting {
		t.Fatal("warning did not wait on actual org quota lock")
	}
	_ = lockTx.Rollback(ctx)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- w.queueOperatorQuotaWarning(ctx, orgID) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var emails, events, subscriptions, invoices int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM email_deliveries`).Scan(&emails); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind=$2 AND payload_json ? 'operator_period'`, orgID, audit.KindBillingQuotaWarning80).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM org_subscriptions`).Scan(&subscriptions); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM billing_invoices`).Scan(&invoices); err != nil {
		t.Fatal(err)
	}
	if emails != 1 || events != 1 || subscriptions != 0 || invoices != 0 {
		t.Fatalf("emails=%d events=%d subscriptions=%d invoices=%d", emails, events, subscriptions, invoices)
	}
	// Retiring or unbounding a plan must remove authorization immediately.
	for _, change := range []string{"document_quota_monthly=0", "recipient_quota_monthly=0", "active=false"} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "UPDATE billing_plans SET "+change+" WHERE slug='free'"); err != nil {
			t.Fatal(err)
		}
		engine := *w.billing
		engine.Queries = w.queries.WithTx(tx)
		if _, _, err := engine.PlanForOrg(context.Background(), orgID); err == nil {
			t.Fatalf("accepted %s", change)
		}
		_ = tx.Rollback(ctx)
	}
}
