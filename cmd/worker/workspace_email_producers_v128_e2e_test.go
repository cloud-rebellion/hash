//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// This is a real process runtime on the fixture's actual pool. It supplies
// resource ownership only, never an owner actor or SQL/render replacement.
func bindQuotaWarningRuntime128E2E(t *testing.T, w *worker) {
	t.Helper()
	v := workguard.VectorV1{ParentBytes: 128 << 20, DBStagingBytes: 32 << 20, SQLSessions: 2}
	runtime, err := pdfadmission.NewWorkRuntimeV1(w.pool, workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 64, MaxOrganisationGrants: 32}, int64(w.pool.Config().MaxConns)+2)
	if err != nil {
		t.Fatal(err)
	}
	w.sendEngine = &send.Engine{Pool: w.pool, WorkRuntime: runtime}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.CloseV1(ctx); err != nil {
			t.Error("close quota fixture process runtime", err)
		}
	})
}

type quotaWarningFixture128 struct {
	ctx          context.Context
	w            *worker
	org          uuid.UUID
	operator     bool
	resetDate    string
	subscription *generated.ListSubscriptionsOverQuotaWarningRow
}

func newQuotaWarningFixture128E2E(t *testing.T, operator bool) *quotaWarningFixture128 {
	t.Helper()
	ctx, pool, w, org, user, _ := setupSoftDeletePurgeE2E(t)
	w.audit = audit.New(w.queries, pool)
	w.baseURL = "https://hash.example.test"
	bindQuotaWarningRuntime128E2E(t, w)
	if _, err := w.queries.CreateUser(ctx, generated.CreateUserParams{OrgID: org, Email: uuid.NewString() + "@quota-viewer.test", Name: "Quota viewer", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	// Count-only billing fixtures are not promoted to signing/source authority.
	for i := 0; i < 4; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind) VALUES($1,$2,'quota count fixture','blocks')`, org, user); err != nil {
			t.Fatal(err)
		}
	}
	f := &quotaWarningFixture128{ctx: ctx, w: w, org: org, operator: operator}
	if operator {
		w.billing = billing.NewOperator(w.queries, []config.OperatorEntitlement{{OrgID: org, PlanSlug: "free", ReviewRef: "test-reviewed-plan"}})
		if err := w.billing.ValidateOperatorPlans(ctx); err != nil {
			t.Fatal(err)
		}
		_, end := w.billing.QuotaPeriod(nil, time.Now().UTC())
		f.resetDate = end.Format("2006-01-02")
	} else {
		if _, err := pool.Exec(ctx, `INSERT INTO org_subscriptions(org_id,plan_id,provider,status,current_period_start,current_period_end)
SELECT $1,id,'mock','active',date_trunc('month',now()),date_trunc('month',now())+interval '1 month' FROM billing_plans WHERE slug='free'`, org); err != nil {
			t.Fatal(err)
		}
		rows, err := w.queries.ListSubscriptionsOverQuotaWarning(ctx, quotaWarningThreshold)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.OrgID == org {
				f.subscription = row
			}
		}
		if f.subscription == nil {
			t.Fatal("actual 80-percent subscription scan did not select fixture")
		}
		f.resetDate = f.subscription.CurrentPeriodEnd.Time.UTC().Format("2006-01-02")
	}
	return f
}

func (f *quotaWarningFixture128) produce() error {
	if f.operator {
		return f.w.queueOperatorQuotaWarning(f.ctx, f.org)
	}
	if state := f.w.sendQuotaWarningObserved(f.ctx, f.subscription); state != flarereport.InvocationReturned {
		return fmt.Errorf("subscription quota producer state: %s", state)
	}
	return nil
}

func (f *quotaWarningFixture128) saveEdition(t *testing.T, revision int64, html string) {
	t.Helper()
	if err := f.w.queries.CreateServiceEmailTemplateRevisionV1(f.ctx, generated.CreateServiceEmailTemplateRevisionV1Params{OrgID: f.org, Kind: dispatch.KindQuotaWarning80, Revision: revision,
		SubjectTemplate: fmt.Sprintf("Literal saved quota %d {{org_name}}", revision), HtmlTemplate: html, TextTemplate: fmt.Sprintf("Saved quota edition %d", revision)}); err != nil {
		t.Fatal(err)
	}
	if err := f.w.queries.SetServiceEmailTemplateHeadV1(f.ctx, generated.SetServiceEmailTemplateHeadV1Params{OrgID: f.org, Kind: dispatch.KindQuotaWarning80, Revision: revision}); err != nil {
		t.Fatal(err)
	}
}

type frozenQuotaMail128 struct{ To, Subject, HTML, Text string }

func (f *quotaWarningFixture128) queued(t *testing.T) []frozenQuotaMail128 {
	t.Helper()
	rows, err := f.w.pool.Query(f.ctx, `SELECT to_email,subject,html_body,text_body FROM email_deliveries WHERE smtp_org_id=$1 AND smtp_purpose='workspace' ORDER BY to_email`, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []frozenQuotaMail128
	for rows.Next() {
		var row frozenQuotaMail128
		if err := rows.Scan(&row.To, &row.Subject, &row.HTML, &row.Text); err != nil {
			t.Fatal(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *quotaWarningFixture128) assertAtomicCounts(t *testing.T, wantMail, wantEvents int) {
	t.Helper()
	var mail, events int
	if err := f.w.pool.QueryRow(f.ctx, `SELECT count(*) FROM email_deliveries WHERE smtp_org_id=$1`, f.org).Scan(&mail); err != nil {
		t.Fatal(err)
	}
	if err := f.w.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind=$2`, f.org, audit.KindBillingQuotaWarning80).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if mail != wantMail || events != wantEvents {
		t.Fatalf("mail/events=%d/%d, want%d/%d", mail, events, wantMail, wantEvents)
	}
	if !f.operator {
		var marked bool
		if err := f.w.pool.QueryRow(f.ctx, `SELECT last_quota_warning_sent_at IS NOT NULL FROM org_subscriptions WHERE org_id=$1`, f.org).Scan(&marked); err != nil {
			t.Fatal(err)
		}
		if marked != (wantEvents == 1) {
			t.Fatal("subscription period marker disagrees with atomic warning")
		}
	}
}

func TestQuotaWarningsFreezeSavedWorkspaceLocaleAndEdition128E2E(t *testing.T) {
	for _, operator := range []bool{false, true} {
		t.Run(fmt.Sprintf("operator=%v", operator), func(t *testing.T) {
			f := newQuotaWarningFixture128E2E(t, operator)
			if _, err := f.w.pool.Exec(f.ctx, `INSERT INTO org_email_preferences_v1(org_id,revision,locale) VALUES($1,1,'sv')`, f.org); err != nil {
				t.Fatal(err)
			}
			f.saveEdition(t, 1, "<p>Saved quota edition one</p>")
			if err := f.produce(); err != nil {
				t.Fatal(err)
			}
			f.assertAtomicCounts(t, 2, 1)
			before := f.queued(t)
			if len(before) != 2 || before[0].To == before[1].To {
				t.Fatal("all original workspace users must receive one warning")
			}
			for _, mail := range before {
				if !strings.HasPrefix(mail.Subject, "Literal saved quota 1 ") || !strings.Contains(mail.HTML, "Saved quota edition one") || !strings.Contains(mail.HTML, "har nått") || !strings.Contains(mail.Text, "Perioden nollställs") {
					t.Fatal("saved literal edition and Swedish native protected quota copy were not both frozen")
				}
				if !strings.Contains(mail.HTML, f.resetDate) || !strings.Contains(mail.Text, f.resetDate) {
					t.Fatal("quota reset date did not keep the same endpoint in language-neutral ISO format")
				}
				if operator && !strings.Contains(mail.HTML, "kalendermånad") {
					t.Fatal("operator period copy changed")
				}
				if !operator && !strings.Contains(mail.HTML, "faktureringsperiod") {
					t.Fatal("subscription period copy changed")
				}
			}
			if _, err := f.w.pool.Exec(f.ctx, `UPDATE org_email_preferences_v1 SET locale='en',revision=2,updated_at=clock_timestamp() WHERE org_id=$1`, f.org); err != nil {
				t.Fatal(err)
			}
			f.saveEdition(t, 2, "<p>Later saved quota edition</p>")
			if err := f.produce(); err != nil {
				t.Fatal(err)
			}
			f.assertAtomicCounts(t, 2, 1)
			after := f.queued(t)
			if len(after) != len(before) {
				t.Fatal("same-period preference/edit change duplicated queue rows")
			}
			for i := range before {
				if before[i] != after[i] {
					t.Fatal("queued bytes changed after preference or edition update")
				}
			}
		})
	}
}

func TestQuotaWarningSelectedEditionAndOutboxFailuresRollback128E2E(t *testing.T) {
	for _, operator := range []bool{false, true} {
		t.Run(fmt.Sprintf("operator=%v", operator), func(t *testing.T) {
			f := newQuotaWarningFixture128E2E(t, operator)
			// Invalid retained source must not silently fall back to the builtin.
			f.saveEdition(t, 1, "<script>invalid saved source</script>")
			if err := f.produce(); err == nil {
				t.Fatal("invalid selected edition falsely succeeded")
			}
			f.assertAtomicCounts(t, 0, 0)
			f.saveEdition(t, 2, "<p>Valid retry edition</p>")
			if _, err := f.w.pool.Exec(f.ctx, `CREATE FUNCTION quota128_enqueue_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture enqueue failure'; END $$;
CREATE TRIGGER quota128_enqueue_failure BEFORE INSERT ON email_deliveries FOR EACH ROW EXECUTE FUNCTION quota128_enqueue_failure()`); err != nil {
				t.Fatal(err)
			}
			if err := f.produce(); err == nil {
				t.Fatal("outbox failure falsely succeeded")
			}
			f.assertAtomicCounts(t, 0, 0)
			if _, err := f.w.pool.Exec(f.ctx, `DROP TRIGGER quota128_enqueue_failure ON email_deliveries; DROP FUNCTION quota128_enqueue_failure()`); err != nil {
				t.Fatal(err)
			}
			if err := f.produce(); err != nil {
				t.Fatal(err)
			}
			f.assertAtomicCounts(t, 2, 1)
		})
	}
}

func TestSubscriptionQuotaWarningDeduplicatesConcurrentSavedEditions128E2E(t *testing.T) {
	f := newQuotaWarningFixture128E2E(t, false)
	f.saveEdition(t, 1, "<p>Concurrent saved edition</p>")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- f.produce() }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	f.assertAtomicCounts(t, 2, 1)
}
