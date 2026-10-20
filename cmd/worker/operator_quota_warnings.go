// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Internal entitlements have no subscription row. Deduplicate their monthly
// warnings using the committed audit event under the same org quota lock used
// by authoring. Queue, marker and audit commit atomically without fake billing.
func (w *worker) sendOperatorQuotaWarning(ctx context.Context, orgID uuid.UUID) {
	w.sendOperatorQuotaWarningObserved(ctx, orgID)
}
func (w *worker) sendOperatorQuotaWarningObserved(ctx context.Context, orgID uuid.UUID) flarereport.JobInvocationState {
	if w.pool == nil || w.audit == nil || !w.billing.OperatorMode() {
		return flarereport.InvocationUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := w.queueOperatorQuotaWarning(ctx, orgID); err != nil {
		slog.Warn("operator_quota_warning", "org_id", orgID, "err", err)
		return flarereport.InvocationPartial
	}
	return flarereport.InvocationReturned
}
func (w *worker) queueOperatorQuotaWarning(ctx context.Context, orgID uuid.UUID) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	q := w.queries.WithTx(tx)
	if err := w.billing.LockDocumentQuotaMutation(ctx, q, orgID); err != nil {
		return err
	}
	// Load the same live plan inside this transaction, after obtaining the lock.
	engine := *w.billing
	engine.Queries = q
	plan, _, err := engine.PlanForOrg(ctx, orgID)
	if err != nil {
		return err
	}
	start, end := engine.QuotaPeriod(nil, time.Now().UTC())
	period := start.Format("2006-01")
	var sent bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM events WHERE org_id=$1 AND kind=$2 AND payload_json->>'operator_period'=$3)`, orgID, audit.KindBillingQuotaWarning80, period).Scan(&sent); err != nil {
		return err
	}
	if sent {
		return nil
	}
	usage, err := q.CountBillingUsageInPeriodForOrg(ctx, generated.CountBillingUsageInPeriodForOrgParams{OrgID: orgID, PeriodStart: pgtype.Timestamptz{Time: start, Valid: true}, PeriodEnd: pgtype.Timestamptz{Time: end, Valid: true}})
	if err != nil {
		return err
	}
	if usage == nil {
		return fmt.Errorf("operator quota usage unavailable")
	}
	clamp := func(v int64) int32 {
		if v > math.MaxInt32 {
			return math.MaxInt32
		}
		return int32(v)
	}
	kind, used, limit, pct := pickTrippedQuota(&generated.ListSubscriptionsOverQuotaWarningRow{DocumentQuotaMonthly: plan.DocumentQuotaMonthly, RecipientQuotaMonthly: plan.RecipientQuotaMonthly, DocumentsUsed: clamp(usage.DocumentsUsed), RecipientsUsed: clamp(usage.RecipientsUsed)}, quotaWarningThreshold)
	if kind == "" {
		return nil
	}
	org, err := q.GetOrg(ctx, orgID)
	if err != nil {
		return err
	}
	users, err := q.ListUsersByOrg(ctx, orgID)
	if err != nil {
		return err
	}
	subj, html, text, err := dispatch.Render(dispatch.KindQuotaWarning80, dispatch.TemplateContext{OrgName: org.Name, PlanName: plan.Name, QuotaKind: kind, QuotaUsed: int(used), QuotaLimit: int(limit), QuotaPct: pct, PeriodResetAt: end.Format("January 2, 2006"), UpgradeURL: w.baseURL + "/settings/billing", InternalOperator: true})
	if err != nil {
		return err
	}
	for _, u := range users {
		if _, err := q.EnqueueEmailDelivery(ctx, generated.EnqueueEmailDeliveryParams{ToEmail: u.Email, Subject: subj, HtmlBody: html, TextBody: text, HeadersJson: []byte(`{}`)}); err != nil {
			return err
		}
	}
	pending, err := w.audit.LogTx(ctx, tx, audit.Entry{OrgID: orgID, Kind: audit.KindBillingQuotaWarning80, Payload: map[string]any{"operator_period": period, "plan": plan.Slug, "quota_kind": kind, "used": used, "limit": limit, "pct": pct, "recipients": len(users)}})
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	w.audit.Publish(pending)
	return nil
}
