// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package pdfadmission

import (
	"context"
	"time"
)

const workRuntimeCleanupIntervalV1 = time.Second
const workRuntimeCleanupPassV1 = time.Second

// StartCleanupV1 schedules the process runtime's existing strict reconciliation.
// A timer grants no retirement authority: pending consumers, unknown observers
// and unproven backend fences keep their original ownership and charges.
// Call once at process startup. The returned idempotent stop joins the loop;
// callers must stop it before CloseV1 or closing the application pool.
func (r *WorkRuntimeV1) StartCleanupV1() func() {
	if r == nil || r.SessionsV1() == nil {
		return func() {}
	}
	return startWorkRuntimeCleanupV1(r.ReconcileCleanupV1)
}

func startWorkRuntimeCleanupV1(reconcile func(context.Context) error) func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(workRuntimeCleanupIntervalV1)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pass, stop := context.WithTimeout(ctx, workRuntimeCleanupPassV1)
				_ = reconcile(pass)
				stop()
			}
		}
	}()
	return func() { cancel(); <-done }
}
