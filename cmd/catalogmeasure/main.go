// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Command catalogmeasure explicitly measures ONE selected catalog source.
// It never inventories, repairs on read, migrates, or backfills at startup.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runCatalogMeasureV1(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "catalogmeasure: selected source could not be measured; no retry was dispatched")
		os.Exit(1)
	}
}

func runCatalogMeasureV1(parent context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("catalogmeasure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kind := flags.String("kind", "", "plan or eidas-rule")
	source := flags.String("id", "", "explicit source UUID")
	org := flags.String("org", "", "actual organization UUID for eidas-rule")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("invalid maintenance selection")
	}
	id, err := uuid.Parse(*source)
	if err != nil || id == uuid.Nil {
		return errors.New("invalid source UUID")
	}
	orgID := uuid.Nil
	switch *kind {
	case "plan":
		if *org != "" {
			return errors.New("plan catalog is process scoped")
		}
	case "eidas-rule":
		orgID, err = uuid.Parse(*org)
		if err != nil || orgID == uuid.Nil {
			return errors.New("rule organization required")
		}
	default:
		return errors.New("explicit kind required")
	}
	allocations, err := config.LoadWorkRuntimeLimitsV1()
	if err != nil || allocations == nil {
		return errors.New("explicit work allocations required")
	}
	// No connection pool or second coordinator is created by this fixed command.
	// The ONE configured factory owns its explicit process-control SQL observer.
	if allocations.Limits.Global.SQLSessions > allocations.TotalDBConnections {
		return errors.New("SQL allocation exceeds assigned database connections")
	}
	dsn := os.Getenv("HASH_DB_URL")
	if dsn == "" {
		return errors.New("database configuration required")
	}
	pg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return errors.New("database configuration invalid")
	}
	coordinator, err := workguard.NewV1(allocations.Limits)
	if err != nil {
		return err
	}
	work, err := pdfadmission.NewWorkAdmissionV1(coordinator)
	if err != nil {
		return err
	}
	factory, err := pdfadmission.NewApplicationSessionFactoryV1(pg, work, pdfadmission.ApplicationSessionDirectProfileV1)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	var owner *pdfadmission.ApplicationCatalogMaintenanceV1
	if *kind == "plan" {
		owner, err = factory.ControlledMeasurePlanSourceV1(ctx, id)
	} else {
		owner, err = factory.ControlledMeasureEIDASRuleSourceV1(ctx, orgID, id)
	}
	// Actual same-owner cleanup is attempted even after failed/unknown commit.
	// A process observer cannot prove its own backend gone; that remains an
	// explicit numeric pending receipt, never a synthetic last-observer credit.
	defer func() {
		if owner != nil {
			owner.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = factory.CloseV1(cleanup)
	}()
	if err != nil {
		return err
	}
	receipt, err := owner.ReceiptV1()
	if err != nil {
		return err
	}
	result := struct {
		Measurement                      pdfadmission.CatalogMeasurementReceiptV1 `json:"measurement"`
		Complete                         bool                                     `json:"measurement_committed"`
		ProcessObserverRetirementPending bool                                     `json:"process_observer_retirement_pending"`
	}{receipt, true, true}
	return json.NewEncoder(out).Encode(result)
}
