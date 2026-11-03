//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// These actual coordinator regressions need no database or PDF worker. They
// distinguish a finite fixture grant from a changed/waived production policy.
func TestTemplatePDFNativeFixtureProviderProfileE2E(t *testing.T) {
	ordinary, err := htmlAuthoringNativeLimitsE2E()
	if err != nil || ordinary.ParentBytes != 2<<30 || ordinary.DBStagingBytes != 2<<30 || ordinary.SQLSessions != 16 || ordinary.ProviderStreams != 0 {
		t.Fatal("ordinary native fixture capacity changed", ordinary, err)
	}
	metadata, err := htmlAuthoringNativeLimitsE2E(htmlAuthoringMetadataReadProfileE2E)
	if err != nil || metadata.ParentBytes != 3<<30 || metadata.ProviderStreams != 0 {
		t.Fatal("existing metadata-only fixture changed", metadata, err)
	}
	funded, err := htmlAuthoringNativeLimitsE2E(htmlAuthoringTemplatePDFReadProfileE2E)
	if err != nil || funded.ParentBytes != ordinary.ParentBytes || funded.DBStagingBytes != ordinary.DBStagingBytes || funded.SQLSessions != ordinary.SQLSessions || funded.ProviderStreams != 1 {
		t.Fatal("PDF fixture changed unrelated capacity or lacks its one real provider lane", funded, err)
	}
	for _, profiles := range [][]htmlAuthoringNativeTestProfileE2E{{0}, {3}, {htmlAuthoringMetadataReadProfileE2E, htmlAuthoringTemplatePDFReadProfileE2E}} {
		if _, err := htmlAuthoringNativeLimitsE2E(profiles...); err == nil {
			t.Fatal("unknown or combined native fixture profile accepted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	org := uuid.New()
	for _, kind := range []string{"ordinary refuses before provider", "explicit PDF permits exactly one"} {
		t.Run(kind, func(t *testing.T) {
			limits := ordinary
			if kind == "explicit PDF permits exactly one" {
				limits = funded
			}
			coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 256, MaxOrganisationGrants: 128})
			if err != nil {
				t.Fatal(err)
			}
			grant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
			if limits.ProviderStreams == 0 {
				if grant != nil || !errors.Is(err, workguard.ErrUnavailableV1) || coordinator.SnapshotV1(org).GlobalGrants != 0 {
					t.Fatal("zero-provider fixture admitted or minted credit", err)
				}
				return
			}
			if grant == nil || err != nil {
				t.Fatal("explicit provider lane refused", err)
			}
			defer grant.Close()
			second, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
			if second != nil || !errors.Is(err, workguard.ErrUnavailableV1) {
				t.Fatal("finite PDF provider lane was bypassed", err)
			}
			if snapshot := coordinator.SnapshotV1(org); snapshot.Global.ProviderStreams != 1 || snapshot.Global.ParentBytes != 0 || snapshot.GlobalGrants != 1 {
				t.Fatal("provider-only admission changed Parent funding or lost its live owner", snapshot)
			}
			grant.Close()
			if snapshot := coordinator.SnapshotV1(org); snapshot.Global != (workguard.VectorV1{}) || snapshot.GlobalGrants != 0 {
				t.Fatal("actual provider close did not retire exactly its grant", snapshot)
			}
		})
	}
}
