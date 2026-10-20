//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"testing"
)

func TestHTMLAuthoringBodyUsesActualOneReaderClassAndJoinedConsumersE2E(t *testing.T) {
	for _, order := range []string{"consumer_before_sql", "sql_before_consumer"} {
		t.Run(order, func(t *testing.T) {
			database := isolateHTMLTemplateDatabaseE2E(t)
			f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
			ctx, cancel := context.WithTimeout(f.ctx, authoring.MutationTimeout)
			defer cancel()
			o, err := f.s.openHTMLAuthoringV1(ctx, f.org, uuid.New())
			if err != nil {
				t.Fatal(err)
			}
			defer o.closeConsumerV1(ctx)
			defer o.closeSQLV1(ctx)
			before := htmlAuthoringNativeSnapshotE2E(t, f.s)
			if before.Organisation.ParentBytes != 32<<20 || before.Organisation.DBStagingBytes != 32<<20 {
				t.Fatalf("actual reader did not hold its original class: %+v", before)
			}
			err = o.session.WithTxV1(ctx, func(ctx context.Context, _ generated.DBTX) error {
				for range 2 {
					prior := htmlAuthoringNativeSnapshotE2E(t, f.s)
					// Empty maps have zero raw string bytes, but retain positive actual
					// typed/container storage and their literal JSON bodies.
					if err := o.reader.AcquireStringMapsV1(ctx, nil, nil); err != nil {
						return err
					}
					after := htmlAuthoringNativeSnapshotE2E(t, f.s)
					delta := after.Organisation.ParentBytes - prior.Organisation.ParentBytes
					if delta <= 0 || delta >= 1<<20 || after.OrganisationGrants != prior.OrganisationGrants+1 {
						t.Fatalf("body duplicated fixed reader class or omitted typed storage: before=%+v after=%+v", prior, after)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			live := htmlAuthoringNativeSnapshotE2E(t, f.s)
			if order == "consumer_before_sql" {
				o.closeConsumerV1(ctx)
				if got := htmlAuthoringNativeSnapshotE2E(t, f.s); got.Organisation.ParentBytes != live.Organisation.ParentBytes || got.Organisation.DBStagingBytes != live.Organisation.DBStagingBytes {
					t.Fatalf("live SQL lost original header/model debt: %+v", got)
				}
				if err = o.session.WithTxV1(ctx, func(ctx context.Context, _ generated.DBTX) error {
					return o.reader.AcquireStringMapsV1(ctx, nil, nil)
				}); !errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
					t.Fatalf("closed header consumer admitted another body: %v", err)
				}
			}
			if err = o.session.CommitV1(ctx); err != nil {
				t.Fatal(err)
			}
			if err = o.closeSQLV1(ctx); err != nil {
				t.Fatal(err)
			}
			if order == "sql_before_consumer" {
				if got := htmlAuthoringNativeSnapshotE2E(t, f.s); got.Organisation.ParentBytes != live.Organisation.ParentBytes || got.Organisation.DBStagingBytes != live.Organisation.DBStagingBytes {
					t.Fatalf("physical SQL join refunded live models: %+v", got)
				}
			}
			o.closeConsumerV1(ctx)
			o.closeConsumerV1(ctx)
			got := htmlAuthoringNativeSnapshotE2E(t, f.s)
			if got.Organisation.ParentBytes != 0 || got.Organisation.DBStagingBytes != 0 || got.Organisation.SQLSessions != 1 || got.OrganisationGrants != 1 {
				t.Fatalf("actual last consumer/physical join or duplicate close wrong: %+v", got)
			}
		})
	}
}
