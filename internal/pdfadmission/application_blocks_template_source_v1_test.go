// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Synthetic rows exercise the actual bounded native reader and admission
// bookkeeping. The existing concurrent PATCH/create PostgreSQL regression
// separately qualifies the real MVCC wait and matching M97 producer.
func TestBlocksTemplateSourceRefreshesOnlyMissingLockedCacheV1(t *testing.T) {
	for _, update := range []bool{false, true} {
		for _, outcome := range []string{"fresh", "missing", "changed parent", "SQL failure", "already measured"} {
			t.Run(fmt.Sprintf("update=%t/%s", update, outcome), func(t *testing.T) {
				f, session, _ := applicationRequestLoanFixtureV1(t)
				session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
				ctx := applicationTestContextV1(t)
				stamp := pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
				tpl := generated.Template{ID: f.scope.DocumentID, OrgID: f.scope.OrgID, SourceKind: "blocks", Name: "Current template", Version: 2, CreatedAt: stamp, UpdatedAt: stamp, BlocksJson: []byte(`{"version":1,"blocks":[]}`), VariablesJson: []byte(`{}`), FieldsJson: []byte(`[]`)}
				raw, _ := htmlAuthoringTemplateBodyBytesV1(&tpl)
				fresh := generated.GetNonHTMLTemplateSourceHeaderForShareV1Row{ID: tpl.ID, OrgID: tpl.OrgID, SourceKind: tpl.SourceKind, Version: tpl.Version, CreatedAt: stamp, UpdatedAt: stamp, RawTextBytes: raw, BlocksWireBytes: int64(len(tpl.BlocksJson)), VariablesWireBytes: 2, FieldsWireBytes: 2, MeasurementServerVersionNum: 160015, ServerVersionNum: 160015}
				missing := fresh
				missing.MasterWireBytes, missing.BlocksWireBytes, missing.VariablesWireBytes, missing.FieldsWireBytes, missing.SanitizationWireBytes, missing.MeasurementServerVersionNum = -1, -1, -1, -1, -1, -1
				row := func(h generated.GetNonHTMLTemplateSourceHeaderForShareV1Row) pgx.Row {
					if update {
						return htmlRevisionReadRowTestV1{record: generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Row(h)}
					}
					return htmlRevisionReadRowTestV1{record: h}
				}
				rows := []pgx.Row{row(missing), row(fresh), htmlRevisionReadRowTestV1{record: tpl}}
				wantCalls, wantOK := 3, outcome == "fresh" || outcome == "already measured"
				switch outcome {
				case "missing":
					rows, wantCalls = []pgx.Row{row(missing), row(missing)}, 2
				case "changed parent":
					changed := fresh
					changed.Version++
					rows, wantCalls = []pgx.Row{row(missing), row(changed)}, 2
				case "SQL failure":
					rows, wantCalls = []pgx.Row{row(missing), htmlRevisionReadRowTestV1{err: context.Canceled}}, 2
				case "already measured":
					rows, wantCalls = rows[1:], 2
				}
				tx := &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: rows}
				session.state.tx = tx
				var reader *ApplicationHTMLAuthoringReaderV1
				var source *ApplicationBlocksTemplateSourceV1
				t.Cleanup(func() {
					if source != nil {
						source.CloseConsumerV1()
					}
					if reader != nil {
						reader.CloseConsumerV1()
					}
					if !applicationDoneV1(f.done) {
						close(f.done)
					}
					cleanup, stop := context.WithTimeout(context.Background(), time.Second)
					defer stop()
					_ = f.adapter.CloseV1(cleanup)
				})
				guards := 0
				err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
					var err error
					reader, err = session.NewHTMLAuthoringReaderV1(call)
					if err != nil {
						return err
					}
					source, err = session.NewBlocksTemplateSourceV1(call, reader)
					if err != nil {
						return err
					}
					guard := func(context.Context) error { guards++; return nil }
					var result *generated.Template
					if update {
						result, err = source.GetTemplateForUpdateAfterHeaderV1(call, generated.GetTemplateForUpdateParams{ID: tpl.ID, OrgID: tpl.OrgID}, guard)
					} else {
						result, err = source.GetTemplateForShareAfterHeaderV1(call, generated.GetTemplateForShareParams{ID: tpl.ID, OrgID: tpl.OrgID}, guard)
					}
					if wantOK && (result == nil || result.Version != tpl.Version) {
						return errors.New("reader lost current source")
					}
					return err
				})
				if (err == nil) != wantOK || tx.calls != wantCalls || len(tx.rows) != 0 || guards != 1 {
					t.Fatalf("bounded source refresh: success=%t calls=%d remaining=%d guards=%d", err == nil, tx.calls, len(tx.rows), guards)
				}
			})
		}
	}
}
