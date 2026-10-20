// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// These tests enter the real NewWriter/Append/field-update path using the
// constructed-writer component fixture. SQL rows and physical retirement are
// explicitly synthetic; they establish neither actual PG cache provenance nor
// managed-field/signing-page creation or complete route acceptance.
func htmlRevisionFreshMeasurementRowsTestV1(f *htmlRevisionWriterFixtureV1) (generated.DocumentSigningPolicySizesV1, generated.DocumentReadReportSizesV1) {
	return generated.DocumentSigningPolicySizesV1{
			DocumentID: f.document.ID, OrgID: f.document.OrgID,
			HtmlOriginWireBytes: 1, HtmlCurrentWireBytes: 1, VariablesWireBytes: 1,
			MeasurementServerVersionNum: 160015,
		}, generated.DocumentReadReportSizesV1{
			DocumentID: f.document.ID, OrgID: f.document.OrgID,
			ReportWireBytes: 1, MeasurementServerVersionNum: 160015,
		}
}

func TestHTMLRevisionFreshMeasurementsUseConstructedWriterAndRetainLoansV1(t *testing.T) {
	withHTMLRevisionConstructedWriterFixtureV1(t, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
		if f.writer == nil || !f.writer.appended || !f.writer.fieldsWritten || f.writer.measured || len(f.writer.freshFields) != 0 {
			t.Fatal("generic constructed writer did not reach its actual fresh measurement point")
		}
		policy, report := htmlRevisionFreshMeasurementRowsTestV1(f)
		f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: policy}, htmlRevisionReadRowTestV1{record: report})
		calls, before := f.tx.calls, f.coordinator.SnapshotV1(f.document.OrgID)
		if err := f.writer.MeasureFreshPolicyV1(call); err != nil {
			t.Fatal(err)
		}
		// Zero newly managed fields means exactly two dispatches: fresh document
		// policy and fresh report. No old-field list, M92 or maintenance read.
		if !f.writer.measured || f.tx.calls != calls+2 || len(f.tx.rows) != 0 || f.coordinator.SnapshotV1(f.document.OrgID) != before {
			t.Fatal("fresh dispatch count, once-only state or original held loans changed")
		}
		if err := f.writer.MeasureFreshPolicyV1(call); !errors.Is(err, ErrHTMLRevisionWriterV1) || f.tx.calls != calls+2 {
			t.Fatal("second measurement dispatched or escaped once-only refusal", err)
		}
		copied := &ApplicationHTMLRevisionWriterV1{self: f.writer}
		if err := copied.MeasureFreshPolicyV1(call); !errors.Is(err, ErrHTMLRevisionWriterV1) || f.tx.calls != calls+2 {
			t.Fatal("copied shell gained actual constructed-writer authority", err)
		}
	})
}

func TestHTMLRevisionFreshMeasurementsRejectReturnedScopeWireAndGenerationV1(t *testing.T) {
	type rowCase struct {
		name   string
		change func(*htmlRevisionWriterFixtureV1, *generated.DocumentSigningPolicySizesV1, *generated.DocumentReadReportSizesV1)
		calls  int
	}
	for _, tc := range []rowCase{
		{"policy_document", func(_ *htmlRevisionWriterFixtureV1, p *generated.DocumentSigningPolicySizesV1, _ *generated.DocumentReadReportSizesV1) {
			p.DocumentID = uuid.New()
		}, 1},
		{"policy_org", func(_ *htmlRevisionWriterFixtureV1, p *generated.DocumentSigningPolicySizesV1, _ *generated.DocumentReadReportSizesV1) {
			p.OrgID = uuid.New()
		}, 1},
		{"policy_generation_zero", func(_ *htmlRevisionWriterFixtureV1, p *generated.DocumentSigningPolicySizesV1, _ *generated.DocumentReadReportSizesV1) {
			p.MeasurementServerVersionNum = 0
		}, 1},
		{"origin_zero", func(_ *htmlRevisionWriterFixtureV1, p *generated.DocumentSigningPolicySizesV1, _ *generated.DocumentReadReportSizesV1) {
			p.HtmlOriginWireBytes = 0
		}, 1},
		{"origin_over_private_bound", func(f *htmlRevisionWriterFixtureV1, p *generated.DocumentSigningPolicySizesV1, _ *generated.DocumentReadReportSizesV1) {
			p.HtmlOriginWireBytes = f.writer.originWireUpper + 1
		}, 1},
		{"current_over_private_bound", func(f *htmlRevisionWriterFixtureV1, p *generated.DocumentSigningPolicySizesV1, _ *generated.DocumentReadReportSizesV1) {
			p.HtmlCurrentWireBytes = f.writer.sourceWireUpper + 1
		}, 1},
		{"variables_over_private_bound", func(f *htmlRevisionWriterFixtureV1, p *generated.DocumentSigningPolicySizesV1, _ *generated.DocumentReadReportSizesV1) {
			p.VariablesWireBytes = f.writer.variablesWireUpper + 1
		}, 1},
		{"report_document", func(_ *htmlRevisionWriterFixtureV1, _ *generated.DocumentSigningPolicySizesV1, r *generated.DocumentReadReportSizesV1) {
			r.DocumentID = uuid.New()
		}, 2},
		{"report_org", func(_ *htmlRevisionWriterFixtureV1, _ *generated.DocumentSigningPolicySizesV1, r *generated.DocumentReadReportSizesV1) {
			r.OrgID = uuid.New()
		}, 2},
		{"report_generation_disagrees", func(_ *htmlRevisionWriterFixtureV1, _ *generated.DocumentSigningPolicySizesV1, r *generated.DocumentReadReportSizesV1) {
			r.MeasurementServerVersionNum++
		}, 2},
		{"report_zero", func(_ *htmlRevisionWriterFixtureV1, _ *generated.DocumentSigningPolicySizesV1, r *generated.DocumentReadReportSizesV1) {
			r.ReportWireBytes = 0
		}, 2},
		{"report_over_private_bound", func(f *htmlRevisionWriterFixtureV1, _ *generated.DocumentSigningPolicySizesV1, r *generated.DocumentReadReportSizesV1) {
			r.ReportWireBytes = f.writer.reportWireUpper + 1
		}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHTMLRevisionConstructedWriterFixtureV1(t, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
				policy, report := htmlRevisionFreshMeasurementRowsTestV1(f)
				tc.change(f, &policy, &report)
				f.tx.rows = append(f.tx.rows, htmlRevisionReadRowTestV1{record: policy}, htmlRevisionReadRowTestV1{record: report})
				calls, before := f.tx.calls, f.coordinator.SnapshotV1(f.document.OrgID)
				if err := f.writer.MeasureFreshPolicyV1(call); !errors.Is(err, ErrHTMLRevisionWriterV1) {
					t.Fatal("returned stale/scope/wire disagreement accepted", err)
				}
				if f.writer.measured || f.tx.calls != calls+tc.calls || f.coordinator.SnapshotV1(f.document.OrgID) != before {
					t.Fatal("invalid measurement became complete, dispatched beyond refusal or credited live loans")
				}
			})
		})
	}
}

func TestHTMLRevisionFreshMeasurementsValidateRetainedProjectionBeforeDispatchV1(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*htmlRevisionWriterFixtureV1)
	}{
		{"updated_document", func(f *htmlRevisionWriterFixtureV1) { f.writer.updated.ID = uuid.New() }},
		{"updated_org", func(f *htmlRevisionWriterFixtureV1) { f.writer.updated.OrgID = uuid.New() }},
		{"current_row", func(f *htmlRevisionWriterFixtureV1) { f.writer.updated.HtmlCurrentMaterializationID.Bytes = uuid.New() }},
		{"current_sequence", func(f *htmlRevisionWriterFixtureV1) { f.writer.updated.HtmlCurrentMaterializationSequence.Int32++ }},
		{"row_document", func(f *htmlRevisionWriterFixtureV1) { f.writer.row.DocumentID = uuid.New() }},
		{"candidate_org", func(f *htmlRevisionWriterFixtureV1) { f.writer.candidate.document.OrgID = uuid.New() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHTMLRevisionConstructedWriterFixtureV1(t, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
				tc.change(f)
				calls := f.tx.calls
				if err := f.writer.MeasureFreshPolicyV1(call); !errors.Is(err, ErrHTMLRevisionWriterV1) || f.tx.calls != calls || f.writer.measured {
					t.Fatal("retained original/candidate/returned projection disagreement dispatched fresh measurement", err)
				}
			})
		})
	}
}

func TestHTMLRevisionFreshMeasurementsRejectCorruptFieldReceiptsBeforeAnyWriteV1(t *testing.T) {
	// Fault injection into private retained field receipts is a negative oracle.
	// This does not construct genuine managed fields or grant authority to IDs.
	for _, kind := range []string{"one_field", "count_mismatch", "old_id", "duplicate", "foreign_document", "oversize_options", "malformed_options"} {
		t.Run(kind, func(t *testing.T) {
			withHTMLRevisionConstructedWriterFixtureV1(t, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
				a, b := uuid.New(), uuid.New()
				fields := []*generated.DocumentField{{ID: a, DocumentID: f.document.ID, OptionsJson: []byte("{}")}, {ID: b, DocumentID: f.document.ID, OptionsJson: []byte("{}")}}
				ids := []uuid.UUID{a, b}
				switch kind {
				case "one_field":
					fields, ids = fields[:1], ids[:1]
				case "count_mismatch":
					ids = ids[:1]
				case "old_id":
					ids[0] = uuid.New()
				case "duplicate":
					fields[1].ID, ids[1] = a, a
				case "foreign_document":
					fields[1].DocumentID = uuid.New()
				case "oversize_options":
					fields[1].OptionsJson = []byte(`{"value":"` + strings.Repeat("x", 2048) + `"}`)
				case "malformed_options":
					fields[1].OptionsJson = []byte(`{"value":`)
				}
				f.writer.freshFields, f.writer.freshFieldIDs = fields, ids
				calls := f.tx.calls
				if err := f.writer.MeasureFreshPolicyV1(call); err == nil || f.tx.calls != calls || f.writer.measured {
					t.Fatal("invalid retained field identity/options reached the first cache write", err)
				}
			})
		})
	}
}

func TestHTMLRevisionFreshMeasurementsRejectForeignCallbackAndClosedWriterV1(t *testing.T) {
	withHTMLRevisionConstructedWriterFixtureV1(t, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
		foreign, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		calls := f.tx.calls
		if err := f.writer.MeasureFreshPolicyV1(foreign); !errors.Is(err, ErrHTMLRevisionWriterV1) || f.tx.calls != calls {
			t.Fatal("foreign callback dispatched through another native writer", err)
		}
		f.writer.CloseConsumerV1()
		if err := f.writer.MeasureFreshPolicyV1(call); !errors.Is(err, ErrHTMLRevisionWriterV1) || f.tx.calls != calls {
			t.Fatal("closed writer dispatched measurements", err)
		}
	})
}
