// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Pure component oracle only. Synthetic header/row values grant no SQL cache,
// scope, source validity, retirement or work authority. Root must qualify actual
// PostgreSQL JSONB output and the original statements independently.
func htmlRevisionSnapshotFixtureV1() (*generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, *generated.Document) {
	stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), Valid: true}
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), UpdatedAt: stamp, Article13NoticeSchema: "hash-a13", LawfulBasis: "contract", HtmlSourceJson: []byte("{}"), MetadataRedactionReport: []byte("{}"), PdfStorageKey: pgtype.Text{String: "source/key", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "version", Valid: true}, PdfSha256: bytes.Repeat([]byte{7}, 32)}
	h := &generated.GetHTMLRevisionSnapshotSizeHeaderV1Row{ID: doc.ID, OrgID: doc.OrgID, UpdatedAt: stamp, ServerVersionNum: 160015, NoticeRawTextBytes: int64(len(doc.Article13NoticeSchema) + len(doc.LawfulBasis))}
	return h, doc
}
func htmlRevisionSnapshotWireOracleV1(t *testing.T, v any) int64 {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	n, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(applicationTestContextV1(t), raw)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func htmlRevisionSnapshotTextBytesV1(values ...string) int64 {
	var n int64
	for _, value := range values {
		n += int64(len(value))
	}
	return n
}
func htmlRevisionSnapshotEscapeByteaV1(raw []byte) string {
	// Octal-escape every byte, including printable ones: an independent worst
	// valid escape representation. JSON quoting doubles each backslash.
	var out strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&out, "\\%03o", b)
	}
	return out.String()
}
func TestHTMLRevisionSnapshotFullRowAndContextJSONComponentsV1(t *testing.T) {
	h, doc := htmlRevisionSnapshotFixtureV1()
	text := strings.Repeat("é<&\\\"\n\u0001", 17)
	id := uuid.New().String()
	field := map[string]any{"id": id, "document_id": doc.ID.String(), "recipient_id": id, "type": "signature", "page": int32(math.MinInt32), "x_pct": json.RawMessage("-999.9999"), "y_pct": json.RawMessage("0.0000"), "w_pct": json.RawMessage("999.9999"), "h_pct": json.RawMessage("1.0000"), "required": true, "label": text, "options_json": map[string]any{"label": text, "empty": []any{}}, "value": text, "completed_at": "infinity", "created_at": "294276-12-31T23:59:59.999999+15:59:59"}
	h.FieldCount = 1
	h.MeasuredFieldCount = 1
	h.FieldRawTextBytes = htmlRevisionSnapshotTextBytesV1("signature", text, text)
	h.FieldOptionsWireBytes = htmlRevisionSnapshotWireOracleV1(t, field["options_json"])
	party := map[string]any{"id": id, "document_id": doc.ID.String(), "email": text, "name": text, "role": "customer", "status": "pending", "order_index": int32(math.MinInt32), "locale": "sv", "created_at": "4714-11-24T00:00:00.000001-15:59:59 BC"}
	h.RecipientCount = 1
	h.RecipientRawTextBytes = htmlRevisionSnapshotTextBytesV1(text, text, "customer", "pending", "sv", "omitted declined reason") + 4096 // full credential BYTEA is omitted by M74 but counted by M94.
	brand := map[string]any{"document_id": doc.ID.String(), "updated_at": "infinity"}
	for _, key := range htmlRevisionSnapshotBrandingKeysV1[1:11] {
		brand[key] = text
		h.BrandingRawTextBytes += int64(len(text))
	}
	h.BrandingCount = 1
	notice := map[string]any{"schema": doc.Article13NoticeSchema, "epoch_at": "infinity", "sent_at": "-infinity", "epoch_committed": true, "lawful_basis": doc.LawfulBasis, "expires_at": "294276-12-31T23:59:59.999999+15:59:59", "branding": brand}
	payload := map[string]any{"text": text, "nested": []any{map[string]any{}, []any{}, true, 1}}
	binary := []byte{0, 1, 31, 92, 127, 128, 255}
	for _, mode := range []string{"escape", "hex"} {
		t.Run(mode, func(t *testing.T) {
			rawBytea := htmlRevisionSnapshotEscapeByteaV1(binary)
			if mode == "hex" {
				rawBytea = "\\x" + hex.EncodeToString(binary)
			}
			event := map[string]any{"id": id, "org_id": doc.OrgID.String(), "document_id": doc.ID.String(), "recipient_id": id, "actor_user_id": id, "kind": text, "ip": "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128", "ua": text, "payload_json": payload, "created_at": "294276-12-31T23:59:59.999999+15:59:59", "prev_hash": rawBytea, "row_hash": rawBytea, "payload_hashed": rawBytea}
			h.EventCount = 1
			h.MeasuredEventCount = 1
			h.EventRawTextBytes = 2 * int64(len(text))
			h.EventBinaryBytes = 3 * int64(len(binary))
			h.EventPayloadWireBytes = htmlRevisionSnapshotWireOracleV1(t, payload)
			got, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range []struct {
				name   string
				bound  int64
				actual any
			}{{"fields", got.fieldsJSONBytes, []any{field}}, {"recipients", got.recipientsJSONBytes, []any{party}}, {"branding", got.brandingJSONBytes, brand}, {"notice", got.noticeJSONBytes, notice}, {"events", got.eventsJSONBytes, []any{event}}} {
				if actual := htmlRevisionSnapshotWireOracleV1(t, part.actual); part.bound < actual {
					t.Fatalf("%s envelope %d < independent output %d", part.name, part.bound, actual)
				}
			}
			if got.contextJSONBytes != got.fieldsJSONBytes+got.recipientsJSONBytes+got.noticeJSONBytes+got.eventsJSONBytes {
				t.Fatal("complete context omitted a collection")
			}
		})
	}
}
func TestHTMLRevisionSnapshotEmptyRowsCountsAndFixedStatementTopologyV1(t *testing.T) {
	h, doc := htmlRevisionSnapshotFixtureV1()
	empty, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty.fieldsJSONBytes != 2 || empty.recipientsJSONBytes != 2 || empty.eventsJSONBytes != 2 || empty.brandingJSONBytes != 4 || empty.noticeJSONBytes <= 4 {
		t.Fatal("empty arrays/absent branding/notice disappeared")
	}
	// Existing row counts remain unbounded by application policy; even rows
	// with no variable bytes must pay actual fixed member/type overhead.
	h.FieldCount = 1000000
	h.MeasuredFieldCount = h.FieldCount
	h.RecipientCount = 1000000
	h.EventCount = 1000000
	h.MeasuredEventCount = h.EventCount
	h.HistoryCount = 1000000
	h.MeasuredHistoryCount = h.HistoryCount
	many, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, nil)
	if err != nil {
		t.Fatal("invented collection row cap", err)
	}
	if many.fieldsJSONBytes <= h.FieldCount || many.recipientsJSONBytes <= h.RecipientCount || many.eventsJSONBytes <= h.EventCount || many.historyRowJSONBytes <= h.HistoryCount {
		t.Fatal("empty actual rows lost their fixed schema overhead")
	}
	if many.capture.contextCalls != 2 || many.capture.contextJSONBytes != 2*many.contextJSONBytes || many.capture.freshSnapshotJSONBytes != many.freshSnapshotJSONBytes {
		t.Fatal("actual Capture SELECT/guard topology changed")
	}
	if many.measureFresh.contextCalls != 0 || many.measureFresh.freshSnapshotJSONBytes != many.freshSnapshotJSONBytes {
		t.Fatal("intrinsic sixJSON measurement component changed")
	}
	for _, stage := range []htmlRevisionSnapshotStatementComponentsV1{many.clear, many.project} {
		if stage.contextCalls != 1 || stage.contextJSONBytes != many.contextJSONBytes || stage.historyRows != h.HistoryCount+1 || stage.historyJSONBytes != h.HistoryWireBytes+many.freshSnapshotJSONBytes || stage.historyRawBytes != h.HistoryRawTextBytes+many.freshSnapshotRawBytes || stage.freshSnapshotJSONBytes != 0 {
			t.Fatal("complete old history plus exact new capture not retained", stage)
		}
	}
	if many.clear.historyRowJSONBytes < many.historyRowJSONBytes+many.freshSnapshotRowJSONBytes {
		t.Fatal("fresh capture lost from later comparison collection")
	}
}
func TestHTMLRevisionSnapshotCompleteHistoryAndFreshWireComponentsV1(t *testing.T) {
	h, doc := htmlRevisionSnapshotFixtureV1()
	text := strings.Repeat("é<&\\\"\n\u0001", 13)
	binary := []byte{0, 31, 92, 128, 255}
	b := htmlRevisionSnapshotEscapeByteaV1(binary)
	id := uuid.New().String()
	six := []any{map[string]any{"source": text}, []any{}, []any{}, map[string]any{"notice": text}, []any{}, nil}
	row := map[string]any{"id": id, "document_id": doc.ID.String(), "org_id": doc.OrgID.String(), "materialization_id": id, "kind": "draft_superseded", "captured_updated_at": "infinity", "source_json": six[0], "source_commitment": b, "pdf_key": text, "pdf_sha256": b, "pdf_version_id": text, "page_count": int32(math.MinInt32), "rendered_pdf_key": text, "rendered_pdf_sha256": b, "rendered_pdf_version_id": text, "reviewed_pdf_sha256": b, "reviewed_by": id, "reviewed_at": "-infinity", "fields_json": six[1], "recipients_json": six[2], "notice_context_json": six[3], "ceremony_events_json": six[4], "notice_epoch_at": "infinity", "retain_until": "infinity", "created_by": id, "created_at": "infinity", "metadata_redaction_report": nil}
	var oneWire int64
	for _, value := range six {
		if value != nil {
			oneWire += htmlRevisionSnapshotWireOracleV1(t, value)
		}
	}
	oneRaw := htmlRevisionSnapshotTextBytesV1("draft_superseded", text, text, text, text) + 4*int64(len(binary))
	h.HistoryCount = 2
	h.MeasuredHistoryCount = 2
	h.HistoryWireBytes = 2 * oneWire
	h.HistoryRawTextBytes = 2 * oneRaw
	got, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.historyRows != 2 || got.historyJSONBytes != 2*oneWire || got.historyRawBytes != 2*oneRaw {
		t.Fatal("six historical JSON/cache raw/count sums were narrowed")
	}
	if actual := htmlRevisionSnapshotWireOracleV1(t, []any{row, row}); got.historyRowJSONBytes < actual {
		t.Fatalf("complete historical row envelope %d < %d", got.historyRowJSONBytes, actual)
	}
	if got.freshSnapshotJSONBytes != int64(len(doc.HtmlSourceJson)+len(doc.MetadataRedactionReport))+got.contextJSONBytes {
		t.Fatal("fresh source/report/context sixJSON mass omitted")
	}
	if got.clear.historyRows != 3 || got.project.historyRows != 3 {
		t.Fatal("one genuine fresh capture missing from full later history")
	}
	// Actual normalized current projection replaces origin for snapshot source.
	currentID := uuid.New()
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: currentID, Valid: true}
	doc.HtmlCurrentSourceJson = []byte("{\"current\":true}")
	current := &htmlmaterialization.CurrentReadProjectionV1{ID: currentID, DocumentID: doc.ID, OrgID: doc.OrgID, SourceJson: bytes.Clone(doc.HtmlCurrentSourceJson)}
	normalized, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, current)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.freshSnapshotJSONBytes-got.freshSnapshotJSONBytes != int64(len(doc.HtmlCurrentSourceJson)-len(doc.HtmlSourceJson)) {
		t.Fatal("fresh snapshot selected old origin instead of actual current")
	}
}
func TestHTMLRevisionSnapshotRefusesInvalidScopeCacheGrowthAndOverflowV1(t *testing.T) {
	for _, mutate := range []func(*generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, *generated.Document){func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) { h.OrgID = uuid.New() }, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) {
		h.UpdatedAt.Valid = false
	}, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) {
		h.ServerVersionNum = 0
	}, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) { h.FieldCount = 1 }, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) { h.EventCount = 1 }, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) {
		h.EventScopeMismatchCount = 1
	}, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) { h.HistoryCount = 1 }, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) { h.BrandingCount = 2 }, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) {
		h.NoticeRawTextBytes++
	}, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) {
		h.EventBinaryBytes = 1
	}, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) {
		h.FieldCount = math.MaxInt64
		h.MeasuredFieldCount = h.FieldCount
	}, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) {
		h.EventCount = 1
		h.MeasuredEventCount = 1
		h.EventBinaryBytes = math.MaxInt64
	}, func(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, d *generated.Document) {
		h.HistoryCount = 1
		h.MeasuredHistoryCount = 1
		h.HistoryWireBytes = math.MaxInt64
	}} {
		h, doc := htmlRevisionSnapshotFixtureV1()
		mutate(h, doc)
		if _, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, nil); err == nil {
			t.Fatal("missing scope/cache or wrapping collection accepted")
		}
	}
	h, doc := htmlRevisionSnapshotFixtureV1()
	v := reflect.ValueOf(h).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() != reflect.Int64 {
			continue
		}
		copy := *h
		reflect.ValueOf(&copy).Elem().Field(i).SetInt(-1)
		if _, err := htmlRevisionSnapshotCollectionComponentsForV1(&copy, doc, nil); err == nil {
			t.Fatalf("negative/sentinel header field accepted: %s", v.Type().Field(i).Name)
		}
	}
	current := &htmlmaterialization.CurrentReadProjectionV1{ID: uuid.New(), DocumentID: doc.ID, OrgID: doc.OrgID}
	if _, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, current); err == nil {
		t.Fatal("orphan current row accepted")
	}
}
func TestHTMLRevisionSnapshotFullRowSchemaInventoryV1(t *testing.T) {
	for _, item := range []struct {
		typ  reflect.Type
		keys []string
	}{{reflect.TypeOf(generated.DocumentField{}), htmlRevisionSnapshotFieldKeysV1[:]}, {reflect.TypeOf(generated.Event{}), htmlRevisionSnapshotEventKeysV1[:]}, {reflect.TypeOf(generated.DocumentBrandingOverride{}), htmlRevisionSnapshotBrandingKeysV1[:]}, {reflect.TypeOf(generated.HtmlDocumentMaterializationSnapshot{}), htmlRevisionSnapshotHistoryKeysV1[:]}} {
		var actual []string
		for i := 0; i < item.typ.NumField(); i++ {
			actual = append(actual, strings.Split(item.typ.Field(i).Tag.Get("json"), ",")[0])
		}
		expected := append([]string{}, item.keys...)
		sort.Strings(actual)
		sort.Strings(expected)
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("actual full-row schema changed for %s: %v", item.typ.Name(), actual)
		}
	}
}
