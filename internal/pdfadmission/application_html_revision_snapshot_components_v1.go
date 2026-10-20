// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"errors"
	"math"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/google/uuid"
)

// These are checked logical JSON/text/row components, NOT a native grant or a
// PostgreSQL working-memory/RSS bound. The fixed owner must derive them from
// its actual fresh M94 header after parent->subject->chain, ordered cache pins
// and exact header recheck, plus its original private body snapshot. Neither
// this arithmetic nor caller-supplied values prove provenance or policy.
var errHTMLRevisionSnapshotComponentsV1 = errors.New("pdfadmission: HTML revision snapshot components unavailable")

const (
	// UUID is36 ASCII characters plus JSON quotes; int4 includes its sign.
	htmlRevisionSnapshotUUIDJSONV1 int64 = 38
	htmlRevisionSnapshotInt4JSONV1 int64 = 11
	// PostgreSQL timestamptz has a finite int64-microsecond range, six-digit
	// endpoint years, microseconds/zone/BC suffix, or short infinity spelling.
	// INET is at most16 address bytes plus a128 prefix.64 includes JSON quotes.
	htmlRevisionSnapshotTimeJSONV1 int64 = 64
	htmlRevisionSnapshotINETJSONV1 int64 = 64
	// NUMERIC(7,4) finite output needs <=9 bytes including sign; this also
	// covers quoted non-finite spellings without assuming application validity.
	htmlRevisionSnapshotNumericJSONV1 int64 = 32
	// A nullable TEXT slot needs4 for null, or quotes plus6*actual UTF8 bytes.
	htmlRevisionSnapshotTextSlotJSONV1 int64 = 4
	// bytea hex and escape output both fit6*octet_length+8 after JSON escaping.
	// Do not assume bytea_output=hex: an escaped octal byte can use5 JSON bytes.
	htmlRevisionSnapshotBinarySlotJSONV1 int64 = 8
)

var htmlRevisionSnapshotFieldKeysV1 = [...]string{"id", "document_id", "recipient_id", "type", "page", "x_pct", "y_pct", "w_pct", "h_pct", "required", "label", "options_json", "value", "completed_at", "created_at"}
var htmlRevisionSnapshotRecipientKeysV1 = [...]string{"id", "document_id", "email", "name", "role", "status", "order_index", "locale", "created_at"}
var htmlRevisionSnapshotBrandingKeysV1 = [...]string{"document_id", "primary_hex", "accent_hex", "surface_hex", "text_hex", "muted_hex", "logo_url", "logo_alt", "font_heading", "font_body", "signature_color", "updated_at"}
var htmlRevisionSnapshotNoticeKeysV1 = [...]string{"schema", "epoch_at", "sent_at", "epoch_committed", "lawful_basis", "expires_at", "branding"}
var htmlRevisionSnapshotEventKeysV1 = [...]string{"id", "org_id", "document_id", "recipient_id", "actor_user_id", "kind", "ip", "ua", "payload_json", "created_at", "prev_hash", "row_hash", "payload_hashed"}
var htmlRevisionSnapshotHistoryKeysV1 = [...]string{"id", "document_id", "org_id", "materialization_id", "kind", "captured_updated_at", "source_json", "source_commitment", "pdf_key", "pdf_sha256", "pdf_version_id", "page_count", "rendered_pdf_key", "rendered_pdf_sha256", "rendered_pdf_version_id", "reviewed_pdf_sha256", "reviewed_by", "reviewed_at", "fields_json", "recipients_json", "notice_context_json", "ceremony_events_json", "notice_epoch_at", "retain_until", "created_by", "created_at", "metadata_redaction_report"}

func htmlRevisionSnapshotAddV1(total *int64, n, factor int64) bool {
	if total == nil || *total < 0 || n < 0 || factor < 0 || (factor != 0 && n > (math.MaxInt64-*total)/factor) {
		return false
	}
	*total += n * factor
	return true
}
func htmlRevisionSnapshotSumV1(values ...int64) (int64, error) {
	var n int64
	for _, value := range values {
		if !htmlRevisionSnapshotAddV1(&n, value, 1) {
			return 0, errHTMLRevisionSnapshotComponentsV1
		}
	}
	return n, nil
}

// All keys are actual fixed ASCII schema member names. JSONB text uses a colon
// and space plus comma/space separators; values are accounted separately.
func htmlRevisionSnapshotObjectFixedV1(keys []string, values int64) (int64, error) {
	n := int64(2)
	for i, key := range keys {
		if !htmlRevisionSnapshotAddV1(&n, int64(len(key))+4, 1) {
			return 0, errHTMLRevisionSnapshotComponentsV1
		}
		if i > 0 && !htmlRevisionSnapshotAddV1(&n, 2, 1) {
			return 0, errHTMLRevisionSnapshotComponentsV1
		}
	}
	if !htmlRevisionSnapshotAddV1(&n, values, 1) {
		return 0, errHTMLRevisionSnapshotComponentsV1
	}
	return n, nil
}
func htmlRevisionSnapshotArrayV1(count, rowFixed, raw, binary, wire int64) (int64, error) {
	n := int64(2) // [] remains real output even when count is zero.
	if !htmlRevisionSnapshotAddV1(&n, count, rowFixed) || !htmlRevisionSnapshotAddV1(&n, count, 2) || !htmlRevisionSnapshotAddV1(&n, raw, 6) || !htmlRevisionSnapshotAddV1(&n, binary, 6) || !htmlRevisionSnapshotAddV1(&n, wire, 1) {
		return 0, errHTMLRevisionSnapshotComponentsV1
	}
	return n, nil
}

type htmlRevisionSnapshotStatementComponentsV1 struct {
	contextCalls, contextJSONBytes                                           int64
	historyRows, historyJSONBytes, historyRawBytes, historyRowJSONBytes      int64
	freshSnapshotJSONBytes, freshSnapshotRawBytes, freshSnapshotRowJSONBytes int64
	// These logical masses deliberately sum rather than infer alias reuse.
	// They still need a separately qualified PostgreSQL working-arena adapter.
	logicalJSONBytes, logicalRowJSONBytes int64
}
type htmlRevisionSnapshotCollectionComponentsV1 struct {
	fieldsJSONBytes, recipientsJSONBytes, brandingJSONBytes, noticeJSONBytes, eventsJSONBytes, contextJSONBytes int64
	historyRows, historyJSONBytes, historyRawBytes, historyRowJSONBytes                                         int64
	freshSnapshotJSONBytes, freshSnapshotRawBytes, freshSnapshotRowJSONBytes                                    int64
	capture, measureFresh, clear, project                                                                       htmlRevisionSnapshotStatementComponentsV1
}

// Native owner must use its actual private retained Document/Current, not the
// mutable exposed application model. No size, scope, lock or grant receipt is
// manufactured here. Count growth is checked, never capped or truncated.
func htmlRevisionSnapshotCollectionComponentsForV1(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, doc *generated.Document, current *htmlmaterialization.CurrentReadProjectionV1) (htmlRevisionSnapshotCollectionComponentsV1, error) {
	var out htmlRevisionSnapshotCollectionComponentsV1
	fail := func() (htmlRevisionSnapshotCollectionComponentsV1, error) {
		return htmlRevisionSnapshotCollectionComponentsV1{}, errHTMLRevisionSnapshotComponentsV1
	}
	if h == nil || doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || h.ID != doc.ID || h.OrgID != doc.OrgID || h.UpdatedAt != doc.UpdatedAt || !h.UpdatedAt.Valid || h.ServerVersionNum <= 0 {
		return fail()
	}
	for _, n := range []int64{h.FieldCount, h.MeasuredFieldCount, h.RecipientCount, h.BrandingCount, h.EventCount, h.MeasuredEventCount, h.EventScopeMismatchCount, h.HistoryCount, h.MeasuredHistoryCount, h.FieldRawTextBytes, h.FieldOptionsWireBytes, h.RecipientRawTextBytes, h.BrandingRawTextBytes, h.NoticeRawTextBytes, h.EventRawTextBytes, h.EventBinaryBytes, h.EventPayloadWireBytes, h.HistoryRawTextBytes, h.HistoryWireBytes} {
		if n < 0 {
			return fail()
		}
	}
	if h.MeasuredFieldCount != h.FieldCount || h.MeasuredEventCount != h.EventCount || h.MeasuredHistoryCount != h.HistoryCount || h.EventScopeMismatchCount != 0 || h.BrandingCount > 1 {
		return fail()
	}
	if (h.FieldCount == 0 && (h.FieldRawTextBytes != 0 || h.FieldOptionsWireBytes != 0)) || (h.RecipientCount == 0 && h.RecipientRawTextBytes != 0) || (h.BrandingCount == 0 && h.BrandingRawTextBytes != 0) || (h.EventCount == 0 && (h.EventRawTextBytes != 0 || h.EventBinaryBytes != 0 || h.EventPayloadWireBytes != 0)) || (h.HistoryCount == 0 && (h.HistoryRawTextBytes != 0 || h.HistoryWireBytes != 0)) {
		return fail()
	}
	noticeRaw, err := htmlRevisionSnapshotSumV1(int64(len(doc.Article13NoticeSchema)), int64(len(doc.LawfulBasis)))
	if err != nil || noticeRaw != h.NoticeRawTextBytes {
		return fail()
	}
	source := doc.HtmlSourceJson
	if doc.HtmlCurrentMaterializationID.Valid {
		if current == nil || current.ID == uuid.Nil || current.ID != uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) || current.DocumentID != doc.ID || current.OrgID != doc.OrgID || len(doc.HtmlCurrentSourceJson) == 0 {
			return fail()
		}
		source = doc.HtmlCurrentSourceJson
	} else if current != nil || len(doc.HtmlCurrentSourceJson) != 0 {
		return fail()
	}
	if len(source) == 0 {
		return fail()
	}

	fieldFixed, err := htmlRevisionSnapshotObjectFixedV1(htmlRevisionSnapshotFieldKeysV1[:], 3*htmlRevisionSnapshotUUIDJSONV1+htmlRevisionSnapshotInt4JSONV1+4*htmlRevisionSnapshotNumericJSONV1+5+3*htmlRevisionSnapshotTextSlotJSONV1+2*htmlRevisionSnapshotTimeJSONV1)
	if err != nil {
		return fail()
	}
	out.fieldsJSONBytes, err = htmlRevisionSnapshotArrayV1(h.FieldCount, fieldFixed, h.FieldRawTextBytes, 0, h.FieldOptionsWireBytes)
	if err != nil {
		return fail()
	}
	recipientFixed, err := htmlRevisionSnapshotObjectFixedV1(htmlRevisionSnapshotRecipientKeysV1[:], 2*htmlRevisionSnapshotUUIDJSONV1+htmlRevisionSnapshotInt4JSONV1+htmlRevisionSnapshotTimeJSONV1+5*htmlRevisionSnapshotTextSlotJSONV1)
	if err != nil {
		return fail()
	}
	// Header also counts declined_reason and magic_token_hash for full native
	// Recipient reads. Charging those omitted snapshot bytes is conservative.
	out.recipientsJSONBytes, err = htmlRevisionSnapshotArrayV1(h.RecipientCount, recipientFixed, h.RecipientRawTextBytes, 0, 0)
	if err != nil {
		return fail()
	}
	out.brandingJSONBytes = 4 // SQL absence becomes JSON null inside notice.
	if h.BrandingCount == 1 {
		out.brandingJSONBytes, err = htmlRevisionSnapshotObjectFixedV1(htmlRevisionSnapshotBrandingKeysV1[:], htmlRevisionSnapshotUUIDJSONV1+htmlRevisionSnapshotTimeJSONV1+10*htmlRevisionSnapshotTextSlotJSONV1)
		if err != nil || !htmlRevisionSnapshotAddV1(&out.brandingJSONBytes, h.BrandingRawTextBytes, 6) {
			return fail()
		}
	}
	out.noticeJSONBytes, err = htmlRevisionSnapshotObjectFixedV1(htmlRevisionSnapshotNoticeKeysV1[:], 3*htmlRevisionSnapshotTimeJSONV1+5+2*htmlRevisionSnapshotTextSlotJSONV1)
	if err != nil || !htmlRevisionSnapshotAddV1(&out.noticeJSONBytes, noticeRaw, 6) || !htmlRevisionSnapshotAddV1(&out.noticeJSONBytes, out.brandingJSONBytes, 1) {
		return fail()
	}
	eventFixed, err := htmlRevisionSnapshotObjectFixedV1(htmlRevisionSnapshotEventKeysV1[:], 5*htmlRevisionSnapshotUUIDJSONV1+htmlRevisionSnapshotINETJSONV1+htmlRevisionSnapshotTimeJSONV1+2*htmlRevisionSnapshotTextSlotJSONV1+3*htmlRevisionSnapshotBinarySlotJSONV1)
	if err != nil {
		return fail()
	}
	out.eventsJSONBytes, err = htmlRevisionSnapshotArrayV1(h.EventCount, eventFixed, h.EventRawTextBytes, h.EventBinaryBytes, h.EventPayloadWireBytes)
	if err != nil {
		return fail()
	}
	out.contextJSONBytes, err = htmlRevisionSnapshotSumV1(out.fieldsJSONBytes, out.recipientsJSONBytes, out.noticeJSONBytes, out.eventsJSONBytes)
	if err != nil {
		return fail()
	}
	// The complete immutable snapshot row has6 UUIDs,5 timestamps,int4,
	// 5 TEXT and4 BYTEA columns plus6 JSONB columns. JSON slots add null room;
	// raw cache combines TEXT/BYTEA, so6x is required rather than hex-only2x.
	historyFixed, err := htmlRevisionSnapshotObjectFixedV1(htmlRevisionSnapshotHistoryKeysV1[:], 6*htmlRevisionSnapshotUUIDJSONV1+5*htmlRevisionSnapshotTimeJSONV1+htmlRevisionSnapshotInt4JSONV1+5*htmlRevisionSnapshotTextSlotJSONV1+4*htmlRevisionSnapshotBinarySlotJSONV1+6*4)
	if err != nil {
		return fail()
	}
	out.historyRows, out.historyJSONBytes, out.historyRawBytes = h.HistoryCount, h.HistoryWireBytes, h.HistoryRawTextBytes
	out.historyRowJSONBytes, err = htmlRevisionSnapshotArrayV1(h.HistoryCount, historyFixed, h.HistoryRawTextBytes, 0, h.HistoryWireBytes)
	if err != nil {
		return fail()
	}
	out.freshSnapshotJSONBytes, err = htmlRevisionSnapshotSumV1(int64(len(source)), int64(len(doc.MetadataRedactionReport)), out.contextJSONBytes)
	if err != nil {
		return fail()
	}
	// Both allowed actual snapshot kinds are16 bytes. Source commitment is
	// intrinsically32 by M74. Other variable fields are exact original doc data.
	out.freshSnapshotRawBytes, err = htmlRevisionSnapshotSumV1(16, 32, int64(len(doc.PdfStorageKey.String)), int64(len(doc.PdfSha256)), int64(len(doc.PdfStorageVersionID.String)), int64(len(doc.RenderedPdfKey.String)), int64(len(doc.RenderedPdfSha)), int64(len(doc.RenderedPdfVersionID.String)), int64(len(doc.HtmlReviewedPdfSha256)))
	if err != nil {
		return fail()
	}
	out.freshSnapshotRowJSONBytes = historyFixed
	if !htmlRevisionSnapshotAddV1(&out.freshSnapshotRowJSONBytes, out.freshSnapshotRawBytes, 6) || !htmlRevisionSnapshotAddV1(&out.freshSnapshotRowJSONBytes, out.freshSnapshotJSONBytes, 1) {
		return fail()
	}

	// Capture SELECT and unchanged M74 BEFORE INSERT guard each call the full
	// context once. Fresh row/output is budgeted separately, with no alias credit.
	out.capture, err = htmlRevisionSnapshotStatementV1(out, 2, false, true)
	if err != nil {
		return fail()
	}
	// Intrinsic fresh measurement serializes all6 JSON values, but creates no
	// additional context and returns only fixed cache metadata.
	out.measureFresh, err = htmlRevisionSnapshotStatementV1(out, 0, false, true)
	if err != nil {
		return fail()
	}
	// Fixed new Clear MATERIALIZED context is once. M74 Project trigger is at
	// most once (later materialization only). Both compare complete old history
	// including this new capture. Between these stages only unsigned fields may
	// be removed; no event/recipient/notice growth is covered by the old header.
	out.clear, err = htmlRevisionSnapshotStatementV1(out, 1, true, false)
	if err != nil {
		return fail()
	}
	out.project, err = htmlRevisionSnapshotStatementV1(out, 1, true, false)
	if err != nil {
		return fail()
	}
	return out, nil
}

func htmlRevisionSnapshotStatementV1(c htmlRevisionSnapshotCollectionComponentsV1, contextCalls int64, historyAfterCapture, freshOutput bool) (htmlRevisionSnapshotStatementComponentsV1, error) {
	var out htmlRevisionSnapshotStatementComponentsV1
	out.contextCalls = contextCalls
	if !htmlRevisionSnapshotAddV1(&out.contextJSONBytes, c.contextJSONBytes, contextCalls) {
		return out, errHTMLRevisionSnapshotComponentsV1
	}
	if historyAfterCapture {
		var err error
		out.historyRows, err = htmlRevisionSnapshotSumV1(c.historyRows, 1)
		if err != nil {
			return out, err
		}
		out.historyJSONBytes, err = htmlRevisionSnapshotSumV1(c.historyJSONBytes, c.freshSnapshotJSONBytes)
		if err != nil {
			return out, err
		}
		out.historyRawBytes, err = htmlRevisionSnapshotSumV1(c.historyRawBytes, c.freshSnapshotRawBytes)
		if err != nil {
			return out, err
		}
		out.historyRowJSONBytes, err = htmlRevisionSnapshotSumV1(c.historyRowJSONBytes, c.freshSnapshotRowJSONBytes, 2)
		if err != nil {
			return out, err
		}
	}
	if freshOutput {
		out.freshSnapshotJSONBytes = c.freshSnapshotJSONBytes
		out.freshSnapshotRawBytes = c.freshSnapshotRawBytes
		out.freshSnapshotRowJSONBytes = c.freshSnapshotRowJSONBytes
	}
	var err error
	out.logicalJSONBytes, err = htmlRevisionSnapshotSumV1(out.contextJSONBytes, out.historyJSONBytes, out.freshSnapshotJSONBytes)
	if err != nil {
		return out, err
	}
	out.logicalRowJSONBytes, err = htmlRevisionSnapshotSumV1(out.contextJSONBytes, out.historyRowJSONBytes, out.freshSnapshotRowJSONBytes)
	if err != nil {
		return out, err
	}
	return out, nil
}
