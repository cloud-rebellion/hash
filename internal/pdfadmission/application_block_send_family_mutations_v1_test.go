// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"reflect"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func blockSendFamilyTupleFixtureV1(status string) (*generated.Document, *generated.Document) {
	rootID := uuid.MustParse("c6929f5a-21d8-4b5b-89ce-bc7e152a1d86")
	org := uuid.MustParse("136f408d-7da0-4fdd-bc10-759c52af032b")
	stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 10, 20, 0, 0, time.UTC), Valid: true}
	root := &generated.Document{
		ID: rootID, OrgID: org, IsEnvelope: true, SourceKind: "blocks", Status: "sent",
		SentAt: stamp, Article13NoticeEpochAt: stamp, Article13NoticeSchema: "hash-a13-2026-08-31",
		Article13NoticeEpochV61Committed: true,
	}
	child := &generated.Document{
		ID: uuid.MustParse("a0a23355-ab13-460b-98f0-6093aef2515a"), OrgID: org,
		ParentEnvelopeID: pgtype.UUID{Bytes: rootID, Valid: true}, EnvelopePosition: pgtype.Int4{Int32: 1, Valid: true},
		Name: "Original child", Status: status, SourceKind: "blocks", RoutingTier: "ses",
		BlocksJson: []byte("{\"version\":1,\"blocks\":[]}"), VariablesJson: []byte("{\"amount\":\"20\"}"),
		Metadata: []byte("{\"internal\":\"kept\"}"), MetadataRedactionReport: []byte("{}"),
		PdfSha256: []byte{1, 2, 3}, RenderedPdfSha: []byte{4, 5, 6}, HtmlSourceJson: nil,
		RequiresSignature: true, EvidenceVersionPinsRequired: true, CreatedAt: stamp, UpdatedAt: stamp,
		SignatureFitReservedBytes: 17, SigningAdmissionCount: 2, DefaultLocale: "sv",
	}
	return child, root
}
func blockSendFamilyCompleteFixtureV1(before, root *generated.Document) *generated.Document {
	after := htmlSendCloneDocumentV1(before)
	after.Status = "sent"
	after.SentAt = root.SentAt
	after.Article13NoticeEpochAt = root.Article13NoticeEpochAt
	after.Article13NoticeSchema = root.Article13NoticeSchema
	after.Article13NoticeEpochV61Committed = true
	after.UpdatedAt = pgtype.Timestamptz{Time: root.SentAt.Time.Add(time.Second), Valid: true}
	return after
}

// Mutate a real exported field without sharing mutable byte backing with the
// fixture. This tests every generated Document column, including newly added
// columns, against the independently specified SQL delta contract.
func blockSendMutateTupleFieldV1(v reflect.Value) bool {
	if !v.CanSet() {
		return false
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(v.String() + " changed")
		return true
	case reflect.Bool:
		v.SetBool(!v.Bool())
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(v.Int() + 1)
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
		return true
	case reflect.Array:
		if v.Len() != 0 {
			return blockSendMutateTupleFieldV1(v.Index(0))
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			out := reflect.MakeSlice(v.Type(), v.Len()+1, v.Len()+1)
			reflect.Copy(out, v)
			out.Index(v.Len()).SetUint(255)
			v.Set(out)
			return true
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if blockSendMutateTupleFieldV1(v.Field(i)) {
				return true
			}
		}
	}
	return false
}
func blockSendAssertEveryProtectedColumnV1(t *testing.T, after *generated.Document, accept func(*generated.Document) bool) {
	t.Helper()
	typ := reflect.TypeOf(*after)
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if name == "UpdatedAt" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			changed := htmlSendCloneDocumentV1(after)
			if !blockSendMutateTupleFieldV1(reflect.ValueOf(changed).Elem().Field(i)) {
				t.Fatalf("no mutation available for actual Document column %s", name)
			}
			if accept(changed) {
				t.Fatalf("unexpected full-row mutation of %s crossed family SQL delta guard", name)
			}
		})
	}
}

func TestBlockSendFamilyBeginExactFullTupleV1(t *testing.T) {
	before, _ := blockSendFamilyTupleFixtureV1("draft")
	after := htmlSendCloneDocumentV1(before)
	after.Status = "sealing"
	after.UpdatedAt.Time = after.UpdatedAt.Time.Add(time.Second)
	if !blockSendFamilyBeginTupleV1(before, after) {
		t.Fatal("actual Begin SQL status/time delta refused")
	}
	blockSendAssertEveryProtectedColumnV1(t, after, func(row *generated.Document) bool { return blockSendFamilyBeginTupleV1(before, row) })
	if before.Status != "draft" {
		t.Fatal("old immutable source tuple changed")
	}
	if blockSendFamilyBeginTupleV1(nil, after) || blockSendFamilyBeginTupleV1(before, nil) {
		t.Fatal("nil full row accepted")
	}
	wrong := htmlSendCloneDocumentV1(before)
	wrong.Status = "sent"
	if blockSendFamilyBeginTupleV1(wrong, after) {
		t.Fatal("only an actual draft can begin sealing")
	}
}

func TestBlockSendFamilyCompleteExactCopiedRootTupleV1(t *testing.T) {
	before, root := blockSendFamilyTupleFixtureV1("sealing")
	after := blockSendFamilyCompleteFixtureV1(before, root)
	if !blockSendFamilyCompleteTupleV1(before, after, root) {
		t.Fatal("actual Complete SQL copied-root delta refused")
	}
	blockSendAssertEveryProtectedColumnV1(t, after, func(row *generated.Document) bool { return blockSendFamilyCompleteTupleV1(before, row, root) })
	for _, name := range []string{"ID", "OrgID", "IsEnvelope", "ParentEnvelopeID", "Status", "SentAt", "Article13NoticeEpochAt", "Article13NoticeSchema", "Article13NoticeEpochV61Committed"} {
		t.Run("root "+name, func(t *testing.T) {
			changed := htmlSendCloneDocumentV1(root)
			f := reflect.ValueOf(changed).Elem().FieldByName(name)
			if name == "ParentEnvelopeID" {
				changed.ParentEnvelopeID.Valid = true
			} else if !blockSendMutateTupleFieldV1(f) {
				t.Fatalf("cannot mutate root %s", name)
			}
			if blockSendFamilyCompleteTupleV1(before, after, changed) {
				t.Fatalf("foreign or mismatched root %s accepted", name)
			}
		})
	}
	if before.Status != "sealing" || before.SentAt.Valid || before.Article13NoticeSchema != "" {
		t.Fatal("old source snapshot was replaced by completion")
	}
}

func TestBlockSendFamilyExpiryPreservesWholeCeremonySemanticsV1(t *testing.T) {
	for _, status := range []string{"sent", "in_progress"} {
		for _, deadline := range []string{"absent", "later"} {
			t.Run(status+" "+deadline, func(t *testing.T) {
				before, root := blockSendFamilyTupleFixtureV1(status)
				before.SentAt = root.SentAt
				before.Article13NoticeEpochAt = root.Article13NoticeEpochAt
				before.Article13NoticeSchema = root.Article13NoticeSchema
				before.Article13NoticeEpochV61Committed = true
				if deadline == "later" {
					before.ExpiresAt = pgtype.Timestamptz{Time: root.SentAt.Time.Add(24 * time.Hour), Valid: true}
				}
				after := htmlSendCloneDocumentV1(before)
				after.Status = "expired"
				after.UpdatedAt.Time = after.UpdatedAt.Time.Add(time.Second)
				if !blockSendFamilyExpireTupleV1(before, after) {
					t.Fatal("root expiry must propagate without an individual child deadline")
				}
				blockSendAssertEveryProtectedColumnV1(t, after, func(row *generated.Document) bool { return blockSendFamilyExpireTupleV1(before, row) })
				if before.Status != status {
					t.Fatal("old completed tuple changed")
				}
			})
		}
	}
	for _, status := range []string{"draft", "sealing", "completed", "voided", "expired"} {
		before, _ := blockSendFamilyTupleFixtureV1(status)
		after := htmlSendCloneDocumentV1(before)
		after.Status = "expired"
		if blockSendFamilyExpireTupleV1(before, after) {
			t.Fatalf("status %s must not produce a fresh expiry mutation", status)
		}
	}
}
