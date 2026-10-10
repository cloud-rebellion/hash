// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
)

func htmlDetailFixture(t *testing.T) (*generated.Template, *generated.HtmlTemplateRevision) {
	t.Helper()
	master, err := json.Marshal(htmlmaster.Master{SchemaVersion: 1, HTML: `<p><span data-hash-value="customer"></span></p>`, Values: []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 120}}})
	if err != nil {
		t.Fatal(err)
	}
	content, err := htmlmaster.CanonicalTemplate(master, []byte(`{"customer":"Approved AB"}`))
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := hex.DecodeString(content.SHA256)
	template := &generated.Template{ID: uuid.New(), OrgID: uuid.New(), SourceKind: "html", Version: 3,
		HtmlMasterJson: content.MasterJSON, VariablesJson: content.DefaultsJSON, HtmlContentSha256: digest}
	revision := &generated.HtmlTemplateRevision{TemplateID: template.ID, OrgID: template.OrgID, Version: template.Version,
		HtmlMasterJson: bytes.Clone(content.MasterJSON), VariablesJson: bytes.Clone(content.DefaultsJSON), ContentSha256: bytes.Clone(digest)}
	return template, revision
}

func TestHTMLTemplateDetailApprovalBindsReturnedRevision(t *testing.T) {
	template, revision := htmlDetailFixture(t)
	response, err := toHTMLTemplateDetailResponse(template, revision)
	if err != nil || response.HTMLApproval == nil || response.HTMLApproval.Version != template.Version || response.HTMLApproval.ContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) {
		t.Fatalf("unapproved detail lost exact revision: %+v, %v", response, err)
	}
	encoded, err := json.Marshal(response)
	if err != nil || strings.Contains(string(encoded), "approved_by") || strings.Contains(string(encoded), "approved_at") {
		t.Fatalf("unapproved detail fabricated approval: %s, %v", encoded, err)
	}
	actor := uuid.New()
	when := time.Date(2026, time.October, 10, 4, 0, 0, 123456000, time.UTC)
	revision.ApprovedBy = pgtype.UUID{Bytes: actor, Valid: true}
	revision.ApprovedAt = pgtype.Timestamptz{Time: when, Valid: true}
	response, err = toHTMLTemplateDetailResponse(template, revision)
	if err != nil || response.HTMLApproval.ApprovedBy != actor.String() || response.HTMLApproval.ApprovedAt != when.Format(time.RFC3339Nano) || len(response.HTMLMasterJSON) == 0 {
		t.Fatalf("approved detail lost evidence: %+v, %v", response, err)
	}
}

func TestHTMLTemplateDetailRefusesForeignStaleOrUncommittedApproval(t *testing.T) {
	for _, name := range []string{"tenant", "template", "version", "digest", "current-master", "current-defaults", "revision-master", "revision-defaults", "half-approval", "zero-actor", "infinite-approval"} {
		t.Run(name, func(t *testing.T) {
			template, revision := htmlDetailFixture(t)
			revision.ApprovedBy = pgtype.UUID{Bytes: uuid.New(), Valid: true}
			revision.ApprovedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
			switch name {
			case "tenant":
				revision.OrgID = uuid.New()
			case "template":
				revision.TemplateID = uuid.New()
			case "version":
				revision.Version++
			case "digest":
				revision.ContentSha256[0] ^= 1
			case "current-master":
				var master htmlmaster.Master
				if err := json.Unmarshal(template.HtmlMasterJson, &master); err != nil {
					t.Fatal(err)
				}
				master.HTML = "<p>Changed contract text</p>" + master.HTML
				template.HtmlMasterJson, _ = json.Marshal(master)
			case "current-defaults":
				template.VariablesJson = []byte(`{"customer":"Different AB"}`)
			case "revision-master":
				revision.HtmlMasterJson = bytes.ReplaceAll(revision.HtmlMasterJson, []byte("customer"), []byte("client"))
			case "revision-defaults":
				revision.VariablesJson = []byte(`{"customer":"Different AB"}`)
			case "half-approval":
				revision.ApprovedAt.Valid = false
			case "zero-actor":
				revision.ApprovedBy.Bytes = uuid.Nil
			case "infinite-approval":
				revision.ApprovedAt.InfinityModifier = pgtype.Infinity
			}
			if response, err := toHTMLTemplateDetailResponse(template, revision); err == nil || response.HTMLApproval != nil {
				t.Fatal("exposed approval for mismatched or incomplete content")
			}
		})
	}
}
