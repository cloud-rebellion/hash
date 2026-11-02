// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package handler

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestTemplatePDFExpectationRejectsAmbiguousOrNoncanonicalPins(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	if version, _, ok := parseTemplatePDFExpectationV1(url.Values{"version": {"1"}, "sha256": {digest}}); !ok || version != 1 {
		t.Fatal("canonical expected source refused")
	}
	for _, raw := range []string{
		"", "version=1", "sha256=" + digest, "version=0&sha256=" + digest,
		"version=-1&sha256=" + digest, "version=01&sha256=" + digest,
		"version=%2B1&sha256=" + digest, "version=2147483648&sha256=" + digest,
		"version=1&version=1&sha256=" + digest, "version=1&sha256=" + digest + "&sha256=" + digest,
		"version=1&sha256=" + strings.ToUpper(digest), "version=1&sha256=" + strings.Repeat("z", 64),
		"version=1&sha256=" + digest[:62], "version=1&sha256=" + digest + "&other=1",
	} {
		t.Run(raw, func(t *testing.T) {
			values, err := url.ParseQuery(raw)
			if _, _, ok := parseTemplatePDFExpectationV1(values); err == nil && ok {
				t.Fatal("ambiguous or unpinned request accepted")
			}
		})
	}
}

func TestTemplatePDFSourcePinRequiresTenantAndImmutableVersion(t *testing.T) {
	id, org := uuid.New(), uuid.New()
	stamp := pgtype.Timestamptz{Time: time.Date(2026, 11, 2, 1, 2, 3, 0, time.UTC), Valid: true}
	row := generated.Template{ID: id, OrgID: org, SourceKind: "pdf", Version: 1,
		PdfStorageKey:       pgtype.Text{String: "tenant/exact/source.pdf", Valid: true},
		PdfStorageVersionID: pgtype.Text{String: "immutable-source-version", Valid: true},
		PdfSha256:           make([]byte, 32), EvidenceVersionPinRequired: true, CreatedAt: stamp, UpdatedAt: stamp}
	pin, ok := templatePDFPinForV1(&row, org, id)
	if !ok {
		t.Fatal("complete native source pin refused")
	}
	for name, change := range map[string]func(*generated.Template){
		"foreign_org":       func(x *generated.Template) { x.OrgID = uuid.New() },
		"wrong_id":          func(x *generated.Template) { x.ID = uuid.New() },
		"html":              func(x *generated.Template) { x.SourceKind = "html" },
		"archived":          func(x *generated.Template) { x.ArchivedAt = stamp },
		"version_zero":      func(x *generated.Template) { x.Version = 0 },
		"no_key":            func(x *generated.Template) { x.PdfStorageKey.Valid = false },
		"empty_key":         func(x *generated.Template) { x.PdfStorageKey.String = "" },
		"no_version_pin":    func(x *generated.Template) { x.PdfStorageVersionID.Valid = false },
		"empty_version_pin": func(x *generated.Template) { x.PdfStorageVersionID.String = "" },
		"legacy_pin":        func(x *generated.Template) { x.EvidenceVersionPinRequired = false },
		"no_digest":         func(x *generated.Template) { x.PdfSha256 = nil },
		"no_creation":       func(x *generated.Template) { x.CreatedAt.Valid = false },
		"no_update":         func(x *generated.Template) { x.UpdatedAt.Valid = false },
	} {
		t.Run(name, func(t *testing.T) {
			copy := row
			change(&copy)
			if _, valid := templatePDFPinForV1(&copy, org, id); valid {
				t.Fatal("unsafe source pin accepted")
			}
		})
	}
	for name, change := range map[string]func(*generated.Template){
		"source_key":       func(x *generated.Template) { x.PdfStorageKey.String = "other.pdf" },
		"storage_version":  func(x *generated.Template) { x.PdfStorageVersionID.String = "other-version" },
		"template_version": func(x *generated.Template) { x.Version++ },
		"source_digest":    func(x *generated.Template) { x.PdfSha256 = append([]byte(nil), x.PdfSha256...); x.PdfSha256[0]++ },
		"update_stamp":     func(x *generated.Template) { x.UpdatedAt.Time = x.UpdatedAt.Time.Add(time.Second) },
		"creation_stamp":   func(x *generated.Template) { x.CreatedAt.Time = x.CreatedAt.Time.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := row
			change(&copy)
			current, valid := templatePDFPinForV1(&copy, org, id)
			if !valid || current == pin {
				t.Fatal("post-provider source drift was not detected")
			}
		})
	}
	row.PdfSha256[0] = 9
	if pin.SHA256[0] != 0 {
		t.Fatal("source pin retained a mutable digest borrower")
	}
}
