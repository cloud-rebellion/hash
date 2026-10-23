// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
)

// This is a descriptor-integrity fixture, not an observed renderer/storage
// receipt. The production adapter must still obtain and verify actual bytes.
func assetFixtureV1(t testing.TB) (presign.Execution, AssetSetSnapshotV1) {
	t.Helper()
	x := pureFixture(t).execution.Snapshot()
	prefix := "org/" + x.OrgID.String() + "/documents/" + x.Document.ID.String() + "/"
	s := AssetSetSnapshotV1{SchemaVersion: 1, OrgID: x.OrgID, DocumentID: x.Document.ID, ExecutionID: x.ID}
	for i, role := range assetRolesV1 {
		s.Objects[i] = AssetV1{Role: role, ContentType: assetContentTypeV1(role), Object: presign.ArtifactPin{
			StorageKey: prefix + role, VersionID: "exact-version-" + role, SHA256: assetSHA256V1([]byte(role)), Bytes: 100}}
	}
	s.Objects[1].Object.SHA256 = x.Signature.Style.FontSHA256
	x.Signature.Image = s.Objects[0].Object
	x.VisiblePDF.Artifact = s.Objects[7].Object
	b := sanitize.PDFProviderOverlayBindings{SourceCommitment: x.Document.Materialization.SourceCommitment,
		SigningPlanSHA256: x.Document.SigningPlanSHA256, BrandingSHA256: x.Document.BrandingSHA256,
		PolicySHA256: x.Policy.SHA256, GrantSHA256: x.Grant.SHA256, Font: x.Signature.Style.Font,
		SpanSHA256: s.Objects[0].Object.SHA256, SignatureFontSHA256: s.Objects[1].Object.SHA256,
		InterFontSHA256: s.Objects[2].Object.SHA256, RecipeSHA256: s.Objects[3].Object.SHA256,
		DisclosureSHA256: assetSHA256V1([]byte("synthetic disclosure"))}
	m := sanitize.PDFProviderOverlayManifest{SchemaVersion: 1, Policy: sanitize.PDFProviderOverlayPolicy,
		BindingsSHA256: sanitize.PDFProviderOverlayBindingsSHA256(b), BaseSHA256: x.Document.BasePDF.Artifact.SHA256,
		BaseBytes: x.Document.BasePDF.Artifact.Bytes, SignatureSHA256: s.Objects[4].Object.SHA256,
		DisclosureSHA256: s.Objects[5].Object.SHA256, ProcessingSHA256: assetSHA256V1([]byte("processing")),
		ProcessingBytes: 200, OutputSHA256: x.VisiblePDF.Artifact.SHA256, OutputBytes: x.VisiblePDF.Artifact.Bytes,
		Pages: x.VisiblePDF.Pages, GeometrySHA256: assetSHA256V1([]byte("geometry")), OriginalContentSHA256: assetSHA256V1([]byte("content"))}
	for i, rectangle := range [2][4]int64{{61495996, 119868797, 471967968, 54934399}, {59495996, 71563198, 475967968, 25257599}} {
		m.Forms[i] = sanitize.PDFProviderFormProof{Slot: []string{"provider_signature", "provider_disclosure"}[i], RectangleMicroPoints: rectangle,
			ContentSHA256: assetSHA256V1([]byte("form content")), ResourcesSHA256: assetSHA256V1([]byte("resources")), FragmentGeometrySHA256: assetSHA256V1([]byte("fragment"))}
	}
	s.Bindings, s.Overlay = b, m
	proof, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	s.Objects[6].Object.Bytes = int64(len(proof))
	s.Objects[6].Object.SHA256 = assetSHA256V1(proof)
	x.VisibleStampProofSHA256 = s.Objects[6].Object.SHA256
	e, err := presign.NewExecution(x)
	if err != nil {
		t.Fatal(err)
	}
	s.ExecutionSHA256 = e.Commitment()
	return e, s
}

func TestExecutionAssetSetExactArchivedDescriptor(t *testing.T) {
	e, s := assetFixtureV1(t)
	a, err := NewAssetSetV1(e, s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAssetSetV1(e, a.CanonicalJSON())
	if err != nil || got.Commitment() != a.Commitment() || got.Snapshot() != s {
		t.Fatal("exact archive roundtrip", err)
	}
	if digest(presign.ExecutionDomain, a.CanonicalJSON()) == a.Commitment() {
		t.Fatal("asset commitment purpose collision")
	}
	raw := a.CanonicalJSON()
	raw[0] = '['
	copy := a.Snapshot()
	copy.Objects[0].Object.VersionID = "mutated"
	if a.Snapshot() != s || bytes.Equal(raw, a.CanonicalJSON()) {
		t.Fatal("archive aliases caller memory")
	}
}

func TestExecutionAssetSetRejectsEverySubstitutedRelationship(t *testing.T) {
	e, s := assetFixtureV1(t)
	for name, mutate := range map[string]func(*AssetSetSnapshotV1){
		"org":            func(s *AssetSetSnapshotV1) { s.OrgID = uuid.New() },
		"document":       func(s *AssetSetSnapshotV1) { s.DocumentID = uuid.New() },
		"execution":      func(s *AssetSetSnapshotV1) { s.ExecutionID = uuid.New() },
		"execution_hash": func(s *AssetSetSnapshotV1) { s.ExecutionSHA256 = strings.Repeat("a", 64) },
		"role_order":     func(s *AssetSetSnapshotV1) { s.Objects[0], s.Objects[1] = s.Objects[1], s.Objects[0] },
		"mime":           func(s *AssetSetSnapshotV1) { s.Objects[0].ContentType = "application/pdf" },
		"foreign_key":    func(s *AssetSetSnapshotV1) { s.Objects[2].Object.StorageKey = "org/foreign/font.woff2" },
		"key_traversal":  func(s *AssetSetSnapshotV1) { s.Objects[2].Object.StorageKey += "/../font" },
		"duplicate_key":  func(s *AssetSetSnapshotV1) { s.Objects[2].Object.StorageKey = s.Objects[1].Object.StorageKey },
		"source_overwrite": func(s *AssetSetSnapshotV1) {
			s.Objects[2].Object.StorageKey = e.Snapshot().Document.BasePDF.Artifact.StorageKey
		},
		"latest_alias":    func(s *AssetSetSnapshotV1) { s.Objects[2].Object.VersionID = "" },
		"version_control": func(s *AssetSetSnapshotV1) { s.Objects[2].Object.VersionID = "version\n" },
		"font_size":       func(s *AssetSetSnapshotV1) { s.Objects[1].Object.Bytes = presign.MaxSignatureBytes + 1 },
		"span_version":    func(s *AssetSetSnapshotV1) { s.Objects[0].Object.VersionID = "other" },
		"visible_version": func(s *AssetSetSnapshotV1) { s.Objects[7].Object.VersionID = "other" },
		"font_hash":       func(s *AssetSetSnapshotV1) { s.Objects[1].Object.SHA256 = strings.Repeat("a", 64) },
		"grant_binding":   func(s *AssetSetSnapshotV1) { s.Bindings.GrantSHA256 = strings.Repeat("a", 64) },
		"copy_binding":    func(s *AssetSetSnapshotV1) { s.Bindings.DisclosureSHA256 = strings.Repeat("a", 64) },
		"fragment":        func(s *AssetSetSnapshotV1) { s.Objects[4].Object.SHA256 = strings.Repeat("a", 64) },
		"geometry":        func(s *AssetSetSnapshotV1) { s.Overlay.Forms[0].RectangleMicroPoints[0]++ },
		"proof_size":      func(s *AssetSetSnapshotV1) { s.Objects[6].Object.Bytes++ },
		"proof_hash":      func(s *AssetSetSnapshotV1) { s.Objects[6].Object.SHA256 = strings.Repeat("a", 64) },
		"base_hash":       func(s *AssetSetSnapshotV1) { s.Overlay.BaseSHA256 = strings.Repeat("a", 64) },
		"page_count":      func(s *AssetSetSnapshotV1) { s.Overlay.Pages++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			mutate(&changed)
			if _, err := NewAssetSetV1(e, changed); !errors.Is(err, ErrInvalid) {
				t.Fatal("substituted archive accepted", err)
			}
		})
	}
}

func TestExecutionAssetSetRejectsNoncanonicalAndAmbiguousBytes(t *testing.T) {
	e, s := assetFixtureV1(t)
	a, err := NewAssetSetV1(e, s)
	if err != nil {
		t.Fatal(err)
	}
	raw := a.CanonicalJSON()
	for name, changed := range map[string][]byte{
		"null":            bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1),
		"unknown":         bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1),
		"duplicate":       bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		"case_alias":      bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"Schema_Version":1`), 1),
		"missing_object":  bytes.Replace(raw, []byte(`"signature_font"`), []byte(`"missing_font"`), 1),
		"missing_binding": bytes.Replace(raw, []byte(`"bindings":`), []byte(`"Bindings":`), 1),
		"whitespace":      append([]byte(" "), raw...),
		"trailing":        append(bytes.Clone(raw), []byte(`{}`)...),
		"oversize":        bytes.Repeat([]byte("x"), MaxAssetSetBytesV1+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAssetSetV1(e, changed); !errors.Is(err, ErrInvalid) {
				t.Fatal("ambiguous archive accepted", err)
			}
		})
	}
}
