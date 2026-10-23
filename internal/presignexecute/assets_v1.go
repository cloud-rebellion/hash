// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
)

const AssetSetDomainV1 = "hash:presign-execution-assets:v1\x00"
const MaxAssetSetBytesV1 = 64 * 1024

const (
	AssetSpanV1          = "signature_span"
	AssetFontV1          = "signature_font"
	AssetInterV1         = "inter_font"
	AssetRecipeV1        = "overlay_recipe"
	AssetSignaturePDFV1  = "signature_fragment"
	AssetDisclosurePDFV1 = "disclosure_fragment"
	AssetProofV1         = "overlay_proof"
	AssetVisiblePDFV1    = "visible_pdf"
)

var assetRolesV1 = [8]string{AssetSpanV1, AssetFontV1, AssetInterV1, AssetRecipeV1,
	AssetSignaturePDFV1, AssetDisclosurePDFV1, AssetProofV1, AssetVisiblePDFV1}

// AssetV1 identifies an exact archived version, never the latest object. Role
// order is fixed so a second representation cannot alias the committed set.
type AssetV1 struct {
	Role        string              `json:"role"`
	ContentType string              `json:"content_type"`
	Object      presign.ArtifactPin `json:"object"`
}

type AssetSetSnapshotV1 struct {
	SchemaVersion   int                                 `json:"schema_version"`
	OrgID           uuid.UUID                           `json:"org_id"`
	DocumentID      uuid.UUID                           `json:"document_id"`
	ExecutionID     uuid.UUID                           `json:"execution_id"`
	ExecutionSHA256 string                              `json:"execution_sha256"`
	Objects         [8]AssetV1                          `json:"objects"`
	Bindings        sanitize.PDFProviderOverlayBindings `json:"bindings"`
	Overlay         sanitize.PDFProviderOverlayManifest `json:"overlay"`
}

// AssetSetV1 proves descriptor integrity only. Production still reads each
// exact version through its owned storage operation and validates its bytes.
type AssetSetV1 struct {
	snapshot   AssetSetSnapshotV1
	canonical  []byte
	commitment string
}

func (a AssetSetV1) Snapshot() AssetSetSnapshotV1 { return a.snapshot }
func (a AssetSetV1) CanonicalJSON() []byte        { return bytes.Clone(a.canonical) }
func (a AssetSetV1) Commitment() string           { return a.commitment }

func assetSHA256V1(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func validAssetPinV1(p presign.ArtifactPin, maximum int64) bool {
	if p.Bytes < 1 || p.Bytes > maximum || !validSHA(p.SHA256) ||
		len(p.StorageKey) < 1 || len(p.StorageKey) > 1024 ||
		len(p.VersionID) < 1 || len(p.VersionID) > 1024 ||
		strings.TrimSpace(p.VersionID) != p.VersionID {
		return false
	}
	for _, r := range p.VersionID {
		if r < 33 || r > 126 {
			return false
		}
	}
	for _, part := range strings.Split(p.StorageKey, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
				return false
			}
		}
	}
	return true
}

func assetContentTypeV1(role string) string {
	switch role {
	case AssetSpanV1:
		return "text/html; charset=utf-8"
	case AssetFontV1, AssetInterV1:
		return "font/woff2"
	case AssetRecipeV1, AssetProofV1:
		return "application/json"
	case AssetSignaturePDFV1, AssetDisclosurePDFV1, AssetVisiblePDFV1:
		return "application/pdf"
	default:
		return ""
	}
}

func NewAssetSetV1(execution presign.Execution, s AssetSetSnapshotV1) (AssetSetV1, error) {
	if _, err := presign.DecodeExecution(execution.CanonicalJSON()); err != nil {
		return AssetSetV1{}, invalid("execution asset lineage")
	}
	e := execution.Snapshot()
	if s.SchemaVersion != 1 || s.OrgID != e.OrgID || s.DocumentID != e.Document.ID ||
		s.ExecutionID != e.ID || s.ExecutionSHA256 != execution.Commitment() {
		return AssetSetV1{}, invalid("execution asset identity")
	}
	keys := make(map[string]bool, len(s.Objects))
	ownedPrefix := "org/" + e.OrgID.String() + "/documents/" + e.Document.ID.String() + "/"
	for i, a := range s.Objects {
		maximum := int64(presign.MaxSignatureBytes)
		if i == 4 || i == 5 || i == 7 {
			maximum = int64(presign.MaxPDFBytes)
		}
		if a.Role != assetRolesV1[i] || a.ContentType != assetContentTypeV1(a.Role) ||
			!validAssetPinV1(a.Object, maximum) || !strings.HasPrefix(a.Object.StorageKey, ownedPrefix) || keys[a.Object.StorageKey] {
			return AssetSetV1{}, invalid("execution asset role or exact version")
		}
		keys[a.Object.StorageKey] = true
	}
	if s.Objects[0].Object != e.Signature.Image || s.Objects[1].Object.SHA256 != e.Signature.Style.FontSHA256 ||
		s.Objects[7].Object != e.VisiblePDF.Artifact || keys[e.Document.BasePDF.Artifact.StorageKey] {
		return AssetSetV1{}, invalid("signature, font, source or visible asset differs")
	}
	b, m := s.Bindings, s.Overlay
	if sanitize.ValidatePDFProviderOverlayManifest(m) != nil ||
		b.SourceCommitment != e.Document.Materialization.SourceCommitment ||
		b.SigningPlanSHA256 != e.Document.SigningPlanSHA256 || b.BrandingSHA256 != e.Document.BrandingSHA256 ||
		b.PolicySHA256 != e.Policy.SHA256 || b.GrantSHA256 != e.Grant.SHA256 || b.Font != e.Signature.Style.Font ||
		b.SpanSHA256 != s.Objects[0].Object.SHA256 || b.SignatureFontSHA256 != s.Objects[1].Object.SHA256 ||
		b.InterFontSHA256 != s.Objects[2].Object.SHA256 || b.RecipeSHA256 != s.Objects[3].Object.SHA256 ||
		m.BindingsSHA256 != sanitize.PDFProviderOverlayBindingsSHA256(b) ||
		m.BaseSHA256 != e.Document.BasePDF.Artifact.SHA256 || m.BaseBytes != e.Document.BasePDF.Artifact.Bytes ||
		m.SignatureSHA256 != s.Objects[4].Object.SHA256 || m.DisclosureSHA256 != s.Objects[5].Object.SHA256 ||
		m.OutputSHA256 != e.VisiblePDF.Artifact.SHA256 || m.OutputBytes != e.VisiblePDF.Artifact.Bytes ||
		m.Pages != e.VisiblePDF.Pages {
		return AssetSetV1{}, invalid("actual provider overlay bindings differ")
	}
	proof, err := json.Marshal(m)
	if err != nil || int64(len(proof)) != s.Objects[6].Object.Bytes ||
		assetSHA256V1(proof) != s.Objects[6].Object.SHA256 ||
		s.Objects[6].Object.SHA256 != e.VisibleStampProofSHA256 {
		return AssetSetV1{}, invalid("canonical visible stamp proof differs")
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) < 1 || len(raw) > MaxAssetSetBytesV1 {
		return AssetSetV1{}, invalid("execution asset set bound")
	}
	return AssetSetV1{snapshot: s, canonical: raw, commitment: digest(AssetSetDomainV1, raw)}, nil
}

func DecodeAssetSetV1(execution presign.Execution, raw []byte) (AssetSetV1, error) {
	if len(raw) < 1 || len(raw) > MaxAssetSetBytesV1 || sourcejson.Validate(raw) != nil {
		return AssetSetV1{}, invalid("execution asset JSON")
	}
	var s AssetSetSnapshotV1
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return AssetSetV1{}, invalid("execution asset shape")
	}
	a, err := NewAssetSetV1(execution, s)
	if err != nil || !bytes.Equal(raw, a.CanonicalJSON()) {
		return AssetSetV1{}, invalid("canonical execution asset bytes")
	}
	return a, nil
}
