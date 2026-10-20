// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package documentpackage

import (
	"errors"
)

const ResponseSchemaV1 = "hash-package-response-v1"
const IncorporationVersionV1 = "hash-package-incorporation-v1"
const IncorporationSHA256V1 = "ed7e8d4a4b7e03bb600f94ccd6328e4f457528eb165f18fd0ca6ccfecb972670"
const IncorporationTextV1 = "I have reviewed and agree to the main document and every attachment listed in this contract package. My signature or acknowledgement applies to the complete package identified by the displayed commitments."

var ErrResponseV1 = errors.New("documentpackage: explicit current whole-package consent required")

// ResponseV1 contains observations and an explicit action, never scope,
// authorization, storage locators or server-authored legal copy. Article 13
// acknowledgement is separate and cannot satisfy this consent.
type ResponseV1 struct {
	ManifestSHA256        string `json:"manifest_sha256"`
	LegalCommitmentSHA256 string `json:"legal_commitment_sha256"`
	IncorporationVersion  string `json:"incorporation_version"`
	IncorporationSHA256   string `json:"incorporation_sha256"`
	Consent               bool   `json:"consent"`
}

type IncorporationV1 struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Text    string `json:"text"`
}

func IncorporationCopyV1() IncorporationV1 {
	return IncorporationV1{Version: IncorporationVersionV1, SHA256: IncorporationSHA256V1, Text: IncorporationTextV1}
}

func (r ResponseV1) ValidateV1() error {
	if !r.Consent || r.IncorporationVersion != IncorporationVersionV1 || r.IncorporationSHA256 != IncorporationCopyV1().SHA256 || !responseDigestV1(r.ManifestSHA256) || !responseDigestV1(r.LegalCommitmentSHA256) {
		return ErrResponseV1
	}
	return nil
}

func responseDigestV1(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return s != "0000000000000000000000000000000000000000000000000000000000000000"
}

// BindAuditPayloadV1 is called only after the owned native work has resolved
// and compared the actual immutable Send capture. Caller fields alone must
// never be passed to this method as evidence that a package was authorized.
func (r ResponseV1) BindAuditPayloadV1(payload map[string]any, attemptID, packageID, revision, kind string) error {
	if payload == nil || r.ValidateV1() != nil || attemptID == "" || packageID == "" || revision == "" || (kind != "signed" && kind != "accepted") {
		return ErrResponseV1
	}
	payload["package_response_schema"] = ResponseSchemaV1
	payload["package_send_attempt_id"] = attemptID
	payload["package_id"] = packageID
	payload["capture_revision"] = revision
	payload["manifest_sha256"] = r.ManifestSHA256
	payload["legal_commitment_sha256"] = r.LegalCommitmentSHA256
	payload["incorporation_version"] = r.IncorporationVersion
	payload["incorporation_sha256"] = r.IncorporationSHA256
	payload["package_consent"] = true
	payload["response_kind"] = kind
	return nil
}
