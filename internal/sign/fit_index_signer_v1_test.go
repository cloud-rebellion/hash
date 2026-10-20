// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestFitsIndexV1IssuerSignatureIsIndependentAndCannotCrossDomains(t *testing.T) {
	signer, err := GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"schema":"hash-manual-fit-index-v1","fixture":"domain separation only"}`)
	signature := signer.SignFitsIndexV1(payload)
	public, err := base64.StdEncoding.DecodeString(signer.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	detached, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	commitment := sha256.Sum256(append([]byte("hash:manual-fit-index:v1:"), payload...))
	if !ed25519.Verify(public, commitment[:], detached) {
		t.Fatal("independent frozen-domain verification failed")
	}
	if Verify(signer.PublicKeyBase64(), string(payload), signature) || VerifyEvidenceManifest(signer.PublicKeyBase64(), payload, signature) {
		t.Fatal("fitted index signature replayed as a certificate or export manifest")
	}
	if verifyDomain(signer.PublicKeyBase64(), payload, signer.SignPayload(payload), fitsIndexDomainV1) ||
		verifyDomain(signer.PublicKeyBase64(), payload, signer.SignEvidenceManifest(payload), fitsIndexDomainV1) {
		t.Fatal("certificate or export manifest signature replayed as fitted index")
	}
	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-2] ^= 1
	if verifyDomain(signer.PublicKeyBase64(), tampered, signature, fitsIndexDomainV1) {
		t.Fatal("tampered retained index verified")
	}
}
