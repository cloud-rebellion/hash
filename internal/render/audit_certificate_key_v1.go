// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
)

// Fixed configured key material, not a SQL/source/work-cost authorization.
// Native certificate production accepts this concrete finite cryptographic
// implementation; it does not accept an arbitrary callback or signer object.
type AuditCertificateKeyV1 struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func NewAuditCertificateKeyV1(private ed25519.PrivateKey) *AuditCertificateKeyV1 {
	if len(private) != ed25519.PrivateKeySize {
		return nil
	}
	key := bytes.Clone(private)
	public := bytes.Clone(key[ed25519.SeedSize:])
	return &AuditCertificateKeyV1{private: key, public: public}
}
func (k *AuditCertificateKeyV1) SignPayload(payload []byte) string {
	if k == nil {
		return ""
	}
	h := sha256.New()
	_, _ = h.Write([]byte("hash:audit-cert:v1:"))
	_, _ = h.Write(payload)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.private, h.Sum(nil)))
}
func (k *AuditCertificateKeyV1) PublicKeyBase64() string {
	if k == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(k.public)
}
