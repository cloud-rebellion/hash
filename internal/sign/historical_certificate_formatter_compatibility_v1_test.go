// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"testing"
	"time"
)

// Only the ordinary original formatter's generated SQL boundary is synthetic.
// These rows grant no native Source24/PG/source/claim authority. The unchanged
// original whole certificate function is the independent byte/order oracle.
type historicalCertificateFormatDBV1 struct {
	generated.DBTX
	recipients []*generated.Recipient
	signatures []*generated.Signature
	fields     []*generated.DocumentField
	calls      []string
}

func (d *historicalCertificateFormatDBV1) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	name := strings.SplitN(query, "\n", 2)[0]
	d.calls = append(d.calls, name)
	var rows []any
	switch {
	case strings.Contains(name, "-- name: ListRecipientsByDocument "):
		for _, r := range d.recipients {
			rows = append(rows, r)
		}
	case strings.Contains(name, "-- name: ListSignaturesByDocument "):
		for _, r := range d.signatures {
			rows = append(rows, r)
		}
	case strings.Contains(name, "-- name: ListFieldsByDocument "):
		for _, r := range d.fields {
			rows = append(rows, r)
		}
	default:
		return nil, errors.New("unexpected original certificate formatter query")
	}
	return &presentedCredentialTestRowsV1{objects: rows, index: -1}, nil
}
func TestHistoricalCertificateSharedFormatterPreservesOriginalFullBytesV1(t *testing.T) {
	signer, err := GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 16, 12, 34, 56, 123000000, time.UTC)
	stamp := pgtype.Timestamptz{Time: now, Valid: true}
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Name: `Original <contract> & "name"`, SentAt: stamp, CompletionEffectiveAt: stamp, CompletionEffectiveAtBound: true, MetadataRedactionReport: []byte(`{"schema_version":1,"items":[{"asset":"<asset>","content_type":"image/png","method":"rewritten","bytes_before":123,"bytes_after":99}]}`)}
	rec := &generated.Recipient{ID: uuid.New(), DocumentID: doc.ID, Role: `signer<&`, Name: `A <person>`, Email: `person&other@example.test`, Status: "signed", SignedAt: stamp}
	missing := &generated.Recipient{ID: uuid.New(), DocumentID: doc.ID, Role: "observer", Name: "Unsigned"}
	sig := &generated.Signature{ID: uuid.New(), DocumentID: doc.ID, RecipientID: rec.ID, Font: `Caveat<&`, ImageSha256: make([]byte, sha256.Size)}
	fields := []*generated.DocumentField{{ID: uuid.New(), DocumentID: doc.ID, Type: "text", Page: 2, Label: pgtype.Text{String: `Terms <&>`, Valid: true}, Value: pgtype.Text{String: strings.Repeat("🙂<&\"", 110), Valid: true}, CompletedAt: stamp}, {ID: uuid.New(), DocumentID: doc.ID, Type: "signature", Value: pgtype.Text{String: "must not enter filled field section", Valid: true}}, {ID: uuid.New(), DocumentID: doc.ID, Type: "text", Value: pgtype.Text{Valid: true}}}
	claims := certificateEvidenceClaims{DocumentID: doc.ID.String(), OrgID: doc.OrgID.String(), CompletionEffectiveAt: now.Format(time.RFC3339Nano), FinalPDFSHA256: strings.Repeat("a", 64), DocumentEventsCount: 7, DocumentEventsScope: documentEventsScopeCeremonyRoot, PreFinalChainScope: preFinalChainScopeOrganization}
	manifest := `<section class="hash-envelope-manifest">Exact private terminal snapshot</section>`
	for _, override := range []*string{nil, &manifest} {
		db := &historicalCertificateFormatDBV1{recipients: []*generated.Recipient{rec, missing}, signatures: []*generated.Signature{sig}, fields: fields}
		engine := &Engine{Queries: generated.New(db), Signer: signer, OrgName: "Issuer <&>", BaseURL: " https://hash.example.test/ "}
		oldHTML, oldPayload, oldSignature, err := engine.renderAuditCertificateWithManifest(context.Background(), doc, override, claims)
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := render.CertificatePrefixV1(doc, db.recipients, db.signatures, render.CertificateEvidenceClaimsV1(claims))
		if err != nil {
			t.Fatal(err)
		}
		html, payload, signature, err := render.CertificateFinishV1(prefix, doc, fields, render.CertificateEvidenceClaimsV1(claims), override, render.NewAuditCertificateKeyV1(signer.nativeAuditCertificatePrivateV1()), engine.OrgName, engine.BaseURL)
		if err != nil || html != oldHTML || payload != oldPayload || signature != oldSignature {
			t.Fatal("native shared certificate changed original HTML/payload/Ed25519 bytes", err)
		}
		if !Verify(signer.PublicKeyBase64(), payload, signature) || len(db.calls) != 3 || !strings.Contains(db.calls[0], "ListRecipientsByDocument") || !strings.Contains(db.calls[1], "ListSignaturesByDocument") || !strings.Contains(db.calls[2], "ListFieldsByDocument") {
			t.Fatal("original query/signature ordering changed", db.calls)
		}
		broken := *doc
		broken.CompletionEffectiveAtBound = false
		db.calls = nil
		_, _, _, legacyErr := engine.renderAuditCertificateWithManifest(context.Background(), &broken, override, claims)
		_, nativeErr := render.CertificatePrefixV1(&broken, db.recipients, db.signatures, render.CertificateEvidenceClaimsV1(claims))
		if legacyErr == nil || nativeErr == nil || legacyErr.Error() != nativeErr.Error() || len(db.calls) != 2 {
			t.Fatal("completion gate moved after filled-field SQL", legacyErr, nativeErr, db.calls)
		}
	}
}
