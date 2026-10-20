// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Formatter fixtures only. Actual original row/body association is checked by
// the shared report projection; these rows grant no SQL/source authority.
func certificatePayloadFixtureV1(t *testing.T, layout string) (string, *generated.Document, []*generated.DocumentField, CertificateEvidenceClaimsV1) {
	t.Helper()
	comment, event := reportCommentFixtureV1(t)
	doc := &generated.Document{ID: comment.DocumentID, OrgID: event.OrgID, Name: `Payload <agreement> & "Company"`, SentAt: comment.CreatedAt, CompletionEffectiveAtBound: true, CompletionEffectiveAt: comment.CreatedAt, MetadataRedactionReport: []byte(`{"schema_version":1,"items":[{"asset":"source <asset>","content_type":"image/png","method":"rewritten","bytes_before":123,"bytes_after":99}]}`)}
	finalSHA := sha256.Sum256([]byte("formatter fixture final identity"))
	claims, err := NewCertificateEvidenceClaimsV1(doc, finalSHA[:], &generated.LatestEventChainHeadForOrgRow{RowHash: event.RowHash, CreatedAt: event.CreatedAt}, []*generated.Event{event})
	if err != nil {
		t.Fatal(err)
	}
	if layout != "legacy" {
		view, err := ParticipantReportCommentV1FromRow(comment, []*generated.Event{event})
		if err != nil {
			t.Fatal(err)
		}
		events, err := ParticipantReportEventsV1([]*generated.Event{event}, comment.CreatedAt.Time)
		if err != nil {
			t.Fatal(err)
		}
		r := ParticipantReportV1{Schema: ParticipantReportSchemaV1, DocumentID: doc.ID.String(), Cutoff: comment.CreatedAt.Time.UTC().Format(time.RFC3339Nano), Comments: []ParticipantReportCommentV1{view}, Events: events}
		var section, digest string
		switch layout {
		case "v1":
			section, digest, err = r.HTMLV1()
		case "v2":
			section, digest, err = r.HTMLV2()
		default:
			t.Fatal("unsupported fixture layout", layout)
		}
		if err != nil {
			t.Fatal(err)
		}
		claims.ParticipantReportSchema, claims.ParticipantReportSHA256 = ParticipantReportSchemaV1, digest
		claims.ParticipantReportCutoff, claims.ParticipantReportRows, claims.ParticipantReportHTML = r.Cutoff, 2, section
	}
	prefix, err := CertificatePrefixV1(doc, nil, nil, claims)
	if err != nil {
		t.Fatal(err)
	}
	fields := []*generated.DocumentField{
		{ID: uuid.New(), DocumentID: doc.ID, Type: "text", Page: 2, Label: pgtype.Text{String: `Terms <&>`, Valid: true}, Value: pgtype.Text{String: `Å <terms> & "approved"`, Valid: true}, CompletedAt: comment.CreatedAt},
		{ID: uuid.New(), DocumentID: doc.ID, Type: "signature", Value: pgtype.Text{String: "signature value excluded from filled fields", Valid: true}},
	}
	return prefix, doc, fields, claims
}

func certificatePayloadKeyV1() *AuditCertificateKeyV1 {
	return NewAuditCertificateKeyV1(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)))
}
func verifyCertificatePayloadSignatureV1(t *testing.T, key *AuditCertificateKeyV1, payload, signature string) {
	t.Helper()
	public, err := base64.StdEncoding.DecodeString(key.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	rawSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, _ = h.Write([]byte("hash:audit-cert:v1:"))
	_, _ = h.Write([]byte(payload))
	if !ed25519.Verify(ed25519.PublicKey(public), h.Sum(nil), rawSignature) {
		t.Fatal("Finish did not sign the exact shared payload")
	}
}

func TestCertificatePayloadMatchesFinishWithCompleteRetainedContentV1(t *testing.T) {
	manifest := `<section class="hash-envelope-manifest">Exact frozen &amp; complete NDA</section>`
	for _, layout := range []string{"legacy", "v1", "v2"} {
		for _, withManifest := range []bool{false, true} {
			name := layout + "/ordinary"
			if withManifest {
				name = layout + "/manifest"
			}
			t.Run(name, func(t *testing.T) {
				prefix, doc, fields, claims := certificatePayloadFixtureV1(t, layout)
				originalReport := bytes.Clone(doc.MetadataRedactionReport)
				var annex *string
				if withManifest {
					annex = &manifest
				}
				payload, err := CertificatePayloadV1(prefix, doc, fields, claims, annex)
				if err != nil {
					t.Fatal(err)
				}
				key := certificatePayloadKeyV1()
				rendered, signedPayload, signature, err := CertificateFinishV1(prefix, doc, fields, claims, annex, key, `Issuer <Ops> & "Legal"`, " https://hash.example.test/ ")
				if err != nil || signedPayload != payload || !strings.HasPrefix(rendered, payload) {
					t.Fatal("Finish changed the complete shared payload", err)
				}
				verifyCertificatePayloadSignatureV1(t, key, payload, signature)
				for _, text := range []string{`Payload &lt;agreement&gt; &amp; &quot;Company&quot;`, `Terms &lt;&amp;&gt;`, `Å &lt;terms&gt; &amp; &quot;approved&quot;`, `source &lt;asset&gt;`} {
					if !strings.Contains(payload, text) {
						t.Fatal("payload omitted or changed escaped retained content", text)
					}
				}
				if strings.Contains(payload, "signature value excluded") || strings.Contains(payload, key.PublicKeyBase64()) || !strings.Contains(rendered, `Issuer &lt;Ops&gt; &amp; &quot;Legal&quot;`) {
					t.Fatal("filled-field or detached verification-footer boundary changed")
				}
				sections := []string{`<h3 style="margin-top:24px">Filled fields</h3>`, `<section class="hash-evidence-claims"`}
				if layout != "legacy" {
					sections = append(sections, `<section class="hash-participant-report">`)
					if !strings.Contains(payload, claims.ParticipantReportHTML) {
						t.Fatal("complete exact participant report was omitted")
					}
				}
				if withManifest {
					sections = append(sections, manifest)
				}
				sections = append(sections, `<section class="hash-redaction-report">`)
				last := -1
				for _, section := range sections {
					at := strings.Index(payload, section)
					if at <= last {
						t.Fatal("retained payload section missing or reordered", section)
					}
					last = at
				}
				if !bytes.Equal(originalReport, doc.MetadataRedactionReport) || fields[0].Value.String != `Å <terms> & "approved"` {
					t.Fatal("pure payload formatting changed input observations")
				}
			})
		}
	}
}

func TestCertificatePayloadLimitInclusiveAndNoPartialFailureV1(t *testing.T) {
	if MaxCertificatePayloadBytesV1 != 4<<20 {
		t.Fatal("extraction changed the existing payload limit")
	}
	_, doc, _, claims := certificatePayloadFixtureV1(t, "v2")
	base, err := CertificatePayloadV1("", doc, nil, claims, nil)
	if err != nil || len(base) >= MaxCertificatePayloadBytesV1 {
		t.Fatal("small genuine report fixture failed", err)
	}
	prefix := strings.Repeat("p", MaxCertificatePayloadBytesV1-len(base))
	payload, err := CertificatePayloadV1(prefix, doc, nil, claims, nil)
	if err != nil || len(payload) != MaxCertificatePayloadBytesV1 {
		t.Fatal("inclusive exact payload limit rejected", len(payload), err)
	}
	key := certificatePayloadKeyV1()
	_, signedPayload, signature, err := CertificateFinishV1(prefix, doc, nil, claims, nil, key, "Org", "https://hash.example.test")
	if err != nil || payload != signedPayload {
		t.Fatal("Finish rejected or changed exact-limit payload", err)
	}
	verifyCertificatePayloadSignatureV1(t, key, payload, signature)
	if partial, err := CertificatePayloadV1(prefix+"x", doc, nil, claims, nil); !errors.Is(err, ErrParticipantReportV1) || !errors.Is(err, ErrCertificatePayloadCapacityV1) || partial != "" {
		t.Fatal("overflow returned partial payload or wrong error", err)
	}
	// A nil key proves payload refusal precedes the existing signer guard.
	if rendered, partial, sig, err := CertificateFinishV1(prefix+"x", doc, nil, claims, nil, nil, "Org", ""); !errors.Is(err, ErrParticipantReportV1) || !errors.Is(err, ErrCertificatePayloadCapacityV1) || rendered != "" || partial != "" || sig != "" {
		t.Fatal("Finish overflow returned partial output or reached signing", err)
	}
	legacy := claims
	legacy.ParticipantReportSchema, legacy.ParticipantReportHTML = "", ""
	if old, err := CertificatePayloadV1(strings.Repeat("p", MaxCertificatePayloadBytesV1+1), doc, nil, legacy, nil); err != nil || len(old) <= MaxCertificatePayloadBytesV1 {
		t.Fatal("new mandatory-report limit was applied retroactively to legacy formatting", err)
	}
}

func TestCertificatePayloadRefusalsReturnNoPartialBytesV1(t *testing.T) {
	prefix, doc, fields, original := certificatePayloadFixtureV1(t, "v2")
	emptyManifest := ""
	for _, name := range []string{"schema", "missing-report", "digest", "empty-manifest"} {
		t.Run(name, func(t *testing.T) {
			claims := original
			var manifest *string
			switch name {
			case "schema":
				claims.ParticipantReportSchema = "unsupported"
			case "missing-report":
				claims.ParticipantReportHTML = ""
			case "digest":
				claims.ParticipantReportSHA256 = "short"
			case "empty-manifest":
				manifest = &emptyManifest
			}
			payload, err := CertificatePayloadV1(prefix, doc, fields, claims, manifest)
			if err == nil || errors.Is(err, ErrCertificatePayloadCapacityV1) || payload != "" {
				t.Fatal("payload refusal returned partial bytes", err)
			}
			rendered, partial, signature, finishErr := CertificateFinishV1(prefix, doc, fields, claims, manifest, nil, "Org", "")
			if finishErr == nil || finishErr.Error() != err.Error() || rendered != "" || partial != "" || signature != "" {
				t.Fatal("Finish changed shared payload refusal or attempted signing", err, finishErr)
			}
		})
	}
}
