//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
)

// Uses the actual public PDF-template variables producer, native PostgreSQL,
// public attachment selection and Send. The existing isolated parser and
// synthetic versioned storage peers are unchanged. No document variables,
// package capture, admission, lawful-basis confirmation or status is seeded.
// This test stops at the real durable initial Send; worker completion, signing,
// configured providers and the full negotiation ceremony remain separate.
func TestPublicPlainPDFPackageSendVariablesSemanticEqualityV1E2E(t *testing.T) {
	for _, scenario := range []string{"same string map", "changed binding value", "additional binding key"} {
		t.Run(scenario, func(t *testing.T) {
			q := inspectionFixturePG236(t)
			template, parties := ownedPDFMaterializationTemplateV1(t, q, 1, 1)
			created := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(created, ownedPDFMaterializationRequestV1(t, q, "REST", "", template, parties, "Actual plain PDF package variables"))
			var response documentResponse
			if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &response) != nil || response.ID == uuid.Nil {
				t.Fatal("public PDF-template creation failed", created.Code, created.Body.String())
			}
			root := packageLatest223(t, q, response.ID)
			ownedPDFMaterializationExactV1(t, q, template, root.ID, 1, 1)
			if root.SourceKind != "pdf" || len(root.HtmlSourceJson) != 0 || len(root.HtmlCurrentSourceJson) != 0 || len(root.BlocksJson) != 0 || q.f.s.Send == nil || q.f.s.Send.Resolver == nil {
				t.Fatal("test did not reach the genuine plain-PDF resolver journey")
			}
			originalVariables := bytes.Clone(root.VariablesJson)
			var values map[string]string
			if err := json.Unmarshal(originalVariables, &values); err != nil || len(values) != 1 || values["contract.reference"] != "Actual exact source" {
				t.Fatal("public PDF variables producer omitted the actual nonempty string map", err)
			}
			canonical, err := json.Marshal(values)
			if err != nil || bytes.Equal(originalVariables, canonical) {
				t.Fatal("real PostgreSQL JSONB wire did not differ from the resolver's compact string-map spelling", err)
			}
			if scenario != "same string map" {
				variable := "contract.reference"
				if scenario == "additional binding key" {
					variable = "contract.additional"
				}
				binding, err := json.Marshal(map[string]string{"source_kind": "static", "fallback": "A genuinely different resolved source value"})
				if err != nil {
					t.Fatal(err)
				}
				changed := submitSessionOperationE2E(q.f.s, http.MethodPut, "/api/v1/documents/"+root.ID.String()+"/variable-bindings/"+variable, string(binding), q.cookie)
				if changed.Code != http.StatusOK {
					t.Fatal("public static-fallback binding creation failed", changed.Code, changed.Body.String())
				}
				root = packageLatest223(t, q, root.ID)
				if !bytes.Equal(root.VariablesJson, originalVariables) {
					t.Fatal("binding creation rewrote the actual static variables")
				}
			}
			annex := packageImported220(t, q, "Actual plain-PDF package annex")
			selection := packagePDFVariablesSelection286(t, q, root, annex)
			root = packageLatest223(t, q, root.ID)
			originalSource := packagePDFVariablesSource286(t, q, root.ID)
			before := packagePDFVariablesEffects286(t, q)
			providerBefore := packagePDFVariablesProvider286(t, q)
			raw, err := json.Marshal(sendDocumentInput{LawfulBasis: "contract", PackageSend: &selection})
			if err != nil {
				t.Fatal(err)
			}
			sent := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/send", string(raw), q.cookie)
			if scenario != "same string map" {
				if sent.Code != http.StatusConflict || packagePDFVariablesEffects286(t, q) != before || packagePDFVariablesProvider286(t, q) != providerBefore {
					t.Fatal("changed actual resolver map was accepted or retained effects", sent.Code, sent.Body.String())
				}
				if packagePDFVariablesSource286(t, q, root.ID) != originalSource {
					t.Fatal("refused Send rewrote the genuine plain-PDF source")
				}
				ownedPlainAssertDrainedV1(t, q)
				return
			}
			var outcome sendDocumentResponse
			if sent.Code != http.StatusAccepted || json.Unmarshal(sent.Body.Bytes(), &outcome) != nil || outcome.Status != "sealing" || len(outcome.Links) != 0 || outcome.PackageSend == nil || outcome.PackageSend.Outcome != "active" {
				t.Fatal("format-only plain-PDF package Send did not commit durable sealing", sent.Code, sent.Body.String())
			}
			attempt, err := uuid.Parse(outcome.PackageSend.AttemptID)
			if err != nil || attempt == uuid.Nil {
				t.Fatal("actual package Send omitted its attempt identity", err)
			}
			if packagePDFVariablesSource286(t, q, root.ID) != originalSource || !bytes.Equal(packageLatest223(t, q, root.ID).VariablesJson, originalVariables) || packagePDFVariablesProvider286(t, q) != providerBefore {
				t.Fatal("format-only Send rewrote static variables, source pins, protected logical size or original PDF objects")
			}
			var packageID uuid.UUID
			var revision int64
			var manifestRaw, manifestSHA, legalSHA []byte
			err = q.f.pool.QueryRow(q.f.ctx, `SELECT a.package_id,a.capture_revision,c.manifest,c.manifest_sha256,c.legal_commitment_sha256
    FROM document_package_send_attempts_v1 a JOIN document_package_captures_v1 c
     ON c.package_id=a.package_id AND c.revision=a.capture_revision AND c.org_id=a.org_id
    WHERE a.attempt_id=$1 AND a.document_id=$2 AND a.org_id=$3`, attempt, root.ID, q.f.org).Scan(&packageID, &revision, &manifestRaw, &manifestSHA, &legalSHA)
			if err != nil || len(manifestSHA) != sha256.Size || len(legalSHA) != sha256.Size {
				t.Fatal("actual immutable capture is absent", err)
			}
			digest := sha256.Sum256(manifestRaw)
			capture, err := documentpackage.DecodeManifestV1(manifestRaw, documentpackage.ExpectedV1{Binding: documentpackage.BindingV1{OrgID: q.f.org, DocumentID: root.ID, PackageID: packageID, Revision: revision}, CommitmentSHA256: hex.EncodeToString(legalSHA)})
			if err != nil || !bytes.Equal(digest[:], manifestSHA) {
				t.Fatal("actual package capture failed its unchanged canonical codec", err)
			}
			main := capture.Main()
			if main.DocumentID != root.ID || main.Title != root.Name || main.Source.Kind != documentpackage.SourcePDFImportV1 || main.Source.CommitmentSHA256 != "" || main.Source.OriginCommitmentSHA256 != "" || main.Source.Materialization != nil || main.PDF.Key != root.PdfStorageKey.String || main.PDF.VersionID != root.PdfStorageVersionID.String || main.PDF.SHA256 != hex.EncodeToString(root.PdfSha256) || main.PDF.Bytes <= 0 || main.PDF.Pages != 1 || len(capture.Annexes()) != 1 || capture.Annexes()[0].DocumentID != annex.ID {
				t.Fatal("format-only Send changed the exact imported PDF/source capture tuple")
			}
			// The imported-PDF manifest deliberately carries PDF/source pins, not a
			// variables field. Original document Vars and their native size are checked
			// above; this assertion does not invent captured variable commitments.
			ownedPlainAssertDrainedV1(t, q)
		})
	}
}

func packagePDFVariablesSelection286(t *testing.T, q *ownedPublicReadFixtureV1, root, annex *generated.Document) packageSendInputV1 {
	t.Helper()
	var view struct {
		DocumentID uuid.UUID `json:"document_id"`
		UpdatedAt  string    `json:"updated_at"`
		PackageID  string    `json:"package_id"`
		Generation string    `json:"generation"`
	}
	read := submitSessionOperationE2E(q.f.s, http.MethodGet, "/api/v1/documents/"+root.ID.String()+"/attachments", "", q.cookie)
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &view) != nil || view.DocumentID != root.ID {
		t.Fatal("actual package inventory failed", read.Code, read.Body.String())
	}
	raw, err := json.Marshal(map[string]any{"member_document_id": annex.ID.String(), "expected_updated_at": view.UpdatedAt, "expected_member_updated_at": annex.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_package_id": view.PackageID, "expected_generation": view.Generation, "ordinal": 1, "title": annex.Name, "category": "DPA"})
	if err != nil {
		t.Fatal(err)
	}
	selected := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/attachments", string(raw), q.cookie)
	if selected.Code != http.StatusCreated {
		t.Fatal("actual package attachment selection failed", selected.Code, selected.Body.String())
	}
	read = submitSessionOperationE2E(q.f.s, http.MethodGet, "/api/v1/documents/"+root.ID.String()+"/attachments", "", q.cookie)
	if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &view) != nil || view.PackageID == "" || view.Generation == "0" {
		t.Fatal("saved actual package inventory failed", read.Code)
	}
	return packageSendInputV1{ExpectedUpdatedAt: view.UpdatedAt, PackageID: view.PackageID, Generation: view.Generation}
}

func packagePDFVariablesSource286(t *testing.T, q *ownedPublicReadFixtureV1, document uuid.UUID) string {
	t.Helper()
	var state string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_array(d.source_kind,d.template_id,d.pdf_storage_key,d.pdf_storage_version_id,encode(d.pdf_sha256,'hex'),d.evidence_version_pins_required,d.html_source_json,d.html_current_source_json,d.variables_json,p.variables_wire_bytes)::text
  FROM documents d JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id AND p.org_id=d.org_id WHERE d.id=$1 AND d.org_id=$2`, document, q.f.org).Scan(&state)
	if err != nil {
		t.Fatal("actual source/variables/native-size observation failed", err)
	}
	return state
}

func packagePDFVariablesEffects286(t *testing.T, q *ownedPublicReadFixtureV1) string {
	t.Helper()
	base := packageMeasurementState232(t, q)
	var state string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
 'recipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1),
 'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY b.document_id,b.variable_name) FROM document_variable_bindings b JOIN documents d ON d.id=b.document_id WHERE d.org_id=$1),
 'lawful_basis',(SELECT jsonb_agg(to_jsonb(l) ORDER BY l.document_id) FROM document_lawful_basis_confirmations l WHERE l.org_id=$1),
 'emails',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM email_deliveries e))::text`, q.f.org).Scan(&state)
	if err != nil {
		t.Fatal("actual refusal-effect observation failed", err)
	}
	return base + state
}

func packagePDFVariablesProvider286(t *testing.T, q *ownedPublicReadFixtureV1) string {
	t.Helper()
	q.storagePeer.mu.Lock()
	defer q.storagePeer.mu.Unlock()
	raw, err := json.Marshal(struct {
		Objects       map[string][]byte
		Puts, Deletes int
	}{q.storagePeer.objects, q.storagePeer.puts, q.storagePeer.deletes})
	if err != nil {
		t.Fatal("provider object observation failed", err)
	}
	return string(raw)
}
