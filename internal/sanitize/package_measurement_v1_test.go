// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sanitize

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func storedProofFixtureV1(t *testing.T) ([]byte, Report) {
	t.Helper()
	source, output := []byte("synthetic source"), []byte("synthetic cleaned")
	proof := newPDFProof(source, output, 2, PDFProperties{}, PDFProperties{}, strings.Repeat("a", 64), strings.Repeat("a", 64))
	report := Report{Asset: "synthetic", ContentType: "application/pdf", Method: "pdfcpu", Stripped: proof.Removed, BytesBefore: int64(len(source)), BytesAfter: int64(len(output)), Provenance: "observed", PDF: proof}
	raw, err := MergeReports(nil, report)
	if err != nil {
		t.Fatal(err)
	}
	return raw, report
}
func TestStoredPDFProvenanceV1BindsActualOutput(t *testing.T) {
	raw, r := storedProofFixtureV1(t)
	if err := ValidateStoredPDFProvenanceV1(raw, r.PDF.OutputSHA256, r.BytesAfter, 2); err != nil {
		t.Fatal(err)
	}
	old := r
	other := *r.PDF
	other.OutputSHA256 = strings.Repeat("b", 64)
	old.PDF = &other
	withHistory, err := MergeReports(raw, old)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateStoredPDFProvenanceV1(withHistory, r.PDF.OutputSHA256, r.BytesAfter, 2); err != nil {
		t.Fatal("valid separately observed history rejected", err)
	}
	for _, tc := range []struct {
		name, hash string
		size       int64
		pages      int
	}{{"hash", strings.Repeat("c", 64), r.BytesAfter, 2}, {"bytes", r.PDF.OutputSHA256, r.BytesAfter + 1, 2}, {"pages", r.PDF.OutputSHA256, r.BytesAfter, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(ValidateStoredPDFProvenanceV1(raw, tc.hash, tc.size, tc.pages), ErrStoredPDFProvenanceV1) {
				t.Fatal("unbound tuple accepted")
			}
		})
	}
}
func TestStoredPDFProvenanceV1RejectsAliasedAndConflictingEvidence(t *testing.T) {
	raw, r := storedProofFixtureV1(t)
	duplicate, err := MergeReports(raw, r)
	if err != nil {
		t.Fatal(err)
	}
	var missingEnvelope map[string]json.RawMessage
	if err = json.Unmarshal(raw, &missingEnvelope); err != nil {
		t.Fatal(err)
	}
	var missingItems []map[string]json.RawMessage
	if err = json.Unmarshal(missingEnvelope["items"], &missingItems); err != nil {
		t.Fatal(err)
	}
	var missingPDF map[string]json.RawMessage
	if err = json.Unmarshal(missingItems[0]["pdf"], &missingPDF); err != nil {
		t.Fatal(err)
	}
	var missingAfter map[string]json.RawMessage
	if err = json.Unmarshal(missingPDF["after"], &missingAfter); err != nil {
		t.Fatal(err)
	}
	delete(missingAfter, "annotations")
	missingPDF["after"], err = json.Marshal(missingAfter)
	if err != nil {
		t.Fatal(err)
	}
	missingItems[0]["pdf"], err = json.Marshal(missingPDF)
	if err != nil {
		t.Fatal(err)
	}
	missingEnvelope["items"], err = json.Marshal(missingItems)
	if err != nil {
		t.Fatal(err)
	}
	missingFalse, err := json.Marshal(missingEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{"missing": "{}", "legacy": strings.Replace(string(raw), "\"schema_version\":2", "\"schema_version\":1", 1), "alias-schema": strings.Replace(string(raw), "schema_version", "SCHEMA_VERSION", 1), "alias-items": strings.Replace(string(raw), "items", "ITEMS", 1), "mixed-alias": strings.TrimSuffix(string(raw), "}") + ",\"ITEMS\":[]}", "unknown": strings.TrimSuffix(string(raw), "}") + ",\"extra\":false}", "null-items": "{\"schema_version\":2,\"items\":null}", "duplicate-output": string(duplicate), "trailing": string(raw) + " {}", "missing-observed-false": string(missingFalse)}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(ValidateStoredPDFProvenanceV1([]byte(body), r.PDF.OutputSHA256, r.BytesAfter, 2), ErrStoredPDFProvenanceV1) {
				t.Fatal("unsafe/aliased evidence accepted")
			}
		})
	}
	var env map[string]json.RawMessage
	if err = json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var items []json.RawMessage
	if err = json.Unmarshal(env["items"], &items); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(items[0]), "\"provenance\":\"observed\"", "\"provenance\":null", 1)
	env["items"] = json.RawMessage("[" + bad + "]")
	broken, _ := json.Marshal(env)
	if !errors.Is(ValidateStoredPDFProvenanceV1(broken, r.PDF.OutputSHA256, r.BytesAfter, 2), ErrStoredPDFProvenanceV1) {
		t.Fatal("null observed proof accepted")
	}
}
func TestPageCountIsolatedV1CannotFallBack(t *testing.T) {
	old := activePDFWorker.Load()
	activePDFWorker.Store(nil)
	t.Cleanup(func() { activePDFWorker.Store(old) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := PageCountIsolatedWithContextV1(ctx, []byte("%PDF-synthetic")); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("nil worker permitted caller parsing", err)
	}
	if _, err := PageCountIsolatedWithContextV1(context.Background(), []byte("%PDF-synthetic")); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("unbounded dispatch permitted", err)
	}
	cancel()
	if _, err := PageCountIsolatedWithContextV1(ctx, []byte("%PDF-synthetic")); !errors.Is(err, context.Canceled) {
		t.Fatal("original cancellation hidden", err)
	}
}
func TestPageCountIsolatedV1FundsCommonWorkerStdout(t *testing.T) {
	small, err := PageCountIsolatedParentWorkV1(1)
	if err != nil || small < 4*MaxPDFBytes {
		t.Fatal("nominal tiny response underfunds common stdout", small, err)
	}
	large, err := PageCountIsolatedParentWorkV1(MaxPDFBytes)
	if err != nil || large <= small {
		t.Fatal("source overlap not funded", large, err)
	}
	for _, n := range []int64{-1, 0, MaxPDFBytes + 1} {
		if _, err := PageCountIsolatedParentWorkV1(n); !errors.Is(err, ErrPDFTooLarge) {
			t.Fatal("invalid source price accepted", n, err)
		}
	}
}
