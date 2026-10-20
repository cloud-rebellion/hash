// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"encoding/json"
	"unsafe"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

// These are complete fixed LOGICAL input/result staging components, not a Go
// allocator/hash-directory, HTTP transport, PostgreSQL executor or RSS proof.
// The unchanged generic source grammar has no member ceiling. Runtime hash,
// TLS/DNS/transport, pools, GC and process headroom remain measured gates.
// No expression below authorizes a source, tenant, database row or callback.
func htmlSendResolverAddV1(total *int64, n, m int64) error {
	if n < 0 || m < 0 || !htmlInputAddV1(total, n, m) {
		return ErrHTMLSendWorkV1
	}
	return nil
}
func htmlSendResolverParseLogicalV1(raw int64, passes int64) (int64, error) {
	return htmlSendResolverParseDepthLogicalV1(raw, passes, 65)
}
func htmlSendResolverParseDepthLogicalV1(raw int64, passes int64, depth int64) (int64, error) {
	if raw < 0 || passes < 0 || depth < 0 {
		return 0, ErrHTMLSendWorkV1
	}
	// A JSON scalar/key/item needs at least ONE source byte. Counting raw nodes
	// therefore dominates all accepted and error-prefix topologies, including
	// empty containers; it introduces no new accepted member/depth limit. Each
	// visit prices the union of decoder Token, []any slot, map[string]any entry,
	// duplicate-key map entry, RawMessage value and explicit container headers.
	// This is logical entry/slot mass; Swiss directory growth is NOT inferred.
	node := int64(unsafe.Sizeof(any(nil)) + unsafe.Sizeof("") + unsafe.Sizeof(bool(false)) + unsafe.Sizeof(json.RawMessage(nil)) + 2*unsafe.Sizeof(int(0)) + 4*unsafe.Sizeof(uintptr(0)))
	n := int64(0)
	for _, x := range [][2]int64{{raw, node}, {raw, 4}, {1, int64(unsafe.Sizeof(json.Decoder{})) + depth*int64(unsafe.Sizeof(uintptr(0))+unsafe.Sizeof(int(0)))}} {
		if err := htmlSendResolverAddV1(&n, x[0], x[1]); err != nil {
			return 0, err
		}
	}
	out := int64(0)
	if err := htmlSendResolverAddV1(&out, n, passes); err != nil {
		return 0, err
	}
	return out, nil
}
func htmlSendHTTPReadLogicalV1(source *resolver.HTTPSource, ref resolver.Ref) (int64, error) {
	if source == nil {
		return 0, ErrHTMLSendWorkV1
	}
	n := int64(0)
	// Original ReadAll's old/new byte backing, retained exact body and defensive
	// inspection view. The original cap+1 sentinel is unchanged.
	if err := htmlSendResolverAddV1(&n, int64(resolver.SendHTTPResponseByteLimitV1()+1), 4); err != nil {
		return 0, err
	}
	// Actual trusted configuration and exact already-admitted binding path/ref:
	// URI/request/header/string/error copies and dotted-path string span slots.
	for _, x := range [][2]int64{{int64(len(source.BaseURL) + len(source.Token) + len(ref.Source) + len(ref.Path)), 8}, {int64(len(ref.Path) + 1), int64(unsafe.Sizeof(""))}, {1, 256}} {
		if err := htmlSendResolverAddV1(&n, x[0], x[1]); err != nil {
			return 0, err
		}
	}
	return n, nil
}
func htmlSendHTTPDecodeLogicalV1(raw int64) (int64, error) {
	if raw < 0 || raw > int64(resolver.SendHTTPResponseByteLimitV1()) {
		return 0, ErrHTMLSendWorkV1
	}
	n, err := htmlSendResolverParseLogicalV1(raw, 2)
	if err != nil {
		return 0, err
	}
	// SourceJSON Token validator and unchanged UseNumber map Decode. stringify
	// never expands numeric exponents: Number.String keeps lexical bytes. Each
	// JSON string byte may escape to six bytes; two encoder buffers and one
	// returned string copy price18raw. Inspect/body/decoder bytes are separate.
	if err = htmlSendResolverAddV1(&n, raw, 18+8); err != nil {
		return 0, err
	}
	return n, nil
}
func htmlSendResolverInputLogicalV1(doc *generated.Document, bindings []*generated.DocumentVariableBinding) (int64, error) {
	if doc == nil {
		return 0, ErrHTMLSendWorkV1
	}
	n, err := htmlSendResolverParseLogicalV1(int64(len(doc.VariablesJson)), 4)
	if err != nil {
		return 0, err
	}
	// Resolve and reviewed-CRM comparison each ParseVariableValues via the
	// RawMessage map then string map. Final escaped JSON is priced before
	// Marshal; initial static values contribute at most their actual input bytes.
	if err = htmlSendResolverAddV1(&n, int64(len(doc.VariablesJson)), 18); err != nil {
		return 0, err
	}
	for _, b := range bindings {
		if b == nil || b.DocumentID != doc.ID {
			return 0, ErrHTMLSendWorkV1
		}
		raw := int64(len(b.VariableName) + len(b.SourceKind) + len(b.SourceRef) + len(b.SourcePath) + len(b.Fallback) + len(b.LastValue) + len(b.LastError))
		// Native private definition, Resolve bindingSnapshot, staged definitions,
		// complete report copies and original final observation/CAS parameters.
		if err = htmlSendResolverAddV1(&n, raw, 8); err != nil {
			return 0, err
		}
		if err = htmlSendResolverAddV1(&n, 1, 4*int64(unsafe.Sizeof(generated.DocumentVariableBinding{}))+4*int64(unsafe.Sizeof(resolver.ResolveReport{}))+int64(unsafe.Sizeof(generated.UpdateVariableBindingResolvedParams{}))+int64(unsafe.Sizeof(generated.UpdateVariableBindingErrorParams{}))+16*int64(unsafe.Sizeof(uintptr(0)))); err != nil {
			return 0, err
		}
		if b.SourceKind == string(resolver.SourceOrgSetting) {
			if err = htmlSendResolverAddV1(&n, 1, int64(unsafe.Sizeof(ApplicationHTMLSendSQLStageV1{}))+int64(unsafe.Sizeof(ApplicationHTMLSendWorkV1{}))+int64(unsafe.Sizeof(ApplicationHTMLAuthoringReaderV1{}))+int64(unsafe.Sizeof(htmlSendOrgSourceReadsV1{}))+int64(unsafe.Sizeof(applicationHTMLSendPlanPolicyGrantV1{}))); err != nil {
				return 0, err
			}
		}
		// Both original static and missing-source fallback values already exist in
		// the held binding/body loan. Copies and final JSON escaping need own mass.
		if err = htmlSendResolverAddV1(&n, int64(len(b.VariableName)+len(b.Fallback)), 18); err != nil {
			return 0, err
		}
	}
	// The original CRM audit view constructs up to14 concrete key/value slots
	// per actual binding BEFORE the fresh event owner admits its Marshal. Own
	// those map/array/entry headers here; metadata string backing is separately
	// retained by the actual observation/report components above.
	if err = htmlSendResolverAddV1(&n, int64(len(bindings)), 32*int64(unsafe.Sizeof("")+unsafe.Sizeof(any(nil))+2*unsafe.Sizeof(uintptr(0)))+4*int64(unsafe.Sizeof(uintptr(0)))); err != nil {
		return 0, err
	}
	if err = htmlSendResolverAddV1(&n, 1, 2*int64(unsafe.Sizeof(audit.Entry{}))+8*int64(unsafe.Sizeof(uuid.UUID{}))+8*int64(unsafe.Sizeof("")+unsafe.Sizeof(any(nil)))); err != nil {
		return 0, err
	}
	if err = htmlSendResolverAddV1(&n, int64(len(bindings)+1), 32); err != nil {
		return 0, err
	}
	return n, nil
}
func htmlSendResolverValueLogicalV1(value string) (int64, error) {
	n := int64(0)
	// Actual returned string, out/report/staged/private/export copies plus the
	// final JSON encoder's two growing buffers and returned raw (18*bytes).
	if err := htmlSendResolverAddV1(&n, int64(len(value)), 18+8); err != nil {
		return 0, err
	}
	if err := htmlSendResolverAddV1(&n, 1, 64); err != nil {
		return 0, err
	}
	return n, nil
}
func htmlSendCRMResolverLogicalV1(bindingCount int) (scratch, retained int64, err error) {
	if bindingCount < 0 {
		return 0, 0, ErrHTMLSendWorkV1
	}
	// Before/after credential checks and each of at most16 sequential records
	// use the same existing256KiB cap. Strict JSON then RawMessage/typed scalar
	// decoding are sequential; the peak prices all generic logical slots and
	// raw/decoder/stringify buffers for ONE actual bounded response.
	scratch, err = htmlSendResolverParseLogicalV1(crmconnection.MaxResponseBytes, 2)
	if err != nil {
		return 0, 0, err
	}
	if err = htmlSendResolverAddV1(&scratch, crmconnection.MaxResponseBytes, 18+8); err != nil {
		return 0, 0, err
	}
	// The original batch retains typed records and two credential observations.
	// Complete response strings fit the original cumulative4.5MiB body budget;
	// contact full_name adds at most one byte per one of16 records. Six copies
	// cover typed fields, relationship aliases, cloned Record maps and reports.
	if err = htmlSendResolverAddV1(&retained, crmconnection.MaxSnapshotResponseBytes+crmconnection.MaxUniqueRecords, 6); err != nil {
		return 0, 0, err
	}
	// Actual maximum catalog has18 company fields. ReadRecords permits16 records;
	// this fixed accepted topology prices full typed objects/map entries/refs.
	row := int64(unsafe.Sizeof(crmconnection.RecordObservation{})) + 2*18*int64(unsafe.Sizeof("")+unsafe.Sizeof(crmconnection.Scalar{})) + int64(unsafe.Sizeof(crmconnection.RecordRef{}))
	if err = htmlSendResolverAddV1(&retained, crmconnection.MaxUniqueRecords, row); err != nil {
		return 0, 0, err
	}
	if err = htmlSendResolverAddV1(&retained, int64(bindingCount), 2*18*int64(unsafe.Sizeof("")+unsafe.Sizeof(crmconnection.Scalar{}))+16*int64(unsafe.Sizeof(resolver.CRMValueObservation{}))+crmconnection.MaxScalarBytes*26); err != nil {
		return 0, 0, err
	}
	// Report copies also detach actual account metadata independently of the
	// returned value. Existing identity limits are2048origin+2*256remoteIDs,
	// generation20, two64hex digests and a bounded fixed transformation label.
	if err = htmlSendResolverAddV1(&retained, int64(bindingCount), 16*(2048+2*crmconnection.MaxOpaqueIDBytes+20+2*64+64)); err != nil {
		return 0, 0, err
	}
	// Keyring refuses every ciphertext length except93 before plaintext, with
	// canonical64-byte token and actual Identity AAD <=UUIDs+2048origin+256IDs.
	if err = htmlSendResolverAddV1(&scratch, 2048+2*crmconnection.MaxOpaqueIDBytes+2*36+crmconnection.CredentialCiphertextBytes+64, 18); err != nil {
		return 0, 0, err
	}
	return scratch, retained, nil
}

func htmlSendPlanFeaturesLogicalV1(wire int64) (int64, error) {
	// The original full features json.Unmarshal may fail only after visiting an
	// invalid nested shape. Preserve the standard JSON decoder10000 depth gate,
	// not the HTTP validator's64 gate. Numeric float parse scratch is one pinned
	// 800-byte decimal family and errors, conservatively the existing8192 class.
	n, err := htmlSendResolverParseDepthLogicalV1(wire, 1, min(wire+1, 10001))
	if err != nil {
		return 0, err
	}
	if err = htmlSendResolverAddV1(&n, 1, 8192); err != nil {
		return 0, err
	}
	return n, nil
}
