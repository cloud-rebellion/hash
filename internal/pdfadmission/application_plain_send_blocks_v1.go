// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"math/big"
	"unsafe"
)

var ErrPlainSendBlockTreeV1 = errors.New("pdfadmission: canonical block tree refused")
var ErrPlainSendBlockValuesV1 = errors.New("pdfadmission: malformed block variable map")
var ErrPlainSendBlockVariablesV1 = errors.New("pdfadmission: unresolved block values")
var ErrPlainSendBlockLegalV1 = errors.New("pdfadmission: withdrawn built-in legal draft")
var ErrPlainSendBlockEvidenceV1 = errors.New("pdfadmission: immutable block evidence refused")

type plainSendBlockPolicyFailureV1 struct{ kind, cause error }

func (e plainSendBlockPolicyFailureV1) Error() string   { return e.cause.Error() }
func (e plainSendBlockPolicyFailureV1) Unwrap() []error { return []error{e.kind, e.cause} }
func plainSendBlockPolicyFailureForV1(kind, cause error) error {
	if cause == nil {
		return nil
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, ErrHTMLSendWorkV1) || errors.Is(cause, ErrHTMLRevisionSourceV1) {
		return cause
	}
	return plainSendBlockPolicyFailureV1{kind, cause}
}

// This meter prices ALL lexical occurrences as transient decoder work; it
// deliberately does not infer final block topology, validate grammar, reject
// duplicates, apply tree caps early or alter encoding/json's merge/null rules.
// Only the original canonical decoder/validator decides valid block content.
// Logical staging/slots are not allocator capacity, process RSS or GC proof.
func plainSendBlockLexicalWorkV1(ctx context.Context, raw []byte) (int64, error) {
	var objects, arrays, stringsCount, slots int64
	quoted, escaped := false, false
	for i, c := range raw {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		if quoted {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
			stringsCount++
		case '{':
			objects++
		case '[':
			arrays++
		case ':', ',':
			slots++
		}
	}
	n := int64(0)
	for _, x := range [][2]int64{{objects, 4*int64(unsafe.Sizeof(blocks.Block{})) + 4*int64(unsafe.Sizeof(map[string]any{}))}, {arrays, 8 * int64(unsafe.Sizeof([]any{}))}, {stringsCount, 8 * int64(unsafe.Sizeof(""))}, {slots + objects + arrays, 8*int64(unsafe.Sizeof(any(nil))) + 4*int64(unsafe.Sizeof("")) + 8*int64(unsafe.Sizeof(uintptr(0)))}, {int64(len(raw)), 16}, {min(int64(len(raw))+1, 10001), 8 * int64(unsafe.Sizeof(uintptr(0)))}, {1, 4*int64(unsafe.Sizeof(json.Decoder{})) + 4*int64(unsafe.Sizeof(blocks.Tree{})) + 16*int64(unsafe.Sizeof(big.Rat{}))}} {
		if !htmlInputAddV1(&n, x[0], x[1]) {
			return 0, ErrHTMLSendWorkV1
		}
	}
	return n, nil
}

// The only instance is private to an active actual source-policy method. Pure
// block parsing calls this immediately before its unchanged big.Rat.SetString.
// Both comparison operands and Cmp/cross-product/pow staging share a continuous
// MAX reservation through the original synchronous source operation's join.
type plainSendBlockDecimalAdmissionV1 struct {
	source *applicationHTMLSendSourceStateV1
}

func (a plainSendBlockDecimalAdmissionV1) BeforeDecimalV1(value string) (failure error) {
	defer func() {
		if failure != nil && a.source != nil {
			a.source.blockAdmissionFailure = failure
		}
	}()
	s := a.source
	if s == nil || s.owner == nil || !s.blockProcessing || s.closeRequested.Load() {
		return ErrHTMLSendWorkV1
	}
	if err := s.owner.binding.ctx.Err(); err != nil {
		return err
	}
	b, err := blocks.DecimalLogicalBoundForSendV1(value)
	if err != nil {
		return err
	}
	bits := int64(0)
	for _, v := range []int64{b.MantissaBits, b.PowerFiveBits, b.NumeratorBits, b.DenominatorBits} {
		if !htmlInputAddV1(&bits, v, 1) {
			return ErrHTMLSendWorkV1
		}
	}
	// 64 rounded logical word sets cover the two original Rat operands, decimal
	// conversion/power, reductions and cross-products; explicit type headers and
	// source copies remain separate. No arithmetic call executes while pricing.
	words := bits / 64
	if bits%64 != 0 {
		words++
	}
	n := int64(0)
	if !htmlInputAddV1(&n, words, 64*8) || !htmlInputAddV1(&n, b.SourceBytes, 8) || !htmlInputAddV1(&n, 1, 32*int64(unsafe.Sizeof(big.Int{}))+8*int64(unsafe.Sizeof(big.Rat{}))) {
		return ErrHTMLSendWorkV1
	}
	s.blockDecimalPeak = max(s.blockDecimalPeak, n)
	total := s.blockWorkBase
	if !htmlInputAddV1(&total, s.blockDecimalPeak, 1) {
		return ErrHTMLSendWorkV1
	}
	return s.owner.holdV1(htmlRevisionSourceStateV1, total, 0)
}

// Caller holds the actual immutable source mutex and active native owner.
func (s *applicationHTMLSendSourceStateV1) ensureBlockTreeV1() error {
	if s.blockTreeAttempted {
		return s.blockTreeFailure
	}
	s.blockTreeAttempted = true
	s.blockTreeFailure = ErrHTMLSendWorkV1
	doc := s.owner.snapshot.document
	rawWork, err := plainSendBlockLexicalWorkV1(s.owner.binding.ctx, doc.BlocksJson)
	if err != nil {
		return err
	}
	varsWork, err := plainSendBlockLexicalWorkV1(s.owner.binding.ctx, doc.VariablesJson)
	if err != nil {
		return err
	}
	if !htmlInputAddV1(&rawWork, varsWork, 4) {
		return ErrHTMLSendWorkV1
	}
	s.blockWorkBase = rawWork
	if err = s.owner.holdV1(htmlRevisionSourceStateV1, rawWork, rawWork); err != nil {
		return err
	}
	was := s.blockProcessing
	s.blockProcessing = true
	defer func() { s.blockProcessing = was }()
	tree, err := blocks.ParseCanonicalTreeForSendV1(doc.BlocksJson, plainSendBlockDecimalAdmissionV1{source: s})
	if err != nil {
		s.blockTreeFailure = plainSendBlockPolicyFailureForV1(ErrPlainSendBlockTreeV1, err)
		return s.blockTreeFailure
	}
	s.blockTree = tree
	s.blockTreeFailure = nil
	return nil
}
func (s *applicationHTMLSendSourceStateV1) validateBlockEvidenceV1() error {
	if s.blockEvidenceAttempted {
		return s.blockEvidenceFailure
	}
	s.blockEvidenceAttempted = true
	s.blockEvidenceFailure = ErrHTMLSendWorkV1
	if err := blocks.ValidateImmutableSigningEvidence(s.blockTree); err != nil {
		s.blockEvidenceFailure = plainSendBlockPolicyFailureForV1(ErrPlainSendBlockEvidenceV1, err)
		return s.blockEvidenceFailure
	}
	s.blockEvidenceFailure = nil
	return nil
}

// Existing family structure validation precedes variable freezing. It parses
// actual blocks and checks immutable evidence without demanding resolved values.
func (h *ApplicationHTMLSendSourceV1) ValidateBlockStructureV1() error {
	if h == nil || h.state == nil {
		return ErrHTMLSendWorkV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil || s.owner.snapshot == nil || s.owner.snapshot.document.SourceKind != "blocks" {
		return ErrHTMLSendWorkV1
	}
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	if err := s.ensureBlockTreeV1(); err != nil {
		return err
	}
	return s.validateBlockEvidenceV1()
}
func (h *ApplicationHTMLSendSourceV1) ValidateResolvedBlocksV1() error {
	if h == nil || h.state == nil {
		return ErrHTMLSendWorkV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil || !s.attempted || s.failure != nil {
		return ErrHTMLSendWorkV1
	}
	if s.owner.snapshot.document.SourceKind != "blocks" {
		return nil
	}
	if s.blockAttempted {
		return s.blockFailure
	}
	s.blockAttempted = true
	s.blockFailure = ErrHTMLSendWorkV1
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	doc := s.owner.snapshot.document
	if err := s.ensureBlockTreeV1(); err != nil {
		s.blockFailure = err
		return err
	}
	if blocks.WithdrawnBuiltInLegalDraftForSendV1(s.blockTree) {
		s.blockFailure = plainSendBlockPolicyFailureV1{ErrPlainSendBlockLegalV1, errors.New("withdrawn built-in legal draft")}
		return s.blockFailure
	}
	s.blockProcessing = true
	defer func() { s.blockProcessing = false }()
	values, err := blocks.ValidateResolvedVariableValuesForSendV1(s.blockTree, doc.VariablesJson, plainSendBlockDecimalAdmissionV1{source: s})
	if err != nil {
		s.blockFailure = plainSendBlockPolicyFailureForV1(ErrPlainSendBlockVariablesV1, err)
		return s.blockFailure
	}
	if err = s.owner.binding.ctx.Err(); err != nil {
		return err
	}
	s.blockValues = values
	s.blockFailure = nil
	return nil
}
func (h *ApplicationHTMLSendSourceV1) RequiredBlockRolesV1() ([]string, error) {
	if h == nil || h.state == nil {
		return nil, ErrHTMLSendWorkV1
	}
	s := h.state
	if !s.lockV1() {
		return nil, ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil || (s.blockAttempted && s.blockFailure != nil) {
		return nil, ErrHTMLSendWorkV1
	}
	if s.blockRolesAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	s.blockRolesAttempted = true
	s.blockRolesFailure = ErrHTMLSendWorkV1
	if err := s.owner.beginV1(); err != nil {
		return nil, err
	}
	defer s.owner.finishV1()
	s.blockProcessing = true
	defer func() { s.blockProcessing = false }()
	if err := s.ensureBlockTreeV1(); err != nil {
		s.blockRolesFailure = err
		return nil, err
	}
	if err := s.validateBlockEvidenceV1(); err != nil {
		s.blockRolesFailure = err
		return nil, err
	}
	if s.blockValues == nil {
		values, err := blocks.ParseVariableValues(s.owner.snapshot.document.VariablesJson)
		if err != nil {
			s.blockRolesFailure = plainSendBlockPolicyFailureForV1(ErrPlainSendBlockValuesV1, err)
			return nil, s.blockRolesFailure
		}
		s.blockValues = values
	}
	roles, err := blocks.RequiredSignerRolesForVariablesForSendV1(s.blockTree, s.blockValues, plainSendBlockDecimalAdmissionV1{source: s})
	if err != nil {
		s.blockRolesFailure = plainSendBlockPolicyFailureForV1(ErrPlainSendBlockVariablesV1, err)
		return nil, s.blockRolesFailure
	}
	if err = s.owner.binding.ctx.Err(); err != nil {
		return nil, err
	}
	s.blockRoles = roles
	s.blockRolesFailure = nil
	return append([]string(nil), roles...), nil
}

var _ blocks.ConditionalSendAdmissionV1 = plainSendBlockDecimalAdmissionV1{}
