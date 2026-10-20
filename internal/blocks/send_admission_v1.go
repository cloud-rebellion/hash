// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ConditionalSendAdmissionV1 observes the original numeric conversion site.
// It carries no workguard, authentication or persistence authority. The native
// Send owner must derive and install its allowance before returning nil, keep
// that allowance through the owning operation (including both Rats and Cmp),
// and retain every resulting value through actual last use.
type ConditionalSendAdmissionV1 interface {
	BeforeDecimalV1(string) error
}

type conditionalSendWorkV1 struct {
	admission ConditionalSendAdmissionV1
	failure   error
}

func newConditionalSendWorkV1(a ConditionalSendAdmissionV1) *conditionalSendWorkV1 {
	if a == nil {
		return nil
	}
	return &conditionalSendWorkV1{admission: a}
}
func (w *conditionalSendWorkV1) beforeDecimalV1(value string) error {
	if w == nil {
		return nil
	}
	if w.failure != nil {
		return w.failure
	}
	if err := w.admission.BeforeDecimalV1(value); err != nil {
		w.failure = err
		return err
	}
	return nil
}
func (w *conditionalSendWorkV1) resultV1(err error) error {
	// Original validators intentionally flatten some domain errors with %v.
	// Native admission refusal is separately retained without changing those
	// original wrappers or treating resource refusal as malformed contract prose.
	if w != nil && w.failure != nil {
		return w.failure
	}
	return err
}

// ParseCanonicalTreeForSendV1 uses the original decoder, missing-ID check and
// validator. Typed tree decoding must already have its separate native allowance.
func ParseCanonicalTreeForSendV1(raw []byte, a ConditionalSendAdmissionV1) (*Tree, error) {
	w := newConditionalSendWorkV1(a)
	tree, err := parseCanonicalTreeForSendV1(raw, w)
	if err = w.resultV1(err); err != nil {
		return nil, err
	}
	return tree, nil
}
func ValidateForSendV1(tree *Tree, a ConditionalSendAdmissionV1) error {
	w := newConditionalSendWorkV1(a)
	return w.resultV1(validateTreeForSendV1(tree, w))
}
func ValidateResolvedVariableValuesForSendV1(tree *Tree, raw json.RawMessage, a ConditionalSendAdmissionV1) (map[string]string, error) {
	w := newConditionalSendWorkV1(a)
	values, err := validateResolvedVariableValuesForSendV1(tree, raw, w)
	if err = w.resultV1(err); err != nil {
		return nil, err
	}
	return values, nil
}
func RequiredSignerRolesForVariablesForSendV1(tree *Tree, vars map[string]string, a ConditionalSendAdmissionV1) ([]string, error) {
	w := newConditionalSendWorkV1(a)
	roles, err := requiredSignerRolesForVariablesForSendV1(tree, vars, w)
	if err = w.resultV1(err); err != nil {
		return nil, err
	}
	return roles, nil
}

// DecimalLogicalBoundV1 describes the original Go1.26.9 decimal SetString path.
// These are source-derived magnitude components, not a process heap/RSS bound,
// a scratch allocator proof, a grammar restriction or authority to dispatch.
// Scan work includes the whole lexical source even when conversion will fail.
// A native owner must separately price Rat headers, scratch, paired Cmp,
// original parser/map/string work, and actual retention.
type DecimalLogicalBoundV1 struct {
	SourceBytes, MantissaDigits, FractionDigits                 int64
	MantissaBits, PowerFiveBits, NumeratorBits, DenominatorBits int64
	Exponent, AdjustedExponent                                  int64
	ExponentValid, ZeroMantissa, ConversionPossible             bool
}

// DecimalLogicalBoundForSendV1 performs no big-number conversion. Its caller
// must guard the pinned Go1.26.9 implementation before using these components.
// It follows math/big/ratconv.go: scan mantissa and int64 exponent, special-case
// zero, then adjusted decimal exponent's existing abs<=1e6 power-five gate and
// existing +/-1e7 shift gate. Zero with a valid int64 exponent is accepted
// before those power gates. Invalid exponent syntax/range still fails first.
func DecimalLogicalBoundForSendV1(value string) (DecimalLogicalBoundV1, error) {
	var out DecimalLogicalBoundV1
	out.SourceBytes = int64(len(value))
	if !strictDecimalPattern.MatchString(value) {
		return out, fmt.Errorf("not a decimal number")
	}
	mantissaEnd := len(value)
	if at := strings.IndexAny(value, "eE"); at >= 0 {
		mantissaEnd = at
		exponent, err := strconv.ParseInt(value[at+1:], 10, 64)
		if err == nil {
			out.Exponent = exponent
			out.ExponentValid = true
		}
	} else {
		out.ExponentValid = true
	}
	out.ZeroMantissa = true
	fraction := false
	for i := 0; i < mantissaEnd; i++ {
		b := value[i]
		if b == '.' {
			fraction = true
			continue
		}
		if b < '0' || b > '9' {
			continue
		}
		out.MantissaDigits++
		if fraction {
			out.FractionDigits++
		}
		if b != '0' {
			out.ZeroMantissa = false
		}
	}
	if out.MantissaDigits > math.MaxInt64/4 {
		return out, fmt.Errorf("decimal logical magnitude overflow")
	}
	out.MantissaBits = 4 * out.MantissaDigits
	out.NumeratorBits = out.MantissaBits
	out.DenominatorBits = 1
	if !out.ExponentValid {
		return out, nil
	}
	// Go's original signed arithmetic has defined wrap behavior. Retaining that
	// expression follows the pinned path without inventing a new accepted range.
	out.AdjustedExponent = out.Exponent - out.FractionDigits
	if out.ZeroMantissa {
		out.NumeratorBits = 0
		out.ConversionPossible = true
		return out, nil
	}
	q := out.AdjustedExponent
	if q < -1_000_000 || q > 1_000_000 {
		return out, nil
	}
	if q < -10_000_000 || q > 10_000_000 {
		return out, nil
	}
	abs := q
	if abs < 0 {
		abs = -abs
	}
	if abs != 0 {
		out.PowerFiveBits = 3*abs + 1
	}
	if q > 0 {
		if out.NumeratorBits > math.MaxInt64-4*q {
			return out, fmt.Errorf("decimal logical magnitude overflow")
		}
		out.NumeratorBits += 4 * q
	} else if q < 0 {
		out.DenominatorBits += 4 * (-q)
	}
	out.ConversionPossible = true
	return out, nil
}

// WithdrawnBuiltInLegalDraftForSendV1 preserves the existing Send guard's
// exact three fragments and pre-order text/table-cell walk. It does not
// validate a tree, add new legal policy or approve other contract wording.
func WithdrawnBuiltInLegalDraftForSendV1(tree *Tree) bool {
	if tree == nil {
		return false
	}
	const (
		withdrawnLicenseClaim = "Atomicsite-binären levereras under sin öppna licens Apache 2.0"
		withdrawnDPAClaim     = "Ett personuppgiftsbiträdesavtal (Bilaga A) gäller från driftstart"
		unreviewedKitMarker   = "DRAFT KIT v1 (auto-seeded by Hash"
	)
	var found bool
	var walk func([]Block)
	walk = func(items []Block) {
		for i := range items {
			block := &items[i]
			if strings.Contains(block.Text, withdrawnLicenseClaim) ||
				strings.Contains(block.Text, withdrawnDPAClaim) ||
				strings.Contains(block.Text, unreviewedKitMarker) {
				found = true
				return
			}
			for _, row := range block.Rows {
				for _, cell := range row {
					if strings.Contains(cell, withdrawnLicenseClaim) ||
						strings.Contains(cell, withdrawnDPAClaim) ||
						strings.Contains(cell, unreviewedKitMarker) {
						found = true
						return
					}
				}
			}
			walk(block.Content)
			if found {
				return
			}
		}
	}
	walk(tree.Blocks)
	return found
}
