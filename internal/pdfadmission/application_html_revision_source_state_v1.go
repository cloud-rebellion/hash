// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"errors"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

// Invoked only by the genuine collection's nested field read while the fixed
// source/state producer and outer collection callback are BOTH active. Original
// placement/party/options decisions still run in their unchanged order.
func (s *applicationHTMLRevisionSourceOwnerV1) fieldOptionsComponentsV1(rows []*generated.DocumentField) error {
	if len(rows) != 2 {
		return nil
	} // original count refusal parses no options
	total := int64(0)
	for _, row := range rows {
		if row == nil || len(row.OptionsJson) == 0 || len(row.OptionsJson) > 2048 {
			continue
		} // unchanged strict size refusal
		original, err := htmlAuthoringInputRootShapeV1(s.binding.ctx, htmlInputStringMapV1, row.OptionsJson)
		if err != nil {
			return errors.Join(htmlsource.ErrInvalid, err)
		}
		parsed, err := htmlAuthoringInputParserArenaV1(original, 3)
		if err != nil {
			return err
		}
		// Successful typed options have exactly3 keys and3 string values; their
		// escaped output can expand sixfold. Include all original decoded key/value
		// bytes even when the later semantic checker refuses an unknown key.
		raw := int64(32)
		if !htmlInputAddV1(&raw, original.stringBytes, 6) {
			return ErrHTMLRevisionSourceV1
		}
		output := htmlAuthoringInputShapeV1{raw: raw, strings: 6, stringBytes: raw, objects: 1, tableSlots: 12, depth: 1}
		future, err := htmlAuthoringInputParserArenaV1(output, 1)
		if err != nil {
			return err
		}
		for _, part := range []int64{parsed, future} {
			if !htmlInputAddV1(&total, part, 1) {
				return ErrHTMLRevisionSourceV1
			}
		}
		if !htmlInputAddV1(&total, raw, 18) {
			return ErrHTMLRevisionSourceV1
		}
	}
	combined, err := htmlAuthoringSumV1(s.stateScratchBase, total)
	if err != nil {
		return err
	}
	return s.holdV1(htmlRevisionSourceStateV1, combined, 0)
}
func (s *applicationHTMLRevisionSourceOwnerV1) stateComponentsV1() (int64, error) {
	if s.effectiveRawMaster.SchemaVersion != htmlmaster.SigningPageSchemaVersion {
		return 0, nil
	}
	readiness, err := htmlRevisionContractReadinessComponentsForV1(s.effectiveRawMaster, htmlmaster.Input{Values: s.effectiveInput.Values, Sections: s.effectiveInput.Sections})
	if err != nil {
		return 0, err
	}
	n := readiness.parentBytes
	mapBytes, err := htmlRevisionRetentionMapV1(2)
	if err != nil {
		return 0, err
	}
	if !htmlInputAddV1(&n, mapBytes, 3) || !htmlInputAddV1(&n, int64(unsafe.Sizeof(htmlsource.ContractParty{})), 4) ||
		!htmlInputAddV1(&n, int64(unsafe.Sizeof(htmlmaster.SigningPagePolicy{})), 2) ||
		!htmlInputAddV1(&n, int64(unsafe.Sizeof(htmlsource.SigningArtifact{}))+2*int64(unsafe.Sizeof(htmlsource.SigningRectangle{})), 2) {
		return 0, ErrHTMLRevisionSourceV1
	}
	return n, nil
}
