// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
)

// Costs derive only from retained native snapshots, before member arrays, hex
// strings or constructors. The post-marshal64KiB limit is not an allocation
// allowance: accepted bounded strings may escape to six times their length.
func htmlSendPackageCaptureConstructionV1(root *generated.Document, draft *applicationDocumentPackageDraftSnapshotV1) (int64, error) {
	if root == nil || draft == nil || !draft.present || draft.count < 0 || draft.count > documentpackage.MaxAnnexesV1 {
		return 0, ErrHTMLSendPackageCaptureV1
	}
	n := int64(draft.count + 1)
	var text, keyBytes, materializations int64
	for i := 0; i < int(n); i++ {
		title, category, key, version := root.Name, "", root.PdfStorageKey.String, root.PdfStorageVersionID.String
		if i > 0 {
			a := &draft.rows[i-1]
			title, category, key, version = a.Title, a.Category, a.PdfKey, a.PdfVersionID
			if a.MaterializationID.Valid {
				materializations++
			}
		} else if root.HtmlCurrentMaterializationID.Valid {
			materializations++
		}
		if len(title) < 1 || len(title) > documentpackage.MaxTitleBytesV1 || len(category) > documentpackage.MaxCategoryBytesV1 || len(key) < 1 || len(key) > documentpackage.MaxObjectTextBytesV1 || len(version) < 1 || len(version) > documentpackage.MaxObjectTextBytesV1 {
			return 0, ErrHTMLSendPackageCaptureV1
		}
		for _, v := range []string{title, category, key, version} {
			if !htmlInputAddV1(&text, int64(len(v)), 1) {
				return 0, ErrHTMLSendPackageCaptureV1
			}
		}
		if !htmlInputAddV1(&keyBytes, int64(len(key)), 1) {
			return 0, ErrHTMLSendPackageCaptureV1
		}
	}
	encoded := int64(4096)
	if !htmlInputAddV1(&encoded, n, 1024) || !htmlInputAddV1(&encoded, text, 6) {
		return 0, ErrHTMLSendPackageCaptureV1
	}
	objects := 2 + 3*n + materializations
	arraySlots := int64(0)
	if draft.count > 0 {
		arraySlots = 2 * htmlInputPowerV1(int64(draft.count))
	}
	shape := htmlAuthoringInputShapeV1{raw: encoded, stringBytes: encoded, strings: 13 + 23*n + 3*materializations, scalars: 3 * n, objects: objects, arrays: 1, tableSlots: 16 * objects, arraySlots: arraySlots, depth: 5}
	// NewCapture clones canonical bytes, token-decodes, typed-decodes, and calls
	// NewManifest again. Both constructors' maps/strings/encoders are additive.
	total, err := htmlAuthoringInputParserArenaV1(shape, 2)
	if err != nil {
		return 0, err
	}
	maps, err := htmlRevisionRetentionMapV1(int(n))
	if err != nil {
		return 0, err
	}
	for _, part := range [][2]int64{{encoded, 12}, {text, 4}, {n, 8 * (int64(unsafe.Sizeof(documentpackage.MemberV1{})) + int64(unsafe.Sizeof(documentpackage.MaterializationPinV1{})))}, {maps, 4}, {keyBytes + n, 4 * int64(unsafe.Sizeof(""))}, {n + 1, 4096}} {
		if !htmlInputAddV1(&total, part[0], part[1]) {
			return 0, ErrHTMLSendPackageCaptureV1
		}
	}
	fixed := 8 * (int64(unsafe.Sizeof(documentpackage.InputV1{})) + int64(unsafe.Sizeof(documentpackage.ManifestV1{})) + int64(unsafe.Sizeof(documentpackage.CaptureV1{})) + int64(unsafe.Sizeof(documentpackage.CaptureHeaderV1{})))
	if !htmlInputAddV1(&total, fixed, 1) {
		return 0, ErrHTMLSendPackageCaptureV1
	}
	return total, nil
}

// M101 derives retained intake reports in the trigger even though they are not
// Append parameters. Fund the main/frozen reports and native bind/RETURNING/DB
// overlap independently of canonical construction. Retain through SQL retirement.
func htmlSendPackageCaptureStatementV1(root *generated.Document, draft *applicationDocumentPackageDraftSnapshotV1, manifestBytes int) (raw, db int64, err error) {
	if root == nil || draft == nil || draft.count < 0 || draft.count > documentpackage.MaxAnnexesV1 || manifestBytes < 1 || manifestBytes > documentpackage.MaxManifestBytesV1 {
		return 0, 0, ErrHTMLSendPackageCaptureV1
	}
	var reports, text int64
	for i := 0; i <= draft.count; i++ {
		report := root.MetadataRedactionReport
		if i > 0 {
			a := &draft.rows[i-1]
			report = a.PdfIntakeReport
			for _, s := range []string{a.Title, a.Category, a.PdfKey, a.PdfVersionID} {
				if !htmlInputAddV1(&text, int64(len(s)), 1) {
					return 0, 0, ErrHTMLSendPackageCaptureV1
				}
			}
		}
		if len(report) < 1 || len(report) > 65536 || !htmlInputAddV1(&reports, int64(len(report)), 1) {
			return 0, 0, ErrHTMLSendPackageCaptureV1
		}
	}
	for _, s := range []string{root.Name, root.PdfStorageKey.String, root.PdfStorageVersionID.String} {
		if !htmlInputAddV1(&text, int64(len(s)), 1) {
			return 0, 0, ErrHTMLSendPackageCaptureV1
		}
	}
	raw = 16384 + 4*(int64(unsafe.Sizeof(generated.AppendDocumentPackageCaptureV1Params{}))+int64(unsafe.Sizeof(generated.DocumentPackageCapturesV1{})))
	for _, part := range [][2]int64{{int64(manifestBytes), 8}, {reports, 4}, {text, 4}} {
		if !htmlInputAddV1(&raw, part[0], part[1]) {
			return 0, 0, ErrHTMLSendPackageCaptureV1
		}
	}
	db = 16384
	if !htmlInputAddV1(&db, raw, 8) {
		return 0, 0, ErrHTMLSendPackageCaptureV1
	}
	return raw, db, nil
}
