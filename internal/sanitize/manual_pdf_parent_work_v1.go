// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sanitize

import "unsafe"

// These are logical parent request/frame/decoded-result prices for the EXISTING
// isolated worker. They grant no child execution slot, address space, process
// or retirement authority. The original worker remains responsible for its
// actual slot, OS restrictions, deadline, cmd.Run and joined IPC. No RSS or
// fleet capacity claim follows from these conservative parent prices.
func ManualPDFInspectionParentWorkV1(sourceBytes int64) (scratch, geometry int64, err error) {
	if sourceBytes < 1 || sourceBytes > MaxPDFBytes {
		return 0, 0, ErrPDFTooLarge
	}
	fixed := 4*int64(unsafe.Sizeof(pdfWorkerRequest{})) + 4*int64(unsafe.Sizeof(pdfWorkerResponse{})) + 4*int64(unsafe.Sizeof(pdfWorkerOutput{})) + 8*pdfWorkerHeaderLimit
	// The original common runner bounds stdout even for manual-inspect. Its
	// header/parser/actual request copies and decoded geometry overlap here.
	scratch = 4*sourceBytes + 4*(MaxPDFBytes+pdfWorkerHeaderLimit) + 8*manualMetadataLimit + fixed
	geometry = 8*manualMetadataLimit + 4*MaxPDFPages*int64(unsafe.Sizeof(PDFManualPage{})) + 4*int64(unsafe.Sizeof(PDFManualGeometry{}))
	return scratch, geometry, nil
}
func ManualPDFCompositionParentWorkV1(sourceBytes, overlayBytes int64) (scratch, output int64, err error) {
	if sourceBytes < 1 || sourceBytes > MaxPDFBytes || overlayBytes < 1 || overlayBytes > MaxPDFBytes-sourceBytes {
		return 0, 0, ErrPDFTooLarge
	}
	fixed := 4*int64(unsafe.Sizeof(pdfWorkerRequest{})) + 4*int64(unsafe.Sizeof(pdfWorkerResponse{})) + 4*int64(unsafe.Sizeof(pdfWorkerOutput{})) + 4*int64(unsafe.Sizeof(PDFManualOverlayResult{})) + 8*pdfWorkerHeaderLimit
	// Actual original/overlay borrowers have their independent owners. This
	// prices the original newly framed request, bounded stdout/parser scratch,
	// descriptors and separately retained composed result before its producer.
	scratch = 4*(sourceBytes+overlayBytes) + 4*(MaxPDFBytes+pdfWorkerHeaderLimit) + 8*manualMetadataLimit + fixed
	output = 4*MaxPDFBytes + 4*int64(unsafe.Sizeof(PDFManualOverlayResult{}))
	return scratch, output, nil
}
