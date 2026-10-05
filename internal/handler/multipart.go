// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"log/slog"
	"net/http"
)

// File parts above this threshold spill to temporary storage. Overall request
// size is independently bounded by each caller's MaxBytesReader.
const multipartFileMemory = 1 << 20

func cleanupMultipart(r *http.Request) {
	if r.MultipartForm != nil {
		if err := r.MultipartForm.RemoveAll(); err != nil {
			slog.Error("multipart temporary file cleanup failed", "err", err)
		}
	}
}
