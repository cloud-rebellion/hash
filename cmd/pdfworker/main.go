// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// hash-pdf-worker processes one in-memory PDF job, then exits. It never loads
// application configuration, storage keys, database connections, or fonts.
package main

import (
	"os"
	"runtime/debug"

	"github.com/bright-interaction/hash/internal/sanitize"
)

func main() {
	debug.SetMemoryLimit(384 << 20) // GC target; the hard address-space limit is separate.
	if err := restrictPDFWorker(); err != nil {
		os.Exit(1)
	}
	if err := sanitize.ServePDFWorker(os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}
