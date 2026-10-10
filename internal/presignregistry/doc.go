// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package presignregistry persists owner-reviewed workflow definitions and
// named interactive self-grants. It does not execute a workflow, stamp a PDF,
// consume a grant use, create a signature or enable delegated signing.
//
// Immutable definitions and consent snapshots are separate from terminal
// retirement/revocation. A later execution adapter must enforce the stored rules
// against actual source3 artifacts and atomically pair a use with its execution,
// provider signature and sealing intent. Descriptor validation proves neither
// live provider authority nor legal effect.
package presignregistry
