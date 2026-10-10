// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package presign defines the separate policy, self-grant and exact-document
// execution commitments for delegated provider signing. It does not implement
// signing, a policy registry, authentication, rendering, storage or persistence.
// Its descriptors assert identity and authority; they do not independently prove
// either assertion or establish any particular legal effect.
//
// Policy, Grant and Execution have private, immutable snapshots. Constructors
// validate and copy their inputs, and accessors return owned copies. The new
// purpose-separated encodings do not modify HTML source schemas 1/2/3, existing
// manual signing evidence, or Article 13 acknowledgment bytes. No public token,
// human acknowledgment, portal visit or manual signing event is synthesized.
//
// A caller must obtain authoritative observations with the original admitted
// credential, retain the document, selected approved template/workflow, members,
// credential and grant with a consistent SQL lock order, and recheck all natural
// deadlines after external work and audit waits. AuthorizeFreshExecution must
// run immediately before atomically consuming the use and persisting execution,
// provider signature/status and the durable draft-to-sealing plan. A successful
// pure predicate is not that transaction and cannot prevent a revocation race.
//
// ValidateCommittedExecution checks the integrity of frozen descriptors only.
// It neither proves that an execution committed nor authorizes another use. The
// caller must authenticate the original actor/organization before readback and
// recover only a genuinely committed plan. Current revocation never rewrites
// that plan. Customer invitation, partial-signature visibility, final evidence,
// negotiation supersession and application enablement require later integration.
package presign
