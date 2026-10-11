// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package presignexecute persists immutable delegated execution evidence.
//
// This is not an execution permission, a public signing endpoint or a renderer.
// A fresh caller must authenticate the original admitted executor, retain its
// original credential/deadline, lock live users before the grant head, and check
// the selected policy/template/source/CRM/data/field and verified artifact
// observations before and after audit waits. It allocates the real ceremony
// epoch in the same draft transaction, appends the exact chained audit, then
// constructs a Record and calls AppendAtomic on that transaction. AppendAtomic
// does not commit or publish audit events. The caller rechecks all natural
// deadlines immediately before commit, and never compensates prepared evidence
// after an attempted/ambiguous commit.
//
// LoadOutcome validates committed integrity, not current grant eligibility.
// Its caller authenticates the original actor/credential in a short transaction
// before loading, retains that admission through readback and rechecks its
// deadline. A revoked or expired grant does not erase a committed use. It is
// never a reason to admit a fresh execution, reset a nonce or reopen a document.
//
// The SQL ledger leaves migration81's immutable consumed_uses=0 untouched.
// Selected-revision uses are append-only and contiguous under the grant-head
// lock. Delegated signatures retain an explicit kind, null manual IP/UA and
// exact execution pairing; no portal visit, privacy acknowledgment or notice is
// invented. The permanently retained sealing intent is unsupported by ordinary
// manual recovery. Dedicated artifact retention, visible PDF/disclosure,
// customer signing and superseding negotiation remain separate integration.
package presignexecute
