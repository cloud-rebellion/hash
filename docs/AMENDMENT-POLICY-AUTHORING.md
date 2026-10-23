# Optional later-change policy in a reviewed design

An owner can enable **Include an owner-reviewed policy for later changes** in the HTML design editor's existing reviewed contract profile. The setting is optional and absent from saved data when disabled. It supports the existing version 2 and version 3 design profiles; generic version 1 designs receive no inferred policy.

The owner chooses an existing printed contract term, then records a clause reference, the explicitly permitted later processes, email where agreed notice is selected, and timing or other conditions quoted from that same clause. No process is selected by default. The owner writes the clause in the existing declared value or wording section; this setting generates no legal text. The editor shows current design wording and points out when a per-document value still needs actual clause text.

The declaration is `contract_profile.amendment_policy`:

```json
{
  "term": "later_changes",
  "clause_reference": "Section 12.",
  "allowed_modes": ["acknowledgement", "agreed_notice", "signature"],
  "allowed_channels": ["email"],
  "effective_condition": "after 30 days"
}
```

This is a structural example, not agreement wording or a suggested legal clause. The named term must already map to one distinct printed value or wording section. The reference and condition must occur exactly in that term's actual materialized clause. Bounds are UTF8 bytes: reference 512, condition 2048, actual clause 8192; whitespace around text, invalid Unicode, hidden format characters and controls other than LF/TAB are refused. Modes are unique and canonically sorted. `allowed_channels` is explicitly `[]` unless agreed notice is permitted, when it must be exactly `["email"]`. Missing/null channels are refused.

Save/reload passes through the existing strict profile/author validators, deep-copies both arrays and retains the declaration in dirty-state/source comparison. Without the optional field, existing profile serialization remains unchanged. Actual clause checks participate in the existing populated document, preview and revision validation. They check structural correspondence, not whether legal language supports the owner's selected processes.

Owner enable plus the existing complete PDF review and owner approval are the explicit declaration/approval steps. There is no invented additional legal-approval flag. The native Send producer must freeze the actual source/PDF/version and emit the immutable agreement basis consumed by Later amendments. This frontend cut alone does not write a frozen policy or create a signature, acknowledgement, notice or legally effective change.

The eight authored tests cover actual strict validators, proxy-safe author roundtrip, signature-only explicit empty channels, array ownership, optional absence/old profile preservation, actual value/section correspondence and actual owner editor callbacks. They are **UNRUN** here. Native composition, Svelte check/build, browser review, completed agreement/Send freeze and all three later amendment journeys remain required before feature-complete or release claims.
