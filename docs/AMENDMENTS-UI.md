# Later amendments in the application

This source-only cut supplies staff screens for three agreement-permitted processes and a separate read-only notice reader. It is not a release or legal-sufficiency assessment. Native persistence, delivery adapters, migrations and their tests must be composed and qualified together before enabling the feature.

A completed agreement keeps its original signed PDF and evidence report. Later amendments lists the full linked history and labels the latest **proposed** amendment; this does not determine which terms are legally effective. An owner prepares a separate draft before linking: amendment wording and cover, original agreement reference, accompanying documents, PDF review, recipients and signature locations. Linking does not send it. Linked preparation becomes read-only; changed content needs a new separate proposal.

- **New signature:** review and send the independent draft through ordinary signing with fresh credentials.
- **Explicit acknowledgement:** review and send the independent draft through explicit Accept without a signature. The original signature profile is unchanged.
- **Agreed notice:** review exact email subject, text and explicit audience, then issue the reviewed notice. Ordinary signing/Accept/Send is unavailable for that notice document. Queued, retrying, provider acceptance, failure and verified receipt events are distinct. Provider acceptance establishes none of delivery, agreement, signature or effectiveness.

An owner can explicitly attest to a clause in an earlier agreement, its reference, permitted processes, email channel and timing conditions. The screen labels this as an owner review, not a new approval by the other party. Saved agreement policies are selectable only when returned by native inventory. The initial design-policy authoring/Send producer is a separate required successor, not fabricated by these screens. The amendment cover remains a reviewed part of the independently authored document; the checkbox records review and does not generate legal wording or certify its meaning.

## Staff API

The strict `hash-later-amendments-v1` DTO and transport are in `frontend/src/lib/amendments.ts` and `frontend/src/lib/api/amendments.ts`.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/documents/{originalID}/amendments` | Original artifact references, actual policies, full ordered proposed history and latest proposed head |
| `GET /api/v1/documents/{candidateID}/amendment` | Direct authenticated candidate relation; only this route's 404 means ordinary document |
| `POST /api/v1/documents/{originalID}/amendments` | Link reviewed draft using immutable request ID and expected head/document clock |
| `POST /api/v1/documents/{originalID}/amendments/{amendmentID}/notice` | Issue exact reviewed notice and ordered explicit audience |
| `POST /api/v1/documents/{originalID}/amendments/{amendmentID}/notice/access/{accessID}/revoke` | Owner revokes one exact email link with `{}`; saved access status remains separate from email progress |

Unknown outcomes retain the exact reviewed request. Refresh reconciles its immutable ID and content; deliberate retry uses that same request. No changed-content replay or silent new ID occurs. Link revocation is intrinsically idempotent by access ID; only a fresh saved capability status is shown as revoked, including after an unknown POST outcome. Previously downloaded files cannot be withdrawn. Fresh identity and document checks precede writes; native owner/tenant/CAS/file-set checks remain authoritative. Interrupted relation lookup blocks Send. Notice-linked pages cannot use ordinary Send; native transition fences remain essential. Full history is capped at the native 64 links, and draft choices use the existing paged document API.

## Notice reader

Email enters `/notice/{noticeID}#access=hn1.…`. Browser component construction removes the entire fragment synchronously before parsing or async API work. The token is a private one-shot local, never reactive UI state, browser storage, error detail, query string or telemetry. All browser Flare startup/reporting paths skip `/notice/`, including an existing reporter after client navigation. The layout performs no staff identity probe and renders no authenticated navigation there.

`POST /api/v1/notices/{id}/access` exchanges strict JSON for a server-owned purpose-specific HttpOnly, Secure, SameSite Strict cookie. JavaScript never sets or reads it. Metadata and file requests then use only that cookie, with no-store, no-referrer and refused redirects. Expired read sessions ask the reader to reopen the original email; every service read must check expiry/revocation.

`GET /api/v1/notices/{id}` exposes only the closed public DTO. `GET /api/v1/notices/{id}/files/{position}` uses exact If-Match. Before reading bytes, the client checks every identity/version/hash/size/page header. It enforces the whole-set 50 MiB/500 page limit and verifies actual PDF length and SHA-256. Files are exact saved versions, never mutable latest-file URLs. Previous fetches and PDF owners retire before bytes are cleared or another viewer opens. Reading/downloading submits no signature, acknowledgement or read receipt and makes no acceptance/effectiveness inference.

## Qualification

Authored Bun tests exercise the actual controller/transport and extracted actual Svelte entry/retirement callbacks: all three processes, stale identity/clock, immutable replay/reconciliation, exact audience, direct candidate fencing, malformed/bounded responses, file proof, cancellation, fragment removal and Flare entry paths. These tests are **UNRUN** in this partition. Svelte check/build, actual browser and accessibility review, database/outbox/delivery/access journeys, configured SMTP and revocation/expiry acceptance remain required. Initial policy producer and complete sales readiness are not supplied by this screen cut alone.
