# Native email work ownership

`emailtemplates.PrepareNativeV1` prepares only the existing decline and quota
warning messages. Its caller supplies the actual original `pgx.Tx`, workspace,
concrete `dispatch.TemplateContext` and the `WorkV1()` of its existing,
pool-matched `WorkRuntime`. No new coordinator, fabricated owner actor, injected
SQL/render callback or send authority is created. The producer keeps all its
original document/token/notice or subscription/dedup checks.

The helper returns frozen subject, HTML, text, selected locale and template
revision with a private process-resource owner. Immediately defer
`CloseConsumerV1` and retain the owner through enqueue/commit and any synchronous
postcommit delivery use. Closure is idempotent. On failure the helper closes its
owner; the caller rolls back the original transaction. Resource refusal is not
permission to fall back to an unowned renderer or ignore a saved edition.

## Admission and retained data

The existing `ApplicationServiceEmailControlV1` retains its original process
coordinator and workspace identity. Before expansion, `AdmitNativeContextV1`
bounds the aggregate concrete string fields to
`ServiceEmailDesignRenderedBytesV1` (262144 bytes), then prices 64 times the
actual string bytes plus 65536 parent bytes. It interprets no URLs or template
syntax and deliberately does not change legacy document-locale fallback.

The selected edition header and row are SHARE-locked by the original
transaction. Header-derived source admission precedes reading the full saved
source. Existing template source/digest validation and synchronous
`BeginTemplateWorkV1` loans remain in place. Only an absent edition selects
built-in copy; unreadable, invalid or mismatched retained source fails closed.

`ReserveNativeOutputV1` uses the existing sample render workspace formula:
16 times `ServiceEmailDesignRenderedBytesV1`, 65536 bytes, the existing fixed
design work, and 64 times the maximum combined design/subject/HTML/text source
bytes. Its DB staging loan covers two maximum rendered bodies, the maximum
rendered subject and 65536 row bytes. These reservations precede native
rendering and outbox allocation. Native output is then checked against the
existing 4096-byte subject and 262144-byte HTML/text limits.

One control cannot reserve both a sample and native output operation. Closing a
consumer while synchronous template work remains does not release that work;
its existing borrower closure joins before the original retained grants retire.
No SMTP, provider call, SQL authority, recipient selection or delivery trigger is
part of this resource helper.

## Language and transaction ordering

Quota reads its saved workspace preference through the original transaction.
An existing preference stays SHARE-locked until that transaction ends. Absence
selects legacy English at that read's linearization point; it does not create a
row or acquire a new document/quota lock. Decline preserves its supplied original
locked document language. The new waits do not replace the producer's final
authority/status/token/notice recheck.

The helper produces strings before enqueue. Queued message format and bytes
remain unchanged. A later settings edit cannot rewrite retained mail. The
existing [process work configuration](WORK-RUNTIME.md) still supplies all
resource budgets; this change adds no runtime settings, reserved capacity or
deployment readiness claim. Server and worker allocations remain separate and
must fit their actual aggregate deployment.

The authored tests cover admission refusal, native output ownership, closed and
foreign contexts, owner/key/tenant/CAS behavior, immutable editions and selected
languages. They must be generated/compiled and executed on the assembled
candidate before qualification; authored test source alone is not a pass.
