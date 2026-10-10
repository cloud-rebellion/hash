# Upload security

Hash accepts PDF document/template imports and branding logos. Upload limits
apply to compressed input; decoded content needs separate limits.

JPEG/PNG branding uploads and palette extraction share a decoder that checks
the image header before allocating pixels. It rejects input over 4 MiB,
either dimension over 4096 pixels, and images over 4,194,304 pixels. Logo
uploads must match their declared JPEG/PNG format. Palette extraction detects
either supported format. Valid images are decoded and re-encoded before logo
storage to remove metadata.

PDF intake rewrites content through pdfcpu and rejects detected active PDF
actions, JavaScript, XFA, and rich-media facilities. The one-step document
and template imports reject PDFs exceeding 500 pages before optimization.
Counting pages still requires parsing untrusted PDF bytes. Intake parsing and
rewriting now use the bundled isolated Linux worker described below. These
controls do not establish a complete malware scan or protection against every
parser vulnerability.

The HTTP server requires a private local ClamD Unix socket outside explicit
development. Uploads require an explicit clean verdict before parsing,
rendering, or release to object storage; detected content and scanner failures
block processing. Hash does not implement a quarantine service. The scanner
daemon, signature updates, socket permissions, and deployed rejection/recovery
behavior still require acceptance. Bound processing time and expanded resources,
and retain only the minimum diagnostic metadata. Do not send customer
documents to a public scanning service without an approved data-processing
arrangement. Follow the [OWASP File Upload guidance](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

SVG logos use a separate stripping path and are not protected by the raster
dimension guard. Review SVG active content and serving behavior separately.
Run renderers with restricted network access and resource limits, keep parser
dependencies updated, and verify the actual deployed controls. Local unit
tests alone do not establish production upload safety.

## PDF metadata evidence

PDF optimization alone does not remove source Info or XMP in the pinned
pdfcpu version. Intake explicitly clears source Info fields and Metadata
references/streams, rewrites the file, and verifies the output. Shared metadata
objects that also serve visual content are refused. The measured policy checks
source Info, Metadata facilities, object streams, linearization, attachments,
forms and annotations, while preserving page count, effective page boxes,
rotation and UserUnit. It does not classify arbitrary XML or page content as
metadata. New pdfcpu Producer and equal current creation/modification dates may
be generated; these are reported separately from removed source metadata.

Fresh PDF reports use envelope schema2 and carry the exact source/output SHA-256,
page and geometry observations, observed removal, prior absence, and generated
Info. No source metadata values are retained in the report or parser logs.
Template uploads retain this observation bound to the stored object key,
SHA-256 and VersionID internally. REST/MCP clones copy the observation from the
SHARE-locked template; corrupt bindings fail closed. Field-only template edits
retain the same source observation. HTML revisions preserve reports per
immutable materialization and snapshot, projecting PDF and report together.

Legacy records without measurements remain explicitly unknown. They cannot
acquire a fresh cleanup attestation by reuse. Existing signed PDFs, certificate
payloads and signatures retain their original bytes. New certificates bind the
measured artifact hashes and state the scope of the intake check; they do not
certify legal sufficiency, malware safety, final-PDF metadata or printed content.

Migration75 adds nullable provenance columns without backfilling history, and
refuses destructive rollback once provenance exists. The strict worker protocol
is version2; older worker responses are refused. Release this schema with the
matching new app and bundled worker after draining old admission and job
processing. Old compiled
SELECT-star readers and snapshot writers are incompatible with the new schema;
a mixed old/new rolling release is not supported. This coordinated deployment
and the actual release-host controls still require acceptance.

Document imports, PDF template uploads and MCP `create_pdf_document` share
process admission: two active imports globally and one per organisation.
REST admission occurs before body parsing; MCP admission occurs before typed
argument decoding, base64 allocation and rendering, although the MCP transport
has already received its bounded JSON envelope. A lease lasts through storage
and database bookkeeping and is released on failure. REST overload returns
HTTP 429 with Retry-After; MCP returns an explicit capacity error. There is no
in-memory waiting queue. This limits simultaneous imports, not each parser's
maximum memory or execution time. Keep the singleton HTTP lease enforced;
multiple independent replicas would require shared admission and fencing.

Multipart uploads retain at most 1 MiB of file-part data in the form parser;
larger file parts spill to temporary storage. Total request limits still
apply. Handlers explicitly remove spilled files on return, including rejected
uploads, before releasing import admission. This reduces overlapping parser
and processing copies; subsequent PDF/image processing still loads bounded
input into memory. Go multipart parsing also reserves memory for non-file
fields, so this threshold is not a total request-memory bound. Keep temporary
storage private and capacity-limited in deployment.

The shared PDF sanitizer rejects input over50MiB before page-count parsing.
This applies to direct imports, template uploads and generated PDFs arriving
from REST/MCP rendering, independent of transport limits. It bounds compressed
input, not expanded PDF object streams or optimizer allocations.

PDF optimization and secondary cleanup write through bounded output buffers.
Writes that would exceed50MiB are refused before copying into the buffer.
This limits logical output size and buffer growth. The worker separately bounds
execution and address space; aggregate resident memory still needs measured
deployment limits.
Output-limit failures in cleanup passes reject the upload. Other optional
cleanup errors retain the previous fallback behavior.

A local ClamD protocol client is implemented in `internal/malwarescan`. It uses
a Unix socket, bounded INSTREAM chunks, a 160 MiB input cap, a 30-second total
deadline, cancellation, and a 4 KiB verdict cap. Source PDF intake remains
capped at 50 MiB. Only an exact complete clean response passes. PDF/template/logo
sanitization, palette extraction, HTML/Markdown replacement imports through
REST and MCP, and uploaded evidence-bundle verification use the shared scanner
gate. Real ClamAV/EICAR rejection, daemon limits, signature updates, socket
permissions, outage recovery, and live deployment acceptance remain pending.
Protocol reference: https://docs.clamav.net/manual/Usage/ClamdProtocol.html

Scanner compatibility checks require a loaded nonzero signature database
and timestamp within 48 hours, allowing at most 15 minutes of future clock skew.
Run ClamD with `TZ=UTC`: its version reply uses an unzoned local timestamp.
Startup, each scan, and public readiness check scanner compatibility and
signature freshness; a failed check blocks startup, processing, or readiness.
The public readiness probe has a one-second budget and sends no uploaded
content. These implemented checks do not establish that the real daemon,
signature refresh, monitoring, parser capacity, or production recovery has been
accepted. See [Malware scanning](./MALWARE-SCANNING.md) for the deployment contract.

Canonical block validation permits at most64 nesting levels and10,000 total
blocks, including nested children. Limit violations are typed invalid-block
errors; REST authoring reports400. This bounds canonical validation/persistence
acceptance. It does not isolate the HTML/Markdown parser or PDF decompression
before canonical validation, and is not a process-level CPU/memory sandbox.

Canonical HTML/Markdown replacement imports (REST and MCP) use checked conversion: source is capped at 1 MiB, HTML is capped at 20,000 tokenizer tokens before DOM construction, and the resulting canonical tree must pass the shared 10,000-block/64-level limits. Rejection returns an error and never substitutes a partial tree. HTML conversion helpers traverse the DOM iteratively. These limits complement shared admission and malware scanning; they do not provide process isolation or a hard CPU/memory deadline for the underlying parser. The separate HTML-to-PDF proposal renderer remains governed by its own request and renderer controls.

The Gotenberg client applies one 60-second context budget to render admission, all retry attempts, and retry backoff. A shorter caller deadline takes precedence. This bounds Hash's wait and request lifetime; cancellation alone does not prove that Chromium has stopped work remotely. Live renderer cancellation and resource isolation still require acceptance evidence.

## Isolated PDF intake worker

Production server and background worker require the bundled
`/usr/local/bin/hash-pdf-worker`; `HASH_PDF_WORKER` may select an approved absolute
executable path. Explicit development may omit it. Configured or production
failures never fall back to in-process parsing. Startup probes a real synthetic
PDF rewrite/page count under the installed policy. `/health` checks `pdf_parser`
without customer data. Success and failure are cached for ten seconds, and
concurrent health calls share one probe with a one-second budget independent of
request cancellation. Health traffic cannot start a parser for every request;
occupied slots retain the previous readiness result. Processing capacity returns
429 with Retry-After; worker failure or deadline returns 503 on REST PDF intake,
including failure of the separate page-count admission after a successful clean.

Each clean or count starts a fresh child with only bounded stdin/stdout pipes,
discarded stderr, a fixed environment without service credentials and no extra
file descriptors. No PDF temporary files or user font/config directories are
used. Linux amd64/arm64 are the supported sandbox architectures. Before stdin is
read, hard limits cap CPU at10 seconds, address space at2GiB, open descriptors
at64, and core/file output at zero. A384MiB Go GC target complements the hard
address-space limit; neither is a384MiB resident-memory guarantee. The parent
applies a15-second wall deadline, respects shorter caller deadlines, kills and
waits for canceled children and bounds pipe teardown. Two immediate process
slots provide shared clean/count admission; no unbounded queue is introduced.

The ABI-checked Linux syscall allowlist is synchronized across all Go threads.
It permits the runtime's memory, timer/poller and own-thread signal operations;
file opens, sockets, exec, ptrace and signals to another process are denied.
All `fcntl` commands are denied too: pipe ownership and asynchronous I/O can
otherwise signal a same-UID parent despite blocking kill syscalls. A disposable
parent/child regression demonstrated that gap before the restriction; the final
real parser probe and PDF intake still work with it denied.
Failed policy installation, including positive TSYNC failure, aborts the child.
Seccomp is one boundary within this design, not a universal exploit-proof
sandbox; see the [Linux kernel guidance](https://docs.kernel.org/userspace-api/seccomp_filter.html).

Native regressions exercise a real protocol child, invalid/truncated/overflow
output, credential exclusion, bounded concurrent admission, cancellation,
reaping and capacity reuse. Linux arm64 checks in a read-only, network-isolated,
non-root container exercise file/socket/exec/parent-signal denials and the hard
mapping limit on additional runtime threads. The existing BeAuto PDF also
sanitized and retained its 12-page count with Go 1.26.9. Required CI explicitly runs the Linux
resource/syscall tests without race instrumentation (its virtual shadow memory
would exceed the child's production limit); the ordinary package suite still
runs with the race detector.

The protocol-2 `compose-signing-page-v1` operation adds separately rendered body
and fixed signing-page PDFs inside the isolated worker. The application applies
the malware scanner gate to both inputs before child admission; the worker
performs active-content inspection before bounded merging. The worker
then performs measured cleanup and verifies every original body page plus the
single approved A4 suffix geometry. Combined inputs/output remain capped at
50 MiB and final pages at 500. The response binds both components, merged input,
final output and page geometry; strict parent checks refuse inconsistent proof.
Configured worker failure never falls back to parent-process composition, even
in development. Migration76 and the matching app/worker need a coordinated
release after old processing is drained. Actual release-host acceptance remains
pending.

This boundary covers the sanitizer, shared page counter and this specific
HTML signing-page composition. Signing watermark
and merge, evidence attachment/extraction and HTML parsers still have separate
in-process calls. Full exact-image Linux amd64 acceptance, parser attack corpus,
aggregate parent/child RSS and concurrency headroom, real scanner and recovery
acceptance remain required before production readiness is claimed.
