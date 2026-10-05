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
Counting pages still requires parsing untrusted PDF bytes. Parsing and rewriting run
inside the application process; these controls do not establish a complete
malware scan or protection against every parser vulnerability.

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
This limits logical output size and buffer growth, not the parser's internal
object graph, decompressed streams, aggregate resident memory or CPU time.
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
