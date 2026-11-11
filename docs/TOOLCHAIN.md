# Hash Go 1.26.11 compiler qualification

Both application and renderer module directives, Docker builders and exported
Hash CI jobs select Go 1.26.11. The immutable builder is
`golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb`.
The official index identifies Alpine 3.24. The browser-fixture catalog helper
and source-built development MinIO use the same compiler. Runtime Alpine,
Chromium, OpenSSL floors, application module dependencies and checksums are
unchanged.

This update addresses [GO-2026-6859](https://pkg.go.dev/vuln/GO-2026-6859), an
HTTP/1 server crash caused by a request-body-limit/header race. The advisory
was published on 2026-11-11; [Go 1.26.11](https://go.dev/doc/devel/release#go1.26.11)
was released on 2026-11-10. The application and renderer scans must pass using
the patched compiler. No new vulnerability exception is added.

## Authoring resource model

The authoring resource guard accepts only the exact reviewed default 64-bit
`go1.26.9`, `go1.26.10` and `go1.26.11` implementations, with build information
present and no nonempty `GOEXPERIMENT`. Older entries preserve model
compatibility; they do not satisfy the module, builder or CI release
requirements. Future patches, custom/development version suffixes, 32-bit
builds, missing build information and every nonempty experiment (including
`nogreenteagc`) refuse.

The authenticated Go 1.26.10 and 1.26.11 SDK `src` trees contain 11,503 and
11,504 regular files respectively. The source comparison finds 54 changed
paths. The JSON decoder, internal map/ABI implementation, strings, fmt,
reflect, strconv, math/big, regexp and crypto/tls source used by the authoring
input and logical resource models are byte-identical. Runtime changes are
confined to Linux 32-bit implementation files, which this model refuses.
Compiler, linker, cgo, FIPS crypto and networking fixes are present; this is
not a claim that the complete compiler or standard library is unchanged.
Existing typed-layout and resource-admission tests must execute with the new
compiler. Their input limits, cost formulas and ownership rules are unchanged.

The TLS-control models in render, ai and storage cover logical active controls
and exclude x509 internals, cached roots/session caches and process RSS. Their
unchanged TLS message-size implementation supports the same stated scope.
Source comparison does not establish physical allocator, TLS verification
heap, cached certificate, process RSS or workload capacity bounds.

## HTTP cleanup model

`net/http/transfer.go` changes in Go 1.26.11: request bodies handle a nil
receiver, and early-close draining distinguishes an exact boundary from EOF.
Review of `body.Close` confirms that a non-nil body still sets `closed=true`
before every normal return following a first close, including input-drain
errors. The existing renderer classification therefore remains limited to a
server-owned HTTP/1 body after its read gate joins and its raw Close returns
normally. Socket retirement remains separate; arbitrary closers, panics and
unknown cleanup outcomes do not acquire this classification. The renderer
cleanup tests must execute with the new compiler. Its third-party HTTP/2
implementation and dependencies do not change.

## Release boundaries

`hash/.github/workflows/ci.yml` exports as the standalone repository's
`.github/workflows/ci.yml`. The root `.github/workflows/hash-ci.yml` is a
separate legacy companion; its absence is not a standalone Hash failure. The
script checks the companion conditionally when it exists. Stage's dedicated
Hash compiler admission is a separate controller change.

This document records source qualification rationale, not completed release
qualification. Both modules' tests, Linux images, vulnerability scans, exact
Stage checks, runtime journeys and operational capacity still require actual
receipts for this compiler/source combination. Historical signature-fit and
earlier qualification receipts remain historical records.
