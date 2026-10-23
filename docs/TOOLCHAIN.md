# Hash Go 1.26.10 compiler qualification

Both application and renderer module directives, Docker builders and exported
Hash CI jobs select Go 1.26.10. The immutable builder is
`golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca`.
The inspected official index identifies Alpine 3.24. Runtime Alpine, Chromium,
OpenSSL floors, application module dependencies and checksums are unchanged.

The authoring resource guard accepts only the exact reviewed default 64-bit
`go1.26.9` and `go1.26.10` model implementations, with build information present
and no nonempty `GOEXPERIMENT`. The older entry preserves model compatibility;
it does not satisfy the new module, builder or CI release requirements. Future
patches, custom/development version suffixes, 32-bit builds, missing build
information and every nonempty experiment (including `nogreenteagc`) refuse.

The installed authenticated Go 1.26.9 and 1.26.10 SDK trees each contain 11,503
regular `src` files. The source comparison captured for this change finds nine
changed paths: SDK module/vendor metadata, one module-dependency test,
`internal/buildcfg/zbootstrap.go`'s version string, and three `crypto/x509`
files. All runtime/ABI/maps/compiler, JSON, fmt, reflect, mail, strconv,
math/big, regexp, TLS and HTTP implementations used by the existing resource
and cleanup models are byte-identical. The existing source-pinned Go 1.26.9
comments in those models remain provenance for the same implementation; none
of their layout checks, cost formulas, ownership/retirement rules or input
limits changes.

The certificate change adds distrusted-SPKI filtering. The three TLS-control
models in render, ai and storage explicitly cover logical active controls,
and exclude measurement of x509 internals, cached roots/session caches and
process RSS. Their unchanged TLS message-size source supports the same stated
scope. This source comparison does not establish physical allocator, TLS
verification heap, cached certificate, process RSS or workload capacity bounds.

The renderer's HTTP/1 request-body Close classification remains tied to the
unchanged standard `net/http/transfer.go` implementation. Its separate HTTP/2
implementation and existing third-party dependencies do not change. Historical
signature-fit provenance and earlier qualification receipts remain historical
records; this compiler update does not rewrite or renew them.

`hash/.github/workflows/ci.yml` exports as the standalone repository's
`.github/workflows/ci.yml`. The old monorepo `.github/workflows/hash-ci.yml`
update is a separate legacy companion: it is not an exported bootstrap input
and its absence is not a standalone Hash failure. The script's existing check
of `../.github/workflows/hash-ci.yml` stays conditional on that file existing.
Stage's dedicated Hash source-admitted compiler cohort is a separate change.

This document records source qualification rationale, not completed release
qualification. The new runtime tests and existing ownership/admission tests,
both modules' native suites, Linux images, vulnerability scans, exact Stage
checks, runtime journeys and measured operational capacity still require
actual receipts for this compiler/source combination.
