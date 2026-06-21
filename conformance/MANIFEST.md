# Vendored ECF Conformance Vectors

This directory holds the canonical ECF conformance corpus vendored from
the architecture repo. The Rust `wire-conformance` harness loads
`vectors-v{N}.cbor` from here.

The `.cbor` is the build-fixture output produced by Go's
`cmd/internal/wire-conformance build-fixture` against the `.diag` source
at the arch-repo canonical path:
`entity-core-architecture/.../core-protocol-domain/specs/test-vectors/ecf-conformance/conformance-vectors-v{N}.diag`.

Per the ECF conformance cross-team assignment §2.2, this
impl does NOT regenerate `.cbor` from `.diag` — that would defeat the
cross-bless of the loaded fixture.

## v1 (starter — pre-cross-bless)

- File: `vectors-v1.cbor`
- SHA-256: `9d96f00754238928557b8c3462b9078ca31cdf0d0ff8d6065c0b9a61e783a4bd`
- Source: `entity-core-go/test-vectors/v1/conformance-vectors-v1.cbor`
  (Go's `build-fixture` output, vendored)
- Spec: `ENTITY-CBOR-ENCODING.md` v1.5, Appendix E
- Vector count: 69

When arch republishes the corpus at the canonical arch-repo path, re-vendor
from there and update this manifest.
