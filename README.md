# Entity Core Rust

Rust implementation of Entity Core Protocol v7.9. Clean rewrite
replacing `entity-core-rs`.

It is one of three independent reference implementations (alongside the
Go oracle and the Python reference) and is the upstream the entity-browser and
Godot apps depend on. See `docs/ARCHITECTURE.md` for the crate DAG and
design decisions, and `docs/CLI.md` for the command-line tools. The
normative protocol spec lives in the `entity-core-architecture` repo.

---

## What's in here

A standalone Cargo workspace: a strict crate DAG (no cycles) plus protocol
extensions, language bindings, and command-line tools.

**Core (the protocol itself)** — `ecf` (deterministic CBOR) → `hash` →
`entity` → `crypto` (Ed25519/Ed448 identity) · `store` · `types` ·
`capability` (4-D grants) · `wire` (framing) · `handler` (dispatch) ·
`protocol` (EXECUTE + connect handshake) · `tree` (`system/tree` get/put) ·
`peer` (the assembled peer) · `entity-core` (facade re-export crate).

**Extensions** (each layers on the core traits, opt-in via cargo features):

- Messaging & flow: `inbox`, `continuation`, `subscription`, `clock`, `relay`
  (opaque-envelope transport), `route` (routing table).
- Data & versioning: `revision` (version control + merge), `history` (audit
  trail), `query` (find/count, optional SQLite index), `content`,
  `local-files`, `storage-substitute-{sources,http}`.
- Identity & trust: `attestation` (signed claims), `quorum` (K-of-N consensus),
  `role` (grant bundles), `identity`, `registry` (name→peer), `discovery`
  (mDNS find-and-prompt), `capability` (request/delegate/revoke handler).
- Compute & ops: `compute` (pure-eval engine), `handler-ops`
  (register/unregister handlers), `type-system` (validation), `encryption`
  (group/self AEAD modes), `conformance`, `durability` (exploratory).

**Bindings** — `ffi` (C cdylib + header), `godot` (GDExtension), `sdk`
(higher-level peer API), `shell` (cross-frontend verb dispatcher), and the
`wasm-worker-*` stack (browser peer-in-a-Web-Worker).

**Tools** — see [Tools](#tools) below and `docs/CLI.md`.

---

## Repository layout (sibling references)

This workspace is **self-contained** — all path dependencies are
internal. The following sibling repos are referenced for
documentation, interop testing, and historical context, but are not
required to build:

```
entity-systems/
├── entity-core-rust/             ← this repo
├── entity-core-architecture/     ← protocol spec (recommended for contributors)
├── entity-core-go/               ← reference implementation (interop testing)
└── entity-core-rs/               ← old implementation (reference only)
```

Other repos in the ecosystem (e.g. `entity-browser-rust`,
`entity-core-godot`) consume this workspace's crates via a Cargo
**git dependency** pinned to a release tag
(`git = "https://github.com/EntityChurch/entity-core-rust", tag = "v0.8.0"`),
so a lone clone builds standalone. Sibling-folder development is kept as a
**local, gitignored** `.cargo/config.toml` `paths = [...]` override — never a
committed `[patch]`/path dependency.

---

## Prerequisites

Only **`make`** and **`podman`** on the host. Nothing else — no Rust,
`rustup`, `mise`, or system C toolchain. The Rust version is pinned in
`rust-toolchain.toml` and baked into the image via `Dockerfile`.

---

## Build & run

`make` is the entrypoint — every release-gate workflow runs through it
(make + podman only). The multistage `Dockerfile` carries the toolchain;
in-container tasks bind-mount the source with a persistent cargo cache.

```bash
make build      # build the release runtime image (entity binary)
make test       # cargo test --release in the toolchain container
make lint       # cargo clippy -D warnings + cargo fmt --check (read-only)
make fmt        # cargo fmt (writes — autoformat)
make check      # lint + test (the green gate)
make clean      # remove the build + toolchain images
make clippy     # cargo clippy --all-targets -- -D warnings
make wasm       # wasm32-unknown-unknown cross-compile check
```

A fresh clone with no siblings present must pass `make build` and
`make test` — that's the standalone-build contract.

For live-mounted iteration (interactive shell, fast incremental
rebuilds), `compose.yaml` is an optional developer convenience — **not**
the build door:

```bash
podman compose run --rm shell        # interactive bash with full toolchain
podman compose run --rm peer --help  # run the peer binary
```

### WASM build check

`make wasm` mirrors the CI command — run it after any change to
async/await, time, networking, or task spawning. See
`docs/ARCHITECTURE-WASM-AND-TRANSPORT.md` for the full
WASM-compatibility and transport-abstraction story.

### Targets & artifacts

`make build` compiles **only** the `entity` peer binary (crate `entity-cli`)
and packs it into the runtime image. The language bindings are separate
artifacts, built on demand by their consumers:

| Artifact | Build | Output | Target |
|---|---|---|---|
| `entity` peer + image | `make build` | runtime image with `entity` at `/usr/local/bin/entity` | host arch |
| C FFI library | `cargo build -p entity-core-ffi --release` | `libentity_core_ffi.{so,dylib,dll}` + generated `bindings/ffi/include/entity_core_ffi.h` (cbindgen) | host arch |
| Godot GDExtension | `cargo build -p entity-core-godot --release` | `libentity_core_godot.{so,dylib,dll}` | host arch |
| WASM worker peer | `cargo build --target wasm32-unknown-unknown -p entity-wasm-worker-host …` | `.wasm` | wasm32 |

**Processor architecture:** builds are **host-native** — the `rust` / `debian`
base images are multi-arch manifests, so podman pulls the host's architecture
(x86_64, arm64, …) and the image matches the build host. There is no
cross-platform image orchestration; to produce a different arch, build on that
arch (or run podman with `--platform` under emulation). The only non-host build
target is **`wasm32-unknown-unknown`** (toolchain target pinned in
`rust-toolchain.toml`; the worker peer's wasm stack-size is set in
`.cargo/config.toml`).

**Crypto agility** is a runtime/connection property, not a build flag: a single
binary supports Ed25519 + Ed448 identities and SHA-256 + SHA-384 content hashes,
selected per peer/connection via `entity` CLI flags (`--key-type`,
`--hash-type`) and negotiated in the hello handshake. See `docs/CLI.md`.

---

## Tools

This repo builds these command-line tools (full flag reference: `--help`
and `docs/CLI.md`):

- **`entity`** (crate `entity-cli`, `cmd/entity-peer`) — the peer CLI. Manage
  identity keypairs (`entity identity …`) and run/inspect peers
  (`entity peer init|start|show|…`), including the transports, storage backend,
  hash format, served namespaces, and the `issue-binding` registry operator
  tool. This is the binary shipped in the release image.
- **`wire-conformance`** (`cmd/wire-conformance`) — ECF wire-format conformance
  harness. `wire-conformance emit-canonical` reads a conformance-vector corpus
  and produces a canonical-ECF emission file, which is diffed against the Go and
  Python implementations to prove byte-for-byte encoding parity.
- **`fetch-published-fixture`** (`core/peer/src/bin`) — cross-impl interop test
  harness. Drives the published-root read flow against an external HTTP-poll
  origin (a cohort publisher) and asserts byte-equality against pinned hashes.
  Internal/CI use — the Rust side of the cohort's publish-fetch contract.

The `make` targets (`build`/`test`/`clippy`/`fmt`/`wasm`) are documented under
[Build & run](#build--run) and in `docs/CLI.md`.

---

## Notes

- `Cargo.lock` is gitignored (resolved fresh in the build container);
  exact external versions are pinned in `[workspace.dependencies]` in the
  root `Cargo.toml`.
- All workspace dependencies are declared in the root `Cargo.toml`
  under `[workspace.dependencies]`. Member crates pick them up with
  `dep.workspace = true`. Add new external deps to the root, not to
  individual members.
- The crate DAG is strict (see `CLAUDE.md`). A crate may only depend
  on crates above it in the list — no cycles.

---

## Supporting the project

This project is developed in the open. If it's useful to you, the best support is
to use it, report issues, and contribute back — see
[CONTRIBUTING.md](CONTRIBUTING.md).

To support the work directly, see the project's funding page.
