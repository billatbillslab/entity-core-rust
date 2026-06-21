# Command-line tools

This repo ships two operator-facing tool surfaces: the **`entity`** binary
(the peer CLI) and the **`make`** build targets. Both run with only `make` +
`podman` on the host — no native Rust toolchain required.

For the authoritative, always-current flag reference, run any command with
`--help`. This page is the orientation map.

---

## `make` targets (build / test / lint)

`make` is the build entrypoint (make + podman only; see the `Makefile` and
`Dockerfile`). Each target runs inside the pinned toolchain container.

| Target | What it does |
|---|---|
| `make build` | Compile the release `entity` binary and produce the runtime image. |
| `make test` | `cargo test --release` across the workspace, in the toolchain container. |
| `make lint` | `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check` (read-only static checks). |
| `make fmt` | `cargo fmt` — autoformat (writes). |
| `make check` | `lint` + `test` (the green gate). |
| `make clean` | Remove the build + toolchain images. |
| `make clippy` | `cargo clippy --all-targets -- -D warnings`. |
| `make wasm` | `wasm32-unknown-unknown` cross-compile check (canonical feature set). |
| `make toolchain` | Build the toolchain-only image (no source) used by the above. |

A fresh clone with no siblings present must pass `make build` and `make test`
— that is the standalone-build contract.

`compose.yaml` is an optional developer convenience (live-mounted iteration,
interactive shell) — **not** the build door.

---

## `entity` — the peer CLI

The `entity` binary manages identities and runs peers. Top-level commands:

```
entity identity <create|list|show> ...
entity peer <init|start|list|show|issue-binding> ...
```

### `entity identity`

Manage Ed25519/Ed448 identity keypairs (stored in the local keystore).

- `entity identity create [name] [--key-type ed25519|ed448]` — mint a keypair
  (default name `default`, default `ed25519`; v7.67 adds `ed448`).
- `entity identity list` — list keypairs.
- `entity identity show [name]` — show identity details (peer ID, key type).

### `entity peer`

Manage and run peers. Global flags before the subcommand: `--verbose`,
`--trace-entities`, `--profile` (span timing).

- `entity peer init <name> [--admin <id-name>] [--admin-key <peer-id>]
  [--key-type ed25519|ed448]` — initialize a peer; the minted key is saved with
  an algorithm-tagged PEM header that `peer start` auto-detects.
- `entity peer start <name> [flags]` — start a peer. Key flags:
  - `--listen <addr>` — TCP listen address.
  - `--ws-listen <addr>` — WebSocket listen address.
  - `--http-listen <addr>` / `--http-path <path>` — HTTP-live transport
    (EXTENSION-NETWORK §6.5.2c; default path `/entity`).
  - `--http-poll-addr <addr>` | `--http-poll-mount-on-live` — HTTP-poll
    serving transport (mutually exclusive postures).
  - `--serve-namespace <system/content/ns>` | `--serve-closure-root` — what the
    poll listener serves (a content namespace vs the signed-root closure).
  - `--storage memory|sqlite` — storage backend (overrides `config.toml`).
  - `--hash-type sha256|sha384` — home content-hash format authored + preferred
    in hello negotiation (V7 §4.5/§8.2; default `sha256`, the conformance floor).
  - `--files name:/fs/path:tree/prefix/` — expose a directory via local/files.
  - `--history <pattern[:max_depth]>` — enable history recording.
  - `--publish-root` / `--publish-descriptors` — sign a published-root over the
    served namespace / publish content descriptors on `--files` roots.
  - `--debug-grants`, `--validate` — debug/conformance only; **not** for
    production (`--validate` exposes §7a test handlers).
- `entity peer list` / `entity peer show <name>` — inspect configured peers.
- `entity peer issue-binding <registry-name> <bind-name> <target-peer-id>
  [--transport tcp://host:port]... [--ttl-ms <ms>] [--storage sqlite]
  [--hash-type ...]` — operator tool to sign and publish a peer-issued registry
  binding (`name → target_peer_id`) for serving as a coral-reef.

Cross-impl note: the HTTP / hash-type / files flags mirror the Go reference
peer's equivalents (`-http-addr`, `--hash-type`, `--files`, …) for interop.

---

## Conformance & interop tools

These are developer/CI tools that prove cross-implementation parity, not
day-to-day peer operation.

### `wire-conformance` — ECF encoding conformance harness

`cmd/wire-conformance`. Validates that this implementation's deterministic-CBOR
(ECF) wire encoding matches the Go and Python references byte-for-byte.

- `wire-conformance emit-canonical --input <corpus.cbor> --out <emission.cbor>
  [--impl-version <v>]` — read a conformance-vector corpus
  (`conformance-vectors-v{N}.cbor`) and write a canonical-ECF emission file. The
  emission is diffed against the other implementations' emissions for the same
  corpus; zero divergence is the pass condition. (The harness also covers
  decode-reject vectors — bytes a conforming decoder must reject.)

### `fetch-published-fixture` — published-root read interop harness

`core/peer/src/bin/fetch-published-fixture.rs`. The Rust side of the cohort's
publish-fetch contract: drives the Tier-1 published-root read flow against an
**external** HTTP-poll origin (e.g. the Go publisher) and asserts byte-equality
against the pinned contract hashes. Internal/CI use.
