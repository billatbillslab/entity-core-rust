# Entity Core Rust — make + podman build convention.
#
# Host needs ONLY `make` + `podman` (no host Rust/cargo). The multistage
# Dockerfile carries the toolchain and compiles the release `entity` binary;
# the `toolchain` stage is reused for in-container tests.
IMAGE  := entity-core-rust
CARGO_CACHE := $(HOME)/.cache/cargo-entity-core-rust

# ============================================================================
# Podman resource caps — per-container ceilings so a build/run can't take the
# host down. Tune the COMMITTED defaults for THIS project; override per-machine
# WITHOUT editing this file via env vars or an untracked caps.local.mk.
#   Precedence (highest first):  env var  >  caps.local.mk  >  defaults below
#   CAP_SWAP == CAP_MEM  =>  zero swap: OOM-killed cleanly at the cap instead of
#   thrashing the host into a freeze.
# ============================================================================
-include caps.local.mk          # untracked per-machine overrides (gitignored)

# Defaults sized for this workspace: the heaviest target (`make test` — a clean
# `cargo test --release` compiling all crates + test binaries at -j12) peaks at
# ~2.5 GiB RSS; 4g is peak + ~60% headroom (protective without false-OOMing our
# own build). Re-measure if the workspace grows: container cgroup memory.peak.
CAP_MEM           ?= 4g         # hard memory ceiling per container
CAP_SWAP          ?= $(CAP_MEM) # keep == CAP_MEM (no swap); raise only deliberately
CAP_PIDS          ?= 2048       # max procs/threads (RUN only) — stops fork bombs
CAP_CPUS          ?= 4          # CPU cores at runtime (RUN only; fractional ok)
CAP_CGROUP_PARENT ?=            # optional host slice to nest under, e.g. dev-heavy.slice

_cap_cgp := $(if $(strip $(CAP_CGROUP_PARENT)),--cgroup-parent=$(CAP_CGROUP_PARENT),)

# podman BUILD accepts --memory/--memory-swap/--cgroup-parent (NOT --cpus/--pids-limit)
PODMAN_BUILD_CAPS := --memory=$(CAP_MEM) --memory-swap=$(CAP_SWAP) $(_cap_cgp)
# podman RUN accepts the full set
PODMAN_RUN_CAPS   := --memory=$(CAP_MEM) --memory-swap=$(CAP_SWAP) \
                     --pids-limit=$(CAP_PIDS) --cpus=$(CAP_CPUS) $(_cap_cgp)

.PHONY: help build image toolchain test clippy lint fmt check clean wasm

.DEFAULT_GOAL := help

# ADR-0019 Tier-1 verbs: help build test lint fmt check clean (+ the repo's
# clippy/toolchain/wasm). lint is read-only (clippy + rustfmt --check); fmt
# writes (cargo fmt). Every recipe runs inside the pinned toolchain image.
help:
	@echo "entity-core-rust — make + podman (host needs only make + podman)"
	@echo
	@echo "  build    release build of the entity CLI in-container (alias: image)"
	@echo "  test     cargo test --release across the workspace"
	@echo "  lint     cargo clippy -D warnings + cargo fmt --check (read-only)"
	@echo "  fmt      cargo fmt (writes)"
	@echo "  check    lint + test (the green gate)"
	@echo "  clean    remove the build + toolchain images"
	@echo "  clippy   clippy only · wasm   wasm32 cross-compile check"

# Release build: compiles the `entity` CLI inside the container (Dockerfile
# builder stage) and produces the runtime image. Green on a bare box.
build:
	podman build $(PODMAN_BUILD_CAPS) -t $(IMAGE) .

# `image` alias keeps the older name working; `build` is the Tier-1 entry point.
image: build

# Toolchain-only image (rust + wasm32 target + clippy/rustfmt, no source).
toolchain:
	podman build $(PODMAN_BUILD_CAPS) --target toolchain -t $(IMAGE)-toolchain .

# In-container tests / lint against the bind-mounted source, with a persistent
# cargo registry cache so crates aren't re-fetched each run. CARGO_TARGET_DIR is
# redirected to a dedicated cache volume so cargo never writes into the repo's
# host-owned `target/` (the container runs as root; a host-uid-owned target/ from
# an earlier build would otherwise fail every write with Permission denied).
TARGET_CACHE := $(HOME)/.cache/cargo-target-entity-core-rust
define RUN_TOOLCHAIN
	mkdir -p $(CARGO_CACHE) $(TARGET_CACHE)
	podman run --rm $(PODMAN_RUN_CAPS) \
		-e CARGO_TARGET_DIR=/target \
		-v $(CURDIR):/work:Z \
		-v $(CARGO_CACHE):/usr/local/cargo/registry:Z \
		-v $(TARGET_CACHE):/target:Z \
		-w /work \
		$(IMAGE)-toolchain \
		sh -c '$(1)'
endef

test: toolchain
	$(call RUN_TOOLCHAIN,cargo test --release)

clippy: toolchain
	$(call RUN_TOOLCHAIN,cargo clippy --all-targets -- -D warnings)

# Tier-1 lint = read-only static checks: clippy + rustfmt --check (absorbs the
# fmt-check that used to live under `fmt`, per ADR-0019).
lint: toolchain
	$(call RUN_TOOLCHAIN,cargo clippy --all-targets -- -D warnings && cargo fmt --check)

# Tier-1 fmt = autoformat (writes). Was `cargo fmt --check` (read-only) before
# ADR-0019 split the write-verb from the check; the --check now lives in lint.
fmt: toolchain
	$(call RUN_TOOLCHAIN,cargo fmt)

# Tier-1 check = the green gate (lint + test).
check: lint test

# Tier-1 clean = remove the build artifacts (the runtime + toolchain images).
clean:
	-podman rmi $(IMAGE) $(IMAGE)-toolchain

# wasm32 cross-compile check. Canonical feature set per CLAUDE.md (excludes
# websocket — tokio-tungstenite doesn't compile for wasm32-unknown-unknown).
# Builds the `entity-peer` crate (core/peer), which carries these features.
# NOTE: the feature list lives in a variable so its commas are not parsed as
# $(call) argument separators (which would silently truncate it at the first comma).
WASM_FEATURES := inbox,continuation,subscription,clock,revision,query,history,compute,handlers,identity,role,registry,discovery,type-system,content
wasm: toolchain
	$(call RUN_TOOLCHAIN,cargo build --target wasm32-unknown-unknown -p entity-peer --no-default-features --features $(WASM_FEATURES))
