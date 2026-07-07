# Stogas Gateway Reproducible Build Audit

This directory defines the deterministic bare-metal SEV-SNP IGVM build. The release artifact is built from the gateway source tree, a pinned Guix channel, fixed public upstream sources, committed lockfiles, small patch files, and regenerated local caches.

## Trust Boundary

- `stogas/release/guix/channels.scm` pins the Guix package universe at commit `d1e9e23fd441fce828fa74616271b00b90853cee`, authenticated from introduction commit `9edb3f66fd807b096b48283debdcddccfea34bad` and OpenPGP fingerprint `BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA`.
- `stogas/release/pins.lock.json` is the compact pin ledger for Guix bootstrap bytes, GitHub Actions pins, fixed upstream source hashes, Cargo lock hashes, Cargo vendor-cache hashes, and patch hashes.
- `transports/go.mod`, `transports/go.sum`, `core/go.mod`, and `core/go.sum` are the Go dependency ledger. `BUILD_AUDIT.md` intentionally does not duplicate every Go module hash.
- `stogas/release/locks/*.Cargo.lock` are the Rust dependency ledgers for the two Rust tool packages.
- `stogas/release/patches/*.patch` are the only Stogas source modifications applied to third-party Rust/IGVM tooling.
- `stogas/release/vendor/` is the local release cache root. It is ignored by Git and regenerated before release.
- `transports/vendor/` is ignored as a safety rail because Go can only consume `-mod=vendor` from the module root. The release build creates that path inside the Guix sandbox, not as a committed or release-owned working-tree cache.
- The Guix gateway source input is path-allowlisted to `core/` and `transports/`. Release files under `stogas/release` are passed as explicit inputs, so unrelated repository files cannot perturb `gateway.igvm`.

## Phase 1: Network Hydration

Hydration is allowed to use the network. Its job is to turn public origins and lockfiles into local caches that the offline build can consume.

Files involved:

| File | Role |
| --- | --- |
| `stogas/release/scripts/hydrate-go-vendor.sh` | Uses Go from the pinned Guix channel to run `go mod tidy`, `go mod download`, `go mod verify`, and `go mod vendor` with a writable local module cache, then records the regenerated vendor source-tree hash. |
| `stogas/release/scripts/hydrate-rust-vendor.sh` | Downloads pinned Rust tool sources, verifies SHA-256, applies audited patches, copies committed Cargo locks, and runs `cargo vendor --locked`. |
| `stogas/release/scripts/hydrate-guix-closure.sh` | Runs Go/Rust hydration, hydrates the Guix closure, roots it against GC, then dry-runs the final no-substitutes build. |
| `transports/go.mod`, `transports/go.sum`, `core/go.mod`, `core/go.sum` | Go module graph and checksum-log ledger. |
| `stogas/release/locks/*.Cargo.lock` | Rust crate graph ledgers. |
| `stogas/release/patches/*.patch` | Auditable third-party source changes. |

Pure-Source Go Hydration boundary:

1. `go mod download` downloads modules using `GOPROXY=https://proxy.golang.org,direct`.
2. `GOSUMDB=sum.golang.org` forces public checksum database verification for public modules.
3. `go mod verify` checks the downloaded module cache against the recorded module hashes.
4. `go mod vendor -o stogas/release/vendor/go-vendor` writes the verified source tree to the release-owned ignored cache.
5. A deterministic hash over the regenerated vendor source tree is written to `stogas/release/vendor/go-vendor.sha256` and `stogas/release/vendor/go-cache-manifest.json`.
6. `git diff --exit-code -- go.mod go.sum` fails if hydration changed the committed ledger.
7. `GOFLAGS=-modcacherw` keeps the ignored cache removable so clean-cache rebuilds start from public sources and lockfiles, not local leftovers.

The raw Go module cache is not release authority. It may be restored from CI cache for speed, including partial cache matches in non-release dependency checks. Hydration treats it as untrusted: `go mod verify` must pass, otherwise the Go module/build/vendor caches are purged and regenerated. The final derivation consumes the hydrated module cache only after it regenerates `transports/vendor/` offline and checks that the resulting vendor source-tree hash matches `go-vendor.sha256`.

The release build does not trust checked-in Go vendor source because no Go vendor source is checked in. The final derivation copies the hydrated Go module cache into the build sandbox, runs `go mod verify` again with the network disabled, regenerates `transports/vendor/` inside the sandbox, checks `go.mod`/`go.sum` and the vendor source-tree hash, and only then compiles with `-mod=vendor`.

Rust hydration boundary:

1. Pinned upstream archives are downloaded from the public URLs in `stogas/release/pins.lock.json`.
2. Archive SHA-256 hashes are checked before extraction.
3. Only patch files listed in `stogas/release/pins.lock.json` are applied.
4. `cargo vendor --locked` runs through `guix time-machine -C stogas/release/guix/channels.scm`.
5. Generated vendor trees are hashed and compared with `stogas/release/pins.lock.json`.
6. Each Rust Guix package checks the same vendor-tree hash again inside its isolated build.

Cache use is fail-closed: a missing cache triggers hydration; a stale or modified cache fails its hash or package-manager verification. CI may use an external cache for speed, but cache contents are never release authority.

The PR dependency workflow also runs `govulncheck ./...` from `transports/` after hydration. This is a live vulnerability-database signal for dependency review only; it is intentionally excluded from the offline release derivation.

## Phase 2: Offline Release Build

`stogas/release/scripts/build-release.sh <vX.Y.Z> <out-dir>` is the release authority. It requires a clean gateway worktree, verifies pins, runs closure hydration, then executes:

```text
guix time-machine -C stogas/release/guix/channels.scm -- build \
  -L stogas/release/guix/modules \
  --no-substitutes --substitute-urls='' --no-offload \
  --timeout=3600 --max-silent-time=900 --check \
  -f stogas/release/guix/release.scm
```

The final build has no network substitute path and no offload path. Guix grafts remain enabled so pinned-channel security grafts are applied deterministically for that Guix revision. The hydration preflight fails if the final dry run would compile compiler/toolchain/base packages locally. In normal release operation, the final release-authority derivation compiles only the gateway Go payload and assembles already hydrated Guix store inputs. Product-specific Stogas derivations, such as the kernel, OVMF, UKI tools, and IGVM tools, are fixed-source, hash-pinned Guix inputs; they may be built during hydration if no substitute is available, but they are not unpinned fallback work.

Local publish builds keep `guix build --check` enabled so Guix rebuilds the derivation and fails on nondeterministic output before Stogas countersigns. The GitHub draft-release workflow may skip that duplicate rebuild for speed because it only produces a draft artifact; `bun stogas gateway release publish` independently rebuilds the same source locally, compares the IGVM hash and launch measurement against the GitHub artifact, signs only on an exact match, and then publishes the release.

The wrapper keeps an exact output allowlist and fails if the final release directory contains any file beyond the listed artifacts. Do not add release files unless they are required for verification, reproducibility audit, or IGVM smoke/debug.

Release graph files:

| File | Role |
| --- | --- |
| `stogas/release/guix/release.scm` | Builds the raw output directory containing `gateway.igvm`, `gateway.efi`, `gateway.init`, `gateway.kernel`, `gateway.initramfs.cpio.zst`, `launch-measurement.txt`, `release-manifest.json`, `SHA256SUMS`, `pins.lock.json`, `igvmmeasure-check-kvm.txt`, `ukify-inspect.txt`, `kernel-config.txt`, and `build-inputs.sha256`; its gateway source input includes only `core/` and `transports/`. The GitHub release workflow keeps only runtime/proof essentials at top level and packs advanced evidence into `gateway-evidence.tar.zst`. |
| `stogas/release/guix/modules/stogas/release/packages.scm` | Defines Stogas-local Guix packages for the custom kernel, UKI tooling, OVMF, and IGVM measurement/update tools. |
| `stogas/release/guix/cmdline.txt` | Fixed guest kernel command line. |
| `stogas/release/guix/os-release` | Fixed UKI OS release metadata. |
| `.github/workflows/gateway-igvm-release.yml` | Builds the draft release in GitHub Actions from the same deterministic build script. |
| `.github/workflows/pr-dependencies.yml` | Verifies that Go dependencies hydrate from `go.mod`/`go.sum` without checked-in vendor code. |

Build flow by file:

| Phase | File | What runs there |
| --- | --- | --- |
| Release authority wrapper | `stogas/release/scripts/build-release.sh` | Enforces a clean gateway tree for real releases, runs pin verification, runs closure hydration, exports release metadata, invokes the final `guix time-machine ... build --check`, and copies the Guix output directory to the requested release directory. |
| Pin checks | `stogas/release/scripts/verify-pins.mjs` | Fails closed on stale source hashes, stale patch hashes, missing lockfiles, missing workflow pins, checked-in vendor caches, or audit text that no longer describes the enforced trust boundary. |
| Hydration orchestrator | `stogas/release/scripts/hydrate-guix-closure.sh` | Runs Go and Rust hydration, hydrates the Guix closure into the local store, roots it against GC, and verifies that the final no-substitutes dry run would not compile compiler/toolchain/base packages. |
| Go hydration | `stogas/release/scripts/hydrate-go-vendor.sh` | Uses pinned Guix `go@1.26` to download modules, verify them against `go.sum`/`sum.golang.org`, write the audited vendor view to ignored `stogas/release/vendor/go-vendor`, and write ignored Go cache manifests including the vendor tree hash. |
| Rust hydration | `stogas/release/scripts/hydrate-rust-vendor.sh` | Downloads pinned Rust tool sources, checks source hashes, applies audited patches, uses committed Cargo locks, vendors crates, and checks generated vendor-tree hashes. |
| Guix package graph | `stogas/release/guix/modules/stogas/release/packages.scm` | Defines the Stogas-local Guix derivations for Linux 6.18.35, `ukify`/`linuxx64.efi.stub`, AmdSev OVMF, `igvm-wrap`, `igvm-update`, and `igvmmeasure`. |
| Final Guix derivation | `stogas/release/guix/release.scm` | Defines the measured release output: copies gateway source without vendor caches, imports the hydrated Go module cache, sets offline Go mode with `GOPROXY=off`/`GOSUMDB=off`, checks `go.mod`/`go.sum` before and after vendoring, runs offline `go mod verify`, regenerates vendor inside the sandbox, checks the vendor source-tree hash, builds the Go `/init`, adds the pinned Guix `nss-certs` bundle at `/etc/ssl/certs/ca-certificates.crt`, creates the deterministic initramfs with single-threaded zstd, builds the UKI, wraps/injects the IGVM, measures it with `igvmmeasure --check-kvm gateway.igvm measure`, and writes manifest, checksum, KVM measurement, UKI inspect, kernel image, kernel config, and build-input evidence. |
| Fixed UKI inputs | `stogas/release/guix/cmdline.txt`, `stogas/release/guix/os-release` | Provide deterministic kernel command line and UKI OS metadata consumed by `release.scm`. |
| PR workflow | `.github/workflows/pr-dependencies.yml` | Verifies release pins and Go dependency hydration on dependency/source changes without relying on committed vendor code. |
| Draft release workflow | `.github/workflows/gateway-igvm-release.yml` | Runs from pushed `v*.*.*` tags, builds with read-only repository authority, packages advanced evidence into `gateway-evidence.tar.zst`, deletes stale draft assets, then publishes the clean draft release from a separate contents-write job after verifying the tag points at the checked-out commit. |

## Package And Toolchain Pins

All direct compiler/build-tool inputs come from the pinned Guix channel. The full transitive closure is determined by Guix and hydrated before release; it is not hand-copied into this file.

| Definition | Purpose | Public source / Guix root | Pin / direct inputs |
| --- | --- | --- | --- |
| `guix` bootstrap | Installs Guix on CI runners. | `https://ftp.gnu.org/gnu/guix/guix-binary-1.5.0.x86_64-linux.tar.xz` | SHA-256 `aa41025489c5061543e9c48873eaa829b900b2da75d40f9648913622f5f47817`. |
| `stogas-linux-6.18` | Minimal Linux 6.18.35 guest kernel with built-in EFI, virtio, configfs/TSM, SEV-SNP report paths, and explicit hardening options. | Guix `linux-libre@6.18.35` from the pinned Guix channel. | Kernel config hash is recorded in each manifest; required built-ins are listed in `stogas/release/pins.lock.json`. Raw packet sockets and legacy virtio PCI are explicitly disabled. |
| `stogas-systemd-uki-tools` | Builds deterministic `ukify` and `linuxx64.efi.stub`. | `https://github.com/systemd/systemd/archive/55393e3cecf6f2b274c379c39d2375a136474e8e.tar.gz` | SHA-256 `fc38bcef1012e0fb0bee661a961628e0bf0dc86ffb69c4178d060f253a983bb8`; Guix base32 `1f1vk0x2a3q6ilbw8sgvdz40vgz050b9c6k6xq5zpq0j23pvqf7w`; inputs include `gcc-toolchain`, `meson`, `ninja`, `pkg-config`, `python`, `python-jinja2`, `python-pefile`, and `python-pyelftools`. |
| `stogas-edk2-amdsev-ovmf` | Builds AMD SEV OVMF from `OvmfPkg/AmdSev/AmdSevX64.dsc`. | `https://github.com/tianocore/edk2`, commit `b03a21a63e3bd001f52c527e5a57feddb53a690b`, recursive submodules. | Guix recursive base32 `0mpfs9vd9fy6103k83jwd58xcy1j908m6b27bclxmbrc9vim9l8n`; inherits `ovmf-x86-64` inputs and adds `dosfstools`, `grub-efi`, and `mtools`. The AmdSev target currently expects GRUB helper script tooling during the OVMF build, but the final IGVM authorizes the UKI by injected hash; simplifying this target remains an audit focus. |
| `stogas-virt-firmware-rs-tools` | Builds `igvm-wrap` and `igvm-update`. | `https://gitlab.com/kraxel/virt-firmware-rs/-/archive/e01dffc463934547a42506df656becd9061926f7/virt-firmware-rs-e01dffc463934547a42506df656becd9061926f7.tar.gz` | SHA-256 `f0d242cb0952724f3147ab5c51f6135ef1fdc4b6b634f92acd4f68240f86ea25`; Guix base32 `09gahq7j8s2grlmgjd5nnv2gvway2gv52p5b8wqlywjj175l5lph`; Cargo vendor hash `f255fd2e4b39db99e7c8127d4bcac6b0f06565aa2bd2f1c59669cee8280dd3a5`; inputs include `rust`, `bash-minimal`, `coreutils`, and `findutils`. |
| `stogas-igvmmeasure` | Builds SVSM `igvmmeasure` for launch measurement calculation. | `https://github.com/coconut-svsm/svsm/archive/8850f7bd766e0b592d01efb67c615a9d8f171269.tar.gz` | SHA-256 `301e0f90615c1d01cf6ca21c0fc3aee477af649b07b82b7a1be402c2d79b960e`; Guix base32 `03lnkgbw40p43dx2pf07kdjayxz4mv1hy752dk7h27awc680y7ih`; Cargo vendor hash `a8e661722a66994ceee5fb73be70acbefcfec0524e81e1c37dc3612527c8618d`; inputs include `rust`, `bash-minimal`, `coreutils`, and `findutils`. |
| `stogas-gateway-igvm-release` | Assembles the final IGVM release directory. | Local gateway repository source at the release tag. | Direct inputs include `bash-minimal`, `coreutils`, `cpio`, `findutils`, `grep`, `go@1.26`, `gzip`, `nss-certs`, `sed`, `tar`, `zstd`, and the Stogas-built kernel/UKI/OVMF/IGVM tools. |

## Patches

| Patch | Applies to | Files | Why |
| --- | --- | --- | --- |
| `stogas/release/patches/virt-firmware-rs-kvm-vmsa-last.patch` | `virt-firmware-rs` commit `e01dffc463934547a42506df656becd9061926f7` | `igvm-tools/src/builder.rs` | Sorts SNP VMSA directives after regular memory directives so generated IGVM files satisfy `igvmmeasure --check-kvm` for the bare-metal QEMU/KVM launch path. |
| `stogas/release/patches/svsm-igvmmeasure-standalone-cargo.patch` | SVSM commit `8850f7bd766e0b592d01efb67c615a9d8f171269` | `tools/igvmmeasure/Cargo.toml` | Detaches `igvmmeasure` from the larger SVSM workspace by replacing workspace dependency references with explicit crate versions. Source files remain upstream SVSM files. |

The final IGVM wraps AmdSev OVMF with `igvm-wrap --snp --real16`. Real-mode firmware entry is required for the generated SEV-SNP platform to include the SNP VMSA reset-vector context that QEMU consumes during `igvm-cfg` launch.

Patch file hashes are pinned in `stogas/release/pins.lock.json` and verified by `stogas/release/scripts/verify-pins.mjs`.
