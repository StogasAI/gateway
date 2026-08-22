# Stogas Gateway Build Audit

This directory builds the SEV-SNP gateway IGVM from reviewed source and fixed public inputs. The supported build host is x86_64 Linux with Bash, Git, Node.js, curl, GNU core and find utilities, tar, patch, and a working Guix daemon. `scripts/install-guix-bootstrap.sh` installs the fixed Guix bootstrap on systems with sudo and standard Linux account tools. No host compiler or host package set is trusted.

## Authority

The build authority is:

- the gateway Git tag and tree;
- `guix/channels.scm`, which fixes and authenticates the Guix revision;
- `pins.lock.json`, which records direct source, cache, lock, action, and patch hashes;
- `core/go.mod`, `core/go.sum`, `transports/go.mod`, and `transports/go.sum`;
- `locks/*.Cargo.lock`;
- `patches/*.patch`;
- `snp-launch-policy.json`;
- `guix/release.scm` and `guix/modules/stogas/release/packages.scm`.

`vendor/` and `transports/vendor/` are ignored caches. They are never source authority.

The final gateway source input contains only `core/` and `transports/`. Each release file is passed to Guix as an explicit input. Unrelated repository files cannot change the IGVM.

## Build Flow

### 1. Verify pins

`scripts/verify-pins.mjs` checks:

- lock, source, Cargo lock, cache-tree, and patch hashes;
- exact patch-directory contents and safe patch paths;
- the authenticated Guix channel;
- fixed GitHub Action commits;
- the launch policy;
- the offline build and cache boundaries.

### 2. Hydrate inputs

After Guix is installed, hydration is the only networked build phase. Each downloader checks the fixed hash before an input is used; Guix also checks every source in its package graph.

#### Pure-Source Go Hydration

`scripts/hydrate-go-vendor.sh` uses the pinned Guix Go package. It runs `go mod tidy`, `go mod download`, `go mod verify`, and `go mod vendor`. Public modules use `sum.golang.org`. Hydration fails if a committed `go.mod` or `go.sum` changes.

The verified source view is written to `stogas/release/vendor/go-vendor`. The final build copies it to `transports/vendor/`, checks its complete tree hash, and builds with `GOPROXY=off`, `GOSUMDB=off`, and `-mod=vendor`. `GOFLAGS=-modcacherw` keeps the ignored download cache removable.

#### Rust Hydration

`scripts/hydrate-rust-vendor.sh` downloads each fixed upstream archive, checks SHA-256, reads the ordered patch list from `pins.lock.json`, applies it with zero fuzz, installs the committed Cargo lock, and runs `cargo vendor --locked` with pinned Guix Rust.

Go verifies restored module downloads, regenerates the vendor tree, and records its complete tree hash. Restored Rust vendor trees are accepted only when their fixed tree hashes match. The shared tree hash includes paths, file bytes, entry type, executable state, and empty directories. Links and special files fail.

#### Guix Closure

`scripts/hydrate-guix-closure.sh` builds and roots only the final package's development inputs. It then dry-runs the offline release and permits only the final release derivation to remain unbuilt.

### 3. Build once, offline

`scripts/build-release.sh <vX.Y.Z> <out-dir>`:

1. Requires a clean gateway tree.
2. Resolves the authenticated Guix time-machine profile once.
3. Takes one immutable snapshot of the allowed gateway source.
4. Hydrates and verifies all inputs.
5. Runs one final Guix build with:

   ```text
   --no-substitutes --substitute-urls='' --no-offload
   ```

6. Copies only the allowed output files and verifies `SHA256SUMS`.

The final Guix derivation fixes `SOURCE_DATE_EPOCH=1`, `LC_ALL=C`, `TZ=UTC`, and umask `022`. It builds static Go binaries with a fixed empty build ID and `-trimpath`, normalizes the root file-system timestamps, writes deterministic cpio and zstd output, builds the UKI, creates four ordered SNP VMSAs, injects the UKI, and measures the result with `igvmmeasure --check-kvm`.

There is no same-store `guix build --check` pass. GitHub builds the tag once. Stogas independently builds the same tag once before publication and requires the complete release manifest to match. The manifest binds the IGVM, launch policy, source identity, tools, inputs, and launch measurement. These two independent builds are the reproducibility check.

## Custom Patches

Each patched upstream project has one self-contained patch. `pins.lock.json` is the ordered patch ledger used by hydration; the Guix package graph applies the same files.

| Patch                                     | Upstream                                                             | Purpose                                                                                                                                                                           |
| ----------------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `patches/virt-firmware-rs-qemu-kvm.patch` | `virt-firmware-rs` commit `e01dffc463934547a42506df656becd9061926f7` | Adds four-CPU SNP VMSAs, uses the OVMF AP reset vector, sets the required real-mode CR0 value, and orders VMSAs for QEMU/KVM measurement. Includes focused register tests.        |
| `patches/svsm-igvmmeasure-qemu-kvm.patch` | SVSM commit `8850f7bd766e0b592d01efb67c615a9d8f171269`               | Makes `igvmmeasure` a standalone locked crate and checks and normalizes QEMU/KVM multi-VMSA measurement behavior. Includes focused ordering, validation, and normalization tests. |

Both patched Rust packages run their tests inside their Guix builds.

## Outputs

The local build contains:

- `gateway.igvm`;
- `gateway-launch-policy.json`;
- `release-manifest.json`;
- `SHA256SUMS`;
- `LICENSE` and `NOTICE`;
- `gateway.init`, `gateway.kernel`, and `gateway.initramfs.cpio.zst` for local smoke tests;
- `kernel-config.txt` for direct audit.

The GitHub release contains `LICENSE`, `NOTICE`, `gateway.igvm`, `gateway-launch-policy.json`, `release-manifest.json`, `SHA256SUMS`, and its build-identity record. The smoke files and full kernel configuration remain in the local counterbuild. Pins, locks, patches, and recipes remain in the tagged source, so the public release does not duplicate them.

The release manifest records the Git identity, direct input hashes, compiler and tool identity, public artifact hashes and sizes, SNP policy, four-vCPU count, and launch measurement. The exact Guix closure is recoverable from the fixed channel and derivation; a host-specific store-path listing is not a release artifact.

## Audit Procedure

1. Check the tag and Git tree.
2. Run `node stogas/release/scripts/verify-pins.mjs`.
3. Review both files under `patches/`.
4. Run `stogas/release/scripts/build-release.sh <tag> <allowed-output-dir>` on x86_64 Linux.
5. Check `SHA256SUMS`, `release-manifest.json`, and `gateway-launch-policy.json`.
6. Compare `release-manifest.json` byte for byte with the other independent build.
