# Gateway IGVM Build Audit

`scripts/build-release.sh <vX.Y.Z> <empty-out-dir>` builds the SEV-SNP gateway image from the tagged source. It runs on x86_64 Linux with Bash, Git, Node.js, GNU coreutils, and a running Guix daemon. `scripts/install-guix-bootstrap.sh` installs the pinned Guix release on hosts with sudo and keeps the store of a host that already runs it. Guix supplies every compiler and tool, so the host toolchain never reaches the image.

## Inputs

Everything that can change the image is in the tagged commit. Besides the files, the build uses the tag, which the gateway reports as its version, and the commit time, which init uses as the earliest valid clock time:

| Input                                                          | Purpose                                                                                                                                                                                |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `guix/channels.scm`                                            | The Guix commit that supplies every compiler and tool. Guix authenticates the channel before use.                                                                                      |
| `pins.lock.json`                                               | The Guix bootstrap binary, and each upstream source (Go, Linux, edk2, systemd, virt-firmware-rs, COCONUT-SVSM, ntpd-rs, and the verifier) as a full commit with its Guix content hash. |
| `core/go.sum`, `transports/go.sum`                             | The hash of every Go module.                                                                                                                                                           |
| `locks/*.Cargo.lock`                                           | The version and hash of every Rust crate. See `locks/README.md`.                                                                                                                       |
| `patches/`                                                     | Three upstream patches, described below.                                                                                                                                               |
| `guix/linux.config`                                            | The kernel options, applied on top of `allnoconfig`.                                                                                                                                   |
| `guix/cmdline.txt`, `guix/os-release`, `guix/ntp.toml`         | The kernel command line, the image metadata, and the NTS time sources.                                                                                                                 |
| `snp-launch-policies.json`                                     | The SEV-SNP launch policies that the release manifest embeds.                                                                                                                          |
| `guix/release.scm`, `guix/modules/stogas/release/packages.scm` | The build recipe.                                                                                                                                                                      |

## Build

`build-release.sh`:

1. Copies the tracked files and any new files that Git does not ignore to a temporary directory, and builds only from that copy. It refuses uncommitted changes unless `STOGAS_RELEASE_ALLOW_DIRTY=1` is set for a local test build.
2. Runs `scripts/verify-pins.mjs`, which checks the pins that Guix cannot check: a full Guix commit, the Go toolchain line in `transports/go.mod`, the commit of the Go verifier bindings, and full-commit GitHub Action pins.
3. Downloads and vendors the Go modules with the pinned Go in a pure Guix environment. `go mod verify` checks every module against `go.sum`, and the build stops if vendoring changes `go.mod` or `go.sum`.
4. Computes the source digests of the copy, the verifier source, and the vendored Go modules.
5. Runs `guix build -f guix/release.scm`.

A source digest identifies a directory with SHA-256 instead of Git's SHA-1. It is the SHA-256 of the canonical JSON array with one `{"mode","path","sha256"}` object per file, sorted by path: `mode` is `493` for an executable file and `420` otherwise, `path` is relative with `/` separators, and `sha256` is the file's SHA-256 in lowercase hex. `scripts/source-digest.mjs` computes it, and Stogas verifier and catalog releases use the same format.

Guix builds each package without network access, and every download must match its pinned hash. Guix substitute servers do not carry the custom packages (Go, Linux, AmdSev OVMF, the systemd EFI stub and `ukify`, the IGVM tools, ntpd-rs, and the verifier), so Guix builds them from source. Unmodified Guix packages such as GCC and Rust can come from the Guix substitute servers, which build them through the Guix full-source bootstrap. To build them locally instead, run the Guix daemon with `--no-substitutes`.

Guix runs two build farms, `ci.guix.gnu.org` and `bordeaux.guix.gnu.org`, and each builds every package from source on its own. The build takes prebuilt packages from one farm only: `bordeaux.guix.gnu.org`, or the farm that `STOGAS_GUIX_SUBSTITUTE_URL` names. GitHub's release build names `ci.guix.gnu.org`. A package that the farms built differently therefore enters GitHub's build and a default rebuild as different bytes, and a package that only one farm publishes is built from source on the other side. Matching release bytes then show that no single farm's package changed the image. Guix checks each downloaded package against the farm's signing key.

`guix/release.scm`:

1. Builds the gateway with CGO, statically linked to the verifier library, and the init program in pure Go.
2. Packs init, the gateway, `ntp-daemon`, `guix/ntp.toml`, and the Guix CA certificates into a reproducible zstd cpio initramfs.
3. Combines the kernel, the initramfs, `cmdline.txt`, and `os-release` into a unified kernel image (UKI) with the systemd EFI stub.
4. Wraps AmdSev OVMF into an SNP IGVM file with four vCPUs and adds the UKI as measured pages. The build fails if any page is unmeasured or shared, because the host could change it without changing the launch measurement.
5. Computes the launch measurement with `igvmmeasure --check-kvm` and writes `release-manifest.json`.

The build sets `SOURCE_DATE_EPOCH=1`, `LC_ALL=C`, `TZ=UTC`, and umask `022`, and sets every initramfs timestamp to 1. Go binaries build with `-trimpath` and no build ID.

## Patches

Guix applies each patch with zero fuzz.

| Patch                             | Upstream         | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| --------------------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `edk2-amdsev-kernel-only.patch`   | edk2             | The AmdSev firmware installs fixed ACPI tables for four vCPUs and 16 GiB of memory instead of the tables that QEMU supplies, so the guest runs no ACPI code from the host. It boots only the kernel in the IGVM file and halts if it does not start. It has no GRUB and no drivers for disks, USB, displays, keyboards, virtio devices, or host SMBIOS tables. It never reads PCI option ROMs, the host's boot order, or variables from disk, ignores the host's S3 resume flag, and always makes the stack non-executable. GenFw writes a zero PE timestamp, so the firmware builds reproducibly. |
| `virt-firmware-rs-qemu-kvm.patch` | virt-firmware-rs | `igvm-wrap --cpus` adds an SNP VMSA for each additional vCPU at the OVMF SEV reset vector, sets the CR0 value that QEMU/KVM requires, and places the VMSAs last in vCPU order, as QEMU/KVM measures them. Includes tests.                                                                                                                                                                                                                                                                                                                                                                          |
| `svsm-igvmmeasure-qemu-kvm.patch` | COCONUT-SVSM     | Makes `igvmmeasure` a standalone crate, accepts one VMSA per vCPU in order, and applies the CR4 and RFLAGS bits that KVM sets before it measures a VMSA. Includes tests.                                                                                                                                                                                                                                                                                                                                                                                                                           |

## Checks During the Build

- Go runs its full test suite. The patched IGVM tools, the ntpd-rs protocol and daemon libraries, and the verifier run their tests.
- The kernel build fails if the final configuration differs from any line in `guix/linux.config`.
- `igvmmeasure --check-kvm` fails if the IGVM file breaks the rules that QEMU/KVM measurement depends on.
- The release fails if `snp-launch-policies.json` is not canonical JSON, because verifiers check the embedded policies against the hash of that file.

## Outputs

| File                                                           | Use                                                       |
| -------------------------------------------------------------- | --------------------------------------------------------- |
| `gateway.igvm`, `release-manifest.json`, `LICENSE`, `NOTICE`   | Published in the GitHub release with a build attestation. |
| `gateway.init`, `gateway.kernel`, `gateway.initramfs.cpio.zst` | Local tests.                                              |
| `kernel-config.txt`                                            | Review of the full kernel configuration.                  |

The manifest records the image hash and size, the launch measurement and launch policies, the source commit and digest, the digests of the verifier source and the vendored Go modules, the Guix commit, the hashes of the kernel, firmware, EFI stub, UKI, and measurement tool, and the hashes of the inputs above.

## Reproducibility

GitHub builds each tag, and Stogas rebuilds it independently. Stogas approves a release only if both `release-manifest.json` files match byte for byte.

To check a release:

1. Check out the tag on x86_64 Linux.
2. Review `patches/` and the pins.
3. Run `stogas/release/scripts/build-release.sh <tag> <empty-dir>`.
4. Compare the new `release-manifest.json` with the published one byte for byte.
5. Check that the published `gateway.igvm` matches the hash and size in the manifest.
