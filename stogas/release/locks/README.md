# Rust lockfiles

Each lockfile pins every crate that a Rust release tool uses. Guix reads these copies before it fetches the upstream source, downloads each crate by its checksum, and builds with `cargo --locked --offline`. If the upstream source has its own `Cargo.lock`, the build fails unless it is identical to the copy here.

- `virt-firmware-rs.Cargo.lock` builds `igvm-wrap` and `igvm-update`.
- `igvmmeasure.Cargo.lock` builds the SVSM `igvmmeasure` tool, which `svsm-igvmmeasure-qemu-kvm.patch` turns into a standalone crate.
- `ntpd-rs.Cargo.lock` builds `ntp-daemon`, which keeps the guest clock synchronized over NTS. It is the upstream lock with `ntpd-rs-dependency-updates.patch` applied.
- `stogas-verifier.Cargo.lock` builds the offline evidence verifier that the gateway links.
