# Rust lockfiles

These lockfiles are release inputs, not vendored source.

- `virt-firmware-rs.Cargo.lock` pins the crates used to build `igvm-wrap` and `igvm-update`.
- `igvmmeasure.Cargo.lock` pins the crates used to build the standalone SVSM `igvmmeasure` tool after applying `svsm-igvmmeasure-standalone-cargo.patch`.

`scripts/hydrate-rust-vendor.sh` uses these files to rebuild the ignored `vendor/` cache from public upstream sources.
