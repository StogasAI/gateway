# Stogas Gateway

The OpenAI-compatible gateway that runs inside Stogas confidential VMs, with the reproducible build of its AMD SEV-SNP image.

[Website](https://stogas.ai) · [Documentation](https://stogas.ai/docs) · [Build audit](stogas/release/BUILD_AUDIT.md) · [Security](SECURITY.md)

## Repository

| Path              | Contents                                                                                                                                                         |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `core/`           | The provider layer of [Bifrost](https://github.com/maximhq/bifrost), with our changes committed in place. `stogas/upstream-sync.lock` names the upstream commit. |
| `transports/`     | The Stogas API, the signed catalog loader, routing, policies, and the entrypoint                                                                                 |
| `stogas/pdftext/` | The program that reads the text of one PDF. The gateway starts it for each file, and it gives up every system call but input, output and memory before it reads. |
| `stogas/release/` | The reproducible image build                                                                                                                                     |

## Build and test

Install Bun, Go, Rust through rustup, and jq. Then run:

```console
bun install --frozen-lockfile
bun run check
bun run build
```

`check` runs the Go tests. Both scripts first build the verifier library at the commit that `stogas/release/pins.lock.json` names, and the PDF reader.

## Rebuild a release

```console
stogas/release/scripts/build-release.sh v<version> <empty-directory>
```

The build needs x86_64 Linux and Guix. It writes `gateway.igvm` and a manifest that holds the image's hash and its SEV-SNP launch measurement, and the same tag gives the same bytes on every host. Each release also has a CycloneDX bill of materials, `sbom.cdx.json`. GitHub attests the manifest, the image, and the bill of materials of each release. GitLab.com's hosted runners build the tag again and attest the manifest and the image in `gitlab-attestation.jsonl`. Stogas signs a manifest only when both builds give the same bytes.

The [build audit](stogas/release/BUILD_AUDIT.md) lists every input and step.

## License

[Apache-2.0](LICENSE). [NOTICE](NOTICE) credits Bifrost and the other upstream work.
