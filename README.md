# Stogas Gateway

The public OpenAI-compatible Stogas gateway and its reproducible AMD SEV-SNP IGVM build.

The repository contains:

- `core/`: the allowlisted Maxim Bifrost runtime/provider layer;
- `transports/`: the Stogas API transport, catalog routing, and gateway entrypoint;
- `stogas/`: catalog sources and the reproducible IGVM release pipeline.

The public inference listener uses port `5185`. A separate private `GET /ready` listener uses port `5186`; it is not part of the public API.

The normal `/v1/responses` and `/v1/chat/completions` routes also accept Stogas E2EE envelopes addressed to every node in a verified fleet bundle. Decryption, provider dispatch, signed response proof generation, and authenticated response streaming all remain inside the confidential guest; no plaintext-aware router or separate E2EE endpoint is required.

## Build and test

Install Bun and Go, then run:

```console
bun install --frozen-lockfile
bun run check
bun run build
```

`check` validates the compiled catalog and runs the complete transport Go test suite. Pull requests also verify dependency hydration, vulnerability data, release pins, and reproducible-build inputs.

## Confidential release

Tagged releases build `gateway.igvm` and publish GitHub artifact attestations for the IGVM and canonical launch policy. Stogas independently rebuilds the same pinned Guix derivation and accepts a release only when the IGVM hash and SNP launch measurement match exactly.

See [the reproducible-build audit](stogas/release/BUILD_AUDIT.md) for build inputs and verification details.

## License

Licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for upstream attribution.
