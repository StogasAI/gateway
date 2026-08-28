# Stogas Gateway

The public OpenAI-compatible Stogas gateway and its reproducible AMD SEV-SNP IGVM build.

The repository contains:

- `core/`: the allowlisted Maxim Bifrost runtime/provider layer;
- `transports/`: the Stogas API transport, signed catalog loader, routing, and gateway entrypoint;
- `stogas/`: the reproducible IGVM release pipeline.

The public inference listener uses port `5185`. A separate private `GET /ready` listener uses port `5186`; it is not part of the public API.

The normal `/v1/responses` and `/v1/chat/completions` routes also accept Stogas E2EE envelopes addressed to every node in a verified fleet bundle. The E2EE media type selects encrypted request handling; any outer credential is ignored and the authenticated inner credential is authoritative. Decryption, provider dispatch, signed response proof generation, and authenticated response streaming all remain inside the confidential guest; no plaintext-aware router or separate E2EE endpoint is required.

`Stogas-Receipt: v1` requests a signed receipt. A buffered response adds one final top-level
`stogas` object. A stream emits the same compact JSON in an ignored `: stogas {...}` SSE comment
before `[DONE]`, `response.completed`, or `response.incomplete`. The signed `created_at` uses canonical UTC milliseconds.

Direct Chat Completions and Responses requests have a 60-minute lifecycle, including provider transport. Streaming clients can use that full period while they keep accepting bytes. A downstream socket write that makes no progress for one minute is closed; model silence does not start this timer. Final response delivery cannot continue more than one minute past the request deadline. Process cleanup has a separate five-minute bound after the request-drain wait, which keeps the guest shutdown hard cap at 65 minutes.

The measured guest profile has four vCPUs and 16 GiB RAM. Its current conservative starting limits are a 10 GiB Go soft limit and a 4 GiB aggregate request/stream admission budget. Request admission accounts for five times the body size, with a 1 MiB minimum; this is a capacity weight, not an allocation or a claim that five copies exist. Stream state accounts for cumulative framed bytes once, and each downstream data frame adds one exact temporary reservation until the client reads it or disconnects. Provider and downstream queues each hold one item, and each stream is capped at 64 MiB. Private diagnostics expose actual RSS, Go-managed memory, garbage collection, reservation classes, peaks, and capacity failures so these starting values can be calibrated from real load.

The MVP inference wire is text-only in both directions. Catalog modalities describe the true upstream
model and deployment capabilities; they do not grant support for those modalities through the Stogas
API. Requests containing image, audio, video, file, or PDF content are rejected, and responses never
expose binary or file artifacts. Supported hosted tools can return text, citations, and control records.

The gateway always replaces high-confidence structured PII and secrets in provider-bound text with
irreversible typed placeholders before token estimation and provider conversion. There is no request
header or runtime switch. The detector validates check digits and surrounding context where needed,
and deliberately does not guess names, street addresses, locations, IP addresses, or ordinary dates
and numbers. The internal policy compiler accepts explicit detector options for email, phone, U.S.
Social Security, payment card, IP, credentials, private keys, JSON Web Tokens, database URLs, exact
vendor tokens, bank identifiers, national identifiers, health identifiers, and bounded custom RE2
patterns. There are no presets, and no public control selects these options today.
Signed and encrypted reasoning payloads remain unchanged.

Requests must authenticate with a Stogas API key. They can also supply at most one credential for
each supported provider with
`X-Stogas-Upstream-OpenAI-API-Key`, `X-Stogas-Upstream-Anthropic-API-Key`, and
`X-Stogas-Upstream-Chutes-API-Key`. These credentials do not constrain routing. After catalog
resolution, the gateway keeps only the credential for the resolved provider. Azure requires one
stored, ARM-discovered credential assigned to the Stogas API key and does not accept pass-through
credentials. The gateway removes pass-through fields from the request, derives a stable keyed ID for
the hold and analytics, and never persists the plaintext secret.

## Build and test

Install Bun and Go, then run:

```console
bun install --frozen-lockfile
bun run check
bun run build
```

`check` validates the embedded emergency catalog and runs the complete transport Go test suite. Pull requests also verify dependency hydration, vulnerability data, release pins, and reproducible-build inputs.

## Confidential release

Tagged releases build `gateway.igvm` and a canonical manifest that binds its hash, build inputs, SNP launch policy, and measurement. GitHub attests that manifest. Stogas independently rebuilds the same pinned Guix derivation and signs the identical manifest only when the complete result matches.

See [the reproducible-build audit](stogas/release/BUILD_AUDIT.md) for build inputs and verification details.

## License

Licensed under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for upstream attribution.
