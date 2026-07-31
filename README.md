# Adaptive ML-KEM / db4 / CoAP Block1 telemetry

This is a modular C11 research implementation for dynamically adapting
wavelet-compressed telemetry to a constrained IPv6/6LoWPAN link.

The runtime does **not** require fixed queue, loss or RTT thresholds. It
normalizes live network parameters, infers one of five states with an online
HMM, and selects the compression and Block1 policy associated with that state.

```text
GOOD -> NORMAL -> DEGRADED -> CONGESTED -> RECOVERY
```

## Modules

| Module | Files | Responsibility |
| --- | --- | --- |
| Dynamic five-state HMM | `hmm.c` | Gaussian emissions, online soft-EM, learned transition matrix and recovery hysteresis |
| Daubechies compression | `wavelet_db4.c`, `codec.c` | Multilevel db4 DWT, MAD noise estimate, adaptive soft threshold, quantization and sparse encoding |
| CoAP Block1 | `coap_block.c` | RFC 7252 packet encoding/parsing and RFC 7959 Block1/Size1 options |
| Security | `security*.c` | Provider API, replay control, test provider, and optional ML-KEM/HKDF/AES-GCM provider |
| End-to-end pipeline | `pipeline.c`, `receiver.c` | Compress, protect, split, transmit, verify, reassemble and reconstruct |
| Contiki-NG target | `platform/contiki-ng` | 6LoWPAN/RPL/CoAP client and server applications |

The parameter surface is in
[`config/runtime.conf`](config/runtime.conf). Numeric values there are
starting priors and policy parameters, not precise network-state thresholds.
All transition probabilities and emission distributions continue learning
while the program runs.

## Host build and tests

Requirements: a C11 compiler, `make`, and the math library.

```sh
make test
make demo
./build/adaptive_demo --config config/runtime.conf --steps 24
make check
```

`make check` additionally runs undefined-behavior and bounds sanitizers.

The default executable uses a deterministic test security provider so the
entire pipeline can run without external dependencies. The program prints
`security=test-only`; that mode is not cryptographic.

## Production ML-KEM build

The production provider uses:

- ML-KEM from liboqs;
- transcript-bound HKDF-SHA-256;
- separate client-to-server and server-to-client traffic keys;
- AES-256-GCM per Block1 payload;
- monotonically increasing sequence numbers and replay rejection.

With liboqs and OpenSSL development packages installed:

```sh
make production
make demo WITH_OQS=1
./build/adaptive_demo --oqs ML-KEM-512 --steps 24
```

The Docker environment builds a pinned liboqs release and validates both the
dependency-free and production libraries:

```sh
docker compose build host
docker compose run --rm host
```

The server ML-KEM encapsulation key must be authenticated and provisioned or
pinned by the deployment. ML-KEM establishes a shared secret; it does not by
itself authenticate the peer.

The compact record layer in this repository is not a wire-compatible
implementation of RFC 8613 OSCORE. If OSCORE interoperability is required,
keep the HMM/wavelet modules and connect `adaptive_security_session_t` to a
standards-compliant OSCORE implementation.

## Contiki-NG / 6LoWPAN

The Contiki target contains both endpoints:

```sh
docker compose build contiki
docker compose run --rm contiki
```

Or build against an existing checkout:

```sh
make -C platform/contiki-ng \
  CONTIKI=/path/to/contiki-ng TARGET=native

make -C platform/contiki-ng \
  CONTIKI=/path/to/contiki-ng TARGET=cooja
```

`adaptive-node` performs live parameter inference, db4 compression and
confirmed Block1 uploads. `adaptive-server` authenticates every block,
rejects replayed records, reassembles the compressed representation and runs
the inverse db4 transform.

The Cooja target deliberately uses the non-cryptographic test provider.
Actual MCU firmware needs a board-specific ML-KEM/AEAD port or a
cross-compiled liboqs-compatible provider. The exact port depends on the MCU,
RAM/flash budget, hardware crypto and entropy source; those cannot be selected
correctly without a target board.

Override these weak hooks for the real device:

```c
double adaptive_platform_queue_ratio(void);
double adaptive_platform_mac_retry_ratio(void);
void adaptive_platform_read_window(float *samples, size_t count,
                                   uint32_t window_id);
```

## Block sizing

The policy stores CoAP `SZX`, where payload bytes are:

```text
block_bytes = 2^(SZX + 4)
```

The security record consumes part of this payload, so the actual compressed
bytes carried by a block are:

```text
plain_capacity = block_bytes - security_overhead
```

Choose `SZX` after accounting for the board's IEEE 802.15.4 MAC security,
6LoWPAN/IPHC, UDP and CoAP headers. The default policy is conservative but is
not a substitute for measuring the actual link-layer frame budget.

## Repository layout

```text
include/adaptive/       public APIs
src/                    portable implementation
tests/                  unit and end-to-end loopback tests
config/                 runtime parameters
platform/contiki-ng/    6LoWPAN client/server
docker/                 Contiki build image
docs/                   design and parameter reference
scripts/                repeatable build/check entry points
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/PARAMETERS.md`](docs/PARAMETERS.md) for integration details.
