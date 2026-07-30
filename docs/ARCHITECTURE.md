# Architecture

## Runtime path

```text
network counters
  -> EWMA normalization
  -> online five-state HMM
  -> state policy
       |-- sampling factor
       |-- db4 threshold multiplier
       |-- quantization bits
       `-- CoAP Block1 SZX
  -> db4 DWT over a complete sensor window
  -> detail soft-thresholding and sparse coefficient encoding
  -> per-block authenticated security record
  -> CoAP CON POST + Block1 + Size1
  -> UDP / IPv6 / 6LoWPAN / IEEE 802.15.4
```

The receiver performs the inverse sequence. DWT is always performed before
Block1 segmentation, so CoAP boundaries do not create wavelet boundary
artifacts.

## Dynamic state inference

The input vector contains:

```text
queue occupancy
loss / CoAP timeout EWMA
RTT EWMA
MAC retry estimate
goodput EWMA
```

Goodput is direction-inverted during normalization because falling goodput is
a congestion signal. The first observation initializes a data-derived scale.
Subsequent observations are normalized against the previous EWMA baseline.

For each state, the HMM stores a diagonal Gaussian emission distribution.
Prediction and correction are:

```text
predicted[j] = sum_i posterior_previous[i] * transition[i][j]
posterior[j] proportional to emission(x | j) * predicted[j]
```

Emission parameters use online soft-EM. Transition counts use exponential
forgetting plus a configurable prior. `RECOVERY` is history-dependent: it can
only be entered while leaving `CONGESTED`, and remains active for
`recovery_hold` observations unless congestion returns.

## Wavelet representation

The codec uses periodic extension, which is exactly invertible for the
power-of-two streaming windows accepted by the configuration validator.
For each window:

1. Run multilevel db4 analysis.
2. Estimate noise from the finest detail band using MAD.
3. Compute `threshold_gain[state] * sigma * sqrt(2 log N)`.
4. Soft-threshold detail coefficients; preserve approximation coefficients.
5. Select a scale from the largest remaining coefficient.
6. Quantize to the state's configured signed bit width.
7. Encode nonzero `(index, int16 value)` pairs.

The binary header records the window id, state, sample count, levels,
quantization width, scale, threshold, nonzero count and a CRC32 over the sparse
pair stream. The security provider supplies cryptographic integrity; CRC32
exists for early format/corruption diagnostics.

## CoAP block representation

Every non-final protected payload has exactly the selected Block1 size. The
security overhead is reserved first, and the remainder carries compressed
representation bytes. All blocks in one window use a four-byte token derived
from `window_id`.

The compact AAD binds:

- CoAP type and method;
- Block1 number, More flag and SZX;
- token/window identity;
- content format.

Host parsing rejects malformed options, missing Block1, illegal SZX values,
out-of-order blocks, token changes and capacity overflows.

## Security boundary

`adaptive_security_session_t` is the only interface required by the pipeline.
The repository supplies two implementations:

1. `security_test.c`: deterministic framing/replay test provider. Never use it
   for real data.
2. `security_oqs.c`: ML-KEM key establishment followed by HKDF-SHA-256 and
   directional AES-256-GCM record keys.

Production deployments must authenticate or pin the ML-KEM server key and
must use a cryptographic entropy source. Congestion adaptation never changes
the KEM parameter set, disables integrity, shortens keys or reuses nonces.

## Memory bounds

All codec, CoAP and pipeline buffers have compile-time maxima in
`include/adaptive/types.h`. The default window is smaller than the maximum.
The host implementation uses bounded stack buffers; the Contiki applications
use static buffers to avoid protothread lifetime and small-stack problems.
