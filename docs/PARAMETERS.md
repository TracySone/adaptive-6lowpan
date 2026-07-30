# Parameter reference

## Baseline normalizer

| Key | Meaning |
| --- | --- |
| `baseline.alpha` | EWMA update rate for live network baselines |
| `baseline.epsilon` | Numerical floor for normalization variance |

## HMM

| Key pattern | Meaning |
| --- | --- |
| `hmm.emission_alpha` | Online soft-EM learning rate |
| `hmm.transition_forgetting` | Decay applied to learned transition counts |
| `hmm.transition_smoothing` | Strength of the transition prior during updates |
| `hmm.transition_prior_strength` | Initial effective transition observations |
| `hmm.min_variance` | Emission variance floor |
| `hmm.recovery_hold` | Minimum recovery-state observation count |
| `hmm.initial.STATE` | Initial state probability |
| `hmm.transition.FROM.TO` | Initial transition prior |
| `hmm.mean.STATE.METRIC` | Normalized emission mean |
| `hmm.variance.STATE.METRIC` | Normalized emission variance |

States are `good`, `normal`, `degraded`, `congested`, and `recovery`.
Metrics are `queue`, `loss`, `rtt`, `retry`, and `goodput`.

## Compression and transport policy

| Key pattern | Meaning |
| --- | --- |
| `wavelet.window_size` | Power-of-two samples per logical representation |
| `wavelet.levels` | db4 decomposition levels |
| `policy.threshold_gain.STATE` | Multiplier applied to the universal threshold |
| `policy.quant_bits.STATE` | Signed coefficient quantization width |
| `policy.block_szx.STATE` | CoAP Block1 size exponent |
| `policy.sampling_factor.STATE` | Requested fraction of the nominal sample rate |
| `coap.uri_path` | Upload resource path |
| `coap.content_format` | CoAP content-format number |

The generic pipeline reports `sampling_factor` but does not silently discard
sensor samples. The application or board-specific sensor hook owns the
sampling clock and decides how to apply the requested factor.

Parameters should preserve these policy directions:

```text
threshold_gain: GOOD <= NORMAL <= DEGRADED <= CONGESTED
quant_bits:     GOOD >= NORMAL >= DEGRADED >= CONGESTED
block_szx:      GOOD >= NORMAL >= DEGRADED >= CONGESTED
sampling:       GOOD >= NORMAL >= DEGRADED >= CONGESTED
```

`RECOVERY` should normally sit between `NORMAL` and `DEGRADED`.
