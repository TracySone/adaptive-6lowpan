#ifndef ADAPTIVE_CODEC_H
#define ADAPTIVE_CODEC_H

#include "adaptive/config.h"
#include "adaptive/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint32_t window_id;
  adaptive_state_t state;
  size_t sample_count;
  unsigned levels;
  unsigned quant_bits;
  size_t nonzero_coefficients;
  double threshold;
  double coefficient_scale;
} adaptive_codec_metadata_t;

int adaptive_codec_encode(const float *samples, size_t sample_count,
                          uint32_t window_id, adaptive_state_t state,
                          const adaptive_config_t *config,
                          uint8_t *output, size_t output_capacity,
                          size_t *output_length,
                          adaptive_codec_metadata_t *metadata);

int adaptive_codec_decode(const uint8_t *input, size_t input_length,
                          float *samples, size_t sample_capacity,
                          size_t *sample_count,
                          adaptive_codec_metadata_t *metadata);

#ifdef __cplusplus
}
#endif

#endif
