#ifndef ADAPTIVE_CONFIG_H
#define ADAPTIVE_CONFIG_H

#include "adaptive/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  double baseline_alpha;
  double baseline_epsilon;
  double emission_alpha;
  double transition_forgetting;
  double transition_smoothing;
  double transition_prior_strength;
  double min_emission_variance;
  unsigned recovery_hold;

  double initial_probability[ADAPTIVE_STATE_COUNT];
  double transition_prior[ADAPTIVE_STATE_COUNT][ADAPTIVE_STATE_COUNT];
  double emission_mean[ADAPTIVE_STATE_COUNT][ADAPTIVE_METRIC_COUNT];
  double emission_variance[ADAPTIVE_STATE_COUNT][ADAPTIVE_METRIC_COUNT];

  size_t window_size;
  unsigned wavelet_levels;
  double threshold_gain[ADAPTIVE_STATE_COUNT];
  unsigned quant_bits[ADAPTIVE_STATE_COUNT];
  uint8_t block_szx[ADAPTIVE_STATE_COUNT];
  double sampling_factor[ADAPTIVE_STATE_COUNT];

  char uri_path[ADAPTIVE_MAX_URI_PATH + 1U];
  unsigned content_format;
} adaptive_config_t;

void adaptive_config_defaults(adaptive_config_t *config);
int adaptive_config_load(adaptive_config_t *config, const char *path,
                         char *error, size_t error_capacity);
int adaptive_config_validate(const adaptive_config_t *config,
                             char *error, size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
