#ifndef ADAPTIVE_HMM_H
#define ADAPTIVE_HMM_H

#include "adaptive/config.h"
#include "adaptive/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  double probability[ADAPTIVE_STATE_COUNT];
  double transition[ADAPTIVE_STATE_COUNT][ADAPTIVE_STATE_COUNT];
  double transition_count[ADAPTIVE_STATE_COUNT][ADAPTIVE_STATE_COUNT];
  double transition_prior[ADAPTIVE_STATE_COUNT][ADAPTIVE_STATE_COUNT];
  double emission_mean[ADAPTIVE_STATE_COUNT][ADAPTIVE_METRIC_COUNT];
  double emission_variance[ADAPTIVE_STATE_COUNT][ADAPTIVE_METRIC_COUNT];
  double emission_alpha;
  double transition_forgetting;
  double transition_smoothing;
  double min_variance;
  adaptive_state_t state;
  adaptive_state_t previous_state;
  unsigned recovery_hold;
  unsigned recovery_remaining;
  uint64_t observations;
} adaptive_hmm_t;

int adaptive_hmm_init(adaptive_hmm_t *hmm,
                      const adaptive_config_t *config);
int adaptive_hmm_step(adaptive_hmm_t *hmm,
                      const adaptive_network_metrics_t *normalized,
                      adaptive_state_t *state,
                      double probability[ADAPTIVE_STATE_COUNT]);

#ifdef __cplusplus
}
#endif

#endif
