#ifndef ADAPTIVE_METRICS_H
#define ADAPTIVE_METRICS_H

#include "adaptive/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  double mean[ADAPTIVE_METRIC_COUNT];
  double variance[ADAPTIVE_METRIC_COUNT];
  double alpha;
  double epsilon;
  int initialized;
} adaptive_normalizer_t;

void adaptive_normalizer_init(adaptive_normalizer_t *normalizer,
                              double alpha, double epsilon);
int adaptive_normalizer_update(adaptive_normalizer_t *normalizer,
                               const adaptive_network_metrics_t *raw,
                               adaptive_network_metrics_t *normalized);

#ifdef __cplusplus
}
#endif

#endif
