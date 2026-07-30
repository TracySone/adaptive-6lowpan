#include "adaptive/metrics.h"

#include <math.h>
#include <string.h>

void
adaptive_normalizer_init(adaptive_normalizer_t *normalizer,
                         double alpha, double epsilon)
{
  if(normalizer == NULL) {
    return;
  }
  memset(normalizer, 0, sizeof(*normalizer));
  normalizer->alpha = alpha;
  normalizer->epsilon = epsilon;
}

int
adaptive_normalizer_update(adaptive_normalizer_t *normalizer,
                           const adaptive_network_metrics_t *raw,
                           adaptive_network_metrics_t *normalized)
{
  unsigned metric;
  if(normalizer == NULL || raw == NULL || normalized == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  for(metric = 0; metric < ADAPTIVE_METRIC_COUNT; metric++) {
    if(!isfinite(raw->value[metric])) {
      return ADAPTIVE_ERR_RANGE;
    }
  }

  if(!normalizer->initialized) {
    for(metric = 0; metric < ADAPTIVE_METRIC_COUNT; metric++) {
      double scale = fabs(raw->value[metric]) * 0.1;
      if(scale < 1.0) {
        scale = 1.0;
      }
      normalizer->mean[metric] = raw->value[metric];
      normalizer->variance[metric] = scale * scale;
      normalized->value[metric] = 0.0;
    }
    normalizer->initialized = 1;
    return ADAPTIVE_OK;
  }

  for(metric = 0; metric < ADAPTIVE_METRIC_COUNT; metric++) {
    double old_mean = normalizer->mean[metric];
    double old_variance = normalizer->variance[metric];
    double delta = raw->value[metric] - old_mean;
    double z = delta / sqrt(old_variance + normalizer->epsilon);

    if(metric == ADAPTIVE_METRIC_GOODPUT) {
      z = -z;
    }
    if(z > 6.0) z = 6.0;
    if(z < -6.0) z = -6.0;
    normalized->value[metric] = z;

    normalizer->mean[metric] = old_mean + normalizer->alpha * delta;
    normalizer->variance[metric] =
        (1.0 - normalizer->alpha) *
        (old_variance + normalizer->alpha * delta * delta);
    if(normalizer->variance[metric] < normalizer->epsilon) {
      normalizer->variance[metric] = normalizer->epsilon;
    }
  }
  return ADAPTIVE_OK;
}
