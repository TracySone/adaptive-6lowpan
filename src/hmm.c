#include "adaptive/hmm.h"

#include <float.h>
#include <math.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static void
normalize(double *values, size_t count)
{
  double total = 0.0;
  size_t i;
  for(i = 0; i < count; i++) {
    total += values[i];
  }
  if(total <= DBL_MIN) {
    double uniform = 1.0 / (double)count;
    for(i = 0; i < count; i++) {
      values[i] = uniform;
    }
    return;
  }
  for(i = 0; i < count; i++) {
    values[i] /= total;
  }
}

static double
emission_log_probability(const adaptive_hmm_t *hmm, unsigned state,
                         const adaptive_network_metrics_t *observation)
{
  double result = 0.0;
  unsigned metric;
  for(metric = 0; metric < ADAPTIVE_METRIC_COUNT; metric++) {
    double variance = hmm->emission_variance[state][metric];
    double delta =
        observation->value[metric] - hmm->emission_mean[state][metric];
    if(variance < hmm->min_variance) {
      variance = hmm->min_variance;
    }
    result += -0.5 * (log(2.0 * M_PI * variance) +
                      (delta * delta) / variance);
  }
  return result;
}

static adaptive_state_t
largest_probability(const double probability[ADAPTIVE_STATE_COUNT])
{
  unsigned state;
  unsigned best = 0U;
  for(state = 1; state < ADAPTIVE_STATE_COUNT; state++) {
    if(probability[state] > probability[best]) {
      best = state;
    }
  }
  return (adaptive_state_t)best;
}

static void
update_transition(adaptive_hmm_t *hmm, adaptive_state_t from,
                  adaptive_state_t to)
{
  unsigned row;
  unsigned column;
  for(row = 0; row < ADAPTIVE_STATE_COUNT; row++) {
    double total = 0.0;
    for(column = 0; column < ADAPTIVE_STATE_COUNT; column++) {
      hmm->transition_count[row][column] *= hmm->transition_forgetting;
    }
    if(row == (unsigned)from) {
      hmm->transition_count[row][to] += 1.0;
    }
    for(column = 0; column < ADAPTIVE_STATE_COUNT; column++) {
      total += hmm->transition_count[row][column] +
               hmm->transition_smoothing *
               hmm->transition_prior[row][column];
    }
    for(column = 0; column < ADAPTIVE_STATE_COUNT; column++) {
      hmm->transition[row][column] =
          (hmm->transition_count[row][column] +
           hmm->transition_smoothing *
           hmm->transition_prior[row][column]) / total;
    }
  }
}

static void
update_emissions(adaptive_hmm_t *hmm,
                 const adaptive_network_metrics_t *observation)
{
  unsigned state;
  unsigned metric;
  /*
   * Online soft-EM: every state's parameters move in proportion to its
   * posterior responsibility. This avoids one early hard assignment
   * absorbing all later congestion observations.
   */
  for(state = 0; state < ADAPTIVE_STATE_COUNT; state++) {
    double rate = hmm->emission_alpha * hmm->probability[state];
    for(metric = 0; metric < ADAPTIVE_METRIC_COUNT; metric++) {
      double mean = hmm->emission_mean[state][metric];
      double delta = observation->value[metric] - mean;
      double variance = hmm->emission_variance[state][metric];
      mean += rate * delta;
      variance = (1.0 - rate) * variance + rate * delta * delta;
      if(variance < hmm->min_variance) {
        variance = hmm->min_variance;
      }
      hmm->emission_mean[state][metric] = mean;
      hmm->emission_variance[state][metric] = variance;
    }
  }
}

int
adaptive_hmm_init(adaptive_hmm_t *hmm, const adaptive_config_t *config)
{
  unsigned row;
  unsigned column;
  double initial[ADAPTIVE_STATE_COUNT];
  if(hmm == NULL || config == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  memset(hmm, 0, sizeof(*hmm));
  memcpy(hmm->transition_prior, config->transition_prior,
         sizeof(hmm->transition_prior));
  memcpy(hmm->emission_mean, config->emission_mean,
         sizeof(hmm->emission_mean));
  memcpy(hmm->emission_variance, config->emission_variance,
         sizeof(hmm->emission_variance));
  memcpy(initial, config->initial_probability, sizeof(initial));
  normalize(initial, ADAPTIVE_STATE_COUNT);
  memcpy(hmm->probability, initial, sizeof(initial));

  for(row = 0; row < ADAPTIVE_STATE_COUNT; row++) {
    double row_total = 0.0;
    for(column = 0; column < ADAPTIVE_STATE_COUNT; column++) {
      row_total += config->transition_prior[row][column];
    }
    for(column = 0; column < ADAPTIVE_STATE_COUNT; column++) {
      hmm->transition[row][column] =
          config->transition_prior[row][column] / row_total;
      hmm->transition_count[row][column] =
          config->transition_prior_strength *
          hmm->transition[row][column];
      hmm->transition_prior[row][column] = hmm->transition[row][column];
    }
  }

  hmm->emission_alpha = config->emission_alpha;
  hmm->transition_forgetting = config->transition_forgetting;
  hmm->transition_smoothing = config->transition_smoothing;
  hmm->min_variance = config->min_emission_variance;
  hmm->recovery_hold = config->recovery_hold;
  hmm->state = largest_probability(initial);
  hmm->previous_state = hmm->state;
  return ADAPTIVE_OK;
}

int
adaptive_hmm_step(adaptive_hmm_t *hmm,
                  const adaptive_network_metrics_t *normalized,
                  adaptive_state_t *state,
                  double probability[ADAPTIVE_STATE_COUNT])
{
  double prediction[ADAPTIVE_STATE_COUNT] = { 0.0 };
  double emission_log[ADAPTIVE_STATE_COUNT];
  double posterior[ADAPTIVE_STATE_COUNT];
  double max_log = -DBL_MAX;
  adaptive_state_t candidate;
  adaptive_state_t selected;
  adaptive_state_t from;
  unsigned i;
  unsigned j;

  if(hmm == NULL || normalized == NULL || state == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }

  for(j = 0; j < ADAPTIVE_STATE_COUNT; j++) {
    for(i = 0; i < ADAPTIVE_STATE_COUNT; i++) {
      prediction[j] += hmm->probability[i] * hmm->transition[i][j];
    }
    emission_log[j] = emission_log_probability(hmm, j, normalized);
    if(emission_log[j] > max_log) {
      max_log = emission_log[j];
    }
  }
  for(j = 0; j < ADAPTIVE_STATE_COUNT; j++) {
    posterior[j] = prediction[j] * exp(emission_log[j] - max_log);
  }
  normalize(posterior, ADAPTIVE_STATE_COUNT);
  candidate = largest_probability(posterior);
  from = hmm->state;
  selected = candidate;

  /*
   * RECOVERY is history-dependent. It is entered only when leaving
   * CONGESTED and is held for a configurable number of observations.
   */
  if(from == ADAPTIVE_STATE_CONGESTED &&
     candidate != ADAPTIVE_STATE_CONGESTED) {
    selected = ADAPTIVE_STATE_RECOVERY;
    hmm->recovery_remaining = hmm->recovery_hold;
  } else if(from == ADAPTIVE_STATE_RECOVERY) {
    if(candidate == ADAPTIVE_STATE_CONGESTED) {
      selected = ADAPTIVE_STATE_CONGESTED;
      hmm->recovery_remaining = 0U;
    } else if(hmm->recovery_remaining > 0U) {
      selected = ADAPTIVE_STATE_RECOVERY;
      hmm->recovery_remaining--;
    } else if(candidate == ADAPTIVE_STATE_RECOVERY) {
      selected = ADAPTIVE_STATE_NORMAL;
    }
  } else if(candidate == ADAPTIVE_STATE_RECOVERY) {
    selected = ADAPTIVE_STATE_NORMAL;
  }

  hmm->previous_state = from;
  hmm->state = selected;
  memcpy(hmm->probability, posterior, sizeof(posterior));
  if(selected != candidate) {
    for(j = 0; j < ADAPTIVE_STATE_COUNT; j++) {
      hmm->probability[j] *= 0.5;
    }
    hmm->probability[selected] += 0.5;
    normalize(hmm->probability, ADAPTIVE_STATE_COUNT);
  }
  update_transition(hmm, from, selected);
  update_emissions(hmm, normalized);
  hmm->observations++;
  *state = selected;
  if(probability != NULL) {
    memcpy(probability, hmm->probability, sizeof(hmm->probability));
  }
  return ADAPTIVE_OK;
}
