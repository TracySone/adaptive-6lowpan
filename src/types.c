#include "adaptive/types.h"

#include <ctype.h>
#include <string.h>

static int
name_equal(const char *left, const char *right)
{
  if(left == NULL || right == NULL) {
    return 0;
  }
  while(*left != '\0' && *right != '\0') {
    if(tolower((unsigned char)*left) != tolower((unsigned char)*right)) {
      return 0;
    }
    left++;
    right++;
  }
  return *left == '\0' && *right == '\0';
}

const char *
adaptive_state_name(adaptive_state_t state)
{
  static const char *const names[ADAPTIVE_STATE_COUNT] = {
    "GOOD", "NORMAL", "DEGRADED", "CONGESTED", "RECOVERY"
  };
  return (unsigned)state < ADAPTIVE_STATE_COUNT ? names[state] : "UNKNOWN";
}

const char *
adaptive_metric_name(adaptive_metric_t metric)
{
  static const char *const names[ADAPTIVE_METRIC_COUNT] = {
    "queue", "loss", "rtt", "retry", "goodput"
  };
  return (unsigned)metric < ADAPTIVE_METRIC_COUNT ? names[metric] : "unknown";
}

int
adaptive_state_from_name(const char *name, adaptive_state_t *state)
{
  unsigned i;
  if(name == NULL || state == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  for(i = 0; i < ADAPTIVE_STATE_COUNT; i++) {
    if(name_equal(name, adaptive_state_name((adaptive_state_t)i))) {
      *state = (adaptive_state_t)i;
      return ADAPTIVE_OK;
    }
  }
  return ADAPTIVE_ERR_FORMAT;
}

int
adaptive_metric_from_name(const char *name, adaptive_metric_t *metric)
{
  unsigned i;
  if(name == NULL || metric == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  for(i = 0; i < ADAPTIVE_METRIC_COUNT; i++) {
    if(name_equal(name, adaptive_metric_name((adaptive_metric_t)i))) {
      *metric = (adaptive_metric_t)i;
      return ADAPTIVE_OK;
    }
  }
  return ADAPTIVE_ERR_FORMAT;
}
