#ifndef ADAPTIVE_TYPES_H
#define ADAPTIVE_TYPES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADAPTIVE_STATE_COUNT 5U
#define ADAPTIVE_METRIC_COUNT 5U
#define ADAPTIVE_MAX_WINDOW 256U
#define ADAPTIVE_MAX_REPRESENTATION (64U + (ADAPTIVE_MAX_WINDOW * 4U))
#define ADAPTIVE_MAX_BLOCK_SIZE 1024U
#define ADAPTIVE_MAX_COAP_PACKET 1152U
#define ADAPTIVE_MAX_URI_PATH 63U

typedef enum {
  ADAPTIVE_STATE_GOOD = 0,
  ADAPTIVE_STATE_NORMAL = 1,
  ADAPTIVE_STATE_DEGRADED = 2,
  ADAPTIVE_STATE_CONGESTED = 3,
  ADAPTIVE_STATE_RECOVERY = 4
} adaptive_state_t;

typedef enum {
  ADAPTIVE_METRIC_QUEUE = 0,
  ADAPTIVE_METRIC_LOSS = 1,
  ADAPTIVE_METRIC_RTT = 2,
  ADAPTIVE_METRIC_RETRY = 3,
  ADAPTIVE_METRIC_GOODPUT = 4
} adaptive_metric_t;

typedef enum {
  ADAPTIVE_OK = 0,
  ADAPTIVE_COMPLETE = 1,
  ADAPTIVE_ERR_ARGUMENT = -1,
  ADAPTIVE_ERR_RANGE = -2,
  ADAPTIVE_ERR_CAPACITY = -3,
  ADAPTIVE_ERR_FORMAT = -4,
  ADAPTIVE_ERR_INTEGRITY = -5,
  ADAPTIVE_ERR_REPLAY = -6,
  ADAPTIVE_ERR_CRYPTO = -7,
  ADAPTIVE_ERR_IO = -8,
  ADAPTIVE_ERR_UNSUPPORTED = -9
} adaptive_result_t;

typedef struct {
  double value[ADAPTIVE_METRIC_COUNT];
} adaptive_network_metrics_t;

const char *adaptive_state_name(adaptive_state_t state);
const char *adaptive_metric_name(adaptive_metric_t metric);
int adaptive_state_from_name(const char *name, adaptive_state_t *state);
int adaptive_metric_from_name(const char *name, adaptive_metric_t *metric);

#ifdef __cplusplus
}
#endif

#endif
