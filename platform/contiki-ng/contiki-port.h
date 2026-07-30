#ifndef ADAPTIVE_CONTIKI_PORT_H
#define ADAPTIVE_CONTIKI_PORT_H

#include "adaptive/types.h"
#include "contiki.h"

#include <stddef.h>

typedef struct {
  double loss_ewma;
  double retry_ewma;
  double rtt_ms_ewma;
  double goodput_bps_ewma;
  unsigned consecutive_failures;
  int initialized;
} adaptive_contiki_observer_t;

void adaptive_contiki_observer_init(adaptive_contiki_observer_t *observer);
void adaptive_contiki_observer_record(adaptive_contiki_observer_t *observer,
                                      clock_time_t elapsed,
                                      int success, size_t payload_bytes);
void adaptive_contiki_metrics_snapshot(
    const adaptive_contiki_observer_t *observer,
    adaptive_network_metrics_t *metrics);

/*
 * Weak application hooks. Override these in a board-specific source file.
 */
double adaptive_platform_queue_ratio(void);
double adaptive_platform_mac_retry_ratio(void);
void adaptive_platform_read_window(float *samples, size_t sample_count,
                                   uint32_t window_id);

#endif
