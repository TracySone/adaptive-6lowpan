#include "contiki-port.h"

#include <string.h>

#define PORT_EWMA_ALPHA 0.125

void
adaptive_contiki_observer_init(adaptive_contiki_observer_t *observer)
{
  if(observer != NULL) {
    memset(observer, 0, sizeof(*observer));
  }
}

static double
ewma(double previous, double sample, int initialized)
{
  return initialized ?
      (1.0 - PORT_EWMA_ALPHA) * previous + PORT_EWMA_ALPHA * sample :
      sample;
}

void
adaptive_contiki_observer_record(adaptive_contiki_observer_t *observer,
                                 clock_time_t elapsed,
                                 int success, size_t payload_bytes)
{
  double rtt_ms;
  double goodput;
  if(observer == NULL) {
    return;
  }
  if(elapsed == 0) elapsed = 1;
  rtt_ms = 1000.0 * elapsed / CLOCK_SECOND;
  goodput = success ?
      (8.0 * payload_bytes * CLOCK_SECOND / elapsed) : 0.0;
  observer->loss_ewma =
      ewma(observer->loss_ewma, success ? 0.0 : 1.0,
           observer->initialized);
  observer->rtt_ms_ewma =
      ewma(observer->rtt_ms_ewma, rtt_ms, observer->initialized);
  observer->goodput_bps_ewma =
      ewma(observer->goodput_bps_ewma, goodput, observer->initialized);
  if(success) {
    observer->consecutive_failures = 0U;
  } else {
    observer->consecutive_failures++;
  }
  observer->retry_ewma =
      ewma(observer->retry_ewma,
           observer->consecutive_failures > 0U ? 1.0 : 0.0,
           observer->initialized);
  observer->initialized = 1;
}

void
adaptive_contiki_metrics_snapshot(
    const adaptive_contiki_observer_t *observer,
    adaptive_network_metrics_t *metrics)
{
  if(observer == NULL || metrics == NULL) {
    return;
  }
  metrics->value[ADAPTIVE_METRIC_QUEUE] =
      adaptive_platform_queue_ratio();
  metrics->value[ADAPTIVE_METRIC_LOSS] = observer->loss_ewma;
  metrics->value[ADAPTIVE_METRIC_RTT] = observer->rtt_ms_ewma;
  metrics->value[ADAPTIVE_METRIC_RETRY] =
      observer->retry_ewma + adaptive_platform_mac_retry_ratio();
  metrics->value[ADAPTIVE_METRIC_GOODPUT] = observer->goodput_bps_ewma;
}

__attribute__((weak)) double
adaptive_platform_queue_ratio(void)
{
  return 0.0;
}

__attribute__((weak)) double
adaptive_platform_mac_retry_ratio(void)
{
  return 0.0;
}

__attribute__((weak)) void
adaptive_platform_read_window(float *samples, size_t sample_count,
                              uint32_t window_id)
{
  size_t i;
  (void)window_id;
  /*
   * Deterministic triangle signal for Cooja. A real board overrides this
   * function and fills the window from its ADC/sensor driver.
   */
  for(i = 0; i < sample_count; i++) {
    size_t phase = i % 32U;
    samples[i] = phase < 16U ?
        (float)phase / 16.0f :
        (float)(32U - phase) / 16.0f;
  }
}
