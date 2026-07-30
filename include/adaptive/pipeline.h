#ifndef ADAPTIVE_PIPELINE_H
#define ADAPTIVE_PIPELINE_H

#include "adaptive/coap_block.h"
#include "adaptive/codec.h"
#include "adaptive/config.h"
#include "adaptive/hmm.h"
#include "adaptive/metrics.h"
#include "adaptive/security.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*adaptive_transport_send_fn)(const uint8_t *packet,
                                          size_t packet_length,
                                          void *context);

typedef struct {
  adaptive_config_t config;
  adaptive_normalizer_t normalizer;
  adaptive_hmm_t hmm;
  adaptive_security_session_t *security;
  uint32_t next_window_id;
  uint16_t next_message_id;
} adaptive_pipeline_t;

typedef struct {
  uint32_t window_id;
  adaptive_state_t state;
  double state_probability;
  double sampling_factor;
  size_t input_bytes;
  size_t compressed_bytes;
  size_t protected_body_bytes;
  size_t block_count;
  uint8_t block_szx;
  double compression_ratio;
} adaptive_pipeline_stats_t;

int adaptive_pipeline_init(adaptive_pipeline_t *pipeline,
                           const adaptive_config_t *config,
                           adaptive_security_session_t *security);

int adaptive_pipeline_process(adaptive_pipeline_t *pipeline,
                              const float *samples, size_t sample_count,
                              const adaptive_network_metrics_t *metrics,
                              adaptive_transport_send_fn send,
                              void *send_context,
                              adaptive_pipeline_stats_t *stats);

size_t adaptive_pipeline_build_aad(const adaptive_coap_block_t *block,
                                   uint8_t output[16]);

#ifdef __cplusplus
}
#endif

#endif
