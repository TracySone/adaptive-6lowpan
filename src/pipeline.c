#include "adaptive/pipeline.h"

#include <stdint.h>
#include <string.h>

static void
write_u32_be(uint8_t output[4], uint32_t value)
{
  output[0] = (uint8_t)(value >> 24U);
  output[1] = (uint8_t)(value >> 16U);
  output[2] = (uint8_t)(value >> 8U);
  output[3] = (uint8_t)value;
}

int
adaptive_pipeline_init(adaptive_pipeline_t *pipeline,
                       const adaptive_config_t *config,
                       adaptive_security_session_t *security)
{
  int result;
  if(pipeline == NULL || config == NULL || security == NULL ||
     security->seal == NULL || security->overhead == 0U) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  memset(pipeline, 0, sizeof(*pipeline));
  pipeline->config = *config;
  pipeline->security = security;
  pipeline->next_window_id = 1U;
  pipeline->next_message_id = 1U;
  adaptive_normalizer_init(&pipeline->normalizer,
                           config->baseline_alpha,
                           config->baseline_epsilon);
  result = adaptive_hmm_init(&pipeline->hmm, config);
  return result;
}

int
adaptive_pipeline_process(adaptive_pipeline_t *pipeline,
                          const float *samples, size_t sample_count,
                          const adaptive_network_metrics_t *metrics,
                          adaptive_transport_send_fn send,
                          void *send_context,
                          adaptive_pipeline_stats_t *stats)
{
  adaptive_network_metrics_t normalized;
  adaptive_state_t state;
  double state_probability[ADAPTIVE_STATE_COUNT];
  uint8_t representation[ADAPTIVE_MAX_REPRESENTATION];
  uint8_t record[ADAPTIVE_MAX_BLOCK_SIZE];
  uint8_t packet[ADAPTIVE_MAX_COAP_PACKET];
  uint8_t aad[16];
  adaptive_codec_metadata_t codec_metadata;
  size_t representation_length;
  size_t block_size;
  size_t plaintext_capacity;
  size_t block_count;
  size_t total_protected;
  size_t offset = 0U;
  size_t block_number;
  uint32_t window_id;
  int result;

  if(pipeline == NULL || samples == NULL || metrics == NULL || send == NULL ||
     sample_count != pipeline->config.window_size) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  result = adaptive_normalizer_update(&pipeline->normalizer, metrics,
                                      &normalized);
  if(result != ADAPTIVE_OK) return result;
  result = adaptive_hmm_step(&pipeline->hmm, &normalized, &state,
                             state_probability);
  if(result != ADAPTIVE_OK) return result;

  window_id = pipeline->next_window_id++;
  result = adaptive_codec_encode(samples, sample_count, window_id, state,
                                 &pipeline->config, representation,
                                 sizeof(representation),
                                 &representation_length, &codec_metadata);
  if(result != ADAPTIVE_OK) return result;

  block_size = adaptive_coap_block_size(pipeline->config.block_szx[state]);
  if(block_size == 0U || block_size > sizeof(record) ||
     block_size <= pipeline->security->overhead) {
    return ADAPTIVE_ERR_RANGE;
  }
  plaintext_capacity = block_size - pipeline->security->overhead;
  block_count =
      (representation_length + plaintext_capacity - 1U) / plaintext_capacity;
  total_protected =
      representation_length + block_count * pipeline->security->overhead;
  if(total_protected > UINT32_MAX) {
    return ADAPTIVE_ERR_RANGE;
  }

  for(block_number = 0U; block_number < block_count; block_number++) {
    adaptive_coap_block_t block;
    size_t remaining = representation_length - offset;
    size_t plaintext_length =
        remaining < plaintext_capacity ? remaining : plaintext_capacity;
    size_t record_length;
    size_t packet_length;
    size_t aad_length;
    uint8_t more = (block_number + 1U < block_count) ? 1U : 0U;

    memset(&block, 0, sizeof(block));
    block.type = ADAPTIVE_COAP_TYPE_CON;
    block.code = ADAPTIVE_COAP_CODE_POST;
    block.message_id = pipeline->next_message_id++;
    block.token_length = 4U;
    write_u32_be(block.token, window_id);
    block.block_number = (uint32_t)block_number;
    block.more = more;
    block.szx = pipeline->config.block_szx[state];
    block.content_format = pipeline->config.content_format;
    block.size1 = (uint32_t)total_protected;
    aad_length = adaptive_pipeline_build_aad(&block, aad);
    result = adaptive_security_seal(
        pipeline->security, representation + offset, plaintext_length,
        aad, aad_length, record, sizeof(record), &record_length);
    if(result != ADAPTIVE_OK) return result;
    if(record_length > block_size ||
       (more != 0U && record_length != block_size)) {
      return ADAPTIVE_ERR_FORMAT;
    }
    block.payload = record;
    block.payload_length = record_length;
    result = adaptive_coap_build_block1(
        &block, pipeline->config.uri_path,
        packet, sizeof(packet), &packet_length);
    if(result != ADAPTIVE_OK) return result;
    result = send(packet, packet_length, send_context);
    if(result != ADAPTIVE_OK) return result;
    offset += plaintext_length;
  }

  if(stats != NULL) {
    memset(stats, 0, sizeof(*stats));
    stats->window_id = window_id;
    stats->state = state;
    stats->state_probability = state_probability[state];
    stats->sampling_factor = pipeline->config.sampling_factor[state];
    stats->input_bytes = sample_count * sizeof(*samples);
    stats->compressed_bytes = representation_length;
    stats->protected_body_bytes = total_protected;
    stats->block_count = block_count;
    stats->block_szx = pipeline->config.block_szx[state];
    stats->compression_ratio =
        (double)representation_length / (double)stats->input_bytes;
  }
  return ADAPTIVE_OK;
}
