#include "adaptive/receiver.h"

#include "adaptive/pipeline.h"

#include <string.h>

void
adaptive_receiver_init(adaptive_receiver_t *receiver,
                       adaptive_security_session_t *security)
{
  if(receiver != NULL) {
    memset(receiver, 0, sizeof(*receiver));
    receiver->security = security;
  }
}

int
adaptive_receiver_accept(adaptive_receiver_t *receiver,
                         const uint8_t *packet, size_t packet_length,
                         float *samples, size_t sample_capacity,
                         size_t *sample_count,
                         adaptive_codec_metadata_t *metadata)
{
  adaptive_coap_block_t block;
  uint8_t plaintext[ADAPTIVE_MAX_BLOCK_SIZE];
  uint8_t aad[16];
  size_t plaintext_length;
  size_t aad_length;
  int result;

  if(receiver == NULL || receiver->security == NULL ||
     packet == NULL || samples == NULL || sample_count == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  result = adaptive_coap_parse_block1(packet, packet_length, &block);
  if(result != ADAPTIVE_OK) return result;

  if(block.block_number == 0U) {
    receiver->representation_length = 0U;
    receiver->next_block = 0U;
    receiver->token_length = block.token_length;
    memcpy(receiver->token, block.token, block.token_length);
    receiver->active = 1;
  }
  if(!receiver->active || block.block_number != receiver->next_block ||
     block.token_length != receiver->token_length ||
     memcmp(block.token, receiver->token, block.token_length) != 0) {
    return ADAPTIVE_ERR_FORMAT;
  }
  aad_length = adaptive_pipeline_build_aad(&block, aad);
  result = adaptive_security_open(receiver->security,
                                  block.payload, block.payload_length,
                                  aad, aad_length,
                                  plaintext, sizeof(plaintext),
                                  &plaintext_length);
  if(result != ADAPTIVE_OK) return result;
  if(plaintext_length >
     sizeof(receiver->representation) - receiver->representation_length) {
    return ADAPTIVE_ERR_CAPACITY;
  }
  memcpy(receiver->representation + receiver->representation_length,
         plaintext, plaintext_length);
  receiver->representation_length += plaintext_length;
  receiver->next_block++;
  if(block.more != 0U) {
    return ADAPTIVE_OK;
  }

  result = adaptive_codec_decode(receiver->representation,
                                 receiver->representation_length,
                                 samples, sample_capacity,
                                 sample_count, metadata);
  if(result == ADAPTIVE_OK) {
    receiver->active = 0;
    return ADAPTIVE_COMPLETE;
  }
  return result;
}
