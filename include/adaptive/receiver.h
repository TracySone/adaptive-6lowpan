#ifndef ADAPTIVE_RECEIVER_H
#define ADAPTIVE_RECEIVER_H

#include "adaptive/coap_block.h"
#include "adaptive/codec.h"
#include "adaptive/security.h"
#include "adaptive/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  adaptive_security_session_t *security;
  uint8_t representation[ADAPTIVE_MAX_REPRESENTATION];
  size_t representation_length;
  uint32_t next_block;
  uint8_t token[8];
  size_t token_length;
  int active;
} adaptive_receiver_t;

void adaptive_receiver_init(adaptive_receiver_t *receiver,
                            adaptive_security_session_t *security);

/*
 * Returns ADAPTIVE_COMPLETE when a complete window has been decoded.
 * Returns ADAPTIVE_OK when more Block1 messages are expected.
 */
int adaptive_receiver_accept(adaptive_receiver_t *receiver,
                             const uint8_t *packet, size_t packet_length,
                             float *samples, size_t sample_capacity,
                             size_t *sample_count,
                             adaptive_codec_metadata_t *metadata);

#ifdef __cplusplus
}
#endif

#endif
