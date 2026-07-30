#ifndef ADAPTIVE_COAP_BLOCK_H
#define ADAPTIVE_COAP_BLOCK_H

#include "adaptive/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ADAPTIVE_COAP_TYPE_CON 0U
#define ADAPTIVE_COAP_CODE_POST 2U

typedef struct {
  uint8_t type;
  uint8_t code;
  uint16_t message_id;
  uint8_t token[8];
  size_t token_length;
  uint32_t block_number;
  uint8_t more;
  uint8_t szx;
  unsigned content_format;
  uint32_t size1;
  const uint8_t *payload;
  size_t payload_length;
} adaptive_coap_block_t;

size_t adaptive_coap_block_size(uint8_t szx);
int adaptive_coap_build_block1(const adaptive_coap_block_t *block,
                               const char *uri_path,
                               uint8_t *output, size_t output_capacity,
                               size_t *output_length);
int adaptive_coap_parse_block1(const uint8_t *packet, size_t packet_length,
                               adaptive_coap_block_t *block);

#ifdef __cplusplus
}
#endif

#endif
