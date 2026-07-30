#include "adaptive/pipeline.h"

#include <string.h>

static void
write_u32_be(uint8_t output[4], uint32_t value)
{
  output[0] = (uint8_t)(value >> 24U);
  output[1] = (uint8_t)(value >> 16U);
  output[2] = (uint8_t)(value >> 8U);
  output[3] = (uint8_t)value;
}

size_t
adaptive_pipeline_build_aad(const adaptive_coap_block_t *block,
                            uint8_t output[16])
{
  size_t copy;
  if(block == NULL || output == NULL) {
    return 0U;
  }
  memset(output, 0, 16U);
  output[0] = 0xa1U;
  output[1] = block->type;
  output[2] = block->code;
  output[3] = block->szx;
  output[4] = block->more;
  output[5] = (uint8_t)block->token_length;
  write_u32_be(output + 6U, block->block_number);
  copy = block->token_length < 4U ? block->token_length : 4U;
  memcpy(output + 10U, block->token, copy);
  output[14] = (uint8_t)(block->content_format >> 8U);
  output[15] = (uint8_t)block->content_format;
  return 16U;
}
