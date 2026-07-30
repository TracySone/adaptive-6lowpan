#include "adaptive/coap_block.h"

#include <limits.h>
#include <string.h>

static int
encode_extended(unsigned value, uint8_t *nibble, uint8_t extension[2],
                size_t *extension_length)
{
  if(value < 13U) {
    *nibble = (uint8_t)value;
    *extension_length = 0U;
  } else if(value < 269U) {
    *nibble = 13U;
    extension[0] = (uint8_t)(value - 13U);
    *extension_length = 1U;
  } else if(value <= 65804U) {
    unsigned adjusted = value - 269U;
    *nibble = 14U;
    extension[0] = (uint8_t)(adjusted >> 8U);
    extension[1] = (uint8_t)adjusted;
    *extension_length = 2U;
  } else {
    return ADAPTIVE_ERR_RANGE;
  }
  return ADAPTIVE_OK;
}

static int
append_option(uint8_t *output, size_t capacity, size_t *offset,
              unsigned delta, const uint8_t *value, size_t length)
{
  uint8_t delta_nibble;
  uint8_t length_nibble;
  uint8_t delta_extension[2];
  uint8_t length_extension[2];
  size_t delta_length;
  size_t length_length;
  size_t required;
  int result;

  if(length > UINT_MAX) {
    return ADAPTIVE_ERR_RANGE;
  }
  result = encode_extended(delta, &delta_nibble, delta_extension,
                           &delta_length);
  if(result != ADAPTIVE_OK) return result;
  result = encode_extended((unsigned)length, &length_nibble, length_extension,
                           &length_length);
  if(result != ADAPTIVE_OK) return result;
  required = 1U + delta_length + length_length + length;
  if(*offset > capacity || required > capacity - *offset) {
    return ADAPTIVE_ERR_CAPACITY;
  }
  output[(*offset)++] = (uint8_t)((delta_nibble << 4U) | length_nibble);
  memcpy(output + *offset, delta_extension, delta_length);
  *offset += delta_length;
  memcpy(output + *offset, length_extension, length_length);
  *offset += length_length;
  if(length > 0U) {
    memcpy(output + *offset, value, length);
    *offset += length;
  }
  return ADAPTIVE_OK;
}

static size_t
encode_uint(uint32_t value, uint8_t output[4])
{
  size_t length;
  if(value == 0U) {
    return 0U;
  }
  if(value <= 0xffU) length = 1U;
  else if(value <= 0xffffU) length = 2U;
  else if(value <= 0xffffffU) length = 3U;
  else length = 4U;
  {
    size_t i;
    for(i = 0; i < length; i++) {
      output[length - 1U - i] = (uint8_t)(value >> (i * 8U));
    }
  }
  return length;
}

static int
append_uri_path(uint8_t *output, size_t capacity, size_t *offset,
                const char *path, unsigned *previous_option)
{
  const char *cursor = path;
  int first = 1;
  while(*cursor == '/') cursor++;
  while(*cursor != '\0') {
    const char *end = cursor;
    size_t length;
    int result;
    while(*end != '\0' && *end != '/') end++;
    length = (size_t)(end - cursor);
    if(length > 0U) {
      unsigned delta = first ? 11U - *previous_option : 0U;
      result = append_option(output, capacity, offset, delta,
                             (const uint8_t *)cursor, length);
      if(result != ADAPTIVE_OK) return result;
      *previous_option = 11U;
      first = 0;
    }
    cursor = end;
    while(*cursor == '/') cursor++;
  }
  return first ? ADAPTIVE_ERR_FORMAT : ADAPTIVE_OK;
}

size_t
adaptive_coap_block_size(uint8_t szx)
{
  if(szx > 6U) {
    return 0U;
  }
  return (size_t)1U << (szx + 4U);
}

int
adaptive_coap_build_block1(const adaptive_coap_block_t *block,
                           const char *uri_path,
                           uint8_t *output, size_t output_capacity,
                           size_t *output_length)
{
  size_t offset;
  unsigned previous_option = 0U;
  uint8_t encoded[4];
  size_t encoded_length;
  uint32_t block_value;
  int result;

  if(block == NULL || uri_path == NULL || output == NULL ||
     output_length == NULL || block->token_length > 8U ||
     block->szx > 6U || block->block_number > 0xfffffU ||
     (block->payload_length > 0U && block->payload == NULL) ||
     output_capacity < 4U + block->token_length) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  output[0] = (uint8_t)(0x40U | ((block->type & 0x03U) << 4U) |
                        (uint8_t)block->token_length);
  output[1] = block->code;
  output[2] = (uint8_t)(block->message_id >> 8U);
  output[3] = (uint8_t)block->message_id;
  offset = 4U;
  memcpy(output + offset, block->token, block->token_length);
  offset += block->token_length;

  result = append_uri_path(output, output_capacity, &offset, uri_path,
                           &previous_option);
  if(result != ADAPTIVE_OK) return result;

  encoded_length = encode_uint((uint32_t)block->content_format, encoded);
  result = append_option(output, output_capacity, &offset,
                         12U - previous_option, encoded, encoded_length);
  if(result != ADAPTIVE_OK) return result;
  previous_option = 12U;

  block_value = (block->block_number << 4U) |
                ((uint32_t)(block->more != 0U) << 3U) |
                block->szx;
  encoded_length = encode_uint(block_value, encoded);
  result = append_option(output, output_capacity, &offset,
                         27U - previous_option, encoded, encoded_length);
  if(result != ADAPTIVE_OK) return result;
  previous_option = 27U;

  if(block->size1 > 0U) {
    encoded_length = encode_uint(block->size1, encoded);
    result = append_option(output, output_capacity, &offset,
                           60U - previous_option, encoded, encoded_length);
    if(result != ADAPTIVE_OK) return result;
  }

  if(block->payload_length > 0U) {
    if(offset >= output_capacity ||
       block->payload_length > output_capacity - offset - 1U) {
      return ADAPTIVE_ERR_CAPACITY;
    }
    output[offset++] = 0xffU;
    memcpy(output + offset, block->payload, block->payload_length);
    offset += block->payload_length;
  }
  *output_length = offset;
  return ADAPTIVE_OK;
}

static int
decode_extended(uint8_t nibble, const uint8_t *packet, size_t packet_length,
                size_t *offset, unsigned *value)
{
  if(nibble < 13U) {
    *value = nibble;
    return ADAPTIVE_OK;
  }
  if(nibble == 13U) {
    if(*offset >= packet_length) return ADAPTIVE_ERR_FORMAT;
    *value = 13U + packet[(*offset)++];
    return ADAPTIVE_OK;
  }
  if(nibble == 14U) {
    if(*offset > packet_length || packet_length - *offset < 2U) {
      return ADAPTIVE_ERR_FORMAT;
    }
    *value = 269U + ((unsigned)packet[*offset] << 8U) +
             packet[*offset + 1U];
    *offset += 2U;
    return ADAPTIVE_OK;
  }
  return ADAPTIVE_ERR_FORMAT;
}

static int
decode_uint(const uint8_t *input, size_t length, uint32_t *value)
{
  size_t i;
  uint32_t result = 0U;
  if(length > 4U) return ADAPTIVE_ERR_FORMAT;
  for(i = 0; i < length; i++) {
    result = (result << 8U) | input[i];
  }
  *value = result;
  return ADAPTIVE_OK;
}

int
adaptive_coap_parse_block1(const uint8_t *packet, size_t packet_length,
                           adaptive_coap_block_t *block)
{
  size_t offset;
  unsigned option_number = 0U;
  int found_block1 = 0;
  if(packet == NULL || block == NULL || packet_length < 4U ||
     (packet[0] >> 6U) != 1U || (packet[0] & 0x0fU) > 8U) {
    return ADAPTIVE_ERR_FORMAT;
  }
  memset(block, 0, sizeof(*block));
  block->type = (packet[0] >> 4U) & 0x03U;
  block->code = packet[1];
  block->message_id =
      (uint16_t)(((uint16_t)packet[2] << 8U) | packet[3]);
  block->token_length = packet[0] & 0x0fU;
  if(packet_length < 4U + block->token_length) {
    return ADAPTIVE_ERR_FORMAT;
  }
  offset = 4U;
  memcpy(block->token, packet + offset, block->token_length);
  offset += block->token_length;

  while(offset < packet_length && packet[offset] != 0xffU) {
    uint8_t header = packet[offset++];
    unsigned delta;
    unsigned length;
    uint32_t option_value;
    int result;
    result = decode_extended(header >> 4U, packet, packet_length,
                             &offset, &delta);
    if(result != ADAPTIVE_OK) return result;
    result = decode_extended(header & 0x0fU, packet, packet_length,
                             &offset, &length);
    if(result != ADAPTIVE_OK) return result;
    if(offset > packet_length || length > packet_length - offset ||
       option_number > UINT_MAX - delta) {
      return ADAPTIVE_ERR_FORMAT;
    }
    option_number += delta;
    if(option_number == 12U) {
      result = decode_uint(packet + offset, length, &option_value);
      if(result != ADAPTIVE_OK) return result;
      block->content_format = option_value;
    } else if(option_number == 27U) {
      result = decode_uint(packet + offset, length, &option_value);
      if(result != ADAPTIVE_OK || (option_value & 0x07U) > 6U) {
        return ADAPTIVE_ERR_FORMAT;
      }
      block->szx = (uint8_t)(option_value & 0x07U);
      block->more = (uint8_t)((option_value >> 3U) & 0x01U);
      block->block_number = option_value >> 4U;
      found_block1 = 1;
    } else if(option_number == 60U) {
      result = decode_uint(packet + offset, length, &option_value);
      if(result != ADAPTIVE_OK) return result;
      block->size1 = option_value;
    }
    offset += length;
  }
  if(!found_block1) {
    return ADAPTIVE_ERR_FORMAT;
  }
  if(offset < packet_length) {
    offset++;
    if(offset == packet_length) {
      return ADAPTIVE_ERR_FORMAT;
    }
    block->payload = packet + offset;
    block->payload_length = packet_length - offset;
  }
  return ADAPTIVE_OK;
}
