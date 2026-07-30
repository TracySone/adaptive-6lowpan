#include "adaptive/codec.h"

#include "adaptive/wavelet.h"

#include <math.h>
#include <stdint.h>
#include <string.h>

#define CODEC_HEADER_BYTES 28U
#define CODEC_VERSION 1U

static void
write_u16(uint8_t *output, uint16_t value)
{
  output[0] = (uint8_t)(value & 0xffU);
  output[1] = (uint8_t)(value >> 8U);
}

static void
write_u32(uint8_t *output, uint32_t value)
{
  output[0] = (uint8_t)(value & 0xffU);
  output[1] = (uint8_t)((value >> 8U) & 0xffU);
  output[2] = (uint8_t)((value >> 16U) & 0xffU);
  output[3] = (uint8_t)(value >> 24U);
}

static uint16_t
read_u16(const uint8_t *input)
{
  return (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8U));
}

static uint32_t
read_u32(const uint8_t *input)
{
  return (uint32_t)input[0] |
         ((uint32_t)input[1] << 8U) |
         ((uint32_t)input[2] << 16U) |
         ((uint32_t)input[3] << 24U);
}

static void
write_float(uint8_t *output, float value)
{
  uint32_t bits;
  memcpy(&bits, &value, sizeof(bits));
  write_u32(output, bits);
}

static float
read_float(const uint8_t *input)
{
  uint32_t bits = read_u32(input);
  float value;
  memcpy(&value, &bits, sizeof(value));
  return value;
}

static uint32_t
crc32_update(uint32_t crc, const uint8_t *data, size_t length)
{
  size_t i;
  crc = ~crc;
  for(i = 0; i < length; i++) {
    unsigned bit;
    crc ^= data[i];
    for(bit = 0; bit < 8U; bit++) {
      uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
      crc = (crc >> 1U) ^ (0xedb88320U & mask);
    }
  }
  return ~crc;
}

int
adaptive_codec_encode(const float *samples, size_t sample_count,
                      uint32_t window_id, adaptive_state_t state,
                      const adaptive_config_t *config,
                      uint8_t *output, size_t output_capacity,
                      size_t *output_length,
                      adaptive_codec_metadata_t *metadata)
{
  float coefficients[ADAPTIVE_MAX_WINDOW];
  float scratch[ADAPTIVE_MAX_WINDOW];
  size_t approximation_count;
  size_t nonzero = 0U;
  size_t i;
  size_t write_offset;
  double sigma;
  double threshold;
  double maximum = 0.0;
  double scale;
  int maximum_integer;
  int result;

  if(samples == NULL || config == NULL || output == NULL ||
     output_length == NULL || (unsigned)state >= ADAPTIVE_STATE_COUNT) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  if(sample_count != config->window_size ||
     sample_count > ADAPTIVE_MAX_WINDOW || sample_count > UINT16_MAX) {
    return ADAPTIVE_ERR_RANGE;
  }
  memcpy(coefficients, samples, sample_count * sizeof(*samples));
  result = adaptive_db4_forward(coefficients, sample_count,
                                config->wavelet_levels,
                                scratch, ADAPTIVE_MAX_WINDOW);
  if(result != ADAPTIVE_OK) {
    return result;
  }

  sigma = adaptive_wavelet_noise_sigma(coefficients, sample_count,
                                       scratch, ADAPTIVE_MAX_WINDOW);
  threshold = config->threshold_gain[state] * sigma *
              sqrt(2.0 * log((double)sample_count));
  approximation_count = sample_count >> config->wavelet_levels;
  adaptive_wavelet_soft_threshold(coefficients, approximation_count,
                                  sample_count, threshold);

  for(i = 0; i < sample_count; i++) {
    double magnitude = fabs(coefficients[i]);
    if(magnitude > maximum) {
      maximum = magnitude;
    }
  }
  maximum_integer = (1 << (config->quant_bits[state] - 1U)) - 1;
  scale = maximum > 0.0 ? maximum / maximum_integer : 1.0;

  for(i = 0; i < sample_count; i++) {
    long quantized = lround(coefficients[i] / scale);
    if(quantized > maximum_integer) quantized = maximum_integer;
    if(quantized < -maximum_integer) quantized = -maximum_integer;
    if(quantized != 0L) {
      nonzero++;
    }
  }
  if(nonzero > UINT16_MAX ||
     CODEC_HEADER_BYTES + nonzero * 4U > output_capacity) {
    return ADAPTIVE_ERR_CAPACITY;
  }

  memset(output, 0, CODEC_HEADER_BYTES);
  memcpy(output, "ADW1", 4U);
  output[4] = CODEC_VERSION;
  output[5] = (uint8_t)config->wavelet_levels;
  output[6] = (uint8_t)config->quant_bits[state];
  output[7] = (uint8_t)state;
  write_u16(output + 8U, (uint16_t)sample_count);
  write_u16(output + 10U, (uint16_t)nonzero);
  write_u32(output + 12U, window_id);
  write_float(output + 16U, (float)scale);
  write_float(output + 20U, (float)threshold);

  write_offset = CODEC_HEADER_BYTES;
  for(i = 0; i < sample_count; i++) {
    long quantized = lround(coefficients[i] / scale);
    if(quantized > maximum_integer) quantized = maximum_integer;
    if(quantized < -maximum_integer) quantized = -maximum_integer;
    if(quantized != 0L) {
      write_u16(output + write_offset, (uint16_t)i);
      write_u16(output + write_offset + 2U,
                (uint16_t)(int16_t)quantized);
      write_offset += 4U;
    }
  }
  write_u32(output + 24U,
            crc32_update(0U, output + CODEC_HEADER_BYTES,
                         write_offset - CODEC_HEADER_BYTES));
  *output_length = write_offset;
  if(metadata != NULL) {
    metadata->window_id = window_id;
    metadata->state = state;
    metadata->sample_count = sample_count;
    metadata->levels = config->wavelet_levels;
    metadata->quant_bits = config->quant_bits[state];
    metadata->nonzero_coefficients = nonzero;
    metadata->threshold = threshold;
    metadata->coefficient_scale = scale;
  }
  return ADAPTIVE_OK;
}

int
adaptive_codec_decode(const uint8_t *input, size_t input_length,
                      float *samples, size_t sample_capacity,
                      size_t *sample_count,
                      adaptive_codec_metadata_t *metadata)
{
  float scratch[ADAPTIVE_MAX_WINDOW];
  uint16_t count;
  uint16_t nonzero;
  uint32_t expected_crc;
  uint32_t actual_crc;
  uint32_t window_id;
  float scale;
  float threshold;
  unsigned levels;
  unsigned quant_bits;
  adaptive_state_t state;
  size_t i;
  uint16_t previous_index = 0U;
  int have_previous = 0;
  int result;

  if(input == NULL || samples == NULL || sample_count == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  if(input_length < CODEC_HEADER_BYTES ||
     memcmp(input, "ADW1", 4U) != 0 ||
     input[4] != CODEC_VERSION) {
    return ADAPTIVE_ERR_FORMAT;
  }
  levels = input[5];
  quant_bits = input[6];
  state = (adaptive_state_t)input[7];
  count = read_u16(input + 8U);
  nonzero = read_u16(input + 10U);
  window_id = read_u32(input + 12U);
  scale = read_float(input + 16U);
  threshold = read_float(input + 20U);
  expected_crc = read_u32(input + 24U);
  if(count == 0U || count > ADAPTIVE_MAX_WINDOW || count > sample_capacity ||
     levels == 0U || levels >= sizeof(size_t) * 8U ||
     ((size_t)count >> (levels - 1U)) < 8U ||
     quant_bits < 2U || quant_bits > 15U ||
     (unsigned)state >= ADAPTIVE_STATE_COUNT ||
     !isfinite(scale) || scale <= 0.0f ||
     CODEC_HEADER_BYTES + (size_t)nonzero * 4U != input_length) {
    return ADAPTIVE_ERR_FORMAT;
  }
  actual_crc = crc32_update(0U, input + CODEC_HEADER_BYTES,
                            input_length - CODEC_HEADER_BYTES);
  if(actual_crc != expected_crc) {
    return ADAPTIVE_ERR_INTEGRITY;
  }

  memset(samples, 0, count * sizeof(*samples));
  for(i = 0; i < nonzero; i++) {
    size_t offset = CODEC_HEADER_BYTES + i * 4U;
    uint16_t index = read_u16(input + offset);
    int16_t quantized = (int16_t)read_u16(input + offset + 2U);
    if(index >= count || (have_previous && index <= previous_index)) {
      return ADAPTIVE_ERR_FORMAT;
    }
    samples[index] = (float)(quantized * scale);
    previous_index = index;
    have_previous = 1;
  }
  result = adaptive_db4_inverse(samples, count, levels,
                                scratch, ADAPTIVE_MAX_WINDOW);
  if(result != ADAPTIVE_OK) {
    return result;
  }
  *sample_count = count;
  if(metadata != NULL) {
    metadata->window_id = window_id;
    metadata->state = state;
    metadata->sample_count = count;
    metadata->levels = levels;
    metadata->quant_bits = quant_bits;
    metadata->nonzero_coefficients = nonzero;
    metadata->threshold = threshold;
    metadata->coefficient_scale = scale;
  }
  return ADAPTIVE_OK;
}
