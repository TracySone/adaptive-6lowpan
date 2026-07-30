#include "adaptive/wavelet.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/*
 * Daubechies db4 analysis low-pass filter. The high-pass filter is the
 * quadrature mirror of this sequence. Periodic extension is used so the
 * transform remains exactly invertible for power-of-two streaming windows.
 */
static const double db4_low[8] = {
  -0.010597401784997278,
   0.032883011666982945,
   0.030841381835986965,
  -0.187034811718881140,
  -0.027983769416983850,
   0.630880767929858700,
   0.714846570552915400,
   0.230377813308896400
};

static double
db4_high(unsigned index)
{
  double value = db4_low[7U - index];
  return (index & 1U) != 0U ? value : -value;
}

static int
validate_transform(size_t count, unsigned levels, size_t scratch_count)
{
  size_t divisor;
  if(count < 8U || count > ADAPTIVE_MAX_WINDOW || levels == 0U ||
     levels >= sizeof(size_t) * 8U || scratch_count < count) {
    return ADAPTIVE_ERR_RANGE;
  }
  if((count >> (levels - 1U)) < 8U) {
    return ADAPTIVE_ERR_RANGE;
  }
  divisor = (size_t)1U << levels;
  if(count % divisor != 0U || count / divisor < 1U) {
    return ADAPTIVE_ERR_RANGE;
  }
  return ADAPTIVE_OK;
}

int
adaptive_db4_forward(float *values, size_t count, unsigned levels,
                     float *scratch, size_t scratch_count)
{
  size_t current = count;
  unsigned level;
  int result;
  if(values == NULL || scratch == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  result = validate_transform(count, levels, scratch_count);
  if(result != ADAPTIVE_OK) {
    return result;
  }

  for(level = 0; level < levels; level++) {
    size_t half = current / 2U;
    size_t i;
    for(i = 0; i < half; i++) {
      double low = 0.0;
      double high = 0.0;
      unsigned k;
      for(k = 0; k < 8U; k++) {
        size_t index = (2U * i + k) % current;
        low += db4_low[k] * values[index];
        high += db4_high(k) * values[index];
      }
      scratch[i] = (float)low;
      scratch[half + i] = (float)high;
    }
    memcpy(values, scratch, current * sizeof(*values));
    current = half;
  }
  return ADAPTIVE_OK;
}

int
adaptive_db4_inverse(float *coefficients, size_t count, unsigned levels,
                     float *scratch, size_t scratch_count)
{
  size_t current;
  unsigned level;
  int result;
  if(coefficients == NULL || scratch == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  result = validate_transform(count, levels, scratch_count);
  if(result != ADAPTIVE_OK) {
    return result;
  }
  current = count >> levels;

  for(level = 0; level < levels; level++) {
    size_t reconstructed = current * 2U;
    size_t i;
    memset(scratch, 0, reconstructed * sizeof(*scratch));
    for(i = 0; i < current; i++) {
      unsigned k;
      for(k = 0; k < 8U; k++) {
        size_t index = (2U * i + k) % reconstructed;
        scratch[index] +=
            (float)(db4_low[k] * coefficients[i] +
                    db4_high(k) * coefficients[current + i]);
      }
    }
    memcpy(coefficients, scratch, reconstructed * sizeof(*coefficients));
    current = reconstructed;
  }
  return ADAPTIVE_OK;
}

static int
compare_float(const void *left, const void *right)
{
  float a = *(const float *)left;
  float b = *(const float *)right;
  return (a > b) - (a < b);
}

double
adaptive_wavelet_noise_sigma(const float *coefficients, size_t count,
                             float *scratch, size_t scratch_count)
{
  size_t detail_count;
  size_t i;
  double median;
  if(coefficients == NULL || scratch == NULL || count < 2U ||
     scratch_count < count / 2U) {
    return 0.0;
  }
  detail_count = count / 2U;
  for(i = 0; i < detail_count; i++) {
    scratch[i] = fabsf(coefficients[detail_count + i]);
  }
  qsort(scratch, detail_count, sizeof(*scratch), compare_float);
  if((detail_count & 1U) != 0U) {
    median = scratch[detail_count / 2U];
  } else {
    median = 0.5 *
        (scratch[detail_count / 2U - 1U] + scratch[detail_count / 2U]);
  }
  return median / 0.6744897501960817;
}

void
adaptive_wavelet_soft_threshold(float *coefficients, size_t first_detail,
                                size_t count, double threshold)
{
  size_t i;
  if(coefficients == NULL || first_detail > count || threshold < 0.0) {
    return;
  }
  for(i = first_detail; i < count; i++) {
    double value = coefficients[i];
    double magnitude = fabs(value);
    if(magnitude <= threshold) {
      coefficients[i] = 0.0f;
    } else {
      coefficients[i] =
          (float)(copysign(magnitude - threshold, value));
    }
  }
}
