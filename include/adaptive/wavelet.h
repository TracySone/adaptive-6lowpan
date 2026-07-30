#ifndef ADAPTIVE_WAVELET_H
#define ADAPTIVE_WAVELET_H

#include "adaptive/types.h"

#ifdef __cplusplus
extern "C" {
#endif

int adaptive_db4_forward(float *values, size_t count, unsigned levels,
                         float *scratch, size_t scratch_count);
int adaptive_db4_inverse(float *coefficients, size_t count, unsigned levels,
                         float *scratch, size_t scratch_count);
double adaptive_wavelet_noise_sigma(const float *coefficients, size_t count,
                                    float *scratch, size_t scratch_count);
void adaptive_wavelet_soft_threshold(float *coefficients, size_t first_detail,
                                     size_t count, double threshold);

#ifdef __cplusplus
}
#endif

#endif
