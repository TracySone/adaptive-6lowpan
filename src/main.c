#include "adaptive/config.h"
#include "adaptive/pipeline.h"
#include "adaptive/receiver.h"
#include "adaptive/security.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

typedef struct {
  adaptive_receiver_t receiver;
  float samples[ADAPTIVE_MAX_WINDOW];
  size_t sample_count;
  adaptive_codec_metadata_t metadata;
  unsigned complete_windows;
} loopback_t;

static int
loopback_send(const uint8_t *packet, size_t packet_length, void *context)
{
  loopback_t *loopback = context;
  int result = adaptive_receiver_accept(
      &loopback->receiver, packet, packet_length,
      loopback->samples, ADAPTIVE_MAX_WINDOW,
      &loopback->sample_count, &loopback->metadata);
  if(result == ADAPTIVE_COMPLETE) {
    loopback->complete_windows++;
    return ADAPTIVE_OK;
  }
  return result;
}

static void
generate_signal(float *samples, size_t count, unsigned step)
{
  size_t i;
  for(i = 0; i < count; i++) {
    double t = (double)i / (double)count;
    double drift = 0.15 * sin(2.0 * M_PI * step / 17.0);
    samples[i] = (float)(
        sin(2.0 * M_PI * 3.0 * t) +
        0.30 * cos(2.0 * M_PI * 11.0 * t) +
        0.05 * sin(2.0 * M_PI * (double)(i + step) / 7.0) +
        drift);
  }
}

static void
generate_network_parameters(adaptive_network_metrics_t *metrics,
                            unsigned step)
{
  unsigned phase = step % 24U;
  double pressure;
  if(phase < 5U) pressure = 0.15 + 0.02 * phase;
  else if(phase < 10U) pressure = 0.35 + 0.10 * (phase - 5U);
  else if(phase < 16U) pressure = 1.15 + 0.08 * (phase - 10U);
  else if(phase < 20U) pressure = 0.75 - 0.12 * (phase - 16U);
  else pressure = 0.20;

  metrics->value[ADAPTIVE_METRIC_QUEUE] = 0.08 + 0.42 * pressure;
  metrics->value[ADAPTIVE_METRIC_LOSS] = 0.01 + 0.10 * pressure;
  metrics->value[ADAPTIVE_METRIC_RTT] = 45.0 + 95.0 * pressure;
  metrics->value[ADAPTIVE_METRIC_RETRY] = 0.02 + 0.18 * pressure;
  metrics->value[ADAPTIVE_METRIC_GOODPUT] =
      18000.0 / (1.0 + 0.85 * pressure);
}

static double
rmse(const float *left, const float *right, size_t count)
{
  double sum = 0.0;
  size_t i;
  for(i = 0; i < count; i++) {
    double difference = left[i] - right[i];
    sum += difference * difference;
  }
  return sqrt(sum / (double)count);
}

static void
usage(const char *program)
{
  fprintf(stderr,
          "Usage: %s [--config PATH] [--steps N] [--oqs [ALGORITHM]]\n",
          program);
}

int
main(int argc, char **argv)
{
  adaptive_config_t config;
  adaptive_security_session_t client_security;
  adaptive_security_session_t server_security;
  adaptive_kem_info_t kem_info;
  adaptive_pipeline_t pipeline;
  loopback_t loopback;
  const char *config_path = "config/runtime.conf";
  const char *oqs_algorithm = NULL;
  unsigned steps = 36U;
  int use_oqs = 0;
  int index;
  char error[160];
  int result;

  adaptive_config_defaults(&config);
  adaptive_security_session_reset(&client_security);
  adaptive_security_session_reset(&server_security);
  memset(&kem_info, 0, sizeof(kem_info));
  memset(&loopback, 0, sizeof(loopback));

  for(index = 1; index < argc; index++) {
    if(strcmp(argv[index], "--config") == 0 && index + 1 < argc) {
      config_path = argv[++index];
    } else if(strcmp(argv[index], "--steps") == 0 && index + 1 < argc) {
      char *end = NULL;
      unsigned long parsed = strtoul(argv[++index], &end, 10);
      if(end == argv[index] || *end != '\0' || parsed == 0UL) {
        usage(argv[0]);
        return 2;
      }
      steps = (unsigned)parsed;
    } else if(strcmp(argv[index], "--oqs") == 0) {
      use_oqs = 1;
      if(index + 1 < argc && argv[index + 1][0] != '-') {
        oqs_algorithm = argv[++index];
      }
    } else {
      usage(argv[0]);
      return 2;
    }
  }

  result = adaptive_config_load(&config, config_path, error, sizeof(error));
  if(result != ADAPTIVE_OK) {
    fprintf(stderr, "configuration error: %s\n", error);
    return 1;
  }

  if(use_oqs) {
    result = adaptive_security_oqs_pair(
        &client_security, &server_security, oqs_algorithm, &kem_info);
    if(result != ADAPTIVE_OK) {
      fprintf(stderr,
              "ML-KEM provider unavailable; build with WITH_OQS=1 "
              "and install liboqs + OpenSSL\n");
      return 1;
    }
    printf("# kem=%s public_key=%zu ciphertext=%zu shared_secret=%zu\n",
           kem_info.algorithm, kem_info.public_key_bytes,
           kem_info.ciphertext_bytes, kem_info.shared_secret_bytes);
  } else {
    result = adaptive_security_test_pair(
        &client_security, &server_security,
        UINT64_C(0x6c6f7770616e2026));
    if(result != ADAPTIVE_OK) {
      fprintf(stderr, "unable to initialize test security provider\n");
      return 1;
    }
    puts("# security=test-only (not cryptographic)");
  }

  result = adaptive_pipeline_init(&pipeline, &config, &client_security);
  if(result != ADAPTIVE_OK) {
    fprintf(stderr, "pipeline initialization failed: %d\n", result);
    goto cleanup;
  }
  adaptive_receiver_init(&loopback.receiver, &server_security);
  puts("step,state,probability,compressed_bytes,blocks,block_bytes,"
       "sampling_factor,rmse");

  {
    unsigned step;
    for(step = 0; step < steps; step++) {
      float source[ADAPTIVE_MAX_WINDOW];
      adaptive_network_metrics_t metrics;
      adaptive_pipeline_stats_t stats;
      unsigned before = loopback.complete_windows;
      double error_value;
      generate_signal(source, config.window_size, step);
      generate_network_parameters(&metrics, step);
      result = adaptive_pipeline_process(
          &pipeline, source, config.window_size, &metrics,
          loopback_send, &loopback, &stats);
      if(result != ADAPTIVE_OK ||
         loopback.complete_windows != before + 1U ||
         loopback.sample_count != config.window_size) {
        fprintf(stderr, "window %u failed: %d\n", step, result);
        goto cleanup;
      }
      error_value = rmse(source, loopback.samples, config.window_size);
      printf("%u,%s,%.4f,%zu,%zu,%zu,%.3f,%.6f\n",
             step, adaptive_state_name(stats.state),
             stats.state_probability, stats.compressed_bytes,
             stats.block_count,
             adaptive_coap_block_size(stats.block_szx),
             stats.sampling_factor, error_value);
    }
  }
  result = ADAPTIVE_OK;

cleanup:
  adaptive_security_session_destroy(&client_security);
  adaptive_security_session_destroy(&server_security);
  return result == ADAPTIVE_OK ? 0 : 1;
}
