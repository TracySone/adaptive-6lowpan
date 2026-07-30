#include "adaptive/coap_block.h"
#include "adaptive/codec.h"
#include "adaptive/config.h"
#include "adaptive/hmm.h"
#include "adaptive/pipeline.h"
#include "adaptive/receiver.h"
#include "adaptive/security.h"
#include "adaptive/wavelet.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static unsigned failures;

#define EXPECT(CONDITION) \
  do { \
    if(!(CONDITION)) { \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #CONDITION); \
      failures++; \
    } \
  } while(0)

static void
fill_signal(float *samples, size_t count)
{
  size_t i;
  for(i = 0; i < count; i++) {
    samples[i] = (float)(
        sin(2.0 * M_PI * 3.0 * i / count) +
        0.2 * cos(2.0 * M_PI * 9.0 * i / count));
  }
}

static void
test_wavelet_roundtrip(void)
{
  float values[128];
  float original[128];
  float scratch[128];
  double maximum_error = 0.0;
  size_t i;
  fill_signal(values, 128U);
  memcpy(original, values, sizeof(values));
  EXPECT(adaptive_db4_forward(values, 128U, 3U, scratch, 128U) ==
         ADAPTIVE_OK);
  EXPECT(adaptive_db4_inverse(values, 128U, 3U, scratch, 128U) ==
         ADAPTIVE_OK);
  for(i = 0; i < 128U; i++) {
    double error = fabs(values[i] - original[i]);
    if(error > maximum_error) maximum_error = error;
  }
  EXPECT(maximum_error < 1.0e-5);
}

static void
test_codec(void)
{
  adaptive_config_t config;
  adaptive_codec_metadata_t encoded;
  adaptive_codec_metadata_t decoded;
  float source[128];
  float restored[128];
  uint8_t representation[ADAPTIVE_MAX_REPRESENTATION];
  size_t representation_length = 0U;
  size_t restored_count = 0U;
  double sum = 0.0;
  size_t i;
  adaptive_config_defaults(&config);
  config.threshold_gain[ADAPTIVE_STATE_NORMAL] = 0.25;
  config.quant_bits[ADAPTIVE_STATE_NORMAL] = 15U;
  fill_signal(source, 128U);
  EXPECT(adaptive_codec_encode(
      source, 128U, 77U, ADAPTIVE_STATE_NORMAL, &config,
      representation, sizeof(representation), &representation_length,
      &encoded) == ADAPTIVE_OK);
  EXPECT(representation_length > 28U);
  EXPECT(adaptive_codec_decode(
      representation, representation_length, restored, 128U,
      &restored_count, &decoded) == ADAPTIVE_OK);
  EXPECT(restored_count == 128U);
  EXPECT(decoded.window_id == 77U);
  for(i = 0; i < 128U; i++) {
    double difference = source[i] - restored[i];
    sum += difference * difference;
  }
  EXPECT(sqrt(sum / 128.0) < 0.15);
  representation[representation_length - 1U] ^= 1U;
  EXPECT(adaptive_codec_decode(
      representation, representation_length, restored, 128U,
      &restored_count, &decoded) == ADAPTIVE_ERR_INTEGRITY);
}

static void
test_coap(void)
{
  adaptive_coap_block_t input;
  adaptive_coap_block_t parsed;
  uint8_t payload[32];
  uint8_t packet[256];
  size_t packet_length = 0U;
  unsigned i;
  memset(&input, 0, sizeof(input));
  for(i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)i;
  input.type = ADAPTIVE_COAP_TYPE_CON;
  input.code = ADAPTIVE_COAP_CODE_POST;
  input.message_id = 0x1234U;
  input.token_length = 4U;
  memcpy(input.token, "W001", 4U);
  input.block_number = 3U;
  input.more = 1U;
  input.szx = 2U;
  input.content_format = 42U;
  input.size1 = 200U;
  input.payload = payload;
  input.payload_length = sizeof(payload);
  EXPECT(adaptive_coap_build_block1(
      &input, "/telemetry/data", packet, sizeof(packet),
      &packet_length) == ADAPTIVE_OK);
  EXPECT(adaptive_coap_parse_block1(packet, packet_length, &parsed) ==
         ADAPTIVE_OK);
  EXPECT(parsed.message_id == input.message_id);
  EXPECT(parsed.block_number == input.block_number);
  EXPECT(parsed.more == input.more);
  EXPECT(parsed.szx == input.szx);
  EXPECT(parsed.content_format == input.content_format);
  EXPECT(parsed.size1 == input.size1);
  EXPECT(parsed.payload_length == sizeof(payload));
  EXPECT(memcmp(parsed.payload, payload, sizeof(payload)) == 0);
}

static void
test_security(void)
{
  adaptive_security_session_t client;
  adaptive_security_session_t server;
  uint8_t record[128];
  uint8_t plaintext[64];
  size_t record_length = 0U;
  size_t plaintext_length = 0U;
  static const uint8_t message[] = "test message";
  static const uint8_t aad[] = "block metadata";
  adaptive_security_session_reset(&client);
  adaptive_security_session_reset(&server);
  EXPECT(adaptive_security_test_pair(
      &client, &server, UINT64_C(123456)) == ADAPTIVE_OK);
  EXPECT(adaptive_security_seal(
      &client, message, sizeof(message), aad, sizeof(aad),
      record, sizeof(record), &record_length) == ADAPTIVE_OK);
  EXPECT(adaptive_security_open(
      &server, record, record_length, aad, sizeof(aad),
      plaintext, sizeof(plaintext), &plaintext_length) == ADAPTIVE_OK);
  EXPECT(plaintext_length == sizeof(message));
  EXPECT(memcmp(plaintext, message, sizeof(message)) == 0);
  EXPECT(adaptive_security_open(
      &server, record, record_length, aad, sizeof(aad),
      plaintext, sizeof(plaintext), &plaintext_length) ==
      ADAPTIVE_ERR_REPLAY);
  adaptive_security_session_destroy(&client);
  adaptive_security_session_destroy(&server);
}

static void
test_hmm(void)
{
  adaptive_config_t config;
  adaptive_hmm_t hmm;
  adaptive_network_metrics_t observation;
  adaptive_state_t state = ADAPTIVE_STATE_NORMAL;
  double probability[ADAPTIVE_STATE_COUNT];
  unsigned step;
  unsigned index;
  adaptive_config_defaults(&config);
  EXPECT(adaptive_hmm_init(&hmm, &config) == ADAPTIVE_OK);
  for(index = 0; index < ADAPTIVE_METRIC_COUNT; index++) {
    observation.value[index] = 2.0;
  }
  for(step = 0; step < 8U; step++) {
    EXPECT(adaptive_hmm_step(&hmm, &observation, &state, probability) ==
           ADAPTIVE_OK);
  }
  EXPECT(state == ADAPTIVE_STATE_CONGESTED ||
         state == ADAPTIVE_STATE_DEGRADED);
  {
    double total = 0.0;
    for(index = 0; index < ADAPTIVE_STATE_COUNT; index++) {
      total += probability[index];
    }
    EXPECT(fabs(total - 1.0) < 1.0e-9);
  }
}

typedef struct {
  adaptive_receiver_t receiver;
  float output[ADAPTIVE_MAX_WINDOW];
  size_t output_count;
  unsigned complete;
} test_loopback_t;

static int
test_send(const uint8_t *packet, size_t packet_length, void *context)
{
  test_loopback_t *loopback = context;
  adaptive_codec_metadata_t metadata;
  int result = adaptive_receiver_accept(
      &loopback->receiver, packet, packet_length,
      loopback->output, ADAPTIVE_MAX_WINDOW,
      &loopback->output_count, &metadata);
  if(result == ADAPTIVE_COMPLETE) {
    loopback->complete++;
    return ADAPTIVE_OK;
  }
  return result;
}

static void
test_pipeline(void)
{
  adaptive_config_t config;
  adaptive_security_session_t client;
  adaptive_security_session_t server;
  adaptive_pipeline_t pipeline;
  adaptive_pipeline_stats_t stats;
  adaptive_network_metrics_t metrics = {
    { 0.1, 0.01, 40.0, 0.02, 20000.0 }
  };
  test_loopback_t loopback;
  float source[128];
  adaptive_config_defaults(&config);
  adaptive_security_session_reset(&client);
  adaptive_security_session_reset(&server);
  memset(&loopback, 0, sizeof(loopback));
  fill_signal(source, 128U);
  EXPECT(adaptive_security_test_pair(
      &client, &server, UINT64_C(987654)) == ADAPTIVE_OK);
  EXPECT(adaptive_pipeline_init(&pipeline, &config, &client) == ADAPTIVE_OK);
  adaptive_receiver_init(&loopback.receiver, &server);
  EXPECT(adaptive_pipeline_process(
      &pipeline, source, 128U, &metrics,
      test_send, &loopback, &stats) == ADAPTIVE_OK);
  EXPECT(loopback.complete == 1U);
  EXPECT(loopback.output_count == 128U);
  EXPECT(stats.block_count >= 1U);
  adaptive_security_session_destroy(&client);
  adaptive_security_session_destroy(&server);
}

int
main(void)
{
  adaptive_config_t config;
  char error[128];
  adaptive_config_defaults(&config);
  EXPECT(adaptive_config_validate(&config, error, sizeof(error)) ==
         ADAPTIVE_OK);
  EXPECT(adaptive_config_load(
      &config, "config/runtime.conf", error, sizeof(error)) == ADAPTIVE_OK);
  test_wavelet_roundtrip();
  test_codec();
  test_coap();
  test_security();
  test_hmm();
  test_pipeline();
  if(failures != 0U) {
    fprintf(stderr, "%u test assertion(s) failed\n", failures);
    return 1;
  }
  puts("all tests passed");
  return 0;
}
