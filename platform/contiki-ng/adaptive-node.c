#include "contiki.h"
#include "coap-blocking-api.h"
#include "coap-engine.h"

#include "adaptive/codec.h"
#include "adaptive/config.h"
#include "adaptive/hmm.h"
#include "adaptive/metrics.h"
#include "adaptive/pipeline.h"
#include "adaptive/security.h"
#include "contiki-port.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef ADAPTIVE_SERVER_EP
#define ADAPTIVE_SERVER_EP "coap://[fe80::212:7402:2:202]"
#endif

#ifndef ADAPTIVE_SEND_INTERVAL
#define ADAPTIVE_SEND_INTERVAL (15 * CLOCK_SECOND)
#endif

#define ADAPTIVE_TEST_SEED UINT64_C(0x6c6f7770616e2026)

PROCESS(adaptive_node_process, "Adaptive telemetry node");
AUTOSTART_PROCESSES(&adaptive_node_process);

static int response_ok;

static void
response_handler(coap_message_t *response)
{
  response_ok =
      response != NULL && response->code >= 64U && response->code < 96U;
}

static void
write_u32_be(uint8_t output[4], uint32_t value)
{
  output[0] = (uint8_t)(value >> 24U);
  output[1] = (uint8_t)(value >> 16U);
  output[2] = (uint8_t)(value >> 8U);
  output[3] = (uint8_t)value;
}

PROCESS_THREAD(adaptive_node_process, ev, data)
{
  static struct etimer timer;
  static coap_endpoint_t server_ep;
  static coap_message_t request[1];
  static adaptive_config_t config;
  static adaptive_normalizer_t normalizer;
  static adaptive_hmm_t hmm;
  static adaptive_contiki_observer_t observer;
  static adaptive_security_session_t client_security;
  static adaptive_security_session_t unused_server_security;
  static adaptive_network_metrics_t raw_metrics;
  static adaptive_network_metrics_t normalized_metrics;
  static adaptive_state_t state;
  static double state_probability[ADAPTIVE_STATE_COUNT];
  static float samples[ADAPTIVE_MAX_WINDOW];
  static uint8_t representation[ADAPTIVE_MAX_REPRESENTATION];
  static uint8_t record[ADAPTIVE_MAX_BLOCK_SIZE];
  static uint8_t aad[16];
  static size_t representation_length;
  static size_t representation_offset;
  static size_t plaintext_capacity;
  static size_t plaintext_length;
  static size_t record_length;
  static size_t block_count;
  static size_t protected_size;
  static size_t block_size;
  static uint32_t window_id;
  static uint32_t block_number;
  static uint8_t more;
  static clock_time_t send_started;
  static int result;

  PROCESS_BEGIN();

  (void)ev;
  (void)data;
  adaptive_config_defaults(&config);
  adaptive_normalizer_init(&normalizer, config.baseline_alpha,
                           config.baseline_epsilon);
  adaptive_hmm_init(&hmm, &config);
  adaptive_contiki_observer_init(&observer);
  adaptive_security_session_reset(&client_security);
  adaptive_security_session_reset(&unused_server_security);
  result = adaptive_security_test_pair(
      &client_security, &unused_server_security, ADAPTIVE_TEST_SEED);
  adaptive_security_session_destroy(&unused_server_security);
  if(result != ADAPTIVE_OK) {
    puts("security initialization failed");
    PROCESS_EXIT();
  }
  coap_endpoint_parse(ADAPTIVE_SERVER_EP, strlen(ADAPTIVE_SERVER_EP),
                      &server_ep);
  window_id = 1U;
  etimer_set(&timer, ADAPTIVE_SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    adaptive_platform_read_window(samples, config.window_size, window_id);
    adaptive_contiki_metrics_snapshot(&observer, &raw_metrics);
    result = adaptive_normalizer_update(
        &normalizer, &raw_metrics, &normalized_metrics);
    if(result == ADAPTIVE_OK) {
      result = adaptive_hmm_step(
          &hmm, &normalized_metrics, &state, state_probability);
    }
    if(result == ADAPTIVE_OK) {
      result = adaptive_codec_encode(
          samples, config.window_size, window_id, state, &config,
          representation, sizeof(representation), &representation_length,
          NULL);
    }
    if(result != ADAPTIVE_OK) {
      printf("encode error %d\n", result);
      etimer_reset(&timer);
      continue;
    }

    block_size = adaptive_coap_block_size(config.block_szx[state]);
    if(block_size <= client_security.overhead) {
      puts("configured Block1 size is too small");
      etimer_reset(&timer);
      continue;
    }
    plaintext_capacity = block_size - client_security.overhead;
    block_count =
        (representation_length + plaintext_capacity - 1U) /
        plaintext_capacity;
    protected_size =
        representation_length + block_count * client_security.overhead;
    representation_offset = 0U;
    block_number = 0U;

    while(representation_offset < representation_length) {
      adaptive_coap_block_t aad_block;
      size_t remaining = representation_length - representation_offset;
      plaintext_length =
          remaining < plaintext_capacity ? remaining : plaintext_capacity;
      more = representation_offset + plaintext_length <
             representation_length;
      memset(&aad_block, 0, sizeof(aad_block));
      aad_block.type = COAP_TYPE_CON;
      aad_block.code = COAP_POST;
      aad_block.token_length = 4U;
      write_u32_be(aad_block.token, window_id);
      aad_block.block_number = block_number;
      aad_block.more = more;
      aad_block.szx = config.block_szx[state];
      aad_block.content_format = config.content_format;
      adaptive_pipeline_build_aad(&aad_block, aad);
      result = adaptive_security_seal(
          &client_security, representation + representation_offset,
          plaintext_length, aad, sizeof(aad),
          record, sizeof(record), &record_length);
      if(result != ADAPTIVE_OK) {
        printf("seal error %d\n", result);
        break;
      }

      coap_init_message(request, COAP_TYPE_CON, COAP_POST, 0);
      coap_set_token(request, aad_block.token, aad_block.token_length);
      coap_set_header_uri_path(request, config.uri_path);
      coap_set_header_content_format(request, config.content_format);
      coap_set_header_block1(request, block_number, more, block_size);
      coap_set_header_size1(request, protected_size);
      coap_set_payload(request, record, record_length);
      response_ok = 0;
      send_started = clock_time();
      COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);
      adaptive_contiki_observer_record(
          &observer, clock_time() - send_started, response_ok, record_length);
      if(!response_ok) {
        puts("Block1 request timed out or was rejected");
        break;
      }
      representation_offset += plaintext_length;
      block_number++;
    }
    printf("window=%lu state=%s p=%u/100 blocks=%lu bytes=%lu\n",
           (unsigned long)window_id, adaptive_state_name(state),
           (unsigned)(state_probability[state] * 100.0),
           (unsigned long)block_count,
           (unsigned long)representation_length);
    window_id++;
    etimer_reset(&timer);
  }

  PROCESS_END();
}
