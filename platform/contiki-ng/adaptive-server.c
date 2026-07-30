#include "contiki.h"
#include "coap-engine.h"

#include "adaptive/codec.h"
#include "adaptive/coap_block.h"
#include "adaptive/pipeline.h"
#include "adaptive/security.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ADAPTIVE_TEST_SEED UINT64_C(0x6c6f7770616e2026)
#define ADAPTIVE_REQUEST_ENTITY_INCOMPLETE_4_08 136U

PROCESS(adaptive_server_process, "Adaptive telemetry server");
AUTOSTART_PROCESSES(&adaptive_server_process);

static adaptive_security_session_t server_security;
static uint8_t representation[ADAPTIVE_MAX_REPRESENTATION];
static size_t representation_length;
static uint32_t next_block;
static uint8_t active_token[8];
static size_t active_token_length;
static int transfer_active;
static uint8_t plaintext[ADAPTIVE_MAX_BLOCK_SIZE];
static float decoded_samples[ADAPTIVE_MAX_WINDOW];
static uint8_t aad[16];

static int
szx_from_size(uint16_t size, uint8_t *szx)
{
  uint8_t candidate;
  for(candidate = 0U; candidate <= 6U; candidate++) {
    if(adaptive_coap_block_size(candidate) == size) {
      *szx = candidate;
      return ADAPTIVE_OK;
    }
  }
  return ADAPTIVE_ERR_RANGE;
}

static void
telemetry_post_handler(coap_message_t *request,
                       coap_message_t *response,
                       uint8_t *buffer, uint16_t preferred_size,
                       int32_t *offset)
{
  adaptive_coap_block_t block;
  adaptive_codec_metadata_t metadata;
  const uint8_t *payload = NULL;
  size_t payload_length;
  size_t plaintext_length;
  size_t sample_count;
  uint32_t number;
  uint32_t block_offset;
  uint16_t size;
  uint8_t more;
  uint8_t szx;
  unsigned content_format = 0U;
  int payload_result;
  int result;
  (void)buffer;
  (void)preferred_size;
  (void)offset;

  payload_result = coap_get_payload(request, &payload);
  payload_length = payload_result > 0 ? (size_t)payload_result : 0U;
  if(!coap_get_header_block1(
         request, &number, &more, &size, &block_offset) ||
     payload == NULL || payload_length == 0U ||
     szx_from_size(size, &szx) != ADAPTIVE_OK ||
     request->token_len == 0U || request->token_len > sizeof(active_token)) {
    coap_set_status_code(response, BAD_REQUEST_4_00);
    return;
  }
  (void)block_offset;
  (void)coap_get_header_content_format(request, &content_format);
  memset(&block, 0, sizeof(block));
  block.type = request->type;
  block.code = request->code;
  block.token_length = request->token_len;
  memcpy(block.token, request->token, request->token_len);
  block.block_number = number;
  block.more = more;
  block.szx = szx;
  block.content_format = content_format;
  adaptive_pipeline_build_aad(&block, aad);

  if(number == 0U) {
    representation_length = 0U;
    next_block = 0U;
    active_token_length = request->token_len;
    memcpy(active_token, request->token, request->token_len);
    transfer_active = 1;
  }
  if(!transfer_active || number != next_block ||
     request->token_len != active_token_length ||
     memcmp(request->token, active_token, active_token_length) != 0) {
    coap_set_status_code(response,
                         ADAPTIVE_REQUEST_ENTITY_INCOMPLETE_4_08);
    return;
  }
  result = adaptive_security_open(
      &server_security, payload, payload_length, aad, sizeof(aad),
      plaintext, sizeof(plaintext), &plaintext_length);
  if(result != ADAPTIVE_OK ||
     plaintext_length > sizeof(representation) - representation_length) {
    coap_set_status_code(response, UNAUTHORIZED_4_01);
    return;
  }
  memcpy(representation + representation_length, plaintext, plaintext_length);
  representation_length += plaintext_length;
  next_block++;
  coap_set_header_block1(response, number, more, size);
  if(more) {
    coap_set_status_code(response, CONTINUE_2_31);
    return;
  }

  result = adaptive_codec_decode(
      representation, representation_length,
      decoded_samples, ADAPTIVE_MAX_WINDOW, &sample_count, &metadata);
  if(result != ADAPTIVE_OK) {
    coap_set_status_code(response, BAD_REQUEST_4_00);
    return;
  }
  transfer_active = 0;
  printf("decoded window=%lu state=%s samples=%lu coefficients=%lu\n",
         (unsigned long)metadata.window_id,
         adaptive_state_name(metadata.state),
         (unsigned long)sample_count,
         (unsigned long)metadata.nonzero_coefficients);
  coap_set_status_code(response, CHANGED_2_04);
}

RESOURCE(res_telemetry,
         "title=\"Adaptive db4 telemetry\";rt=\"application/octet-stream\"",
         NULL, telemetry_post_handler, NULL, NULL);

PROCESS_THREAD(adaptive_server_process, ev, data)
{
  static adaptive_security_session_t unused_client_security;
  static int result;
  PROCESS_BEGIN();
  (void)ev;
  (void)data;
  adaptive_security_session_reset(&unused_client_security);
  adaptive_security_session_reset(&server_security);
  result = adaptive_security_test_pair(
      &unused_client_security, &server_security, ADAPTIVE_TEST_SEED);
  adaptive_security_session_destroy(&unused_client_security);
  if(result != ADAPTIVE_OK) {
    puts("security initialization failed");
    PROCESS_EXIT();
  }
  coap_activate_resource(&res_telemetry, "telemetry");
  puts("adaptive telemetry server ready");
  while(1) {
    PROCESS_YIELD();
  }
  PROCESS_END();
}
