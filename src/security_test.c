#include "adaptive/security.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint64_t tx_key;
  uint64_t rx_key;
  uint64_t tx_sequence;
  uint64_t rx_highest;
  int rx_initialized;
} test_context_t;

static void
write_u64_be(uint8_t output[8], uint64_t value)
{
  unsigned i;
  for(i = 0; i < 8U; i++) {
    output[7U - i] = (uint8_t)(value >> (8U * i));
  }
}

static uint64_t
read_u64_be(const uint8_t input[8])
{
  uint64_t value = 0U;
  unsigned i;
  for(i = 0; i < 8U; i++) {
    value = (value << 8U) | input[i];
  }
  return value;
}

static uint64_t
mix64(uint64_t value)
{
  value ^= value >> 30U;
  value *= UINT64_C(0xbf58476d1ce4e5b9);
  value ^= value >> 27U;
  value *= UINT64_C(0x94d049bb133111eb);
  return value ^ (value >> 31U);
}

static uint8_t
stream_byte(uint64_t key, uint64_t sequence, size_t index)
{
  uint64_t block = mix64(key ^ sequence ^
                         ((uint64_t)(index / 8U) *
                          UINT64_C(0x9e3779b97f4a7c15)));
  return (uint8_t)(block >> (8U * (index % 8U)));
}

static uint32_t
fnv1a(uint32_t hash, const uint8_t *data, size_t length)
{
  size_t i;
  for(i = 0; i < length; i++) {
    hash ^= data[i];
    hash *= UINT32_C(16777619);
  }
  return hash;
}

static void
make_tag(uint64_t key, const uint8_t *header,
         const uint8_t *ciphertext, size_t ciphertext_length,
         const uint8_t *aad, size_t aad_length,
         uint8_t tag[ADAPTIVE_SECURITY_TAG_BYTES])
{
  unsigned lane;
  for(lane = 0; lane < 4U; lane++) {
    uint32_t hash = UINT32_C(2166136261) ^
                    (uint32_t)(key >> ((lane & 1U) * 32U)) ^
                    (lane * UINT32_C(0x9e3779b9));
    hash = fnv1a(hash, header, 1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES);
    hash = fnv1a(hash, aad, aad_length);
    hash = fnv1a(hash, ciphertext, ciphertext_length);
    tag[lane * 4U] = (uint8_t)(hash >> 24U);
    tag[lane * 4U + 1U] = (uint8_t)(hash >> 16U);
    tag[lane * 4U + 2U] = (uint8_t)(hash >> 8U);
    tag[lane * 4U + 3U] = (uint8_t)hash;
  }
}

static int
test_seal(void *context, const uint8_t *plaintext, size_t plaintext_length,
          const uint8_t *aad, size_t aad_length,
          uint8_t *record, size_t record_capacity, size_t *record_length)
{
  test_context_t *test = context;
  uint64_t sequence;
  size_t i;
  uint8_t *tag;
  if(test == NULL ||
     plaintext_length > record_capacity ||
     ADAPTIVE_SECURITY_OVERHEAD > record_capacity - plaintext_length) {
    return ADAPTIVE_ERR_CAPACITY;
  }
  sequence = test->tx_sequence++;
  record[0] = ADAPTIVE_SECURITY_RECORD_VERSION;
  write_u64_be(record + 1U, sequence);
  for(i = 0; i < plaintext_length; i++) {
    record[1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES + i] =
        plaintext[i] ^ stream_byte(test->tx_key, sequence, i);
  }
  tag = record + 1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES + plaintext_length;
  make_tag(test->tx_key, record,
           record + 1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES, plaintext_length,
           aad, aad_length, tag);
  *record_length = plaintext_length + ADAPTIVE_SECURITY_OVERHEAD;
  return ADAPTIVE_OK;
}

static int
test_open(void *context, const uint8_t *record, size_t record_length,
          const uint8_t *aad, size_t aad_length,
          uint8_t *plaintext, size_t plaintext_capacity,
          size_t *plaintext_length)
{
  test_context_t *test = context;
  uint64_t sequence;
  size_t ciphertext_length;
  uint8_t expected[ADAPTIVE_SECURITY_TAG_BYTES];
  const uint8_t *received;
  unsigned difference = 0U;
  size_t i;
  if(test == NULL || record_length < ADAPTIVE_SECURITY_OVERHEAD ||
     record[0] != ADAPTIVE_SECURITY_RECORD_VERSION) {
    return ADAPTIVE_ERR_FORMAT;
  }
  sequence = read_u64_be(record + 1U);
  if(test->rx_initialized && sequence <= test->rx_highest) {
    return ADAPTIVE_ERR_REPLAY;
  }
  ciphertext_length = record_length - ADAPTIVE_SECURITY_OVERHEAD;
  if(ciphertext_length > plaintext_capacity) {
    return ADAPTIVE_ERR_CAPACITY;
  }
  received = record + 1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES +
             ciphertext_length;
  make_tag(test->rx_key, record,
           record + 1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES, ciphertext_length,
           aad, aad_length, expected);
  for(i = 0; i < ADAPTIVE_SECURITY_TAG_BYTES; i++) {
    difference |= expected[i] ^ received[i];
  }
  if(difference != 0U) {
    return ADAPTIVE_ERR_INTEGRITY;
  }
  for(i = 0; i < ciphertext_length; i++) {
    plaintext[i] =
        record[1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES + i] ^
        stream_byte(test->rx_key, sequence, i);
  }
  test->rx_highest = sequence;
  test->rx_initialized = 1;
  *plaintext_length = ciphertext_length;
  return ADAPTIVE_OK;
}

static void
test_destroy(void *context)
{
  test_context_t *test = context;
  if(test != NULL) {
    memset(test, 0, sizeof(*test));
    free(test);
  }
}

static void
initialize_session(adaptive_security_session_t *session,
                   test_context_t *context)
{
  adaptive_security_session_reset(session);
  session->context = context;
  session->seal = test_seal;
  session->open = test_open;
  session->destroy = test_destroy;
  session->overhead = ADAPTIVE_SECURITY_OVERHEAD;
  session->production = 0;
}

int
adaptive_security_test_pair(adaptive_security_session_t *client,
                            adaptive_security_session_t *server,
                            uint64_t seed)
{
  test_context_t *client_context;
  test_context_t *server_context;
  uint64_t client_to_server;
  uint64_t server_to_client;
  if(client == NULL || server == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  client_context = calloc(1U, sizeof(*client_context));
  server_context = calloc(1U, sizeof(*server_context));
  if(client_context == NULL || server_context == NULL) {
    free(client_context);
    free(server_context);
    return ADAPTIVE_ERR_CAPACITY;
  }
  client_to_server = mix64(seed ^ UINT64_C(0x434c49454e542d54));
  server_to_client = mix64(seed ^ UINT64_C(0x5345525645522d54));
  client_context->tx_key = client_to_server;
  client_context->rx_key = server_to_client;
  server_context->tx_key = server_to_client;
  server_context->rx_key = client_to_server;
  initialize_session(client, client_context);
  initialize_session(server, server_context);
  return ADAPTIVE_OK;
}
