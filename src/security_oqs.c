#include "adaptive/security.h"

#include <string.h>

#ifndef ADAPTIVE_WITH_LIBOQS

int
adaptive_security_oqs_pair(adaptive_security_session_t *client,
                           adaptive_security_session_t *server,
                           const char *algorithm,
                           adaptive_kem_info_t *info)
{
  (void)client;
  (void)server;
  (void)algorithm;
  if(info != NULL) {
    memset(info, 0, sizeof(*info));
  }
  return ADAPTIVE_ERR_UNSUPPORTED;
}

#else

#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  uint8_t tx_key[32];
  uint8_t rx_key[32];
  uint8_t tx_nonce_base[12];
  uint8_t rx_nonce_base[12];
  uint64_t tx_sequence;
  uint64_t rx_highest;
  int rx_initialized;
} oqs_context_t;

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

static int
hkdf_expand(const uint8_t *shared, size_t shared_length,
            const uint8_t *transcript, size_t transcript_length,
            const char *label, uint8_t output[32])
{
  uint8_t salt[EVP_MAX_MD_SIZE];
  uint8_t prk[EVP_MAX_MD_SIZE];
  uint8_t info[96];
  unsigned salt_length = 0U;
  unsigned prk_length = 0U;
  unsigned output_length = 0U;
  EVP_MD_CTX *digest = NULL;
  size_t label_length = strlen(label);
  int ok = 0;
  if(label_length + 1U > sizeof(info)) return ADAPTIVE_ERR_RANGE;

  digest = EVP_MD_CTX_new();
  if(digest == NULL ||
     EVP_DigestInit_ex(digest, EVP_sha256(), NULL) != 1 ||
     EVP_DigestUpdate(digest, transcript, transcript_length) != 1 ||
     EVP_DigestFinal_ex(digest, salt, &salt_length) != 1) {
    goto cleanup;
  }
  if(HMAC(EVP_sha256(), salt, (int)salt_length,
          shared, shared_length, prk, &prk_length) == NULL) {
    goto cleanup;
  }
  memcpy(info, label, label_length);
  info[label_length] = 1U;
  if(HMAC(EVP_sha256(), prk, (int)prk_length, info, label_length + 1U,
          output, &output_length) == NULL || output_length < 32U) {
    goto cleanup;
  }
  ok = 1;

cleanup:
  if(digest != NULL) EVP_MD_CTX_free(digest);
  OPENSSL_cleanse(salt, sizeof(salt));
  OPENSSL_cleanse(prk, sizeof(prk));
  OPENSSL_cleanse(info, sizeof(info));
  return ok ? ADAPTIVE_OK : ADAPTIVE_ERR_CRYPTO;
}

static void
make_nonce(const uint8_t base[12], uint64_t sequence, uint8_t nonce[12])
{
  unsigned i;
  memcpy(nonce, base, 12U);
  for(i = 0; i < 8U; i++) {
    nonce[11U - i] ^= (uint8_t)(sequence >> (8U * i));
  }
}

static int
oqs_seal(void *context, const uint8_t *plaintext, size_t plaintext_length,
         const uint8_t *aad, size_t aad_length,
         uint8_t *record, size_t record_capacity, size_t *record_length)
{
  oqs_context_t *oqs = context;
  EVP_CIPHER_CTX *cipher = NULL;
  uint8_t nonce[12];
  uint64_t sequence;
  int length = 0;
  int final_length = 0;
  int ok = 0;
  uint8_t *ciphertext;
  uint8_t *tag;
  if(oqs == NULL || plaintext_length > INT_MAX || aad_length > INT_MAX ||
     plaintext_length > record_capacity ||
     ADAPTIVE_SECURITY_OVERHEAD > record_capacity - plaintext_length) {
    return ADAPTIVE_ERR_CAPACITY;
  }
  sequence = oqs->tx_sequence++;
  record[0] = ADAPTIVE_SECURITY_RECORD_VERSION;
  write_u64_be(record + 1U, sequence);
  ciphertext = record + 1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES;
  tag = ciphertext + plaintext_length;
  make_nonce(oqs->tx_nonce_base, sequence, nonce);

  cipher = EVP_CIPHER_CTX_new();
  if(cipher == NULL ||
     EVP_EncryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
     EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_IVLEN,
                         (int)sizeof(nonce), NULL) != 1 ||
     EVP_EncryptInit_ex(cipher, NULL, NULL, oqs->tx_key, nonce) != 1 ||
     EVP_EncryptUpdate(cipher, NULL, &length, record,
                       1 + ADAPTIVE_SECURITY_SEQUENCE_BYTES) != 1 ||
     (aad_length > 0U &&
      EVP_EncryptUpdate(cipher, NULL, &length, aad, (int)aad_length) != 1) ||
     EVP_EncryptUpdate(cipher, ciphertext, &length,
                       plaintext, (int)plaintext_length) != 1 ||
     EVP_EncryptFinal_ex(cipher, ciphertext + length, &final_length) != 1 ||
     EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG,
                         ADAPTIVE_SECURITY_TAG_BYTES, tag) != 1) {
    goto cleanup;
  }
  *record_length = plaintext_length + ADAPTIVE_SECURITY_OVERHEAD;
  ok = 1;

cleanup:
  if(cipher != NULL) EVP_CIPHER_CTX_free(cipher);
  OPENSSL_cleanse(nonce, sizeof(nonce));
  return ok ? ADAPTIVE_OK : ADAPTIVE_ERR_CRYPTO;
}

static int
oqs_open(void *context, const uint8_t *record, size_t record_length,
         const uint8_t *aad, size_t aad_length,
         uint8_t *plaintext, size_t plaintext_capacity,
         size_t *plaintext_length)
{
  oqs_context_t *oqs = context;
  EVP_CIPHER_CTX *cipher = NULL;
  uint8_t nonce[12];
  uint64_t sequence;
  size_t ciphertext_length;
  const uint8_t *ciphertext;
  const uint8_t *tag;
  int length = 0;
  int final_length = 0;
  int ok = 0;
  if(oqs == NULL || record_length < ADAPTIVE_SECURITY_OVERHEAD ||
     record[0] != ADAPTIVE_SECURITY_RECORD_VERSION ||
     aad_length > INT_MAX) {
    return ADAPTIVE_ERR_FORMAT;
  }
  sequence = read_u64_be(record + 1U);
  if(oqs->rx_initialized && sequence <= oqs->rx_highest) {
    return ADAPTIVE_ERR_REPLAY;
  }
  ciphertext_length = record_length - ADAPTIVE_SECURITY_OVERHEAD;
  if(ciphertext_length > plaintext_capacity || ciphertext_length > INT_MAX) {
    return ADAPTIVE_ERR_CAPACITY;
  }
  ciphertext = record + 1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES;
  tag = ciphertext + ciphertext_length;
  make_nonce(oqs->rx_nonce_base, sequence, nonce);

  cipher = EVP_CIPHER_CTX_new();
  if(cipher == NULL ||
     EVP_DecryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
     EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_IVLEN,
                         (int)sizeof(nonce), NULL) != 1 ||
     EVP_DecryptInit_ex(cipher, NULL, NULL, oqs->rx_key, nonce) != 1 ||
     EVP_DecryptUpdate(cipher, NULL, &length, record,
                       1 + ADAPTIVE_SECURITY_SEQUENCE_BYTES) != 1 ||
     (aad_length > 0U &&
      EVP_DecryptUpdate(cipher, NULL, &length, aad, (int)aad_length) != 1) ||
     EVP_DecryptUpdate(cipher, plaintext, &length,
                       ciphertext, (int)ciphertext_length) != 1 ||
     EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG,
                         ADAPTIVE_SECURITY_TAG_BYTES, (void *)tag) != 1 ||
     EVP_DecryptFinal_ex(cipher, plaintext + length, &final_length) != 1) {
    goto cleanup;
  }
  *plaintext_length = ciphertext_length;
  oqs->rx_highest = sequence;
  oqs->rx_initialized = 1;
  ok = 1;

cleanup:
  if(cipher != NULL) EVP_CIPHER_CTX_free(cipher);
  OPENSSL_cleanse(nonce, sizeof(nonce));
  return ok ? ADAPTIVE_OK : ADAPTIVE_ERR_INTEGRITY;
}

static void
oqs_destroy(void *context)
{
  oqs_context_t *oqs = context;
  if(oqs != NULL) {
    OPENSSL_cleanse(oqs, sizeof(*oqs));
    free(oqs);
  }
}

static int
initialize_contexts(oqs_context_t *client, oqs_context_t *server,
                    const uint8_t *shared, size_t shared_length,
                    const uint8_t *transcript, size_t transcript_length)
{
  uint8_t c2s_key[32];
  uint8_t s2c_key[32];
  uint8_t c2s_nonce[32];
  uint8_t s2c_nonce[32];
  int result;
#define EXPAND(LABEL, TARGET) \
  do { \
    result = hkdf_expand(shared, shared_length, transcript, transcript_length, \
                         LABEL, TARGET); \
    if(result != ADAPTIVE_OK) goto cleanup; \
  } while(0)
  EXPAND("adaptive/c2s/key", c2s_key);
  EXPAND("adaptive/s2c/key", s2c_key);
  EXPAND("adaptive/c2s/nonce", c2s_nonce);
  EXPAND("adaptive/s2c/nonce", s2c_nonce);
  memcpy(client->tx_key, c2s_key, 32U);
  memcpy(client->rx_key, s2c_key, 32U);
  memcpy(server->tx_key, s2c_key, 32U);
  memcpy(server->rx_key, c2s_key, 32U);
  memcpy(client->tx_nonce_base, c2s_nonce, 12U);
  memcpy(client->rx_nonce_base, s2c_nonce, 12U);
  memcpy(server->tx_nonce_base, s2c_nonce, 12U);
  memcpy(server->rx_nonce_base, c2s_nonce, 12U);
  result = ADAPTIVE_OK;
cleanup:
  OPENSSL_cleanse(c2s_key, sizeof(c2s_key));
  OPENSSL_cleanse(s2c_key, sizeof(s2c_key));
  OPENSSL_cleanse(c2s_nonce, sizeof(c2s_nonce));
  OPENSSL_cleanse(s2c_nonce, sizeof(s2c_nonce));
  return result;
#undef EXPAND
}

static void
set_session(adaptive_security_session_t *session, oqs_context_t *context)
{
  adaptive_security_session_reset(session);
  session->context = context;
  session->seal = oqs_seal;
  session->open = oqs_open;
  session->destroy = oqs_destroy;
  session->overhead = ADAPTIVE_SECURITY_OVERHEAD;
  session->production = 1;
}

int
adaptive_security_oqs_pair(adaptive_security_session_t *client,
                           adaptive_security_session_t *server,
                           const char *algorithm,
                           adaptive_kem_info_t *info)
{
  OQS_KEM *kem = NULL;
  uint8_t *public_key = NULL;
  uint8_t *secret_key = NULL;
  uint8_t *ciphertext = NULL;
  uint8_t *client_shared = NULL;
  uint8_t *server_shared = NULL;
  oqs_context_t *client_context = NULL;
  oqs_context_t *server_context = NULL;
  int result = ADAPTIVE_ERR_CRYPTO;
  const char *selected = algorithm != NULL ? algorithm : OQS_KEM_alg_ml_kem_512;

  if(client == NULL || server == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  kem = OQS_KEM_new(selected);
  if(kem == NULL) {
    return ADAPTIVE_ERR_UNSUPPORTED;
  }
  public_key = malloc(kem->length_public_key);
  secret_key = malloc(kem->length_secret_key);
  ciphertext = malloc(kem->length_ciphertext);
  client_shared = malloc(kem->length_shared_secret);
  server_shared = malloc(kem->length_shared_secret);
  client_context = calloc(1U, sizeof(*client_context));
  server_context = calloc(1U, sizeof(*server_context));
  if(public_key == NULL || secret_key == NULL || ciphertext == NULL ||
     client_shared == NULL || server_shared == NULL ||
     client_context == NULL || server_context == NULL) {
    result = ADAPTIVE_ERR_CAPACITY;
    goto cleanup;
  }
  if(OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS ||
     OQS_KEM_encaps(kem, ciphertext, client_shared, public_key) != OQS_SUCCESS ||
     OQS_KEM_decaps(kem, server_shared, ciphertext, secret_key) != OQS_SUCCESS ||
     CRYPTO_memcmp(client_shared, server_shared,
                   kem->length_shared_secret) != 0) {
    goto cleanup;
  }
  result = initialize_contexts(client_context, server_context,
                               client_shared, kem->length_shared_secret,
                               ciphertext, kem->length_ciphertext);
  if(result != ADAPTIVE_OK) goto cleanup;
  set_session(client, client_context);
  set_session(server, server_context);
  client_context = NULL;
  server_context = NULL;
  if(info != NULL) {
    memset(info, 0, sizeof(*info));
    info->public_key_bytes = kem->length_public_key;
    info->secret_key_bytes = kem->length_secret_key;
    info->ciphertext_bytes = kem->length_ciphertext;
    info->shared_secret_bytes = kem->length_shared_secret;
    (void)snprintf(info->algorithm, sizeof(info->algorithm), "%s",
                   kem->method_name);
  }
  result = ADAPTIVE_OK;

cleanup:
  if(secret_key != NULL) OQS_MEM_secure_free(secret_key, kem->length_secret_key);
  if(client_shared != NULL)
    OQS_MEM_secure_free(client_shared, kem->length_shared_secret);
  if(server_shared != NULL)
    OQS_MEM_secure_free(server_shared, kem->length_shared_secret);
  free(public_key);
  free(ciphertext);
  oqs_destroy(client_context);
  oqs_destroy(server_context);
  OQS_KEM_free(kem);
  return result;
}

#endif
