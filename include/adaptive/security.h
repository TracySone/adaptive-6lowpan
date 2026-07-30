#ifndef ADAPTIVE_SECURITY_H
#define ADAPTIVE_SECURITY_H

#include "adaptive/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ADAPTIVE_SECURITY_RECORD_VERSION 1U
#define ADAPTIVE_SECURITY_SEQUENCE_BYTES 8U
#define ADAPTIVE_SECURITY_TAG_BYTES 16U
#define ADAPTIVE_SECURITY_OVERHEAD \
  (1U + ADAPTIVE_SECURITY_SEQUENCE_BYTES + ADAPTIVE_SECURITY_TAG_BYTES)

typedef struct adaptive_security_session adaptive_security_session_t;

typedef struct {
  size_t public_key_bytes;
  size_t secret_key_bytes;
  size_t ciphertext_bytes;
  size_t shared_secret_bytes;
  char algorithm[32];
} adaptive_kem_info_t;

typedef int (*adaptive_security_seal_fn)(
    void *context, const uint8_t *plaintext, size_t plaintext_length,
    const uint8_t *aad, size_t aad_length,
    uint8_t *record, size_t record_capacity, size_t *record_length);

typedef int (*adaptive_security_open_fn)(
    void *context, const uint8_t *record, size_t record_length,
    const uint8_t *aad, size_t aad_length,
    uint8_t *plaintext, size_t plaintext_capacity, size_t *plaintext_length);

typedef void (*adaptive_security_destroy_fn)(void *context);

struct adaptive_security_session {
  void *context;
  adaptive_security_seal_fn seal;
  adaptive_security_open_fn open;
  adaptive_security_destroy_fn destroy;
  size_t overhead;
  int production;
};

void adaptive_security_session_reset(adaptive_security_session_t *session);
void adaptive_security_session_destroy(adaptive_security_session_t *session);
int adaptive_security_seal(adaptive_security_session_t *session,
                           const uint8_t *plaintext, size_t plaintext_length,
                           const uint8_t *aad, size_t aad_length,
                           uint8_t *record, size_t record_capacity,
                           size_t *record_length);
int adaptive_security_open(adaptive_security_session_t *session,
                           const uint8_t *record, size_t record_length,
                           const uint8_t *aad, size_t aad_length,
                           uint8_t *plaintext, size_t plaintext_capacity,
                           size_t *plaintext_length);

/*
 * Deterministic non-cryptographic provider for tests and Cooja only.
 * It is deliberately marked production=0 and must never protect real data.
 */
int adaptive_security_test_pair(adaptive_security_session_t *client,
                                adaptive_security_session_t *server,
                                uint64_t seed);

/*
 * ML-KEM + HKDF-SHA-256 + AES-256-GCM provider.
 * Requires a build with ADAPTIVE_WITH_LIBOQS and links liboqs + OpenSSL.
 */
int adaptive_security_oqs_pair(adaptive_security_session_t *client,
                               adaptive_security_session_t *server,
                               const char *algorithm,
                               adaptive_kem_info_t *info);

#ifdef __cplusplus
}
#endif

#endif
