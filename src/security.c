#include "adaptive/security.h"

#include <string.h>

void
adaptive_security_session_reset(adaptive_security_session_t *session)
{
  if(session != NULL) {
    memset(session, 0, sizeof(*session));
  }
}

void
adaptive_security_session_destroy(adaptive_security_session_t *session)
{
  if(session != NULL) {
    if(session->destroy != NULL && session->context != NULL) {
      session->destroy(session->context);
    }
    adaptive_security_session_reset(session);
  }
}

int
adaptive_security_seal(adaptive_security_session_t *session,
                       const uint8_t *plaintext, size_t plaintext_length,
                       const uint8_t *aad, size_t aad_length,
                       uint8_t *record, size_t record_capacity,
                       size_t *record_length)
{
  if(session == NULL || session->seal == NULL ||
     (plaintext_length > 0U && plaintext == NULL) ||
     (aad_length > 0U && aad == NULL) || record == NULL ||
     record_length == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  return session->seal(session->context, plaintext, plaintext_length,
                       aad, aad_length, record, record_capacity,
                       record_length);
}

int
adaptive_security_open(adaptive_security_session_t *session,
                       const uint8_t *record, size_t record_length,
                       const uint8_t *aad, size_t aad_length,
                       uint8_t *plaintext, size_t plaintext_capacity,
                       size_t *plaintext_length)
{
  if(session == NULL || session->open == NULL || record == NULL ||
     (aad_length > 0U && aad == NULL) || plaintext == NULL ||
     plaintext_length == NULL) {
    return ADAPTIVE_ERR_ARGUMENT;
  }
  return session->open(session->context, record, record_length,
                       aad, aad_length, plaintext, plaintext_capacity,
                       plaintext_length);
}
