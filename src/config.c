#include "adaptive/config.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
set_error(char *error, size_t capacity, const char *message)
{
  if(error != NULL && capacity > 0U) {
    (void)snprintf(error, capacity, "%s", message);
  }
}

static char *
trim(char *text)
{
  char *end;
  while(*text != '\0' && isspace((unsigned char)*text)) {
    text++;
  }
  if(*text == '\0') {
    return text;
  }
  end = text + strlen(text) - 1;
  while(end > text && isspace((unsigned char)*end)) {
    *end-- = '\0';
  }
  return text;
}

static int
parse_double(const char *text, double *value)
{
  char *end = NULL;
  double parsed;
  errno = 0;
  parsed = strtod(text, &end);
  if(errno != 0 || end == text || *trim(end) != '\0' || !isfinite(parsed)) {
    return ADAPTIVE_ERR_FORMAT;
  }
  *value = parsed;
  return ADAPTIVE_OK;
}

static int
parse_unsigned(const char *text, unsigned long *value)
{
  char *end = NULL;
  unsigned long parsed;
  errno = 0;
  parsed = strtoul(text, &end, 10);
  if(errno != 0 || end == text || *trim(end) != '\0') {
    return ADAPTIVE_ERR_FORMAT;
  }
  *value = parsed;
  return ADAPTIVE_OK;
}

static void
initialize_emissions(adaptive_config_t *config)
{
  static const double center[ADAPTIVE_STATE_COUNT] = {
    -1.0, 0.0, 0.75, 1.5, 0.25
  };
  unsigned state;
  unsigned metric;
  for(state = 0; state < ADAPTIVE_STATE_COUNT; state++) {
    for(metric = 0; metric < ADAPTIVE_METRIC_COUNT; metric++) {
      config->emission_mean[state][metric] = center[state];
      config->emission_variance[state][metric] = 1.0;
    }
  }
}

void
adaptive_config_defaults(adaptive_config_t *config)
{
  static const double transition[ADAPTIVE_STATE_COUNT][ADAPTIVE_STATE_COUNT] = {
    { 0.75, 0.20, 0.04, 0.01, 0.00 },
    { 0.10, 0.70, 0.16, 0.04, 0.00 },
    { 0.02, 0.12, 0.60, 0.26, 0.00 },
    { 0.00, 0.00, 0.02, 0.76, 0.22 },
    { 0.04, 0.36, 0.20, 0.05, 0.35 }
  };
  static const double threshold_gain[ADAPTIVE_STATE_COUNT] = {
    0.75, 1.00, 1.35, 2.00, 1.20
  };
  static const unsigned quant_bits[ADAPTIVE_STATE_COUNT] = {
    14U, 12U, 10U, 8U, 10U
  };
  static const uint8_t block_szx[ADAPTIVE_STATE_COUNT] = {
    2U, 2U, 1U, 1U, 1U
  };
  static const double sampling_factor[ADAPTIVE_STATE_COUNT] = {
    1.00, 1.00, 0.80, 0.50, 0.75
  };
  unsigned i;

  if(config == NULL) {
    return;
  }
  memset(config, 0, sizeof(*config));
  config->baseline_alpha = 0.04;
  config->baseline_epsilon = 1.0e-9;
  config->emission_alpha = 0.025;
  config->transition_forgetting = 0.995;
  config->transition_smoothing = 0.25;
  config->transition_prior_strength = 8.0;
  config->min_emission_variance = 0.05;
  config->recovery_hold = 3U;
  config->initial_probability[ADAPTIVE_STATE_NORMAL] = 1.0;
  memcpy(config->transition_prior, transition, sizeof(transition));
  initialize_emissions(config);
  config->window_size = 128U;
  config->wavelet_levels = 3U;
  memcpy(config->threshold_gain, threshold_gain, sizeof(threshold_gain));
  memcpy(config->quant_bits, quant_bits, sizeof(quant_bits));
  memcpy(config->block_szx, block_szx, sizeof(block_szx));
  memcpy(config->sampling_factor, sampling_factor, sizeof(sampling_factor));
  (void)snprintf(config->uri_path, sizeof(config->uri_path), "%s",
                 "telemetry");
  config->content_format = 42U;

  for(i = 0; i < ADAPTIVE_METRIC_COUNT; i++) {
    config->emission_mean[ADAPTIVE_STATE_RECOVERY][i] =
        config->emission_mean[ADAPTIVE_STATE_NORMAL][i] + 0.25;
  }
}

static int
set_state_value(const char *key, const char *prefix, const char *value,
                double target[ADAPTIVE_STATE_COUNT])
{
  adaptive_state_t state;
  double parsed;
  size_t prefix_length = strlen(prefix);
  if(strncmp(key, prefix, prefix_length) != 0) {
    return 0;
  }
  if(adaptive_state_from_name(key + prefix_length, &state) != ADAPTIVE_OK ||
     parse_double(value, &parsed) != ADAPTIVE_OK) {
    return ADAPTIVE_ERR_FORMAT;
  }
  target[state] = parsed;
  return 1;
}

static int
set_state_unsigned(const char *key, const char *prefix, const char *value,
                   unsigned target[ADAPTIVE_STATE_COUNT])
{
  adaptive_state_t state;
  unsigned long parsed;
  size_t prefix_length = strlen(prefix);
  if(strncmp(key, prefix, prefix_length) != 0) {
    return 0;
  }
  if(adaptive_state_from_name(key + prefix_length, &state) != ADAPTIVE_OK ||
     parse_unsigned(value, &parsed) != ADAPTIVE_OK) {
    return ADAPTIVE_ERR_FORMAT;
  }
  target[state] = (unsigned)parsed;
  return 1;
}

static int
set_state_u8(const char *key, const char *prefix, const char *value,
             uint8_t target[ADAPTIVE_STATE_COUNT])
{
  adaptive_state_t state;
  unsigned long parsed;
  size_t prefix_length = strlen(prefix);
  if(strncmp(key, prefix, prefix_length) != 0) {
    return 0;
  }
  if(adaptive_state_from_name(key + prefix_length, &state) != ADAPTIVE_OK ||
     parse_unsigned(value, &parsed) != ADAPTIVE_OK || parsed > 255UL) {
    return ADAPTIVE_ERR_FORMAT;
  }
  target[state] = (uint8_t)parsed;
  return 1;
}

static int
set_matrix_value(const char *key, const char *prefix, const char *value,
                 double target[ADAPTIVE_STATE_COUNT][ADAPTIVE_STATE_COUNT])
{
  char names[64];
  char *dot;
  adaptive_state_t row;
  adaptive_state_t column;
  double parsed;
  size_t prefix_length = strlen(prefix);
  if(strncmp(key, prefix, prefix_length) != 0) {
    return 0;
  }
  if(strlen(key + prefix_length) >= sizeof(names)) {
    return ADAPTIVE_ERR_FORMAT;
  }
  (void)snprintf(names, sizeof(names), "%s", key + prefix_length);
  dot = strchr(names, '.');
  if(dot == NULL) {
    return ADAPTIVE_ERR_FORMAT;
  }
  *dot++ = '\0';
  if(adaptive_state_from_name(names, &row) != ADAPTIVE_OK ||
     adaptive_state_from_name(dot, &column) != ADAPTIVE_OK ||
     parse_double(value, &parsed) != ADAPTIVE_OK) {
    return ADAPTIVE_ERR_FORMAT;
  }
  target[row][column] = parsed;
  return 1;
}

static int
set_emission_value(const char *key, const char *prefix, const char *value,
                   double target[ADAPTIVE_STATE_COUNT][ADAPTIVE_METRIC_COUNT])
{
  char names[64];
  char *dot;
  adaptive_state_t state;
  adaptive_metric_t metric;
  double parsed;
  size_t prefix_length = strlen(prefix);
  if(strncmp(key, prefix, prefix_length) != 0) {
    return 0;
  }
  if(strlen(key + prefix_length) >= sizeof(names)) {
    return ADAPTIVE_ERR_FORMAT;
  }
  (void)snprintf(names, sizeof(names), "%s", key + prefix_length);
  dot = strchr(names, '.');
  if(dot == NULL) {
    return ADAPTIVE_ERR_FORMAT;
  }
  *dot++ = '\0';
  if(adaptive_state_from_name(names, &state) != ADAPTIVE_OK ||
     adaptive_metric_from_name(dot, &metric) != ADAPTIVE_OK ||
     parse_double(value, &parsed) != ADAPTIVE_OK) {
    return ADAPTIVE_ERR_FORMAT;
  }
  target[state][metric] = parsed;
  return 1;
}

static int
apply_key(adaptive_config_t *config, const char *key, const char *value)
{
  double parsed;
  unsigned long unsigned_value;
  int handled;

#define SET_DOUBLE(KEY, FIELD) \
  if(strcmp(key, KEY) == 0) { \
    if(parse_double(value, &parsed) != ADAPTIVE_OK) return ADAPTIVE_ERR_FORMAT; \
    config->FIELD = parsed; \
    return 1; \
  }
#define SET_UNSIGNED(KEY, FIELD) \
  if(strcmp(key, KEY) == 0) { \
    if(parse_unsigned(value, &unsigned_value) != ADAPTIVE_OK) \
      return ADAPTIVE_ERR_FORMAT; \
    config->FIELD = (unsigned)unsigned_value; \
    return 1; \
  }

  SET_DOUBLE("baseline.alpha", baseline_alpha)
  SET_DOUBLE("baseline.epsilon", baseline_epsilon)
  SET_DOUBLE("hmm.emission_alpha", emission_alpha)
  SET_DOUBLE("hmm.transition_forgetting", transition_forgetting)
  SET_DOUBLE("hmm.transition_smoothing", transition_smoothing)
  SET_DOUBLE("hmm.transition_prior_strength", transition_prior_strength)
  SET_DOUBLE("hmm.min_variance", min_emission_variance)
  SET_UNSIGNED("hmm.recovery_hold", recovery_hold)

  if(strcmp(key, "wavelet.window_size") == 0) {
    if(parse_unsigned(value, &unsigned_value) != ADAPTIVE_OK) {
      return ADAPTIVE_ERR_FORMAT;
    }
    config->window_size = (size_t)unsigned_value;
    return 1;
  }
  SET_UNSIGNED("wavelet.levels", wavelet_levels)
  SET_UNSIGNED("coap.content_format", content_format)

  if(strcmp(key, "coap.uri_path") == 0) {
    if(strlen(value) > ADAPTIVE_MAX_URI_PATH) {
      return ADAPTIVE_ERR_RANGE;
    }
    (void)snprintf(config->uri_path, sizeof(config->uri_path), "%s", value);
    return 1;
  }

  handled = set_state_value(key, "hmm.initial.", value,
                            config->initial_probability);
  if(handled != 0) return handled;
  handled = set_state_value(key, "policy.threshold_gain.", value,
                            config->threshold_gain);
  if(handled != 0) return handled;
  handled = set_state_unsigned(key, "policy.quant_bits.", value,
                               config->quant_bits);
  if(handled != 0) return handled;
  handled = set_state_u8(key, "policy.block_szx.", value,
                         config->block_szx);
  if(handled != 0) return handled;
  handled = set_state_value(key, "policy.sampling_factor.", value,
                            config->sampling_factor);
  if(handled != 0) return handled;
  handled = set_matrix_value(key, "hmm.transition.", value,
                             config->transition_prior);
  if(handled != 0) return handled;
  handled = set_emission_value(key, "hmm.mean.", value,
                               config->emission_mean);
  if(handled != 0) return handled;
  handled = set_emission_value(key, "hmm.variance.", value,
                               config->emission_variance);
  if(handled != 0) return handled;

#undef SET_DOUBLE
#undef SET_UNSIGNED
  return 0;
}

int
adaptive_config_load(adaptive_config_t *config, const char *path,
                     char *error, size_t error_capacity)
{
  FILE *file;
  char line[256];
  unsigned line_number = 0U;

  if(config == NULL || path == NULL) {
    set_error(error, error_capacity, "config and path are required");
    return ADAPTIVE_ERR_ARGUMENT;
  }
  file = fopen(path, "r");
  if(file == NULL) {
    set_error(error, error_capacity, "unable to open configuration file");
    return ADAPTIVE_ERR_IO;
  }

  while(fgets(line, sizeof(line), file) != NULL) {
    char *key;
    char *value;
    char *separator;
    char *comment;
    int result;
    line_number++;
    comment = strchr(line, '#');
    if(comment != NULL) {
      *comment = '\0';
    }
    key = trim(line);
    if(*key == '\0') {
      continue;
    }
    separator = strchr(key, '=');
    if(separator == NULL) {
      (void)snprintf(line, sizeof(line), "line %u: expected key=value",
                     line_number);
      set_error(error, error_capacity, line);
      (void)fclose(file);
      return ADAPTIVE_ERR_FORMAT;
    }
    *separator++ = '\0';
    key = trim(key);
    value = trim(separator);
    result = apply_key(config, key, value);
    if(result <= 0) {
      (void)snprintf(line, sizeof(line), "line %u: invalid key or value",
                     line_number);
      set_error(error, error_capacity, line);
      (void)fclose(file);
      return result < 0 ? result : ADAPTIVE_ERR_FORMAT;
    }
  }
  if(ferror(file)) {
    set_error(error, error_capacity, "error while reading configuration");
    (void)fclose(file);
    return ADAPTIVE_ERR_IO;
  }
  (void)fclose(file);
  return adaptive_config_validate(config, error, error_capacity);
}

static int
is_power_of_two(size_t value)
{
  return value != 0U && (value & (value - 1U)) == 0U;
}

int
adaptive_config_validate(const adaptive_config_t *config,
                         char *error, size_t error_capacity)
{
  unsigned state;
  unsigned metric;
  double total = 0.0;

  if(config == NULL) {
    set_error(error, error_capacity, "configuration is required");
    return ADAPTIVE_ERR_ARGUMENT;
  }
  if(config->baseline_alpha <= 0.0 || config->baseline_alpha >= 1.0 ||
     config->emission_alpha <= 0.0 || config->emission_alpha >= 1.0 ||
     config->transition_forgetting <= 0.0 ||
     config->transition_forgetting > 1.0 ||
     config->transition_smoothing < 0.0 ||
     config->transition_prior_strength <= 0.0 ||
     config->min_emission_variance <= 0.0) {
    set_error(error, error_capacity, "invalid adaptive learning parameter");
    return ADAPTIVE_ERR_RANGE;
  }
  if(!is_power_of_two(config->window_size) ||
     config->window_size > ADAPTIVE_MAX_WINDOW ||
     config->wavelet_levels == 0U ||
     config->wavelet_levels >= sizeof(size_t) * 8U ||
     (config->window_size >> (config->wavelet_levels - 1U)) < 8U) {
    set_error(error, error_capacity, "invalid wavelet window or level");
    return ADAPTIVE_ERR_RANGE;
  }
  if(config->uri_path[0] == '\0') {
    set_error(error, error_capacity, "CoAP URI path must not be empty");
    return ADAPTIVE_ERR_RANGE;
  }

  for(state = 0; state < ADAPTIVE_STATE_COUNT; state++) {
    double row = 0.0;
    total += config->initial_probability[state];
    if(config->threshold_gain[state] < 0.0 ||
       config->quant_bits[state] < 2U || config->quant_bits[state] > 15U ||
       config->block_szx[state] > 6U ||
       config->sampling_factor[state] <= 0.0 ||
       config->sampling_factor[state] > 1.0) {
      set_error(error, error_capacity, "invalid state policy");
      return ADAPTIVE_ERR_RANGE;
    }
    for(metric = 0; metric < ADAPTIVE_METRIC_COUNT; metric++) {
      if(config->emission_variance[state][metric] <= 0.0) {
        set_error(error, error_capacity, "emission variance must be positive");
        return ADAPTIVE_ERR_RANGE;
      }
    }
    for(metric = 0; metric < ADAPTIVE_STATE_COUNT; metric++) {
      if(config->transition_prior[state][metric] < 0.0) {
        set_error(error, error_capacity, "negative transition probability");
        return ADAPTIVE_ERR_RANGE;
      }
      row += config->transition_prior[state][metric];
    }
    if(row <= 0.0) {
      set_error(error, error_capacity, "transition row must have mass");
      return ADAPTIVE_ERR_RANGE;
    }
  }
  if(total <= 0.0) {
    set_error(error, error_capacity, "initial probabilities must have mass");
    return ADAPTIVE_ERR_RANGE;
  }
  return ADAPTIVE_OK;
}
