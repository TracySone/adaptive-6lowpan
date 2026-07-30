CC ?= cc
AR ?= ar
BUILD_DIR ?= build
WITH_OQS ?= 0
SANITIZE ?= 0

CPPFLAGS += -Iinclude
CFLAGS += -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror -MMD -MP
LDLIBS += -lm

ifeq ($(SANITIZE),1)
CFLAGS += -O1 -fno-omit-frame-pointer -fsanitize=undefined,bounds
LDFLAGS += -fsanitize=undefined,bounds
endif

ifeq ($(WITH_OQS),1)
OQS_CFLAGS := $(shell pkg-config --cflags liboqs 2>/dev/null)
OQS_LIBS := $(shell pkg-config --libs liboqs 2>/dev/null)
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(strip $(OQS_LIBS)),)
$(error WITH_OQS=1 requires a pkg-config-visible liboqs installation)
endif
ifeq ($(strip $(OPENSSL_LIBS)),)
$(error WITH_OQS=1 requires OpenSSL development libraries)
endif
CPPFLAGS += -DADAPTIVE_WITH_LIBOQS $(OQS_CFLAGS) $(OPENSSL_CFLAGS)
LDLIBS += $(OQS_LIBS) $(OPENSSL_LIBS)
endif

CORE_SOURCES := \
	src/types.c \
	src/config.c \
	src/metrics.c \
	src/hmm.c \
	src/wavelet_db4.c \
	src/codec.c \
	src/coap_block.c \
	src/security.c \
	src/security_oqs.c \
	src/aad.c \
	src/pipeline.c \
	src/receiver.c

CORE_OBJECTS := $(CORE_SOURCES:src/%.c=$(BUILD_DIR)/%.o)
TEST_SECURITY_OBJECT := $(BUILD_DIR)/security_test.o
DEMO_OBJECT := $(BUILD_DIR)/main.o
TEST_OBJECT := $(BUILD_DIR)/test_main.o
LIBRARY := $(BUILD_DIR)/libadaptive6lowpan.a
DEMO := $(BUILD_DIR)/adaptive_demo
TEST_BINARY := $(BUILD_DIR)/adaptive_tests

.PHONY: all lib demo test check production clean

all: lib demo $(TEST_BINARY)

lib: $(LIBRARY)

demo: $(DEMO)

test: $(TEST_BINARY)
	./$(TEST_BINARY)

check:
	rm -rf build-sanitize
	$(MAKE) test SANITIZE=1 BUILD_DIR=build-sanitize

production:
	$(MAKE) clean
	$(MAKE) lib WITH_OQS=1

$(LIBRARY): $(CORE_OBJECTS)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

$(DEMO): $(CORE_OBJECTS) $(TEST_SECURITY_OBJECT) $(DEMO_OBJECT)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(TEST_BINARY): $(CORE_OBJECTS) $(TEST_SECURITY_OBJECT) $(TEST_OBJECT)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_main.o: tests/test_main.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) build-sanitize

-include $(CORE_OBJECTS:.o=.d)
-include $(TEST_SECURITY_OBJECT:.o=.d)
-include $(DEMO_OBJECT:.o=.d)
-include $(TEST_OBJECT:.o=.d)
