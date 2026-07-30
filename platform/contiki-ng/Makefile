CONTIKI_PROJECT = adaptive-node adaptive-server
all: $(CONTIKI_PROJECT)

CONTIKI ?= ../../../contiki-ng

PROJECTDIRS += ../../src .
PROJECT_SOURCEFILES += \
	types.c \
	config.c \
	metrics.c \
	hmm.c \
	wavelet_db4.c \
	codec.c \
	coap_block.c \
	security.c \
	security_test.c \
	aad.c \
	contiki-port.c

CFLAGS += -I../../include -DADAPTIVE_EMBEDDED

MODULES += os/net/app-layer/coap
MAKE_NET = MAKE_NET_IPV6
MAKE_ROUTING = MAKE_ROUTING_RPL_LITE

include $(CONTIKI)/Makefile.include
