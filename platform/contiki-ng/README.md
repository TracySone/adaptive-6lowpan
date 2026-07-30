# Contiki-NG target

This directory contains a Block1 client (`adaptive-node`) and receiver
(`adaptive-server`). Both use Contiki-NG's IPv6/6LoWPAN, RPL and CoAP stack.

Build against a Contiki-NG checkout:

```sh
make CONTIKI=/path/to/contiki-ng TARGET=native
make CONTIKI=/path/to/contiki-ng TARGET=cooja
```

The default Cooja build intentionally uses `adaptive_security_test_pair`.
That provider tests framing, replay handling and state transitions but is not
cryptographic. Real firmware must replace it with a board-specific
ML-KEM/AEAD provider or a cross-compiled liboqs provider and must provision an
authenticated server encapsulation key.

Override these weak hooks from `contiki-port.c` for a board:

- `adaptive_platform_read_window`
- `adaptive_platform_queue_ratio`
- `adaptive_platform_mac_retry_ratio`

Change `ADAPTIVE_SERVER_EP` in `project-conf.h` to the receiver's address.
