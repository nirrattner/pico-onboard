#include <stdio.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "events.h"
#include "network.h"
#include "storage.h"
#include "timer.h"

int main() {
  stdio_init_all();
  cyw43_arch_init();

  events_open();
  timer_open();
  network_open();

  while (1) {
    if (events_get() & EVENT__NETWORK_POLL) {
      events_clear(EVENT__NETWORK_POLL);
      network_poll();
    }

    // if (events_get() & EVENT__NETWORK_SCAN) {
    //   events_clear(EVENT__NETWORK_SCAN);
    //   network_scan();
    // }

    // if (events_get() & EVENT__NETWORK_SCAN_TIMEOUT) {
    //   events_clear(EVENT__NETWORK_SCAN_TIMEOUT);
    //   network_scan_timeout();
    // }
  }
}
