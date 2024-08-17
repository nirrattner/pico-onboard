#include <stdio.h>

#include "pico/cyw43_arch.h"

#include "network.h"
#include "events.h"
#include "timer.h"

#define NETWORK_POLL_PERIOD_MS (10)

typedef enum {
  NETWORK_STATE__CLOSED = 0,
  NETWORK_STATE__OPEN,
  NETWORK_STATE__SCANNING,
} network_state_t;

typedef struct {
  network_state_t state;
} network_context_t;
static network_context_t context;

static int scan_callback(
    void *callback_data,
    const cyw43_ev_scan_result_t *result);

void network_open(void) {
  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

  cyw43_arch_enable_sta_mode();
  
  timer_enable_event(EVENT__NETWORK_POLL, NETWORK_POLL_PERIOD_MS, TIMER_MODE__REPEAT);
}

void network_scan(void) {
  int error;
  cyw43_wifi_scan_options_t scan_options = {0};

  error = cyw43_wifi_scan(&cyw43_state, &scan_options, NULL, scan_callback);
  if (error != 0) {
    printf("Scan error %d\n", error);
    return;
  }

  printf("Starting scan!\n");
  context.state = NETWORK_STATE__SCANNING;
}

void network_poll(void) {
  cyw43_arch_poll();

  if (context.state != NETWORK_STATE__SCANNING) {
    return;
  }

  if (cyw43_wifi_scan_active(&cyw43_state)) {
    return;
  }

  printf("Finished scan!\n");
  context.state = NETWORK_STATE__OPEN;
}

void network_scan_timeout(void) {
}

static int scan_callback(
    void *callback_data,
    const cyw43_ev_scan_result_t *result) {
  if (result == NULL) {
    return 0;
  }

  printf("ssid: %-32s rssi: %4d chan: %3d mac: %02x:%02x:%02x:%02x:%02x:%02x sec: %u\n",
      result->ssid,
      result->rssi,
      result->channel,
      result->bssid[0], 
      result->bssid[1], 
      result->bssid[2], 
      result->bssid[3], 
      result->bssid[4],
      result->bssid[5],
      result->auth_mode);
  return 0;
}

