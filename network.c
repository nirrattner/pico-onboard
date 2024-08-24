#include <stdio.h>

#include "pico/cyw43_arch.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "dhcp_server.h"
#include "dns_server.h"
#include "events.h"
#include "network.h"
#include "network_interface.h"
#include "timer.h"

#define AP_SSID "pico-onboard"
#define AP_PASSWORD "pico-password"

#define SCAN_BUFFER_SIZE (256)

#define TCP_SERVER_LISTEN_BACKLOG (1)
#define TCP_PORT (8080)

#define NETWORK_POLL_PERIOD_MS (10)

typedef enum {
  NETWORK_STATE__CLOSED = 0,
  NETWORK_STATE__AWAITING_CONNECTION,
  NETWORK_STATE__AWAITING_REQUEST,
  NETWORK_STATE__SCANNING,
} network_state_t;

typedef struct {
  dhcp_server_t dhcp_server;
  dns_server_t dns_server;
  struct tcp_pcb *tcp_server_pcb;
  struct tcp_pcb *client_pcb;
  ip4_addr_t gateway_ip_address;
  network_state_t state;
  uint8_t scan_buffer[SCAN_BUFFER_SIZE];
  uint8_t scan_buffer_index;
  ssids_header_t *ssids_header;
} network_context_t;
static network_context_t context;

static void tcp_server_open(void);
static void tcp_close_client(struct tcp_pcb *client_pcb);

static err_t tcp_accept_callback(
    void *argument,
    struct tcp_pcb *client_pcb,
    err_t error);
static err_t tcp_receive_callback(
    void *argument,
    struct tcp_pcb *client_pcb,
    struct pbuf *buffer,
    err_t error);
static void tcp_error_callback(
    void *arguments, 
    err_t error);

static int scan_callback(
    void *callback_data,
    const cyw43_ev_scan_result_t *result);

void network_open(void) {
  ip4_addr_t ip_address_mask;

  cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);

  cyw43_arch_enable_ap_mode(AP_SSID, AP_PASSWORD, CYW43_AUTH_WPA2_AES_PSK);

  IP4_ADDR(ip_2_ip4(&context.gateway_ip_address), 192, 168, 4, 1);
  IP4_ADDR(ip_2_ip4(&ip_address_mask), 255, 255, 255, 0);
  dhcp_server_init(&context.dhcp_server, &context.gateway_ip_address, &ip_address_mask);
  dns_server_init(&context.dns_server, &context.gateway_ip_address);
  tcp_server_open();
  
  timer_enable_event(EVENT__NETWORK_POLL, NETWORK_POLL_PERIOD_MS, TIMER_MODE__REPEAT);
  
  context.state = NETWORK_STATE__AWAITING_CONNECTION;
}

void network_scan(void) {
  int error;
  response_t response;
  cyw43_wifi_scan_options_t scan_options = {0};

  cyw43_arch_enable_sta_mode();
  error = cyw43_wifi_scan(&cyw43_state, &scan_options, NULL, scan_callback);
  if (error != 0) {
    printf("Scan error %d\n", error);
    response.type = RESPONSE_TYPE__ERROR;
    tcp_write(
        context.client_pcb,
        (void *)&response,
        sizeof(response_t),
        0);
    return;
  }

  printf("Starting scan!\n");

  response.type = RESPONSE_TYPE__SSIDS;
  memcpy(context.scan_buffer, (void *)&response, sizeof(response_t));
  context.scan_buffer_index = sizeof(response_t);
  context.ssids_header = (ssids_header_t *)&context.scan_buffer[context.scan_buffer_index];
  context.ssids_header->size = 0;
  context.scan_buffer_index += sizeof(ssids_header_t);

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
  cyw43_arch_disable_sta_mode();

  if (context.client_pcb == NULL) {
    context.state = NETWORK_STATE__AWAITING_CONNECTION;
    return;
  }

  tcp_write(
      context.client_pcb,
      context.scan_buffer,
      context.scan_buffer_index,
      0);
  context.state = NETWORK_STATE__AWAITING_REQUEST;
}

void network_scan_timeout(void) {
  // TODO
}

static void tcp_server_open(void) {
  struct tcp_pcb *server_pcb;
  err_t error;
  
  server_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (server_pcb == NULL) {
    printf("Failed to create pcb\n");
    return;
  }
  
  error = tcp_bind(server_pcb, IP_ANY_TYPE, TCP_PORT);
  if (error) {
    printf("Failed to bind to port %d\n", TCP_PORT);
    return;
  }
  
  context.tcp_server_pcb = tcp_listen_with_backlog(server_pcb, TCP_SERVER_LISTEN_BACKLOG);
  if (context.tcp_server_pcb == NULL) {
    printf("Failed to listen\n");
    return;
  }
  
  tcp_accept(context.tcp_server_pcb, tcp_accept_callback);
}

static void tcp_close_client(struct tcp_pcb *client_pcb) {
  err_t error;

  if (context.state == NETWORK_STATE__AWAITING_REQUEST) {
    context.state = NETWORK_STATE__AWAITING_CONNECTION;
  }
  context.client_pcb = NULL;

  if (client_pcb == NULL) {
    return;
  }

  error = tcp_close(client_pcb);
  if (error == ERR_OK) {
    return;
  }
  tcp_abort(client_pcb);
}

static err_t tcp_accept_callback(
    void *argument,
    struct tcp_pcb *client_pcb,
    err_t error) {
  if (context.state != NETWORK_STATE__AWAITING_CONNECTION) {
    printf("Connection rejected\n");
    return ERR_VAL;
  }

  printf("Connected!\n");

  tcp_recv(client_pcb, tcp_receive_callback);
  tcp_err(client_pcb, tcp_error_callback);

  context.state = NETWORK_STATE__AWAITING_REQUEST;
  context.client_pcb = client_pcb;
  
  return ERR_OK;
}

static err_t tcp_receive_callback(
    void *argument,
    struct tcp_pcb *client_pcb,
    struct pbuf *packet_buffer,
    err_t error) {
  int bytes_read;
  request_t request;
  response_t response;

  if (packet_buffer == NULL) {
    tcp_close_client(client_pcb);
    printf("Connection closed (%u)\n", error);
    return ERR_OK;
  }

  pbuf_copy_partial(
      packet_buffer,
      (void *)&request,
      sizeof(request_t),
      0);
  bytes_read = sizeof(request_t);

  printf("REQUEST[%u]\n", request.type);

  switch (request.type) {
    case REQUEST_TYPE__PING:
      response.type = RESPONSE_TYPE__PONG;
      tcp_write(
          client_pcb,
          (void *)&response,
          sizeof(response_t),
          0);
      break;
    case REQUEST_TYPE__SCAN:
      network_scan();
      break;
    case REQUEST_TYPE__CREDENTIALS:
      response.type = RESPONSE_TYPE__OK;
      tcp_write(
          client_pcb,
          (void *)&response,
          sizeof(response_t),
          0);
      break;
  }
  
  pbuf_free(packet_buffer);
  tcp_recved(client_pcb, bytes_read);

  return ERR_OK;
}

static void tcp_error_callback(
    void *arguments, 
    err_t error) {
  printf("Connection error (%x)\n", error);
  tcp_close_client(context.client_pcb);
}

static int scan_callback(
    void *callback_data,
    const cyw43_ev_scan_result_t *result) {
  ssid_t *ssid;
  uint8_t ssid_size;
  uint8_t ssid_index;
  uint8_t scan_buffer_index;

  if (result == NULL) {
    return 0;
  }

  ssid_size = strlen(result->ssid);
  if (ssid_size == 0) {
    return 0;
  }

  printf("ssid[%u]: %-32s rssi: %4d chan: %3d mac: %02x:%02x:%02x:%02x:%02x:%02x sec: %u\n",
      ssid_size,
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

  if (context.scan_buffer_index + sizeof(ssid_t) + ssid_size >= SCAN_BUFFER_SIZE) {
    printf("Buffer at capacity\n");
    return 0;
  }

  scan_buffer_index = sizeof(response_t) + sizeof(ssids_header_t);
  for (ssid_index = 0; ssid_index < context.ssids_header->size; ssid_index++) {
    ssid = (ssid_t *)&context.scan_buffer[scan_buffer_index];
    scan_buffer_index += sizeof(ssid_t);
    if (ssid_size == ssid->size 
        && memcmp(
            result->ssid, 
            &context.scan_buffer[scan_buffer_index],
            ssid->size) == 0) {
      printf("Duplicate %.*s\n", ssid_size, &context.scan_buffer[scan_buffer_index]);
      return 0;
    }
    scan_buffer_index += ssid->size;
  }

  context.ssids_header->size++;
  ssid = (ssid_t *)&context.scan_buffer[context.scan_buffer_index];
  ssid->auth_mode = result->auth_mode;
  ssid->size = ssid_size;
  context.scan_buffer_index += sizeof(ssid_t);
  memcpy(&context.scan_buffer[context.scan_buffer_index], result->ssid, ssid_size);
  context.scan_buffer_index += ssid_size;
  return 0;
}

