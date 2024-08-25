#include <stdio.h>

#include "pico/cyw43_arch.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "dhcp_server.h"
#include "dns_server.h"
#include "events.h"
#include "network.h"
#include "network_interface.h"
#include "storage.h"
#include "timer.h"

#define AP_SSID "pico-onboard"
#define AP_PASSWORD "pico-password"

#define AUTH_RESULT_WPA_FLAG (2)
#define AUTH_RESULT_WPA2_FLAG (4)

#define BUFFER_SIZE (256)

#define TCP_SERVER_LISTEN_BACKLOG (1)
#define TCP_PORT (8080)

#define NETWORK_POLL_PERIOD_MS (10)

typedef enum {
  NETWORK_STATE__CLOSED = 0,
  NETWORK_STATE__AWAITING_CLIENT,
  NETWORK_STATE__AWAITING_REQUEST,
  NETWORK_STATE__AWAITING_CREDENTIALS,
  NETWORK_STATE__SCANNING,
  NETWORK_STATE__CLOSING_ERROR,
  NETWORK_STATE__CLOSING_CREDENTIALS,
  NETWORK_STATE__AWAITING_WIFI,
  NETWORK_STATE__CONNECTED,
} network_state_t;

typedef struct {
  dhcp_server_t dhcp_server;
  dns_server_t dns_server;
  struct tcp_pcb *tcp_server_pcb;
  struct tcp_pcb *client_pcb;
  ip4_addr_t gateway_ip_address;
  uint8_t buffer[BUFFER_SIZE];
  uint8_t buffer_index;
  network_state_t state;
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
static err_t tcp_sent_callback(
    void *argument,
    struct tcp_pcb *pcb, 
    uint16_t bytes_sent);
static void tcp_error_callback(
    void *arguments, 
    err_t error);

static void receive_request_header(struct pbuf *packet_buffer);
static void receive_credentials(struct pbuf *packet_buffer);

static void request_ping(void);
static void request_scan_initiate(void);
static void request_scan_complete(void);
static void request_credentials_initiate(void);
static void request_credentials_complete(void);

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
  
  context.state = NETWORK_STATE__AWAITING_CLIENT;
}

void network_poll(void) {
  cyw43_arch_poll();

  if (context.state == NETWORK_STATE__SCANNING
      && cyw43_wifi_scan_active(&cyw43_state) == 0) {
    request_scan_complete();
  }

  if (context.state == NETWORK_STATE__AWAITING_WIFI) {
    if (cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA) != CYW43_LINK_UP) {
      return;
    }
    printf("CONNECTED!\n");
    context.state = NETWORK_STATE__CONNECTED;
  }
}

void request_scan_timeout(void) {
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
    context.state = NETWORK_STATE__AWAITING_CLIENT;
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
  if (context.state != NETWORK_STATE__AWAITING_CLIENT) {
    printf("Connection rejected\n");
    return ERR_VAL;
  }

  printf("Connected!\n");

  tcp_recv(client_pcb, tcp_receive_callback);
  tcp_sent(client_pcb, tcp_sent_callback);
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
  if (packet_buffer == NULL) {
    tcp_close_client(context.client_pcb);
    printf("Connection closed (%u)\n", error);
    return ERR_OK;
  }

  switch (context.state) {
    case NETWORK_STATE__AWAITING_REQUEST:
      receive_request_header(packet_buffer);
      break;
    case NETWORK_STATE__AWAITING_CREDENTIALS:
      receive_credentials(packet_buffer);
      break;
    default:
      // TODO: Error?
      break;
  }
  return ERR_OK;
}

static err_t tcp_sent_callback(
    void *argument,
    struct tcp_pcb *client_pcb,
    uint16_t bytes_sent) {
  switch (context.state) {
    case NETWORK_STATE__CLOSING_ERROR:
      tcp_close_client(context.client_pcb);
      break;
    case NETWORK_STATE__CLOSING_CREDENTIALS:
      tcp_close_client(context.client_pcb);
      request_credentials_complete();
      break;
  }
}

static void tcp_error_callback(
    void *arguments, 
    err_t error) {
  printf("Connection error (%x)\n", error);
  tcp_close_client(context.client_pcb);
}

static void request_ping(void) {
  response_header_t response_header;

  response_header.type = RESPONSE_TYPE__PONG;
  tcp_write(
      context.client_pcb,
      (void *)&response_header,
      sizeof(response_header_t),
      0);
}

static void receive_request_header(struct pbuf *packet_buffer) {
  request_header_t *request_header;
  uint8_t bytes_read;

  request_header = (request_header_t *)context.buffer;

  bytes_read = packet_buffer->tot_len < BUFFER_SIZE
      ? packet_buffer->tot_len
      : BUFFER_SIZE;
  bytes_read = pbuf_copy_partial(
      packet_buffer,
      context.buffer,
      bytes_read,
      0);
  tcp_recved(context.client_pcb, bytes_read);
  pbuf_free(packet_buffer);

  printf("REQUEST[%u]\n", request_header->type);

  switch (request_header->type) {
    case REQUEST_TYPE__PING:
      request_ping();
      break;
    case REQUEST_TYPE__SCAN:
      request_scan_initiate();
      break;
    case REQUEST_TYPE__CREDENTIALS:
      context.buffer_index = bytes_read;
      context.state = NETWORK_STATE__AWAITING_CREDENTIALS;
      request_credentials_initiate();
      break;
  }
}

static void receive_credentials(struct pbuf *packet_buffer) {
  int bytes_read;
  credentials_message_t *credentials_message;

  bytes_read = packet_buffer->tot_len < (BUFFER_SIZE - context.buffer_index)
      ? packet_buffer->tot_len
      : BUFFER_SIZE - context.buffer_index;
  bytes_read = pbuf_copy_partial(
      packet_buffer,
      &context.buffer[context.buffer_index],
      bytes_read,
      0);
  context.buffer_index += bytes_read;
  tcp_recved(context.client_pcb, bytes_read);
  pbuf_free(packet_buffer);

  request_credentials_initiate();
}

static void request_scan_initiate(void) {
  int error;
  response_header_t response_header;
  ssids_message_header_t *ssids_message_header;
  cyw43_wifi_scan_options_t scan_options = {0};

  cyw43_arch_enable_sta_mode();
  error = cyw43_wifi_scan(&cyw43_state, &scan_options, NULL, scan_callback);
  if (error != 0) {
    printf("Scan error %d\n", error);
    response_header.type = RESPONSE_TYPE__ERROR;
    tcp_write(
        context.client_pcb,
        (void *)&response_header,
        sizeof(response_header_t),
        0);
    context.state = NETWORK_STATE__CLOSING_ERROR;
    return;
  }

  printf("Starting scan!\n");

  response_header.type = RESPONSE_TYPE__SSIDS;
  memcpy(context.buffer, (void *)&response_header, sizeof(response_header_t));
  context.buffer_index = sizeof(response_header_t);
  ssids_message_header = (ssids_message_header_t *)&context.buffer[context.buffer_index];
  ssids_message_header->size = 0;
  context.buffer_index += sizeof(ssids_message_header_t);

  context.state = NETWORK_STATE__SCANNING;
}

static void request_scan_complete(void) {
  printf("Finished scan!\n");
  cyw43_arch_disable_sta_mode();

  if (context.client_pcb == NULL) {
    context.state = NETWORK_STATE__AWAITING_CLIENT;
    return;
  }

  tcp_write(
      context.client_pcb,
      context.buffer,
      context.buffer_index,
      0);
  context.state = NETWORK_STATE__AWAITING_REQUEST;
}

static void request_credentials_initiate(void) {
  credentials_message_t *credentials_message;
  response_header_t response_header;
  uint8_t read_buffer_index;

  read_buffer_index = sizeof(request_header_t);
  if (context.buffer_index < read_buffer_index + sizeof(credentials_message_t)) {
    return;
  }

  credentials_message = (credentials_message_t *)&context.buffer[read_buffer_index];

  if (credentials_message->ssid_size > SSID_MAX_SIZE
      || credentials_message->password_size > PASSWORD_MAX_SIZE) {
    printf(
        "Message too large (ssid: %u, password: %u)\n", 
        credentials_message->ssid_size,
        credentials_message->password_size);
    response_header.type = RESPONSE_TYPE__ERROR;
    tcp_write(
        context.client_pcb,
        (void *)&response_header,
        sizeof(response_header_t),
        0);
    context.state = NETWORK_STATE__CLOSING_ERROR;
    return;
  }

  read_buffer_index += sizeof(credentials_message_t);
  if (context.buffer_index < read_buffer_index + credentials_message->ssid_size + credentials_message->password_size) {
    return;
  }

  printf(
      "SSID[%u] '%.*s'\n",
      credentials_message->ssid_size,
      credentials_message->ssid_size,
      &context.buffer[read_buffer_index]);

  read_buffer_index += credentials_message->ssid_size;
  printf(
      "PASSWORD[%u] '%.*s'\n",
      credentials_message->password_size,
      credentials_message->password_size,
      &context.buffer[read_buffer_index]);

  response_header.type = RESPONSE_TYPE__OK;
  tcp_write(
      context.client_pcb,
      (void *)&response_header,
      sizeof(response_header_t),
      0);
  context.state = NETWORK_STATE__CLOSING_CREDENTIALS;
}

static void request_credentials_complete(void) {
  credentials_message_t *credentials_message;
  int result;
  uint8_t read_buffer_index;
  const storage_data_t *storage_data;

  printf("request_credentials_complete\n");

  tcp_close(context.tcp_server_pcb);
  context.tcp_server_pcb = NULL;
  dhcp_server_deinit(&context.dhcp_server);
  dns_server_deinit(&context.dns_server);
  cyw43_arch_disable_ap_mode();

  read_buffer_index = sizeof(request_header_t);
  credentials_message = (credentials_message_t *)&context.buffer[read_buffer_index];

  read_buffer_index += sizeof(credentials_message_t);

  storage_write(
      credentials_message->auth_mode,
      &context.buffer[read_buffer_index],
      credentials_message->ssid_size,
      &context.buffer[read_buffer_index + credentials_message->ssid_size],
      credentials_message->password_size);

  storage_data = storage_read();

  printf("AUTH MODE: %u\n", storage_data->auth_mode);
  printf("SSID: %s\n", storage_data->ssid);
  printf("PASSWORD: %s\n", storage_data->password);

  cyw43_arch_enable_sta_mode();
  result = cyw43_arch_wifi_connect_async(
      storage_data->ssid,
      storage_data->password,
      storage_data->auth_mode);

  printf("Connecting (%d)\n", result);
  context.state = NETWORK_STATE__AWAITING_WIFI;
}

static int scan_callback(
    void *callback_data,
    const cyw43_ev_scan_result_t *result) {
  ssids_message_header_t *ssids_message_header;
  ssid_message_t *ssid_message;
  uint8_t ssid_size;
  uint8_t ssid_index;
  uint8_t buffer_index;

  if (result == NULL 
      || context.state != NETWORK_STATE__SCANNING) {
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

  if (context.buffer_index + sizeof(ssid_message_t) + ssid_size >= BUFFER_SIZE) {
    printf("Buffer at capacity\n");
    return 0;
  }

  ssids_message_header = (ssids_message_header_t *)&context.buffer[sizeof(response_header_t)];
  buffer_index = sizeof(response_header_t) + sizeof(ssids_message_header_t);
  for (ssid_index = 0; ssid_index < ssids_message_header->size; ssid_index++) {
    ssid_message = (ssid_message_t *)&context.buffer[buffer_index];
    buffer_index += sizeof(ssid_message_t);
    if (ssid_size == ssid_message->size 
        && memcmp(
            result->ssid, 
            &context.buffer[buffer_index],
            ssid_size) == 0) {
      return 0;
    }
    buffer_index += ssid_message->size;
  }

  ssids_message_header->size++;
  ssid_message = (ssid_message_t *)&context.buffer[context.buffer_index];

  if (result->auth_mode & AUTH_RESULT_WPA2_FLAG) {
    ssid_message->auth_mode = CYW43_AUTH_WPA2_AES_PSK;
  } else if (result->auth_mode & AUTH_RESULT_WPA_FLAG) {
    ssid_message->auth_mode = CYW43_AUTH_WPA_TKIP_PSK;
  } else {
    ssid_message->auth_mode = 0;
  }

  ssid_message->size = ssid_size;
  context.buffer_index += sizeof(ssid_message_t);
  memcpy(&context.buffer[context.buffer_index], result->ssid, ssid_size);
  context.buffer_index += ssid_size;
  return 0;
}

