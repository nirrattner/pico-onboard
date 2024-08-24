#ifndef _NETWORK_INTERFACE_H
#define _NETWORK_INTERFACE_H

typedef enum {
  REQUEST_TYPE__PING = 0,
  REQUEST_TYPE__SCAN,
  REQUEST_TYPE__CREDENTIALS,
} request_type_t;

typedef enum {
  RESPONSE_TYPE__OK = 0,
  RESPONSE_TYPE__ERROR,
  RESPONSE_TYPE__PONG,
  RESPONSE_TYPE__SSIDS,
} response_type_t;

#pragma pack(1)
typedef struct {
  uint8_t type;
} request_t;

typedef struct {
  uint8_t type;
} response_t;

typedef struct {
  uint8_t size;
} ssids_header_t;

typedef struct {
  uint32_t auth_mode;
  uint8_t size;
} ssid_t;
#pragma pack()

#endif

