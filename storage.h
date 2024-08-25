#ifndef _STORAGE_H
#define _STORAGE_H

#include <stdint.h>

#define SSID_MAX_SIZE (32)
#define PASSWORD_MAX_SIZE (64)

typedef struct {
  uint32_t magic_value;
  uint32_t authorization_type;
  uint8_t ssid[SSID_MAX_SIZE];
  uint8_t ssid_length;
  uint8_t password[PASSWORD_MAX_SIZE];
  uint8_t password_length;
} storage_data_t;

void storage_open(void);

#endif

