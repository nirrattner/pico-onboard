#ifndef _STORAGE_H
#define _STORAGE_H

#include <stdint.h>

#define SSID_MAX_LENGTH (32)
#define PASSWORD_MAX_LENGTH (64)

typedef struct {
  uint32_t magic_value;
  uint8_t ssid[SSID_MAX_LENGTH];
  uint8_t ssid_length;
  uint8_t password[PASSWORD_MAX_LENGTH];
  uint8_t password_length;
  uint32_t authorization_type;
} storage_data_t;

void storage_open(void);

#endif

