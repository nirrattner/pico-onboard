#ifndef _STORAGE_H
#define _STORAGE_H

#include <stdint.h>

#define SSID_MAX_SIZE (32)
#define PASSWORD_MAX_SIZE (64)

typedef struct {
  uint32_t magic_value;
  uint32_t auth_mode;
  uint8_t ssid[SSID_MAX_SIZE + 1];
  uint8_t password[PASSWORD_MAX_SIZE + 1];
} storage_data_t;

void storage_open(void);

void storage_write(
    uint32_t auth_mode,
    uint8_t *ssid,
    uint8_t ssid_size,
    uint8_t *password,
    uint8_t password_size);

const storage_data_t *storage_read(void);

#endif

