#include <stdio.h>
#include <string.h>

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/stdlib.h"

#include "storage.h"

#define STORAGE_ADDRESS_OFFSET (PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE)
#define STORAGE_ADDRESS (XIP_BASE + STORAGE_ADDRESS_OFFSET)

#define MAGIC_VALUE ('P' << 24 | 'I' << 16 | 'O' << 8 | 'B')

typedef struct {
  union {
    storage_data_t data;
    uint8_t buffer[FLASH_PAGE_SIZE];
  };
} storage_context_t;
static storage_context_t context;

void storage_open(void) {
  context.data = *((storage_data_t *)STORAGE_ADDRESS);

  printf("storage_open\n");

  if (context.data.magic_value == MAGIC_VALUE) {
    printf("Initialized %x\n", context.data.magic_value);
    return;
  }

  printf("Uninitialized: %x vs %x\n", context.data.magic_value, MAGIC_VALUE);
}

void storage_write(
    uint32_t auth_mode,
    uint8_t *ssid,
    uint8_t ssid_size,
    uint8_t *password,
    uint8_t password_size) {
  uint32_t interrupts;

  context.data.magic_value = MAGIC_VALUE;
  context.data.auth_mode = auth_mode;
  memcpy(context.data.ssid, ssid, ssid_size);
  context.data.ssid[ssid_size] = '\0';
  memcpy(context.data.password, password, password_size);
  context.data.password[password_size] = '\0';

  // TODO: May miss timer interrupt
  // Test how long this takes and restore timer funtionality
  // interrupts = save_and_disable_interrupts();
  // flash_range_erase(STORAGE_ADDRESS_OFFSET, FLASH_SECTOR_SIZE);
  // flash_range_program(STORAGE_ADDRESS_OFFSET, context.buffer, FLASH_PAGE_SIZE);
  // restore_interrupts(interrupts);
}

const storage_data_t *storage_read(void) {
  return (const storage_data_t *) &context.data;
}

