#include <stdio.h>

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
  printf("Buffer %x%x%x%x\n",
      context.buffer[0],
      context.buffer[1],
      context.buffer[2],
      context.buffer[3]);

  context.data.magic_value = MAGIC_VALUE;


  printf("Writing\n");

  // TODO: May miss timer interrupt
  // Test how long this takes and restore timer funtionality
  uint32_t interrupts = save_and_disable_interrupts();
  flash_range_erase(STORAGE_ADDRESS_OFFSET, FLASH_SECTOR_SIZE);
  flash_range_program(STORAGE_ADDRESS_OFFSET, context.buffer, FLASH_PAGE_SIZE);
  restore_interrupts(interrupts);

  printf("Wrote\n");

}



