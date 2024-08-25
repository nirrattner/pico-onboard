#include "hardware/irq.h"
#include "hardware/timer.h"
#include "pico/stdlib.h"

#include "events.h"
#include "timer.h"

#define TIMER_ID (0)
#define TIMER_PERIOD_US (1000)

typedef struct {
  volatile uint32_t counter_ms;
  volatile event_t events_enabled;
  volatile uint32_t event_counter_ms[NUM_EVENTS];
  volatile uint32_t timer_expiry_us;

  uint32_t repeat_count_ms[NUM_EVENTS];
} timer_context;
static timer_context context;

static void timer_interrupt_callback(void);

void timer_open(void) {
  irq_set_exclusive_handler(TIMER_IRQ_0, timer_interrupt_callback);
  irq_set_enabled(TIMER_IRQ_0, true);

  context.counter_ms = 0;
  context.events_enabled = EVENT__NONE;
  context.timer_expiry_us = timer_hw->timerawl + TIMER_PERIOD_US;
  timer_hw->alarm[TIMER_ID] = context.timer_expiry_us;
  hw_set_bits(&timer_hw->inte, 1u << TIMER_ID);
}

void timer_enable_event(event_t event, uint32_t period_ms, timer_mode_t timer_mode) {
  uint8_t event_index;
  context.events_enabled |= event;

  for (event_index = 0; event_index < NUM_EVENTS; event_index++) {
    if (event == (1 << event_index)) {
      context.event_counter_ms[event_index] = context.counter_ms + period_ms;
      if (timer_mode == TIMER_MODE__ONCE) {
        context.repeat_count_ms[event_index] = 0;
      } else {
        context.repeat_count_ms[event_index] = period_ms;
      }
      return;
    }
  }
}

void timer_disable_event(event_t event) {
  context.events_enabled &= ~event;
}

static void timer_interrupt_callback(void) {
  uint8_t event_index;

  hw_clear_bits(&timer_hw->intr, 1u << TIMER_ID);

  // TODO: Expire only on next event to reduce power consumption
  context.timer_expiry_us += TIMER_PERIOD_US;
  timer_hw->alarm[TIMER_ID] = context.timer_expiry_us;

  for (event_index = 0; event_index < NUM_EVENTS; event_index++) {
    if ((context.events_enabled & (1 << event_index))
        && context.counter_ms == context.event_counter_ms[event_index]) {
      events_set(1 << event_index);
      if (context.repeat_count_ms[event_index]) {
        context.event_counter_ms[event_index] += context.repeat_count_ms[event_index];
      } else {
        context.events_enabled &= ~(1 << event_index);
      }
    }
  }

  context.counter_ms++;
}
