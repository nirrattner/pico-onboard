#ifndef _TIMER_H
#define _TIMER_H

#include "events.h"

typedef enum {
  TIMER_MODE__ONCE = 0,
  TIMER_MODE__REPEAT,
} timer_mode_t;

void timer_open(void);
void timer_enable_event(event_t event, uint32_t period_ms, timer_mode_t timer_mode);
void timer_disable_event(event_t event);

#endif

