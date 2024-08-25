#ifndef _EVENTS_H
#define _EVENTS_H

#include <stdint.h>

#define NUM_EVENTS (2)

typedef enum {
  EVENT__NONE = 0,
  EVENT__NETWORK_POLL         = (1 << 0),
  EVENT__NETWORK_SCAN_TIMEOUT = (1 << 2),
} event_t;

void events_open(void);
void events_set(event_t events);
void events_clear(event_t events);
event_t events_get(void);

#endif

