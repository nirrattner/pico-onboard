#include "events.h"

typedef struct {
  volatile event_t events;
} event_context;
static event_context context;

void events_open(void) {
  context.events = EVENT__NONE;
}

void events_set(event_t events) {
  context.events |= events;
}

void events_clear(event_t events) {
  context.events &= ~events;
}

event_t events_get(void) {
  return context.events;
}

