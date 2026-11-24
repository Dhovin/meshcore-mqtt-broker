#ifndef _SHIM_ESP_EVENT_H
#define _SHIM_ESP_EVENT_H

#include "esp_err.h"

typedef const char* esp_event_base_t;
typedef void (*esp_event_handler_t)(void* handler_args, esp_event_base_t base,
                                    int32_t event_id, void* event_data);
#define ESP_EVENT_ANY_ID (-1)

#endif
