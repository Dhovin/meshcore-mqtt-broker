#ifndef _SHIM_FREERTOS_SEMPHR_H
#define _SHIM_FREERTOS_SEMPHR_H

#include "FreeRTOS.h"
#include <mutex>

typedef std::recursive_mutex* SemaphoreHandle_t;

inline SemaphoreHandle_t xSemaphoreCreateRecursiveMutex() {
    return new std::recursive_mutex();
}

inline void xSemaphoreTakeRecursive(SemaphoreHandle_t m, unsigned long timeout) {
    (void)timeout;
    if (m) m->lock();
}

inline void xSemaphoreGiveRecursive(SemaphoreHandle_t m) {
    if (m) m->unlock();
}

#endif
