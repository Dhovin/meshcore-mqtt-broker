#ifndef _SHIM_FREERTOS_H
#define _SHIM_FREERTOS_H

#include <mutex>

#ifndef portMAX_DELAY
#define portMAX_DELAY 0xFFFFFFFFUL
#endif

typedef std::mutex portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED {}
#define portENTER_CRITICAL(mux) do { if (mux) (mux)->lock(); } while (0)
#define portEXIT_CRITICAL(mux)  do { if (mux) (mux)->unlock(); } while (0)

#endif
