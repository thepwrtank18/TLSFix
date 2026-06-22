// Legacy macOS (10.x) lacks clock_gettime; provide mbedtls_ms_time() via gettimeofday
// (selected by -DMBEDTLS_PLATFORM_MS_TIME_ALT in build-mbedtls-mac.sh).
#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"
#include <sys/time.h>
mbedtls_ms_time_t mbedtls_ms_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (mbedtls_ms_time_t)tv.tv_sec * 1000 + (mbedtls_ms_time_t)(tv.tv_usec / 1000);
}
