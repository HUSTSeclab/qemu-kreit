#include "kreit/sanitizer/common.h"
#include "kreit/sanitizer/ubsan.h"

#include <stdint.h>
#include <string.h>

void __kreit_ubsan_handle_divrem_overflow(void *lhs, void *rhs, size_t size)
{
    uint8_t rhs_byte[32];
    memcpy(rhs_byte, rhs, size);
    for (int i = 0; i < size; i++) {
        if (!rhs_byte[i])
            return;
    }
    __kreit_ubsan_report_div_zero();
}

void __kreit_ubsan_report_div_zero(void)
{
    __kreit_sanitizer_report("div zero detected");
    __kreit_sanitizer_abort();
}
