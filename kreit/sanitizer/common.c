#include "kreit/sanitizer/common.h"

#include <stdlib.h>
#include <stdint.h>
#include "qemu/osdep.h"
#include "qemu/log.h"

void __kreit_sanitizer_report(const char *str)
{
    qemu_log("%s", str);
}

void __attribute__((noreturn)) __kreit_sanitizer_abort(void)
{
    exit(-1);
}
