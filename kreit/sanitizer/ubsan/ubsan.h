#ifndef __KREIT_TARGET_SANITIZER__
#define __KREIT_TARGET_SANITIZER__

#include <stdlib.h>

void __kreit_ubsan_handle_divrem_overflow(void *lhs, void *rhs, size_t size);

void __kreit_ubsan_report_div_zero(void);

#endif // __KREIT_TARGET_SANITIZER__
