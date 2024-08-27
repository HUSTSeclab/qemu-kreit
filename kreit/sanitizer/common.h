#ifndef __KREIT_SANITIZER_COMMON__
#define __KREIT_SANITIZER_COMMON__

void __kreit_sanitizer_report(const char *str);

void __attribute__((noreturn)) __kreit_sanitizer_abort(void);

#endif // __KREIT_SANITIZER_COMMON__
