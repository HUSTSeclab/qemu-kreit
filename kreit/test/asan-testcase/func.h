#ifndef BOKASAN_TEST_FUNC_H
#define BOKASAN_TEST_FUNC_H

#include <stddef.h>

#define __WEAK __attribute__((weak))

typedef void* (*malloc_t)(size_t size);
typedef void (*free_t)(void* ptr);
typedef void* (*calloc_t)(size_t nmemb, size_t size);

__WEAK malloc_t _malloc = (malloc_t)0xffff800000078fa0;
__WEAK free_t _free = (free_t)0xffff800000078f70;
__WEAK calloc_t _calloc = (calloc_t)0xffff800000078fd0;

#endif  // BOKASAN_TEST_FUNC_H
